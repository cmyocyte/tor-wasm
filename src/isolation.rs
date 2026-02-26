//! Circuit Isolation Policy
//!
//! Implements circuit isolation to prevent cross-site correlation attacks.
//! Different requests to different domains use different circuits.
//!
//! ## Security Rationale
//!
//! Without circuit isolation, an adversary controlling two websites could
//! correlate visits by observing that both requests came from the same
//! circuit (and thus the same exit node at the same time).
//!
//! With isolation, each domain gets its own circuit, preventing this attack.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::{Duration, Instant};

use crate::protocol::Circuit;

/// How circuits should be isolated
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IsolationType {
    /// One circuit per domain (e.g., example.com)
    /// This is the default and recommended setting
    #[default]
    PerDomain,

    /// One circuit per (domain, port) pair
    /// More paranoid - different ports are isolated
    PerDestination,

    /// New circuit for every request (most paranoid)
    /// Warning: Very slow, only use for highly sensitive operations
    PerRequest,

    /// Single circuit for all requests (no isolation)
    /// Warning: NOT RECOMMENDED - allows correlation attacks
    None,
}

/// Configuration for circuit isolation
#[derive(Debug, Clone)]
pub struct IsolationConfig {
    /// The isolation policy to use
    pub policy: IsolationType,

    /// Maximum age of a circuit before forced rotation (default: 10 minutes)
    pub max_circuit_age: Duration,

    /// Maximum number of requests per circuit before rotation (default: 100)
    pub max_requests_per_circuit: u32,

    /// Maximum number of cached circuits (default: 10)
    pub max_cached_circuits: usize,
}

impl Default for IsolationConfig {
    fn default() -> Self {
        Self {
            policy: IsolationType::PerDomain,
            max_circuit_age: Duration::from_secs(10 * 60), // 10 minutes
            max_requests_per_circuit: 100,
            max_cached_circuits: 10,
        }
    }
}

impl IsolationConfig {
    /// Create a paranoid configuration (new circuit per request)
    pub fn paranoid() -> Self {
        Self {
            policy: IsolationType::PerRequest,
            ..Default::default()
        }
    }

    /// Create a relaxed configuration (single circuit for all)
    /// WARNING: Not recommended for security-sensitive applications
    pub fn relaxed() -> Self {
        Self {
            policy: IsolationType::None,
            max_circuit_age: Duration::from_secs(30 * 60), // 30 minutes
            max_requests_per_circuit: 1000,
            max_cached_circuits: 1,
        }
    }
}

/// Key for circuit isolation - determines which circuit to use
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IsolationKey {
    /// Domain or full destination string
    key: String,
}

impl IsolationKey {
    /// Create an isolation key for a given host and port based on policy
    pub fn for_destination(host: &str, port: u16, policy: IsolationType) -> Self {
        let key = match policy {
            IsolationType::PerDomain => {
                // Extract domain (remove port, trailing dot)
                host.trim_end_matches('.').to_lowercase()
            }
            IsolationType::PerDestination => {
                // Include port
                format!("{}:{}", host.to_lowercase(), port)
            }
            IsolationType::PerRequest => {
                // Unique key for each request
                format!("{}:{}:{}", host, port, uuid_v4())
            }
            IsolationType::None => {
                // Single key for all
                "global".to_string()
            }
        };

        Self { key }
    }

    /// Get the key string
    pub fn as_str(&self) -> &str {
        &self.key
    }
}

/// Metadata about a cached circuit
struct CachedCircuit {
    /// The circuit itself (wrapped for shared access)
    circuit: Rc<RefCell<Circuit>>,

    /// When this circuit was created
    created_at: Instant,

    /// Number of requests made on this circuit
    request_count: u32,

    /// The isolation key for this circuit
    isolation_key: IsolationKey,
}

impl CachedCircuit {
    fn new(circuit: Circuit, key: IsolationKey) -> Self {
        Self {
            circuit: Rc::new(RefCell::new(circuit)),
            created_at: Instant::now(),
            request_count: 0,
            isolation_key: key,
        }
    }

    /// Check if this circuit should be retired
    fn should_retire(&self, config: &IsolationConfig) -> bool {
        // Check age
        if self.created_at.elapsed() > config.max_circuit_age {
            log::info!(
                "  🔄 Circuit aged out ({}s old)",
                self.created_at.elapsed().as_secs()
            );
            return true;
        }

        // Check request count
        if self.request_count >= config.max_requests_per_circuit {
            log::info!(
                "  🔄 Circuit at request limit ({} requests)",
                self.request_count
            );
            return true;
        }

        false
    }

    /// Increment request count
    fn increment_requests(&mut self) {
        self.request_count += 1;
    }
}

/// Circuit cache with isolation support
pub struct CircuitCache {
    /// Configuration
    config: IsolationConfig,

    /// Cached circuits by isolation key
    circuits: HashMap<String, CachedCircuit>,

    /// Order of circuit insertion (for LRU eviction)
    insertion_order: Vec<String>,
}

impl CircuitCache {
    /// Create a new circuit cache with the given configuration
    pub fn new(config: IsolationConfig) -> Self {
        Self {
            config,
            circuits: HashMap::new(),
            insertion_order: Vec::new(),
        }
    }

    /// Get the isolation policy
    pub fn policy(&self) -> IsolationType {
        self.config.policy
    }

    /// Create an isolation key for a destination
    pub fn isolation_key(&self, host: &str, port: u16) -> IsolationKey {
        IsolationKey::for_destination(host, port, self.config.policy)
    }

    /// Get a circuit for the given isolation key, if one exists and is valid
    pub fn get(&mut self, key: &IsolationKey) -> Option<Rc<RefCell<Circuit>>> {
        let key_str = key.as_str();

        // Check if we have a circuit for this key
        if let Some(cached) = self.circuits.get_mut(key_str) {
            // Check if it should be retired
            if cached.should_retire(&self.config) {
                log::info!("  ♻️ Retiring old circuit for '{}'", key_str);
                self.remove(key);
                return None;
            }

            // Increment request count
            cached.increment_requests();

            log::info!(
                "  ✅ Reusing circuit for '{}' (request #{})",
                key_str,
                cached.request_count
            );

            return Some(Rc::clone(&cached.circuit));
        }

        None
    }

    /// Store a circuit for the given isolation key
    pub fn store(&mut self, key: IsolationKey, circuit: Circuit) -> Rc<RefCell<Circuit>> {
        let key_str = key.as_str().to_string();

        // Evict old circuits if at capacity
        while self.circuits.len() >= self.config.max_cached_circuits {
            self.evict_oldest();
        }

        // Store the circuit
        let cached = CachedCircuit::new(circuit, key.clone());
        let circuit_rc = Rc::clone(&cached.circuit);

        self.circuits.insert(key_str.clone(), cached);
        self.insertion_order.push(key_str.clone());

        log::info!(
            "  📦 Cached circuit for '{}' (total: {})",
            key_str,
            self.circuits.len()
        );

        circuit_rc
    }

    /// Remove a circuit by isolation key
    pub fn remove(&mut self, key: &IsolationKey) {
        let key_str = key.as_str();
        self.circuits.remove(key_str);
        self.insertion_order.retain(|k| k != key_str);
    }

    /// Evict the oldest circuit
    fn evict_oldest(&mut self) {
        if let Some(oldest_key) = self.insertion_order.first().cloned() {
            log::info!("  🗑️ Evicting oldest circuit '{}'", oldest_key);
            self.circuits.remove(&oldest_key);
            self.insertion_order.remove(0);
        }
    }

    /// Clear all cached circuits
    pub fn clear(&mut self) {
        log::info!("  🗑️ Clearing all {} cached circuits", self.circuits.len());
        self.circuits.clear();
        self.insertion_order.clear();
    }

    /// Get the number of cached circuits
    pub fn len(&self) -> usize {
        self.circuits.len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.circuits.is_empty()
    }

    /// Get statistics about the cache
    pub fn stats(&self) -> CircuitCacheStats {
        let total_requests: u32 = self.circuits.values().map(|c| c.request_count).sum();

        let oldest_age = self
            .circuits
            .values()
            .map(|c| c.created_at.elapsed())
            .max()
            .unwrap_or(Duration::ZERO);

        CircuitCacheStats {
            cached_circuits: self.circuits.len(),
            total_requests,
            oldest_circuit_age_secs: oldest_age.as_secs(),
            policy: self.config.policy,
        }
    }
}

/// Statistics about the circuit cache
#[derive(Debug, Clone)]
pub struct CircuitCacheStats {
    pub cached_circuits: usize,
    pub total_requests: u32,
    pub oldest_circuit_age_secs: u64,
    pub policy: IsolationType,
}

/// Generate a simple UUID v4 for per-request isolation
fn uuid_v4() -> String {
    use getrandom::getrandom;

    let mut bytes = [0u8; 16];
    getrandom(&mut bytes).unwrap_or_else(|_| {
        // Fallback to timestamp if getrandom fails
        let now = web_time::Instant::now();
        bytes[0..8].copy_from_slice(&(now.elapsed().as_nanos() as u64).to_le_bytes());
    });

    // Format as UUID
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_isolation_key_per_domain() {
        let key1 = IsolationKey::for_destination("example.com", 80, IsolationType::PerDomain);
        let key2 = IsolationKey::for_destination("example.com", 443, IsolationType::PerDomain);
        let key3 = IsolationKey::for_destination("other.com", 80, IsolationType::PerDomain);

        // Same domain, different ports should have same key
        assert_eq!(key1.as_str(), key2.as_str());

        // Different domains should have different keys
        assert_ne!(key1.as_str(), key3.as_str());
    }

    #[test]
    fn test_isolation_key_per_destination() {
        let key1 = IsolationKey::for_destination("example.com", 80, IsolationType::PerDestination);
        let key2 = IsolationKey::for_destination("example.com", 443, IsolationType::PerDestination);

        // Same domain, different ports should have different keys
        assert_ne!(key1.as_str(), key2.as_str());
        assert_eq!(key1.as_str(), "example.com:80");
        assert_eq!(key2.as_str(), "example.com:443");
    }

    #[test]
    fn test_isolation_key_none() {
        let key1 = IsolationKey::for_destination("example.com", 80, IsolationType::None);
        let key2 = IsolationKey::for_destination("other.com", 443, IsolationType::None);

        // All destinations should have same key
        assert_eq!(key1.as_str(), key2.as_str());
        assert_eq!(key1.as_str(), "global");
    }

    #[test]
    fn test_isolation_key_per_request() {
        let key1 = IsolationKey::for_destination("example.com", 80, IsolationType::PerRequest);
        let key2 = IsolationKey::for_destination("example.com", 80, IsolationType::PerRequest);

        // Each request should have unique key
        assert_ne!(key1.as_str(), key2.as_str());
    }
}
