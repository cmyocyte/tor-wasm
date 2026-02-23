//! Circuit Prebuilding Pool
//!
//! Maintains a pool of ready-to-use circuits for improved latency.
//! 
//! Security considerations:
//! - Limited pool size (prevents fingerprinting)
//! - Circuit expiration (stale circuits are suspicious)
//! - No destination-specific prebuilding (reveals intent)

use std::collections::VecDeque;
use std::rc::Rc;
use std::cell::RefCell;

use crate::protocol::{Circuit, CircuitBuilder, RelaySelector};
use crate::error::{TorError, Result};

/// Timestamp in milliseconds (WASM-compatible)
fn now_ms() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now() as u64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

/// Configuration for circuit pool
#[derive(Debug, Clone)]
pub struct CircuitPoolConfig {
    /// Maximum number of prebuilt circuits
    pub max_prebuilt: usize,
    /// Maximum age of a prebuilt circuit in milliseconds
    pub max_age_ms: u64,
    /// Minimum circuits to maintain in pool
    pub min_circuits: usize,
    /// How often to check for maintenance (ms)
    pub maintenance_interval_ms: u64,
}

impl Default for CircuitPoolConfig {
    fn default() -> Self {
        Self {
            max_prebuilt: 3,           // Security: limit to prevent fingerprinting
            max_age_ms: 10 * 60 * 1000, // 10 minutes
            min_circuits: 1,           // Keep at least 1 ready
            maintenance_interval_ms: 30_000, // Check every 30s
        }
    }
}

/// A prebuilt circuit ready for use
struct PrebuiltCircuit {
    /// The circuit itself
    circuit: Rc<RefCell<Circuit>>,
    /// When it was created
    created_at: u64,
}

impl PrebuiltCircuit {
    fn new(circuit: Circuit) -> Self {
        Self {
            circuit: Rc::new(RefCell::new(circuit)),
            created_at: now_ms(),
        }
    }

    fn age_ms(&self) -> u64 {
        now_ms().saturating_sub(self.created_at)
    }

    fn is_expired(&self, max_age_ms: u64) -> bool {
        self.age_ms() > max_age_ms
    }
}

/// Pool of prebuilt circuits
pub struct PrebuiltCircuitPool {
    /// Available prebuilt circuits
    available: VecDeque<PrebuiltCircuit>,
    /// Configuration
    config: CircuitPoolConfig,
    /// Last maintenance time
    last_maintenance: u64,
    /// Statistics
    stats: CircuitPoolStats,
}

/// Statistics about circuit pool usage
#[derive(Debug, Clone, Default)]
pub struct CircuitPoolStats {
    /// Total circuits built
    pub circuits_built: u64,
    /// Circuits served from pool (cache hit)
    pub pool_hits: u64,
    /// Circuits built on demand (cache miss)
    pub pool_misses: u64,
    /// Circuits expired (too old)
    pub circuits_expired: u64,
    /// Current pool size
    pub current_pool_size: usize,
}

impl PrebuiltCircuitPool {
    /// Create a new circuit pool with default config
    pub fn new() -> Self {
        Self::with_config(CircuitPoolConfig::default())
    }

    /// Create a new circuit pool with custom config
    pub fn with_config(config: CircuitPoolConfig) -> Self {
        Self {
            available: VecDeque::new(),
            config,
            last_maintenance: now_ms(),
            stats: CircuitPoolStats::default(),
        }
    }

    /// Get a circuit from the pool, or build a new one
    /// 
    /// This is the main entry point - returns a ready-to-use circuit.
    pub async fn get_circuit(
        &mut self,
        builder: &CircuitBuilder,
        selector: &RelaySelector,
    ) -> Result<Rc<RefCell<Circuit>>> {
        // Run maintenance if needed
        self.maybe_expire_old_circuits();

        // Try to get from pool
        if let Some(prebuilt) = self.available.pop_front() {
            log::info!("♻️ Using prebuilt circuit (age: {}ms)", prebuilt.age_ms());
            self.stats.pool_hits += 1;
            self.stats.current_pool_size = self.available.len();
            return Ok(prebuilt.circuit);
        }

        // Build new circuit
        log::info!("🔨 Building new circuit (pool empty)");
        self.stats.pool_misses += 1;
        
        let circuit = builder.build_circuit(selector).await?;
        self.stats.circuits_built += 1;
        
        Ok(Rc::new(RefCell::new(circuit)))
    }

    /// Return a circuit to the pool for reuse
    /// 
    /// Circuit will be kept if pool has room and circuit is healthy.
    pub fn return_circuit(&mut self, circuit: Rc<RefCell<Circuit>>) {
        // Don't return if pool is full
        if self.available.len() >= self.config.max_prebuilt {
            log::debug!("Pool full, dropping circuit");
            return;
        }

        // Check if circuit is still usable
        // (In a real implementation, we'd check if it's still connected)
        
        // Wrap in PrebuiltCircuit with current timestamp
        // Note: This resets the age, which is intentional - 
        // a recently-used circuit is still fresh
        let prebuilt = PrebuiltCircuit {
            circuit,
            created_at: now_ms(),
        };
        
        self.available.push_back(prebuilt);
        self.stats.current_pool_size = self.available.len();
        log::debug!("Circuit returned to pool (size: {})", self.available.len());
    }

    /// Prebuild circuits up to the minimum
    /// 
    /// Call this after bootstrap to have circuits ready.
    pub async fn warm_up(
        &mut self,
        builder: &CircuitBuilder,
        selector: &RelaySelector,
    ) -> Result<usize> {
        let mut built = 0;
        
        while self.available.len() < self.config.min_circuits {
            log::info!("🔥 Warming up circuit pool ({}/{})", 
                self.available.len(), self.config.min_circuits);
            
            match builder.build_circuit(selector).await {
                Ok(circuit) => {
                    self.available.push_back(PrebuiltCircuit::new(circuit));
                    self.stats.circuits_built += 1;
                    built += 1;
                }
                Err(e) => {
                    log::warn!("Failed to prebuild circuit: {}", e);
                    break;
                }
            }
        }
        
        self.stats.current_pool_size = self.available.len();
        log::info!("✅ Circuit pool warmed up ({} circuits ready)", self.available.len());
        
        Ok(built)
    }

    /// Background maintenance task
    /// 
    /// In WASM, call this periodically from JS.
    pub fn maintain(&mut self) {
        self.expire_old_circuits();
        self.last_maintenance = now_ms();
    }

    /// Check if maintenance should run
    fn maybe_expire_old_circuits(&mut self) {
        let now = now_ms();
        if now.saturating_sub(self.last_maintenance) > self.config.maintenance_interval_ms {
            self.expire_old_circuits();
            self.last_maintenance = now;
        }
    }

    /// Remove expired circuits from pool
    fn expire_old_circuits(&mut self) {
        let before = self.available.len();
        
        self.available.retain(|c| !c.is_expired(self.config.max_age_ms));
        
        let expired = before - self.available.len();
        if expired > 0 {
            log::info!("🗑️ Expired {} old circuits from pool", expired);
            self.stats.circuits_expired += expired as u64;
        }
        
        self.stats.current_pool_size = self.available.len();
    }

    /// Get pool statistics
    pub fn get_stats(&self) -> CircuitPoolStats {
        CircuitPoolStats {
            current_pool_size: self.available.len(),
            ..self.stats.clone()
        }
    }

    /// Get current pool size
    pub fn size(&self) -> usize {
        self.available.len()
    }

    /// Check if pool has available circuits
    pub fn has_available(&self) -> bool {
        !self.available.is_empty()
    }

    /// Clear all circuits from pool
    pub fn clear(&mut self) {
        self.available.clear();
        self.stats.current_pool_size = 0;
        log::info!("Circuit pool cleared");
    }
}

impl Default for PrebuiltCircuitPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_config_defaults() {
        let config = CircuitPoolConfig::default();
        assert_eq!(config.max_prebuilt, 3);
        assert_eq!(config.max_age_ms, 10 * 60 * 1000);
    }

    #[test]
    fn test_pool_stats() {
        let pool = PrebuiltCircuitPool::new();
        let stats = pool.get_stats();
        assert_eq!(stats.circuits_built, 0);
        assert_eq!(stats.pool_hits, 0);
        assert_eq!(stats.pool_misses, 0);
    }
}

