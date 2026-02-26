// Arti StateMgr trait adapter for our IndexedDB storage
//
// This adapter allows Arti to use browser IndexedDB as if it were
// a filesystem-based state manager.

use super::WasmStorage;
use crate::error::{Result, TorError};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::sync::Arc;

/// Adapter that implements state management for Arti
///
/// This wraps our IndexedDB storage and provides the interface
/// that Arti expects for persisting state.
pub struct ArtiStateManager {
    storage: Arc<WasmStorage>,
}

impl ArtiStateManager {
    /// Create a new Arti state manager
    pub async fn new() -> Result<Self> {
        let storage = Arc::new(WasmStorage::new().await?);
        Ok(Self { storage })
    }

    /// Create from existing storage
    pub fn from_storage(storage: Arc<WasmStorage>) -> Self {
        Self { storage }
    }

    /// Load state by key
    ///
    /// Generic method that can load any serializable type
    pub async fn load<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        log::debug!("Loading state for key: {}", key);

        let bytes = match self.storage.get("state", key).await? {
            Some(b) => b,
            None => return Ok(None),
        };

        let value: T = serde_json::from_slice(&bytes)
            .map_err(|e| TorError::Storage(format!("Failed to deserialize state: {}", e)))?;

        Ok(Some(value))
    }

    /// Store state by key
    ///
    /// Generic method that can store any serializable type
    pub async fn store<T: Serialize>(&self, key: &str, value: &T) -> Result<()> {
        log::debug!("Storing state for key: {}", key);

        let bytes = serde_json::to_vec(value)
            .map_err(|e| TorError::Storage(format!("Failed to serialize state: {}", e)))?;

        self.storage.set("state", key, &bytes).await?;
        Ok(())
    }

    /// Delete state by key
    pub async fn delete(&self, key: &str) -> Result<()> {
        log::debug!("Deleting state for key: {}", key);
        self.storage.delete("state", key).await?;
        Ok(())
    }

    /// List all state keys
    pub async fn list_keys(&self) -> Result<Vec<String>> {
        self.storage.list_keys("state").await
    }

    /// Check if key exists
    pub async fn exists(&self, key: &str) -> Result<bool> {
        Ok(self.storage.get("state", key).await?.is_some())
    }
}

/// Guard node manager for persistent guard selection
///
/// Implements Tor's guard node selection and persistence according
/// to the Tor specification (guard rotation, staleness, etc.)
pub struct GuardManager {
    state: Arc<ArtiStateManager>,
}

impl GuardManager {
    /// Create a new guard manager
    pub async fn new(state: Arc<ArtiStateManager>) -> Result<Self> {
        Ok(Self { state })
    }

    /// Load persisted guard nodes
    pub async fn load_guards(&self) -> Result<Option<GuardSet>> {
        self.state.load("guards").await
    }

    /// Store guard nodes
    pub async fn store_guards(&self, guards: &GuardSet) -> Result<()> {
        log::info!("Storing {} guard nodes", guards.guards.len());
        self.state.store("guards", guards).await
    }

    /// Add a guard to the set
    pub async fn add_guard(&self, guard: Guard) -> Result<()> {
        let mut guards = self.load_guards().await?.unwrap_or_default();

        // Check if guard already exists
        if guards
            .guards
            .iter()
            .any(|g| g.fingerprint == guard.fingerprint)
        {
            log::debug!("Guard {} already exists", guard.fingerprint);
            return Ok(());
        }

        guards.guards.push(guard);
        guards.last_modified = current_timestamp();

        self.store_guards(&guards).await
    }

    /// Remove a guard from the set
    pub async fn remove_guard(&self, fingerprint: &str) -> Result<()> {
        let mut guards = self.load_guards().await?.unwrap_or_default();

        guards.guards.retain(|g| g.fingerprint != fingerprint);
        guards.last_modified = current_timestamp();

        self.store_guards(&guards).await
    }

    /// Mark a guard as used
    pub async fn mark_used(&self, fingerprint: &str) -> Result<()> {
        let mut guards = self.load_guards().await?.unwrap_or_default();

        if let Some(guard) = guards
            .guards
            .iter_mut()
            .find(|g| g.fingerprint == fingerprint)
        {
            guard.last_used = current_timestamp();
            guard.use_count += 1;
        }

        self.store_guards(&guards).await
    }

    /// Mark a guard as failed
    pub async fn mark_failed(&self, fingerprint: &str) -> Result<()> {
        let mut guards = self.load_guards().await?.unwrap_or_default();

        if let Some(guard) = guards
            .guards
            .iter_mut()
            .find(|g| g.fingerprint == fingerprint)
        {
            guard.failure_count += 1;
            guard.last_failed = Some(current_timestamp());

            // If too many failures, mark as unreachable
            if guard.failure_count > 3 {
                guard.unreachable = true;
                log::warn!(
                    "Guard {} marked unreachable after {} failures",
                    fingerprint,
                    guard.failure_count
                );
            }
        }

        self.store_guards(&guards).await
    }

    /// Get usable guards (not unreachable, not stale)
    pub async fn get_usable_guards(&self) -> Result<Vec<Guard>> {
        let guards = self.load_guards().await?.unwrap_or_default();
        let now = current_timestamp();

        Ok(guards
            .guards
            .into_iter()
            .filter(|g| !g.unreachable && !is_stale(g.added_at, now))
            .collect())
    }

    /// Prune stale guards
    pub async fn prune_stale(&self) -> Result<usize> {
        let mut guards = self.load_guards().await?.unwrap_or_default();
        let now = current_timestamp();
        let initial_count = guards.guards.len();

        guards.guards.retain(|g| !is_stale(g.added_at, now));

        let pruned = initial_count - guards.guards.len();
        if pruned > 0 {
            log::info!("Pruned {} stale guards", pruned);
            guards.last_modified = now;
            self.store_guards(&guards).await?;
        }

        Ok(pruned)
    }
}

/// Set of guard nodes
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GuardSet {
    /// List of guard nodes
    pub guards: Vec<Guard>,
    /// When this set was last modified
    pub last_modified: u64,
    /// Guard selection parameters
    pub params: GuardParams,
}

/// Individual guard node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Guard {
    /// Relay fingerprint
    pub fingerprint: String,
    /// Relay nickname
    pub nickname: String,
    /// IP address
    pub address: String,
    /// OR port
    pub port: u16,
    /// When this guard was added
    pub added_at: u64,
    /// When this guard was last used
    pub last_used: u64,
    /// Number of times used
    pub use_count: u64,
    /// Number of failures
    pub failure_count: u32,
    /// Last failure timestamp
    pub last_failed: Option<u64>,
    /// Whether guard is currently unreachable
    pub unreachable: bool,
}

/// Guard selection parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardParams {
    /// Maximum number of guards to use
    pub max_guards: usize,
    /// How long before a guard is considered stale (seconds)
    pub guard_lifetime: u64,
    /// How long to wait before retrying a failed guard (seconds)
    pub retry_timeout: u64,
}

impl Default for GuardParams {
    fn default() -> Self {
        Self {
            max_guards: 3,
            guard_lifetime: 90 * 24 * 60 * 60, // 90 days
            retry_timeout: 60 * 60,            // 1 hour
        }
    }
}

/// Get current timestamp in seconds
fn current_timestamp() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

/// Check if a guard is stale based on its age
fn is_stale(added_at: u64, now: u64) -> bool {
    const GUARD_LIFETIME: u64 = 90 * 24 * 60 * 60; // 90 days
    now - added_at > GUARD_LIFETIME
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guard_staleness() {
        let now = current_timestamp();
        let recent = now - (10 * 24 * 60 * 60); // 10 days ago
        let old = now - (100 * 24 * 60 * 60); // 100 days ago

        assert!(!is_stale(recent, now));
        assert!(is_stale(old, now));
    }

    #[test]
    fn test_guard_params_defaults() {
        let params = GuardParams::default();
        assert_eq!(params.max_guards, 3);
        assert_eq!(params.guard_lifetime, 90 * 24 * 60 * 60);
    }
}
