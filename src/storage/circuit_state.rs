// Circuit state management for persistence
//
// Manages circuit pool state, allowing circuits to be
// saved and restored across browser sessions.

use super::{ArtiStateManager, CircuitData, CircuitState};
use crate::error::{Result, TorError};
use std::sync::Arc;
use serde::{Serialize, Deserialize};

/// Circuit pool manager for persistent circuit state
pub struct CircuitStateManager {
    state: Arc<ArtiStateManager>,
}

impl CircuitStateManager {
    /// Create a new circuit state manager
    pub fn new(state: Arc<ArtiStateManager>) -> Self {
        Self { state }
    }
    
    /// Save circuit state
    pub async fn save_circuit(&self, circuit: &CircuitData) -> Result<()> {
        let key = format!("circuit_{}", circuit.id);
        log::debug!("Saving circuit {}", circuit.id);
        self.state.store(&key, circuit).await
    }
    
    /// Load circuit state
    pub async fn load_circuit(&self, circuit_id: u32) -> Result<Option<CircuitData>> {
        let key = format!("circuit_{}", circuit_id);
        self.state.load(&key).await
    }
    
    /// Delete circuit state
    pub async fn delete_circuit(&self, circuit_id: u32) -> Result<()> {
        let key = format!("circuit_{}", circuit_id);
        log::debug!("Deleting circuit {}", circuit_id);
        self.state.delete(&key).await
    }
    
    /// Load all circuits
    pub async fn load_all_circuits(&self) -> Result<Vec<CircuitData>> {
        let keys = self.state.list_keys().await?;
        let mut circuits = Vec::new();
        
        for key in keys {
            if key.starts_with("circuit_") {
                if let Some(circuit) = self.state.load::<CircuitData>(&key).await? {
                    circuits.push(circuit);
                }
            }
        }
        
        log::debug!("Loaded {} circuits from storage", circuits.len());
        Ok(circuits)
    }
    
    /// Save circuit pool state
    pub async fn save_pool(&self, pool: &CircuitPool) -> Result<()> {
        log::info!("Saving circuit pool with {} circuits", pool.circuits.len());
        self.state.store("circuit_pool", pool).await
    }
    
    /// Load circuit pool state
    pub async fn load_pool(&self) -> Result<Option<CircuitPool>> {
        self.state.load("circuit_pool").await
    }
    
    /// Prune old/failed circuits
    pub async fn prune_old_circuits(&self, max_age_seconds: u64) -> Result<usize> {
        let circuits = self.load_all_circuits().await?;
        let now = (js_sys::Date::now() / 1000.0) as u64;
        let mut pruned = 0;
        
        for circuit in circuits {
            let age = now.saturating_sub(circuit.created_at);
            
            // Prune if too old or in failed state
            if age > max_age_seconds || matches!(circuit.state, CircuitState::Failed) {
                self.delete_circuit(circuit.id).await?;
                pruned += 1;
            }
        }
        
        if pruned > 0 {
            log::info!("Pruned {} old/failed circuits", pruned);
        }
        
        Ok(pruned)
    }
    
    /// Get circuit statistics
    pub async fn get_stats(&self) -> Result<CircuitStats> {
        let circuits = self.load_all_circuits().await?;
        
        let mut stats = CircuitStats::default();
        stats.total = circuits.len();
        
        for circuit in circuits {
            match circuit.state {
                CircuitState::Building => stats.building += 1,
                CircuitState::Open => stats.open += 1,
                CircuitState::Closing => stats.closing += 1,
                CircuitState::Failed => stats.failed += 1,
            }
        }
        
        Ok(stats)
    }
}

/// Circuit pool state
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CircuitPool {
    /// Active circuits
    pub circuits: Vec<u32>, // Circuit IDs
    /// Pool configuration
    pub config: PoolConfig,
    /// Last update timestamp
    pub last_updated: u64,
}

/// Circuit pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolConfig {
    /// Target number of circuits to maintain
    pub target_size: usize,
    /// Maximum circuit age before replacement (seconds)
    pub max_age: u64,
    /// Whether to pre-build circuits
    pub prebuild: bool,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            target_size: 3,
            max_age: 10 * 60, // 10 minutes
            prebuild: true,
        }
    }
}

/// Circuit statistics
#[derive(Debug, Default, Clone)]
pub struct CircuitStats {
    pub total: usize,
    pub building: usize,
    pub open: usize,
    pub closing: usize,
    pub failed: usize,
}

impl CircuitStats {
    pub fn usable(&self) -> usize {
        self.open
    }
    
    pub fn in_progress(&self) -> usize {
        self.building + self.closing
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_pool_config_defaults() {
        let config = PoolConfig::default();
        assert_eq!(config.target_size, 3);
        assert_eq!(config.max_age, 10 * 60);
        assert!(config.prebuild);
    }
    
    #[test]
    fn test_circuit_stats() {
        let mut stats = CircuitStats::default();
        stats.open = 3;
        stats.building = 1;
        stats.failed = 2;
        
        assert_eq!(stats.usable(), 3);
        assert_eq!(stats.in_progress(), 1);
        assert_eq!(stats.total, 0); // Only counts what's explicitly set
    }
}

