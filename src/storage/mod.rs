// Storage module for Tor data persistence
//
// Provides IndexedDB-backed storage for:
// - Tor directory consensus
// - Relay descriptors and metadata
// - Circuit pool state
// - Client state (guards, path selection, etc.)

mod indexeddb;
mod serde_helpers;
mod arti_adapter;
mod circuit_state;

pub use indexeddb::{WasmStorage, StorageStats};
pub use serde_helpers::{StorageSerializer, ConsensusData, RelayData, CircuitData, CircuitState, ClientState, RelayFlags};
pub use arti_adapter::{ArtiStateManager, GuardManager, GuardSet, Guard, GuardParams};
pub use circuit_state::{CircuitStateManager, CircuitPool, PoolConfig, CircuitStats};

use crate::error::{Result, TorError};
use std::sync::Arc;

/// High-level storage manager for Tor data
/// 
/// Wraps WasmStorage with Tor-specific methods for storing
/// and retrieving consensus, relays, circuits, etc.
pub struct TorStorageManager {
    storage: Arc<WasmStorage>,
    serializer: StorageSerializer,
}

impl TorStorageManager {
    /// Create a new storage manager
    pub async fn new() -> Result<Self> {
        let storage = Arc::new(WasmStorage::new().await?);
        let serializer = StorageSerializer::new();
        
        Ok(Self {
            storage,
            serializer,
        })
    }
    
    /// Store Tor directory consensus
    pub async fn store_consensus(&self, consensus: &ConsensusData) -> Result<()> {
        log::info!("Storing consensus with {} relays", consensus.relay_count());
        
        let bytes = self.serializer.serialize_consensus(consensus)?;
        self.storage.set("consensus", "latest", &bytes).await?;
        
        // Also store timestamp for freshness checks
        let timestamp_bytes = consensus.valid_until.to_le_bytes();
        self.storage.set("consensus", "timestamp", &timestamp_bytes).await?;
        
        Ok(())
    }
    
    /// Load Tor directory consensus
    pub async fn load_consensus(&self) -> Result<Option<ConsensusData>> {
        log::debug!("Loading consensus from storage");
        
        let bytes = match self.storage.get("consensus", "latest").await? {
            Some(b) => b,
            None => return Ok(None),
        };
        
        let consensus = self.serializer.deserialize_consensus(&bytes)?;
        
        // Check if consensus is still fresh (max 3 hours old)
        let now = js_sys::Date::now() / 1000.0;
        if now > consensus.valid_until as f64 {
            log::warn!("Stored consensus is stale, needs refresh");
            return Ok(None);
        }
        
        log::info!("Loaded consensus with {} relays", consensus.relay_count());
        Ok(Some(consensus))
    }
    
    /// Store relay descriptor
    pub async fn store_relay(&self, relay: &RelayData) -> Result<()> {
        let bytes = self.serializer.serialize_relay(relay)?;
        self.storage.set("relays", &relay.fingerprint, &bytes).await?;
        Ok(())
    }
    
    /// Load relay descriptor
    pub async fn load_relay(&self, fingerprint: &str) -> Result<Option<RelayData>> {
        let bytes = match self.storage.get("relays", fingerprint).await? {
            Some(b) => b,
            None => return Ok(None),
        };
        
        Ok(Some(self.serializer.deserialize_relay(&bytes)?))
    }
    
    /// Store multiple relays (batch operation)
    pub async fn store_relays(&self, relays: &[RelayData]) -> Result<()> {
        log::info!("Storing {} relays", relays.len());
        
        for relay in relays {
            self.store_relay(relay).await?;
        }
        
        Ok(())
    }
    
    /// Load all relays
    pub async fn load_all_relays(&self) -> Result<Vec<RelayData>> {
        let keys = self.storage.list_keys("relays").await?;
        let mut relays = Vec::with_capacity(keys.len());
        
        for key in keys {
            if let Some(relay) = self.load_relay(&key).await? {
                relays.push(relay);
            }
        }
        
        log::info!("Loaded {} relays from storage", relays.len());
        Ok(relays)
    }
    
    /// Store circuit state
    pub async fn store_circuit(&self, circuit: &CircuitData) -> Result<()> {
        let bytes = self.serializer.serialize_circuit(circuit)?;
        let key = format!("circuit_{}", circuit.id);
        self.storage.set("circuits", &key, &bytes).await?;
        Ok(())
    }
    
    /// Load circuit state
    pub async fn load_circuit(&self, circuit_id: u32) -> Result<Option<CircuitData>> {
        let key = format!("circuit_{}", circuit_id);
        let bytes = match self.storage.get("circuits", &key).await? {
            Some(b) => b,
            None => return Ok(None),
        };
        
        Ok(Some(self.serializer.deserialize_circuit(&bytes)?))
    }
    
    /// Delete circuit (when closed)
    pub async fn delete_circuit(&self, circuit_id: u32) -> Result<()> {
        let key = format!("circuit_{}", circuit_id);
        self.storage.delete("circuits", &key).await?;
        Ok(())
    }
    
    /// Store client state (guards, path selection, etc.)
    pub async fn store_client_state(&self, state: &ClientState) -> Result<()> {
        let bytes = self.serializer.serialize_client_state(state)?;
        self.storage.set("state", "client", &bytes).await?;
        Ok(())
    }
    
    /// Load client state
    pub async fn load_client_state(&self) -> Result<Option<ClientState>> {
        let bytes = match self.storage.get("state", "client").await? {
            Some(b) => b,
            None => return Ok(None),
        };
        
        Ok(Some(self.serializer.deserialize_client_state(&bytes)?))
    }
    
    /// Get storage statistics
    pub async fn get_stats(&self) -> Result<StorageStats> {
        self.storage.get_stats().await
    }
    
    /// Clear all Tor data (useful for testing or reset)
    pub async fn clear_all(&self) -> Result<()> {
        log::warn!("Clearing ALL Tor storage data");
        
        self.storage.clear("consensus").await?;
        self.storage.clear("relays").await?;
        self.storage.clear("circuits").await?;
        self.storage.clear("cache").await?;
        self.storage.clear("state").await?;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;
    
    wasm_bindgen_test_configure!(run_in_browser);
    
    #[wasm_bindgen_test]
    async fn test_storage_manager_init() {
        let manager = TorStorageManager::new().await.unwrap();
        let stats = manager.get_stats().await.unwrap();
        assert_eq!(stats.total_entries(), 0);
    }
}

