// Serialization helpers for Tor data structures
use crate::error::{Result, TorError};
use serde::{Deserialize, Serialize};

/// Tor directory consensus data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusData {
    /// Valid-after timestamp (seconds since epoch)
    pub valid_after: u64,
    /// Valid-until timestamp (seconds since epoch)
    pub valid_until: u64,
    /// Consensus method version
    pub consensus_method: u32,
    /// List of relay fingerprints in this consensus
    pub relay_fingerprints: Vec<String>,
    /// Raw consensus document (for signature verification)
    pub raw_document: Vec<u8>,
}

impl ConsensusData {
    pub fn relay_count(&self) -> usize {
        self.relay_fingerprints.len()
    }

    pub fn is_fresh(&self) -> bool {
        let now = js_sys::Date::now() / 1000.0;
        now < self.valid_until as f64
    }
}

/// Tor relay descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayData {
    /// Relay nickname
    pub nickname: String,
    /// Relay fingerprint (hex)
    pub fingerprint: String,
    /// IP address
    pub ip_address: String,
    /// OR port (onion router port)
    pub or_port: u16,
    /// Dir port (directory port, may be 0)
    pub dir_port: u16,
    /// Relay flags
    pub flags: RelayFlags,
    /// Bandwidth in bytes/sec
    pub bandwidth: u64,
    /// ntor onion key (base64)
    pub ntor_onion_key: String,
    /// Ed25519 identity key (base64)
    pub ed25519_identity: Option<String>,
    /// Published timestamp
    pub published: u64,
}

/// Relay flags from consensus
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RelayFlags {
    pub authority: bool,
    pub bad_exit: bool,
    pub exit: bool,
    pub fast: bool,
    pub guard: bool,
    pub hsdir: bool,
    pub no_ed_consensus: bool,
    pub stable: bool,
    pub running: bool,
    pub valid: bool,
    pub v2dir: bool,
}

impl RelayFlags {
    /// Check if relay can be used as guard
    pub fn is_guard(&self) -> bool {
        self.guard && self.fast && self.stable && self.valid && self.running
    }

    /// Check if relay can be used as exit
    pub fn is_exit(&self) -> bool {
        self.exit && !self.bad_exit && self.valid && self.running
    }

    /// Check if relay can be used as middle
    pub fn is_middle(&self) -> bool {
        self.fast && self.valid && self.running
    }
}

/// Circuit state for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitData {
    /// Circuit ID
    pub id: u32,
    /// Relay fingerprints in circuit (guard, middle, exit)
    pub relay_fingerprints: Vec<String>,
    /// Circuit creation time
    pub created_at: u64,
    /// Last used timestamp
    pub last_used: u64,
    /// Circuit state
    pub state: CircuitState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CircuitState {
    /// Circuit is being built
    Building,
    /// Circuit is ready for streams
    Open,
    /// Circuit is closing
    Closing,
    /// Circuit failed
    Failed,
}

/// Client state for persistence
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientState {
    /// Selected guard nodes
    pub guards: Vec<String>,
    /// Bootstrap state
    pub bootstrap_complete: bool,
    /// Last consensus fetch time
    pub last_consensus_fetch: u64,
    /// Client preferences
    pub preferences: ClientPreferences,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientPreferences {
    /// Preferred exit countries (ISO 2-letter codes)
    pub exit_countries: Vec<String>,
    /// Excluded exit countries
    pub excluded_exit_countries: Vec<String>,
    /// Strict nodes (only use specified nodes)
    pub strict_nodes: bool,
    /// Entry nodes (fingerprints)
    pub entry_nodes: Vec<String>,
    /// Exit nodes (fingerprints)
    pub exit_nodes: Vec<String>,
}

/// Storage serializer/deserializer
pub struct StorageSerializer;

impl Default for StorageSerializer {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageSerializer {
    pub fn new() -> Self {
        Self
    }

    /// Serialize consensus data to bytes
    pub fn serialize_consensus(&self, consensus: &ConsensusData) -> Result<Vec<u8>> {
        serde_json::to_vec(consensus)
            .map_err(|e| TorError::Storage(format!("Failed to serialize consensus: {}", e)))
    }

    /// Deserialize consensus data from bytes
    pub fn deserialize_consensus(&self, bytes: &[u8]) -> Result<ConsensusData> {
        serde_json::from_slice(bytes)
            .map_err(|e| TorError::Storage(format!("Failed to deserialize consensus: {}", e)))
    }

    /// Serialize relay data to bytes
    pub fn serialize_relay(&self, relay: &RelayData) -> Result<Vec<u8>> {
        serde_json::to_vec(relay)
            .map_err(|e| TorError::Storage(format!("Failed to serialize relay: {}", e)))
    }

    /// Deserialize relay data from bytes
    pub fn deserialize_relay(&self, bytes: &[u8]) -> Result<RelayData> {
        serde_json::from_slice(bytes)
            .map_err(|e| TorError::Storage(format!("Failed to deserialize relay: {}", e)))
    }

    /// Serialize circuit data to bytes
    pub fn serialize_circuit(&self, circuit: &CircuitData) -> Result<Vec<u8>> {
        serde_json::to_vec(circuit)
            .map_err(|e| TorError::Storage(format!("Failed to serialize circuit: {}", e)))
    }

    /// Deserialize circuit data from bytes
    pub fn deserialize_circuit(&self, bytes: &[u8]) -> Result<CircuitData> {
        serde_json::from_slice(bytes)
            .map_err(|e| TorError::Storage(format!("Failed to deserialize circuit: {}", e)))
    }

    /// Serialize client state to bytes
    pub fn serialize_client_state(&self, state: &ClientState) -> Result<Vec<u8>> {
        serde_json::to_vec(state)
            .map_err(|e| TorError::Storage(format!("Failed to serialize client state: {}", e)))
    }

    /// Deserialize client state from bytes
    pub fn deserialize_client_state(&self, bytes: &[u8]) -> Result<ClientState> {
        serde_json::from_slice(bytes)
            .map_err(|e| TorError::Storage(format!("Failed to deserialize client state: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consensus_serialization() {
        let consensus = ConsensusData {
            valid_after: 1234567890,
            valid_until: 1234567890 + 3600,
            consensus_method: 31,
            relay_fingerprints: vec!["ABCD1234".to_string(), "EFGH5678".to_string()],
            raw_document: vec![1, 2, 3, 4],
        };

        let serializer = StorageSerializer::new();
        let bytes = serializer.serialize_consensus(&consensus).unwrap();
        let deserialized = serializer.deserialize_consensus(&bytes).unwrap();

        assert_eq!(consensus.valid_after, deserialized.valid_after);
        assert_eq!(consensus.relay_count(), deserialized.relay_count());
    }

    #[test]
    fn test_relay_serialization() {
        let relay = RelayData {
            nickname: "TestRelay".to_string(),
            fingerprint: "ABCD1234EFGH5678".to_string(),
            ip_address: "1.2.3.4".to_string(),
            or_port: 9001,
            dir_port: 9030,
            flags: RelayFlags {
                guard: true,
                fast: true,
                stable: true,
                valid: true,
                running: true,
                ..Default::default()
            },
            bandwidth: 1000000,
            ntor_onion_key: "base64key".to_string(),
            ed25519_identity: Some("ed25519key".to_string()),
            published: 1234567890,
        };

        let serializer = StorageSerializer::new();
        let bytes = serializer.serialize_relay(&relay).unwrap();
        let deserialized = serializer.deserialize_relay(&bytes).unwrap();

        assert_eq!(relay.nickname, deserialized.nickname);
        assert_eq!(relay.fingerprint, deserialized.fingerprint);
        assert!(deserialized.flags.is_guard());
    }

    #[test]
    fn test_relay_flags() {
        let mut flags = RelayFlags::default();
        assert!(!flags.is_guard());
        assert!(!flags.is_exit());
        assert!(!flags.is_middle());

        flags.guard = true;
        flags.fast = true;
        flags.stable = true;
        flags.valid = true;
        flags.running = true;
        assert!(flags.is_guard());
        assert!(flags.is_middle());

        flags.exit = true;
        assert!(flags.is_exit());

        flags.bad_exit = true;
        assert!(!flags.is_exit());
    }
}
