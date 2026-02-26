//! Network adapter layer for Arti
//!
//! Provides WASM-compatible implementations of Arti's networking traits,
//! using WebSocket connections through our bridge server to connect to
//! real Tor relays.

mod connection_manager;
mod error_handling;
mod provider;
mod tls;

pub use connection_manager::ConnectionManager;
pub use error_handling::{NetworkError, RecoveryStrategy};
pub use provider::WasmTcpProvider;
pub use tls::{CertificateInfo, WasmTlsConnector, WasmTlsStream};

use std::net::SocketAddr;

/// Configuration for network operations
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// WebSocket bridge URL
    pub bridge_url: String,

    /// Connection timeout in seconds
    pub connect_timeout: u64,

    /// Maximum concurrent connections
    pub max_connections: usize,

    /// Enable connection pooling
    pub enable_pooling: bool,

    /// Retry failed connections
    pub retry_on_failure: bool,

    /// Maximum retries
    pub max_retries: u32,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            bridge_url: "ws://localhost:8080".to_string(),
            connect_timeout: 10, // Reduced to 10s for faster failover
            max_connections: 50,
            enable_pooling: true,
            retry_on_failure: true,
            max_retries: 3,
        }
    }
}

impl NetworkConfig {
    /// Create config with custom bridge URL
    pub fn with_bridge(bridge_url: impl Into<String>) -> Self {
        Self {
            bridge_url: bridge_url.into(),
            ..Default::default()
        }
    }

    /// Build WebSocket URL for connecting to a relay
    pub fn build_url(&self, addr: &SocketAddr) -> String {
        format!("{}?addr={}:{}", self.bridge_url, addr.ip(), addr.port())
    }
}

/// Network statistics
#[derive(Debug, Default, Clone)]
pub struct NetworkStats {
    /// Total connections attempted
    pub connections_attempted: u64,

    /// Successful connections
    pub connections_successful: u64,

    /// Failed connections
    pub connections_failed: u64,

    /// Currently active connections
    pub active_connections: usize,

    /// Total bytes sent
    pub bytes_sent: u64,

    /// Total bytes received
    pub bytes_received: u64,
}

impl NetworkStats {
    /// Get success rate as percentage
    pub fn success_rate(&self) -> f64 {
        if self.connections_attempted == 0 {
            return 0.0;
        }
        (self.connections_successful as f64 / self.connections_attempted as f64) * 100.0
    }

    /// Get failure rate as percentage
    pub fn failure_rate(&self) -> f64 {
        if self.connections_attempted == 0 {
            return 0.0;
        }
        (self.connections_failed as f64 / self.connections_attempted as f64) * 100.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_config() {
        let config = NetworkConfig::default();
        assert_eq!(config.bridge_url, "ws://localhost:8080");
        assert_eq!(config.connect_timeout, 30);
    }

    #[test]
    fn test_build_url() {
        let config = NetworkConfig::default();
        let addr: SocketAddr = "1.2.3.4:9001".parse().unwrap();
        let url = config.build_url(&addr);
        assert_eq!(url, "ws://localhost:8080?addr=1.2.3.4:9001");
    }

    #[test]
    fn test_stats() {
        let mut stats = NetworkStats::default();
        stats.connections_attempted = 10;
        stats.connections_successful = 8;
        stats.connections_failed = 2;

        assert_eq!(stats.success_rate(), 80.0);
        assert_eq!(stats.failure_rate(), 20.0);
    }
}
