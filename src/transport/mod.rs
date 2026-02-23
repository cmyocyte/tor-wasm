//! Transport layer for Tor connections
//!
//! This module provides WebSocket-based transport that allows WASM code
//! to connect to Tor relays through a bridge server.

pub mod websocket;

pub use websocket::WasmTcpStream;

/// Configuration for bridge server
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// Bridge server WebSocket URL
    pub bridge_url: String,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            // Default to localhost for development
            // In production, this would be your deployed bridge
            bridge_url: "ws://localhost:8080".to_string(),
        }
    }
}

impl BridgeConfig {
    /// Create a new bridge configuration
    pub fn new(bridge_url: String) -> Self {
        Self { bridge_url }
    }
    
    /// Build WebSocket URL for connecting to a Tor relay
    pub fn build_url(&self, addr: &std::net::SocketAddr) -> String {
        format!("{}?addr={}", self.bridge_url, addr)
    }
}

