//! Transport layer for Tor connections
//!
//! This module provides transport that allows WASM code to connect to
//! Tor relays through bridge infrastructure.
//!
//! Supports three transport modes:
//! - **Direct mode:** WebSocket with `?addr=1.2.3.4:9001` to a single bridge (simple, legacy)
//! - **Blinded mode:** WebSocket with encrypted relay address under Bridge B's public key.
//!   Bridge A forwards the opaque blob to Bridge B. Neither bridge alone can
//!   correlate client IP with guard relay IP.
//! - **Peer bridge mode:** WebRTC DataChannel through a volunteer's browser tab.
//!   Looks like a video call to DPI equipment. No installation required on either side.

pub mod websocket;
pub mod bridge_blind;
pub mod webrtc;

pub use websocket::WasmTcpStream;
pub use bridge_blind::blind_target_address;
pub use webrtc::WasmRtcStream;

/// Transport mode for connecting to the bridge
#[derive(Debug, Clone, PartialEq)]
pub enum TransportMode {
    /// WebSocket direct to bridge (default)
    WebSocket,
    /// WebRTC through a volunteer peer proxy (Snowflake-like)
    WebRtc,
}

/// Configuration for bridge server
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// Bridge server WebSocket URL (Bridge A in blinded mode, or single bridge in direct mode)
    pub bridge_url: String,

    /// Bridge B's X25519 public key (32 bytes). If set, enables blinded mode:
    /// the relay address is encrypted so Bridge A cannot see it.
    pub bridge_b_pubkey: Option<[u8; 32]>,

    /// Broker URL for peer bridge signaling. If set, enables WebRTC transport.
    pub broker_url: Option<String>,

    /// Preferred transport mode
    pub transport: TransportMode,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            bridge_url: "ws://localhost:8080".to_string(),
            bridge_b_pubkey: None,
            broker_url: None,
            transport: TransportMode::WebSocket,
        }
    }
}

impl BridgeConfig {
    /// Create a new bridge configuration (direct mode — single bridge)
    pub fn new(bridge_url: String) -> Self {
        Self {
            bridge_url,
            bridge_b_pubkey: None,
            broker_url: None,
            transport: TransportMode::WebSocket,
        }
    }

    /// Create a blinded bridge configuration (two-hop mode).
    ///
    /// `bridge_a_url` is the client-facing bridge (sees client IP, not guard IP).
    /// `bridge_b_pubkey` is Bridge B's X25519 public key (sees guard IP, not client IP).
    pub fn blinded(bridge_a_url: String, bridge_b_pubkey: [u8; 32]) -> Self {
        Self {
            bridge_url: bridge_a_url,
            bridge_b_pubkey: Some(bridge_b_pubkey),
            broker_url: None,
            transport: TransportMode::WebSocket,
        }
    }

    /// Create a peer bridge configuration (WebRTC through volunteer proxy).
    ///
    /// `broker_url` is the signaling broker (behind ECH).
    /// `bridge_url` is the bridge server the proxy connects to.
    /// `bridge_b_pubkey` optionally enables blinding on the bridge side.
    pub fn peer_bridge(
        broker_url: String,
        bridge_url: String,
        bridge_b_pubkey: Option<[u8; 32]>,
    ) -> Self {
        Self {
            bridge_url,
            bridge_b_pubkey,
            broker_url: Some(broker_url),
            transport: TransportMode::WebRtc,
        }
    }

    /// Build WebSocket URL for connecting to a Tor relay.
    ///
    /// In direct mode: `ws://bridge?addr=1.2.3.4:9001` (bridge sees relay IP)
    /// In blinded mode: `ws://bridge?dest=<encrypted_blob>` (bridge cannot see relay IP)
    pub fn build_url(&self, addr: &std::net::SocketAddr) -> String {
        match &self.bridge_b_pubkey {
            None => {
                format!("{}?addr={}", self.bridge_url, addr)
            }
            Some(pubkey) => {
                let addr_str = format!("{}", addr);
                match blind_target_address(&addr_str, pubkey) {
                    Ok(blob) => format!("{}?dest={}", self.bridge_url, blob),
                    Err(e) => {
                        log::error!("Bridge blinding failed, falling back to direct: {}", e);
                        format!("{}?addr={}", self.bridge_url, addr)
                    }
                }
            }
        }
    }
}

