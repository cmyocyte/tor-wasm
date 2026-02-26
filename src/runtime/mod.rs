//! WASM-compatible runtime for Arti
//!
//! This module provides a custom runtime implementation that allows Arti
//! to run in WebAssembly environments.

use std::time::{Duration, Instant, SystemTime};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;

mod sleep;
mod spawn;
mod time;
mod stubs;
pub mod tcp;
pub mod compat;
// mod traits_impl; // Temporarily disabled until tor-rtcompat is fully WASM-ready

pub use sleep::WasmSleep;
pub use time::WasmCoarseInstant;
pub use stubs::{WasmUdpSocket, WasmUnixStream, WasmListener};
pub use compat::{TcpStream, TcpConnectFuture, WasmTlsConnector, WasmBlockingHandle};
pub use tcp::WasmTcpListener;

/// WASM-compatible runtime for Arti
///
/// This runtime provides all the necessary traits for Arti to function
/// in a WebAssembly environment, using browser APIs instead of OS primitives.
#[derive(Debug, Clone)]
pub struct WasmRuntime {
    // Bridge configuration for WebSocket connections
    bridge_url: String,
    // Optional meek fallback URL (CDN-tunneled HTTP transport)
    meek_url: Option<String>,
}

impl WasmRuntime {
    /// Create a new WASM runtime with default bridge URL
    pub fn new() -> Self {
        Self::with_bridge_url("ws://localhost:8080".to_string())
    }

    /// Create a new WASM runtime with custom bridge URL
    pub fn with_bridge_url(bridge_url: String) -> Self {
        log::info!("Creating WasmRuntime with bridge: {}", bridge_url);
        Self { bridge_url, meek_url: None }
    }

    /// Create a new WASM runtime with WebSocket bridge + meek fallback
    pub fn with_meek_fallback(bridge_url: String, meek_url: String) -> Self {
        log::info!("Creating WasmRuntime with bridge: {} + meek fallback: {}", bridge_url, meek_url);
        Self { bridge_url, meek_url: Some(meek_url) }
    }

    /// Get the bridge URL
    pub fn bridge_url(&self) -> &str {
        &self.bridge_url
    }

    /// Get the meek fallback URL (if configured)
    pub fn meek_url(&self) -> Option<&str> {
        self.meek_url.as_deref()
    }
}

impl Default for WasmRuntime {
    fn default() -> Self {
        Self::new()
    }
}

// Re-export for convenience
pub use spawn::WasmSpawner;

