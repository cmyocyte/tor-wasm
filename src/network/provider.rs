//! TCP provider implementation for WASM
//!
//! Implements Arti's networking traits using WebSocket connections
//! through our bridge server.

use super::{NetworkConfig, NetworkStats};
use crate::transport::{TransportStream, WasmMeekStream, WasmTcpStream};
use std::cell::UnsafeCell;
use std::io::Result as IoResult;
use std::net::SocketAddr;
use std::rc::Rc;

/// WASM-compatible TCP provider for Arti
///
/// Provides TCP connections by routing through a WebSocket bridge server,
/// which then connects to actual Tor relays.
pub struct WasmTcpProvider {
    /// Network configuration
    config: NetworkConfig,

    /// Network statistics (UnsafeCell is safe in single-threaded WASM)
    stats: Rc<UnsafeCell<NetworkStats>>,
}

impl WasmTcpProvider {
    /// Create a new TCP provider with default configuration
    pub fn new() -> Self {
        Self::with_config(NetworkConfig::default())
    }

    /// Create a new TCP provider with custom configuration
    pub fn with_config(config: NetworkConfig) -> Self {
        log::info!(
            "Creating WasmTcpProvider with bridge: {}",
            config.bridge_url
        );
        Self {
            config,
            stats: Rc::new(UnsafeCell::new(NetworkStats::default())),
        }
    }

    /// Returns true if the bridge URL uses meek transport (HTTP/HTTPS)
    fn is_meek(&self) -> bool {
        self.config.bridge_url.starts_with("https://") || self.config.bridge_url.starts_with("http://")
    }

    /// Connect to a relay with retry logic
    pub async fn connect_with_retry(&self, addr: &SocketAddr) -> IoResult<TransportStream> {
        let max_retries = if self.config.retry_on_failure {
            self.config.max_retries
        } else {
            0
        };

        let mut last_error = None;

        for attempt in 0..=max_retries {
            if attempt > 0 {
                log::warn!("Retry attempt {} for {}", attempt, addr);
                // Wait a bit before retrying
                gloo_timers::future::TimeoutFuture::new(1000 * attempt).await;
            }

            match self.connect_once(addr).await {
                Ok(stream) => {
                    self.record_success();
                    return Ok(stream);
                }
                Err(e) => {
                    log::warn!(
                        "Connection attempt {} failed for {}: {}",
                        attempt + 1,
                        addr,
                        e
                    );
                    last_error = Some(e);
                }
            }
        }

        self.record_failure();
        Err(last_error.unwrap())
    }

    /// Single connection attempt with timeout
    async fn connect_once(&self, addr: &SocketAddr) -> IoResult<TransportStream> {
        log::info!(
            "Connecting to relay at {} via {} (timeout: {}s)",
            addr,
            if self.is_meek() { "meek" } else { "WebSocket" },
            self.config.connect_timeout
        );

        self.record_attempt();

        let start = js_sys::Date::now();

        if self.is_meek() {
            // meek transport: HTTP POST through CDN/Worker
            let target = format!("{}:{}", addr.ip(), addr.port());
            match WasmMeekStream::connect(&self.config.bridge_url, &target).await {
                Ok(stream) => {
                    let elapsed = ((js_sys::Date::now() - start) / 1000.0) as u64;
                    log::info!("meek connected to {} in {}s", addr, elapsed);
                    self.increment_active();
                    Ok(TransportStream::Meek(stream))
                }
                Err(e) => {
                    let elapsed = ((js_sys::Date::now() - start) / 1000.0) as u64;
                    log::error!("meek connect to {} failed after {}s: {}", addr, elapsed, e);
                    Err(e)
                }
            }
        } else {
            // WebSocket transport (default)
            let url = self.config.build_url(addr);
            let connect_future = WasmTcpStream::connect(&url);

            match connect_future.await {
                Ok(stream) => {
                    let elapsed = ((js_sys::Date::now() - start) / 1000.0) as u64;
                    if elapsed > self.config.connect_timeout {
                        log::warn!(
                            "Connection to {} succeeded but took {}s (timeout was {}s)",
                            addr,
                            elapsed,
                            self.config.connect_timeout
                        );
                    } else {
                        log::info!("Successfully connected to {} in {}s", addr, elapsed);
                    }
                    self.increment_active();
                    Ok(TransportStream::WebSocket(stream))
                }
                Err(e) => {
                    let elapsed = ((js_sys::Date::now() - start) / 1000.0) as u64;
                    log::error!("Failed to connect to {} after {}s: {}", addr, elapsed, e);
                    Err(e)
                }
            }
        }
    }

    /// Get current network statistics
    pub fn get_stats(&self) -> NetworkStats {
        unsafe { (*self.stats.get()).clone() }
    }

    /// Get the bridge URL
    pub fn bridge_url(&self) -> &str {
        &self.config.bridge_url
    }

    /// Reset statistics
    pub fn reset_stats(&self) {
        unsafe {
            *self.stats.get() = NetworkStats::default();
        }
    }

    // Statistics helpers

    fn record_attempt(&self) {
        unsafe {
            (*self.stats.get()).connections_attempted += 1;
        }
    }

    fn record_success(&self) {
        unsafe {
            (*self.stats.get()).connections_successful += 1;
        }
    }

    fn record_failure(&self) {
        unsafe {
            (*self.stats.get()).connections_failed += 1;
        }
    }

    fn increment_active(&self) {
        unsafe {
            (*self.stats.get()).active_connections += 1;
        }
    }

    pub fn decrement_active(&self) {
        unsafe {
            let stats = &mut *self.stats.get();
            if stats.active_connections > 0 {
                stats.active_connections -= 1;
            }
        }
    }

    pub fn record_bytes_sent(&self, bytes: u64) {
        unsafe {
            (*self.stats.get()).bytes_sent += bytes;
        }
    }

    pub fn record_bytes_received(&self, bytes: u64) {
        unsafe {
            (*self.stats.get()).bytes_received += bytes;
        }
    }
}

impl Default for WasmTcpProvider {
    fn default() -> Self {
        Self::new()
    }
}

// Clone implementation for use in multiple contexts
impl Clone for WasmTcpProvider {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            stats: Rc::clone(&self.stats),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let provider = WasmTcpProvider::new();
        let stats = provider.get_stats();
        assert_eq!(stats.connections_attempted, 0);
    }

    #[test]
    fn test_stats_tracking() {
        let provider = WasmTcpProvider::new();

        provider.record_attempt();
        provider.record_success();

        let stats = provider.get_stats();
        assert_eq!(stats.connections_attempted, 1);
        assert_eq!(stats.connections_successful, 1);
        assert_eq!(stats.success_rate(), 100.0);
    }

    #[test]
    fn test_config_override() {
        let config = NetworkConfig {
            bridge_url: "ws://custom:9999".to_string(),
            connect_timeout: 60,
            ..Default::default()
        };

        let provider = WasmTcpProvider::with_config(config);
        assert_eq!(provider.config.bridge_url, "ws://custom:9999");
        assert_eq!(provider.config.connect_timeout, 60);
    }
}
