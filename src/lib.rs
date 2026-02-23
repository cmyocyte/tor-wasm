//! # Tor WASM Client
//!
//! A minimal Tor client implementation compiled to WebAssembly.
//! 
//! This is a ground-up implementation designed specifically for WASM,
//! using only browser APIs (WebSocket, WebCrypto) instead of OS primitives.
//!
//! ## Architecture
//!
//! ```text
//! TorClient (WASM)
//!   ↓
//! Circuit Manager
//!   ↓
//! WebSocket Transport (via JS)
//!   ↓
//! Tor Network
//! ```
//!
//! ## Features
//!
//! - **No OS dependencies**: Pure WASM, uses only browser APIs
//! - **Lightweight**: Minimal implementation focused on RPC calls
//! - **Fast**: Compiled Rust, near-native performance
//! - **Secure**: Uses WebCrypto for all cryptographic operations

use wasm_bindgen::prelude::*;
use web_sys::console;
use std::sync::Arc;

// Modules
pub mod protocol;
mod circuit;
mod error;
pub mod storage;
pub mod network;
pub mod runtime;
pub mod transport;
pub mod isolation;
pub mod guards;
pub mod relay_verifier;
pub mod traffic_shaping;
pub mod rate_limiter;
pub mod circuit_pool;
pub mod stream_mux;
pub mod connection_pool;
pub mod parallel_builder;
pub mod cooperative;
pub mod padding;
pub mod congestion;
pub mod fingerprint_defense;
// mod arti_impls; // Temporarily disabled until arti dependencies are WASM-ready

// Security tests (only compiled in test mode)
#[cfg(test)]
mod security_tests;

pub use error::{TorError, Result};
pub use runtime::WasmRuntime;
pub use transport::{WasmTcpStream, BridgeConfig};
pub use storage::{
    TorStorageManager, WasmStorage, 
    ConsensusData, RelayData, CircuitData, CircuitState, ClientState, RelayFlags,
    ArtiStateManager, GuardManager, GuardSet, Guard,
    CircuitStateManager, CircuitPool, CircuitStats,
};
pub use network::{
    WasmTcpProvider, WasmTlsConnector, ConnectionManager,
    NetworkConfig, NetworkStats,
};
pub use isolation::{
    IsolationType, IsolationConfig, IsolationKey, 
    CircuitCache, CircuitCacheStats,
};
pub use guards::{
    GuardState, GuardPersistence, FailureInfo,
    GUARD_LIFETIME_SECS, MIN_GUARDS, MAX_GUARDS,
};
pub use relay_verifier::{
    RelayVerifier, RelayVerifierStats, BandwidthObservation, VerifyError,
};
pub use traffic_shaping::{
    TrafficShaper, TrafficShapingConfig, TrafficShapingStats,
};
pub use rate_limiter::{
    RateLimiter, RateLimiterConfig, RateLimiterStats,
};
pub use circuit_pool::{
    PrebuiltCircuitPool, CircuitPoolConfig, CircuitPoolStats,
};
pub use stream_mux::{
    StreamMultiplexer, StreamMuxConfig, StreamMuxStats,
};
pub use connection_pool::{
    ConnectionPool, ConnectionPoolConfig, ConnectionPoolStats, PooledConnection,
};
pub use parallel_builder::{
    ParallelCircuitBuilder, ParallelBuilderConfig, ParallelBuilderStats,
};
pub use cooperative::{
    CooperativeCircuit, CooperativeStream, CooperativeTlsStream,
    StreamHandle, SchedulerError, SchedulerStats, SchedulerDriver,
    PendingWork, WorkResult,
    drive_scheduler, drive_until_complete, open_cooperative_stream,
    MAX_CELLS_PER_STREAM, MAX_TOTAL_QUEUED_CELLS, MAX_STREAMS_PER_CIRCUIT,
    MAX_INCOMING_BUFFER, DEFAULT_RECEIVE_TIMEOUT_MS, DEFAULT_SEND_TIMEOUT_MS,
};
pub use padding::{
    PaddingScheduler, PaddingConfig, PaddingStats, PaddingState, PaddingCommand,
};
pub use congestion::{
    CongestionController, CongestionAlgorithm, CongestionStats,
    RttEstimator, RttStats, RttSample,
};

/// Parse a URL into (host, port, path, is_https)
fn parse_url(url: &str) -> std::result::Result<(String, u16, String, bool), String> {
    // Simple URL parser for http:// and https:// URLs
    let url = url.trim();
    
    // Detect scheme
    let (without_scheme, is_https) = if url.starts_with("http://") {
        (&url[7..], false)
    } else if url.starts_with("https://") {
        (&url[8..], true)
    } else {
        // Assume HTTP if no scheme
        (url, false)
    };
    
    // Split host/path
    let (host_port, path) = if let Some(slash_pos) = without_scheme.find('/') {
        (&without_scheme[..slash_pos], &without_scheme[slash_pos..])
    } else {
        (without_scheme, "/")
    };
    
    // Split host:port
    let (host, port) = if let Some(colon_pos) = host_port.rfind(':') {
        let host = &host_port[..colon_pos];
        let port_str = &host_port[colon_pos + 1..];
        let port = port_str.parse::<u16>()
            .map_err(|_| format!("Invalid port: {}", port_str))?;
        (host.to_string(), port)
    } else {
        // Default ports based on scheme
        let default_port = if is_https { 443 } else { 80 };
        (host_port.to_string(), default_port)
    };
    
    Ok((host, port, path.to_string(), is_https))
}

/// Initialize the Tor WASM client
/// 
/// This sets up logging and any global state needed.
#[wasm_bindgen(start)]
pub fn init() {
    // Set up panic hook for better error messages
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();

    // Initialize logging
    console_log::init_with_level(log::Level::Info).unwrap();
    
    log::info!("Tor WASM client initialized");
}

/// Main Tor client
#[wasm_bindgen]
pub struct TorClient {
    // Network provider
    network: Arc<WasmTcpProvider>,
    
    // Storage
    storage: Arc<WasmStorage>,
    
    // Current consensus
    consensus: Option<Arc<protocol::Consensus>>,
    
    // Current state
    bootstrapped: bool,
    
    // Circuit cache for isolation
    circuit_cache: CircuitCache,
    
    // Guard node state (persistent across sessions)
    guard_state: GuardState,
    
    // Guard persistence manager
    guard_persistence: GuardPersistence,
    
    // Circuit builder (cached)
    circuit_builder: Option<protocol::CircuitBuilder>,
    
    // Relay selector (cached)
    relay_selector: Option<protocol::RelaySelector>,
    
    // Rate limiter (abuse prevention)
    rate_limiter: RateLimiter,
}

#[wasm_bindgen]
impl TorClient {
    /// Create a new Tor client with custom bridge URL
    #[wasm_bindgen(constructor)]
    pub async fn new(bridge_url: Option<String>) -> std::result::Result<TorClient, JsValue> {
        log::info!("Creating new Tor client");
        
        // Initialize storage
        let storage = Arc::new(
            WasmStorage::new()
                .await
                .map_err(|e| JsValue::from_str(&format!("Storage init failed: {}", e)))?
        );
        
        // Initialize network provider
        let network_config = if let Some(url) = bridge_url {
            network::NetworkConfig::with_bridge(url)
        } else {
            network::NetworkConfig::default()
        };
        
        let network = Arc::new(WasmTcpProvider::with_config(network_config));
        
        log::info!("✅ Tor client created");
        
        // Initialize circuit cache with default isolation (per-domain)
        let circuit_cache = CircuitCache::new(IsolationConfig::default());
        log::info!("  🔒 Circuit isolation: {:?}", circuit_cache.policy());
        
        // Initialize guard persistence
        let guard_persistence = GuardPersistence::new();
        let guard_state = match guard_persistence.load().await {
            Ok(state) => {
                if state.guards.is_empty() {
                    log::info!("  🛡️ No saved guards, will select on bootstrap");
                } else {
                    log::info!("  🛡️ Loaded {} guards from storage", state.guards.len());
                }
                state
            }
            Err(e) => {
                log::warn!("  ⚠️ Failed to load guard state: {}", e);
                GuardState::new()
            }
        };
        
        Ok(Self {
            network,
            storage,
            consensus: None,
            bootstrapped: false,
            circuit_cache,
            guard_state,
            guard_persistence,
            circuit_builder: None,
            relay_selector: None,
            rate_limiter: RateLimiter::new(),
        })
    }
    
    /// Bootstrap the Tor client
    /// 
    /// This fetches the network consensus and prepares circuits.
    #[wasm_bindgen]
    pub async fn bootstrap(&mut self) -> std::result::Result<(), JsValue> {
        log::info!("🔄 Bootstrapping Tor client...");
        
        // 1. Create directory manager
        let mut dir_mgr = protocol::DirectoryManager::new(
            Arc::clone(&self.network),
            Arc::clone(&self.storage),
        );
        
        // 2. Fetch directory consensus
        log::info!("📡 Fetching directory consensus...");
        let consensus = dir_mgr
            .fetch_consensus()
            .await
            .map_err(|e| JsValue::from_str(&format!("Consensus fetch failed: {}", e)))?;
        
        log::info!("✅ Fetched consensus with {} relays", consensus.relays.len());
        
        // ⚠️ SECURITY NOTE: The bridge server pre-parses the consensus
        // We cannot verify directory authority signatures in this architecture
        // This means we're trusting the bridge server's relay data
        // Self-hosting your own bridge mitigates this risk
        log::warn!("⚠️ Consensus received from bridge (not directly verified)");
        log::warn!("⚠️ For maximum security, self-host your own bridge server");
        
        // Validate relay data looks legitimate
        let valid_fingerprints = consensus.relays.iter()
            .filter(|r| {
                // Check fingerprint is valid hex and correct length
                r.fingerprint.len() >= 20 && 
                r.fingerprint.chars().all(|c| c.is_ascii_hexdigit() || c == '+' || c == '/' || c == '=')
            })
            .count();
        
        if valid_fingerprints < consensus.relays.len() / 2 {
            log::error!("❌ Too many invalid relay fingerprints - possible attack!");
            return Err(JsValue::from_str("Consensus validation failed: invalid relay fingerprints"));
        }
        
        // Count relay types
        let guards = consensus.relays.iter().filter(|r| r.is_guard()).count();
        let exits = consensus.relays.iter().filter(|r| r.is_exit()).count();
        let running = consensus.relays.iter().filter(|r| r.is_running()).count();
        
        log::info!("📊 Relay stats:");
        log::info!("  Total: {}", consensus.relays.len());
        log::info!("  Valid fingerprints: {}", valid_fingerprints);
        log::info!("  Running: {}", running);
        log::info!("  Guards: {}", guards);
        log::info!("  Exits: {}", exits);
        
        // Store consensus
        let consensus_arc = Arc::new(consensus);
        self.consensus = Some(Arc::clone(&consensus_arc));
        
        // 3. Update guard selection if needed
        log::info!("🛡️ Checking guard state...");
        self.guard_state.cleanup(); // Clean up expired entries
        
        if self.guard_state.needs_refresh() {
            log::info!("  🔄 Selecting new guards...");
            self.guard_state.select_guards(&consensus_arc.relays)?;
            
            // Save updated guard state
            if let Err(e) = self.guard_persistence.save(&self.guard_state).await {
                log::warn!("  ⚠️ Failed to save guard state: {}", e);
            }
        } else {
            log::info!("  ✅ Using {} existing guards (valid for {} more days)", 
                self.guard_state.guards.len(),
                (self.guard_state.rotate_after.saturating_sub(
                    web_time::SystemTime::now()
                        .duration_since(web_time::SystemTime::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0)
                )) / (24 * 60 * 60)
            );
        }
        
        // 4. Create relay selector with guard preferences
        log::info!("🎯 Creating relay selector...");
        let mut selector = protocol::RelaySelector::new(consensus_arc.relays.clone());
        selector.set_preferred_guards(self.guard_state.usable_guards()
            .into_iter()
            .map(|s| s.clone())
            .collect());
        self.relay_selector = Some(selector);
        
        // 5. Create circuit builder
        log::info!("🔨 Creating circuit builder...");
        self.circuit_builder = Some(protocol::CircuitBuilder::new(
            Arc::clone(&self.network)
        ));
        
        self.bootstrapped = true;
        log::info!("✅ Tor client bootstrapped and ready!");
        
        Ok(())
    }
    
    /// Get client status
    #[wasm_bindgen]
    pub fn get_status(&self) -> JsValue {
        let cache_stats = self.circuit_cache.stats();
        let now = web_time::SystemTime::now()
            .duration_since(web_time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        
        let days_until_guard_rotation = if self.guard_state.rotate_after > now {
            (self.guard_state.rotate_after - now) / (24 * 60 * 60)
        } else {
            0
        };
        
        let status = if let Some(ref consensus) = self.consensus {
            serde_wasm_bindgen::to_value(&serde_json::json!({
                "bootstrapped": self.bootstrapped,
                "consensus_relay_count": consensus.relays.len(),
                "cached_circuits": cache_stats.cached_circuits,
                "total_requests": cache_stats.total_requests,
                "isolation_policy": format!("{:?}", cache_stats.policy),
                "consensus_valid": consensus.is_valid(),
                "consensus_fresh": consensus.is_fresh(),
                "guard_count": self.guard_state.guards.len(),
                "usable_guards": self.guard_state.usable_guard_count(),
                "days_until_guard_rotation": days_until_guard_rotation,
            })).unwrap()
        } else {
            serde_wasm_bindgen::to_value(&serde_json::json!({
                "bootstrapped": self.bootstrapped,
                "consensus_relay_count": 0,
                "cached_circuits": 0,
                "isolation_policy": format!("{:?}", cache_stats.policy),
                "guard_count": self.guard_state.guards.len(),
            })).unwrap()
        };
        
        status
    }
    
    /// Build a new circuit
    #[wasm_bindgen]
    pub async fn build_circuit(&mut self) -> std::result::Result<usize, JsValue> {
        log::info!("🔨 build_circuit() called");
        
        // Rate limiting check
        if !self.rate_limiter.can_create_circuit() {
            log::error!("❌ Rate limited: too many circuits created recently");
            return Err(JsValue::from_str("Rate limited: too many circuit requests. Please wait."));
        }
        
        if !self.bootstrapped {
            log::error!("❌ Client not bootstrapped");
            return Err(JsValue::from_str("Client not bootstrapped"));
        }
        log::debug!("  ✓ Client is bootstrapped");
        
        log::info!("🔨 Building new Tor circuit (v4 - digest fix)...");
        
        // Clone builder and selector to avoid borrow conflicts
        log::debug!("  📋 Cloning circuit builder...");
        let builder = self.circuit_builder.as_ref()
            .ok_or_else(|| {
                log::error!("❌ Circuit builder not initialized");
                JsValue::from_str("Circuit builder not initialized")
            })?
            .clone();
        log::debug!("  ✓ Builder cloned");
        
        log::debug!("  📋 Cloning relay selector...");
        let selector = self.relay_selector.as_ref()
            .ok_or_else(|| {
                log::error!("❌ Relay selector not initialized");
                JsValue::from_str("Relay selector not initialized")
            })?
            .clone();
        log::debug!("  ✓ Selector cloned");
        
        // Build circuit (now we own the builder and selector, no borrow conflicts)
        log::debug!("  🚀 Calling builder.build_circuit()...");
        let circuit = builder.build_circuit(&selector)
            .await
            .map_err(|e| {
                // Don't add extra "Circuit build failed" - the error already has context
                let error_msg = e.to_string();
                log::error!("❌ {}", error_msg);
                JsValue::from_str(&error_msg)
            })?;
        
        log::info!("✅ Circuit built with {} hops", circuit.hop_count());
        
        // Return circuit ID
        // Note: We don't store the circuit to avoid RefCell borrow issues in WASM async code
        Ok(circuit.id as usize)
    }
    
    /// Connect to a host through Tor
    /// 
    /// Returns a circuit ID that can be used for communication
    #[wasm_bindgen]
    pub async fn connect(
        &mut self,
        host: String,
        port: u16,
    ) -> std::result::Result<usize, JsValue> {
        if !self.bootstrapped {
            return Err(JsValue::from_str("Client not bootstrapped"));
        }
        
        log::info!("🌐 Connecting to {}:{} via Tor...", host, port);
        
        // 1. Build a circuit
        log::info!("  Building circuit for connection...");
        
        let builder = self.circuit_builder.as_ref()
            .ok_or_else(|| JsValue::from_str("Circuit builder not initialized"))?
            .clone();
        
        let selector = self.relay_selector.as_ref()
            .ok_or_else(|| JsValue::from_str("Relay selector not initialized"))?
            .clone();
        
        let circuit = builder.build_circuit(&selector)
            .await
            .map_err(|e| JsValue::from_str(&format!("Circuit build failed: {}", e)))?;
        
        let circuit_id = circuit.id;
        
        // Record circuit creation for rate limiting
        self.rate_limiter.record_circuit_created(circuit_id);
        
        // 2. Open a stream through the circuit
        log::info!("  📡 Opening stream to {}:{}...", host, port);
        
        let circuit_rc = std::rc::Rc::new(std::cell::RefCell::new(circuit));
        let mut stream_manager = protocol::StreamManager::new(std::rc::Rc::clone(&circuit_rc));
        
        let _stream = stream_manager.open_stream(&host, port)
            .await
            .map_err(|e| JsValue::from_str(&format!("Stream open failed: {}", e)))?;
        
        log::info!("✅ Connected to {}:{} via Tor circuit {}", host, port, circuit_id);
        
        Ok(circuit_id as usize)
    }
    
    /// Fetch a URL through Tor (HTTP and HTTPS supported)
    /// 
    /// Uses circuit isolation to prevent cross-site correlation.
    /// Different domains use different circuits.
    /// 
    /// Returns the HTTP response body as a string
    #[wasm_bindgen]
    pub async fn fetch(
        &mut self,
        url: String,
    ) -> std::result::Result<String, JsValue> {
        if !self.bootstrapped {
            return Err(JsValue::from_str("Client not bootstrapped"));
        }
        
        // Parse URL (now returns is_https flag)
        let (host, port, path, is_https) = parse_url(&url)
            .map_err(|e| JsValue::from_str(&format!("Invalid URL: {}", e)))?;
        
        let scheme = if is_https { "HTTPS" } else { "HTTP" };
        log::info!("🌐 Fetching {} via Tor ({})...", url, scheme);
        log::info!("  Host: {}, Port: {}, Path: {}, HTTPS: {}", host, port, path, is_https);
        
        // 1. Get or build a circuit (with isolation)
        let isolation_key = self.circuit_cache.isolation_key(&host, port);
        log::info!("  🔒 Isolation key: '{}'", isolation_key.as_str());
        
        let circuit_rc = if let Some(cached) = self.circuit_cache.get(&isolation_key) {
            log::info!("  ♻️ Reusing existing circuit for '{}'", host);
            cached
        } else {
            // Rate limiting check for new circuit
            if !self.rate_limiter.can_create_circuit() {
                log::error!("❌ Rate limited: too many circuits created recently");
                return Err(JsValue::from_str("Rate limited: too many circuit requests. Please wait."));
            }
            
            log::info!("  🔨 Building new circuit for '{}'...", host);
            
            let builder = self.circuit_builder.as_ref()
                .ok_or_else(|| JsValue::from_str("Circuit builder not initialized"))?
                .clone();
            
            let selector = self.relay_selector.as_ref()
                .ok_or_else(|| JsValue::from_str("Relay selector not initialized"))?
                .clone();
            
            let circuit = builder.build_circuit(&selector)
                .await
                .map_err(|e| JsValue::from_str(&format!("Circuit build failed: {}", e)))?;
            
            // Record circuit creation for rate limiting
            self.rate_limiter.record_circuit_created(circuit.id);
            
            log::info!("  ✅ Circuit {} built", circuit.id);
            
            // Cache the circuit for future requests to this domain
            self.circuit_cache.store(isolation_key, circuit)
        };
        
        // 2. Open a stream through the circuit
        log::info!("  📡 Opening stream to {}:{}...", host, port);
        
        let mut stream_manager = protocol::StreamManager::new(circuit_rc);
        
        let stream = stream_manager.open_stream(&host, port)
            .await
            .map_err(|e| JsValue::from_str(&format!("Stream open failed: {}", e)))?;
        
        log::info!("  ✅ Stream opened");
        
        // 3. For HTTPS, wrap stream with TLS
        let response_bytes = if is_https {
            log::info!("  🔐 Establishing TLS connection...");
            
            let mut tls_stream = protocol::TlsTorStream::new(stream, &host)
                .await
                .map_err(|e| JsValue::from_str(&format!("TLS handshake failed: {}", e)))?;
            
            log::info!("  ✅ TLS established");
            
            // Send HTTP request over TLS
            let http_request = format!(
                "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0\r\n\r\n",
                path, host
            );
            
            log::info!("  📤 Sending HTTPS request ({} bytes)...", http_request.len());
            
            tls_stream.write(http_request.as_bytes())
                .await
                .map_err(|e| JsValue::from_str(&format!("Failed to send request: {}", e)))?;
            
            log::info!("  ✅ Request sent");
            log::info!("  📥 Receiving response...");
            
            // Read response
            let response = tls_stream.read_to_end()
                .await
                .map_err(|e| JsValue::from_str(&format!("Failed to receive response: {}", e)))?;
            
            // Close TLS
            let _ = tls_stream.close().await;
            
            response
        } else {
            // Plain HTTP
            let mut stream = stream;
            
            let http_request = format!(
                "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0\r\n\r\n",
                path, host
            );
            
            log::info!("  📤 Sending HTTP request ({} bytes)...", http_request.len());
            
            stream.write_all(http_request.as_bytes())
                .await
                .map_err(|e| JsValue::from_str(&format!("Failed to send request: {}", e)))?;
            
            log::info!("  ✅ Request sent");
            log::info!("  📥 Receiving response...");
            
            let response = stream.read_response()
                .await
                .map_err(|e| JsValue::from_str(&format!("Failed to receive response: {}", e)))?;
            
            // Close stream
            let _ = stream.close().await;
            
            response
        };
        
        log::info!("  ✅ Received {} bytes", response_bytes.len());
        
        // Convert to string
        let response_str = String::from_utf8_lossy(&response_bytes).to_string();
        
        log::info!("✅ Fetch complete: {} bytes", response_str.len());

        Ok(response_str)
    }

    /// Fetch a URL via POST through the Tor network
    ///
    /// Makes an HTTP/HTTPS POST request through a Tor circuit.
    /// Useful for LLM API calls (Anthropic, OpenAI, Mistral, etc.)
    ///
    /// # Arguments
    /// * `url` - The URL to fetch (http:// or https://)
    /// * `headers_json` - JSON string of headers, e.g. {"x-api-key": "...", "content-type": "application/json"}
    /// * `body` - The request body (typically JSON)
    ///
    /// # Returns
    /// The HTTP response body as a string
    #[wasm_bindgen]
    pub async fn fetch_post(
        &mut self,
        url: String,
        headers_json: String,
        body: String,
    ) -> std::result::Result<String, JsValue> {
        if !self.bootstrapped {
            return Err(JsValue::from_str("Client not bootstrapped"));
        }

        // Parse headers from JSON
        let headers: std::collections::HashMap<String, String> = serde_json::from_str(&headers_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid headers JSON: {}", e)))?;

        // Parse URL
        let (host, port, path, is_https) = parse_url(&url)
            .map_err(|e| JsValue::from_str(&format!("Invalid URL: {}", e)))?;

        let scheme = if is_https { "HTTPS" } else { "HTTP" };
        log::info!("🌐 POST {} via Tor ({})...", url, scheme);
        log::info!("  Host: {}, Port: {}, Path: {}", host, port, path);
        log::info!("  Body length: {} bytes", body.len());

        // Get or build a circuit
        let isolation_key = self.circuit_cache.isolation_key(&host, port);

        let circuit_rc = if let Some(cached) = self.circuit_cache.get(&isolation_key) {
            log::info!("  ♻️ Reusing existing circuit for '{}'", host);
            cached
        } else {
            if !self.rate_limiter.can_create_circuit() {
                return Err(JsValue::from_str("Rate limited: too many circuit requests. Please wait."));
            }

            log::info!("  🔨 Building new circuit for '{}'...", host);

            let builder = self.circuit_builder.as_ref()
                .ok_or_else(|| JsValue::from_str("Circuit builder not initialized"))?
                .clone();

            let selector = self.relay_selector.as_ref()
                .ok_or_else(|| JsValue::from_str("Relay selector not initialized"))?
                .clone();

            let circuit = builder.build_circuit(&selector)
                .await
                .map_err(|e| JsValue::from_str(&format!("Circuit build failed: {}", e)))?;

            self.rate_limiter.record_circuit_created(circuit.id);
            log::info!("  ✅ Circuit {} built", circuit.id);

            self.circuit_cache.store(isolation_key, circuit)
        };

        // Open a stream
        log::info!("  📡 Opening stream to {}:{}...", host, port);

        let mut stream_manager = protocol::StreamManager::new(circuit_rc);

        let stream = stream_manager.open_stream(&host, port)
            .await
            .map_err(|e| JsValue::from_str(&format!("Stream open failed: {}", e)))?;

        log::info!("  ✅ Stream opened");

        // Build headers string
        let mut headers_str = String::new();
        for (key, value) in &headers {
            headers_str.push_str(&format!("{}: {}\r\n", key, value));
        }

        // Build HTTP POST request
        let http_request = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0\r\n{}\r\n{}",
            path, host, body.len(), headers_str, body
        );

        let response_bytes = if is_https {
            log::info!("  🔐 Establishing TLS connection...");

            let mut tls_stream = protocol::TlsTorStream::new(stream, &host)
                .await
                .map_err(|e| JsValue::from_str(&format!("TLS handshake failed: {}", e)))?;

            log::info!("  ✅ TLS established");
            log::info!("  📤 Sending POST request ({} bytes)...", http_request.len());

            tls_stream.write(http_request.as_bytes())
                .await
                .map_err(|e| JsValue::from_str(&format!("Failed to send request: {}", e)))?;

            log::info!("  ✅ Request sent");
            log::info!("  📥 Receiving response...");

            let response = tls_stream.read_to_end()
                .await
                .map_err(|e| JsValue::from_str(&format!("Failed to receive response: {}", e)))?;

            let _ = tls_stream.close().await;
            response
        } else {
            let mut stream = stream;

            log::info!("  📤 Sending POST request ({} bytes)...", http_request.len());

            stream.write_all(http_request.as_bytes())
                .await
                .map_err(|e| JsValue::from_str(&format!("Failed to send request: {}", e)))?;

            log::info!("  ✅ Request sent");
            log::info!("  📥 Receiving response...");

            let response = stream.read_response()
                .await
                .map_err(|e| JsValue::from_str(&format!("Failed to receive response: {}", e)))?;

            let _ = stream.close().await;
            response
        };

        log::info!("  ✅ Received {} bytes", response_bytes.len());

        let response_str = String::from_utf8_lossy(&response_bytes).to_string();

        log::info!("✅ POST complete: {} bytes", response_str.len());

        Ok(response_str)
    }

    /// Fetch a URL via POST through the Tor network (Cooperative Scheduler)
    ///
    /// This version uses the novel cooperative scheduler that avoids the
    /// RefCell borrow-across-await bug. It's designed for single-threaded
    /// WASM environments.
    ///
    /// # Arguments
    /// * `url` - The URL to fetch (http:// or https://)
    /// * `headers_json` - JSON string of headers
    /// * `body` - The request body (typically JSON)
    ///
    /// # Returns
    /// The HTTP response body as a string
    #[wasm_bindgen]
    pub async fn fetch_post_cooperative(
        &mut self,
        url: String,
        headers_json: String,
        body: String,
    ) -> std::result::Result<String, JsValue> {
        use std::rc::Rc;
        use std::cell::RefCell;

        if !self.bootstrapped {
            return Err(JsValue::from_str("Client not bootstrapped"));
        }

        // Parse headers from JSON
        let headers: std::collections::HashMap<String, String> = serde_json::from_str(&headers_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid headers JSON: {}", e)))?;

        // Parse URL
        let (host, port, path, is_https) = parse_url(&url)
            .map_err(|e| JsValue::from_str(&format!("Invalid URL: {}", e)))?;

        let scheme = if is_https { "HTTPS" } else { "HTTP" };
        log::info!("🌐 [COOP] POST {} via Tor ({})...", url, scheme);
        log::info!("  Host: {}, Port: {}, Path: {}", host, port, path);
        log::info!("  Body length: {} bytes", body.len());

        // Rate limit check
        if !self.rate_limiter.can_create_circuit() {
            return Err(JsValue::from_str("Rate limited: too many circuit requests. Please wait."));
        }

        // Build a fresh circuit (no caching for cooperative mode to avoid RefCell complexity)
        log::info!("  🔨 Building circuit for cooperative scheduler...");

        let builder = self.circuit_builder.as_ref()
            .ok_or_else(|| JsValue::from_str("Circuit builder not initialized"))?
            .clone();

        let selector = self.relay_selector.as_ref()
            .ok_or_else(|| JsValue::from_str("Relay selector not initialized"))?
            .clone();

        let circuit = builder.build_circuit(&selector)
            .await
            .map_err(|e| JsValue::from_str(&format!("Circuit build failed: {}", e)))?;

        self.rate_limiter.record_circuit_created(circuit.id);
        log::info!("  ✅ Circuit {} built", circuit.id);

        // Wrap in cooperative scheduler
        let scheduler = Rc::new(RefCell::new(CooperativeCircuit::new(circuit)));
        log::info!("  🎛️ Cooperative scheduler initialized");

        // Open stream using cooperative pattern
        log::info!("  📡 Opening stream to {}:{}...", host, port);
        let stream = open_cooperative_stream(&scheduler, &host, port)
            .await
            .map_err(|e| JsValue::from_str(&format!("Stream open failed: {}", e)))?;
        log::info!("  ✅ Stream opened");

        // Build headers string
        let mut headers_str = String::new();
        for (key, value) in &headers {
            headers_str.push_str(&format!("{}: {}\r\n", key, value));
        }

        // Build HTTP POST request
        let http_request = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0\r\n{}\r\n{}",
            path, host, body.len(), headers_str, body
        );

        let response_bytes = if is_https {
            log::info!("  🔐 Establishing TLS connection...");

            let mut tls_stream = CooperativeTlsStream::new(stream, &host)
                .await
                .map_err(|e| JsValue::from_str(&format!("TLS handshake failed: {}", e)))?;

            log::info!("  ✅ TLS established");
            log::info!("  📤 Sending POST request ({} bytes)...", http_request.len());

            tls_stream.write_all(http_request.as_bytes())
                .await
                .map_err(|e| JsValue::from_str(&format!("Failed to send request: {}", e)))?;

            log::info!("  ✅ Request sent");
            log::info!("  📥 Receiving response...");

            let response = tls_stream.read_to_end()
                .await
                .map_err(|e| JsValue::from_str(&format!("Failed to receive response: {}", e)))?;

            let _ = tls_stream.close().await;
            response
        } else {
            let mut stream = stream;

            log::info!("  📤 Sending POST request ({} bytes)...", http_request.len());

            stream.write_all(http_request.as_bytes())
                .await
                .map_err(|e| JsValue::from_str(&format!("Failed to send request: {}", e)))?;

            log::info!("  ✅ Request sent");
            log::info!("  📥 Receiving response...");

            let response = stream.read_to_end()
                .await
                .map_err(|e| JsValue::from_str(&format!("Failed to receive response: {}", e)))?;

            let _ = stream.close().await;
            response
        };

        log::info!("  ✅ Received {} bytes", response_bytes.len());

        let response_str = String::from_utf8_lossy(&response_bytes).to_string();

        log::info!("✅ [COOP] POST complete: {} bytes", response_str.len());

        Ok(response_str)
    }

    /// Make a GET request using the cooperative scheduler
    ///
    /// This is the reliable version that avoids RefCell borrow-across-await issues.
    ///
    /// # Arguments
    /// * `url` - Full URL to fetch (http:// or https://)
    ///
    /// # Returns
    /// The HTTP response body as a string
    #[wasm_bindgen]
    pub async fn fetch_get_cooperative(
        &mut self,
        url: String,
    ) -> std::result::Result<String, JsValue> {
        use std::rc::Rc;
        use std::cell::RefCell;

        if !self.bootstrapped {
            return Err(JsValue::from_str("Client not bootstrapped"));
        }

        // Parse URL
        let (host, port, path, is_https) = parse_url(&url)
            .map_err(|e| JsValue::from_str(&format!("Invalid URL: {}", e)))?;

        let scheme = if is_https { "HTTPS" } else { "HTTP" };
        log::info!("🌐 [COOP] GET {} via Tor ({})...", url, scheme);

        // Rate limit check
        if !self.rate_limiter.can_create_circuit() {
            return Err(JsValue::from_str("Rate limited: too many circuit requests. Please wait."));
        }

        // Build a fresh circuit
        let builder = self.circuit_builder.as_ref()
            .ok_or_else(|| JsValue::from_str("Circuit builder not initialized"))?
            .clone();

        let selector = self.relay_selector.as_ref()
            .ok_or_else(|| JsValue::from_str("Relay selector not initialized"))?
            .clone();

        let circuit = builder.build_circuit(&selector)
            .await
            .map_err(|e| JsValue::from_str(&format!("Circuit build failed: {}", e)))?;

        self.rate_limiter.record_circuit_created(circuit.id);

        // Wrap in cooperative scheduler
        let scheduler = Rc::new(RefCell::new(CooperativeCircuit::new(circuit)));

        // Open stream
        let stream = open_cooperative_stream(&scheduler, &host, port)
            .await
            .map_err(|e| JsValue::from_str(&format!("Stream open failed: {}", e)))?;

        // Build HTTP GET request
        let http_request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0\r\n\r\n",
            path, host
        );

        let response_bytes = if is_https {
            let mut tls_stream = CooperativeTlsStream::new(stream, &host)
                .await
                .map_err(|e| JsValue::from_str(&format!("TLS handshake failed: {}", e)))?;

            tls_stream.write_all(http_request.as_bytes())
                .await
                .map_err(|e| JsValue::from_str(&format!("Failed to send request: {}", e)))?;

            let response = tls_stream.read_to_end()
                .await
                .map_err(|e| JsValue::from_str(&format!("Failed to receive response: {}", e)))?;

            let _ = tls_stream.close().await;
            response
        } else {
            let mut stream = stream;

            stream.write_all(http_request.as_bytes())
                .await
                .map_err(|e| JsValue::from_str(&format!("Failed to send request: {}", e)))?;

            let response = stream.read_to_end()
                .await
                .map_err(|e| JsValue::from_str(&format!("Failed to receive response: {}", e)))?;

            let _ = stream.close().await;
            response
        };

        let response_str = String::from_utf8_lossy(&response_bytes).to_string();
        log::info!("✅ [COOP] GET complete: {} bytes", response_str.len());

        Ok(response_str)
    }

    /// Get number of cached circuits
    #[wasm_bindgen]
    pub fn circuit_count(&self) -> usize {
        self.circuit_cache.len()
    }
    
    /// Check if client is ready
    #[wasm_bindgen]
    pub fn is_ready(&self) -> bool {
        self.bootstrapped
    }
    
    /// Set the circuit isolation policy
    /// 
    /// Options:
    /// - "per_domain" (default): One circuit per domain
    /// - "per_destination": One circuit per (domain, port)
    /// - "per_request": New circuit for every request (slow but most private)
    /// - "none": Single circuit for all (not recommended)
    #[wasm_bindgen]
    pub fn set_isolation_policy(&mut self, policy: &str) {
        let isolation_type = match policy.to_lowercase().as_str() {
            "per_domain" | "domain" => IsolationType::PerDomain,
            "per_destination" | "destination" => IsolationType::PerDestination,
            "per_request" | "request" | "paranoid" => IsolationType::PerRequest,
            "none" | "global" | "off" => IsolationType::None,
            _ => {
                log::warn!("Unknown isolation policy '{}', using per_domain", policy);
                IsolationType::PerDomain
            }
        };
        
        // Create new cache with new policy
        let config = IsolationConfig {
            policy: isolation_type,
            ..IsolationConfig::default()
        };
        
        // Clear existing circuits when policy changes
        self.circuit_cache.clear();
        self.circuit_cache = CircuitCache::new(config);
        
        log::info!("🔒 Circuit isolation policy set to: {:?}", isolation_type);
    }
    
    /// Get the current isolation policy
    #[wasm_bindgen]
    pub fn get_isolation_policy(&self) -> String {
        format!("{:?}", self.circuit_cache.policy())
    }
    
    /// Clear all cached circuits (forces new circuits for all domains)
    #[wasm_bindgen]
    pub fn clear_circuits(&mut self) {
        self.circuit_cache.clear();
        log::info!("🗑️ All cached circuits cleared");
    }
    
    /// Get circuit cache statistics
    #[wasm_bindgen]
    pub fn get_circuit_stats(&self) -> JsValue {
        let stats = self.circuit_cache.stats();
        serde_wasm_bindgen::to_value(&serde_json::json!({
            "cached_circuits": stats.cached_circuits,
            "total_requests": stats.total_requests,
            "oldest_circuit_age_secs": stats.oldest_circuit_age_secs,
            "policy": format!("{:?}", stats.policy),
        })).unwrap_or(JsValue::NULL)
    }
    
    /// Get guard state information
    #[wasm_bindgen]
    pub fn get_guard_info(&self) -> JsValue {
        let now = web_time::SystemTime::now()
            .duration_since(web_time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        
        let days_until_rotation = if self.guard_state.rotate_after > now {
            (self.guard_state.rotate_after - now) / (24 * 60 * 60)
        } else {
            0
        };
        
        serde_wasm_bindgen::to_value(&serde_json::json!({
            "guard_count": self.guard_state.guards.len(),
            "usable_guards": self.guard_state.usable_guard_count(),
            "days_until_rotation": days_until_rotation,
            "bad_guard_count": self.guard_state.bad_guards.len(),
            "selected_at": self.guard_state.selected_at,
            "rotate_after": self.guard_state.rotate_after,
        })).unwrap_or(JsValue::NULL)
    }
    
    /// Force guard rotation (selects new guards)
    #[wasm_bindgen]
    pub async fn rotate_guards(&mut self) -> std::result::Result<(), JsValue> {
        if !self.bootstrapped {
            return Err(JsValue::from_str("Client not bootstrapped"));
        }
        
        let consensus = self.consensus.as_ref()
            .ok_or_else(|| JsValue::from_str("No consensus"))?;
        
        log::info!("🔄 Forcing guard rotation...");
        
        self.guard_state.select_guards(&consensus.relays)
            .map_err(|e| JsValue::from_str(&format!("Guard selection failed: {}", e)))?;
        
        // Save the new state
        if let Err(e) = self.guard_persistence.save(&self.guard_state).await {
            log::warn!("⚠️ Failed to save guard state: {}", e);
        }
        
        // Update relay selector
        if let Some(ref mut selector) = self.relay_selector {
            selector.set_preferred_guards(self.guard_state.usable_guards()
                .into_iter()
                .map(|s| s.clone())
                .collect());
        }
        
        log::info!("✅ Guard rotation complete");
        Ok(())
    }
    
    /// Clear guard state (for testing/debugging)
    #[wasm_bindgen]
    pub async fn clear_guards(&mut self) -> std::result::Result<(), JsValue> {
        log::info!("🗑️ Clearing guard state...");
        
        self.guard_state = GuardState::new();
        
        if let Err(e) = self.guard_persistence.clear().await {
            log::warn!("⚠️ Failed to clear saved guard state: {}", e);
        }
        
        // Clear preferred guards from relay selector
        if let Some(ref mut selector) = self.relay_selector {
            selector.set_preferred_guards(Vec::new());
        }
        
        log::info!("✅ Guard state cleared");
        Ok(())
    }
}
