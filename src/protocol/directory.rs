//! Directory manager for fetching Tor consensus
//!
//! Connects to Tor directory authorities to fetch the network consensus,
//! which contains information about all Tor relays.

use super::{Consensus, ConsensusParser};
use crate::error::{Result, TorError};
use crate::network::WasmTcpProvider;
use crate::storage::WasmStorage;
use futures::io::{AsyncReadExt, AsyncWriteExt};
use std::net::SocketAddr;
use std::sync::Arc;

/// Directory manager for fetching and caching consensus
pub struct DirectoryManager {
    /// Network provider for connections
    network: Arc<WasmTcpProvider>,

    /// Storage for caching consensus
    storage: Arc<WasmStorage>,

    /// Last successful authority
    last_authority: Option<usize>,
}

impl DirectoryManager {
    /// Create a new directory manager
    pub fn new(network: Arc<WasmTcpProvider>, storage: Arc<WasmStorage>) -> Self {
        Self {
            network,
            storage,
            last_authority: None,
        }
    }

    /// Fetch the current network consensus
    pub async fn fetch_consensus(&mut self) -> Result<Consensus> {
        log::info!("📡 Fetching Tor consensus from bridge server...");

        // Fetch from bridge HTTP endpoint instead of directory authorities
        match self.fetch_from_bridge().await {
            Ok(consensus) => {
                log::info!("✅ Successfully fetched consensus from bridge");
                log::info!("📊 Consensus contains {} relays", consensus.relays.len());

                // Count relays with ntor keys
                let with_keys = consensus
                    .relays
                    .iter()
                    .filter(|r| r.ntor_onion_key.is_some())
                    .count();
                log::info!("🔑 {} relays have ntor keys", with_keys);

                // Store in IndexedDB
                if let Err(e) = self.store_consensus(&consensus).await {
                    log::warn!("Failed to cache consensus: {}", e);
                }

                Ok(consensus)
            }
            Err(e) => {
                log::warn!("⚠️  Failed to fetch from bridge: {}", e);
                log::info!("🎭 Using fallback consensus with real Tor relays...");
                self.create_mock_consensus()
            }
        }
    }

    /// Try to fetch consensus from a specific authority
    async fn try_fetch_from(&self, name: &str, addr_str: &str) -> Result<Consensus> {
        // Parse address
        let addr: SocketAddr = addr_str
            .parse()
            .map_err(|e| TorError::Directory(format!("Invalid address {}: {}", addr_str, e)))?;

        // Connect to authority
        let mut stream = self
            .network
            .connect_with_retry(&addr)
            .await
            .map_err(|e| TorError::Network(format!("Connection failed: {}", e)))?;

        // Build HTTP request for consensus
        let request = format!(
            "GET /tor/status-vote/current/consensus HTTP/1.0\r\n\
             Host: {}\r\n\
             User-Agent: tor-wasm/0.1.0\r\n\
             \r\n",
            addr.ip()
        );

        log::info!(
            "📤 Sending HTTP GET request to {} ({} bytes)",
            name,
            request.len()
        );
        log::debug!("Request:\n{}", request);

        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| TorError::Network(format!("Write failed: {}", e)))?;

        stream
            .flush()
            .await
            .map_err(|e| TorError::Network(format!("Flush failed: {}", e)))?;

        log::info!("✅ HTTP request sent and flushed to {}", name);

        // Read response with 5 second timeout
        // For WASM, we'll read in chunks with a total time limit
        log::info!("📖 Reading HTTP response from {} (5s timeout)...", name);
        let mut response = Vec::new();
        let mut buffer = [0u8; 4096];
        let start_time = js_sys::Date::now();
        let timeout_ms = 5000.0;
        let mut read_attempts = 0;

        loop {
            read_attempts += 1;

            // Check timeout
            let elapsed = js_sys::Date::now() - start_time;
            if elapsed > timeout_ms {
                log::warn!(
                    "❌ Read timeout after {}ms ({} read attempts, {} bytes received)",
                    elapsed as u64,
                    read_attempts,
                    response.len()
                );
                return Err(TorError::Network(format!(
                    "Read timeout after {}ms",
                    elapsed as u64
                )));
            }

            // Try to read with a small timeout per read
            log::debug!(
                "📥 Read attempt {} (elapsed: {}ms, received: {} bytes)",
                read_attempts,
                elapsed as u64,
                response.len()
            );

            match stream.read(&mut buffer).await {
                Ok(0) => {
                    // EOF reached
                    log::info!(
                        "✅ EOF reached after {} attempts, received {} bytes total",
                        read_attempts,
                        response.len()
                    );
                    break;
                }
                Ok(n) => {
                    response.extend_from_slice(&buffer[..n]);
                    log::info!(
                        "📦 Read {} bytes in attempt {} (total: {} bytes)",
                        n,
                        read_attempts,
                        response.len()
                    );
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No data available yet, yield to event loop to allow WebSocket to receive data
                    log::debug!(
                        "⏸️  WouldBlock - yielding to event loop (attempt {})",
                        read_attempts
                    );
                    crate::runtime::WasmRuntime::new()
                        .sleep(std::time::Duration::from_millis(10))
                        .await;
                    continue;
                }
                Err(e) => {
                    log::error!(
                        "❌ Read error after {} attempts: {} (kind: {:?})",
                        read_attempts,
                        e,
                        e.kind()
                    );
                    return Err(TorError::Network(format!("Read failed: {}", e)));
                }
            }

            // If we've read enough data (>100KB), assume it's complete
            if response.len() > 100_000 {
                log::info!(
                    "✅ Read sufficient data ({}KB), stopping after {} attempts",
                    response.len() / 1024,
                    read_attempts
                );
                break;
            }
        }

        log::debug!("Received {} bytes from {}", response.len(), name);

        // Parse HTTP response
        let body = Self::parse_http_response(&response)?;

        log::debug!("Consensus body size: {} bytes", body.len());

        // Parse consensus
        ConsensusParser::parse(&body)
    }

    /// Fetch relay descriptors to get real ntor keys
    /// Returns a map of fingerprint -> ntor_onion_key (base64)
    async fn fetch_descriptors(
        &self,
        authority_name: &str,
        addr_str: &str,
        relays: &[super::Relay],
    ) -> Result<std::collections::HashMap<String, String>> {
        use std::collections::HashMap;

        // Parse address
        let addr: SocketAddr = addr_str
            .parse()
            .map_err(|e| TorError::Directory(format!("Invalid address {}: {}", addr_str, e)))?;

        // Build fingerprint list for URL
        // Take first 20 relays to keep request small
        let fingerprints: Vec<&str> = relays
            .iter()
            .take(20)
            .map(|r| r.fingerprint.as_str())
            .collect();

        if fingerprints.is_empty() {
            return Ok(HashMap::new());
        }

        let fp_param = fingerprints.join("+");

        log::info!(
            "  Fetching descriptors for {} relays from {}",
            fingerprints.len(),
            authority_name
        );

        // Connect to authority
        let mut stream = self
            .network
            .connect_with_retry(&addr)
            .await
            .map_err(|e| TorError::Network(format!("Connection failed: {}", e)))?;

        // Build HTTP request for descriptors
        let request = format!(
            "GET /tor/server/fp/{} HTTP/1.0\r\n\
             Host: {}\r\n\
             User-Agent: tor-wasm/0.1.0\r\n\
             \r\n",
            fp_param,
            addr.ip()
        );

        log::debug!("  Descriptor request:\n{}", request);

        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| TorError::Network(format!("Write failed: {}", e)))?;

        stream
            .flush()
            .await
            .map_err(|e| TorError::Network(format!("Flush failed: {}", e)))?;

        // Read response with timeout
        let mut response = Vec::new();
        let mut buffer = [0u8; 8192];
        let start_time = js_sys::Date::now();
        let timeout_ms = 10000.0; // 10 second timeout for descriptors

        loop {
            let elapsed = js_sys::Date::now() - start_time;
            if elapsed > timeout_ms {
                log::warn!("  Descriptor fetch timeout after {}ms", elapsed as u64);
                return Err(TorError::Network("Descriptor fetch timeout".into()));
            }

            match stream.read(&mut buffer).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    response.extend_from_slice(&buffer[..n]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    crate::runtime::WasmRuntime::new()
                        .sleep(std::time::Duration::from_millis(10))
                        .await;
                    continue;
                }
                Err(e) => {
                    return Err(TorError::Network(format!("Read failed: {}", e)));
                }
            }

            // Descriptors can be large, but 1MB should be enough
            if response.len() > 1_000_000 {
                log::debug!(
                    "  Received sufficient descriptor data ({}KB)",
                    response.len() / 1024
                );
                break;
            }
        }

        log::debug!("  Received {} bytes of descriptor data", response.len());

        // Parse HTTP response
        let body = Self::parse_http_response(&response)?;

        // Parse descriptors
        Self::parse_descriptors(&body)
    }

    /// Parse relay descriptors and extract ntor keys
    fn parse_descriptors(data: &[u8]) -> Result<std::collections::HashMap<String, String>> {
        use std::collections::HashMap;

        let text = String::from_utf8_lossy(data);
        let mut descriptors = HashMap::new();

        let mut current_fingerprint: Option<String> = None;
        let mut current_ntor_key: Option<String> = None;

        for line in text.lines() {
            let line = line.trim();

            // Skip empty lines
            if line.is_empty() {
                continue;
            }

            // Parse fingerprint line: "fingerprint XXXX XXXX XXXX ..."
            if line.starts_with("fingerprint ") {
                let fp_parts: Vec<&str> = line.split_whitespace().skip(1).collect();
                let fingerprint = fp_parts.join("");
                current_fingerprint = Some(fingerprint.to_uppercase());
                log::debug!("    Found fingerprint: {:?}", current_fingerprint);
            }
            // Parse ntor key line: "ntor-onion-key <base64>"
            else if line.starts_with("ntor-onion-key ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    current_ntor_key = Some(parts[1].to_string());
                    log::debug!("    Found ntor key: {}", parts[1]);

                    // If we have both fingerprint and key, store them
                    if let (Some(fp), Some(key)) =
                        (current_fingerprint.take(), current_ntor_key.take())
                    {
                        log::debug!("    Storing descriptor: {} -> {}", fp, key);
                        descriptors.insert(fp, key);
                    }
                }
            }
            // Reset on router line (start of new descriptor)
            else if line.starts_with("router ") {
                current_fingerprint = None;
                current_ntor_key = None;
            }
        }

        log::info!("  Parsed {} descriptors with ntor keys", descriptors.len());

        Ok(descriptors)
    }

    /// Parse HTTP response and extract body
    fn parse_http_response(response: &[u8]) -> Result<Vec<u8>> {
        let response_str = String::from_utf8_lossy(response);

        // Check for HTTP status
        if !response_str.starts_with("HTTP/") {
            return Err(TorError::Directory("Invalid HTTP response".into()));
        }

        // Find status code
        let first_line = response_str.lines().next().unwrap_or("");
        if !first_line.contains(" 200 ") {
            return Err(TorError::Directory(format!("HTTP error: {}", first_line)));
        }

        // Find empty line (end of headers)
        if let Some(body_start) = response.windows(4).position(|w| w == b"\r\n\r\n") {
            Ok(response[body_start + 4..].to_vec())
        } else if let Some(body_start) = response.windows(2).position(|w| w == b"\n\n") {
            Ok(response[body_start + 2..].to_vec())
        } else {
            // No headers? Use whole response
            Ok(response.to_vec())
        }
    }

    /// Store consensus in IndexedDB
    async fn store_consensus(&self, consensus: &Consensus) -> Result<()> {
        log::info!("💾 Caching consensus to IndexedDB...");

        // Serialize consensus
        let data = serde_json::to_vec(consensus)
            .map_err(|e| TorError::Storage(format!("Serialization failed: {}", e)))?;

        // Store in IndexedDB
        self.storage.set("consensus", "latest", &data).await?;

        // Also store timestamp
        let timestamp = js_sys::Date::now();
        let timestamp_str = timestamp.to_string();
        self.storage
            .set("consensus", "last_updated", timestamp_str.as_bytes())
            .await?;

        log::info!("✅ Consensus cached successfully");
        Ok(())
    }

    /// Load cached consensus from IndexedDB
    async fn load_cached_consensus(&self) -> Result<Consensus> {
        log::info!("📂 Loading cached consensus from IndexedDB...");

        let data = self
            .storage
            .get("consensus", "latest")
            .await?
            .ok_or_else(|| TorError::Directory("No cached consensus found".into()))?;

        let consensus: Consensus = serde_json::from_slice(&data)
            .map_err(|e| TorError::Storage(format!("Deserialization failed: {}", e)))?;

        // Check if still valid
        if consensus.is_valid() {
            log::info!(
                "✅ Loaded cached consensus ({} relays)",
                consensus.relays.len()
            );
            Ok(consensus)
        } else {
            log::warn!("⚠️  Cached consensus is expired");
            Err(TorError::Directory("Cached consensus expired".into()))
        }
    }

    /// Check if we have a fresh cached consensus
    pub async fn has_fresh_consensus(&self) -> bool {
        if let Ok(Some(data)) = self.storage.get("consensus", "latest").await {
            if let Ok(consensus) = serde_json::from_slice::<Consensus>(&data) {
                return consensus.is_fresh();
            }
        }
        false
    }

    /// Create a mock consensus for testing
    /// This returns a minimal valid consensus that can be used for smoke tests
    fn create_mock_consensus(&self) -> Result<Consensus> {
        use super::{Relay, RelayFlags};
        use std::net::IpAddr;

        log::info!("🎭 Creating fallback consensus with CF-reachable Tor relays...");

        // All relays verified reachable from Cloudflare edge (Feb 2026)
        // ntor keys fetched from directory authority bastet (204.13.164.118:80)
        let mut relays = Vec::new();
        let now = (js_sys::Date::now() / 1000.0) as u64;

        // Guard relay 1
        relays.push(Relay {
            nickname: "chali2na".to_string(),
            fingerprint: "0040E1791755D340BA8109F4C1849666582CF56C".to_string(),
            address: IpAddr::V4(std::net::Ipv4Addr::new(64, 65, 62, 145)),
            or_port: 443,
            dir_port: Some(0),
            bandwidth: 10000000,
            published: now,
            ntor_onion_key: Some("LR1iEwNhvbukFktKw3E8xnlB+SKyIwRJlbFBWiRyZzI".to_string()),
            family: None,
            flags: RelayFlags {
                authority: false,
                bad_exit: false,
                exit: false,
                fast: true,
                guard: true,
                hs_dir: true,
                running: true,
                stable: true,
                v2_dir: true,
                valid: true,
            },
        });

        // Guard relay 2
        relays.push(Relay {
            nickname: "FEVI20".to_string(),
            fingerprint: "007BA681807ED056C04DA1CA22105F5584869F10".to_string(),
            address: IpAddr::V4(std::net::Ipv4Addr::new(23, 134, 90, 59)),
            or_port: 443,
            dir_port: Some(0),
            bandwidth: 8000000,
            published: now,
            ntor_onion_key: Some("9mtrgFg/lPrhT/O3ssxkOSk2NmMmDUE7ltWx7eP8uQM".to_string()),
            family: None,
            flags: RelayFlags {
                authority: false,
                bad_exit: false,
                exit: false,
                fast: true,
                guard: true,
                hs_dir: false,
                running: true,
                stable: true,
                v2_dir: true,
                valid: true,
            },
        });

        // Guard relay 3
        relays.push(Relay {
            nickname: "MaxRelay2".to_string(),
            fingerprint: "008EA22C040A4B5C262551195B5C34B54F353D83".to_string(),
            address: IpAddr::V4(std::net::Ipv4Addr::new(23, 186, 168, 33)),
            or_port: 443,
            dir_port: Some(0),
            bandwidth: 9000000,
            published: now,
            ntor_onion_key: Some("A7OmJsI2nkEKSkPevApwR8R9npCoxqb/4Wm5SP1/VRI".to_string()),
            family: None,
            flags: RelayFlags {
                authority: false,
                bad_exit: false,
                exit: false,
                fast: true,
                guard: true,
                hs_dir: true,
                running: true,
                stable: true,
                v2_dir: true,
                valid: true,
            },
        });

        // Guard relay 4
        relays.push(Relay {
            nickname: "tried".to_string(),
            fingerprint: "00D2CE3C2153EA09786F2105F26B138CF759424F".to_string(),
            address: IpAddr::V4(std::net::Ipv4Addr::new(107, 155, 81, 178)),
            or_port: 443,
            dir_port: Some(0),
            bandwidth: 7000000,
            published: now,
            ntor_onion_key: Some("EH7NK18v7r+fbq/aramaYBAckwI6aJrozHgSm/dg+20".to_string()),
            family: None,
            flags: RelayFlags {
                authority: false,
                bad_exit: false,
                exit: false,
                fast: true,
                guard: true,
                hs_dir: true,
                running: true,
                stable: true,
                v2_dir: true,
                valid: true,
            },
        });

        // Exit+Guard relay 1
        relays.push(Relay {
            nickname: "eo190".to_string(),
            fingerprint: "0082FE19212D9681EEB2320A42ADF0390D231585".to_string(),
            address: IpAddr::V4(std::net::Ipv4Addr::new(23, 129, 64, 190)),
            or_port: 443,
            dir_port: Some(0),
            bandwidth: 8000000,
            published: now,
            ntor_onion_key: Some("I/nyyLJ5h2E9QIkmumS6r1LoS2ZElku+Dn991JejKAM".to_string()),
            family: None,
            flags: RelayFlags {
                authority: false,
                bad_exit: false,
                exit: true,
                fast: true,
                guard: true,
                hs_dir: true,
                running: true,
                stable: true,
                v2_dir: true,
                valid: true,
            },
        });

        // Exit+Guard relay 2
        relays.push(Relay {
            nickname: "SENDNOOSEplz".to_string(),
            fingerprint: "000F3EB75342BE371F1D8D3FAE90890AEB5664EE".to_string(),
            address: IpAddr::V4(std::net::Ipv4Addr::new(204, 137, 14, 106)),
            or_port: 443,
            dir_port: Some(0),
            bandwidth: 9000000,
            published: now,
            ntor_onion_key: Some("qFrokPFfV78HK68kyNEx2UR4VUh8rNF8rilVuzJqkio".to_string()),
            family: None,
            flags: RelayFlags {
                authority: false,
                bad_exit: false,
                exit: true,
                fast: true,
                guard: true,
                hs_dir: true,
                running: true,
                stable: true,
                v2_dir: true,
                valid: true,
            },
        });

        // Exit+Guard relay 3
        relays.push(Relay {
            nickname: "anarchistcook".to_string(),
            fingerprint: "0077640E103A829BF8228D42F95818DAD1E9D84C".to_string(),
            address: IpAddr::V4(std::net::Ipv4Addr::new(179, 43, 159, 78)),
            or_port: 9001,
            dir_port: Some(0),
            bandwidth: 7000000,
            published: now,
            ntor_onion_key: Some("T4wbkGY3400hdVfMWZfdc8ZDyjbndf9vDsiSbBOPHEw".to_string()),
            family: None,
            flags: RelayFlags {
                authority: false,
                bad_exit: false,
                exit: true,
                fast: true,
                guard: true,
                hs_dir: true,
                running: true,
                stable: true,
                v2_dir: true,
                valid: true,
            },
        });

        let consensus = Consensus {
            valid_after: now,
            fresh_until: now + 3600, // Valid for 1 hour
            valid_until: now + 7200, // Valid for 2 hours
            relays,
            version: 3, // Consensus version 3
        };

        log::info!(
            "✅ Created mock consensus with {} relays",
            consensus.relays.len()
        );

        Ok(consensus)
    }

    /// Fetch consensus from bridge HTTP endpoint
    async fn fetch_from_bridge(&self) -> Result<Consensus> {
        use wasm_bindgen::JsCast;
        use wasm_bindgen_futures::JsFuture;
        use web_sys::{Request, RequestInit, RequestMode, Response};

        // Get bridge URL from network provider's configuration
        // Convert ws:// or wss:// to http:// or https://
        let ws_url = self.network.bridge_url();
        let http_url = if ws_url.starts_with("wss://") {
            ws_url.replace("wss://", "https://")
        } else if ws_url.starts_with("ws://") {
            ws_url.replace("ws://", "http://")
        } else {
            ws_url.to_string()
        };
        let bridge_url = format!("{}/tor/consensus", http_url);

        log::info!("🌐 Fetching from bridge: {}", bridge_url);

        // Create fetch request
        let mut opts = RequestInit::new();
        opts.method("GET");
        opts.mode(RequestMode::Cors);

        let request = Request::new_with_str_and_init(&bridge_url, &opts)
            .map_err(|e| TorError::Network(format!("Failed to create request: {:?}", e)))?;

        // Get window and fetch
        let window =
            web_sys::window().ok_or_else(|| TorError::Network("No window object".into()))?;

        let resp_value = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|e| TorError::Network(format!("Fetch failed: {:?}", e)))?;

        // Cast to Response
        let resp: Response = resp_value
            .dyn_into()
            .map_err(|_| TorError::Network("Failed to cast to Response".into()))?;

        // Check status
        if !resp.ok() {
            return Err(TorError::Network(format!(
                "HTTP {}: {}",
                resp.status(),
                resp.status_text()
            )));
        }

        // Get JSON text
        let json_value = JsFuture::from(
            resp.text()
                .map_err(|e| TorError::Network(format!("Failed to get text: {:?}", e)))?,
        )
        .await
        .map_err(|e| TorError::Network(format!("Failed to read text: {:?}", e)))?;

        let json_str = json_value
            .as_string()
            .ok_or_else(|| TorError::Network("Response is not a string".into()))?;

        log::info!("✅ Received {} bytes from bridge", json_str.len());

        // Parse JSON
        let json_data: serde_json::Value = serde_json::from_str(&json_str)
            .map_err(|e| TorError::ParseError(format!("Failed to parse JSON: {}", e)))?;

        // Verify consensus signatures if raw consensus text is included
        if let Some(raw) = json_data.get("raw_consensus").and_then(|v| v.as_str()) {
            let verifier = super::consensus_verify::ConsensusVerifier::new();
            match verifier.verify_consensus(raw) {
                Ok(count) => {
                    log::info!(
                        "✅ Consensus verified: {} authority signatures confirmed",
                        count
                    );
                }
                Err(e) => {
                    log::warn!("❌ Consensus verification FAILED: {}", e);
                    return Err(e);
                }
            }
        } else {
            log::warn!("⚠️ No raw_consensus in bridge response — cannot verify signatures");
        }

        // Extract consensus object
        let consensus_obj = json_data
            .get("consensus")
            .ok_or_else(|| TorError::ParseError("Missing 'consensus' field".into()))?;

        // Parse relays
        let relays_arr = consensus_obj
            .get("relays")
            .and_then(|v| v.as_array())
            .ok_or_else(|| TorError::ParseError("Missing or invalid 'relays' field".into()))?;

        log::info!("📋 Parsing {} relays...", relays_arr.len());

        let mut relays = Vec::new();
        for relay_val in relays_arr {
            let relay = self.parse_relay_json(relay_val)?;
            relays.push(relay);
        }

        // Create consensus
        let consensus = Consensus {
            version: consensus_obj
                .get("version")
                .and_then(|v| v.as_u64())
                .unwrap_or(3) as u32,
            valid_after: 0, // Not used, timestamps come from bridge
            fresh_until: 0,
            valid_until: 0,
            relays,
        };

        Ok(consensus)
    }

    /// Parse a relay from JSON
    fn parse_relay_json(&self, val: &serde_json::Value) -> Result<super::Relay> {
        use std::net::IpAddr;

        let nickname = val
            .get("nickname")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TorError::ParseError("Missing relay nickname".into()))?;

        let fingerprint = val
            .get("fingerprint")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TorError::ParseError("Missing relay fingerprint".into()))?;

        let address_str = val
            .get("address")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TorError::ParseError("Missing relay address".into()))?;

        let address: IpAddr = address_str
            .parse()
            .map_err(|_| TorError::ParseError(format!("Invalid IP address: {}", address_str)))?;

        let or_port = val
            .get("port")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| TorError::ParseError("Missing relay port".into()))?
            as u16;

        let ntor_onion_key = val
            .get("ntor_onion_key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Parse flags
        let flags_obj = val
            .get("flags")
            .and_then(|v| v.as_object())
            .ok_or_else(|| TorError::ParseError("Missing or invalid relay flags".into()))?;

        let flags = super::RelayFlags {
            authority: false,
            bad_exit: false,
            exit: flags_obj
                .get("exit")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            fast: flags_obj
                .get("fast")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            guard: flags_obj
                .get("guard")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            hs_dir: flags_obj
                .get("hsdir")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            running: flags_obj
                .get("running")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            stable: flags_obj
                .get("stable")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            v2_dir: flags_obj
                .get("v2dir")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            valid: flags_obj
                .get("valid")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        };

        Ok(super::Relay {
            nickname: nickname.to_string(),
            fingerprint: fingerprint.to_string(),
            address,
            or_port,
            dir_port: None,
            flags,
            bandwidth: val.get("bandwidth").and_then(|v| v.as_u64()).unwrap_or(0),
            published: val.get("published").and_then(|v| v.as_u64()).unwrap_or(0),
            ntor_onion_key,
            family: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_http_response() {
        let response = b"HTTP/1.0 200 OK\r\n\
                        Content-Type: text/plain\r\n\
                        \r\n\
                        Body content here";

        let body = DirectoryManager::parse_http_response(response).unwrap();
        assert_eq!(body, b"Body content here");
    }

    #[test]
    fn test_parse_http_error() {
        let response = b"HTTP/1.0 404 Not Found\r\n\r\n";

        let result = DirectoryManager::parse_http_response(response);
        assert!(result.is_err());
    }
}
