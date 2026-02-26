//! Network integration tests
//!
//! Tests that connect to real Tor directory authorities and relays.
//!
//! Run with: wasm-pack test --node

use futures::io::{AsyncReadExt, AsyncWriteExt};
use std::net::SocketAddr;
use std::sync::Arc;
use tor_wasm::network::{ConnectionManager, NetworkConfig, WasmTcpProvider, WasmTlsConnector};
use tor_wasm::WasmTcpStream;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

/// Tor directory authorities (for testing)
const DIR_AUTHORITIES: &[(&str, &str)] = &[
    ("moria1", "128.31.0.34:9131"),
    ("tor26", "86.59.21.38:80"),
    ("dizum", "194.109.206.212:80"),
];

#[wasm_bindgen_test]
async fn test_tcp_provider_creation() {
    let provider = WasmTcpProvider::new();
    let stats = provider.get_stats();

    assert_eq!(stats.connections_attempted, 0);
    assert_eq!(stats.connections_successful, 0);
    assert_eq!(stats.connections_failed, 0);
}

#[wasm_bindgen_test]
async fn test_network_config() {
    let config = NetworkConfig::with_bridge("ws://localhost:8080");
    assert_eq!(config.bridge_url, "ws://localhost:8080");

    let addr: SocketAddr = "1.2.3.4:9001".parse().unwrap();
    let url = config.build_url(&addr);
    assert!(url.contains("1.2.3.4:9001"));
}

#[wasm_bindgen_test]
async fn test_tls_connector() {
    let connector = WasmTlsConnector::new();
    // Just test creation for now
    assert!(true); // Placeholder - would need actual stream to test
}

#[wasm_bindgen_test]
async fn test_connection_manager_creation() {
    let provider = Arc::new(WasmTcpProvider::new());
    let manager = ConnectionManager::new(provider);

    assert_eq!(manager.pool_size(), 0);
}

// Note: The following tests require the bridge server to be running!
// Start with: cd ../bridge-server && node index.js 8080

#[wasm_bindgen_test]
#[ignore] // Requires bridge server
async fn test_connect_to_cloudflare() {
    // Test basic connectivity through bridge
    let config = NetworkConfig::with_bridge("ws://localhost:8080");
    let provider = WasmTcpProvider::with_config(config);

    // Connect to Cloudflare DNS
    let addr: SocketAddr = "1.1.1.1:80".parse().unwrap();

    match provider.connect_with_retry(&addr).await {
        Ok(mut stream) => {
            web_sys::console::log_1(&"✅ Connected to 1.1.1.1:80!".into());

            // Send HTTP request
            let request = b"GET / HTTP/1.0\r\nHost: 1.1.1.1\r\n\r\n";
            stream.write_all(request).await.unwrap();

            // Read response
            let mut response = vec![0u8; 1024];
            let n = stream.read(&mut response).await.unwrap();

            web_sys::console::log_1(&format!("✅ Received {} bytes", n).into());

            assert!(n > 0);

            // Check stats
            let stats = provider.get_stats();
            assert_eq!(stats.connections_attempted, 1);
            assert_eq!(stats.connections_successful, 1);
        }
        Err(e) => {
            web_sys::console::error_1(&format!("❌ Failed to connect: {}", e).into());
            panic!("Connection failed - is bridge server running?");
        }
    }
}

#[wasm_bindgen_test]
#[ignore] // Requires bridge server
async fn test_connect_to_tor_directory() {
    // Test connecting to a real Tor directory authority
    let config = NetworkConfig::with_bridge("ws://localhost:8080");
    let provider = WasmTcpProvider::with_config(config);

    // Try moria1 (MIT)
    let (name, addr_str) = DIR_AUTHORITIES[0];
    let addr: SocketAddr = addr_str.parse().unwrap();

    web_sys::console::log_1(&format!("🔌 Connecting to {} ({})", name, addr).into());

    match provider.connect_with_retry(&addr).await {
        Ok(mut stream) => {
            web_sys::console::log_1(&format!("✅ Connected to {}!", name).into());

            // Request consensus status
            let request = format!(
                "GET /tor/status-vote/current/consensus HTTP/1.0\r\n\
                 Host: {}\r\n\
                 \r\n",
                addr.ip()
            );

            stream.write_all(request.as_bytes()).await.unwrap();

            // Read first chunk of response
            let mut response = vec![0u8; 4096];
            let n = stream.read(&mut response).await.unwrap();

            web_sys::console::log_1(&format!("✅ Received {} bytes from directory", n).into());

            // Should be HTTP response
            let response_str = String::from_utf8_lossy(&response[..n]);
            assert!(response_str.contains("HTTP/"));

            web_sys::console::log_1(
                &format!("📄 Response preview: {}", &response_str[..200.min(n)]).into(),
            );

            // Check stats
            let stats = provider.get_stats();
            assert!(stats.connections_successful > 0);
        }
        Err(e) => {
            web_sys::console::error_1(&format!("❌ Failed to connect to {}: {}", name, e).into());
            panic!("Directory connection failed - is bridge server running?");
        }
    }
}

#[wasm_bindgen_test]
#[ignore] // Requires bridge server
async fn test_concurrent_connections() {
    // Test multiple simultaneous connections
    let config = NetworkConfig::with_bridge("ws://localhost:8080");
    let provider = Arc::new(WasmTcpProvider::with_config(config));
    let manager = ConnectionManager::new(Arc::clone(&provider));

    // Connect to multiple addresses
    let addresses = vec!["1.1.1.1:80".parse().unwrap(), "8.8.8.8:80".parse().unwrap()];

    for addr in addresses {
        match manager.get_connection(&addr).await {
            Ok(_stream) => {
                web_sys::console::log_1(&format!("✅ Connected to {}", addr).into());
            }
            Err(e) => {
                web_sys::console::error_1(
                    &format!("❌ Failed to connect to {}: {}", addr, e).into(),
                );
            }
        }
    }

    let stats = provider.get_stats();
    web_sys::console::log_1(
        &format!(
            "📊 Stats: {} attempted, {} successful",
            stats.connections_attempted, stats.connections_successful
        )
        .into(),
    );

    assert!(stats.connections_attempted >= 2);
}

#[wasm_bindgen_test]
#[ignore] // Requires bridge server
async fn test_connection_retry() {
    // Test retry logic with an invalid address
    let config = NetworkConfig {
        bridge_url: "ws://localhost:8080".to_string(),
        retry_on_failure: true,
        max_retries: 2,
        ..Default::default()
    };

    let provider = WasmTcpProvider::with_config(config);

    // Try to connect to an address that doesn't exist
    let addr: SocketAddr = "192.0.2.1:9999".parse().unwrap(); // TEST-NET-1 (reserved)

    let start = js_sys::Date::now();
    match provider.connect_with_retry(&addr).await {
        Ok(_) => {
            panic!("Should have failed to connect to reserved IP");
        }
        Err(e) => {
            let elapsed = js_sys::Date::now() - start;
            web_sys::console::log_1(
                &format!("✅ Correctly failed after {} ms: {}", elapsed, e).into(),
            );

            // Should have retried (with backoff)
            assert!(elapsed > 1000.0); // At least 1 second due to retries

            let stats = provider.get_stats();
            assert_eq!(stats.connections_failed, 1);
        }
    }
}

#[wasm_bindgen_test]
async fn test_statistics_tracking() {
    let provider = WasmTcpProvider::new();

    // Manually record some stats
    provider.record_bytes_sent(1024);
    provider.record_bytes_received(2048);

    let stats = provider.get_stats();
    assert_eq!(stats.bytes_sent, 1024);
    assert_eq!(stats.bytes_received, 2048);

    // Test reset
    provider.reset_stats();
    let stats = provider.get_stats();
    assert_eq!(stats.bytes_sent, 0);
    assert_eq!(stats.bytes_received, 0);
}
