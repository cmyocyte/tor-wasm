//! Basic usage example of tor-wasm
//!
//! This demonstrates the core functionality of the WASM runtime.

use std::time::Duration;
use tor_wasm::{BridgeConfig, WasmRuntime, WasmTcpStream};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();

    // Create WASM runtime with custom bridge
    let runtime = WasmRuntime::with_bridge_url("ws://localhost:8080".to_string());

    println!("Runtime created with bridge: {}", runtime.bridge_url());

    // Example 1: Sleep
    println!("Sleeping for 100ms...");
    runtime.sleep(Duration::from_millis(100)).await;
    println!("Done sleeping!");

    // Example 2: Spawn async tasks
    println!("Spawning async task...");
    runtime.spawn(async {
        println!("Task running in background!");
    })?;

    // Example 3: Time operations
    let instant = runtime.now_coarse();
    println!("Current coarse time: {:?}", instant);

    // Example 4: Connect via WebSocket (requires bridge server)
    println!("\nTo connect to Tor:");
    println!("1. Start bridge server: cd bridge-server && npm start");
    println!("2. Then run this example");

    // Uncomment when bridge server is running:
    /*
    let config = BridgeConfig::new("ws://localhost:8080".to_string());
    let addr = "1.1.1.1:443".parse()?;
    let url = config.build_url(&addr);

    println!("Connecting to {}", url);
    let mut stream = WasmTcpStream::connect(&url).await?;

    // Send HTTP request
    let request = b"GET / HTTP/1.0\r\nHost: 1.1.1.1\r\n\r\n";
    stream.write_all(request).await?;
    stream.flush().await?;

    // Read response
    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await?;
    println!("Received {} bytes: {}", n, String::from_utf8_lossy(&buf[..n]));

    stream.close().await?;
    */

    println!("\n✅ Basic runtime functionality works!");

    Ok(())
}
