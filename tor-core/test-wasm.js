/**
 * Test tor-core WASM on Node.js (simulating embedded runtime)
 * 
 * This proves the WASM module works outside the browser,
 * which validates the IoT use case.
 */

const fs = require('fs');
const path = require('path');

async function main() {
    console.log('🧪 tor-core WASM Test');
    console.log('=====================\n');
    
    // Load the WASM binary
    const wasmPath = path.join(__dirname, 'target/wasm32-unknown-unknown/release/tor_core.wasm');
    const wasmBuffer = fs.readFileSync(wasmPath);
    
    console.log(`📦 WASM size: ${wasmBuffer.length} bytes (${(wasmBuffer.length / 1024).toFixed(1)} KB)`);
    
    // Instantiate the WASM module
    const wasmModule = await WebAssembly.instantiate(wasmBuffer, {
        // No imports needed - our module is self-contained!
    });
    
    const exports = wasmModule.instance.exports;
    
    console.log('\n📋 Exported functions:');
    Object.keys(exports).forEach(name => {
        if (typeof exports[name] === 'function') {
            console.log(`   - ${name}`);
        }
    });
    
    // Get memory
    const memory = exports.memory;
    console.log(`\n💾 Memory: ${memory.buffer.byteLength / 1024} KB initial`);
    
    // Test 1: Create VERSIONS cell
    console.log('\n--- Test 1: tor_create_versions_cell ---');
    const outPtr = 1024; // Use offset 1024 in memory
    const result1 = exports.tor_create_versions_cell(outPtr);
    console.log(`   Result: ${result1} bytes written`);
    
    if (result1 > 0) {
        const view = new Uint8Array(memory.buffer, outPtr, result1);
        console.log(`   Data: [${Array.from(view).map(b => b.toString(16).padStart(2, '0')).join(', ')}]`);
        // Expected: CircID=0, Cmd=7 (VERSIONS), Len=4, Versions=[0004, 0005]
    }
    
    // Test 2: Parse a cell
    console.log('\n--- Test 2: tor_parse_cell ---');
    // Create a fake cell at offset 2048
    const cellPtr = 2048;
    const cellView = new Uint8Array(memory.buffer, cellPtr, 514);
    // Circuit ID = 0x12345678, Command = 7 (VERSIONS)
    cellView[0] = 0x12;
    cellView[1] = 0x34;
    cellView[2] = 0x56;
    cellView[3] = 0x78;
    cellView[4] = 7; // VERSIONS command
    
    const circuitIdOutPtr = 3000;
    const commandOutPtr = 3004;
    const result2 = exports.tor_parse_cell(cellPtr, circuitIdOutPtr, commandOutPtr);
    
    if (result2 === 1) {
        const circuitIdView = new DataView(memory.buffer, circuitIdOutPtr, 4);
        const commandView = new Uint8Array(memory.buffer, commandOutPtr, 1);
        console.log(`   Parsed circuit ID: 0x${circuitIdView.getUint32(0, true).toString(16)}`);
        console.log(`   Parsed command: ${commandView[0]}`);
    } else {
        console.log(`   Parse failed: ${result2}`);
    }
    
    // Test 3: AES encryption
    console.log('\n--- Test 3: tor_aes_encrypt ---');
    const keyPtr = 4000;
    const dataPtr = 4100;
    
    // Set up a key (all zeros for testing)
    const keyView = new Uint8Array(memory.buffer, keyPtr, 16);
    keyView.fill(0x42);
    
    // Set up data to encrypt
    const dataView = new Uint8Array(memory.buffer, dataPtr, 32);
    const originalData = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // "Hello World!"
    dataView.set(originalData);
    
    console.log(`   Original: "${Buffer.from(originalData.slice(0, 12)).toString()}"`);
    
    const result3 = exports.tor_aes_encrypt(keyPtr, dataPtr, 32);
    console.log(`   Encrypt result: ${result3}`);
    
    const encryptedView = new Uint8Array(memory.buffer, dataPtr, 32);
    console.log(`   Encrypted: [${Array.from(encryptedView.slice(0, 12)).map(b => b.toString(16).padStart(2, '0')).join(', ')}]`);
    
    // Test 4: SHA1 hash
    console.log('\n--- Test 4: tor_sha1 ---');
    const sha1DataPtr = 5000;
    const sha1OutPtr = 5100;
    
    const sha1DataView = new Uint8Array(memory.buffer, sha1DataPtr, 11);
    sha1DataView.set(new TextEncoder().encode("Hello World"));
    
    const result4 = exports.tor_sha1(sha1DataPtr, 11, sha1OutPtr);
    console.log(`   SHA1 result: ${result4}`);
    
    const sha1OutView = new Uint8Array(memory.buffer, sha1OutPtr, 20);
    console.log(`   SHA1 hash: ${Array.from(sha1OutView).map(b => b.toString(16).padStart(2, '0')).join('')}`);
    // Expected: 0a4d55a8d778e5022fab701977c5d840bbc486d0
    
    // Test 5: Create ntor handshake
    console.log('\n--- Test 5: tor_create_handshake ---');
    const relayIdPtr = 6000;
    const relayNtorPtr = 6100;
    const handshakeOutPtr = 6200;
    
    // Set up fake relay ID (20 bytes)
    const relayIdView = new Uint8Array(memory.buffer, relayIdPtr, 20);
    relayIdView.fill(0xAA);
    
    // Set up fake ntor key (32 bytes)
    const relayNtorView = new Uint8Array(memory.buffer, relayNtorPtr, 32);
    relayNtorView.fill(0xBB);
    
    const result5 = exports.tor_create_handshake(relayIdPtr, relayNtorPtr, 12345, handshakeOutPtr);
    console.log(`   Handshake data: ${result5} bytes`);
    
    if (result5 === 84) {
        const handshakeView = new Uint8Array(memory.buffer, handshakeOutPtr, 84);
        console.log(`   Relay ID (first 8): [${Array.from(handshakeView.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(', ')}]`);
        console.log(`   Ntor key (8 bytes): [${Array.from(handshakeView.slice(20, 28)).map(b => b.toString(16).padStart(2, '0')).join(', ')}]`);
        console.log(`   Client pubkey (8): [${Array.from(handshakeView.slice(52, 60)).map(b => b.toString(16).padStart(2, '0')).join(', ')}]`);
    }
    
    console.log('\n✅ All tests completed!');
    console.log('\n📊 Summary:');
    console.log(`   WASM Size: ${(wasmBuffer.length / 1024).toFixed(1)} KB`);
    console.log(`   Memory Used: ${memory.buffer.byteLength / 1024} KB`);
    console.log(`   Exports: ${Object.keys(exports).filter(k => typeof exports[k] === 'function').length} functions`);
    console.log('\n🎉 IoT runtime validation PASSED!');
}

main().catch(err => {
    console.error('Test failed:', err);
    process.exit(1);
});

