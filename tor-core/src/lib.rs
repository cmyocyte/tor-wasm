//! tor-core: Platform-agnostic Tor client core
//! 
//! This crate contains the core Tor protocol implementation without
//! any platform-specific dependencies. It can be used in:
//! - Browsers (via wasm-bindgen wrapper)
//! - IoT devices (via embedded WASM runtime)
//! - Native applications (via tokio/async-std)
//!
//! The platform must provide implementations of the `Network` and
//! `Random` traits.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use alloc::string::String;

pub mod crypto;
pub mod protocol;
pub mod error;

// Re-export everything for easy access
pub use error::TorError;
pub use crypto::NtorHandshake;
pub use protocol::{Cell, CellCommand, RelayCommand, create_versions_cell, create_netinfo_cell, create_create2_cell};

// ============================================================================
// FFI exports for embedded WASM runtimes
// These are the C-compatible functions that embedded systems will call
// ============================================================================

/// Test RNG implementation for size measurement
struct TestRng {
    state: u32,
}

impl TestRng {
    fn new(seed: u32) -> Self {
        Self { state: seed }
    }
}

impl Random for TestRng {
    fn fill_bytes(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            // Simple xorshift PRNG for testing
            self.state ^= self.state << 13;
            self.state ^= self.state >> 17;
            self.state ^= self.state << 5;
            *b = self.state as u8;
        }
    }
}

/// Create ntor handshake data (84 bytes)
/// 
/// # Arguments
/// * `relay_id` - 20-byte relay identity fingerprint
/// * `relay_ntor` - 32-byte relay ntor onion key
/// * `seed` - random seed for key generation
/// * `out` - output buffer (must be >= 84 bytes)
/// 
/// # Returns
/// * Number of bytes written (84) on success
/// * 0 on error
#[no_mangle]
pub extern "C" fn tor_create_handshake(
    relay_id: *const u8,
    relay_ntor: *const u8,
    seed: u32,
    out: *mut u8,
) -> u32 {
    if relay_id.is_null() || relay_ntor.is_null() || out.is_null() {
        return 0;
    }
    
    unsafe {
        let id_slice = core::slice::from_raw_parts(relay_id, 20);
        let ntor_slice = core::slice::from_raw_parts(relay_ntor, 32);
        
        let mut id = [0u8; 20];
        let mut ntor = [0u8; 32];
        id.copy_from_slice(id_slice);
        ntor.copy_from_slice(ntor_slice);
        
        let mut rng = TestRng::new(seed);
        let handshake = NtorHandshake::new(&mut rng, id, ntor);
        let data = handshake.handshake_data();
        
        let out_slice = core::slice::from_raw_parts_mut(out, 84);
        out_slice.copy_from_slice(&data);
        
        84
    }
}

/// Parse a Tor cell from bytes
/// 
/// # Arguments
/// * `data` - input buffer (514 bytes)
/// * `circuit_id_out` - output for circuit ID
/// * `command_out` - output for command byte
/// 
/// # Returns
/// * 1 on success, 0 on error
#[no_mangle]
pub extern "C" fn tor_parse_cell(
    data: *const u8,
    circuit_id_out: *mut u32,
    command_out: *mut u8,
) -> u32 {
    if data.is_null() || circuit_id_out.is_null() || command_out.is_null() {
        return 0;
    }
    
    unsafe {
        let data_slice = core::slice::from_raw_parts(data, 514);
        
        match Cell::from_bytes(data_slice) {
            Ok(cell) => {
                *circuit_id_out = cell.circuit_id;
                *command_out = cell.command as u8;
                1
            }
            Err(_) => 0,
        }
    }
}

/// Create a VERSIONS cell
/// 
/// # Arguments
/// * `out` - output buffer (must be >= 16 bytes)
/// 
/// # Returns
/// * Number of bytes written
#[no_mangle]
pub extern "C" fn tor_create_versions_cell(out: *mut u8) -> u32 {
    if out.is_null() {
        return 0;
    }
    
    let cell = create_versions_cell(&[4, 5]);
    
    unsafe {
        let out_slice = core::slice::from_raw_parts_mut(out, cell.len());
        out_slice.copy_from_slice(&cell);
    }
    
    cell.len() as u32
}

/// Create a CREATE2 cell
/// 
/// # Arguments
/// * `circuit_id` - circuit ID
/// * `handshake_data` - 84-byte handshake data
/// * `out` - output buffer (must be >= 514 bytes)
/// 
/// # Returns
/// * 514 (cell size) on success, 0 on error
#[no_mangle]
pub extern "C" fn tor_create_create2_cell(
    circuit_id: u32,
    handshake_data: *const u8,
    out: *mut u8,
) -> u32 {
    if handshake_data.is_null() || out.is_null() {
        return 0;
    }
    
    unsafe {
        let hs_slice = core::slice::from_raw_parts(handshake_data, 84);
        let cell = create_create2_cell(circuit_id, hs_slice);
        let bytes = cell.to_bytes();
        
        let out_slice = core::slice::from_raw_parts_mut(out, bytes.len());
        out_slice.copy_from_slice(&bytes);
        
        bytes.len() as u32
    }
}

// ============================================================================
// AES encryption functions (for onion layers)
// ============================================================================

use aes::Aes128;
use ctr::{Ctr128BE, cipher::{KeyIvInit, StreamCipher}};
use sha1::Sha1;
use sha1::Digest as Sha1Digest;

type Aes128Ctr = Ctr128BE<Aes128>;

/// Encrypt data with AES-128-CTR (one onion layer)
/// 
/// # Arguments
/// * `key` - 16-byte AES key
/// * `data` - data to encrypt (in-place)
/// * `len` - length of data
/// 
/// # Returns
/// * 1 on success, 0 on error
#[no_mangle]
pub extern "C" fn tor_aes_encrypt(
    key: *const u8,
    data: *mut u8,
    len: u32,
) -> u32 {
    if key.is_null() || data.is_null() {
        return 0;
    }
    
    unsafe {
        let key_slice = core::slice::from_raw_parts(key, 16);
        let data_slice = core::slice::from_raw_parts_mut(data, len as usize);
        
        let iv = [0u8; 16]; // Tor uses counter starting from 0
        let mut cipher = Aes128Ctr::new(key_slice.into(), &iv.into());
        cipher.apply_keystream(data_slice);
        
        1
    }
}

/// Calculate SHA1 digest (for relay cell verification)
/// 
/// # Arguments
/// * `data` - data to hash
/// * `len` - length of data
/// * `out` - 20-byte output buffer
/// 
/// # Returns
/// * 1 on success, 0 on error
#[no_mangle]
pub extern "C" fn tor_sha1(
    data: *const u8,
    len: u32,
    out: *mut u8,
) -> u32 {
    if data.is_null() || out.is_null() {
        return 0;
    }
    
    unsafe {
        let data_slice = core::slice::from_raw_parts(data, len as usize);
        let out_slice = core::slice::from_raw_parts_mut(out, 20);
        
        let mut hasher = Sha1::new();
        hasher.update(data_slice);
        let result = hasher.finalize();
        out_slice.copy_from_slice(&result);
        
        1
    }
}

/// Complete ntor handshake and derive keys
/// 
/// # Arguments
/// * `relay_id` - 20-byte relay identity
/// * `relay_ntor` - 32-byte relay ntor key
/// * `client_public` - 32-byte client public key (from handshake)
/// * `server_response` - 64-byte server response (Y || AUTH)
/// * `keys_out` - 72-byte output buffer for derived keys (Df, Db, Kf, Kb)
/// 
/// # Returns
/// * 1 on success, 0 on error (e.g., AUTH verification failed)
#[no_mangle]
pub extern "C" fn tor_complete_handshake(
    relay_id: *const u8,
    relay_ntor: *const u8,
    seed: u32,
    server_response: *const u8,
    keys_out: *mut u8,
) -> u32 {
    if relay_id.is_null() || relay_ntor.is_null() || server_response.is_null() || keys_out.is_null() {
        return 0;
    }
    
    unsafe {
        let id_slice = core::slice::from_raw_parts(relay_id, 20);
        let ntor_slice = core::slice::from_raw_parts(relay_ntor, 32);
        let response_slice = core::slice::from_raw_parts(server_response, 64);
        let keys_slice = core::slice::from_raw_parts_mut(keys_out, 72);
        
        let mut id = [0u8; 20];
        let mut ntor = [0u8; 32];
        id.copy_from_slice(id_slice);
        ntor.copy_from_slice(ntor_slice);
        
        let mut rng = TestRng::new(seed);
        let handshake = NtorHandshake::new(&mut rng, id, ntor);
        
        match handshake.complete(response_slice) {
            Ok(keys) => {
                keys_slice[0..20].copy_from_slice(&keys.forward_digest);
                keys_slice[20..40].copy_from_slice(&keys.backward_digest);
                keys_slice[40..56].copy_from_slice(&keys.forward_key);
                keys_slice[56..72].copy_from_slice(&keys.backward_key);
                1
            }
            Err(_) => 0,
        }
    }
}

/// Result type for Tor operations
pub type Result<T> = core::result::Result<T, TorError>;

/// Network abstraction trait - platform must implement this
pub trait Network {
    /// Connect to a relay at the given address
    fn connect(&mut self, addr: &str, port: u16) -> Result<()>;
    
    /// Send data to the connected relay
    fn send(&mut self, data: &[u8]) -> Result<()>;
    
    /// Receive data from the connected relay
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize>;
    
    /// Close the connection
    fn close(&mut self);
}

/// Random number generator trait - platform must implement this
pub trait Random {
    /// Fill buffer with random bytes
    fn fill_bytes(&mut self, buf: &mut [u8]);
    
    /// Generate a random u32
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }
}

/// Relay information
#[derive(Clone)]
pub struct Relay {
    pub nickname: String,
    pub address: String,
    pub or_port: u16,
    pub fingerprint: [u8; 20],
    pub ntor_onion_key: [u8; 32],
    pub flags: RelayFlags,
}

/// Relay capability flags
#[derive(Clone, Default)]
pub struct RelayFlags {
    pub guard: bool,
    pub exit: bool,
    pub stable: bool,
    pub fast: bool,
    pub valid: bool,
}

/// Circuit keys derived from ntor handshake
pub struct CircuitKeys {
    pub forward_digest: [u8; 20],
    pub backward_digest: [u8; 20],
    pub forward_key: [u8; 16],
    pub backward_key: [u8; 16],
}

/// Tor circuit (3-hop path through network)
pub struct Circuit<N: Network> {
    network: N,
    circuit_id: u32,
    hops: Vec<CircuitHop>,
}

struct CircuitHop {
    keys: CircuitKeys,
    // Cipher state would go here
}

impl<N: Network> Circuit<N> {
    /// Create a new circuit through the given relays
    pub fn new<R: Random>(
        mut network: N,
        rng: &mut R,
        guard: &Relay,
        middle: &Relay,
        exit: &Relay,
    ) -> Result<Self> {
        // Generate circuit ID with high bit set (client-initiated)
        let circuit_id = rng.next_u32() | 0x80000000;
        
        // Connect to guard
        network.connect(&guard.address, guard.or_port)?;
        
        // TODO: Protocol handshake, CREATE2, EXTEND2, etc.
        // This is where the full implementation would go
        
        Ok(Self {
            network,
            circuit_id,
            hops: Vec::new(),
        })
    }
    
    /// Send data through the circuit
    pub fn send(&mut self, _data: &[u8]) -> Result<()> {
        // TODO: Onion encrypt and send
        Ok(())
    }
    
    /// Receive data from the circuit
    pub fn recv(&mut self, _buf: &mut [u8]) -> Result<usize> {
        // TODO: Receive and onion decrypt
        Ok(0)
    }
}

