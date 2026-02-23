//! Cryptographic primitives for Tor protocol

use alloc::vec::Vec;
use x25519_dalek::{PublicKey, StaticSecret};
use hkdf::Hkdf;
use sha2::Sha256;
use hmac::{Hmac, Mac};

use crate::{CircuitKeys, Random, Result, TorError};

type HmacSha256 = Hmac<Sha256>;

/// ntor handshake constants
const PROTOID: &[u8] = b"ntor-curve25519-sha256-1";
const T_MAC: &[u8] = b"ntor-curve25519-sha256-1:mac";
const T_KEY: &[u8] = b"ntor-curve25519-sha256-1:key_extract";
const T_VERIFY: &[u8] = b"ntor-curve25519-sha256-1:verify";
const M_EXPAND: &[u8] = b"ntor-curve25519-sha256-1:key_expand";

/// ntor handshake state
pub struct NtorHandshake {
    client_secret: StaticSecret,
    client_public: PublicKey,
    relay_identity: [u8; 20],
    relay_ntor_key: [u8; 32],
}

impl NtorHandshake {
    /// Create new handshake with random ephemeral key
    pub fn new<R: Random>(rng: &mut R, relay_identity: [u8; 20], relay_ntor_key: [u8; 32]) -> Self {
        let mut secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_bytes);
        
        let client_secret = StaticSecret::from(secret_bytes);
        let client_public = PublicKey::from(&client_secret);
        
        Self {
            client_secret,
            client_public,
            relay_identity,
            relay_ntor_key,
        }
    }
    
    /// Get client public key for CREATE2 cell
    pub fn client_public_key(&self) -> [u8; 32] {
        *self.client_public.as_bytes()
    }
    
    /// Get handshake data for CREATE2 cell (84 bytes)
    pub fn handshake_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(84);
        data.extend_from_slice(&self.relay_identity);  // 20 bytes
        data.extend_from_slice(&self.relay_ntor_key);  // 32 bytes
        data.extend_from_slice(self.client_public.as_bytes()); // 32 bytes
        data
    }
    
    /// Complete handshake with server response (Y || AUTH)
    pub fn complete(&self, server_response: &[u8]) -> Result<CircuitKeys> {
        if server_response.len() < 64 {
            return Err(TorError::Protocol("Server response too short".into()));
        }
        
        let server_public_bytes: [u8; 32] = server_response[0..32]
            .try_into()
            .map_err(|_| TorError::Protocol("Invalid server public key".into()))?;
        let server_auth: [u8; 32] = server_response[32..64]
            .try_into()
            .map_err(|_| TorError::Protocol("Invalid server auth".into()))?;
        
        let server_public = PublicKey::from(server_public_bytes);
        let relay_ntor_public = PublicKey::from(self.relay_ntor_key);
        
        // Compute shared secrets
        let exp_y = self.client_secret.diffie_hellman(&server_public);
        let exp_b = self.client_secret.diffie_hellman(&relay_ntor_public);
        
        // Compute secret_input
        let mut secret_input = Vec::new();
        secret_input.extend_from_slice(exp_y.as_bytes());
        secret_input.extend_from_slice(exp_b.as_bytes());
        secret_input.extend_from_slice(&self.relay_identity);
        secret_input.extend_from_slice(&self.relay_ntor_key);
        secret_input.extend_from_slice(self.client_public.as_bytes());
        secret_input.extend_from_slice(&server_public_bytes);
        secret_input.extend_from_slice(PROTOID);
        
        // Derive KEY_SEED
        let mut key_seed_mac = HmacSha256::new_from_slice(T_KEY)
            .map_err(|_| TorError::Crypto("HMAC init failed".into()))?;
        key_seed_mac.update(&secret_input);
        let key_seed = key_seed_mac.finalize().into_bytes();
        
        // Verify server AUTH
        let mut verify_mac = HmacSha256::new_from_slice(T_VERIFY)
            .map_err(|_| TorError::Crypto("HMAC init failed".into()))?;
        verify_mac.update(&secret_input);
        let verify = verify_mac.finalize().into_bytes();
        
        let mut auth_input = Vec::new();
        auth_input.extend_from_slice(&verify);
        auth_input.extend_from_slice(&self.relay_identity);
        auth_input.extend_from_slice(&self.relay_ntor_key);
        auth_input.extend_from_slice(&server_public_bytes);
        auth_input.extend_from_slice(self.client_public.as_bytes());
        auth_input.extend_from_slice(PROTOID);
        auth_input.extend_from_slice(b"Server");
        
        let mut auth_mac = HmacSha256::new_from_slice(T_MAC)
            .map_err(|_| TorError::Crypto("HMAC init failed".into()))?;
        auth_mac.update(&auth_input);
        let expected_auth = auth_mac.finalize().into_bytes();
        
        // Constant-time comparison
        if !constant_time_compare(&server_auth, &expected_auth[..32]) {
            return Err(TorError::Crypto("Server AUTH verification failed".into()));
        }
        
        // Derive circuit keys using HKDF
        derive_circuit_keys(&key_seed)
    }
}

/// Derive circuit keys from KEY_SEED
fn derive_circuit_keys(key_seed: &[u8]) -> Result<CircuitKeys> {
    let hkdf = Hkdf::<Sha256>::from_prk(key_seed)
        .map_err(|_| TorError::Crypto("HKDF from PRK failed".into()))?;
    
    // Need: Df(20) + Db(20) + Kf(16) + Kb(16) = 72 bytes
    let mut okm = [0u8; 72];
    hkdf.expand(M_EXPAND, &mut okm)
        .map_err(|_| TorError::Crypto("HKDF expand failed".into()))?;
    
    Ok(CircuitKeys {
        forward_digest: okm[0..20].try_into().unwrap(),
        backward_digest: okm[20..40].try_into().unwrap(),
        forward_key: okm[40..56].try_into().unwrap(),
        backward_key: okm[56..72].try_into().unwrap(),
    })
}

/// Constant-time comparison to prevent timing attacks
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    
    struct TestRng([u8; 32]);
    
    impl Random for TestRng {
        fn fill_bytes(&mut self, buf: &mut [u8]) {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = self.0[i % 32];
            }
        }
    }
    
    #[test]
    fn test_handshake_data_length() {
        let mut rng = TestRng([0x42; 32]);
        let handshake = NtorHandshake::new(&mut rng, [0u8; 20], [0u8; 32]);
        assert_eq!(handshake.handshake_data().len(), 84);
    }
}

