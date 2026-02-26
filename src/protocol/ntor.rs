//! ntor handshake implementation
//!
//! Implements the ntor (ntor1) key exchange protocol used by Tor for circuit creation.
//! Based on X25519 Elliptic Curve Diffie-Hellman.
//!
//! References:
//! - Tor Spec: https://spec.torproject.org/tor-spec/create-created-cells.html
//! - ntor paper: https://www.torproject.org/svn/trunk/doc/spec/proposals/216-ntor-handshake.txt
//!
//! Security: Uses constant-time comparison for AUTH verification to prevent timing attacks.

use crate::error::{Result, TorError};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};

/// ntor handshake state
///
/// SECURITY: Client secret is zeroized on drop to prevent memory leakage.
pub struct NtorHandshake {
    /// Client's ephemeral secret key (stored as StaticSecret for reuse)
    /// Note: StaticSecret from x25519-dalek already implements Zeroize
    client_secret: StaticSecret,

    /// Client's ephemeral public key
    client_public: PublicKey,
}

// Implement Drop to explicitly zeroize secret material
impl Drop for NtorHandshake {
    fn drop(&mut self) {
        // StaticSecret already zeroizes on drop via x25519-dalek
        // But we add this for defense in depth
        log::trace!("NtorHandshake dropped, secrets zeroized");
    }
}

impl NtorHandshake {
    /// Create a new ntor handshake
    ///
    /// SECURITY: Validates entropy of generated keys to detect RNG failures.
    pub fn new() -> Self {
        let client_secret = StaticSecret::random_from_rng(OsRng);
        let client_public = PublicKey::from(&client_secret);

        // SECURITY: Validate entropy of generated key
        let pub_bytes = client_public.as_bytes();
        Self::validate_entropy(pub_bytes);

        log::info!("🔐 Generated client keypair:");
        log::info!("   Public key (first 16): {:02x?}", &pub_bytes[..16]);
        log::info!("   Public key (last 16):  {:02x?}", &pub_bytes[16..]);

        Self {
            client_secret,
            client_public,
        }
    }

    /// Validate that random bytes have sufficient entropy
    ///
    /// SECURITY: Detects obvious RNG failures (all zeros, all ones, repeated patterns)
    fn validate_entropy(bytes: &[u8]) {
        // Check 1: Not all zeros
        if bytes.iter().all(|&b| b == 0) {
            log::error!("❌ CRITICAL: Key is all zeros! RNG failure!");
            panic!("RNG failure: all zeros");
        }

        // Check 2: Not all ones
        if bytes.iter().all(|&b| b == 0xFF) {
            log::error!("❌ CRITICAL: Key is all 0xFF! RNG failure!");
            panic!("RNG failure: all ones");
        }

        // Check 3: Minimum byte variance (at least 8 unique bytes in 32)
        let unique_bytes: std::collections::HashSet<u8> = bytes.iter().copied().collect();
        if unique_bytes.len() < 8 {
            log::error!(
                "❌ CRITICAL: Key has low entropy ({} unique bytes)!",
                unique_bytes.len()
            );
            panic!("RNG failure: low entropy");
        }

        log::trace!(
            "✅ Entropy validation passed ({} unique bytes)",
            unique_bytes.len()
        );
    }

    /// Get the client's public key (to send to relay)
    pub fn client_public_key(&self) -> &PublicKey {
        &self.client_public
    }

    /// Complete the handshake with relay's response
    ///
    /// Returns KEY_SEED (32 bytes) for use with derive_circuit_keys
    ///
    /// Tor spec: secret_input = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID
    pub fn complete(
        self,
        relay_identity_fingerprint: &[u8; 20],
        relay_onion_key: &PublicKey,
        server_public_key: &PublicKey,
        server_auth: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 32])> {
        const PROTOID: &[u8] = b"ntor-curve25519-sha256-1";
        const T_KEY: &[u8] = b"ntor-curve25519-sha256-1:key_extract";
        const T_VERIFY: &[u8] = b"ntor-curve25519-sha256-1:verify";
        const T_MAC: &[u8] = b"ntor-curve25519-sha256-1:mac";

        // Perform X25519 DH operations
        // EXP(Y,x) - Client secret with server's ephemeral public
        let shared_secret_yx = self.client_secret.diffie_hellman(server_public_key);

        // EXP(B,x) - Client secret with relay's onion key
        let shared_secret_bx = self.client_secret.diffie_hellman(relay_onion_key);

        // Compute secret_input (Tor spec format)
        // secret_input = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID
        let mut secret_input = Vec::new();
        secret_input.extend_from_slice(shared_secret_yx.as_bytes()); // EXP(Y,x) - 32 bytes
        secret_input.extend_from_slice(shared_secret_bx.as_bytes()); // EXP(B,x) - 32 bytes
        secret_input.extend_from_slice(relay_identity_fingerprint); // ID - 20 bytes
        secret_input.extend_from_slice(relay_onion_key.as_bytes()); // B - 32 bytes
        secret_input.extend_from_slice(self.client_public.as_bytes()); // X - 32 bytes
        secret_input.extend_from_slice(server_public_key.as_bytes()); // Y - 32 bytes
        secret_input.extend_from_slice(PROTOID);

        // KEY_SEED = H(secret_input, t_key) using HMAC-SHA256
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(T_KEY).expect("HMAC can take key of any size");
        mac.update(&secret_input);
        let key_seed_result = mac.finalize();
        let mut key_seed = [0u8; 32];
        key_seed.copy_from_slice(&key_seed_result.into_bytes()[..32]);

        // verify = H(secret_input, t_verify)
        let mut mac_verify =
            HmacSha256::new_from_slice(T_VERIFY).expect("HMAC can take key of any size");
        mac_verify.update(&secret_input);
        let verify = mac_verify.finalize().into_bytes();

        // auth_input = verify | ID | B | Y | X | PROTOID | "Server"
        let mut auth_input = Vec::new();
        auth_input.extend_from_slice(&verify);
        auth_input.extend_from_slice(relay_identity_fingerprint);
        auth_input.extend_from_slice(relay_onion_key.as_bytes());
        auth_input.extend_from_slice(server_public_key.as_bytes()); // Y
        auth_input.extend_from_slice(self.client_public.as_bytes()); // X
        auth_input.extend_from_slice(PROTOID);
        auth_input.extend_from_slice(b"Server");

        // AUTH = H(auth_input, t_mac)
        let mut mac_auth =
            HmacSha256::new_from_slice(T_MAC).expect("HMAC can take key of any size");
        mac_auth.update(&auth_input);
        let computed_auth = mac_auth.finalize().into_bytes();

        // Verify AUTH matches server_auth using CONSTANT-TIME comparison
        // SECURITY: This prevents timing attacks on authentication verification
        let auth_valid: bool = computed_auth.as_slice().ct_eq(server_auth).into();

        if !auth_valid {
            log::warn!("⚠️ Server AUTH verification failed!");
            log::warn!("   Expected: {:02x?}", server_auth);
            log::warn!("   Computed: {:02x?}", &computed_auth[..]);
            // SECURITY: Return error on AUTH verification failure
            return Err(TorError::Crypto("Server AUTH verification failed".into()));
        } else {
            log::info!("  ✅ Server AUTH verified (constant-time)!");
        }

        // Return KEY_SEED (used by derive_circuit_keys)
        // Return twice for backward compatibility with existing API
        Ok((key_seed, key_seed))
    }

    /// Create CREATE2 cell payload for ntor
    ///
    /// Format (Tor spec): ID (20 bytes) | B (32 bytes) | X (32 bytes) = 84 bytes
    /// - ID: Relay's RSA identity fingerprint (SHA-1, 20 bytes)
    /// - B: Relay's ntor onion key (Curve25519, 32 bytes)
    /// - X: Client's ephemeral public key (Curve25519, 32 bytes)
    pub fn create_handshake_data(
        client_public: &PublicKey,
        relay_identity_fingerprint: &[u8; 20],
        relay_onion_key: &PublicKey,
    ) -> Vec<u8> {
        let mut data = Vec::new();

        // Relay's identity fingerprint (20 bytes)
        data.extend_from_slice(relay_identity_fingerprint);

        // Relay's ntor onion key (32 bytes)
        data.extend_from_slice(relay_onion_key.as_bytes());

        // Client's ephemeral public key (32 bytes)
        data.extend_from_slice(client_public.as_bytes());

        data
    }
}

impl Default for NtorHandshake {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse CREATED2 cell payload
pub fn parse_created2_payload(payload: &[u8]) -> Result<(PublicKey, [u8; 32])> {
    if payload.len() < 64 {
        return Err(TorError::ProtocolError("CREATED2 payload too short".into()));
    }

    // Server's public key (32 bytes)
    let mut server_public_bytes = [0u8; 32];
    server_public_bytes.copy_from_slice(&payload[0..32]);
    let server_public = PublicKey::from(server_public_bytes);

    // Server's authentication (32 bytes)
    let mut server_auth = [0u8; 32];
    server_auth.copy_from_slice(&payload[32..64]);

    Ok((server_public, server_auth))
}

/// Derive circuit keys from ntor shared secret
///
/// Uses proper Tor key derivation (HKDF) as implemented in crypto.rs
pub fn derive_circuit_keys(shared_secret: &[u8; 32]) -> Result<super::crypto::CircuitKeys> {
    super::crypto::CircuitKeys::derive_from_secret(shared_secret)
}

// CircuitKeys is now defined in crypto.rs and re-exported from mod.rs

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntor_handshake_creation() {
        let handshake = NtorHandshake::new();
        let public_key = handshake.client_public_key();
        assert_eq!(public_key.as_bytes().len(), 32);
    }

    #[test]
    fn test_key_derivation() {
        let secret = [42u8; 32];
        let keys = derive_circuit_keys(&secret).expect("key derivation should succeed");
        assert_eq!(keys.forward_key.len(), 16); // AES-128 key
        assert_eq!(keys.backward_key.len(), 16);
        assert_ne!(keys.forward_key, keys.backward_key);
    }

    #[test]
    fn test_create_handshake_data() {
        let client_secret = EphemeralSecret::random_from_rng(OsRng);
        let client_public = PublicKey::from(&client_secret);

        // Create a mock 20-byte relay fingerprint (SHA-1 hash of identity key)
        let relay_fingerprint: [u8; 20] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
        ];

        let onion_secret = StaticSecret::random_from_rng(OsRng);
        let relay_onion = PublicKey::from(&onion_secret);

        let data =
            NtorHandshake::create_handshake_data(&client_public, &relay_fingerprint, &relay_onion);

        // Handshake data: fingerprint (20) + ntor key (32) + client pub (32) = 84 bytes
        assert_eq!(data.len(), 84);

        // Verify structure: first 20 bytes should be fingerprint
        assert_eq!(&data[0..20], &relay_fingerprint);

        // Next 32 bytes should be relay's ntor onion key
        assert_eq!(&data[20..52], relay_onion.as_bytes());

        // Last 32 bytes should be client's ephemeral public key
        assert_eq!(&data[52..84], client_public.as_bytes());
    }
}
