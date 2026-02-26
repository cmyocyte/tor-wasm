//! Bridge blinding: encrypt the target relay address so Bridge A cannot see it.
//!
//! Uses X25519 ECDH + HKDF-SHA256 + AES-256-GCM to encrypt the relay address
//! under Bridge B's static public key. Bridge A forwards the opaque blob to
//! Bridge B, which decrypts it to learn the actual relay address.
//!
//! This ensures no single bridge operator can correlate client IP with guard relay IP.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

/// Info string for HKDF key derivation (domain separation)
const HKDF_INFO: &[u8] = b"tor-wasm-bridge-blind-v1";

/// Nonce for AES-GCM (fixed since each ephemeral key is used exactly once)
const FIXED_NONCE: &[u8; 12] = b"bridge-blind";

/// Encrypt a relay address for Bridge B.
///
/// Returns a base64url-encoded blob: `ephemeral_pubkey (32 bytes) || ciphertext`.
/// Bridge A cannot decrypt this — only Bridge B (with its static private key) can.
pub fn blind_target_address(
    relay_addr: &str,
    bridge_b_pubkey: &[u8; 32],
) -> Result<String, String> {
    // Generate ephemeral X25519 keypair
    let mut rng = rand::thread_rng();
    let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    // Compute shared secret: g^{eb}
    let bridge_b_key = PublicKey::from(*bridge_b_pubkey);
    let shared_secret: SharedSecret = ephemeral_secret.diffie_hellman(&bridge_b_key);

    // Derive AES-256 key via HKDF
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut aes_key = [0u8; 32];
    hkdf.expand(HKDF_INFO, &mut aes_key)
        .map_err(|_| "HKDF expand failed".to_string())?;

    // Encrypt the relay address with AES-256-GCM
    let cipher =
        Aes256Gcm::new_from_slice(&aes_key).map_err(|e| format!("AES key init failed: {}", e))?;
    let nonce = Nonce::from_slice(FIXED_NONCE);
    let ciphertext = cipher
        .encrypt(nonce, relay_addr.as_bytes())
        .map_err(|e| format!("AES-GCM encrypt failed: {}", e))?;

    // Concatenate: ephemeral_pubkey (32) || ciphertext (variable + 16 byte tag)
    let mut blob = Vec::with_capacity(32 + ciphertext.len());
    blob.extend_from_slice(ephemeral_public.as_bytes());
    blob.extend_from_slice(&ciphertext);

    // Base64url encode for URL-safe transport
    Ok(URL_SAFE_NO_PAD.encode(&blob))
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::StaticSecret;

    /// Simulate Bridge B decrypting the blinded address
    fn decrypt_blinded_address(
        blob_b64: &str,
        bridge_b_secret: &StaticSecret,
    ) -> Result<String, String> {
        let blob = URL_SAFE_NO_PAD
            .decode(blob_b64)
            .map_err(|e| format!("base64 decode failed: {}", e))?;

        if blob.len() < 32 + 16 {
            return Err("blob too short".to_string());
        }

        // Parse ephemeral public key (first 32 bytes)
        let mut epk_bytes = [0u8; 32];
        epk_bytes.copy_from_slice(&blob[..32]);
        let ephemeral_public = PublicKey::from(epk_bytes);

        // Compute shared secret: g^{be}
        let shared_secret = bridge_b_secret.diffie_hellman(&ephemeral_public);

        // Derive AES-256 key via HKDF (same as client)
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut aes_key = [0u8; 32];
        hkdf.expand(HKDF_INFO, &mut aes_key)
            .map_err(|_| "HKDF expand failed".to_string())?;

        // Decrypt
        let cipher = Aes256Gcm::new_from_slice(&aes_key)
            .map_err(|e| format!("AES key init failed: {}", e))?;
        let nonce = Nonce::from_slice(FIXED_NONCE);
        let plaintext = cipher
            .decrypt(nonce, &blob[32..])
            .map_err(|e| format!("AES-GCM decrypt failed: {}", e))?;

        String::from_utf8(plaintext).map_err(|e| format!("UTF-8 decode failed: {}", e))
    }

    #[test]
    fn test_blind_roundtrip() {
        // Bridge B generates a static keypair
        let bridge_b_secret = StaticSecret::random_from_rng(&mut rand::thread_rng());
        let bridge_b_public = PublicKey::from(&bridge_b_secret);

        let relay_addr = "192.168.1.100:9001";

        // Client encrypts
        let blob = blind_target_address(relay_addr, bridge_b_public.as_bytes())
            .expect("encryption should succeed");

        // Bridge B decrypts
        let decrypted =
            decrypt_blinded_address(&blob, &bridge_b_secret).expect("decryption should succeed");

        assert_eq!(decrypted, relay_addr);
    }

    #[test]
    fn test_wrong_key_fails() {
        let bridge_b_secret = StaticSecret::random_from_rng(&mut rand::thread_rng());
        let bridge_b_public = PublicKey::from(&bridge_b_secret);

        let wrong_secret = StaticSecret::random_from_rng(&mut rand::thread_rng());

        let relay_addr = "10.0.0.1:443";
        let blob = blind_target_address(relay_addr, bridge_b_public.as_bytes())
            .expect("encryption should succeed");

        // Wrong key should fail to decrypt
        let result = decrypt_blinded_address(&blob, &wrong_secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_addresses() {
        let bridge_b_secret = StaticSecret::random_from_rng(&mut rand::thread_rng());
        let bridge_b_public = PublicKey::from(&bridge_b_secret);

        for addr in &[
            "1.2.3.4:9001",
            "192.0.2.1:443",
            "[::1]:9050",
            "relay.example.com:9001",
        ] {
            let blob = blind_target_address(addr, bridge_b_public.as_bytes())
                .expect("encryption should succeed");
            let decrypted = decrypt_blinded_address(&blob, &bridge_b_secret)
                .expect("decryption should succeed");
            assert_eq!(&decrypted, addr);
        }
    }

    #[test]
    fn test_each_encryption_is_unique() {
        let bridge_b_secret = StaticSecret::random_from_rng(&mut rand::thread_rng());
        let bridge_b_public = PublicKey::from(&bridge_b_secret);

        let addr = "1.2.3.4:9001";
        let blob1 = blind_target_address(addr, bridge_b_public.as_bytes()).unwrap();
        let blob2 = blind_target_address(addr, bridge_b_public.as_bytes()).unwrap();

        // Each call uses a new ephemeral key, so blobs differ
        assert_ne!(blob1, blob2);

        // But both decrypt to the same address
        let d1 = decrypt_blinded_address(&blob1, &bridge_b_secret).unwrap();
        let d2 = decrypt_blinded_address(&blob2, &bridge_b_secret).unwrap();
        assert_eq!(d1, addr);
        assert_eq!(d2, addr);
    }
}
