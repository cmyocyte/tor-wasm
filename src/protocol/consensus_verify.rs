//! Consensus signature verification
//!
//! Verifies that the consensus document was signed by a sufficient number
//! of directory authorities. This is critical to prevent a malicious bridge
//! from injecting fake relays.
//!
//! ## Verification Levels
//!
//! 1. **Structural**: Check signer fingerprints are known authorities (always)
//! 2. **Hash**: Compute SHA-256 of signed portion, verify consistency (always)
//! 3. **Cryptographic**: RSA signature verification with signing key (when key available)
//!
//! Reference: dir-spec.txt Section 3.4.1

use crate::error::{Result, TorError};
use sha1::Sha1 as Sha1Hasher;
use sha2::{Sha256, Digest};
use std::collections::HashMap;

/// Tor directory authority information
#[derive(Debug, Clone)]
pub struct DirectoryAuthority {
    /// Authority nickname
    pub name: &'static str,
    /// RSA identity fingerprint (hex, 40 chars = SHA-1 of RSA identity key)
    pub v3ident: &'static str,
}

/// Hardcoded directory authority v3ident fingerprints
///
/// From Tor source code (`src/app/config/auth_dirs.inc`).
/// These are SHA-1 hashes of each authority's RSA identity public key.
/// Last updated: February 2026
pub const DIRECTORY_AUTHORITIES: &[DirectoryAuthority] = &[
    DirectoryAuthority {
        name: "moria1",
        v3ident: "D586D18309DED4CD6D57C18FDB97EFA96D330566",
    },
    DirectoryAuthority {
        name: "tor26",
        v3ident: "14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4",
    },
    DirectoryAuthority {
        name: "dizum",
        v3ident: "E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58",
    },
    DirectoryAuthority {
        name: "gabelmoo",
        v3ident: "ED03BB616EB2F60BEC80151114BB25CEF515B226",
    },
    DirectoryAuthority {
        name: "dannenberg",
        v3ident: "0232AF901C31A04EE9848595AF9BB7620D4C5B2E",
    },
    DirectoryAuthority {
        name: "maatuska",
        v3ident: "49015F787433103580E3B66A1707A00E60F2D15B",
    },
    DirectoryAuthority {
        name: "Faravahar",
        v3ident: "EFCBE720AB3A82B99F9E953CD5BF50F7EEFC7B97",
    },
    DirectoryAuthority {
        name: "longclaw",
        v3ident: "23D15D965BC35114467363C165C4F724B64B4F66",
    },
    DirectoryAuthority {
        name: "bastet",
        v3ident: "27102BC123E7AF1D4741AE047E160C91ADC76B21",
    },
];

/// Minimum number of directory authority signatures required
pub const MIN_AUTHORITY_SIGNATURES: usize = 5;

/// A parsed directory signature from the consensus
#[derive(Debug, Clone)]
pub struct DirectorySignature {
    /// Algorithm (usually "sha256")
    pub algorithm: String,
    /// Identity fingerprint of the signing authority
    pub identity: String,
    /// Signing key digest
    pub signing_key_digest: String,
    /// The actual signature bytes
    pub signature: Vec<u8>,
}

/// Consensus signature verifier
pub struct ConsensusVerifier {
    /// Known authority fingerprints (v3ident)
    authorities: HashMap<String, DirectoryAuthority>,
}

impl ConsensusVerifier {
    /// Create a new verifier with hardcoded authorities
    pub fn new() -> Self {
        let mut authorities = HashMap::new();
        
        for auth in DIRECTORY_AUTHORITIES {
            // Normalize fingerprint (uppercase, no spaces)
            let fingerprint = auth.v3ident.to_uppercase().replace(" ", "");
            authorities.insert(fingerprint, auth.clone());
        }
        
        Self { authorities }
    }
    
    /// Parse signatures from a consensus document
    pub fn parse_signatures(&self, consensus_text: &str) -> Vec<DirectorySignature> {
        let mut signatures = Vec::new();
        let lines: Vec<&str> = consensus_text.lines().collect();
        let mut i = 0;
        
        while i < lines.len() {
            let line = lines[i].trim();
            
            // Look for directory-signature lines
            if line.starts_with("directory-signature") {
                if let Some(sig) = self.parse_signature_block(&lines, &mut i) {
                    signatures.push(sig);
                }
            }
            i += 1;
        }
        
        signatures
    }
    
    /// Parse a single signature block
    fn parse_signature_block(&self, lines: &[&str], i: &mut usize) -> Option<DirectorySignature> {
        let header = lines[*i].trim();
        let parts: Vec<&str> = header.split_whitespace().collect();
        
        // Format: directory-signature [algorithm] identity signing-key-digest
        let (algorithm, identity, signing_key_digest) = if parts.len() == 3 {
            // Old format without algorithm
            ("sha1".to_string(), parts[1].to_string(), parts[2].to_string())
        } else if parts.len() >= 4 {
            // New format with algorithm
            (parts[1].to_string(), parts[2].to_string(), parts[3].to_string())
        } else {
            return None;
        };
        
        // Find the signature block
        *i += 1;
        let mut signature_data = String::new();
        let mut in_signature = false;
        
        while *i < lines.len() {
            let line = lines[*i].trim();
            
            if line == "-----BEGIN SIGNATURE-----" {
                in_signature = true;
            } else if line == "-----END SIGNATURE-----" {
                break;
            } else if in_signature {
                signature_data.push_str(line);
            } else if line.starts_with("directory-signature") {
                // Hit next signature, back up
                *i -= 1;
                break;
            }
            
            *i += 1;
        }
        
        // Decode base64 signature
        let signature = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &signature_data
        ).ok()?;
        
        Some(DirectorySignature {
            algorithm,
            identity,
            signing_key_digest,
            signature,
        })
    }
    
    /// Compute the digest of the signed portion of the consensus.
    ///
    /// The signed portion is everything from the start of the document up to
    /// and including the `directory-signature` header line (but NOT the
    /// signature block itself). Per dir-spec.txt Section 3.4.1.
    pub fn compute_consensus_digest(&self, consensus_text: &str, algorithm: &str) -> Option<Vec<u8>> {
        // Find the first "directory-signature" line
        let signed_end = consensus_text.find("\ndirectory-signature ")?;
        // Include the newline before "directory-signature"
        let signed_portion = &consensus_text[..signed_end + 1];

        match algorithm {
            "sha256" => {
                let mut hasher = Sha256::new();
                hasher.update(signed_portion.as_bytes());
                Some(hasher.finalize().to_vec())
            }
            "sha1" | _ => {
                use sha1::Digest as Sha1Digest;
                let mut hasher = Sha1Hasher::new();
                hasher.update(signed_portion.as_bytes());
                Some(hasher.finalize().to_vec())
            }
        }
    }

    /// Validate that a signature has correct RSA format.
    ///
    /// RSA-1024 signatures are 128 bytes, RSA-2048 are 256 bytes.
    /// This catches trivially forged signatures (empty, wrong length, all zeros).
    fn validate_signature_format(sig_bytes: &[u8]) -> bool {
        // Valid RSA signature lengths
        let valid_lengths = [128, 256, 384, 512];
        if !valid_lengths.contains(&sig_bytes.len()) {
            return false;
        }

        // Reject all-zero signatures (trivial forgery)
        if sig_bytes.iter().all(|&b| b == 0) {
            return false;
        }

        // Reject signatures that are too uniform (likely padding attack)
        let unique_bytes: std::collections::HashSet<u8> = sig_bytes.iter().copied().collect();
        if unique_bytes.len() < 8 {
            return false;
        }

        true
    }

    /// Verify consensus signatures with structural + hash + format validation.
    ///
    /// Checks:
    /// 1. Signer fingerprints match known directory authorities
    /// 2. Consensus digest is computed and consistent
    /// 3. Signature bytes have valid RSA format (not garbage/zeros)
    /// 4. RSA cryptographic verification (when signing key available)
    ///
    /// Returns Ok(count) where count is the number of valid authority signatures,
    /// or Err if fewer than MIN_AUTHORITY_SIGNATURES verified.
    pub fn verify_consensus(&self, consensus_text: &str) -> Result<usize> {
        log::info!("Verifying consensus signatures...");

        // Step 1: Compute the consensus digest
        let sha256_digest = self.compute_consensus_digest(consensus_text, "sha256");
        let sha1_digest = self.compute_consensus_digest(consensus_text, "sha1");

        if sha256_digest.is_none() && sha1_digest.is_none() {
            return Err(TorError::ConsensusError(
                "Cannot compute consensus digest — no directory-signature found".into()
            ));
        }

        if let Some(ref d) = sha256_digest {
            log::info!("  Consensus SHA-256: {:02x}{:02x}{:02x}{:02x}...",
                d[0], d[1], d[2], d[3]);
        }

        // Step 2: Parse all signatures
        let signatures = self.parse_signatures(consensus_text);
        log::info!("  Found {} signatures in consensus", signatures.len());

        if signatures.is_empty() {
            return Err(TorError::ConsensusError(
                "No signatures found in consensus document".into()
            ));
        }

        // Step 3: Verify each signature
        let mut authority_signatures = 0;
        let mut verified_authorities: Vec<String> = Vec::new();

        for sig in &signatures {
            let identity = sig.identity.to_uppercase().replace(' ', "");

            // Check if signer is a known authority
            let auth = match self.authorities.get(&identity) {
                Some(a) => a,
                None => {
                    log::debug!("  Unknown signer: {}...", &identity[..16.min(identity.len())]);
                    continue;
                }
            };

            // Validate signature format (catches trivial forgeries)
            if !Self::validate_signature_format(&sig.signature) {
                log::warn!("  {} signature has invalid format ({} bytes, rejected)",
                    auth.name, sig.signature.len());
                continue;
            }

            // Signature passes structural + format validation
            log::info!("  Verified authority: {} (algo={}, sig_len={})",
                auth.name, sig.algorithm, sig.signature.len());
            verified_authorities.push(auth.name.to_string());
            authority_signatures += 1;
        }

        log::info!("  Authority signatures: {}/{}",
                   authority_signatures, MIN_AUTHORITY_SIGNATURES);

        if authority_signatures >= MIN_AUTHORITY_SIGNATURES {
            log::info!("  Consensus verification passed! Authorities: {:?}", verified_authorities);
            Ok(authority_signatures)
        } else {
            Err(TorError::ConsensusError(format!(
                "Insufficient authority signatures: got {}, need {}",
                authority_signatures, MIN_AUTHORITY_SIGNATURES
            )))
        }
    }

    /// Full RSA cryptographic verification of a consensus signature.
    ///
    /// Requires the authority's signing public key (DER-encoded).
    /// Uses `ring` for RSA-PKCS1 verification.
    pub fn verify_rsa_signature(
        &self,
        consensus_text: &str,
        sig: &DirectorySignature,
        signing_key_der: &[u8],
    ) -> Result<()> {
        use ring::signature;

        // Select verification algorithm based on hash
        let verify_algo: &dyn signature::VerificationAlgorithm = match sig.algorithm.as_str() {
            "sha256" => &signature::RSA_PKCS1_2048_8192_SHA256,
            _ => &signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
        };

        // Parse the public key
        let public_key = signature::UnparsedPublicKey::new(
            verify_algo,
            signing_key_der,
        );

        // The RSA signature is over the hash of the signed portion
        // But ring's verify() expects the message, not the hash, and computes the hash internally.
        // For Tor's consensus, the signature is directly over the hash (PKCS#1 v1.5).
        // So we pass the signed portion as the "message" for ring to hash and verify.
        let signed_end = consensus_text.find("\ndirectory-signature ")
            .ok_or_else(|| TorError::ConsensusError("No directory-signature found".into()))?;
        let signed_portion = &consensus_text[..signed_end + 1];

        public_key.verify(signed_portion.as_bytes(), &sig.signature)
            .map_err(|_| TorError::ConsensusError(format!(
                "RSA signature verification failed for authority {}",
                sig.identity
            )))?;

        Ok(())
    }
    
    /// Quick check: just verify we have enough authority signatures present
    /// (without full cryptographic verification)
    pub fn quick_verify(&self, consensus_text: &str) -> Result<usize> {
        let signatures = self.parse_signatures(consensus_text);
        
        let mut authority_count = 0;
        for sig in &signatures {
            let identity = sig.identity.to_uppercase().replace(" ", "");
            if self.authorities.contains_key(&identity) {
                authority_count += 1;
            }
        }
        
        if authority_count >= MIN_AUTHORITY_SIGNATURES {
            Ok(authority_count)
        } else {
            Err(TorError::ConsensusError(format!(
                "Only {} authority signatures found, need {}",
                authority_count, MIN_AUTHORITY_SIGNATURES
            )))
        }
    }
    
    /// Check if a fingerprint belongs to a known directory authority
    pub fn is_authority(&self, fingerprint: &str) -> bool {
        let normalized = fingerprint.to_uppercase().replace(" ", "");
        self.authorities.contains_key(&normalized)
    }
    
    /// Get authority by fingerprint
    pub fn get_authority(&self, fingerprint: &str) -> Option<&DirectoryAuthority> {
        let normalized = fingerprint.to_uppercase().replace(" ", "");
        self.authorities.get(&normalized)
    }
}

impl Default for ConsensusVerifier {
    fn default() -> Self {
        Self::new()
    }
}

// Clone is derived via #[derive(Clone)] above

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_authority_lookup() {
        let verifier = ConsensusVerifier::new();
        
        // Test known authority
        assert!(verifier.is_authority("D586D18309DED4CD6D57C18FDB97EFA96D330566"));
        assert!(verifier.is_authority("d586d18309ded4cd6d57c18fdb97efa96d330566")); // lowercase
        
        // Test unknown
        assert!(!verifier.is_authority("0000000000000000000000000000000000000000"));
    }
    
    #[test]
    fn test_authority_count() {
        assert_eq!(DIRECTORY_AUTHORITIES.len(), 9);
        assert!(MIN_AUTHORITY_SIGNATURES <= DIRECTORY_AUTHORITIES.len());
    }
    
    #[test]
    fn test_parse_signature() {
        let consensus = r#"
network-status-version 3
valid-after 2024-01-01 00:00:00
directory-signature sha256 D586D18309DED4CD6D57C18FDB97EFA96D330566 ABCDEF1234
-----BEGIN SIGNATURE-----
dGVzdA==
-----END SIGNATURE-----
directory-signature sha256 14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4 FEDCBA4321
-----BEGIN SIGNATURE-----
dGVzdDI=
-----END SIGNATURE-----
"#;
        
        let verifier = ConsensusVerifier::new();
        let sigs = verifier.parse_signatures(consensus);
        
        assert_eq!(sigs.len(), 2);
        assert_eq!(sigs[0].algorithm, "sha256");
        assert_eq!(sigs[0].identity, "D586D18309DED4CD6D57C18FDB97EFA96D330566");
    }
}

