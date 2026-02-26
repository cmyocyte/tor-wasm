//! Advanced Relay Verification
//!
//! Implements additional relay verification beyond basic certificate checking:
//! - Relay family constraints (no two relays from same family in circuit)
//! - Bandwidth observation tracking
//! - Path validation
//!
//! ## Security Rationale
//!
//! **Family Constraints**: A single operator running multiple relays could
//! compromise anonymity by controlling multiple hops. The Tor spec requires
//! that circuits not include relays from the same "family" (declared by operators).
//!
//! **Bandwidth Tracking**: Relays that consistently under-perform their claimed
//! bandwidth may be malicious (attracting traffic then degrading it).

use crate::protocol::Relay;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Error types for relay verification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Two relays in the path are from the same family
    SameFamily { relay1: String, relay2: String },

    /// Relay bandwidth is suspiciously low
    LowBandwidth {
        fingerprint: String,
        claimed: u64,
        observed: u64,
    },

    /// Relay is on the deny list
    DenyListed { fingerprint: String, reason: String },
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::SameFamily { relay1, relay2 } => {
                write!(f, "Relays {} and {} are in the same family", relay1, relay2)
            }
            VerifyError::LowBandwidth {
                fingerprint,
                claimed,
                observed,
            } => write!(
                f,
                "Relay {} claimed {}b/s but observed {}b/s",
                fingerprint, claimed, observed
            ),
            VerifyError::DenyListed {
                fingerprint,
                reason,
            } => write!(f, "Relay {} is deny-listed: {}", fingerprint, reason),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Bandwidth observation for a relay
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthObservation {
    /// Observed bytes per second
    pub observed_bps: u64,
    /// Claimed bandwidth from consensus
    pub claimed_bps: u64,
    /// Number of observations
    pub sample_count: u32,
    /// Last observation timestamp
    pub last_observed: u64,
}

impl BandwidthObservation {
    pub fn new(claimed: u64) -> Self {
        Self {
            observed_bps: 0,
            claimed_bps: claimed,
            sample_count: 0,
            last_observed: 0,
        }
    }

    /// Record a bandwidth observation
    pub fn record(&mut self, bytes: u64, duration_ms: u64) {
        if duration_ms == 0 {
            return;
        }

        let bps = (bytes * 1000) / duration_ms;

        // Exponential moving average
        if self.sample_count == 0 {
            self.observed_bps = bps;
        } else {
            // Weight newer observations more heavily
            self.observed_bps = (self.observed_bps * 3 + bps) / 4;
        }

        self.sample_count += 1;
        self.last_observed = current_time_secs();
    }

    /// Check if observed bandwidth is suspiciously low (< 30% of claimed)
    pub fn is_suspicious(&self) -> bool {
        self.sample_count >= 3 && self.observed_bps < (self.claimed_bps * 3 / 10)
    }
}

/// Advanced relay verifier
pub struct RelayVerifier {
    /// Relay families: fingerprint -> set of family member fingerprints
    families: HashMap<String, HashSet<String>>,

    /// Bandwidth observations: fingerprint -> observation
    bandwidth_observations: HashMap<String, BandwidthObservation>,

    /// Deny list: fingerprints that should never be used
    deny_list: HashMap<String, String>, // fingerprint -> reason

    /// Whether family checking is enabled
    family_check_enabled: bool,

    /// Whether bandwidth checking is enabled
    bandwidth_check_enabled: bool,
}

impl Default for RelayVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayVerifier {
    /// Create a new relay verifier
    pub fn new() -> Self {
        Self {
            families: HashMap::new(),
            bandwidth_observations: HashMap::new(),
            deny_list: HashMap::new(),
            family_check_enabled: true,
            bandwidth_check_enabled: false, // Off by default, needs more testing
        }
    }

    /// Enable or disable family checking
    pub fn set_family_check(&mut self, enabled: bool) {
        self.family_check_enabled = enabled;
    }

    /// Enable or disable bandwidth checking
    pub fn set_bandwidth_check(&mut self, enabled: bool) {
        self.bandwidth_check_enabled = enabled;
    }

    /// Load relay families from consensus data
    pub fn load_families(&mut self, relays: &[Relay]) {
        self.families.clear();

        // In a full implementation, we would parse the "family" line from
        // relay descriptors. For now, we'll build families from declared
        // "family" attributes in the relay data if available.

        // The format in descriptors is:
        // family $<fingerprint> $<fingerprint> ...
        //
        // Families are bidirectional - both members must declare each other

        for relay in relays {
            // If the relay has family info (would come from descriptor parsing)
            if let Some(ref family_str) = relay.family {
                let family_fps: HashSet<String> = parse_family_string(family_str);

                // Add the relay to each family member's set
                for family_fp in &family_fps {
                    self.families
                        .entry(relay.fingerprint.clone())
                        .or_default()
                        .insert(family_fp.clone());
                }
            }
        }

        log::info!("🏠 Loaded family data for {} relays", self.families.len());
    }

    /// Add a relay to the deny list
    pub fn deny_relay(&mut self, fingerprint: &str, reason: &str) {
        self.deny_list
            .insert(fingerprint.to_string(), reason.to_string());
        log::warn!(
            "🚫 Relay {} added to deny list: {}",
            &fingerprint[..8.min(fingerprint.len())],
            reason
        );
    }

    /// Remove a relay from the deny list
    pub fn allow_relay(&mut self, fingerprint: &str) {
        self.deny_list.remove(fingerprint);
    }

    /// Check if a relay is deny-listed
    pub fn is_denied(&self, fingerprint: &str) -> Option<&String> {
        self.deny_list.get(fingerprint)
    }

    /// Check if a circuit path is valid (no family conflicts)
    pub fn validate_path(
        &self,
        guard_fp: &str,
        middle_fp: &str,
        exit_fp: &str,
    ) -> std::result::Result<(), VerifyError> {
        // Check deny list
        if let Some(reason) = self.is_denied(guard_fp) {
            return Err(VerifyError::DenyListed {
                fingerprint: guard_fp.to_string(),
                reason: reason.clone(),
            });
        }
        if let Some(reason) = self.is_denied(middle_fp) {
            return Err(VerifyError::DenyListed {
                fingerprint: middle_fp.to_string(),
                reason: reason.clone(),
            });
        }
        if let Some(reason) = self.is_denied(exit_fp) {
            return Err(VerifyError::DenyListed {
                fingerprint: exit_fp.to_string(),
                reason: reason.clone(),
            });
        }

        // Check family constraints
        if self.family_check_enabled {
            // Guard and middle in same family?
            if self.are_family(guard_fp, middle_fp) {
                return Err(VerifyError::SameFamily {
                    relay1: guard_fp[..8.min(guard_fp.len())].to_string(),
                    relay2: middle_fp[..8.min(middle_fp.len())].to_string(),
                });
            }

            // Guard and exit in same family?
            if self.are_family(guard_fp, exit_fp) {
                return Err(VerifyError::SameFamily {
                    relay1: guard_fp[..8.min(guard_fp.len())].to_string(),
                    relay2: exit_fp[..8.min(exit_fp.len())].to_string(),
                });
            }

            // Middle and exit in same family?
            if self.are_family(middle_fp, exit_fp) {
                return Err(VerifyError::SameFamily {
                    relay1: middle_fp[..8.min(middle_fp.len())].to_string(),
                    relay2: exit_fp[..8.min(exit_fp.len())].to_string(),
                });
            }
        }

        Ok(())
    }

    /// Check if two relays are in the same family
    pub fn are_family(&self, fp1: &str, fp2: &str) -> bool {
        // Same relay is trivially in the same "family"
        if fp1 == fp2 {
            return true;
        }

        // Check if fp1's family contains fp2
        if let Some(family) = self.families.get(fp1) {
            if family.contains(fp2) {
                return true;
            }
        }

        // Check if fp2's family contains fp1
        if let Some(family) = self.families.get(fp2) {
            if family.contains(fp1) {
                return true;
            }
        }

        false
    }

    /// Record a bandwidth observation for a relay
    pub fn record_bandwidth(
        &mut self,
        fingerprint: &str,
        bytes: u64,
        duration_ms: u64,
        claimed: u64,
    ) {
        let observation = self
            .bandwidth_observations
            .entry(fingerprint.to_string())
            .or_insert_with(|| BandwidthObservation::new(claimed));

        observation.record(bytes, duration_ms);
    }

    /// Check if a relay has suspicious bandwidth
    pub fn check_bandwidth(&self, fingerprint: &str) -> std::result::Result<(), VerifyError> {
        if !self.bandwidth_check_enabled {
            return Ok(());
        }

        if let Some(obs) = self.bandwidth_observations.get(fingerprint) {
            if obs.is_suspicious() {
                return Err(VerifyError::LowBandwidth {
                    fingerprint: fingerprint[..8.min(fingerprint.len())].to_string(),
                    claimed: obs.claimed_bps,
                    observed: obs.observed_bps,
                });
            }
        }

        Ok(())
    }

    /// Get statistics about relay verification
    pub fn stats(&self) -> RelayVerifierStats {
        let suspicious_count = self
            .bandwidth_observations
            .values()
            .filter(|o| o.is_suspicious())
            .count();

        RelayVerifierStats {
            families_loaded: self.families.len(),
            bandwidth_observations: self.bandwidth_observations.len(),
            suspicious_relays: suspicious_count,
            deny_listed: self.deny_list.len(),
            family_check_enabled: self.family_check_enabled,
            bandwidth_check_enabled: self.bandwidth_check_enabled,
        }
    }
}

/// Statistics about relay verification state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayVerifierStats {
    pub families_loaded: usize,
    pub bandwidth_observations: usize,
    pub suspicious_relays: usize,
    pub deny_listed: usize,
    pub family_check_enabled: bool,
    pub bandwidth_check_enabled: bool,
}

/// Parse a family string from relay descriptor
/// Format: "$<fp1> $<fp2> nickname $<fp3>"
fn parse_family_string(family_str: &str) -> HashSet<String> {
    let mut family = HashSet::new();

    for member in family_str.split_whitespace() {
        if member.starts_with('$') {
            // Fingerprint format: $ABC123...
            let fp = member.trim_start_matches('$');
            if fp.len() >= 20 && fp.chars().all(|c| c.is_ascii_hexdigit()) {
                family.insert(fp.to_uppercase());
            }
        }
        // Skip nicknames (not starting with $) as they're less reliable
    }

    family
}

/// Get current time in seconds
fn current_time_secs() -> u64 {
    use web_time::SystemTime;

    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// Add family field to Relay if not present
// This would be populated from descriptor parsing

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_family_check() {
        let mut verifier = RelayVerifier::new();

        // Manually add family relationship
        verifier.families.insert(
            "GUARD_FP".to_string(),
            vec!["MIDDLE_FP".to_string()].into_iter().collect(),
        );

        // Same family should fail
        let result = verifier.validate_path("GUARD_FP", "MIDDLE_FP", "EXIT_FP");
        assert!(result.is_err());

        // Different families should pass
        let result = verifier.validate_path("GUARD_FP", "OTHER_FP", "EXIT_FP");
        assert!(result.is_ok());
    }

    #[test]
    fn test_deny_list() {
        let mut verifier = RelayVerifier::new();

        verifier.deny_relay("BAD_RELAY_FP", "Known malicious");

        let result = verifier.validate_path("BAD_RELAY_FP", "MIDDLE_FP", "EXIT_FP");
        assert!(result.is_err());

        if let Err(VerifyError::DenyListed {
            fingerprint,
            reason,
        }) = result
        {
            assert_eq!(fingerprint, "BAD_RELAY_FP");
            assert!(reason.contains("malicious"));
        } else {
            panic!("Expected DenyListed error");
        }
    }

    #[test]
    fn test_bandwidth_observation() {
        let mut obs = BandwidthObservation::new(1_000_000); // 1 MB/s claimed

        // Record several observations showing ~200 KB/s
        obs.record(200_000, 1000); // 200 KB in 1 second
        obs.record(200_000, 1000);
        obs.record(200_000, 1000);

        // Should be suspicious (20% of claimed)
        assert!(obs.is_suspicious());
    }

    #[test]
    fn test_parse_family_string() {
        let family_str = "$ABCD1234567890ABCD1234567890ABCDEF123456 $1234567890ABCD1234567890ABCDEF12345678 nickname";
        let family = parse_family_string(family_str);

        assert_eq!(family.len(), 2);
        assert!(family.contains("ABCD1234567890ABCD1234567890ABCDEF123456"));
        assert!(family.contains("1234567890ABCD1234567890ABCDEF12345678"));
    }
}
