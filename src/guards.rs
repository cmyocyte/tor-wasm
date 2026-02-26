//! Guard Node Persistence
//!
//! Implements guard node selection and persistence per Tor specification.
//!
//! ## Security Rationale
//!
//! Guard persistence is crucial for security:
//! - Using the same guards for 2-3 months limits adversary's observation window
//! - Frequent guard rotation increases chance of hitting malicious guards
//! - Persistent guards mean an adversary can't slowly take over entry points
//!
//! ## Tor Specification
//!
//! Per path-spec.txt section 5:
//! - Guards are selected based on bandwidth, stability, and Guard flag
//! - Guard selection persists for 2-3 months
//! - If all guards fail, new guards are selected
//! - Guard state should be stored persistently (we use IndexedDB)

use crate::error::{Result, TorError};
use crate::protocol::Relay;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// How long guards should be kept before rotation (in seconds)
/// Tor spec says 2-3 months, we use 60 days (conservative)
pub const GUARD_LIFETIME_SECS: u64 = 60 * 24 * 60 * 60; // 60 days

/// Minimum number of guards to keep
pub const MIN_GUARDS: usize = 3;

/// Maximum number of guards to keep
pub const MAX_GUARDS: usize = 5;

/// Number of failed attempts before marking a guard as bad
pub const MAX_FAILURES_BEFORE_BAD: u32 = 5;

/// How long a guard stays in the "bad" list (in seconds)
pub const BAD_GUARD_TIMEOUT_SECS: u64 = 60 * 60; // 1 hour

/// Information about a failed guard attempt
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FailureInfo {
    /// Number of consecutive failures
    pub consecutive_failures: u32,

    /// Timestamp of last failure
    pub last_failure_time: u64,

    /// Last error message
    pub last_error: String,
}

/// Persistent guard state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardState {
    /// Selected guard fingerprints (in order of preference)
    pub guards: Vec<String>,

    /// When guards were selected (Unix timestamp)
    pub selected_at: u64,

    /// When to rotate guards (Unix timestamp)
    pub rotate_after: u64,

    /// Guards that have failed recently (fingerprint -> failure info)
    pub failed_guards: HashMap<String, FailureInfo>,

    /// Guards that are currently "bad" and should not be used
    pub bad_guards: HashMap<String, u64>, // fingerprint -> bad_until timestamp

    /// Version of the guard state format (for future migrations)
    pub version: u32,
}

impl Default for GuardState {
    fn default() -> Self {
        Self {
            guards: Vec::new(),
            selected_at: 0,
            rotate_after: 0,
            failed_guards: HashMap::new(),
            bad_guards: HashMap::new(),
            version: 1,
        }
    }
}

impl GuardState {
    /// Create a new empty guard state
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if the guard state is empty or expired
    pub fn needs_refresh(&self) -> bool {
        if self.guards.is_empty() {
            return true;
        }

        let now = current_time_secs();

        // Check if rotation time has passed
        if now > self.rotate_after {
            log::info!("🔄 Guard rotation time reached");
            return true;
        }

        // Check if we have too few guards (some may have become bad)
        let usable_guards = self.usable_guard_count();
        if usable_guards < MIN_GUARDS {
            log::info!(
                "🔄 Too few usable guards ({}/{})",
                usable_guards,
                MIN_GUARDS
            );
            return true;
        }

        false
    }

    /// Get the number of usable (not bad) guards
    pub fn usable_guard_count(&self) -> usize {
        let now = current_time_secs();

        self.guards
            .iter()
            .filter(|fp| {
                // Check if this guard is in the bad list and still timed out
                if let Some(&bad_until) = self.bad_guards.get(*fp) {
                    now >= bad_until // If timeout passed, it's usable again
                } else {
                    true // Not in bad list, it's usable
                }
            })
            .count()
    }

    /// Select new guards from the consensus
    pub fn select_guards(&mut self, relays: &[Relay]) -> Result<()> {
        log::info!("🛡️ Selecting new guard nodes...");

        // Filter for guard-eligible relays
        let mut guard_candidates: Vec<_> = relays
            .iter()
            .filter(|r| {
                r.is_guard()
                    && r.is_running()
                    && r.is_stable()
                    && !self.is_bad_guard(&r.fingerprint)
            })
            .collect();

        if guard_candidates.len() < MIN_GUARDS {
            return Err(TorError::InvalidRelay(format!(
                "Not enough guard candidates: {} (need {})",
                guard_candidates.len(),
                MIN_GUARDS
            )));
        }

        // Sort by bandwidth (higher is better)
        guard_candidates.sort_by(|a, b| b.bandwidth.cmp(&a.bandwidth));

        // Take top candidates weighted by bandwidth
        // We want some randomness but prefer high-bandwidth guards
        let mut selected = Vec::new();
        let mut rng_state = current_time_secs();

        // Select guards with bandwidth-weighted probability
        while selected.len() < MAX_GUARDS && !guard_candidates.is_empty() {
            // Simple weighted selection: pick from top 20% with some randomness
            let top_count = (guard_candidates.len() / 5).max(1);
            let idx = simple_random(&mut rng_state) as usize % top_count;

            let guard = guard_candidates.remove(idx);
            selected.push(guard.fingerprint.clone());

            log::info!(
                "  ✅ Selected guard: {} ({}kb/s)",
                &guard.fingerprint[..8],
                guard.bandwidth / 1000
            );
        }

        // Update state
        let now = current_time_secs();
        self.guards = selected;
        self.selected_at = now;
        self.rotate_after = now + GUARD_LIFETIME_SECS;

        // Clear failure info for newly selected guards
        self.failed_guards.clear();

        log::info!(
            "🛡️ Selected {} guards, valid until {}",
            self.guards.len(),
            format_timestamp(self.rotate_after)
        );

        Ok(())
    }

    /// Get the next usable guard fingerprint
    pub fn next_guard(&self) -> Option<&String> {
        let now = current_time_secs();

        self.guards.iter().find(|fp| {
            // Skip if in bad list and not timed out
            if let Some(&bad_until) = self.bad_guards.get(*fp) {
                if now < bad_until {
                    return false;
                }
            }
            true
        })
    }

    /// Get all usable guard fingerprints in order
    pub fn usable_guards(&self) -> Vec<&String> {
        let now = current_time_secs();

        self.guards
            .iter()
            .filter(|fp| {
                if let Some(&bad_until) = self.bad_guards.get(*fp) {
                    now >= bad_until
                } else {
                    true
                }
            })
            .collect()
    }

    /// Record a guard failure
    pub fn record_failure(&mut self, fingerprint: &str, error: &str) {
        let now = current_time_secs();

        let failure = self
            .failed_guards
            .entry(fingerprint.to_string())
            .or_default();

        failure.consecutive_failures += 1;
        failure.last_failure_time = now;
        failure.last_error = error.to_string();

        log::warn!(
            "⚠️ Guard {} failed ({} times): {}",
            &fingerprint[..8.min(fingerprint.len())],
            failure.consecutive_failures,
            error
        );

        // Mark as bad if too many failures
        if failure.consecutive_failures >= MAX_FAILURES_BEFORE_BAD {
            self.mark_bad(fingerprint);
        }
    }

    /// Record a guard success (clears failure count)
    pub fn record_success(&mut self, fingerprint: &str) {
        self.failed_guards.remove(fingerprint);
        self.bad_guards.remove(fingerprint);
    }

    /// Mark a guard as bad (temporarily unusable)
    fn mark_bad(&mut self, fingerprint: &str) {
        let bad_until = current_time_secs() + BAD_GUARD_TIMEOUT_SECS;
        self.bad_guards.insert(fingerprint.to_string(), bad_until);

        log::warn!(
            "🚫 Guard {} marked as bad until {}",
            &fingerprint[..8.min(fingerprint.len())],
            format_timestamp(bad_until)
        );
    }

    /// Check if a guard is currently bad
    fn is_bad_guard(&self, fingerprint: &str) -> bool {
        if let Some(&bad_until) = self.bad_guards.get(fingerprint) {
            current_time_secs() < bad_until
        } else {
            false
        }
    }

    /// Serialize state to JSON for storage
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self)
            .map_err(|e| TorError::Storage(format!("Failed to serialize guard state: {}", e)))
    }

    /// Deserialize state from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| TorError::Storage(format!("Failed to deserialize guard state: {}", e)))
    }

    /// Clean up expired entries
    pub fn cleanup(&mut self) {
        let now = current_time_secs();

        // Remove expired bad guards
        self.bad_guards.retain(|_, &mut bad_until| now < bad_until);

        // Remove old failure info (older than 1 day)
        let one_day_ago = now.saturating_sub(24 * 60 * 60);
        self.failed_guards
            .retain(|_, info| info.last_failure_time > one_day_ago);
    }
}

/// Get current time in seconds since Unix epoch
fn current_time_secs() -> u64 {
    use web_time::SystemTime;

    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Simple pseudo-random number generator
fn simple_random(state: &mut u64) -> u64 {
    // xorshift64
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

/// Format a Unix timestamp for logging
fn format_timestamp(ts: u64) -> String {
    // Simple formatting - just show days from now
    let now = current_time_secs();
    if ts > now {
        let days = (ts - now) / (24 * 60 * 60);
        format!("in {} days", days)
    } else {
        "expired".to_string()
    }
}

/// Guard persistence manager
///
/// Handles loading and saving guard state to IndexedDB
pub struct GuardPersistence {
    /// Storage key for guard state
    storage_key: String,
}

impl GuardPersistence {
    /// Create a new guard persistence manager
    pub fn new() -> Self {
        Self {
            storage_key: "tor_guard_state".to_string(),
        }
    }

    /// Load guard state from storage
    pub async fn load(&self) -> Result<GuardState> {
        use web_sys::window;

        let window = window().ok_or_else(|| TorError::Storage("No window".into()))?;
        let storage = window
            .local_storage()
            .map_err(|_| TorError::Storage("localStorage not available".into()))?
            .ok_or_else(|| TorError::Storage("localStorage is null".into()))?;

        match storage.get_item(&self.storage_key) {
            Ok(Some(json)) => {
                log::info!("📂 Loaded guard state from storage");
                GuardState::from_json(&json)
            }
            Ok(None) => {
                log::info!("📂 No saved guard state, starting fresh");
                Ok(GuardState::new())
            }
            Err(e) => {
                log::warn!("⚠️ Failed to load guard state: {:?}", e);
                Ok(GuardState::new())
            }
        }
    }

    /// Save guard state to storage
    pub async fn save(&self, state: &GuardState) -> Result<()> {
        use web_sys::window;

        let window = window().ok_or_else(|| TorError::Storage("No window".into()))?;
        let storage = window
            .local_storage()
            .map_err(|_| TorError::Storage("localStorage not available".into()))?
            .ok_or_else(|| TorError::Storage("localStorage is null".into()))?;

        let json = state.to_json()?;

        storage
            .set_item(&self.storage_key, &json)
            .map_err(|_| TorError::Storage("Failed to save guard state".into()))?;

        log::info!("💾 Saved guard state ({} guards)", state.guards.len());

        Ok(())
    }

    /// Clear saved guard state
    pub async fn clear(&self) -> Result<()> {
        use web_sys::window;

        let window = window().ok_or_else(|| TorError::Storage("No window".into()))?;
        let storage = window
            .local_storage()
            .map_err(|_| TorError::Storage("localStorage not available".into()))?
            .ok_or_else(|| TorError::Storage("localStorage is null".into()))?;

        storage
            .remove_item(&self.storage_key)
            .map_err(|_| TorError::Storage("Failed to clear guard state".into()))?;

        log::info!("🗑️ Cleared saved guard state");

        Ok(())
    }
}

impl Default for GuardPersistence {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guard_state_default() {
        let state = GuardState::new();
        assert!(state.guards.is_empty());
        assert!(state.needs_refresh());
    }

    #[test]
    fn test_failure_tracking() {
        let mut state = GuardState::new();
        state.guards.push("TEST_GUARD_FP".to_string());

        // Record failures
        for i in 0..MAX_FAILURES_BEFORE_BAD {
            state.record_failure("TEST_GUARD_FP", &format!("Error {}", i));

            if i < MAX_FAILURES_BEFORE_BAD - 1 {
                // Not bad yet
                assert!(!state.is_bad_guard("TEST_GUARD_FP"));
            }
        }

        // Should be bad now
        assert!(state.is_bad_guard("TEST_GUARD_FP"));
    }

    #[test]
    fn test_success_clears_failures() {
        let mut state = GuardState::new();

        // Record some failures
        state.record_failure("TEST_GUARD_FP", "Error 1");
        state.record_failure("TEST_GUARD_FP", "Error 2");

        assert!(state.failed_guards.contains_key("TEST_GUARD_FP"));

        // Record success
        state.record_success("TEST_GUARD_FP");

        assert!(!state.failed_guards.contains_key("TEST_GUARD_FP"));
    }

    #[test]
    fn test_serialization() {
        let mut state = GuardState::new();
        state.guards.push("FP1".to_string());
        state.guards.push("FP2".to_string());
        state.selected_at = 1234567890;
        state.rotate_after = 1234567890 + GUARD_LIFETIME_SECS;

        let json = state.to_json().unwrap();
        let restored = GuardState::from_json(&json).unwrap();

        assert_eq!(restored.guards, state.guards);
        assert_eq!(restored.selected_at, state.selected_at);
        assert_eq!(restored.rotate_after, state.rotate_after);
    }
}
