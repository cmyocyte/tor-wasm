//! Tor relay types and selection logic
//!
//! Defines relay metadata and provides algorithms for selecting
//! guard, middle, and exit nodes based on consensus data.

use serde::{Serialize, Deserialize};
use std::net::{SocketAddr, IpAddr};

/// A Tor relay from the consensus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relay {
    /// Relay nickname
    pub nickname: String,
    
    /// Fingerprint (hex-encoded identity key hash)
    pub fingerprint: String,
    
    /// IPv4/IPv6 address
    pub address: IpAddr,
    
    /// OR (Onion Router) port
    pub or_port: u16,
    
    /// Directory port (optional)
    pub dir_port: Option<u16>,
    
    /// Relay flags
    pub flags: RelayFlags,
    
    /// Bandwidth (bytes/sec)
    pub bandwidth: u64,
    
    /// When this relay was first seen
    pub published: u64,
    
    /// ntor onion key (for handshake)
    pub ntor_onion_key: Option<String>,
    
    /// Family declaration (from descriptor)
    /// Format: "$<fingerprint> $<fingerprint> ..."
    #[serde(default)]
    pub family: Option<String>,
}

impl Relay {
    /// Get the SocketAddr for connecting to this relay
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.address, self.or_port)
    }
    
    /// Check if this relay can be used as a guard
    pub fn is_guard(&self) -> bool {
        self.flags.guard && self.flags.stable && self.flags.fast
    }
    
    /// Check if this relay can be used as an exit
    pub fn is_exit(&self) -> bool {
        self.flags.exit && !self.flags.bad_exit
    }
    
    /// Check if this relay is suitable as a middle relay
    pub fn is_middle(&self) -> bool {
        self.flags.fast && self.flags.stable && self.flags.running
    }
    
    /// Check if this relay is currently running
    pub fn is_running(&self) -> bool {
        self.flags.running
    }
    
    /// Check if this relay is stable
    pub fn is_stable(&self) -> bool {
        self.flags.stable
    }
}

/// Relay flags from consensus
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RelayFlags {
    /// Authority - directory authority
    pub authority: bool,
    
    /// BadExit - should not be used as exit
    pub bad_exit: bool,
    
    /// Exit - allows exit traffic
    pub exit: bool,
    
    /// Fast - fast relay
    pub fast: bool,
    
    /// Guard - suitable as entry guard
    pub guard: bool,
    
    /// HSDir - hidden service directory
    pub hs_dir: bool,
    
    /// Running - currently running
    pub running: bool,
    
    /// Stable - stable relay
    pub stable: bool,
    
    /// V2Dir - version 2 directory protocol
    pub v2_dir: bool,
    
    /// Valid - valid relay descriptor
    pub valid: bool,
}

impl RelayFlags {
    /// Parse flags from consensus string
    pub fn from_string(flags: &str) -> Self {
        let mut relay_flags = RelayFlags::default();
        
        for flag in flags.split_whitespace() {
            match flag {
                "Authority" => relay_flags.authority = true,
                "BadExit" => relay_flags.bad_exit = true,
                "Exit" => relay_flags.exit = true,
                "Fast" => relay_flags.fast = true,
                "Guard" => relay_flags.guard = true,
                "HSDir" => relay_flags.hs_dir = true,
                "Running" => relay_flags.running = true,
                "Stable" => relay_flags.stable = true,
                "V2Dir" => relay_flags.v2_dir = true,
                "Valid" => relay_flags.valid = true,
                _ => {} // Ignore unknown flags
            }
        }
        
        relay_flags
    }
}

/// Relay selection algorithm
#[derive(Clone)]
pub struct RelaySelector {
    /// All relays from consensus
    relays: Vec<Relay>,
    
    /// Preferred guard fingerprints (from GuardState persistence)
    /// If set, these guards will be tried first
    preferred_guards: Vec<String>,
}

impl RelaySelector {
    /// Create a new relay selector
    pub fn new(relays: Vec<Relay>) -> Self {
        Self { 
            relays,
            preferred_guards: Vec::new(),
        }
    }
    
    /// Set preferred guards (loaded from persistent storage)
    pub fn set_preferred_guards(&mut self, guards: Vec<String>) {
        log::info!("🛡️ Setting {} preferred guards", guards.len());
        self.preferred_guards = guards;
    }
    
    /// Get the preferred guards
    pub fn preferred_guards(&self) -> &[String] {
        &self.preferred_guards
    }
    
    /// Check if relay uses a standard Tor port
    fn is_standard_port(port: u16) -> bool {
        matches!(port, 443 | 8080 | 8443 | 9001 | 9030 | 9050 | 9051 | 9150)
    }
    
    /// Select a guard relay
    pub fn select_guard(&self) -> Option<&Relay> {
        self.select_guards(1).into_iter().next()
    }
    
    /// Select multiple guard relay candidates (for retry logic)
    /// Prioritizes preferred guards (from persistent storage) first,
    /// then falls back to bandwidth-weighted random selection
    pub fn select_guards(&self, count: usize) -> Vec<&Relay> {
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        
        let mut selected: Vec<&Relay> = Vec::new();
        let mut selected_fps: std::collections::HashSet<&str> = std::collections::HashSet::new();
        
        // First, add preferred guards (in order)
        if !self.preferred_guards.is_empty() {
            log::info!("🛡️ Prioritizing {} preferred guards", self.preferred_guards.len());
            
            for preferred_fp in &self.preferred_guards {
                if selected.len() >= count {
                    break;
                }
                
                // Find this relay in the consensus
                if let Some(relay) = self.relays.iter().find(|r| 
                    &r.fingerprint == preferred_fp && 
                    r.is_guard() && 
                    r.ntor_onion_key.is_some() &&
                    Self::is_standard_port(r.or_port)
                ) {
                    log::info!("  ✅ Using preferred guard: {} ({})", 
                        &relay.nickname, &preferred_fp[..8]);
                    selected.push(relay);
                    selected_fps.insert(&relay.fingerprint);
                } else {
                    log::warn!("  ⚠️ Preferred guard {} not found in consensus", 
                        &preferred_fp[..8.min(preferred_fp.len())]);
                }
            }
        }
        
        // If we need more guards, select from remaining candidates
        if selected.len() < count {
            let mut guards: Vec<&Relay> = self.relays
                .iter()
                .filter(|r| {
                    r.is_guard() 
                    && r.ntor_onion_key.is_some()
                    && Self::is_standard_port(r.or_port)
                    && !selected_fps.contains(r.fingerprint.as_str())
                    // Temporarily exclude problematic relays for testing
                    && r.nickname != "RicsiTORRelay"
                })
                .collect();
            
            // Shuffle the guards to try different ones each time
            guards.shuffle(&mut rng);
            
            // Take a mix: some high-bandwidth, some random
            let mut by_bandwidth = guards.clone();
            by_bandwidth.sort_by(|a, b| b.bandwidth.cmp(&a.bandwidth));
            
            let remaining = count - selected.len();
            let half = remaining / 2;
            
            // Add high-bandwidth guards
            for guard in by_bandwidth.into_iter().take(half.max(1)) {
                if selected.len() >= count {
                    break;
                }
                if !selected_fps.contains(guard.fingerprint.as_str()) {
                    selected.push(guard);
                    selected_fps.insert(&guard.fingerprint);
                }
            }
            
            // Add random guards
            for guard in guards.iter() {
                if selected.len() >= count {
                    break;
                }
                if !selected_fps.contains(guard.fingerprint.as_str()) {
                    selected.push(guard);
                    selected_fps.insert(&guard.fingerprint);
                }
            }
        }
        
        // Shuffle non-preferred guards (keep preferred at front)
        let preferred_count = self.preferred_guards.len().min(selected.len());
        if selected.len() > preferred_count {
            let (preferred, rest) = selected.split_at_mut(preferred_count);
            rest.shuffle(&mut rng);
        }
        
        log::info!("🎲 Selected {} guards ({} preferred, {} fallback)", 
            selected.len(), 
            preferred_count,
            selected.len().saturating_sub(preferred_count));
        
        selected
    }
    
    /// Select a middle relay
    pub fn select_middle(&self, exclude: &[&str]) -> Option<&Relay> {
        self.select_middles(1, exclude).into_iter().next()
    }
    
    /// Select multiple middle relay candidates
    pub fn select_middles(&self, count: usize, exclude: &[&str]) -> Vec<&Relay> {
        use rand::seq::SliceRandom;
        
        let mut middles: Vec<&Relay> = self.relays
            .iter()
            .filter(|r| {
                r.is_middle() 
                && r.ntor_onion_key.is_some()
                && Self::is_standard_port(r.or_port)
                && !exclude.contains(&r.fingerprint.as_str())
                // Temporarily exclude problematic relays for testing
                && r.nickname != "RicsiTORRelay"
                && r.nickname != "franklinrelay"
                && r.nickname != "SharingIsCaring" // Suspected stale ntor key
            })
            .collect();
        
        // Shuffle first, then take a mix of high-bandwidth and random
        let mut rng = rand::thread_rng();
        middles.shuffle(&mut rng);
        
        // Sort by bandwidth but only use top 50% + random 50%
        let mut by_bandwidth = middles.clone();
        by_bandwidth.sort_by(|a, b| b.bandwidth.cmp(&a.bandwidth));
        
        let half = count / 2;
        let mut selected: Vec<&Relay> = by_bandwidth.into_iter().take(half.max(1)).collect();
        
        // Add random middles
        let selected_fps: std::collections::HashSet<&str> = 
            selected.iter().map(|r| r.fingerprint.as_str()).collect();
        for middle in middles.iter() {
            if selected.len() >= count {
                break;
            }
            if !selected_fps.contains(middle.fingerprint.as_str()) {
                selected.push(middle);
            }
        }
        
        // Final shuffle
        selected.shuffle(&mut rng);
        selected
    }
    
    /// Select an exit relay
    pub fn select_exit(&self, exclude: &[&str]) -> Option<&Relay> {
        self.select_exits(1, exclude).into_iter().next()
    }
    
    /// Select multiple exit relay candidates
    pub fn select_exits(&self, count: usize, exclude: &[&str]) -> Vec<&Relay> {
        use rand::seq::SliceRandom;
        
        let mut exits: Vec<&Relay> = self.relays
            .iter()
            .filter(|r| {
                r.is_exit() 
                && r.ntor_onion_key.is_some()
                && Self::is_standard_port(r.or_port)
                && !exclude.contains(&r.fingerprint.as_str())
            })
            .collect();
        
        // Shuffle first, then take a mix of high-bandwidth and random
        let mut rng = rand::thread_rng();
        exits.shuffle(&mut rng);
        
        // Sort by bandwidth but only use top 50% + random 50%
        let mut by_bandwidth = exits.clone();
        by_bandwidth.sort_by(|a, b| b.bandwidth.cmp(&a.bandwidth));
        
        let half = count / 2;
        let mut selected: Vec<&Relay> = by_bandwidth.into_iter().take(half.max(1)).collect();
        
        // Add random exits
        let selected_fps: std::collections::HashSet<&str> = 
            selected.iter().map(|r| r.fingerprint.as_str()).collect();
        for exit in exits.iter() {
            if selected.len() >= count {
                break;
            }
            if !selected_fps.contains(exit.fingerprint.as_str()) {
                selected.push(exit);
            }
        }
        
        // Final shuffle
        selected.shuffle(&mut rng);
        selected
    }
    
    /// Get all guard relays
    pub fn guards(&self) -> Vec<&Relay> {
        self.relays
            .iter()
            .filter(|r| r.is_guard())
            .collect()
    }
    
    /// Get all exit relays
    pub fn exits(&self) -> Vec<&Relay> {
        self.relays
            .iter()
            .filter(|r| r.is_exit())
            .collect()
    }
    
    /// Get total number of relays
    pub fn count(&self) -> usize {
        self.relays.len()
    }
    
    /// Get total number of running relays
    pub fn running_count(&self) -> usize {
        self.relays.iter().filter(|r| r.is_running()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_relay_flags_parsing() {
        let flags = RelayFlags::from_string("Fast Guard Running Stable Valid");
        assert!(flags.fast);
        assert!(flags.guard);
        assert!(flags.running);
        assert!(flags.stable);
        assert!(flags.valid);
        assert!(!flags.exit);
    }
    
    #[test]
    fn test_relay_is_guard() {
        let relay = Relay {
            nickname: "TestGuard".to_string(),
            fingerprint: "ABC123".to_string(),
            address: "1.2.3.4".parse().unwrap(),
            or_port: 9001,
            dir_port: None,
            flags: RelayFlags {
                guard: true,
                stable: true,
                fast: true,
                running: true,
                ..Default::default()
            },
            bandwidth: 1_000_000,
            published: 0,
            ntor_onion_key: None,
            family: None,
        };

        assert!(relay.is_guard());
    }
}

