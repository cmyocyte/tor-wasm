//! Tor consensus parsing
//!
//! Parses the network consensus document from directory authorities,
//! extracting relay descriptors and metadata.

use super::relay::{Relay, RelayFlags};
use crate::error::{Result, TorError};
use std::net::IpAddr;
use serde::{Serialize, Deserialize};

/// Parsed consensus document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Consensus {
    /// Consensus valid-after time
    pub valid_after: u64,
    
    /// Consensus fresh-until time
    pub fresh_until: u64,
    
    /// Consensus valid-until time
    pub valid_until: u64,
    
    /// All relays in the consensus
    pub relays: Vec<Relay>,
    
    /// Consensus version
    pub version: u32,
}

impl Consensus {
    /// Check if this consensus is still fresh
    pub fn is_fresh(&self) -> bool {
        let now = (js_sys::Date::now() / 1000.0) as u64;
        now < self.fresh_until
    }
    
    /// Check if this consensus is still valid
    pub fn is_valid(&self) -> bool {
        let now = (js_sys::Date::now() / 1000.0) as u64;
        now < self.valid_until
    }
    
    /// Get running relays
    pub fn running_relays(&self) -> Vec<&Relay> {
        self.relays.iter().filter(|r| r.is_running()).collect()
    }
}

/// Consensus parser
pub struct ConsensusParser;

impl ConsensusParser {
    /// Parse a consensus document
    pub fn parse(data: &[u8]) -> Result<Consensus> {
        let text = String::from_utf8(data.to_vec())
            .map_err(|e| TorError::Directory(format!("Invalid UTF-8 in consensus: {}", e)))?;
        
        Self::parse_text(&text)
    }
    
    /// Parse consensus from text
    pub fn parse_text(text: &str) -> Result<Consensus> {
        let mut valid_after = 0;
        let mut fresh_until = 0;
        let mut valid_until = 0;
        let mut version = 3; // Default to version 3
        let mut relays = Vec::new();
        
        let mut current_relay: Option<RelayBuilder> = None;
        
        for line in text.lines() {
            let line = line.trim();
            
            if line.is_empty() {
                continue;
            }
            
            // Parse consensus metadata
            if line.starts_with("network-status-version") {
                if let Some(v) = line.split_whitespace().nth(1) {
                    version = v.parse().unwrap_or(3);
                }
            } else if line.starts_with("valid-after") {
                valid_after = Self::parse_timestamp(line).unwrap_or(0);
            } else if line.starts_with("fresh-until") {
                fresh_until = Self::parse_timestamp(line).unwrap_or(0);
            } else if line.starts_with("valid-until") {
                valid_until = Self::parse_timestamp(line).unwrap_or(0);
            }
            // Parse relay entries
            else if line.starts_with("r ") {
                // New relay entry - save previous if exists
                if let Some(builder) = current_relay.take() {
                    if let Some(relay) = builder.build() {
                        relays.push(relay);
                    }
                }
                
                // Start new relay
                current_relay = Some(Self::parse_r_line(line)?);
            } else if line.starts_with("s ") {
                // Relay flags
                if let Some(ref mut builder) = current_relay {
                    let flags_str = &line[2..]; // Skip "s "
                    builder.flags = Some(RelayFlags::from_string(flags_str));
                }
            } else if line.starts_with("w ") {
                // Bandwidth
                if let Some(ref mut builder) = current_relay {
                    if let Some(bw) = Self::parse_bandwidth(line) {
                        builder.bandwidth = Some(bw);
                    }
                }
            } else if line.starts_with("p ") {
                // Exit policy (not fully implemented yet)
                // We just mark that this relay has an exit policy
            } else if line.starts_with("family ") {
                // Family declaration from relay descriptor
                // Format: family $<fp1> $<fp2> ...
                if let Some(ref mut builder) = current_relay {
                    builder.family = Some(line[7..].to_string());
                }
            }
        }
        
        // Don't forget the last relay
        if let Some(builder) = current_relay {
            if let Some(relay) = builder.build() {
                relays.push(relay);
            }
        }
        
        Ok(Consensus {
            valid_after,
            fresh_until,
            valid_until,
            version,
            relays,
        })
    }
    
    /// Parse "r" line (relay descriptor)
    /// Format: r nickname identity published IP ORPort DirPort
    fn parse_r_line(line: &str) -> Result<RelayBuilder> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        
        if parts.len() < 6 {
            return Err(TorError::Directory("Invalid r line".into()));
        }
        
        let nickname = parts[1].to_string();
        let fingerprint = parts[2].to_string(); // Base64 encoded, we'll use as-is
        
        let address: IpAddr = parts[4]
            .parse()
            .map_err(|_| TorError::Directory("Invalid IP address".into()))?;
        
        let or_port: u16 = parts[5]
            .parse()
            .map_err(|_| TorError::Directory("Invalid OR port".into()))?;
        
        let dir_port: Option<u16> = if parts.len() > 6 && parts[6] != "0" {
            parts[6].parse().ok()
        } else {
            None
        };
        
        Ok(RelayBuilder {
            nickname,
            fingerprint,
            address,
            or_port,
            dir_port,
            flags: None,
            bandwidth: None,
            published: 0,
            ntor_onion_key: None,
            family: None,
        })
    }
    
    /// Parse bandwidth from "w" line
    /// Format: w Bandwidth=12345
    fn parse_bandwidth(line: &str) -> Option<u64> {
        for part in line.split_whitespace() {
            if part.starts_with("Bandwidth=") {
                let bw_str = part.strip_prefix("Bandwidth=")?;
                return bw_str.parse().ok();
            }
        }
        None
    }
    
    /// Parse timestamp from consensus line
    fn parse_timestamp(line: &str) -> Option<u64> {
        // Simplified timestamp parsing
        // Real implementation would parse ISO 8601 format
        // For now, return current time
        Some((js_sys::Date::now() / 1000.0) as u64)
    }
}

/// Builder for constructing a Relay from consensus data
struct RelayBuilder {
    nickname: String,
    fingerprint: String,
    address: IpAddr,
    or_port: u16,
    dir_port: Option<u16>,
    flags: Option<RelayFlags>,
    bandwidth: Option<u64>,
    published: u64,
    ntor_onion_key: Option<String>,
    family: Option<String>,
}

impl RelayBuilder {
    fn build(self) -> Option<Relay> {
        Some(Relay {
            nickname: self.nickname,
            fingerprint: self.fingerprint,
            address: self.address,
            or_port: self.or_port,
            dir_port: self.dir_port,
            flags: self.flags.unwrap_or_default(),
            bandwidth: self.bandwidth.unwrap_or(0),
            published: self.published,
            ntor_onion_key: self.ntor_onion_key,
            family: self.family,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_consensus_basic() {
        let sample = "network-status-version 3\n\
                      valid-after 2024-01-01 00:00:00\n\
                      fresh-until 2024-01-01 01:00:00\n\
                      valid-until 2024-01-01 03:00:00\n\
                      r TestRelay ABC123 2024-01-01 1.2.3.4 9001 9030\n\
                      s Fast Guard Running Stable Valid\n\
                      w Bandwidth=1000000\n";
        
        let consensus = ConsensusParser::parse_text(sample).unwrap();
        assert_eq!(consensus.version, 3);
        assert_eq!(consensus.relays.len(), 1);
        
        let relay = &consensus.relays[0];
        assert_eq!(relay.nickname, "TestRelay");
        assert_eq!(relay.or_port, 9001);
        assert!(relay.flags.fast);
        assert!(relay.flags.guard);
    }
}

