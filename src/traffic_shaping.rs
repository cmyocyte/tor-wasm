//! Traffic Analysis Resistance
//!
//! Implements traffic shaping techniques to resist timing and traffic analysis attacks.
//!
//! ## Security Rationale
//!
//! Traffic analysis attacks can de-anonymize Tor users by analyzing:
//! - Timing patterns (when cells are sent)
//! - Volume patterns (how many cells are sent)
//! - Correlation between entry and exit traffic
//!
//! This module provides:
//! - **Padding cells**: Random padding to obscure message sizes
//! - **Timing obfuscation**: Minimum intervals between cells
//! - **Chaff traffic**: Dummy cells during idle periods
//!
//! ## Tor Protocol Reference
//!
//! PADDING cells (command 0) are defined in tor-spec.txt Section 3.
//! They can be sent at any time and are ignored by receivers.

use std::time::Duration;
use serde::{Serialize, Deserialize};

/// Configuration for traffic shaping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficShapingConfig {
    /// Enable random padding cells (default: false)
    pub padding_enabled: bool,
    
    /// Probability of adding a padding cell (0.0 - 1.0, default: 0.1)
    pub padding_probability: f32,
    
    /// Minimum time between cells in milliseconds (default: 0 - disabled)
    pub min_cell_interval_ms: u64,
    
    /// Enable chaff traffic during idle periods (default: false)
    pub chaff_enabled: bool,
    
    /// Interval for chaff cells in seconds (default: 30)
    pub chaff_interval_secs: u64,
    
    /// Maximum random delay to add (in ms, default: 0)
    pub max_random_delay_ms: u64,
}

impl Default for TrafficShapingConfig {
    fn default() -> Self {
        Self {
            padding_enabled: false, // Off by default for performance
            padding_probability: 0.1,
            min_cell_interval_ms: 0, // No minimum interval by default
            chaff_enabled: false,
            chaff_interval_secs: 30,
            max_random_delay_ms: 0, // No random delay by default
        }
    }
}

impl TrafficShapingConfig {
    /// Create a configuration with padding enabled
    pub fn with_padding() -> Self {
        Self {
            padding_enabled: true,
            padding_probability: 0.1,
            ..Default::default()
        }
    }
    
    /// Create a paranoid configuration with all protections
    pub fn paranoid() -> Self {
        Self {
            padding_enabled: true,
            padding_probability: 0.2,
            min_cell_interval_ms: 10,
            chaff_enabled: true,
            chaff_interval_secs: 15,
            max_random_delay_ms: 50,
        }
    }
}

/// Traffic shaping state
pub struct TrafficShaper {
    /// Configuration
    config: TrafficShapingConfig,
    
    /// Timestamp of last cell sent (ms since epoch)
    last_cell_sent_ms: u64,
    
    /// RNG state for padding decisions
    rng_state: u64,
    
    /// Statistics
    stats: TrafficShapingStats,
}

/// Statistics about traffic shaping
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrafficShapingStats {
    /// Number of padding cells sent
    pub padding_cells_sent: u64,
    
    /// Number of chaff cells sent
    pub chaff_cells_sent: u64,
    
    /// Total delay added (ms)
    pub total_delay_added_ms: u64,
    
    /// Number of cells shaped
    pub cells_shaped: u64,
}

impl TrafficShaper {
    /// Create a new traffic shaper with the given configuration
    pub fn new(config: TrafficShapingConfig) -> Self {
        Self {
            config,
            last_cell_sent_ms: 0,
            rng_state: current_time_ms(),
            stats: TrafficShapingStats::default(),
        }
    }
    
    /// Create with default configuration
    pub fn default_config() -> Self {
        Self::new(TrafficShapingConfig::default())
    }
    
    /// Enable or disable padding
    pub fn set_padding(&mut self, enabled: bool) {
        self.config.padding_enabled = enabled;
        log::info!("🔒 Padding cells: {}", if enabled { "enabled" } else { "disabled" });
    }
    
    /// Enable or disable chaff
    pub fn set_chaff(&mut self, enabled: bool) {
        self.config.chaff_enabled = enabled;
        log::info!("🔒 Chaff traffic: {}", if enabled { "enabled" } else { "disabled" });
    }
    
    /// Set minimum cell interval
    pub fn set_min_interval(&mut self, ms: u64) {
        self.config.min_cell_interval_ms = ms;
        log::info!("🔒 Minimum cell interval: {}ms", ms);
    }
    
    /// Should we add a padding cell before sending?
    pub fn should_add_padding(&mut self) -> bool {
        if !self.config.padding_enabled {
            return false;
        }
        
        // Generate random float 0.0-1.0
        let r = self.random_float();
        r < self.config.padding_probability
    }
    
    /// Calculate delay before sending a cell (for timing obfuscation)
    pub fn calculate_delay(&mut self) -> Duration {
        let mut delay_ms = 0u64;
        
        // Enforce minimum interval
        if self.config.min_cell_interval_ms > 0 {
            let now = current_time_ms();
            let elapsed = now.saturating_sub(self.last_cell_sent_ms);
            
            if elapsed < self.config.min_cell_interval_ms {
                delay_ms = self.config.min_cell_interval_ms - elapsed;
            }
        }
        
        // Add random delay
        if self.config.max_random_delay_ms > 0 {
            delay_ms += self.random() % (self.config.max_random_delay_ms + 1);
        }
        
        if delay_ms > 0 {
            self.stats.total_delay_added_ms += delay_ms;
        }
        
        Duration::from_millis(delay_ms)
    }
    
    /// Record that a cell was sent
    pub fn record_cell_sent(&mut self) {
        self.last_cell_sent_ms = current_time_ms();
        self.stats.cells_shaped += 1;
    }
    
    /// Record that a padding cell was sent
    pub fn record_padding_sent(&mut self) {
        self.stats.padding_cells_sent += 1;
    }
    
    /// Record that a chaff cell was sent
    pub fn record_chaff_sent(&mut self) {
        self.stats.chaff_cells_sent += 1;
    }
    
    /// Check if chaff should be sent (based on idle time)
    pub fn should_send_chaff(&self) -> bool {
        if !self.config.chaff_enabled {
            return false;
        }
        
        let now = current_time_ms();
        let idle_ms = now.saturating_sub(self.last_cell_sent_ms);
        
        idle_ms > (self.config.chaff_interval_secs * 1000)
    }
    
    /// Create a PADDING cell (Tor command 0)
    /// 
    /// Format: [CircID (4 bytes)] [CMD=0 (1 byte)] [random payload (509 bytes)]
    pub fn create_padding_cell(circuit_id: u32) -> [u8; 514] {
        let mut cell = [0u8; 514];
        
        // Circuit ID (4 bytes, big-endian)
        cell[0..4].copy_from_slice(&circuit_id.to_be_bytes());
        
        // Command = 0 (PADDING)
        cell[4] = 0;
        
        // Fill payload with random data
        getrandom::getrandom(&mut cell[5..]).unwrap_or_else(|_| {
            // Fallback: use timestamp-based pseudo-random
            let ts = current_time_ms();
            for (i, byte) in cell[5..].iter_mut().enumerate() {
                *byte = ((ts.wrapping_mul(31).wrapping_add(i as u64)) & 0xFF) as u8;
            }
        });
        
        cell
    }
    
    /// Get statistics
    pub fn stats(&self) -> &TrafficShapingStats {
        &self.stats
    }
    
    /// Get configuration
    pub fn config(&self) -> &TrafficShapingConfig {
        &self.config
    }
    
    // Internal random number generation
    fn random(&mut self) -> u64 {
        // xorshift64
        self.rng_state ^= self.rng_state << 13;
        self.rng_state ^= self.rng_state >> 7;
        self.rng_state ^= self.rng_state << 17;
        self.rng_state
    }
    
    fn random_float(&mut self) -> f32 {
        (self.random() % 10000) as f32 / 10000.0
    }
}

/// Get current time in milliseconds
fn current_time_ms() -> u64 {
    use web_time::SystemTime;
    
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Async helper to apply timing delays
pub async fn apply_delay(delay: Duration) {
    if delay.is_zero() {
        return;
    }
    
    gloo_timers::future::TimeoutFuture::new(delay.as_millis() as u32).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_config() {
        let config = TrafficShapingConfig::default();
        assert!(!config.padding_enabled);
        assert!(!config.chaff_enabled);
        assert_eq!(config.min_cell_interval_ms, 0);
    }
    
    #[test]
    fn test_paranoid_config() {
        let config = TrafficShapingConfig::paranoid();
        assert!(config.padding_enabled);
        assert!(config.chaff_enabled);
        assert!(config.min_cell_interval_ms > 0);
    }
    
    #[test]
    fn test_padding_cell_format() {
        let cell = TrafficShaper::create_padding_cell(0x12345678);
        
        // Check circuit ID
        let circ_id = u32::from_be_bytes([cell[0], cell[1], cell[2], cell[3]]);
        assert_eq!(circ_id, 0x12345678);
        
        // Check command
        assert_eq!(cell[4], 0); // PADDING
        
        // Check length
        assert_eq!(cell.len(), 514);
    }
    
    #[test]
    fn test_padding_probability() {
        let mut shaper = TrafficShaper::new(TrafficShapingConfig {
            padding_enabled: true,
            padding_probability: 1.0, // Always pad
            ..Default::default()
        });
        
        // Should always return true with probability 1.0
        assert!(shaper.should_add_padding());
    }
    
    #[test]
    fn test_chaff_timing() {
        let mut shaper = TrafficShaper::new(TrafficShapingConfig {
            chaff_enabled: true,
            chaff_interval_secs: 1, // 1 second for testing
            ..Default::default()
        });
        
        // Simulate last cell sent long ago
        shaper.last_cell_sent_ms = current_time_ms() - 2000; // 2 seconds ago
        
        assert!(shaper.should_send_chaff());
        
        // After sending a cell, should not need chaff
        shaper.record_cell_sent();
        assert!(!shaper.should_send_chaff());
    }
}

