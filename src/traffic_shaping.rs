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
    /// Enable random padding cells (default: true for privacy)
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
    /// Default configuration with padding enabled for privacy.
    ///
    /// Adds ~10% padding overhead. Chaff and timing obfuscation are off
    /// by default (use `paranoid()` for full protection at ~20% overhead).
    fn default() -> Self {
        Self {
            padding_enabled: true, // On by default for privacy
            padding_probability: 0.1,
            min_cell_interval_ms: 0, // No minimum interval by default
            chaff_enabled: false,
            chaff_interval_secs: 30,
            max_random_delay_ms: 0, // No random delay by default
        }
    }
}

impl TrafficShapingConfig {
    /// Create a minimal configuration with no traffic shaping.
    ///
    /// Use this for testing or bandwidth-constrained environments.
    pub fn disabled() -> Self {
        Self {
            padding_enabled: false,
            padding_probability: 0.0,
            min_cell_interval_ms: 0,
            chaff_enabled: false,
            chaff_interval_secs: 30,
            max_random_delay_ms: 0,
        }
    }

    /// Create a configuration with padding enabled (same as default).
    pub fn with_padding() -> Self {
        Self::default()
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

/// Traffic profile that mimics a specific application's WebSocket behavior.
///
/// DPI systems classify encrypted WebSocket traffic by statistical features:
/// - Frame size distribution (mean, variance, histogram)
/// - Inter-arrival timing (bursts vs steady)
/// - Up/down byte ratio
///
/// These profiles shape Tor cell traffic to statistically resemble
/// legitimate WebSocket applications, making classification harder.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum TrafficProfile {
    /// No shaping — raw Tor cells (514 bytes each)
    None,

    /// Chat application (e.g., WhatsApp Web, Telegram Web)
    /// - Small bursts (50-200 bytes) with idle gaps (500-3000ms)
    /// - Occasional large messages (200-1000 bytes)
    /// - Up/down ratio ~0.3 (more received than sent)
    Chat,

    /// Stock ticker / real-time data feed
    /// - Steady small frames (20-100 bytes) every 100-500ms
    /// - Very low up traffic (heartbeats only)
    /// - Up/down ratio ~0.05
    Ticker,

    /// Video call (e.g., Jitsi, Google Meet)
    /// - Sustained high bandwidth (800-1200 byte frames)
    /// - Steady 30-50ms inter-arrival (30fps video)
    /// - Up/down ratio ~0.8 (roughly symmetric)
    Video,
}

impl Default for TrafficProfile {
    fn default() -> Self {
        TrafficProfile::None
    }
}

/// Frame size range for a traffic profile
#[derive(Debug, Clone)]
pub struct FrameSizeRange {
    pub min: usize,
    pub max: usize,
}

/// Profile-specific traffic parameters
#[derive(Debug, Clone)]
pub struct ProfileParams {
    /// Target frame sizes (data will be fragmented/padded to fit)
    pub frame_sizes: FrameSizeRange,
    /// Minimum inter-frame delay in milliseconds
    pub min_delay_ms: u64,
    /// Maximum inter-frame delay in milliseconds
    pub max_delay_ms: u64,
    /// Probability of inserting an idle gap (simulates user think time)
    pub idle_gap_probability: f32,
    /// Idle gap duration range (ms)
    pub idle_gap_min_ms: u64,
    pub idle_gap_max_ms: u64,
}

impl TrafficProfile {
    /// Get the shaping parameters for this profile
    pub fn params(&self) -> Option<ProfileParams> {
        match self {
            TrafficProfile::None => None,
            TrafficProfile::Chat => Some(ProfileParams {
                frame_sizes: FrameSizeRange { min: 50, max: 200 },
                min_delay_ms: 20,
                max_delay_ms: 150,
                idle_gap_probability: 0.15,
                idle_gap_min_ms: 500,
                idle_gap_max_ms: 3000,
            }),
            TrafficProfile::Ticker => Some(ProfileParams {
                frame_sizes: FrameSizeRange { min: 20, max: 100 },
                min_delay_ms: 100,
                max_delay_ms: 500,
                idle_gap_probability: 0.0,
                idle_gap_min_ms: 0,
                idle_gap_max_ms: 0,
            }),
            TrafficProfile::Video => Some(ProfileParams {
                frame_sizes: FrameSizeRange { min: 800, max: 1200 },
                min_delay_ms: 25,
                max_delay_ms: 50,
                idle_gap_probability: 0.0,
                idle_gap_min_ms: 0,
                idle_gap_max_ms: 0,
            }),
        }
    }
}

/// Fragment a data buffer into profile-matching frame sizes.
///
/// Instead of sending Tor cells as 514-byte WebSocket frames (trivially
/// fingerprinted), this splits data into random sizes matching the target
/// profile's distribution.
///
/// Returns a Vec of frame payloads. Each frame may need padding to reach
/// the minimum size. If data is smaller than `min`, it is padded.
pub fn fragment_for_profile(data: &[u8], profile: &TrafficProfile, rng_state: &mut u64) -> Vec<Vec<u8>> {
    let params = match profile.params() {
        Some(p) => p,
        None => return vec![data.to_vec()], // No fragmentation
    };

    let mut frames = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        // Random frame size within profile range
        let range = params.frame_sizes.max - params.frame_sizes.min;
        let frame_size = if range > 0 {
            params.frame_sizes.min + (xorshift64(rng_state) as usize % (range + 1))
        } else {
            params.frame_sizes.min
        };

        let end = (offset + frame_size).min(data.len());
        let mut frame = data[offset..end].to_vec();

        // Pad to minimum frame size if undersized
        if frame.len() < params.frame_sizes.min {
            let pad_len = params.frame_sizes.min - frame.len();
            // Append random padding bytes
            for _ in 0..pad_len {
                frame.push((xorshift64(rng_state) & 0xFF) as u8);
            }
        }

        frames.push(frame);
        offset = end;
    }

    // Handle empty data — send at least one padded frame
    if frames.is_empty() {
        let pad_len = params.frame_sizes.min;
        let mut frame = Vec::with_capacity(pad_len);
        for _ in 0..pad_len {
            frame.push((xorshift64(rng_state) & 0xFF) as u8);
        }
        frames.push(frame);
    }

    frames
}

/// Calculate inter-frame delay for a traffic profile.
///
/// Returns the delay to wait before sending the next frame,
/// including possible idle gaps to simulate human behavior.
pub fn profile_delay(profile: &TrafficProfile, rng_state: &mut u64) -> Duration {
    let params = match profile.params() {
        Some(p) => p,
        None => return Duration::ZERO,
    };

    // Check for idle gap (simulates user pausing)
    if params.idle_gap_probability > 0.0 {
        let r = (xorshift64(rng_state) % 10000) as f32 / 10000.0;
        if r < params.idle_gap_probability {
            let gap_range = params.idle_gap_max_ms - params.idle_gap_min_ms;
            let gap = if gap_range > 0 {
                params.idle_gap_min_ms + (xorshift64(rng_state) % (gap_range + 1))
            } else {
                params.idle_gap_min_ms
            };
            return Duration::from_millis(gap);
        }
    }

    // Normal inter-frame delay
    let delay_range = params.max_delay_ms - params.min_delay_ms;
    let delay = if delay_range > 0 {
        params.min_delay_ms + (xorshift64(rng_state) % (delay_range + 1))
    } else {
        params.min_delay_ms
    };

    Duration::from_millis(delay)
}

/// Simple xorshift64 PRNG (deterministic, fast, no dependencies)
fn xorshift64(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
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
        assert!(config.padding_enabled); // Padding on by default for privacy
        assert!(!config.chaff_enabled);
        assert_eq!(config.min_cell_interval_ms, 0);
    }

    #[test]
    fn test_disabled_config() {
        let config = TrafficShapingConfig::disabled();
        assert!(!config.padding_enabled);
        assert!(!config.chaff_enabled);
        assert_eq!(config.padding_probability, 0.0);
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

    #[test]
    fn test_traffic_profile_params() {
        assert!(TrafficProfile::None.params().is_none());

        let chat = TrafficProfile::Chat.params().unwrap();
        assert!(chat.frame_sizes.min >= 50);
        assert!(chat.frame_sizes.max <= 200);
        assert!(chat.idle_gap_probability > 0.0);

        let ticker = TrafficProfile::Ticker.params().unwrap();
        assert!(ticker.frame_sizes.min >= 20);
        assert!(ticker.frame_sizes.max <= 100);
        assert_eq!(ticker.idle_gap_probability, 0.0);

        let video = TrafficProfile::Video.params().unwrap();
        assert!(video.frame_sizes.min >= 800);
        assert!(video.frame_sizes.max <= 1200);
        assert!(video.min_delay_ms <= 50);
    }

    #[test]
    fn test_fragment_for_profile_chat() {
        let data = vec![0u8; 514]; // One Tor cell
        let mut rng = 12345u64;
        let frames = fragment_for_profile(&data, &TrafficProfile::Chat, &mut rng);

        // 514 bytes should be split into multiple chat-sized frames (50-200 bytes)
        assert!(frames.len() >= 3); // 514 / 200 = 2.57, so at least 3
        for frame in &frames {
            assert!(frame.len() >= 50, "Frame too small: {}", frame.len());
            assert!(frame.len() <= 200, "Frame too large: {}", frame.len());
        }
    }

    #[test]
    fn test_fragment_for_profile_none() {
        let data = vec![42u8; 514];
        let mut rng = 99999u64;
        let frames = fragment_for_profile(&data, &TrafficProfile::None, &mut rng);

        // No fragmentation — single frame with original data
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].len(), 514);
    }

    #[test]
    fn test_fragment_empty_data() {
        let data = vec![];
        let mut rng = 11111u64;
        let frames = fragment_for_profile(&data, &TrafficProfile::Chat, &mut rng);

        // Should produce at least one padded frame
        assert_eq!(frames.len(), 1);
        assert!(frames[0].len() >= 50);
    }

    #[test]
    fn test_profile_delay() {
        let mut rng = 54321u64;

        // None profile — zero delay
        let d = profile_delay(&TrafficProfile::None, &mut rng);
        assert_eq!(d, Duration::ZERO);

        // Chat profile — delay between 20-150ms (or idle gap 500-3000ms)
        let d = profile_delay(&TrafficProfile::Chat, &mut rng);
        assert!(d.as_millis() <= 3000);

        // Video profile — delay between 25-50ms
        let d = profile_delay(&TrafficProfile::Video, &mut rng);
        assert!(d.as_millis() >= 25);
        assert!(d.as_millis() <= 50);
    }
}

