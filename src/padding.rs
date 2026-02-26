//! Channel Padding for Netflow Resistance
//!
//! Implements Tor's channel padding mechanism to resist ISP netflow analysis.
//!
//! ## Background
//!
//! ISPs deploy routers that create Netflow/IPFIX records for every connection,
//! logging: source IP, dest IP, timestamps, packet counts, byte counts.
//! These records can be correlated to deanonymize Tor users.
//!
//! ## How Padding Helps
//!
//! By sending CELL_PADDING cells during idle periods, we:
//! - Obscure when the user is actually active
//! - Make connection idle times less distinguishable
//! - Reduce the precision of timing analysis
//!
//! ## Implementation (per padding-spec.txt)
//!
//! - Send CELL_PADDING at random intervals (1.5s - 9.5s by default)
//! - Negotiate padding parameters with PADDING_NEGOTIATE cell
//! - Respect relay's PADDING_NEGOTIATED response
//!
//! ## References
//!
//! - https://spec.torproject.org/padding-spec/connection-level-padding.html
//! - Proposal 254: Padding Negotiation

use crate::protocol::{Cell, CellCommand};

/// Padding negotiation command types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PaddingCommand {
    /// Start padding
    Start = 1,
    /// Stop padding
    Stop = 2,
}

/// Padding machine state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingState {
    /// Padding is disabled
    Disabled,
    /// Padding is enabled and active
    Enabled,
    /// Waiting for negotiation response
    Negotiating,
}

/// Channel padding configuration
#[derive(Debug, Clone)]
pub struct PaddingConfig {
    /// Whether padding is enabled
    pub enabled: bool,

    /// Minimum padding interval in milliseconds
    pub low_ms: u32,

    /// Maximum padding interval in milliseconds
    pub high_ms: u32,

    /// Timeout for idle connections in milliseconds
    /// (stop padding after this long idle)
    pub idle_timeout_ms: u32,
}

impl Default for PaddingConfig {
    fn default() -> Self {
        // Default values from Tor's padding-spec
        Self {
            enabled: true,
            low_ms: 1500,           // 1.5 seconds minimum
            high_ms: 9500,          // 9.5 seconds maximum
            idle_timeout_ms: 30000, // 30 seconds idle timeout
        }
    }
}

/// Channel padding scheduler
///
/// Manages the timing of CELL_PADDING cells for a connection.
/// This runs independently of circuit activity.
pub struct PaddingScheduler {
    /// Configuration
    config: PaddingConfig,

    /// Current state
    state: PaddingState,

    /// Timestamp of last cell (any type) sent/received
    last_cell_time_ms: u64,

    /// Timestamp of last padding cell sent
    last_padding_time_ms: u64,

    /// Next padding interval (randomized)
    next_interval_ms: u32,

    /// Total padding cells sent (for statistics)
    padding_cells_sent: u64,

    /// Whether the relay supports padding (from PADDING_NEGOTIATED)
    relay_supports_padding: bool,
}

impl PaddingScheduler {
    /// Create a new padding scheduler with default config
    pub fn new() -> Self {
        Self::with_config(PaddingConfig::default())
    }

    /// Create a padding scheduler with custom config
    pub fn with_config(config: PaddingConfig) -> Self {
        Self {
            state: if config.enabled {
                PaddingState::Enabled
            } else {
                PaddingState::Disabled
            },
            next_interval_ms: Self::random_interval(&config),
            config,
            last_cell_time_ms: 0,
            last_padding_time_ms: 0,
            padding_cells_sent: 0,
            relay_supports_padding: true, // Assume true until told otherwise
        }
    }

    /// Generate a random padding interval within the configured range
    fn random_interval(config: &PaddingConfig) -> u32 {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        rng.gen_range(config.low_ms..=config.high_ms)
    }

    /// Enable padding
    pub fn enable(&mut self) {
        self.state = PaddingState::Enabled;
        self.config.enabled = true;
        log::debug!("Channel padding enabled");
    }

    /// Disable padding
    pub fn disable(&mut self) {
        self.state = PaddingState::Disabled;
        self.config.enabled = false;
        log::debug!("Channel padding disabled");
    }

    /// Check if padding is enabled
    pub fn is_enabled(&self) -> bool {
        self.state == PaddingState::Enabled && self.relay_supports_padding
    }

    /// Record that a real cell was sent/received
    ///
    /// This resets the padding timer since we have real activity.
    pub fn on_cell_activity(&mut self, now_ms: u64) {
        self.last_cell_time_ms = now_ms;
    }

    /// Check if we should send a padding cell now
    ///
    /// Returns true if it's time to send padding.
    pub fn should_send_padding(&self, now_ms: u64) -> bool {
        if !self.is_enabled() {
            return false;
        }

        // Don't pad if we've been idle too long
        if self.last_cell_time_ms > 0 {
            let idle_time = now_ms.saturating_sub(self.last_cell_time_ms);
            if idle_time > self.config.idle_timeout_ms as u64 {
                return false;
            }
        }

        // Check if enough time has passed since last padding
        let time_since_activity = if self.last_padding_time_ms > 0 {
            now_ms.saturating_sub(self.last_padding_time_ms)
        } else {
            now_ms.saturating_sub(self.last_cell_time_ms)
        };

        time_since_activity >= self.next_interval_ms as u64
    }

    /// Record that we sent a padding cell
    ///
    /// Call this after sending CELL_PADDING.
    pub fn on_padding_sent(&mut self, now_ms: u64) {
        self.last_padding_time_ms = now_ms;
        self.padding_cells_sent += 1;

        // Generate new random interval for next padding
        self.next_interval_ms = Self::random_interval(&self.config);

        log::trace!(
            "Padding cell sent, next interval: {}ms",
            self.next_interval_ms
        );
    }

    /// Create a CELL_PADDING cell
    ///
    /// Circuit ID 0 is used for link-level padding.
    pub fn create_padding_cell() -> Cell {
        // CELL_PADDING uses circuit ID 0 (link-level)
        // Payload is random or zeros (relays ignore it)
        let payload = vec![0u8; Cell::PAYLOAD_SIZE];
        Cell::new(0, CellCommand::Padding, payload)
    }

    /// Create a PADDING_NEGOTIATE cell to start padding
    ///
    /// This tells the relay we want padding with our parameters.
    pub fn create_negotiate_start(&self) -> Cell {
        let mut payload = vec![0u8; Cell::PAYLOAD_SIZE];

        // Version (1 byte)
        payload[0] = 0; // Version 0

        // Command (1 byte): 1 = start, 2 = stop
        payload[1] = PaddingCommand::Start as u8;

        // ito_low_ms (2 bytes, big-endian) - low end of interval
        let low_ms = (self.config.low_ms / 10) as u16; // Spec uses 10ms units
        payload[2..4].copy_from_slice(&low_ms.to_be_bytes());

        // ito_high_ms (2 bytes, big-endian) - high end of interval
        let high_ms = (self.config.high_ms / 10) as u16;
        payload[4..6].copy_from_slice(&high_ms.to_be_bytes());

        Cell::new(0, CellCommand::PaddingNegotiate, payload)
    }

    /// Create a PADDING_NEGOTIATE cell to stop padding
    pub fn create_negotiate_stop() -> Cell {
        let mut payload = vec![0u8; Cell::PAYLOAD_SIZE];

        // Version (1 byte)
        payload[0] = 0;

        // Command (1 byte): 2 = stop
        payload[1] = PaddingCommand::Stop as u8;

        Cell::new(0, CellCommand::PaddingNegotiate, payload)
    }

    /// Handle PADDING_NEGOTIATED response from relay
    ///
    /// Returns true if relay accepted our padding request.
    pub fn handle_negotiated(&mut self, payload: &[u8]) -> bool {
        if payload.is_empty() {
            return false;
        }

        // Version (1 byte)
        let version = payload[0];
        if version != 0 {
            log::warn!("Unknown PADDING_NEGOTIATED version: {}", version);
            return false;
        }

        // Command (1 byte)
        if payload.len() < 2 {
            return false;
        }

        let command = payload[1];
        match command {
            1 => {
                // Relay started padding
                self.relay_supports_padding = true;
                log::info!("Relay accepted padding negotiation");
                true
            }
            2 => {
                // Relay stopped/refused padding
                self.relay_supports_padding = false;
                log::info!("Relay refused padding negotiation");
                false
            }
            _ => {
                log::warn!("Unknown PADDING_NEGOTIATED command: {}", command);
                false
            }
        }
    }

    /// Get padding statistics
    pub fn stats(&self) -> PaddingStats {
        PaddingStats {
            enabled: self.is_enabled(),
            cells_sent: self.padding_cells_sent,
            next_interval_ms: self.next_interval_ms,
            relay_supports: self.relay_supports_padding,
        }
    }
}

impl Default for PaddingScheduler {
    fn default() -> Self {
        Self::new()
    }
}

/// Padding statistics
#[derive(Debug, Clone)]
pub struct PaddingStats {
    /// Whether padding is currently enabled
    pub enabled: bool,

    /// Total padding cells sent
    pub cells_sent: u64,

    /// Next padding interval in ms
    pub next_interval_ms: u32,

    /// Whether relay supports padding
    pub relay_supports: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padding_scheduler_creation() {
        let scheduler = PaddingScheduler::new();
        assert!(scheduler.is_enabled());
        assert_eq!(scheduler.config.low_ms, 1500);
        assert_eq!(scheduler.config.high_ms, 9500);
    }

    #[test]
    fn test_padding_disabled() {
        let mut scheduler = PaddingScheduler::new();
        scheduler.disable();
        assert!(!scheduler.is_enabled());
        assert!(!scheduler.should_send_padding(10000));
    }

    #[test]
    fn test_padding_timing() {
        let config = PaddingConfig {
            enabled: true,
            low_ms: 100,
            high_ms: 200,
            idle_timeout_ms: 10000,
        };
        let mut scheduler = PaddingScheduler::with_config(config);

        // Record activity
        scheduler.on_cell_activity(1000);

        // Should not pad immediately
        assert!(!scheduler.should_send_padding(1000));

        // Should pad after interval
        assert!(scheduler.should_send_padding(1300));
    }

    #[test]
    fn test_padding_cell_creation() {
        let cell = PaddingScheduler::create_padding_cell();
        assert_eq!(cell.circuit_id, 0);
        assert_eq!(cell.command, CellCommand::Padding);
        assert_eq!(cell.payload.len(), Cell::PAYLOAD_SIZE);
    }

    #[test]
    fn test_negotiate_start_cell() {
        let scheduler = PaddingScheduler::new();
        let cell = scheduler.create_negotiate_start();

        assert_eq!(cell.circuit_id, 0);
        assert_eq!(cell.command, CellCommand::PaddingNegotiate);

        // Check payload format
        assert_eq!(cell.payload[0], 0); // Version
        assert_eq!(cell.payload[1], 1); // Command: Start
    }

    #[test]
    fn test_negotiate_stop_cell() {
        let cell = PaddingScheduler::create_negotiate_stop();

        assert_eq!(cell.payload[0], 0); // Version
        assert_eq!(cell.payload[1], 2); // Command: Stop
    }

    #[test]
    fn test_handle_negotiated() {
        let mut scheduler = PaddingScheduler::new();

        // Relay accepts
        let payload = vec![0, 1]; // Version 0, Command 1 (start)
        assert!(scheduler.handle_negotiated(&payload));
        assert!(scheduler.relay_supports_padding);

        // Relay refuses
        let payload = vec![0, 2]; // Version 0, Command 2 (stop)
        assert!(!scheduler.handle_negotiated(&payload));
        assert!(!scheduler.relay_supports_padding);
    }

    #[test]
    fn test_idle_timeout() {
        let config = PaddingConfig {
            enabled: true,
            low_ms: 100,
            high_ms: 200,
            idle_timeout_ms: 1000,
        };
        let mut scheduler = PaddingScheduler::with_config(config);

        // Record activity
        scheduler.on_cell_activity(1000);

        // After idle timeout, should not pad
        assert!(!scheduler.should_send_padding(3000));
    }
}
