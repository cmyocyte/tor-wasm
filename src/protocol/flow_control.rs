//! Tor SENDME Flow Control
//!
//! Implements Tor's flow control mechanism to prevent buffer overflow.
//!
//! ## How It Works:
//!
//! 1. **Windows:** Each stream and circuit has send/receive windows
//! 2. **Decrement:** Window decrements on each cell sent/received
//! 3. **SENDME:** When window reaches threshold, send SENDME cell
//! 4. **Increment:** Receiving SENDME increments the opposite window
//!
//! ## Window Values (from Tor spec):
//!
//! - **Initial window:** 1000 cells (circuit), 500 cells (stream)
//! - **Increment:** 100 cells per SENDME (circuit), 50 cells (stream)
//! - **Threshold:** Send SENDME when window reaches increment value
//!
//! This prevents:
//! - Buffer overflow attacks
//! - Memory exhaustion
//! - Unfair bandwidth allocation

use crate::error::{Result, TorError};

/// Circuit-level flow control
///
/// Manages SENDME windows for an entire circuit.
/// Each circuit has its own windows independent of streams.
#[derive(Debug, Clone)]
pub struct CircuitFlowControl {
    /// Cells we can send before needing SENDME
    pub send_window: u16,

    /// Cells received since last sending SENDME
    pub recv_window: u16,

    /// Cells delivered to streams
    pub deliver_window: u16,
}

impl CircuitFlowControl {
    /// Initial circuit window size (Tor spec: 1000 cells)
    pub const INITIAL_WINDOW: u16 = 1000;

    /// Window increment per SENDME (Tor spec: 100 cells)
    pub const WINDOW_INCREMENT: u16 = 100;

    /// Create new circuit flow control with default windows
    pub fn new() -> Self {
        Self {
            send_window: Self::INITIAL_WINDOW,
            recv_window: Self::WINDOW_INCREMENT, // Start at increment
            deliver_window: Self::INITIAL_WINDOW,
        }
    }

    /// Check if we can send a cell
    pub fn can_send(&self) -> bool {
        self.send_window > 0
    }

    /// Decrement send window when sending a cell
    pub fn on_send(&mut self) -> Result<()> {
        if self.send_window == 0 {
            return Err(TorError::Stream(
                "Circuit send window exhausted - cannot send".into(),
            ));
        }

        self.send_window -= 1;
        Ok(())
    }

    /// Increment send window when receiving SENDME
    pub fn on_sendme_received(&mut self) {
        self.send_window += Self::WINDOW_INCREMENT;
        log::debug!(
            "Circuit send window: {} (+{})",
            self.send_window,
            Self::WINDOW_INCREMENT
        );
    }

    /// Process received cell and check if we should send SENDME
    ///
    /// Returns `true` if we should send a SENDME back
    pub fn on_receive(&mut self) -> bool {
        // Decrement receive window
        if self.recv_window > 0 {
            self.recv_window -= 1;
        }

        // Decrement deliver window
        if self.deliver_window > 0 {
            self.deliver_window -= 1;
        }

        // Should we send SENDME?
        if self.recv_window == 0 {
            // Reset window
            self.recv_window = Self::WINDOW_INCREMENT;
            log::debug!("Circuit recv window depleted, sending SENDME");
            return true;
        }

        false
    }
}

impl Default for CircuitFlowControl {
    fn default() -> Self {
        Self::new()
    }
}

/// Stream-level flow control
///
/// Manages SENDME windows for a single stream within a circuit.
/// Each stream has independent windows.
#[derive(Debug, Clone)]
pub struct StreamFlowControl {
    /// Cells we can send before needing SENDME
    pub send_window: u16,

    /// Cells received since last sending SENDME
    pub recv_window: u16,

    /// Stream ID this flow control belongs to
    pub stream_id: u16,
}

impl StreamFlowControl {
    /// Initial stream window size (Tor spec: 500 cells)
    pub const INITIAL_WINDOW: u16 = 500;

    /// Window increment per SENDME (Tor spec: 50 cells)
    pub const WINDOW_INCREMENT: u16 = 50;

    /// Create new stream flow control
    pub fn new(stream_id: u16) -> Self {
        Self {
            send_window: Self::INITIAL_WINDOW,
            recv_window: Self::WINDOW_INCREMENT,
            stream_id,
        }
    }

    /// Check if we can send a cell
    pub fn can_send(&self) -> bool {
        self.send_window > 0
    }

    /// Decrement send window when sending a DATA cell
    pub fn on_send(&mut self) -> Result<()> {
        if self.send_window == 0 {
            return Err(TorError::Stream(format!(
                "Stream {} send window exhausted",
                self.stream_id
            )));
        }

        self.send_window -= 1;
        Ok(())
    }

    /// Increment send window when receiving SENDME
    pub fn on_sendme_received(&mut self) {
        self.send_window += Self::WINDOW_INCREMENT;
        log::debug!(
            "Stream {} send window: {} (+{})",
            self.stream_id,
            self.send_window,
            Self::WINDOW_INCREMENT
        );
    }

    /// Process received DATA cell and check if we should send SENDME
    ///
    /// Returns `true` if we should send a SENDME back
    pub fn on_receive_data(&mut self) -> bool {
        // Decrement receive window
        if self.recv_window > 0 {
            self.recv_window -= 1;
        }

        // Should we send SENDME?
        if self.recv_window == 0 {
            // Reset window
            self.recv_window = Self::WINDOW_INCREMENT;
            log::debug!(
                "Stream {} recv window depleted, sending SENDME",
                self.stream_id
            );
            return true;
        }

        false
    }

    /// Check if stream is blocked (can't send more data)
    pub fn is_blocked(&self) -> bool {
        self.send_window == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_flow_control_basic() {
        let mut fc = CircuitFlowControl::new();

        // Initial state
        assert_eq!(fc.send_window, 1000);
        assert_eq!(fc.recv_window, 100);
        assert!(fc.can_send());

        // Send cells
        for _ in 0..10 {
            fc.on_send().unwrap();
        }
        assert_eq!(fc.send_window, 990);

        // Receive SENDME
        fc.on_sendme_received();
        assert_eq!(fc.send_window, 1090);
    }

    #[test]
    fn test_circuit_flow_control_window_exhaustion() {
        let mut fc = CircuitFlowControl::new();

        // Exhaust window
        for _ in 0..1000 {
            fc.on_send().unwrap();
        }

        // Should fail
        assert!(fc.on_send().is_err());
        assert!(!fc.can_send());

        // Receive SENDME
        fc.on_sendme_received();
        assert!(fc.can_send());
        assert_eq!(fc.send_window, 100);
    }

    #[test]
    fn test_circuit_flow_control_receive() {
        let mut fc = CircuitFlowControl::new();

        // Receive cells (starts at 100)
        for i in 1..=100 {
            let should_sendme = fc.on_receive();

            if i < 100 {
                assert!(!should_sendme, "Should not SENDME before window depleted");
            } else {
                assert!(should_sendme, "Should SENDME when window depleted");
            }
        }

        // Window should be reset
        assert_eq!(fc.recv_window, 100);
    }

    #[test]
    fn test_stream_flow_control_basic() {
        let mut fc = StreamFlowControl::new(42);

        // Initial state
        assert_eq!(fc.stream_id, 42);
        assert_eq!(fc.send_window, 500);
        assert_eq!(fc.recv_window, 50);
        assert!(fc.can_send());
        assert!(!fc.is_blocked());

        // Send cells
        for _ in 0..10 {
            fc.on_send().unwrap();
        }
        assert_eq!(fc.send_window, 490);

        // Receive SENDME
        fc.on_sendme_received();
        assert_eq!(fc.send_window, 540);
    }

    #[test]
    fn test_stream_flow_control_blocking() {
        let mut fc = StreamFlowControl::new(1);

        // Exhaust window
        for _ in 0..500 {
            assert!(!fc.is_blocked());
            fc.on_send().unwrap();
        }

        // Now blocked
        assert!(fc.is_blocked());
        assert!(!fc.can_send());
        assert!(fc.on_send().is_err());

        // Unblock with SENDME
        fc.on_sendme_received();
        assert!(!fc.is_blocked());
        assert_eq!(fc.send_window, 50);
    }

    #[test]
    fn test_stream_flow_control_receive() {
        let mut fc = StreamFlowControl::new(1);

        // Receive DATA cells (starts at 50)
        for i in 1..=50 {
            let should_sendme = fc.on_receive_data();

            if i < 50 {
                assert!(!should_sendme);
            } else {
                assert!(should_sendme);
            }
        }

        // Window should be reset
        assert_eq!(fc.recv_window, 50);
    }

    #[test]
    fn test_interleaved_send_receive() {
        let mut fc = StreamFlowControl::new(1);

        // Send 250 cells
        for _ in 0..250 {
            fc.on_send().unwrap();
        }
        assert_eq!(fc.send_window, 250);

        // Receive 25 DATA cells
        for _ in 0..25 {
            assert!(!fc.on_receive_data());
        }

        // Receive 25 more (should trigger SENDME)
        for i in 0..25 {
            let should_sendme = fc.on_receive_data();
            assert_eq!(should_sendme, i == 24);
        }

        // Send window still blocked, but we've processed receives
        assert_eq!(fc.send_window, 250);
        assert!(!fc.is_blocked());
    }
}
