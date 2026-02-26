//! RTT-based Congestion Control (Proposal 324)
//!
//! Implements Tor's RTT-based congestion control to break the ~500KB/s speed limit.
//!
//! ## Background
//!
//! Legacy Tor uses fixed SENDME windows (500 cells per stream), limiting throughput to:
//!   max_speed = (500 cells × 498 bytes) / RTT ≈ 500KB/s for typical RTTs
//!
//! Proposal 324 introduces dynamic congestion windows based on:
//! - RTT (Round-Trip Time) measurement via SENDME timing
//! - BDP (Bandwidth-Delay Product) estimation
//! - Vegas-style congestion avoidance
//!
//! ## Tor-Vegas Algorithm
//!
//! Based on TCP Vegas, adapted for Tor:
//! - Measure RTT from SENDME round-trips
//! - Calculate BDP = bandwidth × RTT
//! - Compare actual in-flight data to BDP
//! - Adjust CWND (congestion window) to stay near BDP
//!
//! ## References
//!
//! - https://spec.torproject.org/proposals/324-rtt-congestion-control.html
//! - "Congestion Control Arrives in Tor 0.4.7-stable!"

use std::time::Instant;

/// Congestion control algorithm selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CongestionAlgorithm {
    /// Fixed windows (legacy, no congestion control)
    Fixed,
    /// Tor-Vegas (default, recommended)
    #[default]
    Vegas,
    /// Tor-NOLA (experimental)
    Nola,
}

/// RTT sample
#[derive(Debug, Clone, Copy)]
pub struct RttSample {
    /// Measured RTT in milliseconds
    pub rtt_ms: u32,
    /// Timestamp when sample was taken
    pub timestamp: Instant,
}

/// RTT estimator using exponential weighted moving average
#[derive(Debug, Clone)]
pub struct RttEstimator {
    /// Smoothed RTT (EWMA)
    srtt_ms: Option<u32>,

    /// RTT variance (for timeout calculation)
    rttvar_ms: Option<u32>,

    /// Minimum observed RTT (estimate of base RTT without queuing)
    min_rtt_ms: Option<u32>,

    /// Maximum observed RTT
    max_rtt_ms: Option<u32>,

    /// Number of samples collected
    sample_count: u32,

    /// Last sample for debugging
    last_sample: Option<RttSample>,
}

impl RttEstimator {
    /// EWMA smoothing factor (α = 1/8, per TCP standard)
    const ALPHA: f32 = 0.125;

    /// Variance smoothing factor (β = 1/4)
    const BETA: f32 = 0.25;

    /// Create a new RTT estimator
    pub fn new() -> Self {
        Self {
            srtt_ms: None,
            rttvar_ms: None,
            min_rtt_ms: None,
            max_rtt_ms: None,
            sample_count: 0,
            last_sample: None,
        }
    }

    /// Add a new RTT sample
    pub fn add_sample(&mut self, rtt_ms: u32) {
        let sample = RttSample {
            rtt_ms,
            timestamp: Instant::now(),
        };

        self.sample_count += 1;
        self.last_sample = Some(sample);

        // Update min/max
        self.min_rtt_ms = Some(self.min_rtt_ms.map(|min| min.min(rtt_ms)).unwrap_or(rtt_ms));
        self.max_rtt_ms = Some(self.max_rtt_ms.map(|max| max.max(rtt_ms)).unwrap_or(rtt_ms));

        // Update SRTT using EWMA
        match self.srtt_ms {
            None => {
                // First sample
                self.srtt_ms = Some(rtt_ms);
                self.rttvar_ms = Some(rtt_ms / 2);
            }
            Some(srtt) => {
                // EWMA update: SRTT = (1-α)×SRTT + α×RTT
                let diff = rtt_ms.abs_diff(srtt);

                let new_rttvar = ((1.0 - Self::BETA) * self.rttvar_ms.unwrap_or(0) as f32
                    + Self::BETA * diff as f32) as u32;
                self.rttvar_ms = Some(new_rttvar);

                let new_srtt =
                    ((1.0 - Self::ALPHA) * srtt as f32 + Self::ALPHA * rtt_ms as f32) as u32;
                self.srtt_ms = Some(new_srtt);
            }
        }

        log::trace!(
            "RTT sample: {}ms, SRTT: {}ms, min: {}ms",
            rtt_ms,
            self.srtt_ms.unwrap_or(0),
            self.min_rtt_ms.unwrap_or(0)
        );
    }

    /// Get smoothed RTT estimate
    pub fn srtt(&self) -> Option<u32> {
        self.srtt_ms
    }

    /// Get minimum observed RTT (base RTT estimate)
    pub fn min_rtt(&self) -> Option<u32> {
        self.min_rtt_ms
    }

    /// Get estimated queuing delay (SRTT - min_RTT)
    pub fn queue_delay(&self) -> Option<u32> {
        match (self.srtt_ms, self.min_rtt_ms) {
            (Some(srtt), Some(min)) if srtt > min => Some(srtt - min),
            _ => Some(0),
        }
    }

    /// Check if we have enough samples for reliable estimates
    pub fn has_enough_samples(&self) -> bool {
        self.sample_count >= 3
    }

    /// Get statistics
    pub fn stats(&self) -> RttStats {
        RttStats {
            srtt_ms: self.srtt_ms,
            min_rtt_ms: self.min_rtt_ms,
            max_rtt_ms: self.max_rtt_ms,
            sample_count: self.sample_count,
            queue_delay_ms: self.queue_delay(),
        }
    }
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self::new()
    }
}

/// RTT statistics
#[derive(Debug, Clone)]
pub struct RttStats {
    pub srtt_ms: Option<u32>,
    pub min_rtt_ms: Option<u32>,
    pub max_rtt_ms: Option<u32>,
    pub sample_count: u32,
    pub queue_delay_ms: Option<u32>,
}

/// Congestion window controller (Tor-Vegas)
///
/// Manages the dynamic congestion window based on RTT measurements.
#[derive(Debug)]
pub struct CongestionController {
    /// Current congestion window (in cells)
    cwnd: u32,

    /// Slow-start threshold
    ssthresh: u32,

    /// RTT estimator
    rtt: RttEstimator,

    /// Algorithm in use
    algorithm: CongestionAlgorithm,

    /// Cells currently in flight (sent but not ACKed)
    in_flight: u32,

    /// Cells ACKed (received SENDMEs)
    acked: u64,

    /// Timestamp of last SENDME sent (for RTT measurement)
    sendme_sent_at: Option<Instant>,

    /// Whether we're in slow-start phase
    in_slow_start: bool,

    /// Vegas parameters
    vegas_alpha: u32,
    vegas_beta: u32,
    vegas_gamma: u32,
}

impl CongestionController {
    /// Initial congestion window (31 cells per spec)
    const INITIAL_CWND: u32 = 31;

    /// Minimum congestion window
    const MIN_CWND: u32 = 31;

    /// Maximum congestion window (can grow large for high-BDP paths)
    const MAX_CWND: u32 = 10000;

    /// Initial slow-start threshold
    const INITIAL_SSTHRESH: u32 = 10000;

    /// SENDME increment (how many cells per SENDME)
    const SENDME_INC: u32 = 31;

    /// Vegas alpha: if queue < alpha, increase window
    const VEGAS_ALPHA: u32 = 3;

    /// Vegas beta: if queue > beta, decrease window
    const VEGAS_BETA: u32 = 6;

    /// Vegas gamma: slow-start exit threshold
    const VEGAS_GAMMA: u32 = 3;

    /// Create a new congestion controller
    pub fn new() -> Self {
        Self::with_algorithm(CongestionAlgorithm::Vegas)
    }

    /// Create with specific algorithm
    pub fn with_algorithm(algorithm: CongestionAlgorithm) -> Self {
        Self {
            cwnd: Self::INITIAL_CWND,
            ssthresh: Self::INITIAL_SSTHRESH,
            rtt: RttEstimator::new(),
            algorithm,
            in_flight: 0,
            acked: 0,
            sendme_sent_at: None,
            in_slow_start: true,
            vegas_alpha: Self::VEGAS_ALPHA,
            vegas_beta: Self::VEGAS_BETA,
            vegas_gamma: Self::VEGAS_GAMMA,
        }
    }

    /// Get current congestion window
    pub fn cwnd(&self) -> u32 {
        self.cwnd
    }

    /// Check if we can send more cells
    pub fn can_send(&self) -> bool {
        self.in_flight < self.cwnd
    }

    /// Get available send window
    pub fn available_window(&self) -> u32 {
        self.cwnd.saturating_sub(self.in_flight)
    }

    /// Record that we sent a DATA cell
    pub fn on_send(&mut self) {
        self.in_flight += 1;
    }

    /// Record that we're sending a SENDME (start RTT timer)
    pub fn on_sendme_sent(&mut self) {
        self.sendme_sent_at = Some(Instant::now());
    }

    /// Process received SENDME (ACK) and update congestion window
    ///
    /// This is where the Vegas algorithm runs.
    pub fn on_sendme_received(&mut self) {
        // Decrease in-flight count
        self.in_flight = self.in_flight.saturating_sub(Self::SENDME_INC);
        self.acked += Self::SENDME_INC as u64;

        // Measure RTT if we have a timer
        if let Some(sent_at) = self.sendme_sent_at.take() {
            let rtt_ms = sent_at.elapsed().as_millis() as u32;
            self.rtt.add_sample(rtt_ms);

            // Run congestion control algorithm
            match self.algorithm {
                CongestionAlgorithm::Fixed => {
                    // No adjustment - legacy behavior
                }
                CongestionAlgorithm::Vegas => {
                    self.vegas_update();
                }
                CongestionAlgorithm::Nola => {
                    // NOLA not fully implemented; fall back to Vegas
                    self.vegas_update();
                }
            }
        }

        log::debug!(
            "SENDME received: cwnd={}, in_flight={}, acked={}",
            self.cwnd,
            self.in_flight,
            self.acked
        );
    }

    /// Tor-Vegas congestion window update
    fn vegas_update(&mut self) {
        // Need RTT samples to run Vegas
        if !self.rtt.has_enough_samples() {
            // In slow-start, increase aggressively
            if self.in_slow_start {
                self.cwnd = (self.cwnd + Self::SENDME_INC).min(Self::MAX_CWND);
            }
            return;
        }

        let srtt = match self.rtt.srtt() {
            Some(s) if s > 0 => s,
            _ => return,
        };

        let min_rtt = match self.rtt.min_rtt() {
            Some(m) if m > 0 => m,
            _ => return,
        };

        // Calculate expected throughput: cwnd / min_rtt
        // Calculate actual throughput: cwnd / srtt
        // Queue occupancy = expected - actual = cwnd × (srtt - min_rtt) / (srtt × min_rtt)
        // Simplified: diff = (srtt - min_rtt) / min_rtt × cwnd / srtt

        // Actually, Vegas uses: diff = (expected - actual) × base_rtt
        // Where expected = cwnd / base_rtt, actual = cwnd / rtt
        // diff = cwnd × (1/base_rtt - 1/rtt) × base_rtt
        //      = cwnd × (1 - base_rtt/rtt)
        //      = cwnd × (rtt - base_rtt) / rtt

        let queue_delay = srtt.saturating_sub(min_rtt);
        let diff = (self.cwnd as u64 * queue_delay as u64 / srtt as u64) as u32;

        log::trace!(
            "Vegas: srtt={}ms, min_rtt={}ms, diff={}, cwnd={}",
            srtt,
            min_rtt,
            diff,
            self.cwnd
        );

        // Slow-start exit condition
        if self.in_slow_start {
            if diff > self.vegas_gamma {
                // Exit slow-start
                self.in_slow_start = false;
                self.ssthresh = self.cwnd;
                log::debug!("Exiting slow-start at cwnd={}", self.cwnd);
            } else {
                // Continue slow-start: increase by SENDME_INC
                self.cwnd = (self.cwnd + Self::SENDME_INC).min(Self::MAX_CWND);
                return;
            }
        }

        // Congestion avoidance (Vegas proper)
        if diff < self.vegas_alpha {
            // Not enough packets in queue - increase window
            self.cwnd = (self.cwnd + 1).min(Self::MAX_CWND);
        } else if diff > self.vegas_beta {
            // Too many packets in queue - decrease window
            self.cwnd = self.cwnd.saturating_sub(1).max(Self::MIN_CWND);
        }
        // else: in equilibrium, keep window
    }

    /// Handle timeout (no SENDME received)
    pub fn on_timeout(&mut self) {
        // Multiplicative decrease
        self.ssthresh = self.cwnd / 2;
        self.cwnd = Self::MIN_CWND;
        self.in_slow_start = true;

        log::warn!("Congestion timeout: resetting to cwnd={}", self.cwnd);
    }

    /// Get current statistics
    pub fn stats(&self) -> CongestionStats {
        CongestionStats {
            cwnd: self.cwnd,
            in_flight: self.in_flight,
            acked: self.acked,
            in_slow_start: self.in_slow_start,
            ssthresh: self.ssthresh,
            algorithm: self.algorithm,
            rtt: self.rtt.stats(),
        }
    }

    /// Check if congestion control is enabled (non-Fixed algorithm)
    pub fn is_enabled(&self) -> bool {
        self.algorithm != CongestionAlgorithm::Fixed
    }
}

impl Default for CongestionController {
    fn default() -> Self {
        Self::new()
    }
}

/// Congestion control statistics
#[derive(Debug, Clone)]
pub struct CongestionStats {
    /// Current congestion window
    pub cwnd: u32,
    /// Cells currently in flight
    pub in_flight: u32,
    /// Total cells acknowledged
    pub acked: u64,
    /// Whether in slow-start phase
    pub in_slow_start: bool,
    /// Slow-start threshold
    pub ssthresh: u32,
    /// Algorithm in use
    pub algorithm: CongestionAlgorithm,
    /// RTT statistics
    pub rtt: RttStats,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_rtt_estimator() {
        let mut rtt = RttEstimator::new();

        // First sample
        rtt.add_sample(100);
        assert_eq!(rtt.srtt(), Some(100));
        assert_eq!(rtt.min_rtt(), Some(100));

        // More samples
        rtt.add_sample(80);
        rtt.add_sample(90);
        rtt.add_sample(85);

        assert!(rtt.has_enough_samples());
        assert_eq!(rtt.min_rtt(), Some(80));

        // SRTT should be smoothed
        let srtt = rtt.srtt().unwrap();
        assert!(srtt >= 80 && srtt <= 100);
    }

    #[test]
    fn test_congestion_controller_initial() {
        let cc = CongestionController::new();

        assert_eq!(cc.cwnd(), CongestionController::INITIAL_CWND);
        assert!(cc.can_send());
        assert!(cc.is_enabled());
    }

    #[test]
    fn test_congestion_controller_send() {
        let mut cc = CongestionController::new();

        // Send some cells
        for _ in 0..10 {
            cc.on_send();
        }

        assert_eq!(cc.in_flight, 10);
        assert!(cc.can_send()); // Still have window

        // Send up to cwnd
        for _ in 0..21 {
            cc.on_send();
        }

        assert_eq!(cc.in_flight, 31);
        assert!(!cc.can_send()); // Window full
    }

    #[test]
    fn test_congestion_controller_sendme() {
        let mut cc = CongestionController::new();

        // Simulate sending and receiving
        for _ in 0..31 {
            cc.on_send();
        }

        assert!(!cc.can_send());

        // Receive SENDME
        cc.on_sendme_received();

        assert!(cc.can_send());
        assert_eq!(cc.in_flight, 0); // Reset
    }

    #[test]
    fn test_vegas_slow_start() {
        let mut cc = CongestionController::new();
        assert!(cc.in_slow_start);

        // Add RTT samples (low queue delay)
        cc.rtt.add_sample(100);
        cc.rtt.add_sample(100);
        cc.rtt.add_sample(100);

        let initial_cwnd = cc.cwnd();

        // Receive SENDME - should increase in slow-start
        cc.on_sendme_sent();
        std::thread::sleep(Duration::from_millis(50));
        cc.on_sendme_received();

        assert!(cc.cwnd() >= initial_cwnd);
    }

    #[test]
    fn test_fixed_algorithm() {
        let mut cc = CongestionController::with_algorithm(CongestionAlgorithm::Fixed);
        assert!(!cc.is_enabled());

        let initial_cwnd = cc.cwnd();

        // Send and receive
        cc.on_send();
        cc.on_sendme_received();

        // Window shouldn't change with fixed algorithm
        assert_eq!(cc.cwnd(), initial_cwnd);
    }
}
