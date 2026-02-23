//! Rate limiting for abuse prevention
//!
//! Prevents:
//! - Circuit creation storms (probing attacks)
//! - Stream flooding (resource exhaustion)
//! - Bandwidth abuse

use std::collections::VecDeque;

/// Rate limiter configuration
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    /// Max circuits per minute
    pub circuits_per_minute: u32,
    /// Max streams per circuit
    pub streams_per_circuit: u32,
    /// Max bytes per second per stream
    pub bytes_per_second: u64,
    /// Window size in milliseconds for rate calculations
    pub window_ms: u64,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            circuits_per_minute: 10,
            streams_per_circuit: 50,
            bytes_per_second: 1_000_000, // 1 MB/s
            window_ms: 60_000,           // 1 minute window
        }
    }
}

/// Timestamp in milliseconds (WASM-compatible)
fn now_ms() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now() as u64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

/// Rate limiter state
#[derive(Debug)]
pub struct RateLimiter {
    config: RateLimiterConfig,
    /// Timestamps of recent circuit creations
    circuit_timestamps: VecDeque<u64>,
    /// Stream count per circuit (circuit_id -> count)
    stream_counts: std::collections::HashMap<u32, u32>,
    /// Bytes sent per stream in current window (stream_id -> (bytes, window_start))
    bandwidth_tracking: std::collections::HashMap<u16, (u64, u64)>,
}

impl RateLimiter {
    /// Create a new rate limiter with default config
    pub fn new() -> Self {
        Self::with_config(RateLimiterConfig::default())
    }

    /// Create a new rate limiter with custom config
    pub fn with_config(config: RateLimiterConfig) -> Self {
        Self {
            config,
            circuit_timestamps: VecDeque::new(),
            stream_counts: std::collections::HashMap::new(),
            bandwidth_tracking: std::collections::HashMap::new(),
        }
    }

    /// Check if a new circuit can be created
    pub fn can_create_circuit(&mut self) -> bool {
        self.cleanup_old_entries();
        
        let count = self.circuit_timestamps.len() as u32;
        if count >= self.config.circuits_per_minute {
            log::warn!(
                "🚫 Rate limit: {} circuits in last minute (max: {})",
                count,
                self.config.circuits_per_minute
            );
            return false;
        }
        true
    }

    /// Record a circuit creation
    pub fn record_circuit_created(&mut self, circuit_id: u32) {
        let now = now_ms();
        self.circuit_timestamps.push_back(now);
        self.stream_counts.insert(circuit_id, 0);
        log::debug!("📊 Rate limiter: recorded circuit {}", circuit_id);
    }

    /// Check if a new stream can be opened on the circuit
    pub fn can_open_stream(&self, circuit_id: u32) -> bool {
        let count = self.stream_counts.get(&circuit_id).copied().unwrap_or(0);
        if count >= self.config.streams_per_circuit {
            log::warn!(
                "🚫 Rate limit: {} streams on circuit {} (max: {})",
                count,
                circuit_id,
                self.config.streams_per_circuit
            );
            return false;
        }
        true
    }

    /// Record a stream opening
    pub fn record_stream_opened(&mut self, circuit_id: u32, stream_id: u16) {
        *self.stream_counts.entry(circuit_id).or_insert(0) += 1;
        self.bandwidth_tracking.insert(stream_id, (0, now_ms()));
        log::debug!(
            "📊 Rate limiter: recorded stream {} on circuit {}",
            stream_id,
            circuit_id
        );
    }

    /// Check if bandwidth limit allows sending data
    pub fn can_send_bytes(&mut self, stream_id: u16, bytes: u64) -> bool {
        let now = now_ms();
        
        let (current_bytes, window_start) = self
            .bandwidth_tracking
            .get(&stream_id)
            .copied()
            .unwrap_or((0, now));

        // Reset window if expired (1 second windows for bandwidth)
        let window_elapsed = now.saturating_sub(window_start);
        if window_elapsed >= 1000 {
            // New window
            return bytes <= self.config.bytes_per_second;
        }

        // Check if adding these bytes would exceed limit
        let projected = current_bytes + bytes;
        if projected > self.config.bytes_per_second {
            log::warn!(
                "🚫 Rate limit: {} bytes/s on stream {} (max: {})",
                projected,
                stream_id,
                self.config.bytes_per_second
            );
            return false;
        }
        true
    }

    /// Record bytes sent
    pub fn record_bytes_sent(&mut self, stream_id: u16, bytes: u64) {
        let now = now_ms();
        
        let entry = self.bandwidth_tracking.entry(stream_id).or_insert((0, now));
        
        // Reset window if expired
        if now.saturating_sub(entry.1) >= 1000 {
            *entry = (bytes, now);
        } else {
            entry.0 += bytes;
        }
    }

    /// Record a stream closed
    pub fn record_stream_closed(&mut self, circuit_id: u32, stream_id: u16) {
        if let Some(count) = self.stream_counts.get_mut(&circuit_id) {
            *count = count.saturating_sub(1);
        }
        self.bandwidth_tracking.remove(&stream_id);
    }

    /// Record a circuit closed
    pub fn record_circuit_closed(&mut self, circuit_id: u32) {
        self.stream_counts.remove(&circuit_id);
    }

    /// Clean up old entries outside the time window
    fn cleanup_old_entries(&mut self) {
        let now = now_ms();
        let cutoff = now.saturating_sub(self.config.window_ms);

        // Remove circuit timestamps older than window
        while let Some(&timestamp) = self.circuit_timestamps.front() {
            if timestamp < cutoff {
                self.circuit_timestamps.pop_front();
            } else {
                break;
            }
        }
    }

    /// Get current rate limiting stats
    pub fn get_stats(&self) -> RateLimiterStats {
        RateLimiterStats {
            circuits_in_window: self.circuit_timestamps.len() as u32,
            max_circuits_per_minute: self.config.circuits_per_minute,
            active_circuits: self.stream_counts.len() as u32,
            max_streams_per_circuit: self.config.streams_per_circuit,
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about rate limiting
#[derive(Debug, Clone)]
pub struct RateLimiterStats {
    pub circuits_in_window: u32,
    pub max_circuits_per_minute: u32,
    pub active_circuits: u32,
    pub max_streams_per_circuit: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_rate_limiting() {
        let mut limiter = RateLimiter::with_config(RateLimiterConfig {
            circuits_per_minute: 3,
            ..Default::default()
        });

        // Should allow first 3 circuits
        assert!(limiter.can_create_circuit());
        limiter.record_circuit_created(1);
        
        assert!(limiter.can_create_circuit());
        limiter.record_circuit_created(2);
        
        assert!(limiter.can_create_circuit());
        limiter.record_circuit_created(3);

        // 4th should be blocked
        assert!(!limiter.can_create_circuit());
    }

    #[test]
    fn test_stream_rate_limiting() {
        let mut limiter = RateLimiter::with_config(RateLimiterConfig {
            streams_per_circuit: 2,
            ..Default::default()
        });

        limiter.record_circuit_created(1);

        // Should allow first 2 streams
        assert!(limiter.can_open_stream(1));
        limiter.record_stream_opened(1, 1);
        
        assert!(limiter.can_open_stream(1));
        limiter.record_stream_opened(1, 2);

        // 3rd should be blocked
        assert!(!limiter.can_open_stream(1));
    }

    #[test]
    fn test_bandwidth_limiting() {
        let mut limiter = RateLimiter::with_config(RateLimiterConfig {
            bytes_per_second: 1000,
            ..Default::default()
        });

        limiter.record_circuit_created(1);
        limiter.record_stream_opened(1, 1);

        // Should allow up to 1000 bytes
        assert!(limiter.can_send_bytes(1, 500));
        limiter.record_bytes_sent(1, 500);

        assert!(limiter.can_send_bytes(1, 400));
        limiter.record_bytes_sent(1, 400);

        // Exceeding should be blocked
        assert!(!limiter.can_send_bytes(1, 200));
    }
}

