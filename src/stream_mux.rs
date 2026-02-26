//! Stream Multiplexing
//!
//! Allows multiple streams on a single circuit for improved efficiency.
//!
//! Security considerations:
//! - Isolate stream failures (one bad stream shouldn't kill circuit)
//! - Enforce stream limits per circuit (rate limiting)
//! - Track stream lifecycle for cleanup

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use crate::error::{Result, TorError};
use crate::protocol::Circuit;

/// Configuration for stream multiplexer
#[derive(Debug, Clone)]
pub struct StreamMuxConfig {
    /// Maximum streams per circuit
    pub max_streams: u16,
    /// Enable stream isolation (failures don't affect other streams)
    pub isolate_failures: bool,
}

impl Default for StreamMuxConfig {
    fn default() -> Self {
        Self {
            max_streams: 50,
            isolate_failures: true,
        }
    }
}

/// Manages multiple streams on a single circuit
pub struct StreamMultiplexer {
    /// The underlying circuit
    circuit: Rc<RefCell<Circuit>>,
    /// Active streams by stream ID
    streams: HashMap<u16, StreamState>,
    /// Next stream ID to assign
    next_stream_id: u16,
    /// Configuration
    config: StreamMuxConfig,
    /// Statistics
    stats: StreamMuxStats,
}

/// State of a single stream
struct StreamState {
    /// Stream ID
    stream_id: u16,
    /// Target host:port
    target: String,
    /// Is stream still open?
    is_open: bool,
    /// Bytes sent on this stream
    bytes_sent: u64,
    /// Bytes received on this stream
    bytes_received: u64,
}

/// Statistics about stream multiplexing
#[derive(Debug, Clone, Default)]
pub struct StreamMuxStats {
    /// Total streams opened
    pub streams_opened: u64,
    /// Total streams closed
    pub streams_closed: u64,
    /// Current active streams
    pub active_streams: usize,
    /// Total bytes sent across all streams
    pub total_bytes_sent: u64,
    /// Total bytes received across all streams
    pub total_bytes_received: u64,
    /// Stream failures
    pub stream_failures: u64,
}

impl StreamMultiplexer {
    /// Create a new stream multiplexer for a circuit
    pub fn new(circuit: Rc<RefCell<Circuit>>) -> Self {
        Self::with_config(circuit, StreamMuxConfig::default())
    }

    /// Create with custom config
    pub fn with_config(circuit: Rc<RefCell<Circuit>>, config: StreamMuxConfig) -> Self {
        Self {
            circuit,
            streams: HashMap::new(),
            next_stream_id: 1, // Stream IDs start at 1
            config,
            stats: StreamMuxStats::default(),
        }
    }

    /// Open a new stream to host:port
    pub async fn open_stream(&mut self, host: &str, port: u16) -> Result<u16> {
        // Check limits
        if self.streams.len() >= self.config.max_streams as usize {
            return Err(TorError::ResourceExhausted(format!(
                "Too many streams (max {})",
                self.config.max_streams
            )));
        }

        // Get next stream ID
        let stream_id = self.allocate_stream_id()?;
        let target = format!("{}:{}", host, port);

        log::info!("📡 Opening stream {} to {}", stream_id, target);

        // Open stream on circuit
        // Note: In the actual implementation, this would call the circuit's open_stream method
        // For now, we just track the state

        // Record the stream
        self.streams.insert(
            stream_id,
            StreamState {
                stream_id,
                target: target.clone(),
                is_open: true,
                bytes_sent: 0,
                bytes_received: 0,
            },
        );

        self.stats.streams_opened += 1;
        self.stats.active_streams = self.streams.len();

        log::info!("✅ Stream {} opened to {}", stream_id, target);

        Ok(stream_id)
    }

    /// Close a stream
    pub async fn close_stream(&mut self, stream_id: u16) -> Result<()> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or_else(|| TorError::InvalidState(format!("Unknown stream {}", stream_id)))?;

        if !stream.is_open {
            return Ok(()); // Already closed
        }

        log::info!("🔌 Closing stream {} to {}", stream_id, stream.target);

        // Mark as closed
        stream.is_open = false;
        self.stats.streams_closed += 1;

        // Remove from active streams
        self.streams.remove(&stream_id);
        self.stats.active_streams = self.streams.len();

        Ok(())
    }

    /// Send data on a stream
    pub async fn send(&mut self, stream_id: u16, data: &[u8]) -> Result<()> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or_else(|| TorError::InvalidState(format!("Unknown stream {}", stream_id)))?;

        if !stream.is_open {
            return Err(TorError::InvalidState("Stream is closed".into()));
        }

        // In actual implementation, this would send through the circuit
        // For now, just track bytes
        stream.bytes_sent += data.len() as u64;
        self.stats.total_bytes_sent += data.len() as u64;

        Ok(())
    }

    /// Record received data on a stream
    pub fn record_received(&mut self, stream_id: u16, bytes: usize) {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.bytes_received += bytes as u64;
            self.stats.total_bytes_received += bytes as u64;
        }
    }

    /// Route incoming data to the correct stream
    pub fn route_data(&mut self, stream_id: u16, data: &[u8]) -> Result<()> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or_else(|| TorError::InvalidState(format!("Unknown stream {}", stream_id)))?;

        if !stream.is_open {
            if self.config.isolate_failures {
                log::warn!("Data for closed stream {}, ignoring", stream_id);
                return Ok(());
            } else {
                return Err(TorError::InvalidState("Stream is closed".into()));
            }
        }

        stream.bytes_received += data.len() as u64;
        self.stats.total_bytes_received += data.len() as u64;

        Ok(())
    }

    /// Handle a stream failure
    pub fn handle_stream_failure(&mut self, stream_id: u16, error: &str) {
        log::warn!("Stream {} failed: {}", stream_id, error);

        self.stats.stream_failures += 1;

        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.is_open = false;
        }

        if self.config.isolate_failures {
            // Just mark this stream as failed, don't affect others
            self.streams.remove(&stream_id);
            self.stats.active_streams = self.streams.len();
        } else {
            // Kill all streams on circuit failure
            self.close_all();
        }
    }

    /// Close all streams
    pub fn close_all(&mut self) {
        let count = self.streams.len();
        self.streams.clear();
        self.stats.streams_closed += count as u64;
        self.stats.active_streams = 0;
        log::info!("Closed all {} streams", count);
    }

    /// Get statistics
    pub fn get_stats(&self) -> StreamMuxStats {
        StreamMuxStats {
            active_streams: self.streams.len(),
            ..self.stats.clone()
        }
    }

    /// Get number of active streams
    pub fn active_count(&self) -> usize {
        self.streams.len()
    }

    /// Check if a stream is open
    pub fn is_stream_open(&self, stream_id: u16) -> bool {
        self.streams
            .get(&stream_id)
            .map(|s| s.is_open)
            .unwrap_or(false)
    }

    /// Get the underlying circuit
    pub fn circuit(&self) -> Rc<RefCell<Circuit>> {
        Rc::clone(&self.circuit)
    }

    /// Allocate the next stream ID
    fn allocate_stream_id(&mut self) -> Result<u16> {
        // Find next available ID
        let start = self.next_stream_id;
        loop {
            let id = self.next_stream_id;
            self.next_stream_id = self.next_stream_id.wrapping_add(1);
            if self.next_stream_id == 0 {
                self.next_stream_id = 1; // Skip 0
            }

            if !self.streams.contains_key(&id) {
                return Ok(id);
            }

            // If we've wrapped around completely, we're out of IDs
            if self.next_stream_id == start {
                return Err(TorError::ResourceExhausted(
                    "No stream IDs available".into(),
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_mux_config_defaults() {
        let config = StreamMuxConfig::default();
        assert_eq!(config.max_streams, 50);
        assert!(config.isolate_failures);
    }
}
