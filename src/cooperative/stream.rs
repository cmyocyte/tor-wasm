//! Cooperative Tor Stream
//!
//! A stream implementation that works with the cooperative scheduler.
//! All operations are timeout-bounded and backpressure-aware.
//!
//! ## Critical Pattern: No Borrow Across Await
//!
//! ```text
//! // Queue operation - brief borrow!
//! let rx = {
//!     let mut scheduler = self.scheduler.borrow_mut();
//!     scheduler.queue_send(stream_id, cell, timeout)
//! };
//! // Borrow released! Now drive scheduler without holding borrow
//! drive_until_complete(&self.scheduler, rx).await
//! ```

use super::scheduler::{drive_until_complete, CooperativeCircuit, StreamHandle};
use crate::error::{Result, TorError};
use crate::protocol::{RelayCell, RelayCommand};
use std::cell::RefCell;
use std::rc::Rc;

/// A Tor stream using the cooperative scheduler
pub struct CooperativeStream {
    /// Handle identifying this stream
    handle: StreamHandle,

    /// Reference to the scheduler
    /// (RefCell is safe - we never borrow across await!)
    scheduler: Rc<RefCell<CooperativeCircuit>>,

    /// Whether stream is closed
    closed: bool,

    /// Custom send timeout (None = use default)
    send_timeout_ms: Option<u32>,

    /// Custom receive timeout (None = use default)
    recv_timeout_ms: Option<u32>,
}

impl CooperativeStream {
    /// Create a new cooperative stream
    pub fn new(handle: StreamHandle, scheduler: Rc<RefCell<CooperativeCircuit>>) -> Self {
        log::debug!(
            "📡 CooperativeStream created for stream {}",
            handle.stream_id()
        );
        Self {
            handle,
            scheduler,
            closed: false,
            send_timeout_ms: None,
            recv_timeout_ms: None,
        }
    }

    /// Set custom send timeout
    pub fn with_send_timeout(mut self, timeout_ms: u32) -> Self {
        self.send_timeout_ms = Some(timeout_ms);
        self
    }

    /// Set custom receive timeout
    pub fn with_recv_timeout(mut self, timeout_ms: u32) -> Self {
        self.recv_timeout_ms = Some(timeout_ms);
        self
    }

    /// Get stream ID
    pub fn stream_id(&self) -> u16 {
        self.handle.stream_id()
    }

    /// Check if stream is closed
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Write data to the stream
    ///
    /// Returns error if:
    /// - Stream is closed
    /// - Send queue is full (backpressure)
    /// - Operation times out
    /// - Circuit dies
    pub async fn write_all(&mut self, data: &[u8]) -> Result<()> {
        if self.closed {
            return Err(TorError::Stream("Stream is closed".into()));
        }

        // Split data into cell-sized chunks (max 498 bytes per RELAY_DATA)
        const MAX_DATA_PER_CELL: usize = 498;

        log::trace!(
            "📤 Writing {} bytes to stream {} in {} chunks",
            data.len(),
            self.handle.stream_id(),
            data.len().div_ceil(MAX_DATA_PER_CELL)
        );

        for chunk in data.chunks(MAX_DATA_PER_CELL) {
            self.write_cell(chunk).await?;
        }

        Ok(())
    }

    /// Write a single cell's worth of data
    async fn write_cell(&mut self, data: &[u8]) -> Result<()> {
        let cell = RelayCell::new(RelayCommand::Data, self.handle.stream_id(), data.to_vec());

        // Queue the send - brief borrow!
        let rx = {
            let mut scheduler = self.scheduler.borrow_mut();
            scheduler
                .queue_send(self.handle.stream_id(), cell, self.send_timeout_ms)
                .map_err(TorError::from)?
        };
        // Borrow released!

        // Drive scheduler until complete - uses the external function
        // that handles borrow correctly
        drive_until_complete(&self.scheduler, rx).await??;

        Ok(())
    }

    /// Read data from the stream
    ///
    /// Returns:
    /// - Ok(n) with n > 0: Read n bytes
    /// - Ok(0): Stream closed (EOF)
    /// - Err: Timeout, circuit death, etc.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        // Loop to handle control cells (SENDME, etc.) without recursion
        loop {
            if self.closed {
                return Ok(0);
            }

            // Register to receive - brief borrow!
            let rx = {
                let mut scheduler = self.scheduler.borrow_mut();
                scheduler
                    .register_receive(self.handle.stream_id(), self.recv_timeout_ms)
                    .map_err(TorError::from)?
            };
            // Borrow released!

            // Drive scheduler until complete - uses the external function
            let cell = drive_until_complete(&self.scheduler, rx).await??;

            match cell.command {
                RelayCommand::Data => {
                    let len = cell.data.len().min(buf.len());
                    buf[..len].copy_from_slice(&cell.data[..len]);
                    log::trace!(
                        "📥 Read {} bytes from stream {}",
                        len,
                        self.handle.stream_id()
                    );
                    return Ok(len);
                }
                RelayCommand::End => {
                    log::info!("📥 Stream {} received END", self.handle.stream_id());
                    self.closed = true;
                    return Ok(0);
                }
                RelayCommand::Sendme => {
                    // Flow control - update window and continue loop
                    log::trace!("📥 Received SENDME for stream {}", self.handle.stream_id());
                    // Continue loop to get actual data
                    continue;
                }
                other => {
                    log::warn!(
                        "⚠️ Unexpected cell type on stream {}: {:?}",
                        self.handle.stream_id(),
                        other
                    );
                    // Continue loop to try again
                    continue;
                }
            }
        }
    }

    /// Read all available data until stream closes
    pub async fn read_to_end(&mut self) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        let mut buf = [0u8; 498];

        loop {
            match self.read(&mut buf).await {
                Ok(0) => break, // EOF
                Ok(n) => result.extend_from_slice(&buf[..n]),
                Err(e) => return Err(e),
            }
        }

        log::info!(
            "📥 Stream {} read {} total bytes",
            self.handle.stream_id(),
            result.len()
        );
        Ok(result)
    }

    /// Close the stream gracefully
    pub async fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }

        log::info!("🔒 Closing stream {}", self.handle.stream_id());

        // Send RELAY_END
        let end_cell = RelayCell::new(
            RelayCommand::End,
            self.handle.stream_id(),
            vec![6], // Reason: DONE
        );

        // Queue the send - brief borrow!
        let result = {
            let mut scheduler = self.scheduler.borrow_mut();
            scheduler.queue_send(self.handle.stream_id(), end_cell, Some(5000))
        };
        // Borrow released!

        if let Ok(rx) = result {
            // Best effort - don't fail if queue is full or times out
            let _ = drive_until_complete(&self.scheduler, rx).await;
        }

        // Remove stream from scheduler - brief borrow
        {
            let mut scheduler = self.scheduler.borrow_mut();
            scheduler.remove_stream(self.handle.stream_id());
        }

        self.closed = true;
        Ok(())
    }
}

impl Drop for CooperativeStream {
    fn drop(&mut self) {
        if !self.closed {
            // Try to close gracefully, but don't block
            // The scheduler will clean up eventually
            log::debug!(
                "⚠️ Stream {} dropped without close()",
                self.handle.stream_id()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_defaults() {
        // Basic structure test (full tests require WASM environment)
        let handle = StreamHandle { stream_id: 42 };
        assert_eq!(handle.stream_id(), 42);
    }
}
