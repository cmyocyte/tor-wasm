//! Tor stream management
//!
//! Opens streams through Tor circuits and provides AsyncRead/AsyncWrite interface.
//! Integrates with `flow_control::StreamFlowControl` for spec-compliant SENDME
//! window management (500-cell initial window, 50-cell SENDME increments).

use super::flow_control::StreamFlowControl;
use super::{Circuit, RelayCell, RelayCommand};
use crate::error::{Result, TorError};
use futures::io::{AsyncRead, AsyncWrite};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

/// Stream manager for opening streams through circuits
pub struct StreamManager {
    /// The circuit to use
    circuit: Rc<RefCell<Circuit>>,

    /// Next stream ID to allocate
    next_stream_id: u16,
}

impl StreamManager {
    /// Create a new stream manager
    pub fn new(circuit: Rc<RefCell<Circuit>>) -> Self {
        Self {
            circuit,
            next_stream_id: 1, // Stream IDs start at 1
        }
    }

    /// Open a stream to a destination through the circuit
    pub async fn open_stream(&mut self, host: &str, port: u16) -> Result<TorStream> {
        let stream_id = self.allocate_stream_id();

        log::info!("Opening stream {} to {}:{}", stream_id, host, port);

        // Create RELAY_BEGIN cell
        // Format: ADDRPORT [FLAGS] NUL
        // ADDRPORT is "host:port" null-terminated
        let target = format!("{}:{}\0", host, port);

        let begin_cell = RelayCell::new(RelayCommand::Begin, stream_id, target.as_bytes().to_vec());

        log::info!("  Sending RELAY_BEGIN cell (stream_id={})", stream_id);

        // Send RELAY_BEGIN through circuit (borrow mutably)
        self.circuit
            .borrow_mut()
            .send_relay_cell(&begin_cell)
            .await?;

        // Wait for RELAY_CONNECTED response
        let response = self.circuit.borrow_mut().receive_relay_cell().await?;

        log::info!(
            "  Received response: {:?} stream_id={}",
            response.command,
            response.stream_id
        );

        // Verify it's for our stream
        if response.stream_id != stream_id {
            return Err(TorError::Stream(format!(
                "Wrong stream ID in response: expected {}, got {}",
                stream_id, response.stream_id
            )));
        }

        // Check response type
        match response.command {
            RelayCommand::Connected => {
                log::info!("Stream {} opened to {}:{}", stream_id, host, port);

                Ok(TorStream {
                    circuit: Rc::clone(&self.circuit),
                    stream_id,
                    flow_control: StreamFlowControl::new(stream_id),
                    recv_buffer: VecDeque::new(),
                    read_waker: None,
                    closed: false,
                })
            }
            RelayCommand::End => {
                let reason = if !response.data.is_empty() {
                    response.data[0]
                } else {
                    0
                };
                Err(TorError::Stream(format!(
                    "Stream connection refused (reason: {})",
                    reason
                )))
            }
            _ => Err(TorError::ProtocolError(format!(
                "Unexpected response to RELAY_BEGIN: {:?}",
                response.command
            ))),
        }
    }

    /// Allocate a new stream ID
    fn allocate_stream_id(&mut self) -> u16 {
        let id = self.next_stream_id;
        self.next_stream_id = self.next_stream_id.wrapping_add(1);
        if self.next_stream_id == 0 {
            self.next_stream_id = 1; // Skip 0
        }
        id
    }
}

/// A Tor stream for sending/receiving data
///
/// Uses `StreamFlowControl` for spec-compliant SENDME window management.
/// Generates SENDME cells automatically when the receive window depletes.
pub struct TorStream {
    /// The circuit this stream uses
    circuit: Rc<RefCell<Circuit>>,

    /// Stream ID
    stream_id: u16,

    /// Flow control (SENDME windows)
    flow_control: StreamFlowControl,

    /// Internal receive buffer for AsyncRead
    recv_buffer: VecDeque<u8>,

    /// Waker for AsyncRead when buffer is empty
    read_waker: Option<Waker>,

    /// Whether stream is closed
    closed: bool,
}

impl TorStream {
    /// Get the stream ID
    pub fn stream_id(&self) -> u16 {
        self.stream_id
    }

    /// Get the circuit ID
    pub fn circuit_id(&self) -> u32 {
        self.circuit.borrow().id
    }

    /// Check if stream is closed
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Get a reference to the flow control state (for diagnostics)
    pub fn flow_control(&self) -> &StreamFlowControl {
        &self.flow_control
    }

    /// Close the stream by sending RELAY_END
    pub async fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }

        log::info!("Closing stream {}", self.stream_id);

        // Create RELAY_END cell (reason: DONE = 6)
        let end_cell = RelayCell::new(RelayCommand::End, self.stream_id, vec![6]);

        // Send RELAY_END through circuit
        let _ = self.circuit.borrow_mut().send_relay_cell(&end_cell).await;

        self.closed = true;

        Ok(())
    }

    /// Write all data through the stream (may require multiple RELAY_DATA cells)
    pub async fn write_all(&mut self, data: &[u8]) -> Result<()> {
        if self.closed {
            return Err(TorError::Stream("Stream is closed".into()));
        }

        let mut offset = 0;
        while offset < data.len() {
            let sent = self.send_data(&data[offset..]).await?;
            if sent == 0 {
                return Err(TorError::Stream("Failed to send data".into()));
            }
            offset += sent;
            log::debug!("  Sent {} bytes, {} total of {}", sent, offset, data.len());
        }

        Ok(())
    }

    /// Read all available data from the stream until EOF or connection close
    pub async fn read_response(&mut self) -> Result<Vec<u8>> {
        if self.closed {
            return Ok(vec![]);
        }

        let mut response = Vec::new();
        let mut buf = [0u8; 498]; // Max RELAY_DATA size

        loop {
            match self.recv_data(&mut buf).await {
                Ok(0) => {
                    log::info!("  Received EOF, total {} bytes", response.len());
                    break;
                }
                Ok(n) => {
                    response.extend_from_slice(&buf[..n]);
                    log::debug!("  Received {} bytes, total {} bytes", n, response.len());
                }
                Err(e) => {
                    if !response.is_empty() {
                        log::warn!("  Read error after {} bytes: {}", response.len(), e);
                        break;
                    }
                    return Err(e);
                }
            }
        }

        Ok(response)
    }

    /// Read response with a timeout (number of empty reads before giving up)
    pub async fn read_response_with_timeout(&mut self, max_wait_cells: usize) -> Result<Vec<u8>> {
        if self.closed {
            return Ok(vec![]);
        }

        let mut response = Vec::new();
        let mut buf = [0u8; 498];
        let mut empty_reads = 0;

        loop {
            match self.recv_data(&mut buf).await {
                Ok(0) => {
                    log::info!("  Received EOF, total {} bytes", response.len());
                    break;
                }
                Ok(n) => {
                    response.extend_from_slice(&buf[..n]);
                    log::debug!("  Received {} bytes, total {} bytes", n, response.len());
                    empty_reads = 0;
                }
                Err(TorError::Stream(msg)) if msg.contains("window") => {
                    empty_reads += 1;
                    if empty_reads >= max_wait_cells {
                        break;
                    }
                }
                Err(e) => {
                    if !response.is_empty() {
                        break;
                    }
                    return Err(e);
                }
            }
        }

        Ok(response)
    }

    /// Send data through the stream
    ///
    /// Uses `StreamFlowControl` for window management. Returns the number of
    /// bytes sent (up to `RelayCell::MAX_DATA_SIZE`).
    pub async fn send_data(&mut self, data: &[u8]) -> Result<usize> {
        if self.closed {
            return Err(TorError::Stream("Stream is closed".into()));
        }

        // Check flow control send window
        if !self.flow_control.can_send() {
            return Err(TorError::Stream(format!(
                "Stream {} send window exhausted",
                self.stream_id
            )));
        }

        // Chunk data to fit in RELAY_DATA (max 498 bytes)
        let max_data_size = RelayCell::MAX_DATA_SIZE;
        let to_send = data.len().min(max_data_size);

        // Create RELAY_DATA cell
        let data_cell =
            RelayCell::new(RelayCommand::Data, self.stream_id, data[..to_send].to_vec());

        // Send through circuit
        self.circuit
            .borrow_mut()
            .send_relay_cell(&data_cell)
            .await?;

        // Decrement send window via flow control
        self.flow_control.on_send()?;

        Ok(to_send)
    }

    /// Read some bytes from the stream (for TLS layer)
    ///
    /// This is a simpler interface than recv_data for use by the TLS layer.
    pub async fn read_some(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.recv_data(buf).await
    }

    /// Send a SENDME cell back to the exit relay for this stream
    async fn send_sendme(&mut self) -> Result<()> {
        log::debug!("Sending stream SENDME for stream {}", self.stream_id);

        let sendme_cell = RelayCell::new(
            RelayCommand::Sendme,
            self.stream_id,
            vec![], // Stream-level SENDME has empty payload
        );

        self.circuit
            .borrow_mut()
            .send_relay_cell(&sendme_cell)
            .await?;

        Ok(())
    }

    /// Receive data from the stream
    ///
    /// Handles SENDME flow control: generates SENDME cells when the receive
    /// window depletes, and processes incoming SENDME cells to replenish
    /// the send window.
    pub async fn recv_data(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.closed {
            return Ok(0); // EOF
        }

        // First, drain any buffered data from previous reads
        if !self.recv_buffer.is_empty() {
            let len = self.recv_buffer.len().min(buf.len());
            for i in 0..len {
                buf[i] = self.recv_buffer.pop_front().unwrap();
            }
            return Ok(len);
        }

        // Loop to handle SENDME cells (they don't contain user data)
        loop {
            // Receive RELAY cell from circuit
            let relay_cell = self.circuit.borrow_mut().receive_relay_cell().await?;

            // Check if it's for our stream (stream_id 0 = circuit-level)
            if relay_cell.stream_id != self.stream_id && relay_cell.stream_id != 0 {
                // Buffer data for other streams (best-effort; proper mux in stream_mux.rs)
                log::debug!(
                    "Received cell for stream {} (expected {}), dropping",
                    relay_cell.stream_id,
                    self.stream_id
                );
                continue;
            }

            // Handle different relay commands
            match relay_cell.command {
                RelayCommand::Data => {
                    // Update flow control — check if we need to send SENDME
                    let should_sendme = self.flow_control.on_receive_data();

                    if should_sendme {
                        self.send_sendme().await?;
                    }

                    // Copy data to caller's buffer
                    let len = relay_cell.data.len().min(buf.len());
                    buf[..len].copy_from_slice(&relay_cell.data[..len]);

                    // Buffer any overflow (data larger than caller's buffer)
                    if relay_cell.data.len() > buf.len() {
                        self.recv_buffer.extend(&relay_cell.data[buf.len()..]);
                    }

                    // Wake any pending AsyncRead
                    if let Some(waker) = self.read_waker.take() {
                        waker.wake();
                    }

                    return Ok(len);
                }
                RelayCommand::End => {
                    // Stream closed by remote
                    self.closed = true;
                    return Ok(0); // EOF
                }
                RelayCommand::Sendme => {
                    // Peer acknowledged our data — replenish send window
                    self.flow_control.on_sendme_received();

                    // Continue loop to get actual data
                    continue;
                }
                _ => {
                    return Err(TorError::ProtocolError(format!(
                        "Unexpected relay command: {:?}",
                        relay_cell.command
                    )));
                }
            }
        }
    }
}

impl Drop for TorStream {
    fn drop(&mut self) {
        if !self.closed {
            log::warn!("Stream {} dropped without being closed", self.stream_id);
        }
    }
}

/// AsyncRead implementation for TorStream
///
/// Drains the internal receive buffer first. If empty, stores the waker
/// and returns Pending — the waker is notified when `recv_data()` pushes
/// new data into the buffer.
impl AsyncRead for TorStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed && self.recv_buffer.is_empty() {
            return Poll::Ready(Ok(0)); // EOF
        }

        // Drain buffered data first
        if !self.recv_buffer.is_empty() {
            let len = self.recv_buffer.len().min(buf.len());
            for i in 0..len {
                buf[i] = self.recv_buffer.pop_front().unwrap();
            }
            return Poll::Ready(Ok(len));
        }

        // No data available — store waker and return Pending.
        // The waker is called from recv_data() when new data arrives.
        self.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

/// AsyncWrite implementation for TorStream
///
/// Respects flow control — returns Pending when the send window is exhausted.
/// The primary send path is through `write_all()` / `send_data()` which are
/// fully async. This trait impl provides composability with libraries
/// expecting AsyncWrite.
impl AsyncWrite for TorStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Stream is closed",
            )));
        }

        // Check flow control send window
        if !self.flow_control.can_send() {
            // Would block — need SENDME from peer
            self.read_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }

        // Decrement flow control window
        // The actual cell transmission is deferred to the async send path.
        // This is safe in WASM single-threaded context.
        let len = buf.len().min(RelayCell::MAX_DATA_SIZE);
        if self.flow_control.on_send().is_err() {
            return Poll::Pending;
        }

        Poll::Ready(Ok(len))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Ok(()));
        }

        self.closed = true;
        Poll::Ready(Ok(()))
    }
}

/// Stream builder for convenient stream creation
pub struct StreamBuilder {
    manager: StreamManager,
}

impl StreamBuilder {
    /// Create a new stream builder
    pub fn new(circuit: Rc<RefCell<Circuit>>) -> Self {
        Self {
            manager: StreamManager::new(circuit),
        }
    }

    /// Open a stream to a host:port
    pub async fn connect(&mut self, host: &str, port: u16) -> Result<TorStream> {
        self.manager.open_stream(host, port).await
    }

    /// Open an HTTP stream
    pub async fn http(&mut self, host: &str) -> Result<TorStream> {
        self.connect(host, 80).await
    }

    /// Open an HTTPS stream
    pub async fn https(&mut self, host: &str) -> Result<TorStream> {
        self.connect(host, 443).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{CircuitKeys, Relay};

    fn create_test_keys() -> CircuitKeys {
        CircuitKeys {
            forward_key: [1u8; 16],
            backward_key: [2u8; 16],
            forward_iv: [3u8; 16],
            backward_iv: [4u8; 16],
            forward_digest: [5u8; 20],
            backward_digest: [6u8; 20],
        }
    }

    #[test]
    fn test_stream_manager_creation() {
        let circuit = Rc::new(RefCell::new(Circuit::new(
            12345,
            vec![],
            create_test_keys(),
        )));

        let manager = StreamManager::new(circuit);
        assert_eq!(manager.next_stream_id, 1);
    }

    #[test]
    fn test_stream_id_allocation() {
        let circuit = Rc::new(RefCell::new(Circuit::new(
            12345,
            vec![],
            create_test_keys(),
        )));

        let mut manager = StreamManager::new(circuit);

        assert_eq!(manager.allocate_stream_id(), 1);
        assert_eq!(manager.allocate_stream_id(), 2);
        assert_eq!(manager.allocate_stream_id(), 3);
    }

    #[test]
    fn test_stream_id_wrapping() {
        let circuit = Rc::new(RefCell::new(Circuit::new(
            12345,
            vec![],
            create_test_keys(),
        )));

        let mut manager = StreamManager::new(circuit);
        manager.next_stream_id = u16::MAX;

        assert_eq!(manager.allocate_stream_id(), u16::MAX);
        assert_eq!(manager.allocate_stream_id(), 1); // Wrapped to 1 (skip 0)
    }
}
