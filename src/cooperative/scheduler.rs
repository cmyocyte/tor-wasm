//! Core Cooperative Circuit Scheduler
//!
//! Owns the circuit and processes operations from multiple streams
//! in a cooperative, non-blocking manner.
//!
//! ## Key Architecture: No Borrow Across Await
//!
//! The scheduler is designed to NEVER hold a borrow across an await point.
//! All async I/O is done with the circuit "checked out" of the scheduler:
//!
//! ```text
//! // Get work to do (brief borrow)
//! let work = { scheduler.borrow_mut().take_pending_work() };
//! // Borrow released!
//!
//! // Do async I/O (no borrow held)
//! let result = work.execute(&mut circuit).await;
//!
//! // Report result (brief borrow)
//! { scheduler.borrow_mut().complete_work(result) };
//! ```

use futures::channel::oneshot;
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;

use crate::error::{Result, TorError};
use crate::protocol::{Circuit, RelayCell};

// ============================================================================
// CONFIGURATION CONSTANTS
// ============================================================================

/// Maximum cells queued per stream (backpressure threshold)
pub const MAX_CELLS_PER_STREAM: usize = 50;

/// Maximum total cells across all streams
pub const MAX_TOTAL_QUEUED_CELLS: usize = 200;

/// Maximum streams per circuit
pub const MAX_STREAMS_PER_CIRCUIT: usize = 20;

/// Maximum buffered incoming cells (not yet claimed by a stream)
pub const MAX_INCOMING_BUFFER: usize = 100;

/// Default timeout for receive operations (milliseconds)
pub const DEFAULT_RECEIVE_TIMEOUT_MS: u32 = 30_000; // 30 seconds

/// Default timeout for send operations (milliseconds)
pub const DEFAULT_SEND_TIMEOUT_MS: u32 = 10_000; // 10 seconds

// ============================================================================
// QUEUED OPERATIONS
// ============================================================================

/// A cell operation queued for sending
struct QueuedSend {
    cell: RelayCell,
    /// Channel to notify when send completes
    completion: oneshot::Sender<Result<()>>,
    /// Deadline (js_sys::Date::now() timestamp)
    deadline: f64,
}

/// A pending receive operation
struct PendingReceive {
    /// Channel to deliver the received cell
    delivery: oneshot::Sender<Result<RelayCell>>,
    /// Deadline (js_sys::Date::now() timestamp)
    deadline: f64,
}

/// Metadata about an active stream
struct StreamInfo {
    stream_id: u16,
    host: String,
    port: u16,
    state: StreamState,
    send_window: u16,
    recv_window: u16,
    /// Per-stream send queue for fair scheduling
    send_queue: VecDeque<QueuedSend>,
    /// Cells received but not yet read by stream
    recv_buffer: VecDeque<RelayCell>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum StreamState {
    Opening,
    Open,
    HalfClosed, // We sent END, waiting for their END
    Closed,
}

/// Error returned when scheduler is at capacity
#[derive(Debug, Clone)]
pub enum SchedulerError {
    /// Send queue is full, apply backpressure
    SendQueueFull {
        stream_id: u16,
        queued: usize,
        max: usize,
    },
    /// Too many streams on this circuit
    TooManyStreams { count: usize, max: usize },
    /// Circuit is dead
    CircuitDead { reason: String },
    /// Operation timed out
    Timeout { operation: String },
    /// Stream not found
    StreamNotFound { stream_id: u16 },
    /// Circuit is checked out
    CircuitUnavailable,
}

impl std::fmt::Display for SchedulerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchedulerError::SendQueueFull {
                stream_id,
                queued,
                max,
            } => {
                write!(
                    f,
                    "Send queue full for stream {} ({}/{} cells)",
                    stream_id, queued, max
                )
            }
            SchedulerError::TooManyStreams { count, max } => {
                write!(f, "Too many streams ({}/{})", count, max)
            }
            SchedulerError::CircuitDead { reason } => {
                write!(f, "Circuit dead: {}", reason)
            }
            SchedulerError::Timeout { operation } => {
                write!(f, "Operation timed out: {}", operation)
            }
            SchedulerError::StreamNotFound { stream_id } => {
                write!(f, "Stream {} not found", stream_id)
            }
            SchedulerError::CircuitUnavailable => {
                write!(f, "Circuit is currently checked out")
            }
        }
    }
}

impl std::error::Error for SchedulerError {}

impl From<SchedulerError> for TorError {
    fn from(e: SchedulerError) -> Self {
        match e {
            SchedulerError::SendQueueFull { .. } => TorError::ResourceExhausted(format!("{}", e)),
            SchedulerError::TooManyStreams { .. } => TorError::ResourceExhausted(format!("{}", e)),
            SchedulerError::CircuitDead { reason } => TorError::CircuitClosed(reason),
            SchedulerError::Timeout { .. } => TorError::Timeout,
            SchedulerError::StreamNotFound { stream_id } => {
                TorError::Stream(format!("Stream {} not found", stream_id))
            }
            SchedulerError::CircuitUnavailable => {
                TorError::Internal("Circuit is checked out".into())
            }
        }
    }
}

// ============================================================================
// PENDING WORK - What needs to be done outside the borrow
// ============================================================================

/// Work that needs to be done with the circuit
#[derive(Debug)]
pub enum PendingWork {
    /// Send a cell
    Send {
        stream_id: u16,
        cell: RelayCell,
        completion: oneshot::Sender<Result<()>>,
    },
    /// Check for incoming cells
    Receive,
    /// Nothing to do
    Idle,
}

/// Result of completed work
pub enum WorkResult {
    /// Send completed
    SendComplete { stream_id: u16, result: Result<()> },
    /// Received a cell
    Received { cell: RelayCell },
    /// No cell available
    NoData,
    /// Receive error
    ReceiveError { error: TorError },
}

// ============================================================================
// COOPERATIVE CIRCUIT SCHEDULER
// ============================================================================

/// The cooperative circuit scheduler
///
/// Owns the circuit and processes operations from multiple streams
/// in a cooperative, non-blocking manner.
pub struct CooperativeCircuit {
    /// The underlying Tor circuit (OWNED, not shared)
    /// Option so we can take() during checkout or on death
    circuit: Option<Circuit>,

    /// Circuit ID for logging
    circuit_id: u32,

    /// Active streams on this circuit (includes per-stream queues)
    streams: HashMap<u16, StreamInfo>,

    /// Streams waiting for incoming cells (with timeouts)
    recv_waiters: HashMap<u16, PendingReceive>,

    /// Next stream ID to allocate
    next_stream_id: u16,

    /// Round-robin index for fair send scheduling
    round_robin_index: usize,

    /// Order of stream IDs for round-robin
    stream_order: Vec<u16>,

    /// Incoming cells for streams that haven't registered to receive yet
    orphan_buffer: VecDeque<(u16, RelayCell)>,

    /// Circuit death reason (if dead)
    death_reason: Option<String>,

    /// Total cells currently queued across all streams
    total_queued_cells: usize,
}

impl CooperativeCircuit {
    /// Create a new cooperative circuit scheduler
    pub fn new(circuit: Circuit) -> Self {
        let circuit_id = circuit.id;
        log::info!("🎛️ Creating CooperativeCircuit for circuit {}", circuit_id);

        Self {
            circuit: Some(circuit),
            circuit_id,
            streams: HashMap::new(),
            recv_waiters: HashMap::new(),
            next_stream_id: 1,
            round_robin_index: 0,
            stream_order: Vec::new(),
            orphan_buffer: VecDeque::new(),
            death_reason: None,
            total_queued_cells: 0,
        }
    }

    /// Get the circuit ID
    pub fn id(&self) -> u32 {
        self.circuit_id
    }

    /// Check if circuit is alive
    pub fn is_alive(&self) -> bool {
        self.circuit.is_some() && self.death_reason.is_none()
    }

    /// Allocate a new stream ID
    fn allocate_stream_id(&mut self) -> u16 {
        let id = self.next_stream_id;
        self.next_stream_id = self.next_stream_id.wrapping_add(1);
        if self.next_stream_id == 0 {
            self.next_stream_id = 1;
        }
        id
    }

    // ========================================================================
    // CHECKOUT/RETURN PATTERN - For async I/O outside RefCell borrow
    // ========================================================================

    /// Temporarily take the circuit out for async operations
    ///
    /// The circuit MUST be returned via `return_circuit()` when done.
    /// While checked out, no operations requiring the circuit will work.
    pub fn checkout_circuit(&mut self) -> Option<Circuit> {
        self.circuit.take()
    }

    /// Return the circuit after async operations
    pub fn return_circuit(&mut self, circuit: Circuit) {
        self.circuit = Some(circuit);
    }

    /// Check if circuit is currently available (not checked out)
    pub fn is_circuit_available(&self) -> bool {
        self.circuit.is_some()
    }

    // ========================================================================
    // QUEUE OPERATIONS (all synchronous - safe to call with borrow)
    // ========================================================================

    /// Queue a cell for sending (with backpressure)
    pub fn queue_send(
        &mut self,
        stream_id: u16,
        cell: RelayCell,
        timeout_ms: Option<u32>,
    ) -> std::result::Result<oneshot::Receiver<Result<()>>, SchedulerError> {
        // Check if circuit is dead
        if let Some(reason) = &self.death_reason {
            return Err(SchedulerError::CircuitDead {
                reason: reason.clone(),
            });
        }

        // Check total queue limit
        if self.total_queued_cells >= MAX_TOTAL_QUEUED_CELLS {
            return Err(SchedulerError::SendQueueFull {
                stream_id,
                queued: self.total_queued_cells,
                max: MAX_TOTAL_QUEUED_CELLS,
            });
        }

        // Get or create stream info
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(SchedulerError::StreamNotFound { stream_id })?;

        // Check per-stream queue limit
        if stream.send_queue.len() >= MAX_CELLS_PER_STREAM {
            return Err(SchedulerError::SendQueueFull {
                stream_id,
                queued: stream.send_queue.len(),
                max: MAX_CELLS_PER_STREAM,
            });
        }

        let (tx, rx) = oneshot::channel();
        let timeout = timeout_ms.unwrap_or(DEFAULT_SEND_TIMEOUT_MS);
        let deadline = js_sys::Date::now() + timeout as f64;

        stream.send_queue.push_back(QueuedSend {
            cell,
            completion: tx,
            deadline,
        });
        self.total_queued_cells += 1;

        log::trace!(
            "📤 Queued cell for stream {} (queue size: {})",
            stream_id,
            stream.send_queue.len()
        );

        Ok(rx)
    }

    /// Register to receive the next cell for a stream (with mandatory timeout)
    pub fn register_receive(
        &mut self,
        stream_id: u16,
        timeout_ms: Option<u32>,
    ) -> std::result::Result<oneshot::Receiver<Result<RelayCell>>, SchedulerError> {
        // Check if circuit is dead
        if let Some(reason) = &self.death_reason {
            return Err(SchedulerError::CircuitDead {
                reason: reason.clone(),
            });
        }

        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(SchedulerError::StreamNotFound { stream_id })?;

        let (tx, rx) = oneshot::channel();

        // Check if we have a buffered cell for this stream
        if let Some(cell) = stream.recv_buffer.pop_front() {
            log::trace!("📥 Returning buffered cell for stream {}", stream_id);
            let _ = tx.send(Ok(cell));
            return Ok(rx);
        }

        // Check orphan buffer
        if let Some(idx) = self
            .orphan_buffer
            .iter()
            .position(|(sid, _)| *sid == stream_id)
        {
            let (_, cell) = self.orphan_buffer.remove(idx).unwrap();
            log::trace!("📥 Returning orphan cell for stream {}", stream_id);
            let _ = tx.send(Ok(cell));
            return Ok(rx);
        }

        // Register to wait
        let timeout = timeout_ms.unwrap_or(DEFAULT_RECEIVE_TIMEOUT_MS);
        let deadline = js_sys::Date::now() + timeout as f64;

        self.recv_waiters.insert(
            stream_id,
            PendingReceive {
                delivery: tx,
                deadline,
            },
        );

        log::trace!(
            "📥 Registered receive waiter for stream {} (timeout: {}ms)",
            stream_id,
            timeout
        );

        Ok(rx)
    }

    // ========================================================================
    // TICK (SYNCHRONOUS) - Only manages state, no async I/O
    // ========================================================================

    /// Synchronous tick - expires timeouts and returns pending work
    ///
    /// This does NOT do any async I/O. It only:
    /// 1. Expires timed-out operations
    /// 2. Returns the next piece of work to do
    ///
    /// The caller is responsible for executing the work outside the borrow.
    pub fn tick_sync(&mut self) -> PendingWork {
        if !self.is_alive() {
            return PendingWork::Idle;
        }

        // Expire timed-out operations
        self.expire_timed_out_operations();

        // Get next send (round-robin)
        if let Some(work) = self.take_next_send() {
            return work;
        }

        // If anyone is waiting to receive, indicate we should check
        if !self.recv_waiters.is_empty() {
            return PendingWork::Receive;
        }

        PendingWork::Idle
    }

    /// Take the next cell to send (round-robin across streams)
    fn take_next_send(&mut self) -> Option<PendingWork> {
        if self.stream_order.is_empty() {
            return None;
        }

        // Try each stream in round-robin order
        let start_index = self.round_robin_index;
        loop {
            let stream_id = self.stream_order[self.round_robin_index];
            self.round_robin_index = (self.round_robin_index + 1) % self.stream_order.len();

            if let Some(stream) = self.streams.get_mut(&stream_id) {
                if let Some(queued) = stream.send_queue.pop_front() {
                    self.total_queued_cells = self.total_queued_cells.saturating_sub(1);

                    log::trace!("📤 Taking cell for stream {} (round-robin)", stream_id);

                    return Some(PendingWork::Send {
                        stream_id,
                        cell: queued.cell,
                        completion: queued.completion,
                    });
                }
            }

            // If we've checked all streams, no work to do
            if self.round_robin_index == start_index {
                break;
            }
        }

        None
    }

    /// Check if there's pending work
    pub fn has_pending_work(&self) -> bool {
        if !self.is_alive() {
            return false;
        }

        // Check if any stream has queued sends
        for stream in self.streams.values() {
            if !stream.send_queue.is_empty() {
                return true;
            }
        }

        // Check if any receives are waiting
        !self.recv_waiters.is_empty()
    }

    /// Expire timed-out send and receive operations
    fn expire_timed_out_operations(&mut self) {
        let now = js_sys::Date::now();

        // Expire send operations
        for stream in self.streams.values_mut() {
            let mut expired_count = 0;
            while let Some(front) = stream.send_queue.front() {
                if now > front.deadline {
                    let queued = stream.send_queue.pop_front().unwrap();
                    let _ = queued.completion.send(Err(TorError::Timeout));
                    expired_count += 1;
                    self.total_queued_cells = self.total_queued_cells.saturating_sub(1);
                } else {
                    break; // Queue is ordered by insertion time
                }
            }
            if expired_count > 0 {
                log::warn!(
                    "⏰ Expired {} send operations for stream {}",
                    expired_count,
                    stream.stream_id
                );
            }
        }

        // Expire receive operations
        let expired_receives: Vec<u16> = self
            .recv_waiters
            .iter()
            .filter(|(_, waiter)| now > waiter.deadline)
            .map(|(stream_id, _)| *stream_id)
            .collect();

        for stream_id in expired_receives {
            if let Some(waiter) = self.recv_waiters.remove(&stream_id) {
                log::warn!("⏰ Receive timeout for stream {}", stream_id);
                let _ = waiter.delivery.send(Err(TorError::Timeout));
            }
        }
    }

    // ========================================================================
    // WORK COMPLETION - Process results of async I/O
    // ========================================================================

    /// Deliver a received cell to the appropriate stream
    pub fn deliver_received(&mut self, cell: RelayCell) {
        let stream_id = cell.stream_id;
        log::trace!(
            "📥 Delivering cell for stream {}: {:?}",
            stream_id,
            cell.command
        );

        // Route to waiting stream
        if let Some(waiter) = self.recv_waiters.remove(&stream_id) {
            let _ = waiter.delivery.send(Ok(cell));
        }
        // Or buffer in stream's recv_buffer
        else if let Some(stream) = self.streams.get_mut(&stream_id) {
            if stream.recv_buffer.len() < MAX_CELLS_PER_STREAM {
                stream.recv_buffer.push_back(cell);
            } else {
                log::warn!("⚠️ Stream {} recv buffer full, dropping cell", stream_id);
            }
        }
        // Or buffer as orphan (stream might register soon)
        else {
            self.orphan_buffer.push_back((stream_id, cell));
            // Clean up orphan buffer if too large
            while self.orphan_buffer.len() > MAX_INCOMING_BUFFER {
                let (old_stream_id, _) = self.orphan_buffer.pop_front().unwrap();
                log::warn!(
                    "⚠️ Evicting orphan cell for stream {} (buffer full)",
                    old_stream_id
                );
            }
        }
    }

    /// Mark the circuit as dead and notify all waiters
    pub fn mark_circuit_dead(&mut self, reason: String) {
        log::error!("💀 Circuit {} dead: {}", self.circuit_id, reason);

        self.death_reason = Some(reason.clone());
        self.circuit = None; // Drop the circuit

        let error = TorError::CircuitClosed(reason);

        // Notify all receive waiters
        for (stream_id, waiter) in self.recv_waiters.drain() {
            log::debug!("  Notifying recv waiter for stream {}", stream_id);
            let _ = waiter.delivery.send(Err(error.clone()));
        }

        // Notify all send waiters
        for stream in self.streams.values_mut() {
            for queued in stream.send_queue.drain(..) {
                log::debug!("  Notifying send waiter for stream {}", stream.stream_id);
                let _ = queued.completion.send(Err(error.clone()));
            }
        }

        self.total_queued_cells = 0;
    }

    // ========================================================================
    // STREAM MANAGEMENT
    // ========================================================================

    /// Register a new stream (internal use during open_stream)
    pub fn register_stream(&mut self, stream_id: u16, host: &str, port: u16) {
        self.streams.insert(
            stream_id,
            StreamInfo {
                stream_id,
                host: host.to_string(),
                port,
                state: StreamState::Opening,
                send_window: 500,
                recv_window: 500,
                send_queue: VecDeque::new(),
                recv_buffer: VecDeque::new(),
            },
        );
        self.stream_order.push(stream_id);
    }

    /// Mark stream as open
    pub fn mark_stream_open(&mut self, stream_id: u16) {
        if let Some(info) = self.streams.get_mut(&stream_id) {
            info.state = StreamState::Open;
        }
    }

    /// Remove a stream
    pub fn remove_stream(&mut self, stream_id: u16) {
        self.streams.remove(&stream_id);
        self.stream_order.retain(|&id| id != stream_id);
    }

    /// Get next stream ID
    pub fn next_stream_id(&mut self) -> u16 {
        self.allocate_stream_id()
    }

    /// Check stream limit
    pub fn can_open_stream(&self) -> bool {
        self.is_alive() && self.streams.len() < MAX_STREAMS_PER_CIRCUIT
    }

    /// Get number of active streams
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Get number of pending sends across all streams
    pub fn pending_sends(&self) -> usize {
        self.total_queued_cells
    }

    /// Get scheduler statistics
    pub fn stats(&self) -> SchedulerStats {
        SchedulerStats {
            circuit_id: self.circuit_id,
            is_alive: self.is_alive(),
            stream_count: self.streams.len(),
            total_queued_sends: self.total_queued_cells,
            pending_receives: self.recv_waiters.len(),
            orphan_buffer_size: self.orphan_buffer.len(),
        }
    }
}

/// Scheduler statistics for monitoring
#[derive(Debug, Clone)]
pub struct SchedulerStats {
    pub circuit_id: u32,
    pub is_alive: bool,
    pub stream_count: usize,
    pub total_queued_sends: usize,
    pub pending_receives: usize,
    pub orphan_buffer_size: usize,
}

/// A handle to a stream on a cooperative circuit
///
/// This is a lightweight handle that doesn't hold any borrows.
/// All operations go through the scheduler.
#[derive(Debug, Clone)]
pub struct StreamHandle {
    pub stream_id: u16,
}

impl StreamHandle {
    pub fn stream_id(&self) -> u16 {
        self.stream_id
    }
}

// ============================================================================
// SCHEDULER DRIVER - Async operations outside RefCell borrow
// ============================================================================

/// Drive the scheduler's async operations without holding RefCell borrow
///
/// This is THE CRITICAL function that avoids borrow-across-await.
/// It alternates between brief borrows for sync work and async I/O.
pub async fn drive_scheduler(scheduler: &Rc<RefCell<CooperativeCircuit>>) -> Result<bool> {
    // Get work to do (brief borrow)
    let work = {
        let mut s = scheduler.borrow_mut();
        s.tick_sync()
    };
    // Borrow released!

    match work {
        PendingWork::Send {
            stream_id,
            cell,
            completion,
        } => {
            // Checkout circuit (brief borrow)
            let mut circuit = {
                let mut s = scheduler.borrow_mut();
                match s.checkout_circuit() {
                    Some(c) => c,
                    None => {
                        // Circuit already checked out or dead
                        let _ =
                            completion.send(Err(TorError::Internal("Circuit unavailable".into())));
                        return Ok(false);
                    }
                }
            };
            // Borrow released!

            // Do async send (NO borrow held!)
            let result = circuit.send_relay_cell(&cell).await;

            // Return circuit and signal completion (brief borrow)
            {
                let mut s = scheduler.borrow_mut();
                s.return_circuit(circuit);
            }
            // Borrow released!

            // Send completion outside borrow
            let _ = completion.send(result.clone());

            if let Err(e) = result {
                // Mark dead on error (brief borrow)
                let mut s = scheduler.borrow_mut();
                s.mark_circuit_dead(format!("Send error: {}", e));
            }

            Ok(true) // Did work
        }

        PendingWork::Receive => {
            // Checkout circuit (brief borrow)
            let mut circuit = {
                let mut s = scheduler.borrow_mut();
                match s.checkout_circuit() {
                    Some(c) => c,
                    None => return Ok(false),
                }
            };
            // Borrow released!

            // Try to receive (NO borrow held!)
            let result = circuit.try_receive_relay_cell().await;

            // Return circuit (brief borrow)
            {
                let mut s = scheduler.borrow_mut();
                s.return_circuit(circuit);
            }
            // Borrow released!

            // Process result
            match result {
                Ok(Some(cell)) => {
                    // Deliver cell (brief borrow)
                    let mut s = scheduler.borrow_mut();
                    s.deliver_received(cell);
                    Ok(true) // Did work
                }
                Ok(None) => Ok(false), // No data
                Err(e) => {
                    // Mark dead on error (brief borrow)
                    let mut s = scheduler.borrow_mut();
                    s.mark_circuit_dead(format!("Receive error: {}", e));
                    Err(e)
                }
            }
        }

        PendingWork::Idle => Ok(false),
    }
}

/// Drive the scheduler until a oneshot receiver completes
///
/// This is the CRITICAL pattern for streams to use:
/// 1. Queue operation (get receiver)
/// 2. Call this function to drive until complete
/// 3. Never hold borrow across await!
pub async fn drive_until_complete<T>(
    scheduler: &Rc<RefCell<CooperativeCircuit>>,
    mut rx: oneshot::Receiver<T>,
) -> std::result::Result<T, TorError> {
    loop {
        // Check if result is ready
        match rx.try_recv() {
            Ok(Some(value)) => return Ok(value),
            Ok(None) => {
                // Not ready - drive scheduler (handles borrow correctly)
                drive_scheduler(scheduler).await?;

                // Yield to allow other work
                gloo_timers::future::TimeoutFuture::new(0).await;
            }
            Err(_) => {
                // Channel closed (sender dropped)
                return Err(TorError::Internal("Operation channel closed".into()));
            }
        }
    }
}

/// Helper for the deprecated SchedulerDriver pattern
pub struct SchedulerDriver {
    scheduler: Rc<RefCell<CooperativeCircuit>>,
}

impl SchedulerDriver {
    pub fn new(scheduler: Rc<RefCell<CooperativeCircuit>>) -> Self {
        Self { scheduler }
    }

    pub async fn run_until_idle(&mut self) {
        loop {
            match drive_scheduler(&self.scheduler).await {
                Ok(true) => {
                    // Did work, continue
                    gloo_timers::future::TimeoutFuture::new(0).await;
                }
                Ok(false) => {
                    // No work, done
                    break;
                }
                Err(_) => {
                    // Error, stop
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheduler_error_display() {
        let err = SchedulerError::SendQueueFull {
            stream_id: 1,
            queued: 50,
            max: 50,
        };
        assert!(format!("{}", err).contains("full"));
    }

    #[test]
    fn test_stream_handle() {
        let handle = StreamHandle { stream_id: 42 };
        assert_eq!(handle.stream_id(), 42);
    }
}
