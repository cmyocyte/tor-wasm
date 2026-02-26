//! Cooperative Scheduling for WASM Tor
//!
//! This module provides a novel cooperative scheduling architecture for running
//! Tor operations in single-threaded WASM environments. The key innovation is
//! avoiding RefCell borrow-across-await issues through a checkout/return pattern.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    CooperativeCircuit                        │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
//! │  │ Stream 1    │  │ Stream 2    │  │ Stream 3    │         │
//! │  │ send_queue  │  │ send_queue  │  │ send_queue  │         │
//! │  │ recv_buf    │  │ recv_buf    │  │ recv_buf    │         │
//! │  └─────────────┘  └─────────────┘  └─────────────┘         │
//! │                                                              │
//! │  ┌─────────────────────────────────────────┐               │
//! │  │ Circuit (owned - can be checked out)    │               │
//! │  │  • send_relay_cell()                    │               │
//! │  │  • try_receive_relay_cell()             │               │
//! │  └─────────────────────────────────────────┘               │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## The Borrow Problem and Our Solution
//!
//! In WASM single-threaded environments, we can't use Mutex (no threads) but
//! need interior mutability for shared state. RefCell panics if you try to
//! borrow_mut() while already borrowed - and async code that holds a borrow
//! across an await point will cause this panic when other code tries to borrow.
//!
//! Our solution: The "checkout/return" pattern for the circuit:
//!
//! ```text
//! // WRONG - holds borrow across await!
//! {
//!     let mut scheduler = scheduler.borrow_mut();
//!     scheduler.tick().await;  // PANIC risk!
//! }
//!
//! // CORRECT - brief borrows only
//! let work = { scheduler.borrow_mut().tick_sync() };  // Brief borrow
//! // Borrow released!
//!
//! let circuit = { scheduler.borrow_mut().checkout_circuit() };  // Brief borrow
//! // Borrow released!
//!
//! let result = circuit.send_relay_cell(&cell).await;  // No borrow held!
//!
//! { scheduler.borrow_mut().return_circuit(circuit) };  // Brief borrow
//! ```

mod scheduler;
mod stream;
mod tls;

pub use scheduler::{
    // The critical functions that avoid borrow-across-await
    drive_scheduler,
    drive_until_complete,
    CooperativeCircuit,
    PendingWork,
    SchedulerDriver,
    SchedulerError,
    SchedulerStats,
    StreamHandle,
    WorkResult,
};
pub use stream::CooperativeStream;
pub use tls::CooperativeTlsStream;

// Configuration constants - exposed for documentation/testing
pub use scheduler::{
    DEFAULT_RECEIVE_TIMEOUT_MS, DEFAULT_SEND_TIMEOUT_MS, MAX_CELLS_PER_STREAM, MAX_INCOMING_BUFFER,
    MAX_STREAMS_PER_CIRCUIT, MAX_TOTAL_QUEUED_CELLS,
};

/// Helper function to open a stream using the cooperative pattern
///
/// This handles all the complexity of:
/// 1. Allocating stream ID
/// 2. Sending RELAY_BEGIN
/// 3. Waiting for RELAY_CONNECTED
/// 4. Returning a ready-to-use CooperativeStream
pub async fn open_cooperative_stream(
    scheduler: &std::rc::Rc<std::cell::RefCell<CooperativeCircuit>>,
    host: &str,
    port: u16,
) -> crate::error::Result<CooperativeStream> {
    use crate::error::TorError;
    use crate::protocol::{RelayCell, RelayCommand};

    // Check if we can open a stream (brief borrow)
    let stream_id = {
        let mut s = scheduler.borrow_mut();
        if !s.can_open_stream() {
            return Err(TorError::ResourceExhausted("Too many streams".into()));
        }
        let id = s.next_stream_id();
        s.register_stream(id, host, port);
        id
    };
    // Borrow released!

    log::info!("📡 Opening stream {} to {}:{}", stream_id, host, port);

    // Create RELAY_BEGIN cell
    let target = format!("{}:{}\0", host, port);
    let begin_cell = RelayCell::new(RelayCommand::Begin, stream_id, target.as_bytes().to_vec());

    // Queue the send (brief borrow)
    let send_rx = {
        let mut s = scheduler.borrow_mut();
        s.queue_send(stream_id, begin_cell, Some(DEFAULT_SEND_TIMEOUT_MS))
            .map_err(TorError::from)?
    };
    // Borrow released!

    // Drive until send completes
    let send_result = drive_until_complete(scheduler, send_rx).await?;
    send_result?;

    // Register to receive CONNECTED (brief borrow)
    let recv_rx = {
        let mut s = scheduler.borrow_mut();
        s.register_receive(stream_id, Some(DEFAULT_RECEIVE_TIMEOUT_MS))
            .map_err(TorError::from)?
    };
    // Borrow released!

    // Drive until receive completes
    let cell = drive_until_complete(scheduler, recv_rx).await??;

    match cell.command {
        RelayCommand::Connected => {
            log::info!("✅ Stream {} opened", stream_id);

            // Mark as open (brief borrow)
            {
                let mut s = scheduler.borrow_mut();
                s.mark_stream_open(stream_id);
            }

            Ok(CooperativeStream::new(
                StreamHandle { stream_id },
                std::rc::Rc::clone(scheduler),
            ))
        }
        RelayCommand::End => {
            // Clean up failed stream (brief borrow)
            {
                let mut s = scheduler.borrow_mut();
                s.remove_stream(stream_id);
            }

            let reason = cell.data.first().copied().unwrap_or(0);
            Err(TorError::Stream(format!(
                "Connection refused (reason: {})",
                reason
            )))
        }
        _ => {
            // Clean up failed stream (brief borrow)
            {
                let mut s = scheduler.borrow_mut();
                s.remove_stream(stream_id);
            }

            Err(TorError::ProtocolError(format!(
                "Unexpected response: {:?}",
                cell.command
            )))
        }
    }
}
