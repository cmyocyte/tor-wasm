//! WebSocket-based TCP stream for WASM
//!
//! This implements AsyncRead and AsyncWrite over WebSocket connections,
//! allowing WASM code to communicate with Tor relays through a bridge server.

use futures::io::{AsyncRead, AsyncWrite};
use std::collections::VecDeque;
use std::io::{self, Result as IoResult};
use std::pin::Pin;
use std::rc::Rc;
use std::cell::UnsafeCell;
use std::task::{Context, Poll, Waker};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{BinaryType, ErrorEvent, MessageEvent, WebSocket};

/// State of the WebSocket connection
#[derive(Debug, Clone, Copy, PartialEq)]
enum ConnectionState {
    Connecting,
    Connected,
    Closing,
    Closed,
}

/// Inner state for the WebSocket stream
struct StreamState {
    /// Current connection state
    state: ConnectionState,

    /// Buffer for received data
    recv_buffer: VecDeque<u8>,

    /// Buffer for data to send
    send_buffer: VecDeque<u8>,

    /// Waker for read operations
    read_waker: Option<Waker>,

    /// Waker for write operations
    write_waker: Option<Waker>,

    /// Last error encountered
    error: Option<String>,

    /// Traffic shaping profile for DPI resistance.
    /// When set to a non-None profile, outgoing data is fragmented into
    /// profile-matching frame sizes instead of the default 514-byte Tor cells.
    traffic_profile: crate::traffic_shaping::TrafficProfile,

    /// RNG state for traffic shaping (deterministic xorshift64)
    shaping_rng: u64,

    /// Pending shaped frames waiting to be sent with timing delays.
    /// The first frame is sent immediately; subsequent frames are queued
    /// here and sent via setTimeout callbacks to match the profile's
    /// inter-frame timing distribution.
    pending_shaped_frames: VecDeque<Vec<u8>>,
}

impl StreamState {
    fn new() -> Self {
        // Seed RNG from current time
        let seed = web_time::SystemTime::now()
            .duration_since(web_time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(42);

        Self {
            state: ConnectionState::Connecting,
            recv_buffer: VecDeque::new(),
            send_buffer: VecDeque::new(),
            read_waker: None,
            write_waker: None,
            error: None,
            traffic_profile: crate::traffic_shaping::TrafficProfile::None,
            shaping_rng: seed,
            pending_shaped_frames: VecDeque::new(),
        }
    }
}

/// WebSocket-based TCP stream for WASM
///
/// This wraps a WebSocket connection and provides AsyncRead/AsyncWrite traits,
/// allowing it to be used as a stream by Arti.
pub struct WasmTcpStream {
    /// The underlying WebSocket
    ws: WebSocket,
    
    /// Shared state between callbacks and stream methods (UnsafeCell is safe in single-threaded WASM)
    state: Rc<UnsafeCell<StreamState>>,
}

/// Reconnection configuration
const MAX_RECONNECT_ATTEMPTS: u32 = 5;
const RECONNECT_BACKOFF_MS: [u32; 5] = [1_000, 2_000, 4_000, 8_000, 16_000];

impl WasmTcpStream {
    /// Connect to a Tor relay through the WebSocket bridge with retry logic.
    ///
    /// Retries up to 5 times with exponential backoff: 1s, 2s, 4s, 8s, 16s.
    pub async fn connect_with_retry(url: &str) -> IoResult<Self> {
        let mut last_err = None;
        for attempt in 0..MAX_RECONNECT_ATTEMPTS {
            match Self::connect(url).await {
                Ok(stream) => {
                    if attempt > 0 {
                        log::info!("WebSocket reconnected on attempt {}", attempt + 1);
                    }
                    return Ok(stream);
                }
                Err(e) => {
                    log::warn!("WebSocket connect attempt {} failed: {}", attempt + 1, e);
                    last_err = Some(e);

                    if attempt + 1 < MAX_RECONNECT_ATTEMPTS {
                        let delay = RECONNECT_BACKOFF_MS[attempt as usize];
                        log::info!("Retrying in {}ms...", delay);
                        gloo_timers::future::TimeoutFuture::new(delay).await;
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::TimedOut, "All reconnection attempts failed")
        }))
    }

    /// Connect to a Tor relay through the WebSocket bridge
    pub async fn connect(url: &str) -> IoResult<Self> {
        log::info!("Connecting to WebSocket bridge: {}", url);
        
        // Create WebSocket
        let ws = WebSocket::new(url).map_err(|e| {
            log::error!("Failed to create WebSocket: {:?}", e);
            io::Error::new(io::ErrorKind::ConnectionRefused, "Failed to create WebSocket")
        })?;
        
        // Set binary mode
        ws.set_binary_type(BinaryType::Arraybuffer);
        
        // Create shared state (UnsafeCell is safe in single-threaded WASM)
        let state = Rc::new(UnsafeCell::new(StreamState::new()));
        
        // Set up event handlers
        Self::setup_handlers(&ws, state.clone())?;
        
        // Wait for connection to open
        let connection_future = {
            let state_clone = state.clone();
            async move {
                // Poll until connected or error
                loop {
                    let current_state = unsafe {
                        let st = &*state_clone.get();
                        if let Some(err) = &st.error {
                            return Err(io::Error::new(io::ErrorKind::Other, err.clone()));
                        }
                        st.state
                    };
                    
                    match current_state {
                        ConnectionState::Connected => return Ok(()),
                        ConnectionState::Closed | ConnectionState::Closing => {
                            return Err(io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                "Connection closed before established",
                            ));
                        }
                        ConnectionState::Connecting => {
                            // Wait a bit and check again
                            crate::runtime::WasmRuntime::new()
                                .sleep(std::time::Duration::from_millis(10))
                                .await;
                        }
                    }
                }
            }
        };
        
        connection_future.await?;
        
        log::info!("WebSocket connected successfully");
        
        Ok(Self { ws, state })
    }
    
    /// Set up WebSocket event handlers
    fn setup_handlers(ws: &WebSocket, state: Rc<UnsafeCell<StreamState>>) -> IoResult<()> {
        // onopen handler
        {
            let state_clone = state.clone();
            let onopen = Closure::wrap(Box::new(move |_event: JsValue| {
                log::debug!("WebSocket opened");
                unsafe {
                    let st = &mut *state_clone.get();
                    st.state = ConnectionState::Connected;
                    if let Some(waker) = st.read_waker.take() {
                        waker.wake();
                    }
                }
            }) as Box<dyn FnMut(JsValue)>);
            
            ws.set_onopen(Some(onopen.as_ref().unchecked_ref()));
            onopen.forget(); // Keep closure alive
        }
        
        // onmessage handler - receives data
        {
            let state_clone = state.clone();
            let onmessage = Closure::wrap(Box::new(move |event: MessageEvent| {
                if let Ok(array_buffer) = event.data().dyn_into::<js_sys::ArrayBuffer>() {
                    let array = js_sys::Uint8Array::new(&array_buffer);
                    let data = array.to_vec();
                    
                    log::debug!("WebSocket received {} bytes", data.len());
                    
                    unsafe {
                        let st = &mut *state_clone.get();
                        st.recv_buffer.extend(data);
                        
                        // Wake up any pending read
                        if let Some(waker) = st.read_waker.take() {
                            waker.wake();
                        }
                    }
                }
            }) as Box<dyn FnMut(MessageEvent)>);
            
            ws.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
            onmessage.forget();
        }
        
        // onerror handler
        {
            let state_clone = state.clone();
            let onerror = Closure::wrap(Box::new(move |event: ErrorEvent| {
                log::error!("WebSocket error: {:?}", event.message());
                unsafe {
                    let st = &mut *state_clone.get();
                    st.error = Some(format!("WebSocket error: {}", event.message()));
                    st.state = ConnectionState::Closed;
                    
                    // Wake up any pending operations
                    if let Some(waker) = st.read_waker.take() {
                        waker.wake();
                    }
                    if let Some(waker) = st.write_waker.take() {
                        waker.wake();
                    }
                }
            }) as Box<dyn FnMut(ErrorEvent)>);
            
            ws.set_onerror(Some(onerror.as_ref().unchecked_ref()));
            onerror.forget();
        }
        
        // onclose handler
        {
            let state_clone = state.clone();
            let onclose = Closure::wrap(Box::new(move |_event: JsValue| {
                log::debug!("WebSocket closed");
                unsafe {
                    let st = &mut *state_clone.get();
                    st.state = ConnectionState::Closed;
                    
                    // Wake up any pending operations
                    if let Some(waker) = st.read_waker.take() {
                        waker.wake();
                    }
                    if let Some(waker) = st.write_waker.take() {
                        waker.wake();
                    }
                }
            }) as Box<dyn FnMut(JsValue)>);
            
            ws.set_onclose(Some(onclose.as_ref().unchecked_ref()));
            onclose.forget();
        }
        
        Ok(())
    }
    
    /// Set the traffic shaping profile for DPI resistance.
    ///
    /// When a non-None profile is active, outgoing data is fragmented into
    /// frame sizes matching the profile's distribution (e.g., Chat: 50-200 bytes).
    /// This prevents DPI from fingerprinting traffic by the characteristic
    /// 514-byte Tor cell size.
    ///
    /// Profiles:
    ///   - `None`: raw Tor cells (no shaping, fastest)
    ///   - `Chat`: bursty small messages (50-200 bytes) with idle gaps
    ///   - `Ticker`: steady small frames (20-100 bytes)
    ///   - `Video`: sustained high-bandwidth (800-1200 bytes)
    pub fn set_traffic_profile(&self, profile: crate::traffic_shaping::TrafficProfile) {
        unsafe {
            let state = &mut *self.state.get();
            log::info!("Traffic shaping profile set to: {:?}", profile);
            state.traffic_profile = profile;
        }
    }

    /// Flush the send buffer to the WebSocket.
    ///
    /// When traffic shaping is active, data is fragmented into profile-matching
    /// frame sizes. The first frame is sent immediately; remaining frames are
    /// queued and sent via setTimeout callbacks to match timing distribution.
    fn flush_send_buffer(&self) -> IoResult<()> {
        unsafe {
            let state = &mut *self.state.get();

            if state.send_buffer.is_empty() {
                return Ok(());
            }

            // Check if we can send
            match state.state {
                ConnectionState::Connected => {},
                ConnectionState::Connecting => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "Connection not yet established",
                    ));
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "Connection closed",
                    ));
                }
            }

            // Drain all buffered data
            let data: Vec<u8> = state.send_buffer.drain(..).collect();

            if data.is_empty() {
                return Ok(());
            }

            // Fragment data according to traffic profile
            let frames = crate::traffic_shaping::fragment_for_profile(
                &data,
                &state.traffic_profile,
                &mut state.shaping_rng,
            );

            if frames.is_empty() {
                return Ok(());
            }

            // Send first frame immediately
            let first = &frames[0];
            log::debug!(
                "Sending {} bytes ({} frames, profile {:?})",
                data.len(),
                frames.len(),
                state.traffic_profile
            );

            let array = js_sys::Uint8Array::from(&first[..]);
            self.ws.send_with_array_buffer(&array.buffer()).map_err(|e| {
                log::error!("Failed to send data: {:?}", e);
                io::Error::new(io::ErrorKind::Other, "Failed to send data over WebSocket")
            })?;

            // If there are more frames, schedule them with timing delays
            if frames.len() > 1 {
                let remaining: Vec<Vec<u8>> = frames[1..].to_vec();
                self.schedule_deferred_frames(remaining, &mut state.shaping_rng);
            }

            Ok(())
        }
    }

    /// Schedule remaining shaped frames with profile-matching timing delays.
    ///
    /// Uses `setTimeout` to send each frame after the appropriate delay,
    /// simulating the inter-frame timing of the active traffic profile.
    fn schedule_deferred_frames(&self, frames: Vec<Vec<u8>>, rng: &mut u64) {
        use crate::traffic_shaping::{profile_delay, TrafficProfile};

        let ws = self.ws.clone();
        let state = self.state.clone();
        let profile = unsafe { (*self.state.get()).traffic_profile };

        // Calculate cumulative delays for each frame
        let mut cumulative_ms: u32 = 0;
        let mut scheduled_frames: Vec<(u32, Vec<u8>)> = Vec::with_capacity(frames.len());

        for frame in frames {
            let delay = profile_delay(&profile, rng);
            cumulative_ms += delay.as_millis() as u32;
            scheduled_frames.push((cumulative_ms, frame));
        }

        // Schedule each frame via setTimeout
        for (delay_ms, frame) in scheduled_frames {
            let ws_clone = ws.clone();
            let state_clone = state.clone();

            let closure = Closure::once(move || {
                // Check connection is still alive
                let connected = unsafe {
                    let st = &*state_clone.get();
                    st.state == ConnectionState::Connected
                };

                if connected {
                    let array = js_sys::Uint8Array::from(&frame[..]);
                    if let Err(e) = ws_clone.send_with_array_buffer(&array.buffer()) {
                        log::warn!("Deferred frame send failed: {:?}", e);
                    }
                }
            });

            let window = web_sys::window().expect("no window");
            let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
                closure.as_ref().unchecked_ref(),
                delay_ms as i32,
            );
            closure.forget(); // Keep alive until setTimeout fires
        }
    }
}

impl AsyncRead for WasmTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        unsafe {
            let state = &mut *self.state.get();
            
            // Check for errors
            if let Some(err) = &state.error {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Other,
                    err.clone(),
                )));
            }
            
            // Check if connection is closed
            if state.state == ConnectionState::Closed && state.recv_buffer.is_empty() {
                return Poll::Ready(Ok(0)); // EOF
            }
            
            // If we have data in the buffer, read it
            if !state.recv_buffer.is_empty() {
                let to_read = buf.len().min(state.recv_buffer.len());
                for (i, byte) in state.recv_buffer.drain(..to_read).enumerate() {
                    buf[i] = byte;
                }
                return Poll::Ready(Ok(to_read));
            }
            
            // No data available, store waker and return pending
            state.read_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

impl AsyncWrite for WasmTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<IoResult<usize>> {
        unsafe {
            let state = &mut *self.state.get();
            
            // Check for errors
            if let Some(err) = &state.error {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Other,
                    err.clone(),
                )));
            }
            
            // Check if connection is ready
            match state.state {
                ConnectionState::Connected => {},
                ConnectionState::Connecting => {
                    // Store waker and return pending
                    state.write_waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }
                _ => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "Connection closed",
                    )));
                }
            }
            
            // Buffer the data
            state.send_buffer.extend(buf);
            
            Poll::Ready(Ok(buf.len()))
        }
    }
    
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        // Try to flush the send buffer
        match self.flush_send_buffer() {
            Ok(()) => Poll::Ready(Ok(())),
            Err(e) if e.kind() == io::ErrorKind::NotConnected => {
                // Store waker for when connection is ready
                unsafe {
                    let state = &mut *self.state.get();
                    state.write_waker = Some(_cx.waker().clone());
                }
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
    
    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        // Flush any remaining data first
        if let Err(e) = self.flush_send_buffer() {
            return Poll::Ready(Err(e));
        }
        
        // Close the WebSocket
        unsafe {
            let state = &mut *self.state.get();
            if state.state != ConnectionState::Closed {
                state.state = ConnectionState::Closing;
                let _ = self.ws.close();
            }
        }
        
        Poll::Ready(Ok(()))
    }
}

// Implement Debug
impl std::fmt::Debug for WasmTcpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unsafe {
            let state = &*self.state.get();
            f.debug_struct("WasmTcpStream")
                .field("state", &state.state)
                .field("recv_buffer_len", &state.recv_buffer.len())
                .field("send_buffer_len", &state.send_buffer.len())
                .finish()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;
    
    #[wasm_bindgen_test]
    async fn test_stream_creation() {
        // This test requires a bridge server running
        // For now, just test that the structure compiles
        assert!(true);
    }
}

