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
}

impl StreamState {
    fn new() -> Self {
        Self {
            state: ConnectionState::Connecting,
            recv_buffer: VecDeque::new(),
            send_buffer: VecDeque::new(),
            read_waker: None,
            write_waker: None,
            error: None,
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

impl WasmTcpStream {
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
    
    /// Flush the send buffer to the WebSocket
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
            
            // Send all buffered data
            let data: Vec<u8> = state.send_buffer.drain(..).collect();
            
            if !data.is_empty() {
                log::debug!("Sending {} bytes over WebSocket", data.len());
                
                let array = js_sys::Uint8Array::from(&data[..]);
                self.ws.send_with_array_buffer(&array.buffer()).map_err(|e| {
                    log::error!("Failed to send data: {:?}", e);
                    io::Error::new(io::ErrorKind::Other, "Failed to send data over WebSocket")
                })?;
            }
            
            Ok(())
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

