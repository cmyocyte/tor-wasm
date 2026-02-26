//! meek transport for WASM
//!
//! Tunnels Tor protocol cells inside HTTP POST request/response bodies.
//! Works through CDNs (Cloudflare, Fastly) — censor sees only HTTPS to
//! a CDN IP, indistinguishable from normal website traffic.
//!
//! Protocol:
//!   POST / with X-Session-Id and X-Target headers
//!   Body: raw Tor cells
//!   Response body: raw Tor cells from relay
//!
//! Unlike WebSocket, no long-lived connection — each exchange is a
//! standard HTTP request/response. Defeats WebSocket-based blocking.

use futures::io::{AsyncRead, AsyncWrite};
use std::cell::UnsafeCell;
use std::collections::VecDeque;
use std::io::{self, Result as IoResult};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

/// State of the meek connection
#[derive(Debug, Clone, Copy, PartialEq)]
enum MeekState {
    Connecting,
    Connected,
    Closed,
}

/// Inner state for the meek stream
struct MeekStreamState {
    state: MeekState,
    recv_buffer: VecDeque<u8>,
    send_buffer: VecDeque<u8>,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    error: Option<String>,
}

impl MeekStreamState {
    fn new() -> Self {
        Self {
            state: MeekState::Connecting,
            recv_buffer: VecDeque::new(),
            send_buffer: VecDeque::new(),
            read_waker: None,
            write_waker: None,
            error: None,
        }
    }
}

/// meek-based TCP stream for WASM
///
/// Uses HTTP POST requests to exchange Tor cells through a CDN.
/// Implements AsyncRead/AsyncWrite for transparent use by Arti.
pub struct WasmMeekStream {
    bridge_url: String,
    session_id: String,
    target: String,
    state: Rc<UnsafeCell<MeekStreamState>>,
    poll_interval_ms: u32,
    _poll_closure: Option<Closure<dyn FnMut()>>,
}

/// Poll interval for fetching relay data (ms)
const MEEK_POLL_INTERVAL: u32 = 100;

/// Maximum send buffer size before flush
const MEEK_FLUSH_THRESHOLD: usize = 514; // One Tor cell

impl WasmMeekStream {
    /// Connect to a Tor relay through a meek bridge.
    ///
    /// `bridge_url` — meek bridge HTTP(S) URL (e.g., `https://bridge.example.com`)
    /// `target` — relay address as `host:port`
    pub async fn connect(bridge_url: &str, target: &str) -> IoResult<Self> {
        let session_id = Self::generate_session_id();

        let state = Rc::new(UnsafeCell::new(MeekStreamState::new()));

        let mut stream = Self {
            bridge_url: bridge_url.to_string(),
            session_id,
            target: target.to_string(),
            state: state.clone(),
            poll_interval_ms: MEEK_POLL_INTERVAL,
            _poll_closure: None,
        };

        // Initial POST to establish session (empty body, target in header)
        match stream.do_exchange(&[]).await {
            Ok(data) => {
                let s = unsafe { &mut *state.get() };
                s.state = MeekState::Connected;
                if !data.is_empty() {
                    s.recv_buffer.extend(data.iter());
                }
                if let Some(w) = s.read_waker.take() {
                    w.wake();
                }
            }
            Err(e) => {
                let s = unsafe { &mut *state.get() };
                s.state = MeekState::Closed;
                s.error = Some(format!("meek connect failed: {}", e));
                return Err(io::Error::new(io::ErrorKind::ConnectionRefused, e));
            }
        }

        // Start background polling loop
        stream.start_poll_loop();

        Ok(stream)
    }

    /// Generate a random session ID (16 hex chars)
    fn generate_session_id() -> String {
        let mut bytes = [0u8; 8];
        if let Ok(crypto) = web_sys::window().and_then(|w| w.crypto().ok()).ok_or(()) {
            let _ = crypto.get_random_values_with_u8_array(&mut bytes);
        } else {
            // Fallback: use performance.now() as entropy
            let now = js_sys::Date::now() as u64;
            bytes = now.to_le_bytes();
        }
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Perform a single HTTP POST exchange
    async fn do_exchange(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let opts = RequestInit::new();
        opts.set_method("POST");
        opts.set_mode(RequestMode::Cors);

        // Set body
        let body = js_sys::Uint8Array::from(data);
        opts.set_body(&body.into());

        let request = Request::new_with_str_and_init(&self.bridge_url, &opts)
            .map_err(|e| format!("Request::new failed: {:?}", e))?;

        let headers = request.headers();
        headers
            .set("X-Session-Id", &self.session_id)
            .map_err(|e| format!("set header failed: {:?}", e))?;
        headers
            .set("X-Target", &self.target)
            .map_err(|e| format!("set header failed: {:?}", e))?;
        headers
            .set("Content-Type", "application/octet-stream")
            .map_err(|e| format!("set header failed: {:?}", e))?;

        // Perform fetch
        let window = web_sys::window().ok_or_else(|| "no window object".to_string())?;

        let resp_value = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|e| format!("fetch failed: {:?}", e))?;

        let resp: Response = resp_value
            .dyn_into()
            .map_err(|_| "response is not a Response".to_string())?;

        if !resp.ok() {
            return Err(format!("HTTP {}", resp.status()));
        }

        // Read response body
        let array_buffer = JsFuture::from(
            resp.array_buffer()
                .map_err(|e| format!("array_buffer failed: {:?}", e))?,
        )
        .await
        .map_err(|e| format!("await array_buffer failed: {:?}", e))?;

        let uint8_array = js_sys::Uint8Array::new(&array_buffer);
        let mut result = vec![0u8; uint8_array.length() as usize];
        uint8_array.copy_to(&mut result);

        Ok(result)
    }

    /// Start background polling loop using setInterval
    fn start_poll_loop(&mut self) {
        let state = self.state.clone();
        let bridge_url = self.bridge_url.clone();
        let session_id = self.session_id.clone();
        let target = self.target.clone();

        let closure = Closure::new(move || {
            let s = unsafe { &mut *state.get() };
            if s.state != MeekState::Connected {
                return;
            }

            // Drain send buffer
            let send_data: Vec<u8> = s.send_buffer.drain(..).collect();

            // Spawn async exchange
            let state_inner = state.clone();
            let url = bridge_url.clone();
            let sid = session_id.clone();
            let tgt = target.clone();

            wasm_bindgen_futures::spawn_local(async move {
                let stream = WasmMeekStreamHelper {
                    bridge_url: url,
                    session_id: sid,
                    target: tgt,
                };
                match stream.do_exchange(&send_data).await {
                    Ok(data) => {
                        let s = unsafe { &mut *state_inner.get() };
                        if !data.is_empty() {
                            s.recv_buffer.extend(data.iter());
                            if let Some(w) = s.read_waker.take() {
                                w.wake();
                            }
                        }
                    }
                    Err(e) => {
                        let s = unsafe { &mut *state_inner.get() };
                        log::warn!("meek poll error: {}", e);
                        s.error = Some(e);
                        s.state = MeekState::Closed;
                        if let Some(w) = s.read_waker.take() {
                            w.wake();
                        }
                    }
                }
            });
        });

        let window = web_sys::window().expect("no window");
        let _ = window.set_interval_with_callback_and_timeout_and_arguments_0(
            closure.as_ref().unchecked_ref(),
            self.poll_interval_ms as i32,
        );

        self._poll_closure = Some(closure);
    }
}

/// Helper struct for async exchange from within spawn_local
struct WasmMeekStreamHelper {
    bridge_url: String,
    session_id: String,
    target: String,
}

impl WasmMeekStreamHelper {
    async fn do_exchange(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let opts = RequestInit::new();
        opts.set_method("POST");
        opts.set_mode(RequestMode::Cors);

        let body = js_sys::Uint8Array::from(data);
        opts.set_body(&body.into());

        let request = Request::new_with_str_and_init(&self.bridge_url, &opts)
            .map_err(|e| format!("Request::new failed: {:?}", e))?;

        let headers = request.headers();
        headers
            .set("X-Session-Id", &self.session_id)
            .map_err(|_| "set header failed".to_string())?;
        headers
            .set("X-Target", &self.target)
            .map_err(|_| "set header failed".to_string())?;
        headers
            .set("Content-Type", "application/octet-stream")
            .map_err(|_| "set header failed".to_string())?;

        let window = web_sys::window().ok_or_else(|| "no window".to_string())?;

        let resp_value = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|e| format!("fetch failed: {:?}", e))?;

        let resp: Response = resp_value
            .dyn_into()
            .map_err(|_| "not a Response".to_string())?;

        if !resp.ok() {
            return Err(format!("HTTP {}", resp.status()));
        }

        let array_buffer = JsFuture::from(
            resp.array_buffer()
                .map_err(|e| format!("array_buffer: {:?}", e))?,
        )
        .await
        .map_err(|e| format!("await: {:?}", e))?;

        let uint8_array = js_sys::Uint8Array::new(&array_buffer);
        let mut result = vec![0u8; uint8_array.length() as usize];
        uint8_array.copy_to(&mut result);

        Ok(result)
    }
}

impl AsyncRead for WasmMeekStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        let state = unsafe { &mut *self.state.get() };

        if !state.recv_buffer.is_empty() {
            let len = std::cmp::min(buf.len(), state.recv_buffer.len());
            for i in 0..len {
                buf[i] = state.recv_buffer.pop_front().unwrap();
            }
            return Poll::Ready(Ok(len));
        }

        match state.state {
            MeekState::Closed => {
                if let Some(ref e) = state.error {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        e.clone(),
                    )))
                } else {
                    Poll::Ready(Ok(0)) // EOF
                }
            }
            _ => {
                state.read_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for WasmMeekStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<IoResult<usize>> {
        let state = unsafe { &mut *self.state.get() };

        match state.state {
            MeekState::Closed => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                state.error.as_deref().unwrap_or("connection closed"),
            ))),
            _ => {
                state.send_buffer.extend(buf.iter());
                Poll::Ready(Ok(buf.len()))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        // Send buffer is drained by the poll loop
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        let state = unsafe { &mut *self.state.get() };
        state.state = MeekState::Closed;
        Poll::Ready(Ok(()))
    }
}

impl Drop for WasmMeekStream {
    fn drop(&mut self) {
        let state = unsafe { &mut *self.state.get() };
        state.state = MeekState::Closed;
    }
}
