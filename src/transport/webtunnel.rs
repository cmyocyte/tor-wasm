//! WebTunnel pluggable transport for WASM
//!
//! Disguises Tor traffic as a normal HTTPS WebSocket connection.
//! Unlike the standard bridge WebSocket transport (which uses `?addr=` or `?dest=`
//! query params), WebTunnel uses a secret path and the standard `Upgrade: websocket`
//! handshake. To DPI equipment, the connection is indistinguishable from a
//! regular HTTPS website that uses WebSocket.
//!
//! The server side serves a cover site for all other requests, so active probers
//! see a normal website. Only clients with the secret path can establish a tunnel.
//!
//! Protocol flow:
//!   1. Client computes HMAC-SHA256(secret_path, timestamp) as challenge
//!   2. Client connects: `wss://innocent-blog.com/<secret-path>`
//!      with `Sec-WebSocket-Protocol: v1.<hmac>.<timestamp>`
//!   3. Server verifies HMAC + timestamp window, upgrades if valid
//!   4. After upgrade, bidirectional byte stream carries Tor cells
//!   5. Non-matching requests or invalid HMAC → cover site 404

use futures::io::{AsyncRead, AsyncWrite};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::VecDeque;
use std::fmt::Write as FmtWrite;
use std::io::{self, Result as IoResult};
use std::pin::Pin;
use std::rc::Rc;
use std::cell::UnsafeCell;
use std::task::{Context, Poll, Waker};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{BinaryType, ErrorEvent, MessageEvent, WebSocket};

type HmacSha256 = Hmac<Sha256>;

/// Compute the HMAC challenge string for WebTunnel probe resistance.
///
/// Format: `v1.<hmac_hex_32chars>.<unix_timestamp>`
/// - HMAC key = the secret path
/// - HMAC message = timestamp string (unix seconds)
/// - Truncated to 128 bits (32 hex chars)
///
/// The server verifies this via `Sec-WebSocket-Protocol` header.
/// A prober who discovers the path but doesn't know the HMAC protocol
/// gets an identical 404 response — indistinguishable from wrong path.
fn compute_hmac_challenge(secret_path: &str) -> String {
    let timestamp = (js_sys::Date::now() / 1000.0) as u64;
    let ts_str = timestamp.to_string();

    let mut mac = HmacSha256::new_from_slice(secret_path.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(ts_str.as_bytes());
    let result = mac.finalize().into_bytes();

    // Truncate to 128 bits (16 bytes = 32 hex chars)
    let mut hex = String::with_capacity(32);
    for byte in &result[..16] {
        let _ = write!(hex, "{:02x}", byte);
    }

    format!("v1.{}.{}", hex, ts_str)
}

/// Connection state for WebTunnel
#[derive(Debug, Clone, Copy, PartialEq)]
enum TunnelState {
    Connecting,
    Connected,
    Closing,
    Closed,
}

/// Inner mutable state for the WebTunnel stream
struct TunnelStreamState {
    state: TunnelState,
    recv_buffer: VecDeque<u8>,
    send_buffer: VecDeque<u8>,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    error: Option<String>,
}

impl TunnelStreamState {
    fn new() -> Self {
        Self {
            state: TunnelState::Connecting,
            recv_buffer: VecDeque::new(),
            send_buffer: VecDeque::new(),
            read_waker: None,
            write_waker: None,
            error: None,
        }
    }
}

/// WebTunnel-based TCP stream for WASM
///
/// Uses a standard WebSocket connection to a secret path on a cover website.
/// The server looks like a normal HTTPS site to probers — only the secret path
/// triggers the WebSocket upgrade and Tor cell relay.
///
/// Implements AsyncRead/AsyncWrite for transparent use by Arti.
pub struct WasmWebTunnelStream {
    ws: WebSocket,
    state: Rc<UnsafeCell<TunnelStreamState>>,
    // Prevent closures from being dropped while WS events can still fire
    _on_open: Closure<dyn FnMut()>,
    _on_message: Closure<dyn FnMut(MessageEvent)>,
    _on_error: Closure<dyn FnMut(ErrorEvent)>,
    _on_close: Closure<dyn FnMut()>,
}

impl WasmWebTunnelStream {
    /// Connect to a Tor relay through a WebTunnel bridge.
    ///
    /// `url` — the bridge server URL (e.g., `wss://innocent-blog.com`)
    /// `secret_path` — the secret path for WebSocket upgrade (e.g., `/ws-a1b2c3d4`)
    ///
    /// The full WebSocket URL is `{url}{secret_path}`. The server upgrades
    /// only this path; all other paths return the cover site.
    pub async fn connect(url: &str, secret_path: &str) -> IoResult<Self> {
        // Build the full URL: wss://host/secret-path
        let full_url = format!(
            "{}{}",
            url.trim_end_matches('/'),
            if secret_path.starts_with('/') { secret_path.to_string() } else { format!("/{}", secret_path) }
        );

        // Compute HMAC challenge for probe resistance.
        // Sent as Sec-WebSocket-Protocol so the server can verify we know the secret.
        let protocol = compute_hmac_challenge(secret_path);
        log::debug!("WebTunnel: HMAC challenge protocol={}", &protocol[..6]);

        let ws = WebSocket::new_with_str(&full_url, &protocol)
            .map_err(|e| io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("WebSocket::new failed: {:?}", e),
            ))?;

        ws.set_binary_type(BinaryType::Arraybuffer);

        let state = Rc::new(UnsafeCell::new(TunnelStreamState::new()));

        // onopen
        let state_open = state.clone();
        let on_open = Closure::once(move || {
            let s = unsafe { &mut *state_open.get() };
            s.state = TunnelState::Connected;
            if let Some(w) = s.write_waker.take() {
                w.wake();
            }
            log::debug!("WebTunnel: connected");
        });
        ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));

        // onmessage
        let state_msg = state.clone();
        let on_message = Closure::wrap(Box::new(move |event: MessageEvent| {
            let s = unsafe { &mut *state_msg.get() };

            if let Ok(buf) = event.data().dyn_into::<js_sys::ArrayBuffer>() {
                let array = js_sys::Uint8Array::new(&buf);
                let len = array.length() as usize;
                let mut data = vec![0u8; len];
                array.copy_to(&mut data);
                s.recv_buffer.extend(data.iter());

                if let Some(w) = s.read_waker.take() {
                    w.wake();
                }
            }
        }) as Box<dyn FnMut(MessageEvent)>);
        ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

        // onerror
        let state_err = state.clone();
        let on_error = Closure::wrap(Box::new(move |_event: ErrorEvent| {
            let s = unsafe { &mut *state_err.get() };
            s.error = Some("WebTunnel: connection error".to_string());
            s.state = TunnelState::Closed;

            if let Some(w) = s.read_waker.take() {
                w.wake();
            }
            if let Some(w) = s.write_waker.take() {
                w.wake();
            }
            log::error!("WebTunnel: connection error");
        }) as Box<dyn FnMut(ErrorEvent)>);
        ws.set_onerror(Some(on_error.as_ref().unchecked_ref()));

        // onclose
        let state_close = state.clone();
        let on_close = Closure::wrap(Box::new(move || {
            let s = unsafe { &mut *state_close.get() };
            s.state = TunnelState::Closed;

            if let Some(w) = s.read_waker.take() {
                w.wake();
            }
            if let Some(w) = s.write_waker.take() {
                w.wake();
            }
            log::debug!("WebTunnel: closed");
        }) as Box<dyn FnMut()>);
        ws.set_onclose(Some(on_close.as_ref().unchecked_ref()));

        // Wait for connection to open
        let state_wait = state.clone();
        wasm_bindgen_futures::JsFuture::from(js_sys::Promise::new(&mut |resolve, _reject| {
            let ws_inner = ws.clone();
            let state_inner = state_wait.clone();

            let check = Closure::wrap(Box::new(move || {
                let s = unsafe { &*state_inner.get() };
                match s.state {
                    TunnelState::Connected => {
                        let _ = resolve.call0(&JsValue::NULL);
                    }
                    TunnelState::Closed => {
                        let _ = resolve.call0(&JsValue::NULL);
                    }
                    _ => {
                        // Check again in 50ms
                        let window = web_sys::window().unwrap();
                        let state_retry = state_inner.clone();
                        let resolve_retry = resolve.clone();
                        let timeout_cb = Closure::once(move || {
                            let s = unsafe { &*state_retry.get() };
                            let _ = resolve_retry.call0(&JsValue::NULL);
                        });
                        let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
                            timeout_cb.as_ref().unchecked_ref(),
                            100,
                        );
                        timeout_cb.forget();
                    }
                }
            }) as Box<dyn FnMut()>);

            // Initial check after 10ms (WebSocket open is async)
            let window = web_sys::window().unwrap();
            let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
                check.as_ref().unchecked_ref(),
                10,
            );
            check.forget();
        })).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "WebTunnel connect timeout"))?;

        // Check final state
        let s = unsafe { &*state.get() };
        if s.state == TunnelState::Closed {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                s.error.as_deref().unwrap_or("WebTunnel connection failed"),
            ));
        }

        Ok(Self {
            ws,
            state,
            _on_open: on_open,
            _on_message: on_message,
            _on_error: on_error,
            _on_close: on_close,
        })
    }

    /// Flush the send buffer through the WebSocket
    fn flush_send_buffer(&self) -> IoResult<()> {
        let state = unsafe { &mut *self.state.get() };

        if state.send_buffer.is_empty() {
            return Ok(());
        }

        if state.state != TunnelState::Connected {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "WebTunnel not connected",
            ));
        }

        let data: Vec<u8> = state.send_buffer.drain(..).collect();
        let array = js_sys::Uint8Array::from(&data[..]);

        self.ws
            .send_with_array_buffer(&array.buffer())
            .map_err(|e| io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("WebTunnel send failed: {:?}", e),
            ))
    }
}

impl AsyncRead for WasmWebTunnelStream {
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
            TunnelState::Closed | TunnelState::Closing => {
                if let Some(ref e) = state.error {
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, e.clone())))
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

impl AsyncWrite for WasmWebTunnelStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<IoResult<usize>> {
        let state = unsafe { &mut *self.state.get() };

        match state.state {
            TunnelState::Connected => {
                state.send_buffer.extend(buf.iter());
                let _ = self.flush_send_buffer();
                Poll::Ready(Ok(buf.len()))
            }
            TunnelState::Connecting => {
                // Buffer data, will be sent on connect
                state.send_buffer.extend(buf.iter());
                state.write_waker = Some(_cx.waker().clone());
                Poll::Pending
            }
            _ => {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    state.error.as_deref().unwrap_or("WebTunnel closed"),
                )))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        match self.flush_send_buffer() {
            Ok(()) => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        let state = unsafe { &mut *self.state.get() };
        state.state = TunnelState::Closing;
        let _ = self.ws.close();
        state.state = TunnelState::Closed;
        Poll::Ready(Ok(()))
    }
}

impl Unpin for WasmWebTunnelStream {}

impl Drop for WasmWebTunnelStream {
    fn drop(&mut self) {
        let state = unsafe { &mut *self.state.get() };
        if state.state == TunnelState::Connected || state.state == TunnelState::Connecting {
            let _ = self.ws.close();
            state.state = TunnelState::Closed;
        }
    }
}
