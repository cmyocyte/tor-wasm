//! Unified transport stream enum
//!
//! Wraps all three transport types (WebSocket, meek, WebRTC) behind a single
//! enum that implements `AsyncRead + AsyncWrite`. This allows `NetStreamProvider`
//! to return any transport type from its `connect()` method, enabling the
//! transport fallback chain (WebSocket → meek → WebRTC).
//!
//! All three inner types are `!Send` (they use `Rc<UnsafeCell<_>>` and JS objects),
//! which is fine — WASM is single-threaded.

use futures::io::{AsyncRead, AsyncWrite};
use std::io::Result as IoResult;
use std::pin::Pin;
use std::task::{Context, Poll};

use super::meek::WasmMeekStream;
use super::webrtc::WasmRtcStream;
use super::websocket::WasmTcpStream;
use super::webtunnel::WasmWebTunnelStream;

/// A unified transport stream that wraps WebSocket, meek, or WebRTC connections.
///
/// This enum enables the transport fallback chain:
///   1. WebSocket (fastest, default)
///   2. meek via CDN (HTTP POST/response, defeats WebSocket blocking)
///   3. WebRTC DataChannel (looks like a video call)
///
/// All variants implement `AsyncRead + AsyncWrite` by delegation.
pub enum TransportStream {
    /// Standard WebSocket transport (default, fastest)
    WebSocket(WasmTcpStream),

    /// meek transport — HTTP POST/response through a CDN
    Meek(WasmMeekStream),

    /// WebRTC DataChannel through a volunteer peer proxy
    WebRtc(WasmRtcStream),

    /// WebTunnel — HTTPS WebSocket on a secret path, disguised as normal website
    WebTunnel(WasmWebTunnelStream),
}

impl TransportStream {
    /// Returns the transport type as a string (for logging/diagnostics)
    pub fn transport_name(&self) -> &'static str {
        match self {
            TransportStream::WebSocket(_) => "websocket",
            TransportStream::Meek(_) => "meek",
            TransportStream::WebRtc(_) => "webrtc",
            TransportStream::WebTunnel(_) => "webtunnel",
        }
    }

    /// Returns true if this is a WebSocket transport
    pub fn is_websocket(&self) -> bool {
        matches!(self, TransportStream::WebSocket(_))
    }

    /// Returns true if this is a meek transport
    pub fn is_meek(&self) -> bool {
        matches!(self, TransportStream::Meek(_))
    }

    /// Returns true if this is a WebRTC transport
    pub fn is_webrtc(&self) -> bool {
        matches!(self, TransportStream::WebRtc(_))
    }

    /// Returns true if this is a WebTunnel transport
    pub fn is_webtunnel(&self) -> bool {
        matches!(self, TransportStream::WebTunnel(_))
    }
}

impl AsyncRead for TransportStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        // SAFETY: We never move the inner value, only delegate to its poll_read.
        // All inner types are Unpin (they use Rc<UnsafeCell<_>>), so this is safe.
        match self.get_mut() {
            TransportStream::WebSocket(stream) => Pin::new(stream).poll_read(cx, buf),
            TransportStream::Meek(stream) => Pin::new(stream).poll_read(cx, buf),
            TransportStream::WebRtc(stream) => Pin::new(stream).poll_read(cx, buf),
            TransportStream::WebTunnel(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TransportStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        match self.get_mut() {
            TransportStream::WebSocket(stream) => Pin::new(stream).poll_write(cx, buf),
            TransportStream::Meek(stream) => Pin::new(stream).poll_write(cx, buf),
            TransportStream::WebRtc(stream) => Pin::new(stream).poll_write(cx, buf),
            TransportStream::WebTunnel(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        match self.get_mut() {
            TransportStream::WebSocket(stream) => Pin::new(stream).poll_flush(cx),
            TransportStream::Meek(stream) => Pin::new(stream).poll_flush(cx),
            TransportStream::WebRtc(stream) => Pin::new(stream).poll_flush(cx),
            TransportStream::WebTunnel(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        match self.get_mut() {
            TransportStream::WebSocket(stream) => Pin::new(stream).poll_close(cx),
            TransportStream::Meek(stream) => Pin::new(stream).poll_close(cx),
            TransportStream::WebRtc(stream) => Pin::new(stream).poll_close(cx),
            TransportStream::WebTunnel(stream) => Pin::new(stream).poll_close(cx),
        }
    }
}

// TransportStream is Unpin because all inner types are Unpin
impl Unpin for TransportStream {}

// Implement From conversions for ergonomic wrapping
impl From<WasmTcpStream> for TransportStream {
    fn from(stream: WasmTcpStream) -> Self {
        TransportStream::WebSocket(stream)
    }
}

impl From<WasmMeekStream> for TransportStream {
    fn from(stream: WasmMeekStream) -> Self {
        TransportStream::Meek(stream)
    }
}

impl From<WasmRtcStream> for TransportStream {
    fn from(stream: WasmRtcStream) -> Self {
        TransportStream::WebRtc(stream)
    }
}

impl From<WasmWebTunnelStream> for TransportStream {
    fn from(stream: WasmWebTunnelStream) -> Self {
        TransportStream::WebTunnel(stream)
    }
}

impl std::fmt::Debug for TransportStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TransportStream::{}", self.transport_name())
    }
}
