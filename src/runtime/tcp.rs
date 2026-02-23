//! TCP provider implementation for WasmRuntime
//!
//! This implements the `TcpProvider` trait required by Arti,
//! using our WebSocket-based transport layer.

use std::io::Result as IoResult;
use std::pin::Pin;
use std::task::{Context, Poll};
use futures::Future;

/// Listener stub (not needed for Tor clients)
pub struct WasmTcpListener;

impl WasmTcpListener {
    fn unsupported() -> IoResult<Self> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TCP listeners are not supported in WASM (clients only)",
        ))
    }
}

/// Future that resolves to a TCP stream  
/// (Generic to avoid importing WasmTcpStream here)
pub struct WasmConnectFuture<T> {
    inner: Pin<Box<dyn Future<Output = IoResult<T>> + 'static>>,
}

impl<T> Future for WasmConnectFuture<T> {
    type Output = IoResult<T>;
    
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.as_mut().poll(cx)
    }
}

/// Future that resolves to a WasmTcpListener (always errors)
pub struct WasmListenFuture;

impl Future for WasmListenFuture {
    type Output = IoResult<WasmTcpListener>;
    
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(WasmTcpListener::unsupported())
    }
}

// Note: AsyncRead and AsyncWrite are already implemented for WasmTcpStream
// in transport/websocket.rs - no need to implement them again here!

