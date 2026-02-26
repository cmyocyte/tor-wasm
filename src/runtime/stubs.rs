//! Stub implementations for unsupported features in WASM
//!
//! These traits are required by Arti but not usable in WASM environment.
//! We provide stub implementations that return errors or panic.

use futures::Future;
use std::io::{self, Result as IoResult};

/// Unsupported UDP socket (WASM can't do UDP)
#[derive(Debug)]
pub struct UnsupportedUdpSocket;

impl UnsupportedUdpSocket {
    fn unsupported() -> IoResult<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "UDP sockets are not supported in WASM environment",
        ))
    }
}

/// Unsupported TCP stream (for Unix sockets)
#[derive(Debug)]
pub struct UnsupportedStream;

impl UnsupportedStream {
    fn unsupported() -> IoResult<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Unix domain sockets are not supported in WASM environment",
        ))
    }
}

/// Unsupported listener (WASM clients don't listen)
#[derive(Debug)]
pub struct UnsupportedListener;

impl UnsupportedListener {
    fn unsupported() -> IoResult<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Listening on ports is not supported in WASM environment",
        ))
    }
}

// We'll implement these traits for WasmRuntime in separate files
// to keep code organized

/// Helper future that immediately returns an error
pub struct UnsupportedFuture<T> {
    error: Option<io::Error>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> UnsupportedFuture<T> {
    pub fn new(kind: io::ErrorKind, message: &str) -> Self {
        Self {
            error: Some(io::Error::new(kind, message.to_string())),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T> Future for UnsupportedFuture<T> {
    type Output = IoResult<T>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        // Safe because we're not moving out of the pinned data
        let this = unsafe { self.get_unchecked_mut() };
        std::task::Poll::Ready(Err(this
            .error
            .take()
            .unwrap_or_else(|| io::Error::other("Unsupported operation"))))
    }
}

// Export helper types
pub use UnsupportedListener as WasmListener;
pub use UnsupportedStream as WasmUnixStream;
pub use UnsupportedUdpSocket as WasmUdpSocket;
