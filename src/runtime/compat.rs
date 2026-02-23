//! tor-rtcompat trait implementations for WasmRuntime
//!
//! This module implements all the traits required by Arti's Runtime trait.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use futures::Future;
use futures::io::{AsyncRead, AsyncWrite};

use super::WasmRuntime;
use crate::transport::{WasmTcpStream, BridgeConfig};
use crate::{Result, TorError};

// Re-export for convenience
pub use super::sleep::WasmSleep;
pub use super::time::WasmCoarseInstant;

/// TCP Stream type for WASM
pub type TcpStream = WasmTcpStream;

/// Future for connecting to TCP
pub struct TcpConnectFuture {
    inner: Pin<Box<dyn Future<Output = io::Result<WasmTcpStream>>>>,
}

impl Future for TcpConnectFuture {
    type Output = io::Result<WasmTcpStream>;
    
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.as_mut().poll(cx)
    }
}

/// Implement TcpProvider trait (connecting to addresses)
impl WasmRuntime {
    /// Connect to a TCP address via WebSocket bridge
    pub fn connect_tcp(&self, addr: SocketAddr) -> TcpConnectFuture {
        let bridge_url = self.bridge_url().to_string();
        
        let future = async move {
            let config = BridgeConfig::new(bridge_url);
            let url = config.build_url(&addr);
            
            WasmTcpStream::connect(&url)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e.to_string()))
        };
        
        TcpConnectFuture {
            inner: Box::pin(future),
        }
    }
}

/// TLS Provider - passthrough (browser handles TLS)
#[derive(Clone)]
pub struct WasmTlsConnector;

impl WasmTlsConnector {
    pub fn new() -> Self {
        WasmTlsConnector
    }
}

/// UDP Socket (not supported in WASM)
pub struct WasmUdpSocket;

impl WasmUdpSocket {
    pub fn unsupported() -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "UDP sockets are not supported in WASM environment",
        ))
    }
}

/// Blocking operations (not supported in WASM)
#[derive(Debug, Clone)]
pub struct WasmBlockingHandle;

impl WasmBlockingHandle {
    pub fn new() -> Self {
        WasmBlockingHandle
    }
    
    pub fn execute_blocking<F, R>(&self, _f: F) -> io::Result<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Blocking operations are not supported in WASM (use async instead)",
        ))
    }
}

/// Unix domain socket (not supported in browsers)
pub mod unix {
    use std::io;
    
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub struct SocketAddr;
    
    pub struct UnixStream;
    
    impl UnixStream {
        pub fn unsupported() -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Unix domain sockets are not supported in WASM/browser environment",
            ))
        }
    }
}

