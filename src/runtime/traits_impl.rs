//! Trait implementations for tor-rtcompat compatibility
//!
//! This module implements tor-rtcompat traits for our WASM types

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::net::SocketAddr;
use async_trait::async_trait;
use futures::{Future, Stream, stream};
use futures::io::{AsyncRead, AsyncWrite};
use tor_rtcompat::{StreamOps, NetStreamListener, CertifiedConn, UdpSocket};

use crate::transport::WasmTcpStream;
use super::tcp::WasmTcpListener;
use super::compat::unix::UnixStream;
use super::compat::WasmTlsConnector;

// Implement StreamOps for WasmTcpStream
impl StreamOps for WasmTcpStream {
    fn set_tcp_notsent_lowat(&self, _notsent_lowat: u32) -> io::Result<()> {
        // WebSocket doesn't support TCP_NOTSENT_LOWAT
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TCP_NOTSENT_LOWAT not supported in WASM/WebSocket",
        ))
    }
}

// Create a stream type for incoming connections (always empty in WASM)
pub struct WasmIncoming;

impl Stream for WasmIncoming {
    type Item = io::Result<(WasmTcpStream, std::net::SocketAddr)>;
    
    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Never yields - listeners not supported in WASM
        Poll::Ready(None)
    }
}

// Implement NetStreamListener for WasmTcpListener
impl NetStreamListener for WasmTcpListener {
    type Stream = WasmTcpStream;
    type Incoming = WasmIncoming;
    
    fn incoming(self) -> Self::Incoming {
        // Listeners not supported in WASM
        WasmIncoming
    }
    
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TCP listeners not supported in WASM",
        ))
    }
}

// Implement traits for UnixStream (stub)
impl AsyncRead for UnixStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Unix sockets not supported in WASM",
        )))
    }
}

impl AsyncWrite for UnixStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Unix sockets not supported in WASM",
        )))
    }
    
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Unix sockets not supported in WASM",
        )))
    }
    
    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl StreamOps for UnixStream {
    fn set_tcp_notsent_lowat(&self, _notsent_lowat: u32) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Unix sockets not supported in WASM",
        ))
    }
}

// Unix socket incoming stream (always empty)
pub struct UnixIncoming;

impl Stream for UnixIncoming {
    type Item = io::Result<(UnixStream, std::os::unix::net::SocketAddr)>;
    
    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(None)
    }
}

// Implement NetStreamListener for UnixStream (stub)
impl NetStreamListener<std::os::unix::net::SocketAddr> for UnixStream {
    type Stream = UnixStream;
    type Incoming = UnixIncoming;
    
    fn incoming(self) -> Self::Incoming {
        UnixIncoming
    }
    
    fn local_addr(&self) -> io::Result<std::os::unix::net::SocketAddr> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Unix sockets not supported in WASM",
        ))
    }
}

// Implement CertifiedConn for WasmTcpStream (browser handles certificates)
impl CertifiedConn for WasmTcpStream {
    fn peer_certificate(&self) -> io::Result<Option<Vec<u8>>> {
        // Browser handles certificate validation
        // We don't have access to the actual certificate
        Ok(None)
    }
    
    fn export_keying_material(
        &self,
        _len: usize,
        _label: &[u8],
        _context: Option<&[u8]>,
    ) -> io::Result<Vec<u8>> {
        // Browser's TLS doesn't expose keying material in WASM
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Keying material export not supported in WASM",
        ))
    }
}

// SAFETY: While WasmTcpStream contains Rc<RefCell>, which is normally !Send + !Sync,
// in WASM there is no true multithreading. JavaScript is single-threaded, and WASM
// runs in that single-threaded context. The Send/Sync requirements come from Arti's
// traits, but in practice, WASM streams will never be accessed from multiple threads.
unsafe impl Send for WasmTcpStream {}
unsafe impl Sync for WasmTcpStream {}

// Implement UdpSocket trait for WasmUdpSocket (stub)
#[async_trait(?Send)]
impl UdpSocket for super::compat::WasmUdpSocket {
    async fn recv(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "UDP not supported in WASM",
        ))
    }
    
    async fn send(&self, _buf: &[u8], _target: &SocketAddr) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "UDP not supported in WASM",
        ))
    }
    
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "UDP not supported in WASM",
        ))
    }
}

// Note: TlsConnector implementation is complex and may need to wait
// until we have proper TLS traits from tor-rtcompat available.
// For now, we stub it at the TlsProvider level in arti_impls.rs

