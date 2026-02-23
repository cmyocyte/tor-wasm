//! Arti trait implementations for WasmRuntime
//!
//! This module implements all tor-rtcompat traits needed for Arti integration

use std::io::{self, Result as IoResult};
use std::net::SocketAddr;
use std::pin::Pin;
use futures::Future;
use futures::io::{AsyncRead, AsyncWrite};
use async_trait::async_trait;
use tor_rtcompat::{NetStreamProvider, UdpProvider, TlsProvider, StreamOps};

use crate::runtime::WasmRuntime;
use crate::transport::WasmTcpStream;

// Implementation 1: NetStreamProvider for regular TCP (SocketAddr)
// Use ?Send since WASM is single-threaded and WebSocket is !Send
#[async_trait(?Send)]
impl NetStreamProvider<SocketAddr> for WasmRuntime {
    type Stream = WasmTcpStream;
    type Listener = crate::runtime::tcp::WasmTcpListener;
    
    async fn connect(
        &self,
        addr: &SocketAddr,
    ) -> IoResult<Self::Stream> {
        let config = crate::transport::BridgeConfig::new(self.bridge_url().to_string());
        let url = config.build_url(addr);
        
        WasmTcpStream::connect(&url)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e.to_string()))
    }
    
    async fn listen(
        &self,
        _addr: &SocketAddr,
    ) -> IoResult<Self::Listener> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TCP listeners not supported in WASM (clients only)",
        ))
    }
}

// Implementation 2: NetStreamProvider for Unix sockets (stub)
#[cfg(unix)]
#[async_trait(?Send)]
impl NetStreamProvider<std::os::unix::net::SocketAddr> for WasmRuntime {
    type Stream = crate::runtime::compat::unix::UnixStream;
    type Listener = crate::runtime::compat::unix::UnixStream; // Dummy
    
    async fn connect(
        &self,
        _addr: &std::os::unix::net::SocketAddr,
    ) -> IoResult<Self::Stream> {
        crate::runtime::compat::unix::UnixStream::unsupported()
    }
    
    async fn listen(
        &self,
        _addr: &std::os::unix::net::SocketAddr,
    ) -> IoResult<Self::Listener> {
        crate::runtime::compat::unix::UnixStream::unsupported()
    }
}

// Implementation 3: TlsProvider (passthrough - browser handles TLS)
impl<S> TlsProvider<S> for WasmRuntime
where
    S: AsyncRead + AsyncWrite + StreamOps + Send + Sync + Unpin + 'static,
{
    type Connector = crate::runtime::compat::WasmTlsConnector;
    type TlsStream = S; // No wrapping needed, browser does TLS
    
    fn tls_connector(&self) -> Self::Connector {
        crate::runtime::compat::WasmTlsConnector::new()
    }
    
    fn supports_keying_material_export(&self) -> bool {
        // WASM/browser TLS doesn't expose keying material
        false
    }
}

// Implementation 4: UdpProvider (stub - not needed for Tor clients)
#[async_trait(?Send)]
impl UdpProvider for WasmRuntime {
    type UdpSocket = crate::runtime::compat::WasmUdpSocket;
    
    async fn bind(&self, _addr: &SocketAddr) -> IoResult<Self::UdpSocket> {
        crate::runtime::compat::WasmUdpSocket::unsupported()
    }
}

