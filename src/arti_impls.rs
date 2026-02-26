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
use crate::transport::{WasmTcpStream, WasmMeekStream, WasmWebTunnelStream, TransportStream};

// Implementation 1: NetStreamProvider for regular TCP (SocketAddr)
// Use ?Send since WASM is single-threaded and WebSocket is !Send
//
// Transport fallback chain:
//   1. WebSocket (fastest, default)
//   2. WebTunnel (HTTPS disguised as normal website — if configured)
//   3. meek via CDN (if WebSocket/WebTunnel fail and meek_url is configured)
//
// This ensures connectivity even when censors block WebSocket/ECH.
#[async_trait(?Send)]
impl NetStreamProvider<SocketAddr> for WasmRuntime {
    type Stream = TransportStream;
    type Listener = crate::runtime::tcp::WasmTcpListener;

    async fn connect(
        &self,
        addr: &SocketAddr,
    ) -> IoResult<Self::Stream> {
        // Try WebSocket first (fast path)
        let config = crate::transport::BridgeConfig::new(self.bridge_url().to_string());
        let url = config.build_url(addr);

        match WasmTcpStream::connect(&url).await {
            Ok(stream) => {
                log::debug!("WebSocket connected to {}", addr);
                return Ok(TransportStream::WebSocket(stream));
            }
            Err(ws_err) => {
                log::warn!("WebSocket connect failed ({})", ws_err);

                // Try WebTunnel if configured (looks like normal HTTPS)
                if let (Some(wt_url), Some(wt_path)) = (self.webtunnel_url(), self.webtunnel_path()) {
                    log::info!("Trying WebTunnel transport...");
                    match WasmWebTunnelStream::connect(wt_url, wt_path).await {
                        Ok(wt_stream) => {
                            log::info!("WebTunnel connected to {}", addr);
                            return Ok(TransportStream::WebTunnel(wt_stream));
                        }
                        Err(wt_err) => {
                            log::warn!("WebTunnel failed: {}", wt_err);
                        }
                    }
                }

                // Try meek fallback (HTTP POST through CDN)
                if let Some(meek_url) = self.meek_url() {
                    log::info!("Trying meek transport...");
                    let target = format!("{}", addr);
                    match WasmMeekStream::connect(meek_url, &target).await {
                        Ok(meek_stream) => {
                            log::info!("meek transport connected to {}", addr);
                            return Ok(TransportStream::Meek(meek_stream));
                        }
                        Err(meek_err) => {
                            log::error!(
                                "meek fallback also failed: {}. All transports exhausted.",
                                meek_err
                            );
                        }
                    }
                }

                Err(io::Error::new(io::ErrorKind::ConnectionRefused, ws_err.to_string()))
            }
        }
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

