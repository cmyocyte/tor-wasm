//! TLS support for WASM using rustls
//!
//! Real TLS implementation using rustls with the ring crypto provider.
//! Handles TLS handshake and encryption/decryption for Tor relay connections.
//!
//! Uses a permissive certificate verifier because Tor relays use self-signed
//! certificates. Tor's security comes from its own onion encryption (ntor
//! handshake + AES-CTR), not TLS certificate validation.

use crate::transport::TransportStream;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};
use std::io::{self, Read, Write};
use std::io::Result as IoResult;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// Buffer size for TLS records (max TLS record = 16KB)
const TLS_BUFFER_SIZE: usize = 16384;

// ---------------------------------------------------------------------------
// Permissive certificate verifier (Tor relays use self-signed certs)
// ---------------------------------------------------------------------------

/// Certificate verifier that accepts all certificates.
///
/// This is equivalent to `rejectUnauthorized: false` in Node.js.
/// Tor relays use self-signed certificates, and Tor's security relies on
/// its own onion encryption, not TLS certificate validation.
#[derive(Debug)]
struct TorRelayVerifier;

impl ServerCertVerifier for TorRelayVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// Certificate info (metadata tracking)
// ---------------------------------------------------------------------------

/// Certificate information (for tracking/debugging)
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    /// Server name (from SNI)
    pub server_name: String,

    /// Peer address
    pub peer_addr: Option<SocketAddr>,

    /// Connection timestamp
    pub connected_at: u64,

    /// TLS version
    pub tls_version: String,
}

impl CertificateInfo {
    /// Create certificate info for a connection
    pub fn new(server_name: String, peer_addr: Option<SocketAddr>) -> Self {
        Self {
            server_name,
            peer_addr,
            connected_at: (js_sys::Date::now() / 1000.0) as u64,
            tls_version: "TLS 1.2/1.3 (rustls)".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// WasmTlsStream — real TLS over transport streams
// ---------------------------------------------------------------------------

/// TLS-wrapped stream for WASM using rustls.
///
/// Performs real TLS encryption/decryption over the underlying transport.
/// The handshake is done in `wrap()` before returning the stream.
pub struct WasmTlsStream {
    /// Underlying transport stream (WebSocket, meek, WebTunnel, or WebRTC)
    inner: TransportStream,

    /// Rustls client connection state machine
    tls: ClientConnection,

    /// Decrypted plaintext waiting to be read by the caller
    plaintext_buf: Vec<u8>,

    /// Encrypted data from the network, waiting for rustls to process
    incoming_tls: Vec<u8>,

    /// Encrypted data from rustls, waiting to be written to the network
    outgoing_tls: Vec<u8>,

    /// Total bytes read (plaintext)
    bytes_read: u64,

    /// Total bytes written (plaintext)
    bytes_written: u64,

    /// Certificate metadata
    cert_info: Option<CertificateInfo>,
}

impl WasmTlsStream {
    /// Wrap a transport stream with real TLS encryption.
    ///
    /// Performs the full TLS handshake before returning.
    /// Uses a permissive certificate verifier (Tor relays use self-signed certs).
    pub async fn wrap(
        mut stream: TransportStream,
        server_name: Option<String>,
        peer_addr: Option<SocketAddr>,
    ) -> IoResult<Self> {
        let sni = server_name.clone().unwrap_or_else(|| "www.example.com".to_string());
        log::info!("TLS handshake with {} (rustls, permissive verifier)", sni);

        // Build TLS config with permissive verifier (no cert validation)
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(TorRelayVerifier))
            .with_no_client_auth();

        // Parse server name for SNI (fallback to "www.example.com" if nickname is invalid)
        let server_name_parsed: ServerName<'static> = match sni.clone().try_into() {
            Ok(name) => name,
            Err(_) => {
                log::debug!("  SNI '{}' is not a valid DNS name, using fallback", sni);
                "www.example.com".to_string().try_into().expect("fallback SNI is valid")
            }
        };

        // Create rustls client connection
        let mut tls = ClientConnection::new(Arc::new(config), server_name_parsed)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("TLS init failed: {}", e)))?;

        // Drive the TLS handshake to completion
        loop {
            // 1. Flush any pending outgoing TLS records (ClientHello, etc.)
            let mut tls_output = Vec::new();
            tls.write_tls(&mut tls_output)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("TLS write_tls: {}", e)))?;

            if !tls_output.is_empty() {
                log::info!("  TLS handshake: sending {} bytes to relay", tls_output.len());
                stream.write_all(&tls_output).await?;
                stream.flush().await?;
                log::info!("  TLS handshake: write+flush complete");
            }

            // 2. Check if handshake is done
            if !tls.is_handshaking() {
                break;
            }

            // 3. Read response from relay (ServerHello, etc.)
            if tls.wants_read() {
                log::info!("  TLS handshake: waiting for relay data...");
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).await?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "Connection closed during TLS handshake",
                    ));
                }
                log::info!("  TLS handshake: received {} bytes from relay", n);

                tls.read_tls(&mut &buf[..n])
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("TLS read_tls: {}", e)))?;

                tls.process_new_packets()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("TLS process: {}", e)))?;
            }
        }

        log::info!("TLS handshake complete (protocol: {:?})", tls.protocol_version());

        let cert_info = server_name.map(|name| CertificateInfo::new(name, peer_addr));

        Ok(Self {
            inner: stream,
            tls,
            plaintext_buf: Vec::with_capacity(TLS_BUFFER_SIZE),
            incoming_tls: Vec::with_capacity(TLS_BUFFER_SIZE),
            outgoing_tls: Vec::new(),
            bytes_read: 0,
            bytes_written: 0,
            cert_info,
        })
    }

    /// Get certificate information
    pub fn certificate_info(&self) -> Option<&CertificateInfo> {
        self.cert_info.as_ref()
    }

    /// Check if TLS handshake is complete (always true after construction)
    pub fn is_handshake_done(&self) -> bool {
        true
    }

    /// Get total plaintext bytes read
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    /// Get total plaintext bytes written
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Get connection age in seconds
    pub fn connection_age(&self) -> Option<u64> {
        self.cert_info.as_ref().map(|cert| {
            let now = (js_sys::Date::now() / 1000.0) as u64;
            now.saturating_sub(cert.connected_at)
        })
    }

    /// Try to process any buffered incoming TLS data and extract plaintext
    fn process_incoming(&mut self) -> IoResult<()> {
        if self.incoming_tls.is_empty() {
            return Ok(());
        }

        // Feed encrypted data to rustls
        let consumed = self.tls
            .read_tls(&mut &self.incoming_tls[..])
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("TLS read_tls: {}", e)))?;

        if consumed > 0 {
            self.incoming_tls.drain(..consumed);
        }

        // Process TLS records
        let state = self.tls
            .process_new_packets()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("TLS process: {}", e)))?;

        // Extract any available plaintext
        if state.plaintext_bytes_to_read() > 0 {
            let mut plaintext = vec![0u8; state.plaintext_bytes_to_read()];
            self.tls
                .reader()
                .read_exact(&mut plaintext)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("TLS reader: {}", e)))?;
            self.plaintext_buf.extend_from_slice(&plaintext);
        }

        Ok(())
    }

    /// Extract encrypted TLS data from rustls into outgoing_tls buffer
    fn extract_outgoing(&mut self) -> IoResult<()> {
        if self.tls.wants_write() {
            self.tls
                .write_tls(&mut self.outgoing_tls)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("TLS write_tls: {}", e)))?;
        }
        Ok(())
    }
}

// AsyncRead: decrypt data from the network
impl AsyncRead for WasmTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        let this = &mut *self;

        // 1. Return buffered plaintext if available
        if !this.plaintext_buf.is_empty() {
            let n = std::cmp::min(buf.len(), this.plaintext_buf.len());
            buf[..n].copy_from_slice(&this.plaintext_buf[..n]);
            this.plaintext_buf.drain(..n);
            this.bytes_read += n as u64;
            return Poll::Ready(Ok(n));
        }

        // 2. Loop: read encrypted data + process until we have plaintext or Pending
        loop {
            // Try processing what we already have
            if !this.incoming_tls.is_empty() {
                this.process_incoming()?;
                if !this.plaintext_buf.is_empty() {
                    let n = std::cmp::min(buf.len(), this.plaintext_buf.len());
                    buf[..n].copy_from_slice(&this.plaintext_buf[..n]);
                    this.plaintext_buf.drain(..n);
                    this.bytes_read += n as u64;
                    return Poll::Ready(Ok(n));
                }
            }

            // Read more encrypted data from the inner transport
            let mut tmp = [0u8; 4096];
            match Pin::new(&mut this.inner).poll_read(cx, &mut tmp) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Ok(0)); // EOF
                }
                Poll::Ready(Ok(n)) => {
                    this.incoming_tls.extend_from_slice(&tmp[..n]);
                    // Loop back to process the new data
                }
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    // Waker registered by inner — we'll be woken when data arrives
                    return Poll::Pending;
                }
            }
        }
    }
}

// AsyncWrite: encrypt data and send to the network
impl AsyncWrite for WasmTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<IoResult<usize>> {
        let this = &mut *self;

        // 1. Flush any pending outgoing TLS data first
        while !this.outgoing_tls.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.outgoing_tls) {
                Poll::Ready(Ok(n)) => {
                    this.outgoing_tls.drain(..n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // 2. Write plaintext to rustls (encrypts internally)
        let written = this.tls
            .writer()
            .write(buf)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("TLS writer: {}", e)))?;

        this.bytes_written += written as u64;

        // 3. Extract encrypted TLS records
        this.extract_outgoing()?;

        // 4. Try to write encrypted data to inner transport
        while !this.outgoing_tls.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.outgoing_tls) {
                Poll::Ready(Ok(n)) => {
                    this.outgoing_tls.drain(..n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => break, // Will flush on next call
            }
        }

        Poll::Ready(Ok(written))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        let this = &mut *self;

        // Extract any pending TLS data
        this.extract_outgoing()?;

        // Flush outgoing TLS data to inner stream
        while !this.outgoing_tls.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.outgoing_tls) {
                Poll::Ready(Ok(n)) => {
                    this.outgoing_tls.drain(..n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Flush inner stream
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        let this = &mut *self;

        // Send TLS close_notify
        this.tls.send_close_notify();
        this.extract_outgoing()?;

        // Flush remaining TLS data
        while !this.outgoing_tls.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.outgoing_tls) {
                Poll::Ready(Ok(n)) => {
                    this.outgoing_tls.drain(..n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Close inner stream
        Pin::new(&mut this.inner).poll_close(cx)
    }
}

// ---------------------------------------------------------------------------
// WasmTlsConnector — creates TLS streams
// ---------------------------------------------------------------------------

/// TLS connector for creating TLS streams
#[derive(Clone)]
pub struct WasmTlsConnector;

impl WasmTlsConnector {
    /// Create a new TLS connector
    pub fn new() -> Self {
        Self
    }

    /// Connect with TLS, performing real handshake via rustls
    pub async fn connect(
        &self,
        stream: TransportStream,
        server_name: Option<&str>,
        peer_addr: Option<SocketAddr>,
    ) -> IoResult<WasmTlsStream> {
        WasmTlsStream::wrap(stream, server_name.map(String::from), peer_addr).await
    }

    /// Connect with TLS (simplified version)
    pub async fn connect_simple(
        &self,
        stream: TransportStream,
        server_name: &str,
    ) -> IoResult<WasmTlsStream> {
        self.connect(stream, Some(server_name), None).await
    }
}

impl Default for WasmTlsConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_connector_creation() {
        let _connector = WasmTlsConnector::new();
    }

    #[test]
    fn test_certificate_info() {
        let addr: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let cert = CertificateInfo::new("test.tor".to_string(), Some(addr));
        assert_eq!(cert.server_name, "test.tor");
        assert_eq!(cert.peer_addr, Some(addr));
    }

    #[test]
    fn test_verifier_schemes() {
        let verifier = TorRelayVerifier;
        let schemes = verifier.supported_verify_schemes();
        assert!(!schemes.is_empty());
    }
}
