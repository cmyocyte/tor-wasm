//! Cooperative TLS Stream
//!
//! TLS over Tor using the cooperative scheduler.
//! Handles the complexity of TLS handshake with proper timeout handling.

use super::stream::CooperativeStream;
use crate::error::{Result, TorError};
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use rustls::pki_types::ServerName;
use std::sync::Arc;
use std::io::{Read, Write};

/// Buffer size for TLS records
const TLS_BUFFER_SIZE: usize = 16384;

/// TLS timeout for handshake (milliseconds)
const TLS_HANDSHAKE_TIMEOUT_MS: u32 = 15_000;

/// TLS stream over a cooperative Tor stream
pub struct CooperativeTlsStream {
    /// Underlying Tor stream
    stream: CooperativeStream,

    /// Rustls connection
    tls: ClientConnection,

    /// Incoming plaintext buffer (decrypted from TLS)
    plaintext_buf: Vec<u8>,

    /// Incoming ciphertext buffer (from network, waiting for TLS processing)
    incoming_tls: Vec<u8>,

    /// Whether handshake is complete
    handshake_complete: bool,
}

impl CooperativeTlsStream {
    /// Create a new TLS stream and perform handshake
    pub async fn new(stream: CooperativeStream, server_name: &str) -> Result<Self> {
        log::info!("🔐 TLS handshake with {} (timeout: {}ms)", server_name, TLS_HANDSHAKE_TIMEOUT_MS);

        // Set aggressive timeouts during handshake
        let stream = stream
            .with_send_timeout(TLS_HANDSHAKE_TIMEOUT_MS)
            .with_recv_timeout(TLS_HANDSHAKE_TIMEOUT_MS);

        // Build root certificate store from Mozilla roots
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        log::debug!("  📜 Loaded {} root certificates", root_store.len());

        // Build TLS config
        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // Parse server name
        let server_name_parsed: ServerName<'static> = server_name
            .to_string()
            .try_into()
            .map_err(|_| TorError::InvalidUrl(format!("Invalid server name: {}", server_name)))?;

        // Create client connection
        let tls = ClientConnection::new(Arc::new(config), server_name_parsed)
            .map_err(|e| TorError::CryptoError(format!("TLS init failed: {}", e)))?;

        let mut tls_stream = Self {
            stream,
            tls,
            plaintext_buf: Vec::with_capacity(TLS_BUFFER_SIZE),
            incoming_tls: Vec::with_capacity(TLS_BUFFER_SIZE),
            handshake_complete: false,
        };

        // Perform handshake
        tls_stream.do_handshake().await?;

        log::info!("✅ TLS handshake complete");

        Ok(tls_stream)
    }

    /// Perform TLS handshake
    async fn do_handshake(&mut self) -> Result<()> {
        log::debug!("  🤝 Starting TLS handshake...");

        loop {
            // Send any pending TLS data
            self.flush_tls_to_network().await?;

            if !self.tls.is_handshaking() {
                self.handshake_complete = true;
                log::debug!("  ✅ TLS handshake complete");
                return Ok(());
            }

            // If handshake needs input, read from network
            if self.tls.wants_read() {
                self.read_tls_from_network().await?;
                self.process_incoming_tls()?;
            }
        }
    }

    /// Flush pending TLS data to the network
    async fn flush_tls_to_network(&mut self) -> Result<()> {
        let mut tls_output = Vec::new();
        self.tls.write_tls(&mut tls_output)
            .map_err(|e| TorError::CryptoError(format!("TLS write error: {}", e)))?;

        if !tls_output.is_empty() {
            log::debug!("    📤 Sending {} bytes of TLS data", tls_output.len());
            self.stream.write_all(&tls_output).await?;
        }

        Ok(())
    }

    /// Read TLS data from the network into our buffer
    async fn read_tls_from_network(&mut self) -> Result<()> {
        let mut buf = [0u8; 498]; // Max Tor cell data size
        let n = self.stream.read(&mut buf).await?;

        if n == 0 {
            return Err(TorError::HandshakeFailed("Connection closed during TLS handshake".into()));
        }

        log::debug!("    📥 Received {} bytes of TLS data from network", n);
        self.incoming_tls.extend_from_slice(&buf[..n]);

        Ok(())
    }

    /// Process buffered incoming TLS data
    fn process_incoming_tls(&mut self) -> Result<()> {
        if self.incoming_tls.is_empty() {
            return Ok(());
        }

        // Feed to rustls
        let processed = self.tls.read_tls(&mut &self.incoming_tls[..])
            .map_err(|e| TorError::CryptoError(format!("TLS read error: {}", e)))?;

        // Remove processed bytes
        self.incoming_tls.drain(..processed);

        // Process the TLS records
        let state = self.tls.process_new_packets()
            .map_err(|e| TorError::CryptoError(format!("TLS process error: {}", e)))?;

        log::debug!("    🔄 Processed {} bytes, {} remaining in buffer",
            processed, self.incoming_tls.len());

        // If there's plaintext available, buffer it
        if state.plaintext_bytes_to_read() > 0 {
            let mut plaintext = vec![0u8; state.plaintext_bytes_to_read()];
            self.tls.reader().read_exact(&mut plaintext)
                .map_err(|e| TorError::CryptoError(format!("TLS plaintext read error: {}", e)))?;
            self.plaintext_buf.extend_from_slice(&plaintext);
        }

        Ok(())
    }

    /// Write plaintext data (will be encrypted)
    pub async fn write(&mut self, data: &[u8]) -> Result<usize> {
        log::debug!("  📤 TLS write: {} bytes", data.len());

        let written = self.tls.writer().write(data)
            .map_err(|e| TorError::Stream(format!("TLS write error: {}", e)))?;

        self.flush_tls_to_network().await?;

        Ok(written)
    }

    /// Write all data (encrypted)
    pub async fn write_all(&mut self, data: &[u8]) -> Result<()> {
        let mut offset = 0;
        while offset < data.len() {
            let written = self.write(&data[offset..]).await?;
            if written == 0 {
                return Err(TorError::Stream("TLS write returned 0".into()));
            }
            offset += written;
        }
        Ok(())
    }

    /// Read plaintext data (decrypted from network)
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        // First, try to satisfy from plaintext buffer
        if !self.plaintext_buf.is_empty() {
            let to_copy = self.plaintext_buf.len().min(buf.len());
            buf[..to_copy].copy_from_slice(&self.plaintext_buf[..to_copy]);
            self.plaintext_buf.drain(..to_copy);
            return Ok(to_copy);
        }

        // Need to read from network
        loop {
            self.read_tls_from_network().await?;
            self.process_incoming_tls()?;

            // Check if we got plaintext
            if !self.plaintext_buf.is_empty() {
                let to_copy = self.plaintext_buf.len().min(buf.len());
                buf[..to_copy].copy_from_slice(&self.plaintext_buf[..to_copy]);
                self.plaintext_buf.drain(..to_copy);
                return Ok(to_copy);
            }

            // Check if connection closed
            if self.stream.is_closed() {
                return Ok(0); // EOF
            }
        }
    }

    /// Read all data until EOF
    pub async fn read_to_end(&mut self) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        let mut buf = [0u8; 4096];

        loop {
            match self.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    result.extend_from_slice(&buf[..n]);
                    log::debug!("    📥 TLS read {} bytes, total {}", n, result.len());
                }
                Err(e) => {
                    // If we have some data, return it
                    if !result.is_empty() {
                        log::warn!("    ⚠️ TLS read error after {} bytes: {}", result.len(), e);
                        break;
                    }
                    return Err(e);
                }
            }
        }

        log::info!("📥 TLS stream read {} total bytes", result.len());
        Ok(result)
    }

    /// Close the TLS connection
    pub async fn close(&mut self) -> Result<()> {
        log::debug!("  🔒 Closing TLS connection");

        self.tls.send_close_notify();
        self.flush_tls_to_network().await?;
        self.stream.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_constants() {
        assert_eq!(TLS_BUFFER_SIZE, 16384);
        assert_eq!(TLS_HANDSHAKE_TIMEOUT_MS, 15_000);
    }
}
