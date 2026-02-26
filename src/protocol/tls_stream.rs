//! TLS-over-Tor stream implementation using rustls
//!
//! This module provides TLS encryption over Tor circuits using rustls.
//! Enabled with ring 0.17's experimental WASM support and rustls-pki-types web feature.

use super::stream::TorStream;
use crate::error::{Result, TorError};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use std::io::{Read, Write};
use std::sync::Arc;

/// Buffer size for TLS records
const TLS_BUFFER_SIZE: usize = 16384;

/// TLS-wrapped Tor stream for HTTPS connections
pub struct TlsTorStream {
    /// The underlying Tor stream
    stream: TorStream,

    /// Rustls client connection
    tls: ClientConnection,

    /// Incoming plaintext buffer (decrypted from TLS)
    plaintext_buf: Vec<u8>,

    /// Incoming ciphertext buffer (from network, waiting for TLS processing)
    incoming_tls: Vec<u8>,
}

impl TlsTorStream {
    /// Create a new TLS stream over a Tor connection
    pub async fn new(stream: TorStream, server_name: &str) -> Result<Self> {
        log::info!("🔐 Initiating TLS handshake with {}", server_name);

        // Build root certificate store from Mozilla roots
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        log::debug!("  📜 Loaded {} root certificates", root_store.len());

        // Build TLS config with ring crypto provider (now std API works!)
        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // Parse server name
        let server_name_parsed: ServerName<'static> = server_name
            .to_string()
            .try_into()
            .map_err(|_| TorError::Network(format!("Invalid server name: {}", server_name)))?;

        // Create client connection
        let tls = ClientConnection::new(Arc::new(config), server_name_parsed)
            .map_err(|e| TorError::Network(format!("TLS error: {}", e)))?;

        let mut tls_stream = Self {
            stream,
            tls,
            plaintext_buf: Vec::with_capacity(TLS_BUFFER_SIZE),
            incoming_tls: Vec::with_capacity(TLS_BUFFER_SIZE),
        };

        // Perform TLS handshake
        tls_stream.handshake().await?;

        log::info!("✅ TLS handshake complete with {}", server_name);

        Ok(tls_stream)
    }

    /// Perform TLS handshake
    async fn handshake(&mut self) -> Result<()> {
        log::debug!("  🤝 Starting TLS handshake...");

        // Loop until handshake is complete
        while self.tls.is_handshaking() {
            // First, send any pending TLS data to the server
            self.flush_tls_output().await?;

            // If handshake needs more input, read from network
            if self.tls.is_handshaking() && self.tls.wants_read() {
                self.read_tls_from_network().await?;
                self.process_incoming_tls()?;
            }
        }

        // Final flush of any remaining TLS data
        self.flush_tls_output().await?;

        log::debug!("  ✅ TLS handshake complete");
        Ok(())
    }

    /// Send any pending TLS output to the network
    async fn flush_tls_output(&mut self) -> Result<()> {
        // Read TLS records from rustls and send over Tor
        let mut tls_output = Vec::new();
        self.tls
            .write_tls(&mut tls_output)
            .map_err(|e| TorError::Network(format!("TLS write error: {}", e)))?;

        if !tls_output.is_empty() {
            log::debug!("    📤 Sending {} bytes of TLS data", tls_output.len());
            self.stream.write_all(&tls_output).await?;
        }

        Ok(())
    }

    /// Read TLS data from the network into our buffer
    async fn read_tls_from_network(&mut self) -> Result<()> {
        let mut buf = [0u8; 498]; // Max Tor cell data size
        let n = self.stream.recv_data(&mut buf).await?;

        if n == 0 {
            return Err(TorError::Network(
                "Connection closed during TLS handshake".into(),
            ));
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
        let processed = self
            .tls
            .read_tls(&mut &self.incoming_tls[..])
            .map_err(|e| TorError::Network(format!("TLS read error: {}", e)))?;

        // Remove processed bytes
        self.incoming_tls.drain(..processed);

        // Process the TLS records
        let state = self
            .tls
            .process_new_packets()
            .map_err(|e| TorError::Network(format!("TLS processing error: {}", e)))?;

        log::debug!(
            "    🔄 Processed {} bytes, {:?} remaining in buffer",
            processed,
            self.incoming_tls.len()
        );

        // If there's plaintext available, buffer it
        if state.plaintext_bytes_to_read() > 0 {
            let mut plaintext = vec![0u8; state.plaintext_bytes_to_read()];
            self.tls
                .reader()
                .read_exact(&mut plaintext)
                .map_err(|e| TorError::Network(format!("TLS plaintext read error: {}", e)))?;
            self.plaintext_buf.extend_from_slice(&plaintext);
        }

        Ok(())
    }

    /// Write application data through the TLS stream
    pub async fn write(&mut self, data: &[u8]) -> Result<usize> {
        log::debug!("  📤 TLS write: {} bytes", data.len());

        // Write to rustls writer
        let written = self
            .tls
            .writer()
            .write(data)
            .map_err(|e| TorError::Network(format!("TLS write error: {}", e)))?;

        // Flush TLS output to network
        self.flush_tls_output().await?;

        Ok(written)
    }

    /// Write all data through the TLS stream
    pub async fn write_all(&mut self, data: &[u8]) -> Result<()> {
        let mut offset = 0;
        while offset < data.len() {
            let written = self.write(&data[offset..]).await?;
            if written == 0 {
                return Err(TorError::Network("TLS write returned 0".into()));
            }
            offset += written;
        }
        Ok(())
    }

    /// Read data from the TLS stream
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
            // Read TLS data from network
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
                return Ok(0);
            }
        }
    }

    /// Read until connection closes (for HTTP responses)
    pub async fn read_to_end(&mut self) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        let mut buf = [0u8; 4096];

        loop {
            match self.read(&mut buf).await {
                Ok(0) => break, // EOF
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

        Ok(result)
    }

    /// Close the TLS connection
    pub async fn close(&mut self) -> Result<()> {
        log::debug!("  🔒 Closing TLS connection");

        // Send TLS close_notify
        self.tls.send_close_notify();
        self.flush_tls_output().await?;

        // Close underlying stream
        self.stream.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_buffer_size() {
        // TLS record max size is 16KB
        assert_eq!(TLS_BUFFER_SIZE, 16384);
    }
}
