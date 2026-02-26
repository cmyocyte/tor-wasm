//! Error types for Tor WASM client
//!
//! This module provides a comprehensive error taxonomy with:
//! - Detailed error variants for different failure modes
//! - Error classification (fatal vs retryable)
//! - User-friendly messages
//! - Error codes for programmatic handling
//! - Recovery suggestions

use serde::{Deserialize, Serialize};
use thiserror::Error;
use wasm_bindgen::JsValue;

pub type Result<T> = std::result::Result<T, TorError>;

/// Error codes for programmatic handling
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    // Connection errors (1xx)
    ConnectionFailed = 100,
    ConnectionTimeout = 101,
    ConnectionRefused = 102,

    // Protocol errors (2xx)
    ProtocolViolation = 200,
    UnexpectedCell = 201,
    DigestMismatch = 202,
    HandshakeFailed = 203,

    // Circuit errors (3xx)
    CircuitBuildFailed = 300,
    CircuitDestroyed = 301,
    AllRelaysFailed = 302,
    StreamFailed = 303,

    // Security errors (4xx) - FATAL
    CertificateError = 400,
    ConsensusError = 401,
    EntropyError = 402,
    AuthVerificationFailed = 403,

    // Cryptographic errors (5xx)
    CryptoError = 500,
    KeyDerivationFailed = 501,

    // Directory/Consensus errors (6xx)
    DirectoryError = 600,
    ConsensusStale = 601,
    NoRelaysAvailable = 602,

    // Storage errors (7xx)
    StorageError = 700,

    // Configuration errors (8xx)
    ConfigError = 800,
    InvalidRelay = 801,
    InvalidUrl = 802,

    // Internal errors (9xx)
    InternalError = 900,
    NotBootstrapped = 901,
}

/// Main error type for Tor WASM client
#[derive(Error, Debug, Clone)]
pub enum TorError {
    // ===== Connection Errors =====
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Connection timeout")]
    Timeout,

    #[error("Connection refused: {0}")]
    ConnectionRefused(String),

    // ===== Protocol Errors =====
    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Unexpected cell: expected {expected}, got {got}")]
    UnexpectedCell { expected: String, got: String },

    #[error("Digest mismatch in relay cell")]
    DigestMismatch,

    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    // ===== Circuit Errors =====
    #[error("Circuit build failed: {0}")]
    CircuitBuildFailed(String),

    #[error("Circuit destroyed: reason={reason} ({reason_name})")]
    CircuitDestroyed { reason: u8, reason_name: String },

    #[error("All relay candidates failed")]
    AllRelaysFailed,

    #[error("Circuit closed: {0}")]
    CircuitClosed(String),

    #[error("Stream error: {0}")]
    Stream(String),

    // ===== Security Errors (FATAL) =====
    #[error("Certificate verification failed: {0}")]
    CertificateError(String),

    #[error("Consensus verification failed: {0}")]
    ConsensusError(String),

    #[error("Entropy/RNG failure: {0}")]
    EntropyError(String),

    #[error("Auth verification failed: {0}")]
    AuthVerificationFailed(String),

    // ===== Cryptographic Errors =====
    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Crypto: {0}")]
    Crypto(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    // ===== Directory/Consensus Errors =====
    #[error("Directory error: {0}")]
    Directory(String),

    #[error("Consensus is stale (expired)")]
    ConsensusStale,

    #[error("No relays available: {0}")]
    NoRelaysAvailable(String),

    // ===== Storage Errors =====
    #[error("Storage error: {0}")]
    Storage(String),

    // ===== Configuration Errors =====
    #[error("Invalid relay: {0}")]
    InvalidRelay(String),

    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    // ===== Network Errors =====
    #[error("Network error: {0}")]
    Network(String),

    // ===== Internal Errors =====
    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Client not bootstrapped")]
    NotBootstrapped,

    // ===== State Errors =====
    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),
}

impl TorError {
    /// Get the error code for programmatic handling
    pub fn code(&self) -> ErrorCode {
        match self {
            // Connection
            TorError::ConnectionFailed(_) => ErrorCode::ConnectionFailed,
            TorError::Timeout => ErrorCode::ConnectionTimeout,
            TorError::ConnectionRefused(_) => ErrorCode::ConnectionRefused,

            // Protocol
            TorError::ProtocolError(_) => ErrorCode::ProtocolViolation,
            TorError::UnexpectedCell { .. } => ErrorCode::UnexpectedCell,
            TorError::DigestMismatch => ErrorCode::DigestMismatch,
            TorError::HandshakeFailed(_) => ErrorCode::HandshakeFailed,

            // Circuit
            TorError::CircuitBuildFailed(_) => ErrorCode::CircuitBuildFailed,
            TorError::CircuitDestroyed { .. } => ErrorCode::CircuitDestroyed,
            TorError::AllRelaysFailed => ErrorCode::AllRelaysFailed,
            TorError::CircuitClosed(_) => ErrorCode::CircuitDestroyed,
            TorError::Stream(_) => ErrorCode::StreamFailed,

            // Security (fatal)
            TorError::CertificateError(_) => ErrorCode::CertificateError,
            TorError::ConsensusError(_) => ErrorCode::ConsensusError,
            TorError::EntropyError(_) => ErrorCode::EntropyError,
            TorError::AuthVerificationFailed(_) => ErrorCode::AuthVerificationFailed,

            // Crypto
            TorError::CryptoError(_) | TorError::Crypto(_) => ErrorCode::CryptoError,
            TorError::KeyDerivationFailed(_) => ErrorCode::KeyDerivationFailed,

            // Directory
            TorError::Directory(_) => ErrorCode::DirectoryError,
            TorError::ConsensusStale => ErrorCode::ConsensusStale,
            TorError::NoRelaysAvailable(_) => ErrorCode::NoRelaysAvailable,

            // Storage
            TorError::Storage(_) => ErrorCode::StorageError,

            // Config
            TorError::InvalidRelay(_) => ErrorCode::InvalidRelay,
            TorError::InvalidUrl(_) => ErrorCode::InvalidUrl,
            TorError::ParseError(_) => ErrorCode::ConfigError,

            // Network
            TorError::Network(_) => ErrorCode::ConnectionFailed,

            // Internal
            TorError::Internal(_) => ErrorCode::InternalError,
            TorError::NotBootstrapped => ErrorCode::NotBootstrapped,

            // State
            TorError::InvalidState(_) => ErrorCode::InternalError,
            TorError::ResourceExhausted(_) => ErrorCode::CircuitBuildFailed,
        }
    }

    /// Whether this error is fatal (should abort the entire client)
    ///
    /// Fatal errors indicate security problems or unrecoverable states.
    /// The client should be destroyed and recreated after a fatal error.
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            TorError::CertificateError(_)
                | TorError::ConsensusError(_)
                | TorError::EntropyError(_)
                | TorError::AuthVerificationFailed(_)
        )
    }

    /// Whether this error can be retried with different relays
    ///
    /// Retryable errors are typically transient network or relay issues.
    /// The client can try again with different relays.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            TorError::ConnectionFailed(_)
                | TorError::Timeout
                | TorError::ConnectionRefused(_)
                | TorError::CircuitBuildFailed(_)
                | TorError::CircuitDestroyed { .. }
                | TorError::CircuitClosed(_)
                | TorError::Network(_)
                | TorError::HandshakeFailed(_)
                | TorError::Stream(_)
        )
    }

    /// Whether this error requires user action (configuration change, etc.)
    pub fn requires_user_action(&self) -> bool {
        matches!(
            self,
            TorError::NotBootstrapped
                | TorError::InvalidUrl(_)
                | TorError::InvalidRelay(_)
                | TorError::ConsensusStale
        )
    }

    /// Get a user-friendly message for display
    pub fn user_message(&self) -> String {
        match self {
            // Connection
            TorError::ConnectionFailed(_) => {
                "Failed to connect to the Tor network. Please check your internet connection."
                    .into()
            }
            TorError::Timeout => {
                "Connection timed out. The Tor network may be slow or unreachable.".into()
            }
            TorError::ConnectionRefused(_) => {
                "Connection was refused. The relay may be offline.".into()
            }

            // Protocol
            TorError::ProtocolError(_) => "A protocol error occurred. Please try again.".into(),
            TorError::UnexpectedCell { .. } => {
                "Received unexpected data from the Tor network.".into()
            }
            TorError::DigestMismatch => "Data integrity check failed. Please try again.".into(),
            TorError::HandshakeFailed(_) => {
                "Failed to establish secure connection. Please try again.".into()
            }

            // Circuit
            TorError::CircuitBuildFailed(_) => {
                "Failed to build a secure circuit. Please try again.".into()
            }
            TorError::CircuitDestroyed { reason, .. } => format!(
                "Your circuit was closed by a relay (reason {}). Please try again.",
                reason
            ),
            TorError::AllRelaysFailed => {
                "All available relays failed. Please try again later.".into()
            }
            TorError::CircuitClosed(_) => "Your circuit was closed. Please try again.".into(),
            TorError::Stream(_) => "Data transfer failed. Please try again.".into(),

            // Security (fatal)
            TorError::CertificateError(_) => {
                "⚠️ SECURITY ERROR: Relay certificate verification failed. Do not continue!".into()
            }
            TorError::ConsensusError(_) => {
                "⚠️ SECURITY ERROR: Network consensus verification failed. Do not continue!".into()
            }
            TorError::EntropyError(_) => {
                "⚠️ SECURITY ERROR: Random number generation failed. Do not continue!".into()
            }
            TorError::AuthVerificationFailed(_) => {
                "⚠️ SECURITY ERROR: Authentication verification failed. Do not continue!".into()
            }

            // Crypto
            TorError::CryptoError(_) | TorError::Crypto(_) => {
                "A cryptographic error occurred. Please try again.".into()
            }
            TorError::KeyDerivationFailed(_) => {
                "Failed to derive encryption keys. Please try again.".into()
            }

            // Directory
            TorError::Directory(_) => {
                "Failed to fetch Tor network directory. Please try again.".into()
            }
            TorError::ConsensusStale => {
                "Network information is outdated. Please restart the client.".into()
            }
            TorError::NoRelaysAvailable(_) => {
                "No suitable relays are available. Please try again later.".into()
            }

            // Storage
            TorError::Storage(_) => {
                "Failed to save/load data. Please check browser storage permissions.".into()
            }

            // Config
            TorError::InvalidRelay(_) => {
                "Invalid relay configuration. Please check your settings.".into()
            }
            TorError::InvalidUrl(_) => "Invalid URL provided. Please check the URL format.".into(),
            TorError::ParseError(_) => "Failed to parse data. Please check your input.".into(),

            // Network
            TorError::Network(_) => {
                "A network error occurred. Please check your internet connection.".into()
            }

            // Internal
            TorError::Internal(_) => "An internal error occurred. Please report this bug.".into(),
            TorError::NotBootstrapped => {
                "The Tor client has not been initialized. Please call bootstrap() first.".into()
            }

            // State
            TorError::InvalidState(_) => {
                "The client is in an invalid state. Please restart and try again.".into()
            }
            TorError::ResourceExhausted(_) => {
                "Too many requests. Please wait a moment and try again.".into()
            }
        }
    }

    /// Get a recovery suggestion for this error
    pub fn recovery_suggestion(&self) -> String {
        match self {
            // Retryable
            err if err.is_retryable() =>
                "This error is usually temporary. Please wait a moment and try again.".into(),

            // Fatal
            err if err.is_fatal() =>
                "This is a security error. Please close the client and do not continue until investigated.".into(),

            // User action required
            TorError::NotBootstrapped =>
                "Call `bootstrap()` to initialize the Tor client before making requests.".into(),
            TorError::ConsensusStale =>
                "Call `bootstrap()` again to refresh the network directory.".into(),
            TorError::InvalidUrl(_) =>
                "Use a valid HTTP or HTTPS URL (e.g., https://example.com).".into(),
            TorError::Storage(_) =>
                "Check that your browser allows localStorage. Try clearing site data.".into(),

            // Default
            _ => "Please try again. If the problem persists, report a bug.".into(),
        }
    }

    /// Create a CircuitDestroyed error with the reason name
    pub fn circuit_destroyed(reason: u8) -> Self {
        let reason_name = match reason {
            0 => "NONE",
            1 => "PROTOCOL",
            2 => "INTERNAL",
            3 => "REQUESTED",
            4 => "HIBERNATING",
            5 => "RESOURCELIMIT",
            6 => "CONNECTFAILED",
            7 => "OR_IDENTITY",
            8 => "CHANNEL_CLOSED",
            9 => "FINISHED",
            10 => "TIMEOUT",
            11 => "DESTROYED",
            12 => "NOSUCHSERVICE",
            _ => "UNKNOWN",
        }
        .to_string();

        TorError::CircuitDestroyed {
            reason,
            reason_name,
        }
    }
}

impl From<TorError> for JsValue {
    fn from(err: TorError) -> Self {
        JsValue::from_str(&err.to_string())
    }
}

/// Error information for JavaScript consumption
#[derive(Serialize, Deserialize)]
pub struct ErrorInfo {
    pub code: u32,
    pub message: String,
    pub user_message: String,
    pub recovery_suggestion: String,
    pub is_fatal: bool,
    pub is_retryable: bool,
}

impl From<&TorError> for ErrorInfo {
    fn from(err: &TorError) -> Self {
        ErrorInfo {
            code: err.code() as u32,
            message: err.to_string(),
            user_message: err.user_message(),
            recovery_suggestion: err.recovery_suggestion(),
            is_fatal: err.is_fatal(),
            is_retryable: err.is_retryable(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fatal_errors() {
        assert!(TorError::CertificateError("test".into()).is_fatal());
        assert!(TorError::ConsensusError("test".into()).is_fatal());
        assert!(TorError::EntropyError("test".into()).is_fatal());
        assert!(TorError::AuthVerificationFailed("test".into()).is_fatal());

        // Non-fatal errors
        assert!(!TorError::ConnectionFailed("test".into()).is_fatal());
        assert!(!TorError::Timeout.is_fatal());
    }

    #[test]
    fn test_retryable_errors() {
        assert!(TorError::ConnectionFailed("test".into()).is_retryable());
        assert!(TorError::Timeout.is_retryable());
        assert!(TorError::CircuitBuildFailed("test".into()).is_retryable());

        // Non-retryable errors
        assert!(!TorError::CertificateError("test".into()).is_retryable());
        assert!(!TorError::NotBootstrapped.is_retryable());
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(
            TorError::ConnectionFailed("test".into()).code(),
            ErrorCode::ConnectionFailed
        );
        assert_eq!(TorError::Timeout.code(), ErrorCode::ConnectionTimeout);
        assert_eq!(
            TorError::CertificateError("test".into()).code(),
            ErrorCode::CertificateError
        );
    }

    #[test]
    fn test_circuit_destroyed() {
        let err = TorError::circuit_destroyed(1);
        if let TorError::CircuitDestroyed {
            reason,
            reason_name,
        } = err
        {
            assert_eq!(reason, 1);
            assert_eq!(reason_name, "PROTOCOL");
        } else {
            panic!("Expected CircuitDestroyed");
        }
    }
}
