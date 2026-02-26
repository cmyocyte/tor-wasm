//! Enhanced error handling for network operations
//!
//! Provides detailed error types and recovery strategies.

use std::fmt;
use std::io;

/// Network error types with detailed context
#[derive(Debug, Clone)]
pub enum NetworkError {
    /// Connection failed to establish
    ConnectionFailed {
        target: String,
        reason: String,
        retry_count: u32,
    },

    /// Connection timeout
    Timeout { target: String, timeout_ms: u32 },

    /// Bridge server unavailable
    BridgeUnavailable { bridge_url: String, reason: String },

    /// TLS error
    TlsError { target: String, reason: String },

    /// Protocol error (invalid data received)
    ProtocolError { details: String },

    /// Connection closed unexpectedly
    ConnectionClosed {
        bytes_sent: u64,
        bytes_received: u64,
    },

    /// Pool exhausted
    PoolExhausted { max_connections: usize },

    /// Invalid address
    InvalidAddress { address: String },
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkError::ConnectionFailed {
                target,
                reason,
                retry_count,
            } => {
                write!(
                    f,
                    "Failed to connect to {} after {} retries: {}",
                    target, retry_count, reason
                )
            }
            NetworkError::Timeout { target, timeout_ms } => {
                write!(
                    f,
                    "Connection to {} timed out after {}ms",
                    target, timeout_ms
                )
            }
            NetworkError::BridgeUnavailable { bridge_url, reason } => {
                write!(f, "Bridge server at {} unavailable: {}", bridge_url, reason)
            }
            NetworkError::TlsError { target, reason } => {
                write!(f, "TLS error connecting to {}: {}", target, reason)
            }
            NetworkError::ProtocolError { details } => {
                write!(f, "Protocol error: {}", details)
            }
            NetworkError::ConnectionClosed {
                bytes_sent,
                bytes_received,
            } => {
                write!(
                    f,
                    "Connection closed unexpectedly (sent: {}, received: {})",
                    bytes_sent, bytes_received
                )
            }
            NetworkError::PoolExhausted { max_connections } => {
                write!(f, "Connection pool exhausted (max: {})", max_connections)
            }
            NetworkError::InvalidAddress { address } => {
                write!(f, "Invalid address: {}", address)
            }
        }
    }
}

impl std::error::Error for NetworkError {}

impl From<NetworkError> for io::Error {
    fn from(err: NetworkError) -> Self {
        let kind = match &err {
            NetworkError::ConnectionFailed { .. } => io::ErrorKind::ConnectionRefused,
            NetworkError::Timeout { .. } => io::ErrorKind::TimedOut,
            NetworkError::BridgeUnavailable { .. } => io::ErrorKind::NotConnected,
            NetworkError::TlsError { .. } => io::ErrorKind::InvalidData,
            NetworkError::ProtocolError { .. } => io::ErrorKind::InvalidData,
            NetworkError::ConnectionClosed { .. } => io::ErrorKind::ConnectionReset,
            NetworkError::PoolExhausted { .. } => io::ErrorKind::WouldBlock,
            NetworkError::InvalidAddress { .. } => io::ErrorKind::InvalidInput,
        };

        io::Error::new(kind, err.to_string())
    }
}

/// Error recovery strategy
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RecoveryStrategy {
    /// Retry the operation
    Retry,

    /// Retry with exponential backoff
    RetryWithBackoff,

    /// Try a different target (e.g., different directory authority)
    TryAlternative,

    /// Fail immediately
    Fail,

    /// Attempt reconnection
    Reconnect,
}

impl NetworkError {
    /// Get the recommended recovery strategy for this error
    pub fn recovery_strategy(&self) -> RecoveryStrategy {
        match self {
            NetworkError::ConnectionFailed { retry_count, .. } => {
                if *retry_count < 3 {
                    RecoveryStrategy::RetryWithBackoff
                } else {
                    RecoveryStrategy::TryAlternative
                }
            }
            NetworkError::Timeout { .. } => RecoveryStrategy::Retry,
            NetworkError::BridgeUnavailable { .. } => RecoveryStrategy::Fail,
            NetworkError::TlsError { .. } => RecoveryStrategy::Reconnect,
            NetworkError::ProtocolError { .. } => RecoveryStrategy::TryAlternative,
            NetworkError::ConnectionClosed { .. } => RecoveryStrategy::Reconnect,
            NetworkError::PoolExhausted { .. } => RecoveryStrategy::Retry,
            NetworkError::InvalidAddress { .. } => RecoveryStrategy::Fail,
        }
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        !matches!(self.recovery_strategy(), RecoveryStrategy::Fail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = NetworkError::ConnectionFailed {
            target: "127.0.0.1:9001".to_string(),
            reason: "refused".to_string(),
            retry_count: 2,
        };

        let msg = err.to_string();
        assert!(msg.contains("127.0.0.1:9001"));
        assert!(msg.contains("2 retries"));
    }

    #[test]
    fn test_recovery_strategy() {
        let err = NetworkError::Timeout {
            target: "test".to_string(),
            timeout_ms: 5000,
        };

        assert_eq!(err.recovery_strategy(), RecoveryStrategy::Retry);
        assert!(err.is_recoverable());
    }

    #[test]
    fn test_non_recoverable() {
        let err = NetworkError::InvalidAddress {
            address: "invalid".to_string(),
        };

        assert_eq!(err.recovery_strategy(), RecoveryStrategy::Fail);
        assert!(!err.is_recoverable());
    }
}
