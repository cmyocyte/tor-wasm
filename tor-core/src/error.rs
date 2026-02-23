//! Error types for tor-core

use alloc::string::String;
use core::fmt;

/// Error types for Tor operations
#[derive(Debug)]
pub enum TorError {
    /// Network connection error
    Network(String),
    /// Protocol error (invalid cells, unexpected responses)
    Protocol(String),
    /// Cryptographic error
    Crypto(String),
    /// Circuit build failed
    CircuitFailed(String),
    /// Stream operation failed
    StreamFailed(String),
}

impl fmt::Display for TorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TorError::Network(msg) => write!(f, "Network error: {}", msg),
            TorError::Protocol(msg) => write!(f, "Protocol error: {}", msg),
            TorError::Crypto(msg) => write!(f, "Crypto error: {}", msg),
            TorError::CircuitFailed(msg) => write!(f, "Circuit failed: {}", msg),
            TorError::StreamFailed(msg) => write!(f, "Stream failed: {}", msg),
        }
    }
}

// Note: We don't implement std::error::Error because we're #![no_std]

