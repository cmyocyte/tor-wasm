//! Tor protocol implementation
//!
//! This module implements the actual Tor protocol, including:
//! - Directory consensus fetching and parsing
//! - Circuit building (3-hop onion routing)
//! - ntor handshake (key exchange)
//! - Stream management
//! - Cell protocol
//! - Certificate verification

mod cell;
mod certs;
mod circuit_builder;
mod consensus;
mod consensus_verify;
mod crypto;
mod directory;
mod flow_control;
mod ntor;
mod relay;
mod stream;
mod tls_stream;

pub use cell::{Cell, CellCommand, RelayCell, RelayCommand};
pub use certs::{CertificateVerifier, CertsCell, Ed25519Certificate, VerifiedRelay};
pub use circuit_builder::{Circuit, CircuitBuilder};
pub use consensus::{Consensus, ConsensusParser};
pub use consensus_verify::DIRECTORY_AUTHORITIES;
pub use consensus_verify::{
    ConsensusVerifier, DirectoryAuthority, DirectorySignature, MIN_AUTHORITY_SIGNATURES,
};
pub use crypto::{derive_circuit_keys as crypto_derive_keys, CircuitKeys, OnionCrypto};
pub use directory::DirectoryManager;
pub use flow_control::{CircuitFlowControl, StreamFlowControl};
pub use ntor::{derive_circuit_keys, NtorHandshake};
pub use relay::{Relay, RelayFlags, RelaySelector};
pub use stream::{StreamBuilder, StreamManager, TorStream};
pub use tls_stream::TlsTorStream;

/// Default HTTP port for directory queries
pub const DEFAULT_DIR_PORT: u16 = 80;

/// HTTP port variant used by some authorities
pub const FALLBACK_DIR_PORT: u16 = 9030;

/// HTTPS port for encrypted directory queries
pub const SECURE_DIR_PORT: u16 = 443;
