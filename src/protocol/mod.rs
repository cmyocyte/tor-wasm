//! Tor protocol implementation
//!
//! This module implements the actual Tor protocol, including:
//! - Directory consensus fetching and parsing
//! - Circuit building (3-hop onion routing)
//! - ntor handshake (key exchange)
//! - Stream management
//! - Cell protocol
//! - Certificate verification

mod directory;
mod relay;
mod consensus;
mod consensus_verify;
mod cell;
mod ntor;
mod circuit_builder;
mod stream;
mod crypto;
mod flow_control;
mod certs;
mod tls_stream;

pub use directory::DirectoryManager;
pub use relay::{Relay, RelayFlags, RelaySelector};
pub use consensus::{Consensus, ConsensusParser};
pub use cell::{Cell, CellCommand, RelayCell, RelayCommand};
pub use ntor::{NtorHandshake, derive_circuit_keys};
pub use circuit_builder::{Circuit, CircuitBuilder};
pub use stream::{StreamManager, TorStream, StreamBuilder};
pub use crypto::{CircuitKeys, OnionCrypto, derive_circuit_keys as crypto_derive_keys};
pub use flow_control::{CircuitFlowControl, StreamFlowControl};
pub use certs::{CertsCell, CertificateVerifier, VerifiedRelay, Ed25519Certificate};
pub use consensus_verify::{ConsensusVerifier, DirectoryAuthority, DirectorySignature, MIN_AUTHORITY_SIGNATURES};
pub use consensus_verify::DIRECTORY_AUTHORITIES;
pub use tls_stream::TlsTorStream;

/// Default HTTP port for directory queries
pub const DEFAULT_DIR_PORT: u16 = 80;

/// HTTP port variant used by some authorities
pub const FALLBACK_DIR_PORT: u16 = 9030;

/// HTTPS port for encrypted directory queries
pub const SECURE_DIR_PORT: u16 = 443;

