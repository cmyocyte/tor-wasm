//! Tor cell protocol
//!
//! Implements the Tor cell format for communication with relays.
//! Cells are the basic unit of communication in the Tor protocol.

use crate::error::{Result, TorError};
use std::io::Write;

/// Cell command types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CellCommand {
    /// PADDING - used for padding
    Padding = 0,
    /// CREATE - create a circuit (deprecated)
    Create = 1,
    /// CREATED - circuit created (deprecated)
    Created = 2,
    /// RELAY - relay cell
    Relay = 3,
    /// DESTROY - destroy a circuit
    Destroy = 4,
    /// CREATE_FAST - fast circuit creation (deprecated)
    CreateFast = 5,
    /// CREATED_FAST - fast circuit created (deprecated)
    CreatedFast = 6,
    /// VERSIONS - negotiate versions
    Versions = 7,
    /// NETINFO - network info exchange
    Netinfo = 8,
    /// RELAY_EARLY - relay cell that can be sent early
    RelayEarly = 9,
    /// CREATE2 - create a circuit (current)
    Create2 = 10,
    /// CREATED2 - circuit created (current)
    Created2 = 11,
    /// PADDING_NEGOTIATE - negotiate padding
    PaddingNegotiate = 12,
    /// VPADDING - variable-length padding
    Vpadding = 128,
    /// CERTS - certificate cell
    Certs = 129,
    /// AUTH_CHALLENGE - authentication challenge
    AuthChallenge = 130,
    /// AUTHENTICATE - authenticate
    Authenticate = 131,
    /// AUTHORIZE - authorize
    Authorize = 132,
}

impl CellCommand {
    /// Parse command from byte
    pub fn from_u8(cmd: u8) -> Option<Self> {
        match cmd {
            0 => Some(CellCommand::Padding),
            1 => Some(CellCommand::Create),
            2 => Some(CellCommand::Created),
            3 => Some(CellCommand::Relay),
            4 => Some(CellCommand::Destroy),
            5 => Some(CellCommand::CreateFast),
            6 => Some(CellCommand::CreatedFast),
            7 => Some(CellCommand::Versions),
            8 => Some(CellCommand::Netinfo),
            9 => Some(CellCommand::RelayEarly),
            10 => Some(CellCommand::Create2),
            11 => Some(CellCommand::Created2),
            12 => Some(CellCommand::PaddingNegotiate),
            128 => Some(CellCommand::Vpadding),
            129 => Some(CellCommand::Certs),
            130 => Some(CellCommand::AuthChallenge),
            131 => Some(CellCommand::Authenticate),
            132 => Some(CellCommand::Authorize),
            _ => None,
        }
    }
}

/// Tor cell
#[derive(Debug, Clone)]
pub struct Cell {
    /// Circuit ID (4 bytes for v4+ protocol)
    pub circuit_id: u32,

    /// Command
    pub command: CellCommand,

    /// Payload (509 bytes for fixed-length cells)
    pub payload: Vec<u8>,
}

impl Cell {
    /// Cell size (514 bytes total: 4 circuit_id + 1 command + 509 payload)
    pub const SIZE: usize = 514;

    /// Payload size for fixed-length cells
    pub const PAYLOAD_SIZE: usize = 509;

    /// Create a new cell
    pub fn new(circuit_id: u32, command: CellCommand, payload: Vec<u8>) -> Self {
        Self {
            circuit_id,
            command,
            payload,
        }
    }

    /// Create a RELAY cell
    pub fn relay(circuit_id: u32, relay_payload: Vec<u8>) -> Self {
        Self::new(circuit_id, CellCommand::Relay, relay_payload)
    }

    /// Serialize cell to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(Self::SIZE);

        // Circuit ID (4 bytes, big-endian)
        buf.write_all(&self.circuit_id.to_be_bytes())
            .map_err(|e| TorError::Internal(format!("Write circuit_id failed: {}", e)))?;

        // Command (1 byte)
        buf.push(self.command as u8);

        // Payload (pad to 509 bytes)
        buf.write_all(&self.payload)
            .map_err(|e| TorError::Internal(format!("Write payload failed: {}", e)))?;

        // Pad to fixed size
        while buf.len() < Self::SIZE {
            buf.push(0);
        }

        Ok(buf)
    }

    /// Parse cell from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(TorError::ProtocolError("Cell too short".into()));
        }

        // Parse circuit ID (4 bytes, big-endian)
        let circuit_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

        // Parse command
        let command = CellCommand::from_u8(data[4])
            .ok_or_else(|| TorError::ProtocolError(format!("Unknown command: {}", data[4])))?;

        // Parse payload
        let payload = data[5..Self::SIZE].to_vec();

        Ok(Self {
            circuit_id,
            command,
            payload,
        })
    }
}

/// Relay command types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RelayCommand {
    /// BEGIN - open stream
    Begin = 1,
    /// DATA - relay data
    Data = 2,
    /// END - close stream
    End = 3,
    /// CONNECTED - stream connected
    Connected = 4,
    /// SENDME - flow control
    Sendme = 5,
    /// EXTEND - extend circuit (deprecated)
    Extend = 6,
    /// EXTENDED - circuit extended (deprecated)
    Extended = 7,
    /// TRUNCATE - truncate circuit
    Truncate = 8,
    /// TRUNCATED - circuit truncated
    Truncated = 9,
    /// DROP - drop cell
    Drop = 10,
    /// RESOLVE - DNS resolve
    Resolve = 11,
    /// RESOLVED - DNS resolved
    Resolved = 12,
    /// BEGIN_DIR - begin directory connection
    BeginDir = 13,
    /// EXTEND2 - extend circuit (current)
    Extend2 = 14,
    /// EXTENDED2 - circuit extended (current)
    Extended2 = 15,
}

impl RelayCommand {
    /// Parse relay command from byte
    pub fn from_u8(cmd: u8) -> Option<Self> {
        match cmd {
            1 => Some(RelayCommand::Begin),
            2 => Some(RelayCommand::Data),
            3 => Some(RelayCommand::End),
            4 => Some(RelayCommand::Connected),
            5 => Some(RelayCommand::Sendme),
            6 => Some(RelayCommand::Extend),
            7 => Some(RelayCommand::Extended),
            8 => Some(RelayCommand::Truncate),
            9 => Some(RelayCommand::Truncated),
            10 => Some(RelayCommand::Drop),
            11 => Some(RelayCommand::Resolve),
            12 => Some(RelayCommand::Resolved),
            13 => Some(RelayCommand::BeginDir),
            14 => Some(RelayCommand::Extend2),
            15 => Some(RelayCommand::Extended2),
            _ => None,
        }
    }
}

/// Relay cell (payload within a RELAY or RELAY_EARLY cell)
#[derive(Debug, Clone)]
pub struct RelayCell {
    /// Relay command
    pub command: RelayCommand,

    /// Recognized (always 0 for outgoing)
    pub recognized: u16,

    /// Stream ID
    pub stream_id: u16,

    /// Digest (4 bytes)
    pub digest: [u8; 4],

    /// Length of data
    pub length: u16,

    /// Data (up to 498 bytes)
    pub data: Vec<u8>,
}

impl RelayCell {
    /// Maximum data size in relay cell
    pub const MAX_DATA_SIZE: usize = 498;

    /// Create a new relay cell
    pub fn new(command: RelayCommand, stream_id: u16, data: Vec<u8>) -> Self {
        Self {
            command,
            recognized: 0,
            stream_id,
            digest: [0; 4],
            length: data.len() as u16,
            data,
        }
    }

    /// Serialize relay cell to bytes (for inclusion in Cell payload)
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(Cell::PAYLOAD_SIZE);

        // Relay command (1 byte)
        buf.push(self.command as u8);

        // Recognized (2 bytes, big-endian)
        buf.write_all(&self.recognized.to_be_bytes())
            .map_err(|e| TorError::Internal(format!("Write recognized failed: {}", e)))?;

        // Stream ID (2 bytes, big-endian)
        buf.write_all(&self.stream_id.to_be_bytes())
            .map_err(|e| TorError::Internal(format!("Write stream_id failed: {}", e)))?;

        // Digest (4 bytes)
        buf.write_all(&self.digest)
            .map_err(|e| TorError::Internal(format!("Write digest failed: {}", e)))?;

        // Length (2 bytes, big-endian)
        buf.write_all(&self.length.to_be_bytes())
            .map_err(|e| TorError::Internal(format!("Write length failed: {}", e)))?;

        // Data
        buf.write_all(&self.data)
            .map_err(|e| TorError::Internal(format!("Write data failed: {}", e)))?;

        // Pad to Cell::PAYLOAD_SIZE
        while buf.len() < Cell::PAYLOAD_SIZE {
            buf.push(0);
        }

        Ok(buf)
    }

    /// Parse relay cell from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 11 {
            return Err(TorError::ProtocolError("Relay cell too short".into()));
        }

        let command = RelayCommand::from_u8(data[0]).ok_or_else(|| {
            TorError::ProtocolError(format!("Unknown relay command: {}", data[0]))
        })?;

        let recognized = u16::from_be_bytes([data[1], data[2]]);
        let stream_id = u16::from_be_bytes([data[3], data[4]]);
        let digest = [data[5], data[6], data[7], data[8]];
        let length = u16::from_be_bytes([data[9], data[10]]);

        let data_end = 11 + length as usize;
        if data_end > data.len() {
            return Err(TorError::ProtocolError("Relay cell data truncated".into()));
        }

        let cell_data = data[11..data_end].to_vec();

        Ok(Self {
            command,
            recognized,
            stream_id,
            digest,
            length,
            data: cell_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cell_serialization() {
        let cell = Cell::new(12345, CellCommand::Create2, vec![1, 2, 3, 4]);
        let bytes = cell.to_bytes().unwrap();
        assert_eq!(bytes.len(), Cell::SIZE);

        let parsed = Cell::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.circuit_id, 12345);
        assert_eq!(parsed.command as u8, CellCommand::Create2 as u8);
    }

    #[test]
    fn test_relay_cell_serialization() {
        let relay = RelayCell::new(RelayCommand::Begin, 100, vec![5, 6, 7]);
        let bytes = relay.to_bytes().unwrap();
        assert_eq!(bytes.len(), Cell::PAYLOAD_SIZE);

        let parsed = RelayCell::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.command as u8, RelayCommand::Begin as u8);
        assert_eq!(parsed.stream_id, 100);
        assert_eq!(parsed.data, vec![5, 6, 7]);
    }
}
