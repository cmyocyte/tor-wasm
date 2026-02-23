//! Tor protocol cell handling

use alloc::vec::Vec;
use crate::{Result, TorError};

/// Tor cell commands
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum CellCommand {
    Padding = 0,
    Create = 1,
    Created = 2,
    Relay = 3,
    Destroy = 4,
    CreateFast = 5,
    CreatedFast = 6,
    Versions = 7,
    Netinfo = 8,
    RelayEarly = 9,
    Create2 = 10,
    Created2 = 11,
    Certs = 129,
    AuthChallenge = 130,
    Authenticate = 131,
}

impl TryFrom<u8> for CellCommand {
    type Error = TorError;
    
    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(CellCommand::Padding),
            1 => Ok(CellCommand::Create),
            2 => Ok(CellCommand::Created),
            3 => Ok(CellCommand::Relay),
            4 => Ok(CellCommand::Destroy),
            5 => Ok(CellCommand::CreateFast),
            6 => Ok(CellCommand::CreatedFast),
            7 => Ok(CellCommand::Versions),
            8 => Ok(CellCommand::Netinfo),
            9 => Ok(CellCommand::RelayEarly),
            10 => Ok(CellCommand::Create2),
            11 => Ok(CellCommand::Created2),
            129 => Ok(CellCommand::Certs),
            130 => Ok(CellCommand::AuthChallenge),
            131 => Ok(CellCommand::Authenticate),
            _ => Err(TorError::Protocol(alloc::format!("Unknown command: {}", value))),
        }
    }
}

/// RELAY cell commands
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum RelayCommand {
    Begin = 1,
    Data = 2,
    End = 3,
    Connected = 4,
    SendMe = 5,
    Extend = 6,
    Extended = 7,
    Truncate = 8,
    Truncated = 9,
    Drop = 10,
    Resolve = 11,
    Resolved = 12,
    BeginDir = 13,
    Extend2 = 14,
    Extended2 = 15,
}

/// Fixed cell size (link protocol v4+)
pub const CELL_SIZE: usize = 514;
pub const CELL_HEADER_SIZE: usize = 5; // 4 bytes circuit ID + 1 byte command
pub const CELL_PAYLOAD_SIZE: usize = 509;

/// A Tor cell
pub struct Cell {
    pub circuit_id: u32,
    pub command: CellCommand,
    pub payload: Vec<u8>,
}

impl Cell {
    /// Create a new cell
    pub fn new(circuit_id: u32, command: CellCommand, payload: Vec<u8>) -> Self {
        Self {
            circuit_id,
            command,
            payload,
        }
    }
    
    /// Serialize cell to bytes (514 bytes for fixed-size cells)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(CELL_SIZE);
        
        // Circuit ID (4 bytes, big-endian)
        bytes.extend_from_slice(&self.circuit_id.to_be_bytes());
        
        // Command (1 byte)
        bytes.push(self.command as u8);
        
        // Payload (509 bytes, zero-padded)
        bytes.extend_from_slice(&self.payload);
        bytes.resize(CELL_SIZE, 0);
        
        bytes
    }
    
    /// Parse cell from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < CELL_HEADER_SIZE {
            return Err(TorError::Protocol("Cell too short".into()));
        }
        
        let circuit_id = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let command = CellCommand::try_from(bytes[4])?;
        
        let payload = if bytes.len() > CELL_HEADER_SIZE {
            bytes[CELL_HEADER_SIZE..].to_vec()
        } else {
            Vec::new()
        };
        
        Ok(Self {
            circuit_id,
            command,
            payload,
        })
    }
}

/// Create a VERSIONS cell
pub fn create_versions_cell(versions: &[u16]) -> Vec<u8> {
    let mut cell = Vec::with_capacity(7 + versions.len() * 2);
    
    // Variable-length cell header
    cell.extend_from_slice(&0u32.to_be_bytes()); // Circuit ID = 0
    cell.push(CellCommand::Versions as u8);
    cell.extend_from_slice(&((versions.len() * 2) as u16).to_be_bytes()); // Length
    
    // Payload: version numbers
    for v in versions {
        cell.extend_from_slice(&v.to_be_bytes());
    }
    
    cell
}

/// Create a NETINFO cell
pub fn create_netinfo_cell(our_addr: &[u8; 4], their_addr: &[u8; 4]) -> Cell {
    let mut payload = Vec::with_capacity(32);
    
    // Timestamp (4 bytes) - just use 0 for now
    payload.extend_from_slice(&0u32.to_be_bytes());
    
    // Other OR's address (Type=4 for IPv4, Len=4, then 4 bytes)
    payload.push(4); // Type: IPv4
    payload.push(4); // Length
    payload.extend_from_slice(their_addr);
    
    // Number of our addresses (1)
    payload.push(1);
    
    // Our address
    payload.push(4); // Type: IPv4
    payload.push(4); // Length
    payload.extend_from_slice(our_addr);
    
    Cell::new(0, CellCommand::Netinfo, payload)
}

/// Create a CREATE2 cell for ntor handshake
pub fn create_create2_cell(circuit_id: u32, handshake_data: &[u8]) -> Cell {
    let mut payload = Vec::with_capacity(4 + handshake_data.len());
    
    // HTYPE = 2 (ntor)
    payload.extend_from_slice(&2u16.to_be_bytes());
    
    // HLEN = handshake data length
    payload.extend_from_slice(&(handshake_data.len() as u16).to_be_bytes());
    
    // HDATA = handshake data
    payload.extend_from_slice(handshake_data);
    
    Cell::new(circuit_id, CellCommand::Create2, payload)
}

/// Parse CREATED2 cell response
pub fn parse_created2_payload(payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() < 2 {
        return Err(TorError::Protocol("CREATED2 payload too short".into()));
    }
    
    let hlen = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    
    if payload.len() < 2 + hlen {
        return Err(TorError::Protocol("CREATED2 payload truncated".into()));
    }
    
    Ok(payload[2..2 + hlen].to_vec())
}

/// DESTROY cell reasons
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum DestroyReason {
    None = 0,
    Protocol = 1,
    Internal = 2,
    Requested = 3,
    Hibernating = 4,
    ResourceLimit = 5,
    ConnectFailed = 6,
    OrIdentity = 7,
    OrConnClosed = 8,
    Finished = 9,
    Timeout = 10,
    Destroyed = 11,
    NoSuchService = 12,
}

impl From<u8> for DestroyReason {
    fn from(value: u8) -> Self {
        match value {
            0 => DestroyReason::None,
            1 => DestroyReason::Protocol,
            2 => DestroyReason::Internal,
            3 => DestroyReason::Requested,
            4 => DestroyReason::Hibernating,
            5 => DestroyReason::ResourceLimit,
            6 => DestroyReason::ConnectFailed,
            7 => DestroyReason::OrIdentity,
            8 => DestroyReason::OrConnClosed,
            9 => DestroyReason::Finished,
            10 => DestroyReason::Timeout,
            11 => DestroyReason::Destroyed,
            12 => DestroyReason::NoSuchService,
            _ => DestroyReason::None,
        }
    }
}

