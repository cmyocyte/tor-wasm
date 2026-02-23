//! Connection manager for pooling and reusing connections
//!
//! Manages multiple TCP connections to Tor relays, providing connection
//! pooling and lifecycle management.

use super::{WasmTcpProvider, NetworkStats};
use crate::transport::WasmTcpStream;
use std::net::SocketAddr;
use std::collections::HashMap;
use std::sync::Arc;
use std::cell::UnsafeCell;
use std::io::Result as IoResult;

/// Connection pool entry
struct PoolEntry {
    /// The stream
    stream: WasmTcpStream,
    
    /// When this connection was created
    created_at: u64,
    
    /// When this connection was last used
    last_used: u64,
    
    /// Number of times this connection has been used
    use_count: u32,
}

/// Connection manager with pooling support
pub struct ConnectionManager {
    /// TCP provider for creating new connections
    provider: Arc<WasmTcpProvider>,
    
    /// Connection pool (address -> stream) - UnsafeCell is safe in single-threaded WASM
    pool: UnsafeCell<HashMap<SocketAddr, PoolEntry>>,
    
    /// Maximum connections to pool
    max_pool_size: usize,
    
    /// Maximum age for pooled connections (seconds)
    max_connection_age: u64,
}

impl ConnectionManager {
    /// Create a new connection manager
    pub fn new(provider: Arc<WasmTcpProvider>) -> Self {
        Self {
            provider,
            pool: UnsafeCell::new(HashMap::new()),
            max_pool_size: 50,
            max_connection_age: 600, // 10 minutes
        }
    }
    
    /// Get a connection to an address (from pool or create new)
    pub async fn get_connection(&self, addr: &SocketAddr) -> IoResult<WasmTcpStream> {
        // Try to get from pool
        if let Some(stream) = self.get_from_pool(addr) {
            log::debug!("Reusing pooled connection to {}", addr);
            return Ok(stream);
        }
        
        // Create new connection
        log::debug!("Creating new connection to {}", addr);
        let stream = self.provider.connect_with_retry(addr).await?;
        
        Ok(stream)
    }
    
    /// Return a connection to the pool
    pub fn return_connection(&self, addr: SocketAddr, stream: WasmTcpStream) {
        unsafe {
            let pool = &mut *self.pool.get();
            
            // Check pool size limit
            if pool.len() >= self.max_pool_size {
                log::debug!("Pool full, dropping connection to {}", addr);
                return;
            }
            
            let now = current_timestamp();
            
            pool.insert(addr, PoolEntry {
                stream,
                created_at: now,
                last_used: now,
                use_count: 0,
            });
            
            log::debug!("Returned connection to pool for {}", addr);
        }
    }
    
    /// Get a connection from the pool
    fn get_from_pool(&self, addr: &SocketAddr) -> Option<WasmTcpStream> {
        unsafe {
            let pool = &mut *self.pool.get();
            
            if let Some(entry) = pool.remove(addr) {
                let now = current_timestamp();
                let age = now - entry.created_at;
                
                // Check if connection is too old
                if age > self.max_connection_age {
                    log::debug!("Pooled connection to {} is too old, dropping", addr);
                    return None;
                }
                
                return Some(entry.stream);
            }
            
            None
        }
    }
    
    /// Prune stale connections from the pool
    pub fn prune_stale(&self) -> usize {
        unsafe {
            let pool = &mut *self.pool.get();
            let now = current_timestamp();
            
            let initial_size = pool.len();
            
            pool.retain(|addr, entry| {
                let age = now - entry.created_at;
                let keep = age <= self.max_connection_age;
                
                if !keep {
                    log::debug!("Pruning stale connection to {}", addr);
                }
                
                keep
            });
            
            let pruned = initial_size - pool.len();
            
            if pruned > 0 {
                log::info!("Pruned {} stale connections from pool", pruned);
            }
            
            pruned
        }
    }
    
    /// Get the current pool size
    pub fn pool_size(&self) -> usize {
        unsafe {
            (*self.pool.get()).len()
        }
    }
    
    /// Clear the entire pool
    pub fn clear_pool(&self) {
        unsafe {
            let pool = &mut *self.pool.get();
            let size = pool.len();
            pool.clear();
            log::info!("Cleared connection pool ({} connections)", size);
        }
    }
    
    /// Get network statistics from the provider
    pub fn get_stats(&self) -> NetworkStats {
        self.provider.get_stats()
    }
}

/// Get current timestamp in seconds
fn current_timestamp() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_connection_manager_creation() {
        let provider = Arc::new(WasmTcpProvider::new());
        let manager = ConnectionManager::new(provider);
        assert_eq!(manager.pool_size(), 0);
    }
    
    #[test]
    fn test_timestamp() {
        let ts = current_timestamp();
        assert!(ts > 0);
    }
}

