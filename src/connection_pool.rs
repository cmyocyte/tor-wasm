//! WebSocket Connection Pooling
//!
//! Reuses WebSocket connections to bridges for improved performance.
//!
//! Security considerations:
//! - Limit pool size (memory exhaustion)
//! - Expire idle connections (stale state)
//! - Separate pools per bridge (no correlation across bridges)

use std::collections::{HashMap, VecDeque};

/// Timestamp in milliseconds (WASM-compatible)
fn now_ms() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now() as u64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

/// Configuration for connection pool
#[derive(Debug, Clone)]
pub struct ConnectionPoolConfig {
    /// Max connections per bridge URL
    pub max_per_bridge: usize,
    /// Max idle time before closing (milliseconds)
    pub max_idle_ms: u64,
    /// Max total connections across all bridges
    pub max_total: usize,
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            max_per_bridge: 5,
            max_idle_ms: 5 * 60 * 1000, // 5 minutes
            max_total: 20,
        }
    }
}

/// A pooled connection entry
/// 
/// Note: In WASM, WebSocket connections are managed by the browser.
/// This tracks metadata about connections we've created.
#[derive(Debug)]
pub struct PooledConnection {
    /// Unique connection ID
    pub id: u64,
    /// Bridge URL this connection is to
    pub bridge_url: String,
    /// When connection was created
    pub created_at: u64,
    /// When connection was last used
    pub last_used: u64,
    /// Is connection still healthy?
    pub is_healthy: bool,
}

impl PooledConnection {
    fn new(id: u64, bridge_url: String) -> Self {
        let now = now_ms();
        Self {
            id,
            bridge_url,
            created_at: now,
            last_used: now,
            is_healthy: true,
        }
    }

    fn touch(&mut self) {
        self.last_used = now_ms();
    }

    fn idle_ms(&self) -> u64 {
        now_ms().saturating_sub(self.last_used)
    }

    fn is_idle(&self, max_idle_ms: u64) -> bool {
        self.idle_ms() > max_idle_ms
    }
}

/// Pool of WebSocket connections to bridges
pub struct ConnectionPool {
    /// Connections per bridge URL
    pools: HashMap<String, VecDeque<PooledConnection>>,
    /// Configuration
    config: ConnectionPoolConfig,
    /// Next connection ID
    next_id: u64,
    /// Statistics
    stats: ConnectionPoolStats,
}

/// Statistics about connection pooling
#[derive(Debug, Clone, Default)]
pub struct ConnectionPoolStats {
    /// Total connections created
    pub connections_created: u64,
    /// Connections served from pool (reused)
    pub pool_hits: u64,
    /// New connections created (cache miss)
    pub pool_misses: u64,
    /// Connections expired (idle timeout)
    pub connections_expired: u64,
    /// Connections returned to pool
    pub connections_returned: u64,
    /// Current total connections in pool
    pub current_pool_size: usize,
}

impl ConnectionPool {
    /// Create a new connection pool with default config
    pub fn new() -> Self {
        Self::with_config(ConnectionPoolConfig::default())
    }

    /// Create with custom config
    pub fn with_config(config: ConnectionPoolConfig) -> Self {
        Self {
            pools: HashMap::new(),
            config,
            next_id: 1,
            stats: ConnectionPoolStats::default(),
        }
    }

    /// Get a connection to a bridge (from pool or new)
    /// 
    /// Returns connection ID. In actual use, caller would use this ID
    /// with the actual WebSocket connection.
    pub fn get_connection(&mut self, bridge_url: &str) -> Option<PooledConnection> {
        self.expire_idle_connections();

        // Try to get from pool
        if let Some(pool) = self.pools.get_mut(bridge_url) {
            while let Some(mut conn) = pool.pop_front() {
                if conn.is_healthy && !conn.is_idle(self.config.max_idle_ms) {
                    conn.touch();
                    self.stats.pool_hits += 1;
                    self.update_pool_size();
                    log::debug!("♻️ Reusing pooled connection {} to {}", conn.id, bridge_url);
                    return Some(conn);
                }
                // Connection is stale/unhealthy, discard it
                self.stats.connections_expired += 1;
            }
        }

        // No pooled connection available
        self.stats.pool_misses += 1;
        None
    }

    /// Create a new connection entry
    /// 
    /// Call this when actually creating a new WebSocket connection.
    pub fn create_connection(&mut self, bridge_url: &str) -> PooledConnection {
        let id = self.next_id;
        self.next_id += 1;
        self.stats.connections_created += 1;
        
        log::debug!("🆕 Creating new connection {} to {}", id, bridge_url);
        PooledConnection::new(id, bridge_url.to_string())
    }

    /// Return a connection to the pool
    /// 
    /// Call this when done with a connection but want to keep it for reuse.
    pub fn return_connection(&mut self, mut conn: PooledConnection) {
        // Check total pool size first
        if self.total_pooled() >= self.config.max_total {
            log::debug!("Total pool full, dropping connection {}", conn.id);
            return;
        }

        // Check if pool has room for this bridge
        let bridge_url = conn.bridge_url.clone();
        let pool = self.pools.entry(bridge_url.clone()).or_default();

        if pool.len() >= self.config.max_per_bridge {
            log::debug!("Pool full for {}, dropping connection {}", bridge_url, conn.id);
            return;
        }

        conn.touch();
        pool.push_back(conn);
        self.stats.connections_returned += 1;
        self.update_pool_size();
        
        log::debug!("📥 Connection returned to pool");
    }

    /// Mark a connection as unhealthy (don't reuse)
    pub fn mark_unhealthy(&mut self, connection_id: u64) {
        for pool in self.pools.values_mut() {
            for conn in pool.iter_mut() {
                if conn.id == connection_id {
                    conn.is_healthy = false;
                    log::debug!("Connection {} marked unhealthy", connection_id);
                    return;
                }
            }
        }
    }

    /// Expire idle connections
    pub fn expire_idle_connections(&mut self) {
        let max_idle = self.config.max_idle_ms;
        let mut expired_count = 0;

        for pool in self.pools.values_mut() {
            let before = pool.len();
            pool.retain(|c| c.is_healthy && !c.is_idle(max_idle));
            expired_count += before - pool.len();
        }

        if expired_count > 0 {
            log::debug!("🗑️ Expired {} idle connections", expired_count);
            self.stats.connections_expired += expired_count as u64;
        }

        // Remove empty pools
        self.pools.retain(|_, pool| !pool.is_empty());
        self.update_pool_size();
    }

    /// Get statistics
    pub fn get_stats(&self) -> ConnectionPoolStats {
        ConnectionPoolStats {
            current_pool_size: self.total_pooled(),
            ..self.stats.clone()
        }
    }

    /// Get total connections in pool
    pub fn total_pooled(&self) -> usize {
        self.pools.values().map(|p| p.len()).sum()
    }

    /// Get pooled connections for a specific bridge
    pub fn pooled_for_bridge(&self, bridge_url: &str) -> usize {
        self.pools.get(bridge_url).map(|p| p.len()).unwrap_or(0)
    }

    /// Clear all pooled connections
    pub fn clear(&mut self) {
        let count = self.total_pooled();
        self.pools.clear();
        self.update_pool_size();
        log::info!("Cleared {} pooled connections", count);
    }

    /// Update the pool size stat
    fn update_pool_size(&mut self) {
        self.stats.current_pool_size = self.total_pooled();
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_pool_config_defaults() {
        let config = ConnectionPoolConfig::default();
        assert_eq!(config.max_per_bridge, 5);
        assert_eq!(config.max_total, 20);
    }

    #[test]
    fn test_create_and_return_connection() {
        let mut pool = ConnectionPool::new();
        
        let conn = pool.create_connection("ws://localhost:8080");
        assert_eq!(conn.id, 1);
        
        pool.return_connection(conn);
        assert_eq!(pool.total_pooled(), 1);
        
        let reused = pool.get_connection("ws://localhost:8080");
        assert!(reused.is_some());
        assert_eq!(reused.unwrap().id, 1);
    }

    #[test]
    fn test_pool_miss() {
        let mut pool = ConnectionPool::new();
        
        let result = pool.get_connection("ws://localhost:8080");
        assert!(result.is_none());
        
        assert_eq!(pool.get_stats().pool_misses, 1);
    }
}

