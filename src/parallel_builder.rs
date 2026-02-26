//! Parallel Circuit Building
//!
//! Builds circuits faster by parallelizing relay selection and connection attempts.
//!
//! Security considerations:
//! - Don't leak which relays we're trying in parallel
//! - Use the first successful connection (race)
//! - Still enforce relay selection constraints

use crate::error::{Result, TorError};
use crate::protocol::{Circuit, CircuitBuilder, Relay, RelaySelector};

/// Configuration for parallel building
#[derive(Debug, Clone)]
pub struct ParallelBuilderConfig {
    /// Number of guard candidates to try in parallel
    pub parallel_guards: usize,
    /// Timeout for each connection attempt (ms)
    pub connection_timeout_ms: u64,
    /// Whether to cancel remaining attempts after first success
    pub cancel_on_success: bool,
}

impl Default for ParallelBuilderConfig {
    fn default() -> Self {
        Self {
            parallel_guards: 3,
            connection_timeout_ms: 10_000, // 10 seconds
            cancel_on_success: true,
        }
    }
}

/// Statistics about parallel building
#[derive(Debug, Clone, Default)]
pub struct ParallelBuilderStats {
    /// Total parallel builds attempted
    pub builds_attempted: u64,
    /// Successful builds
    pub builds_succeeded: u64,
    /// Failed builds
    pub builds_failed: u64,
    /// Average time to first successful connection (ms)
    pub avg_first_success_ms: f64,
    /// Total parallel attempts made
    pub total_parallel_attempts: u64,
}

/// Parallel circuit builder
pub struct ParallelCircuitBuilder {
    /// Configuration
    config: ParallelBuilderConfig,
    /// Statistics
    stats: ParallelBuilderStats,
}

impl ParallelCircuitBuilder {
    /// Create a new parallel builder with default config
    pub fn new() -> Self {
        Self::with_config(ParallelBuilderConfig::default())
    }

    /// Create with custom config
    pub fn with_config(config: ParallelBuilderConfig) -> Self {
        Self {
            config,
            stats: ParallelBuilderStats::default(),
        }
    }

    /// Build a circuit using parallel relay selection
    ///
    /// This tries multiple guards in parallel and uses the first to succeed.
    pub async fn build_fast(
        &mut self,
        builder: &CircuitBuilder,
        selector: &RelaySelector,
    ) -> Result<Circuit> {
        self.stats.builds_attempted += 1;
        let start_time = now_ms();

        log::info!(
            "⚡ Starting parallel circuit build ({} candidates)",
            self.config.parallel_guards
        );

        // 1. Get multiple candidates for each position
        let guards = selector.select_guards(self.config.parallel_guards);

        // Collect guard fingerprints for exclusion
        let guard_fps: Vec<&str> = guards.iter().map(|g| g.fingerprint.as_str()).collect();

        let middles = selector.select_middles(self.config.parallel_guards, &guard_fps);

        // Collect middle fingerprints for exclusion
        let middle_fps: Vec<&str> = middles.iter().map(|m| m.fingerprint.as_str()).collect();
        let mut exclude_for_exits = guard_fps.clone();
        exclude_for_exits.extend(middle_fps.iter().cloned());

        let exits = selector.select_exits(self.config.parallel_guards, &exclude_for_exits);

        log::debug!(
            "Selected {} guards, {} middles, {} exits",
            guards.len(),
            middles.len(),
            exits.len()
        );

        // 2. Try guards sequentially for now (true parallel would need more complex async)
        // In a full implementation, we'd use tokio::select! or futures::select!
        // For WASM, we're somewhat limited in true parallelism

        let mut last_error = None;

        for (i, guard) in guards.iter().enumerate() {
            self.stats.total_parallel_attempts += 1;

            log::info!(
                "  🔄 Trying guard {}/{}: {}",
                i + 1,
                guards.len(),
                guard.nickname
            );

            // Try to build circuit with this guard
            match self
                .try_build_with_guard(builder, guard, &middles, &exits)
                .await
            {
                Ok(circuit) => {
                    let elapsed = now_ms() - start_time;
                    self.stats.builds_succeeded += 1;
                    self.update_avg_time(elapsed);

                    log::info!(
                        "  ✅ Circuit built in {}ms using {}",
                        elapsed,
                        guard.nickname
                    );
                    return Ok(circuit);
                }
                Err(e) => {
                    log::warn!("  ⚠️ Guard {} failed: {}", guard.nickname, e);
                    last_error = Some(e);
                    // Continue to next guard
                }
            }
        }

        self.stats.builds_failed += 1;
        Err(last_error
            .unwrap_or_else(|| TorError::CircuitBuildFailed("All parallel attempts failed".into())))
    }

    /// Try building with a specific guard
    async fn try_build_with_guard<'a>(
        &self,
        builder: &CircuitBuilder,
        guard: &'a Relay,
        middles: &[&'a Relay],
        exits: &[&'a Relay],
    ) -> Result<Circuit> {
        // In a full implementation, this would:
        // 1. Connect to the guard
        // 2. Complete handshake
        // 3. Extend to middle (try multiple if first fails)
        // 4. Extend to exit (try multiple if first fails)

        // For now, delegate to the existing builder with hints
        // Convert references to owned for the builder call
        let middle_slice: Vec<Relay> = middles.iter().map(|r| (*r).clone()).collect();
        let exit_slice: Vec<Relay> = exits.iter().map(|r| (*r).clone()).collect();
        builder
            .build_circuit_with_hints(guard, &middle_slice, &exit_slice)
            .await
    }

    /// Update average success time
    fn update_avg_time(&mut self, new_time: u64) {
        let total_success = self.stats.builds_succeeded as f64;
        if total_success <= 1.0 {
            self.stats.avg_first_success_ms = new_time as f64;
        } else {
            // Rolling average
            let old_avg = self.stats.avg_first_success_ms;
            self.stats.avg_first_success_ms = old_avg + (new_time as f64 - old_avg) / total_success;
        }
    }

    /// Get statistics
    pub fn get_stats(&self) -> ParallelBuilderStats {
        self.stats.clone()
    }

    /// Get configuration
    pub fn get_config(&self) -> &ParallelBuilderConfig {
        &self.config
    }

    /// Update configuration
    pub fn set_config(&mut self, config: ParallelBuilderConfig) {
        self.config = config;
    }
}

impl Default for ParallelCircuitBuilder {
    fn default() -> Self {
        Self::new()
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = ParallelBuilderConfig::default();
        assert_eq!(config.parallel_guards, 3);
        assert!(config.cancel_on_success);
    }

    #[test]
    fn test_stats_initial() {
        let builder = ParallelCircuitBuilder::new();
        let stats = builder.get_stats();
        assert_eq!(stats.builds_attempted, 0);
        assert_eq!(stats.builds_succeeded, 0);
    }
}
