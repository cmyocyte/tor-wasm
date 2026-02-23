//! Coarse time provider using browser's performance API

use std::time::Duration;
use js_sys::Date;

/// Coarse-grained instant for WASM
///
/// Uses JavaScript's Date.now() which is cheaper than high-resolution timers
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WasmCoarseInstant {
    millis_since_epoch: u64,
}

impl WasmCoarseInstant {
    /// Get the current coarse instant
    pub fn now() -> Self {
        let millis = Date::now() as u64;
        Self {
            millis_since_epoch: millis,
        }
    }
    
    /// Get duration since another instant
    pub fn duration_since(&self, earlier: WasmCoarseInstant) -> Duration {
        let millis = self.millis_since_epoch.saturating_sub(earlier.millis_since_epoch);
        Duration::from_millis(millis)
    }
    
    /// Get duration until another instant
    pub fn duration_until(&self, later: WasmCoarseInstant) -> Duration {
        later.duration_since(*self)
    }
    
    /// Check if this instant is after another
    pub fn is_after(&self, other: WasmCoarseInstant) -> bool {
        self.millis_since_epoch > other.millis_since_epoch
    }
}

impl std::ops::Add<Duration> for WasmCoarseInstant {
    type Output = Self;
    
    fn add(self, duration: Duration) -> Self {
        Self {
            millis_since_epoch: self.millis_since_epoch + duration.as_millis() as u64,
        }
    }
}

impl std::ops::Sub<Duration> for WasmCoarseInstant {
    type Output = Self;
    
    fn sub(self, duration: Duration) -> Self {
        Self {
            millis_since_epoch: self.millis_since_epoch.saturating_sub(duration.as_millis() as u64),
        }
    }
}

impl std::ops::Sub<WasmCoarseInstant> for WasmCoarseInstant {
    type Output = Duration;
    
    fn sub(self, other: WasmCoarseInstant) -> Duration {
        self.duration_since(other)
    }
}

use super::WasmRuntime;

impl WasmRuntime {
    /// Get current coarse time
    pub fn now_coarse(&self) -> WasmCoarseInstant {
        WasmCoarseInstant::now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;
    use std::time::Duration;
    
    #[wasm_bindgen_test]
    fn test_coarse_instant() {
        let instant1 = WasmCoarseInstant::now();
        let instant2 = WasmCoarseInstant::now();
        
        // instant2 should be >= instant1
        assert!(instant2 >= instant1);
    }
    
    #[wasm_bindgen_test]
    fn test_duration_operations() {
        let instant = WasmCoarseInstant::now();
        let duration = Duration::from_secs(10);
        
        let later = instant + duration;
        assert!(later > instant);
        
        let elapsed = later - instant;
        assert!(elapsed >= Duration::from_secs(9)); // Allow some tolerance
    }
}

