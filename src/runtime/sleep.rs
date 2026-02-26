//! Sleep provider implementation using browser timers

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};
use wasm_bindgen_futures::JsFuture;
use web_sys::window;

use super::WasmRuntime;

/// A future that resolves after a specified duration
pub struct WasmSleep {
    promise: JsFuture,
}

impl WasmSleep {
    /// Create a new sleep future
    pub fn new(duration: Duration) -> Self {
        let millis = duration.as_millis() as i32;

        // Create a JavaScript Promise that resolves after the duration
        let promise = js_sys::Promise::new(&mut |resolve, _reject| {
            if let Some(window) = window() {
                let _ =
                    window.set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, millis);
            }
        });

        Self {
            promise: JsFuture::from(promise),
        }
    }
}

impl Future for WasmSleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.promise).poll(cx) {
            Poll::Ready(_) => Poll::Ready(()),
            Poll::Pending => Poll::Pending,
        }
    }
}

// Implement SleepProvider trait for WasmRuntime
// Note: We'll need to add tor-rtcompat dependency first,
// but here's the implementation structure

impl WasmRuntime {
    /// Sleep for the specified duration
    pub fn sleep(&self, duration: Duration) -> WasmSleep {
        WasmSleep::new(duration)
    }

    /// Get current time (monotonic)
    pub fn now(&self) -> std::time::Instant {
        // WASM doesn't have true Instant, but we can use performance.now()
        // For now, use SystemTime as approximation
        // TODO: Use performance.now() for better monotonic time
        std::time::Instant::now()
    }

    /// Get current wall-clock time
    pub fn wallclock(&self) -> SystemTime {
        SystemTime::now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    async fn test_sleep() {
        let runtime = WasmRuntime::new();
        let before = std::time::Instant::now();

        runtime.sleep(Duration::from_millis(10)).await;

        let after = std::time::Instant::now();
        let elapsed = after.duration_since(before);

        // Should have slept at least 10ms (with some tolerance)
        assert!(elapsed >= Duration::from_millis(8));
    }
}
