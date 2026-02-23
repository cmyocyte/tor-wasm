//! Task spawning implementation for WASM

use futures::task::{FutureObj, Spawn, SpawnError};
use wasm_bindgen_futures::spawn_local;

use super::WasmRuntime;

/// WASM spawner that uses wasm-bindgen-futures
#[derive(Debug, Clone)]
pub struct WasmSpawner;

impl Spawn for WasmSpawner {
    fn spawn_obj(&self, future: FutureObj<'static, ()>) -> Result<(), SpawnError> {
        // spawn_local runs the future to completion in the browser's event loop
        spawn_local(async move {
            future.await;
        });
        
        Ok(())
    }
}

impl Spawn for WasmRuntime {
    fn spawn_obj(&self, future: FutureObj<'static, ()>) -> Result<(), SpawnError> {
        WasmSpawner.spawn_obj(future)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::task::SpawnExt;
    use wasm_bindgen_test::*;
    use std::sync::{Arc, Mutex};
    
    #[wasm_bindgen_test]
    async fn test_spawn() {
        let runtime = WasmRuntime::new();
        let executed = Arc::new(Mutex::new(false));
        let executed_clone = executed.clone();
        
        runtime.spawn(async move {
            *executed_clone.lock().unwrap() = true;
        }).expect("Failed to spawn task");
        
        // Give the spawned task time to execute
        wasm_bindgen_futures::JsFuture::from(js_sys::Promise::new(&mut |resolve, _reject| {
            web_sys::window().unwrap().set_timeout_with_callback_and_timeout_and_arguments_0(
                &resolve,
                50,
            ).unwrap();
        })).await.unwrap();
        
        assert!(*executed.lock().unwrap(), "Spawned task should have executed");
    }
}

