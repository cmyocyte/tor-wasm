// IndexedDB storage implementation for browser persistence
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{IdbDatabase, IdbObjectStore, IdbRequest, IdbTransaction, IdbTransactionMode, IdbVersionChangeEvent};
use js_sys::{Uint8Array, Array, Promise};
use crate::error::{TorError, Result};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Helper to convert IdbRequest to a Future using callbacks
async fn request_to_future(request: &IdbRequest) -> std::result::Result<JsValue, JsValue> {
    use std::rc::Rc;
    use std::cell::RefCell;
    use wasm_bindgen_futures::JsFuture;
    
    // Create a Promise that resolves/rejects based on the request callbacks
    let promise = Promise::new(&mut |resolve, reject| {
        let resolve = Rc::new(RefCell::new(Some(resolve)));
        let reject = Rc::new(RefCell::new(Some(reject)));
        
        // Success callback
        let resolve_clone = Rc::clone(&resolve);
        let onsuccess = Closure::once(move |event: web_sys::Event| {
            if let Ok(target) = event.target().ok_or("No target") {
                if let Ok(request) = target.dyn_into::<IdbRequest>() {
                    if let Ok(result) = request.result() {
                        if let Some(resolve_fn) = resolve_clone.borrow_mut().take() {
                            let _ = resolve_fn.call1(&JsValue::NULL, &result);
                        }
                    }
                }
            }
        });
        
        // Error callback
        let reject_clone = Rc::clone(&reject);
        let onerror = Closure::once(move |event: web_sys::Event| {
            if let Ok(target) = event.target().ok_or("No target") {
                if let Ok(request) = target.dyn_into::<IdbRequest>() {
                    let error = JsValue::from_str("IndexedDB request failed");
                    if let Some(reject_fn) = reject_clone.borrow_mut().take() {
                        let _ = reject_fn.call1(&JsValue::NULL, &error);
                    }
                }
            }
        });
        
        request.set_onsuccess(Some(onsuccess.as_ref().unchecked_ref()));
        request.set_onerror(Some(onerror.as_ref().unchecked_ref()));
        
        onsuccess.forget();
        onerror.forget();
    });
    
    JsFuture::from(promise).await
}

/// WASM-compatible persistent storage using IndexedDB
/// 
/// Stores Tor consensus, relay database, and circuit state
/// in the browser's IndexedDB for persistence across sessions.
#[derive(Clone)]
pub struct WasmStorage {
    db: IdbDatabase,
}

impl WasmStorage {
    /// Initialize IndexedDB connection
    /// 
    /// Creates the database and object stores if they don't exist.
    /// Object stores:
    /// - "consensus": Tor directory consensus
    /// - "relays": Relay descriptors and metadata
    /// - "circuits": Circuit pool state
    /// - "cache": General purpose cache
    /// - "state": Client state (guards, etc.)
    pub async fn new() -> Result<Self> {
        log::info!("Initializing IndexedDB storage...");
        
        let window = web_sys::window()
            .ok_or_else(|| TorError::Storage("No window object".into()))?;
        
        let idb = window
            .indexed_db()
            .map_err(|e| TorError::Storage(format!("IndexedDB not available: {:?}", e)))?
            .ok_or_else(|| TorError::Storage("IndexedDB not supported".into()))?;
        
        // Open database (version 1)
        let open_request = idb
            .open_with_u32("tor-storage", 1)
            .map_err(|e| TorError::Storage(format!("Failed to open DB: {:?}", e)))?;
        
        // Handle database upgrade (first time or version change)
        let on_upgrade = Closure::wrap(Box::new(move |event: IdbVersionChangeEvent| {
            log::info!("Upgrading IndexedDB schema...");
            
            let target = event.target().expect("Event should have target");
            let request = target
                .dyn_into::<IdbRequest>()
                .expect("Target should be IdbRequest");
            let db = request
                .result()
                .expect("Request should have result")
                .dyn_into::<IdbDatabase>()
                .expect("Result should be IdbDatabase");
            
            // Create object stores
            let stores = vec!["consensus", "relays", "circuits", "cache", "state"];
            for store_name in stores {
                if !db.object_store_names().contains(store_name) {
                    db.create_object_store(store_name)
                        .expect(&format!("Failed to create {} store", store_name));
                    log::info!("Created object store: {}", store_name);
                }
            }
        }) as Box<dyn FnMut(_)>);
        
        open_request.set_onupgradeneeded(Some(on_upgrade.as_ref().unchecked_ref()));
        on_upgrade.forget(); // Keep closure alive
        
        // Wait for database to open
        let db_value = request_to_future(&open_request)
            .await
            .map_err(|e| TorError::Storage(format!("Failed to open DB: {:?}", e)))?;
        
        let db = db_value
            .dyn_into::<IdbDatabase>()
            .map_err(|e| TorError::Storage(format!("Invalid DB object: {:?}", e)))?;
        
        log::info!("IndexedDB initialized successfully");
        Ok(WasmStorage { db })
    }
    
    /// Store data in a specific object store
    /// 
    /// # Arguments
    /// * `store_name` - Name of the object store (e.g., "consensus", "relays")
    /// * `key` - String key to store the data under
    /// * `value` - Byte array to store
    pub async fn set(&self, store_name: &str, key: &str, value: &[u8]) -> Result<()> {
        log::debug!("Storing {} bytes in {}:{}", value.len(), store_name, key);
        
        // Create read-write transaction
        let transaction = self.db
            .transaction_with_str_and_mode(store_name, IdbTransactionMode::Readwrite)
            .map_err(|e| TorError::Storage(format!("Failed to create transaction: {:?}", e)))?;
        
        let object_store = transaction
            .object_store(store_name)
            .map_err(|e| TorError::Storage(format!("Failed to get object store: {:?}", e)))?;
        
        // Convert byte array to Uint8Array
        let js_array = Uint8Array::from(value);
        
        // Store the data
        let request = object_store
            .put_with_key(&js_array, &JsValue::from_str(key))
            .map_err(|e| TorError::Storage(format!("Failed to put data: {:?}", e)))?;
        
        // Wait for operation to complete
        request_to_future(&request)
            .await
            .map_err(|e| TorError::Storage(format!("Failed to store data: {:?}", e)))?;
        
        log::debug!("Stored {}:{} successfully", store_name, key);
        Ok(())
    }
    
    /// Retrieve data from a specific object store
    /// 
    /// # Arguments
    /// * `store_name` - Name of the object store
    /// * `key` - String key to retrieve
    /// 
    /// # Returns
    /// * `Ok(Some(Vec<u8>))` if data exists
    /// * `Ok(None)` if key doesn't exist
    /// * `Err` on error
    pub async fn get(&self, store_name: &str, key: &str) -> Result<Option<Vec<u8>>> {
        log::debug!("Retrieving {}:{}", store_name, key);
        
        // Create read-only transaction
        let transaction = self.db
            .transaction_with_str(store_name)
            .map_err(|e| TorError::Storage(format!("Failed to create transaction: {:?}", e)))?;
        
        let object_store = transaction
            .object_store(store_name)
            .map_err(|e| TorError::Storage(format!("Failed to get object store: {:?}", e)))?;
        
        // Get the data
        let request = object_store
            .get(&JsValue::from_str(key))
            .map_err(|e| TorError::Storage(format!("Failed to get data: {:?}", e)))?;
        
        let result = request_to_future(&request)
            .await
            .map_err(|e| TorError::Storage(format!("Failed to retrieve data: {:?}", e)))?;
        
        // Check if data exists
        if result.is_undefined() || result.is_null() {
            log::debug!("No data found for {}:{}", store_name, key);
            return Ok(None);
        }
        
        // Convert Uint8Array back to Vec<u8>
        let array = Uint8Array::new(&result);
        let mut vec = vec![0u8; array.length() as usize];
        array.copy_to(&mut vec);
        
        log::debug!("Retrieved {} bytes from {}:{}", vec.len(), store_name, key);
        Ok(Some(vec))
    }
    
    /// Delete data from a specific object store
    /// 
    /// # Arguments
    /// * `store_name` - Name of the object store
    /// * `key` - String key to delete
    pub async fn delete(&self, store_name: &str, key: &str) -> Result<()> {
        log::debug!("Deleting {}:{}", store_name, key);
        
        let transaction = self.db
            .transaction_with_str_and_mode(store_name, IdbTransactionMode::Readwrite)
            .map_err(|e| TorError::Storage(format!("Failed to create transaction: {:?}", e)))?;
        
        let object_store = transaction
            .object_store(store_name)
            .map_err(|e| TorError::Storage(format!("Failed to get object store: {:?}", e)))?;
        
        let request = object_store
            .delete(&JsValue::from_str(key))
            .map_err(|e| TorError::Storage(format!("Failed to delete data: {:?}", e)))?;
        
        request_to_future(&request)
            .await
            .map_err(|e| TorError::Storage(format!("Failed to complete delete: {:?}", e)))?;
        
        log::debug!("Deleted {}:{} successfully", store_name, key);
        Ok(())
    }
    
    /// List all keys in a specific object store
    /// 
    /// # Arguments
    /// * `store_name` - Name of the object store
    /// 
    /// # Returns
    /// Vector of all keys in the store
    pub async fn list_keys(&self, store_name: &str) -> Result<Vec<String>> {
        log::debug!("Listing keys in {}", store_name);
        
        let transaction = self.db
            .transaction_with_str(store_name)
            .map_err(|e| TorError::Storage(format!("Failed to create transaction: {:?}", e)))?;
        
        let object_store = transaction
            .object_store(store_name)
            .map_err(|e| TorError::Storage(format!("Failed to get object store: {:?}", e)))?;
        
        let request = object_store
            .get_all_keys()
            .map_err(|e| TorError::Storage(format!("Failed to get all keys: {:?}", e)))?;
        
        let result = request_to_future(&request)
            .await
            .map_err(|e| TorError::Storage(format!("Failed to retrieve keys: {:?}", e)))?;
        
        let array = Array::from(&result);
        let mut keys = Vec::new();
        
        for i in 0..array.length() {
            if let Some(key) = array.get(i).as_string() {
                keys.push(key);
            }
        }
        
        log::debug!("Found {} keys in {}", keys.len(), store_name);
        Ok(keys)
    }
    
    /// Clear all data from a specific object store
    /// 
    /// # Arguments
    /// * `store_name` - Name of the object store to clear
    pub async fn clear(&self, store_name: &str) -> Result<()> {
        log::info!("Clearing all data from {}", store_name);
        
        let transaction = self.db
            .transaction_with_str_and_mode(store_name, IdbTransactionMode::Readwrite)
            .map_err(|e| TorError::Storage(format!("Failed to create transaction: {:?}", e)))?;
        
        let object_store = transaction
            .object_store(store_name)
            .map_err(|e| TorError::Storage(format!("Failed to get object store: {:?}", e)))?;
        
        let request = object_store
            .clear()
            .map_err(|e| TorError::Storage(format!("Failed to clear store: {:?}", e)))?;
        
        request_to_future(&request)
            .await
            .map_err(|e| TorError::Storage(format!("Failed to complete clear: {:?}", e)))?;
        
        log::info!("Cleared {} successfully", store_name);
        Ok(())
    }
    
    /// Get storage statistics
    /// 
    /// Returns the number of keys in each object store
    pub async fn get_stats(&self) -> Result<StorageStats> {
        log::debug!("Getting storage statistics");
        
        let stores = vec!["consensus", "relays", "circuits", "cache", "state"];
        let mut stats = StorageStats::default();
        
        for store_name in stores {
            let keys = self.list_keys(store_name).await?;
            match store_name {
                "consensus" => stats.consensus_entries = keys.len(),
                "relays" => stats.relay_entries = keys.len(),
                "circuits" => stats.circuit_entries = keys.len(),
                "cache" => stats.cache_entries = keys.len(),
                "state" => stats.state_entries = keys.len(),
                _ => {}
            }
        }
        
        log::debug!("Storage stats: {:?}", stats);
        Ok(stats)
    }
}

/// Storage statistics
#[derive(Debug, Default, Clone)]
pub struct StorageStats {
    pub consensus_entries: usize,
    pub relay_entries: usize,
    pub circuit_entries: usize,
    pub cache_entries: usize,
    pub state_entries: usize,
}

impl StorageStats {
    pub fn total_entries(&self) -> usize {
        self.consensus_entries + self.relay_entries + self.circuit_entries + self.cache_entries + self.state_entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;
    
    wasm_bindgen_test_configure!(run_in_browser);
    
    #[wasm_bindgen_test]
    async fn test_storage_init() {
        let storage = WasmStorage::new().await.unwrap();
        let stats = storage.get_stats().await.unwrap();
        assert_eq!(stats.total_entries(), 0);
    }
    
    #[wasm_bindgen_test]
    async fn test_storage_set_get() {
        let storage = WasmStorage::new().await.unwrap();
        
        let data = b"Hello, Tor!";
        storage.set("cache", "test_key", data).await.unwrap();
        
        let retrieved = storage.get("cache", "test_key").await.unwrap();
        assert_eq!(retrieved, Some(data.to_vec()));
    }
    
    #[wasm_bindgen_test]
    async fn test_storage_delete() {
        let storage = WasmStorage::new().await.unwrap();
        
        storage.set("cache", "delete_me", b"data").await.unwrap();
        storage.delete("cache", "delete_me").await.unwrap();
        
        let retrieved = storage.get("cache", "delete_me").await.unwrap();
        assert_eq!(retrieved, None);
    }
    
    #[wasm_bindgen_test]
    async fn test_storage_list_keys() {
        let storage = WasmStorage::new().await.unwrap();
        
        storage.set("cache", "key1", b"data1").await.unwrap();
        storage.set("cache", "key2", b"data2").await.unwrap();
        storage.set("cache", "key3", b"data3").await.unwrap();
        
        let keys = storage.list_keys("cache").await.unwrap();
        assert!(keys.contains(&"key1".to_string()));
        assert!(keys.contains(&"key2".to_string()));
        assert!(keys.contains(&"key3".to_string()));
    }
    
    #[wasm_bindgen_test]
    async fn test_storage_clear() {
        let storage = WasmStorage::new().await.unwrap();
        
        storage.set("cache", "key1", b"data1").await.unwrap();
        storage.set("cache", "key2", b"data2").await.unwrap();
        
        storage.clear("cache").await.unwrap();
        
        let keys = storage.list_keys("cache").await.unwrap();
        assert_eq!(keys.len(), 0);
    }
}

