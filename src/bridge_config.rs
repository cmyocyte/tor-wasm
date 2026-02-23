///! Bridge Configuration and Fallback Logic
///!
///! Handles automatic fallback between local and cloud bridges.

use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};

/// Bridge configuration with fallback support
#[wasm_bindgen]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfiguration {
    /// Primary bridge URL (usually cloud bridge)
    primary: String,
    
    /// Fallback bridges (tried in order if primary fails)
    fallbacks: Vec<String>,
    
    /// Connection timeout in seconds
    timeout: u64,
}

#[wasm_bindgen]
impl BridgeConfiguration {
    /// Create a new bridge configuration with cloud-first fallback
    /// 
    /// # Arguments
    /// * `cloud_bridge` - Your cloud bridge URL (e.g., "wss://bridge.yourwallet.com")
    /// * `local_bridge` - Optional local bridge for development (e.g., "ws://localhost:8080")
    #[wasm_bindgen(constructor)]
    pub fn new(cloud_bridge: String, local_bridge: Option<String>) -> Self {
        let mut fallbacks = Vec::new();
        
        // Add local bridge as fallback if provided
        if let Some(local) = local_bridge {
            fallbacks.push(local);
        }
        
        Self {
            primary: cloud_bridge,
            fallbacks,
            timeout: 10,
        }
    }
    
    /// Create a local-only configuration for development
    #[wasm_bindgen]
    pub fn local_only() -> Self {
        Self {
            primary: "ws://localhost:8080".to_string(),
            fallbacks: vec![],
            timeout: 10,
        }
    }
    
    /// Create a cloud-only configuration for production
    #[wasm_bindgen]
    pub fn cloud_only(url: String) -> Self {
        Self {
            primary: url,
            fallbacks: vec![],
            timeout: 10,
        }
    }
    
    /// Create a configuration with multiple fallbacks
    #[wasm_bindgen]
    pub fn with_fallbacks(primary: String, fallbacks: Vec<JsValue>) -> Result<BridgeConfiguration, JsValue> {
        let fallback_urls: Result<Vec<String>, JsValue> = fallbacks
            .iter()
            .map(|v| {
                v.as_string()
                    .ok_or_else(|| JsValue::from_str("Fallback must be a string"))
            })
            .collect();
        
        Ok(Self {
            primary,
            fallbacks: fallback_urls?,
            timeout: 10,
        })
    }
    
    /// Get the primary bridge URL
    #[wasm_bindgen]
    pub fn get_primary(&self) -> String {
        self.primary.clone()
    }
    
    /// Get all bridge URLs (primary + fallbacks)
    #[wasm_bindgen]
    pub fn get_all_urls(&self) -> Vec<JsValue> {
        let mut urls = vec![JsValue::from_str(&self.primary)];
        for fallback in &self.fallbacks {
            urls.push(JsValue::from_str(fallback));
        }
        urls
    }
    
    /// Set connection timeout in seconds
    #[wasm_bindgen]
    pub fn set_timeout(&mut self, seconds: u64) {
        self.timeout = seconds;
    }
    
    /// Get connection timeout
    #[wasm_bindgen]
    pub fn get_timeout(&self) -> u64 {
        self.timeout
    }
}

impl BridgeConfiguration {
    /// Get all URLs as a vec of strings (internal use)
    pub fn all_urls(&self) -> Vec<String> {
        let mut urls = vec![self.primary.clone()];
        urls.extend(self.fallbacks.clone());
        urls
    }
}

/// Helper to create common bridge configurations
#[wasm_bindgen]
pub struct BridgePresets;

#[wasm_bindgen]
impl BridgePresets {
    /// Development configuration (local bridge only)
    #[wasm_bindgen]
    pub fn development() -> BridgeConfiguration {
        BridgeConfiguration::local_only()
    }
    
    /// Production configuration with cloud bridge and local fallback
    /// 
    /// # Arguments
    /// * `cloud_url` - Your cloud bridge URL (e.g., "wss://bridge.yourwallet.com")
    #[wasm_bindgen]
    pub fn production(cloud_url: String) -> BridgeConfiguration {
        BridgeConfiguration::cloud_only(cloud_url)
    }
    
    /// Hybrid configuration: tries cloud first, falls back to local
    /// 
    /// Best for development/testing with real cloud bridge
    #[wasm_bindgen]
    pub fn hybrid(cloud_url: String) -> BridgeConfiguration {
        BridgeConfiguration::new(cloud_url, Some("ws://localhost:8080".to_string()))
    }
    
    /// Multi-region configuration with geographic fallbacks
    /// 
    /// # Arguments
    /// * `primary_region` - Primary bridge URL (e.g., "wss://us.bridge.yourwallet.com")
    /// * `fallback_regions` - Array of fallback URLs
    #[wasm_bindgen]
    pub fn multi_region(primary_region: String, fallback_regions: Vec<JsValue>) -> Result<BridgeConfiguration, JsValue> {
        BridgeConfiguration::with_fallbacks(primary_region, fallback_regions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_local_only() {
        let config = BridgeConfiguration::local_only();
        assert_eq!(config.get_primary(), "ws://localhost:8080");
        assert_eq!(config.all_urls().len(), 1);
    }
    
    #[test]
    fn test_cloud_with_fallback() {
        let config = BridgeConfiguration::new(
            "wss://bridge.example.com".to_string(),
            Some("ws://localhost:8080".to_string()),
        );
        assert_eq!(config.get_primary(), "wss://bridge.example.com");
        assert_eq!(config.all_urls().len(), 2);
        assert_eq!(config.all_urls()[1], "ws://localhost:8080");
    }
    
    #[test]
    fn test_presets() {
        let dev = BridgePresets::development();
        assert_eq!(dev.get_primary(), "ws://localhost:8080");
        
        let prod = BridgePresets::production("wss://example.com".to_string());
        assert_eq!(prod.get_primary(), "wss://example.com");
        
        let hybrid = BridgePresets::hybrid("wss://example.com".to_string());
        assert_eq!(hybrid.all_urls().len(), 2);
    }
}

