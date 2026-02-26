//! Lox anonymous credential client for WASM
//!
//! Manages trust-tiered bridge credentials in the browser.
//! Credentials are stored in IndexedDB and persist across sessions.
//!
//! Phase 1: HMAC-based credentials (server-linked, same API as BBS+).
//! Phase 2 (future): BBS+ blind signatures for unlinkability.
//!
//! Flow:
//!   1. First visit → `open_invite()` → level-0 credential
//!   2. `get_bridge()` → bridge URL from trust-appropriate pool
//!   3. After 7 days → `trust_migration()` → level 1 (better bridges)
//!   4. Bridge blocked → `check_blockage()` → migration token → new bridge
//!
//! Storage (IndexedDB `lox-credentials`):
//!   - id: credential identifier
//!   - credential: HMAC token (Phase 1) / blinded token (Phase 2)
//!   - trust_level: 0-3
//!   - bridge_url: currently assigned bridge
//!   - created_at: timestamp of first credential
//!   - last_use: timestamp of last bridge use

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response, Headers};
use serde::{Serialize, Deserialize};

/// Stored Lox credential (persisted in IndexedDB)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoxCredential {
    pub id: String,
    pub credential: String,
    pub trust_level: u32,
    pub bridge_url: Option<String>,
    pub bridge_fingerprint: Option<String>,
    pub authority_url: String,
    pub created_at: f64,
    pub last_use: f64,
}

/// Result of a bridge request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeInfo {
    pub bridge_url: String,
    pub bridge_fingerprint: String,
    pub trust_level: u32,
}

/// Result of a blockage check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockageResult {
    pub blocked: bool,
    pub migration_token: Option<String>,
    pub trust_level: u32,
}

/// Lox credential client
pub struct LoxClient {
    authority_url: String,
}

const IDB_STORE_NAME: &str = "lox-credentials";
const IDB_DB_NAME: &str = "tor-wasm-lox";
const CREDENTIAL_KEY: &str = "current";

impl LoxClient {
    /// Create a new Lox client pointing at the given authority URL.
    pub fn new(authority_url: &str) -> Self {
        Self {
            authority_url: authority_url.trim_end_matches('/').to_string(),
        }
    }

    /// Request an open invitation (new credential at trust level 0).
    ///
    /// Rate-limited: 1 per IP per 24 hours on the authority side.
    pub async fn open_invite(&self) -> Result<LoxCredential, String> {
        let url = format!("{}/lox/open-invite", self.authority_url);
        let resp = self.post_json(&url, "{}").await?;

        let id = resp.get("id")
            .and_then(|v| v.as_str())
            .ok_or("missing id in response")?
            .to_string();

        let credential = resp.get("credential")
            .and_then(|v| v.as_str())
            .ok_or("missing credential in response")?
            .to_string();

        let trust_level = resp.get("trust_level")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        let now = js_sys::Date::now();
        let cred = LoxCredential {
            id,
            credential,
            trust_level,
            bridge_url: None,
            bridge_fingerprint: None,
            authority_url: self.authority_url.clone(),
            created_at: now,
            last_use: now,
        };

        // Store in IndexedDB
        self.store_credential(&cred).await?;

        log::info!("Lox: received level-{} credential", trust_level);
        Ok(cred)
    }

    /// Exchange credential for a bridge URL.
    pub async fn get_bridge(&self, cred: &mut LoxCredential) -> Result<BridgeInfo, String> {
        let url = format!("{}/lox/get-bridge", self.authority_url);
        let body = serde_json::json!({
            "id": cred.id,
            "credential": cred.credential,
        }).to_string();

        let resp = self.post_json(&url, &body).await?;

        let bridge_url = resp.get("bridge_url")
            .and_then(|v| v.as_str())
            .ok_or("missing bridge_url")?
            .to_string();

        let fingerprint = resp.get("bridge_fingerprint")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let trust_level = resp.get("trust_level")
            .and_then(|v| v.as_u64())
            .unwrap_or(cred.trust_level as u64) as u32;

        // Update credential with bridge assignment
        cred.bridge_url = Some(bridge_url.clone());
        cred.bridge_fingerprint = Some(fingerprint.clone());
        cred.last_use = js_sys::Date::now();

        self.store_credential(cred).await?;

        Ok(BridgeInfo {
            bridge_url,
            bridge_fingerprint: fingerprint,
            trust_level,
        })
    }

    /// Request trust migration to the next level.
    ///
    /// Requires sufficient credential age (7d for level 1, 30d for 2, 90d for 3).
    pub async fn trust_migration(&self, cred: &mut LoxCredential) -> Result<u32, String> {
        let url = format!("{}/lox/trust-migration", self.authority_url);
        let body = serde_json::json!({
            "id": cred.id,
            "credential": cred.credential,
        }).to_string();

        let resp = self.post_json(&url, &body).await?;

        if let Some(err) = resp.get("error").and_then(|v| v.as_str()) {
            return Err(format!("migration failed: {}", err));
        }

        let new_level = resp.get("trust_level")
            .and_then(|v| v.as_u64())
            .ok_or("missing trust_level")? as u32;

        let new_credential = resp.get("credential")
            .and_then(|v| v.as_str())
            .ok_or("missing credential")?
            .to_string();

        cred.trust_level = new_level;
        cred.credential = new_credential;
        cred.last_use = js_sys::Date::now();

        self.store_credential(cred).await?;

        log::info!("Lox: migrated to trust level {}", new_level);
        Ok(new_level)
    }

    /// Report a blocked bridge and get a migration token for a new bridge.
    ///
    /// Trust level is preserved — users are not penalized for censorship.
    pub async fn check_blockage(
        &self,
        cred: &mut LoxCredential,
        bridge_fingerprint: &str,
    ) -> Result<BlockageResult, String> {
        let url = format!("{}/lox/check-blockage", self.authority_url);
        let body = serde_json::json!({
            "id": cred.id,
            "credential": cred.credential,
            "bridge_fingerprint": bridge_fingerprint,
        }).to_string();

        let resp = self.post_json(&url, &body).await?;

        let blocked = resp.get("blocked")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let migration_token = resp.get("migration_token")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let trust_level = resp.get("trust_level")
            .and_then(|v| v.as_u64())
            .unwrap_or(cred.trust_level as u64) as u32;

        // Clear blocked bridge from credential
        cred.bridge_url = None;
        cred.bridge_fingerprint = None;
        cred.last_use = js_sys::Date::now();

        self.store_credential(cred).await?;

        log::info!("Lox: reported blockage, trust level preserved at {}", trust_level);

        Ok(BlockageResult {
            blocked,
            migration_token,
            trust_level,
        })
    }

    /// Load stored credential from IndexedDB (if any).
    pub async fn load_credential(&self) -> Result<Option<LoxCredential>, String> {
        let window = web_sys::window().ok_or("no window")?;
        let idb_factory = window
            .indexed_db()
            .map_err(|_| "indexedDB not available")?
            .ok_or("indexedDB is null")?;

        // Open database
        let open_req = idb_factory
            .open(IDB_DB_NAME)
            .map_err(|e| format!("open failed: {:?}", e))?;

        let db = JsFuture::from(wasm_bindgen_futures::js_sys_ext::idb_request_to_promise(&open_req))
            .await
            .map_err(|e| format!("open await: {:?}", e))?;

        let db: web_sys::IdbDatabase = db.dyn_into()
            .map_err(|_| "not an IdbDatabase")?;

        // Check if store exists
        let store_names = db.object_store_names();
        let mut has_store = false;
        for i in 0..store_names.length() {
            if let Some(name) = store_names.get(i) {
                if name == IDB_STORE_NAME {
                    has_store = true;
                    break;
                }
            }
        }

        if !has_store {
            db.close();
            return Ok(None);
        }

        // Read credential
        let tx = db
            .transaction_with_str(IDB_STORE_NAME)
            .map_err(|e| format!("tx failed: {:?}", e))?;

        let store = tx
            .object_store(IDB_STORE_NAME)
            .map_err(|e| format!("store failed: {:?}", e))?;

        let get_req = store
            .get(&JsValue::from_str(CREDENTIAL_KEY))
            .map_err(|e| format!("get failed: {:?}", e))?;

        let result = JsFuture::from(wasm_bindgen_futures::js_sys_ext::idb_request_to_promise(&get_req))
            .await
            .map_err(|e| format!("get await: {:?}", e))?;

        db.close();

        if result.is_undefined() || result.is_null() {
            return Ok(None);
        }

        let cred: LoxCredential = serde_wasm_bindgen::from_value(result)
            .map_err(|e| format!("deserialize: {:?}", e))?;

        Ok(Some(cred))
    }

    /// Store credential in IndexedDB.
    async fn store_credential(&self, cred: &LoxCredential) -> Result<(), String> {
        let window = web_sys::window().ok_or("no window")?;
        let idb_factory = window
            .indexed_db()
            .map_err(|_| "indexedDB not available")?
            .ok_or("indexedDB is null")?;

        // Open database (create store if needed via onupgradeneeded)
        let open_req = idb_factory
            .open_with_u32(IDB_DB_NAME, 1)
            .map_err(|e| format!("open failed: {:?}", e))?;

        // Handle upgrade (create object store)
        let on_upgrade = Closure::once(move |event: web_sys::IdbVersionChangeEvent| {
            let db: web_sys::IdbDatabase = event
                .target()
                .unwrap()
                .dyn_into::<web_sys::IdbOpenDbRequest>()
                .unwrap()
                .result()
                .unwrap()
                .dyn_into()
                .unwrap();

            if !db.object_store_names().contains(&IDB_STORE_NAME.into()) {
                let _ = db.create_object_store(IDB_STORE_NAME);
            }
        });

        open_req.set_onupgradeneeded(Some(on_upgrade.as_ref().unchecked_ref()));
        on_upgrade.forget(); // leak to keep alive during async operation

        let db = JsFuture::from(wasm_bindgen_futures::js_sys_ext::idb_request_to_promise(&open_req))
            .await
            .map_err(|e| format!("open await: {:?}", e))?;

        let db: web_sys::IdbDatabase = db.dyn_into()
            .map_err(|_| "not an IdbDatabase")?;

        // Write credential
        let tx = db
            .transaction_with_str_and_mode(IDB_STORE_NAME, web_sys::IdbTransactionMode::Readwrite)
            .map_err(|e| format!("tx failed: {:?}", e))?;

        let store = tx
            .object_store(IDB_STORE_NAME)
            .map_err(|e| format!("store failed: {:?}", e))?;

        let value = serde_wasm_bindgen::to_value(cred)
            .map_err(|e| format!("serialize: {:?}", e))?;

        store
            .put_with_key(&value, &JsValue::from_str(CREDENTIAL_KEY))
            .map_err(|e| format!("put failed: {:?}", e))?;

        // Wait for transaction to complete
        let _ = JsFuture::from(wasm_bindgen_futures::js_sys_ext::idb_transaction_to_promise(&tx))
            .await;

        db.close();
        Ok(())
    }

    /// Helper: POST JSON to a URL and parse the response.
    async fn post_json(
        &self,
        url: &str,
        body: &str,
    ) -> Result<serde_json::Value, String> {
        let opts = RequestInit::new();
        opts.set_method("POST");
        opts.set_mode(RequestMode::Cors);
        opts.set_body(&JsValue::from_str(body));

        let request = Request::new_with_str_and_init(url, &opts)
            .map_err(|e| format!("Request::new: {:?}", e))?;

        request.headers()
            .set("Content-Type", "application/json")
            .map_err(|e| format!("set header: {:?}", e))?;

        let window = web_sys::window().ok_or("no window")?;
        let resp_value = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|e| format!("fetch: {:?}", e))?;

        let resp: Response = resp_value.dyn_into()
            .map_err(|_| "not a Response")?;

        let text = JsFuture::from(
            resp.text().map_err(|e| format!("text(): {:?}", e))?
        ).await
        .map_err(|e| format!("await text: {:?}", e))?;

        let text_str = text.as_string().ok_or("response not a string")?;

        if !resp.ok() {
            return Err(format!("HTTP {}: {}", resp.status(), text_str));
        }

        serde_json::from_str(&text_str)
            .map_err(|e| format!("JSON parse: {}", e))
    }
}

/// Helper: Check if a credential is eligible for trust migration.
pub fn days_until_migration(cred: &LoxCredential) -> f64 {
    let thresholds = [0.0, 7.0, 30.0, 90.0];
    let next_level = (cred.trust_level + 1) as usize;
    if next_level >= thresholds.len() {
        return f64::INFINITY; // Already at max
    }

    let days_since_creation = (js_sys::Date::now() - cred.created_at) / (24.0 * 60.0 * 60.0 * 1000.0);
    let needed = thresholds[next_level];
    (needed - days_since_creation).max(0.0)
}
