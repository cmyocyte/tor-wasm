//! Normalized browser profile and defense configuration.
//!
//! All tor-wasm users report identical values, modeled after
//! Tor Browser's Firefox ESR 115 on Linux.

use serde::{Serialize, Deserialize};

/// The normalized browser fingerprint profile.
/// Every tor-wasm user appears identical.
pub struct NormalizedProfile;

impl NormalizedProfile {
    pub const PLATFORM: &'static str = "Linux x86_64";
    pub const USER_AGENT: &'static str =
        "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0";
    pub const VENDOR: &'static str = "";
    pub const APP_VERSION: &'static str = "5.0 (X11)";
    pub const LANGUAGE: &'static str = "en-US";
    pub const LANGUAGES: &'static [&'static str] = &["en-US", "en"];
    pub const HARDWARE_CONCURRENCY: u32 = 4;
    pub const DEVICE_MEMORY: u32 = 8;
    pub const MAX_TOUCH_POINTS: u32 = 0;
    pub const SCREEN_WIDTH: u32 = 1920;
    pub const SCREEN_HEIGHT: u32 = 1080;
    pub const SCREEN_COLOR_DEPTH: u32 = 24;
    pub const SCREEN_PIXEL_DEPTH: u32 = 24;
    pub const TIMEZONE_OFFSET: i32 = 0;
    pub const TIMEZONE: &'static str = "UTC";
    pub const WEBGL_VENDOR: &'static str = "Mozilla";
    pub const WEBGL_RENDERER: &'static str = "Mozilla";
    pub const AUDIO_SAMPLE_RATE: u32 = 44100;
    pub const AUDIO_MAX_CHANNELS: u32 = 2;
    pub const PERFORMANCE_PRECISION_MS: f64 = 100.0;
    pub const STORAGE_QUOTA: f64 = 1_073_741_824.0; // 1GB
}

/// Configuration for which defenses to apply.
/// All defenses are enabled by default.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DefenseConfig {
    // Tier 1: Critical
    pub webrtc: bool,
    pub canvas: bool,
    pub webgl: bool,
    pub navigator: bool,
    pub screen: bool,
    // Tier 2: Important
    pub timezone: bool,
    pub audio: bool,
    pub fonts: bool,
    pub performance: bool,
    pub client_rects: bool,
    // Tier 3: Hardening
    pub speech: bool,
    pub webgpu: bool,
    pub network: bool,
    pub storage: bool,
    pub media_devices: bool,
    pub battery: bool,
    pub gamepad: bool,
    pub css_media_queries: bool,
    pub workers: bool,
    // New: iframe protection
    pub iframe_protection: bool,
}

impl Default for DefenseConfig {
    fn default() -> Self {
        Self {
            webrtc: true,
            canvas: true,
            webgl: true,
            navigator: true,
            screen: true,
            timezone: true,
            audio: true,
            fonts: true,
            performance: true,
            client_rects: true,
            speech: true,
            webgpu: true,
            network: true,
            storage: true,
            media_devices: true,
            battery: true,
            gamepad: true,
            css_media_queries: true,
            workers: true,
            iframe_protection: true,
        }
    }
}
