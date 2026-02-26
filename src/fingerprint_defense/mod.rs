//! Rust/WASM Fingerprint Defense Module
//!
//! Comprehensive browser fingerprint resistance compiled to WebAssembly.
//! All API overrides are WASM closures that natively return `"[native code]"`
//! from `Function.prototype.toString()`, eliminating the need for JS-level
//! toString spoofing.
//!
//! ## Usage
//!
//! ```javascript
//! import init, { apply_fingerprint_defense } from './pkg/tor_wasm.js';
//! await init();
//! apply_fingerprint_defense();           // Apply all 19 defenses
//! apply_fingerprint_defense({ canvas: true, webgl: false }); // Selective
//! ```
//!
//! ## Advantages over JS version
//!
//! - **Native toString()**: WASM closures return `"[native code]"` automatically
//! - **Binary opacity**: Defense logic is compiled, not inspectable
//! - **Stack trace opacity**: Shows `<wasm>` frames, not filenames
//! - **Near-native timing**: Eliminates timing-based detection
//! - **Iframe protection**: MutationObserver patches dynamically created iframes

use js_sys::{Array, Object, Reflect};
use wasm_bindgen::prelude::*;

pub mod iframe_observer;
pub mod prng;
pub mod profile;
pub mod proxy_helpers;
pub mod tier1_canvas;
pub mod tier1_navigator;
pub mod tier1_screen;
pub mod tier1_webgl;
pub mod tier1_webrtc;
pub mod tier2_audio;
pub mod tier2_client_rects;
pub mod tier2_fonts;
pub mod tier2_performance;
pub mod tier2_timezone;
pub mod tier3_hardening;

use profile::{DefenseConfig, NormalizedProfile};

/// Apply fingerprint defenses. Each category can be individually toggled.
///
/// Pass a JS object with boolean fields to selectively enable/disable defenses:
/// ```javascript
/// apply_fingerprint_defense({ webrtc: true, canvas: true, timezone: false });
/// ```
///
/// Returns `{ applied: string[], count: number, normalized: object }`.
#[wasm_bindgen]
pub fn apply_fingerprint_defense(options: JsValue) -> Result<JsValue, JsValue> {
    let config: DefenseConfig = if options.is_undefined() || options.is_null() {
        DefenseConfig::default()
    } else {
        serde_wasm_bindgen::from_value(options).unwrap_or_else(|_| DefenseConfig::default())
    };

    let mut applied: Vec<&str> = Vec::new();

    // Tier 1: Critical
    if config.webrtc {
        tier1_webrtc::apply()?;
        applied.push("webrtc");
    }
    if config.canvas {
        tier1_canvas::apply()?;
        applied.push("canvas");
    }
    if config.webgl {
        tier1_webgl::apply()?;
        applied.push("webgl");
    }
    if config.navigator {
        tier1_navigator::apply()?;
        applied.push("navigator");
    }
    if config.screen {
        tier1_screen::apply()?;
        applied.push("screen");
    }

    // Tier 2: Important
    if config.timezone {
        tier2_timezone::apply()?;
        applied.push("timezone");
    }
    if config.audio {
        tier2_audio::apply()?;
        applied.push("audio");
    }
    if config.fonts {
        tier2_fonts::apply()?;
        applied.push("fonts");
    }
    if config.performance {
        tier2_performance::apply()?;
        applied.push("performance");
    }
    if config.client_rects {
        tier2_client_rects::apply()?;
        applied.push("clientRects");
    }

    // Tier 3: Hardening
    if config.speech {
        tier3_hardening::apply_speech()?;
        applied.push("speech");
    }
    if config.webgpu {
        tier3_hardening::apply_webgpu()?;
        applied.push("webgpu");
    }
    if config.network {
        tier3_hardening::apply_network()?;
        applied.push("network");
    }
    if config.storage {
        tier3_hardening::apply_storage()?;
        applied.push("storage");
    }
    if config.media_devices {
        tier3_hardening::apply_media_devices()?;
        applied.push("mediaDevices");
    }
    if config.battery {
        tier3_hardening::apply_battery()?;
        applied.push("battery");
    }
    if config.gamepad {
        tier3_hardening::apply_gamepad()?;
        applied.push("gamepad");
    }
    if config.css_media_queries {
        tier3_hardening::apply_css_media_queries()?;
        applied.push("cssMediaQueries");
    }
    if config.workers {
        tier3_hardening::apply_workers()?;
        applied.push("workers");
    }

    // Iframe protection (new — not in JS version)
    if config.iframe_protection {
        iframe_observer::start_iframe_protection(&config)?;
        applied.push("iframeProtection");
    }

    // Build return value
    let result = Object::new();
    let applied_arr = Array::new();
    for name in &applied {
        applied_arr.push(&JsValue::from_str(name));
    }
    Reflect::set(&result, &JsValue::from_str("applied"), &applied_arr)?;
    Reflect::set(
        &result,
        &JsValue::from_str("count"),
        &JsValue::from_f64(applied.len() as f64),
    )?;
    Reflect::set(
        &result,
        &JsValue::from_str("normalized"),
        &build_normalized_object()?,
    )?;

    Ok(result.into())
}

/// Verify defense status — checks each defense is active.
#[wasm_bindgen]
pub fn check_defense_status() -> JsValue {
    let status = Object::new();

    // Navigator check
    if let Ok(nav) = proxy_helpers::get_global("navigator") {
        if let Ok(platform) = Reflect::get(&nav, &JsValue::from_str("platform")) {
            let _ = Reflect::set(
                &status,
                &JsValue::from_str("navigator"),
                &JsValue::from_bool(
                    platform.as_string().as_deref() == Some(NormalizedProfile::PLATFORM),
                ),
            );
        }
    }

    // WebRTC check
    let webrtc_blocked = js_sys::eval("try { new RTCPeerConnection(); false } catch(e) { true }")
        .unwrap_or(JsValue::FALSE);
    let _ = Reflect::set(&status, &JsValue::from_str("webrtc"), &webrtc_blocked);

    // Screen check
    if let Ok(screen) = proxy_helpers::get_global("screen") {
        if let Ok(width) = Reflect::get(&screen, &JsValue::from_str("width")) {
            let _ = Reflect::set(
                &status,
                &JsValue::from_str("screen"),
                &JsValue::from_bool(width.as_f64() == Some(NormalizedProfile::SCREEN_WIDTH as f64)),
            );
        }
    }

    // Timezone check
    let tz = js_sys::eval("new Date().getTimezoneOffset()").unwrap_or(JsValue::from_f64(-1.0));
    let _ = Reflect::set(
        &status,
        &JsValue::from_str("timezone"),
        &JsValue::from_bool(tz.as_f64() == Some(0.0)),
    );

    // Performance check
    let perf = js_sys::eval("performance.now() % 100").unwrap_or(JsValue::from_f64(1.0));
    let _ = Reflect::set(
        &status,
        &JsValue::from_str("performance"),
        &JsValue::from_bool(perf.as_f64() == Some(0.0)),
    );

    // WebGL check
    let webgl = js_sys::eval(
        "try { var c=document.createElement('canvas'); var g=c.getContext('webgl'); \
         g ? g.getExtension('WEBGL_debug_renderer_info')===null : true } catch(e) { true }",
    )
    .unwrap_or(JsValue::FALSE);
    let _ = Reflect::set(&status, &JsValue::from_str("webgl"), &webgl);

    // Anti-detection check (the key test)
    let antidetect = js_sys::eval(
        "try { var d=Object.getOwnPropertyDescriptor(navigator,'platform'); \
         d && d.get ? d.get.toString().includes('[native code]') : false } catch(e) { false }",
    )
    .unwrap_or(JsValue::FALSE);
    let _ = Reflect::set(&status, &JsValue::from_str("antiDetection"), &antidetect);

    status.into()
}

/// Get the normalized browser profile.
#[wasm_bindgen]
pub fn get_normalized_profile() -> JsValue {
    build_normalized_object().unwrap_or(JsValue::UNDEFINED)
}

fn build_normalized_object() -> Result<JsValue, JsValue> {
    let obj = Object::new();
    Reflect::set(
        &obj,
        &JsValue::from_str("platform"),
        &JsValue::from_str(NormalizedProfile::PLATFORM),
    )?;
    Reflect::set(
        &obj,
        &JsValue::from_str("userAgent"),
        &JsValue::from_str(NormalizedProfile::USER_AGENT),
    )?;
    Reflect::set(
        &obj,
        &JsValue::from_str("vendor"),
        &JsValue::from_str(NormalizedProfile::VENDOR),
    )?;
    Reflect::set(
        &obj,
        &JsValue::from_str("language"),
        &JsValue::from_str(NormalizedProfile::LANGUAGE),
    )?;
    Reflect::set(
        &obj,
        &JsValue::from_str("hardwareConcurrency"),
        &JsValue::from_f64(NormalizedProfile::HARDWARE_CONCURRENCY as f64),
    )?;
    Reflect::set(
        &obj,
        &JsValue::from_str("deviceMemory"),
        &JsValue::from_f64(NormalizedProfile::DEVICE_MEMORY as f64),
    )?;
    Reflect::set(
        &obj,
        &JsValue::from_str("screenWidth"),
        &JsValue::from_f64(NormalizedProfile::SCREEN_WIDTH as f64),
    )?;
    Reflect::set(
        &obj,
        &JsValue::from_str("screenHeight"),
        &JsValue::from_f64(NormalizedProfile::SCREEN_HEIGHT as f64),
    )?;
    Reflect::set(
        &obj,
        &JsValue::from_str("timezone"),
        &JsValue::from_str(NormalizedProfile::TIMEZONE),
    )?;
    Reflect::set(
        &obj,
        &JsValue::from_str("webglVendor"),
        &JsValue::from_str(NormalizedProfile::WEBGL_VENDOR),
    )?;
    Reflect::set(
        &obj,
        &JsValue::from_str("webglRenderer"),
        &JsValue::from_str(NormalizedProfile::WEBGL_RENDERER),
    )?;
    Reflect::set(
        &obj,
        &JsValue::from_str("audioSampleRate"),
        &JsValue::from_f64(NormalizedProfile::AUDIO_SAMPLE_RATE as f64),
    )?;
    Reflect::set(
        &obj,
        &JsValue::from_str("performancePrecision"),
        &JsValue::from_f64(NormalizedProfile::PERFORMANCE_PRECISION_MS),
    )?;
    Ok(obj.into())
}
