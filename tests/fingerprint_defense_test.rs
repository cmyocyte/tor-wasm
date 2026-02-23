//! Fingerprint Defense WASM Integration Tests
//!
//! Run with: wasm-pack test --headless --chrome
//! (or --firefox, --safari)

#![cfg(target_arch = "wasm32")]

use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;
use js_sys::{Object, Reflect, Array};

wasm_bindgen_test_configure!(run_in_browser);

// ===== PRNG Tests =====

#[wasm_bindgen_test]
fn prng_deterministic() {
    use tor_wasm::fingerprint_defense::prng::SessionPrng;

    let seed = 42u32;
    let a = SessionPrng::seeded_random(seed, 0);
    let b = SessionPrng::seeded_random(seed, 0);
    assert_eq!(a, b, "Same seed+index should produce same value");
}

#[wasm_bindgen_test]
fn prng_different_indices() {
    use tor_wasm::fingerprint_defense::prng::SessionPrng;

    let seed = 42u32;
    let a = SessionPrng::seeded_random(seed, 0);
    let b = SessionPrng::seeded_random(seed, 1);
    assert_ne!(a, b, "Different indices should produce different values");
}

#[wasm_bindgen_test]
fn prng_noise_in_range() {
    use tor_wasm::fingerprint_defense::prng::SessionPrng;

    for i in 0..100 {
        let noise = SessionPrng::seeded_noise(i);
        assert!(noise >= -1 && noise <= 1, "Noise {} out of range: {}", i, noise);
    }
}

#[wasm_bindgen_test]
fn prng_perturbation_rate() {
    use tor_wasm::fingerprint_defense::prng::SessionPrng;

    let mut count = 0;
    for i in 0..10000 {
        if SessionPrng::should_perturb(42, i) {
            count += 1;
        }
    }
    // ~5% perturbation rate (1/16 = 6.25%, allow some slack)
    assert!(count > 300, "Too few perturbations: {}", count);
    assert!(count < 1000, "Too many perturbations: {}", count);
}

// ===== Apply Defense Tests =====

#[wasm_bindgen_test]
fn apply_defense_default() {
    let result = tor_wasm::fingerprint_defense::apply_fingerprint_defense(JsValue::UNDEFINED)
        .expect("apply_fingerprint_defense should succeed");

    let count = Reflect::get(&result, &JsValue::from_str("count"))
        .unwrap()
        .as_f64()
        .unwrap();
    // Should apply all 20 defenses (19 categories + iframe)
    assert!(count >= 15.0, "Expected at least 15 defenses applied, got {}", count);

    let applied = Reflect::get(&result, &JsValue::from_str("applied")).unwrap();
    let arr: &Array = applied.unchecked_ref();
    assert!(arr.length() >= 15, "Expected at least 15 items in applied array");
}

#[wasm_bindgen_test]
fn apply_defense_selective() {
    let options = Object::new();
    Reflect::set(&options, &JsValue::from_str("webrtc"), &JsValue::TRUE).unwrap();
    Reflect::set(&options, &JsValue::from_str("canvas"), &JsValue::FALSE).unwrap();
    Reflect::set(&options, &JsValue::from_str("navigator"), &JsValue::FALSE).unwrap();
    Reflect::set(&options, &JsValue::from_str("screen"), &JsValue::FALSE).unwrap();
    Reflect::set(&options, &JsValue::from_str("webgl"), &JsValue::FALSE).unwrap();
    Reflect::set(&options, &JsValue::from_str("timezone"), &JsValue::FALSE).unwrap();
    Reflect::set(&options, &JsValue::from_str("audio"), &JsValue::FALSE).unwrap();
    Reflect::set(&options, &JsValue::from_str("fonts"), &JsValue::FALSE).unwrap();
    Reflect::set(&options, &JsValue::from_str("performance"), &JsValue::FALSE).unwrap();
    Reflect::set(&options, &JsValue::from_str("client_rects"), &JsValue::FALSE).unwrap();
    Reflect::set(&options, &JsValue::from_str("speech"), &JsValue::FALSE).unwrap();
    Reflect::set(&options, &JsValue::from_str("webgpu"), &JsValue::FALSE).unwrap();
    Reflect::set(&options, &JsValue::from_str("network"), &JsValue::FALSE).unwrap();
    Reflect::set(&options, &JsValue::from_str("storage"), &JsValue::FALSE).unwrap();
    Reflect::set(&options, &JsValue::from_str("media_devices"), &JsValue::FALSE).unwrap();
    Reflect::set(&options, &JsValue::from_str("battery"), &JsValue::FALSE).unwrap();
    Reflect::set(&options, &JsValue::from_str("gamepad"), &JsValue::FALSE).unwrap();
    Reflect::set(&options, &JsValue::from_str("css_media_queries"), &JsValue::FALSE).unwrap();
    Reflect::set(&options, &JsValue::from_str("workers"), &JsValue::FALSE).unwrap();
    Reflect::set(&options, &JsValue::from_str("iframe_protection"), &JsValue::FALSE).unwrap();

    let result = tor_wasm::fingerprint_defense::apply_fingerprint_defense(options.into())
        .expect("selective apply should succeed");

    let applied = Reflect::get(&result, &JsValue::from_str("applied")).unwrap();
    let arr: &Array = applied.unchecked_ref();
    assert_eq!(arr.length(), 1, "Should only apply webrtc");
    assert_eq!(arr.get(0).as_string().unwrap(), "webrtc");
}

// ===== Navigator Tests =====

#[wasm_bindgen_test]
fn navigator_platform_normalized() {
    // Apply navigator defense
    tor_wasm::fingerprint_defense::tier1_navigator::apply()
        .expect("navigator apply should succeed");

    let platform = js_sys::eval("navigator.platform")
        .unwrap()
        .as_string()
        .unwrap();
    assert_eq!(platform, "Linux x86_64", "Platform should be normalized");
}

#[wasm_bindgen_test]
fn navigator_hardware_concurrency() {
    let hc = js_sys::eval("navigator.hardwareConcurrency")
        .unwrap()
        .as_f64()
        .unwrap();
    assert_eq!(hc, 4.0, "hardwareConcurrency should be normalized to 4");
}

#[wasm_bindgen_test]
fn navigator_language() {
    let lang = js_sys::eval("navigator.language")
        .unwrap()
        .as_string()
        .unwrap();
    assert_eq!(lang, "en-US", "language should be normalized to en-US");
}

// ===== WebRTC Tests =====

#[wasm_bindgen_test]
fn webrtc_blocked() {
    // Apply WebRTC defense
    tor_wasm::fingerprint_defense::tier1_webrtc::apply()
        .expect("webrtc apply should succeed");

    let blocked = js_sys::eval(
        "try { new RTCPeerConnection(); false } catch(e) { e.name === 'NotAllowedError' }"
    ).unwrap();
    assert_eq!(blocked, JsValue::TRUE, "RTCPeerConnection should throw NotAllowedError");
}

// ===== Timezone Tests =====

#[wasm_bindgen_test]
fn timezone_offset_zero() {
    tor_wasm::fingerprint_defense::tier2_timezone::apply()
        .expect("timezone apply should succeed");

    let offset = js_sys::eval("new Date().getTimezoneOffset()")
        .unwrap()
        .as_f64()
        .unwrap();
    assert_eq!(offset, 0.0, "Timezone offset should be 0 (UTC)");
}

// ===== Performance Tests =====

#[wasm_bindgen_test]
fn performance_now_rounded() {
    tor_wasm::fingerprint_defense::tier2_performance::apply()
        .expect("performance apply should succeed");

    let remainder = js_sys::eval("performance.now() % 100")
        .unwrap()
        .as_f64()
        .unwrap();
    assert_eq!(remainder, 0.0, "performance.now() should be rounded to 100ms");
}

// ===== Screen Tests =====

#[wasm_bindgen_test]
fn screen_normalized() {
    tor_wasm::fingerprint_defense::tier1_screen::apply()
        .expect("screen apply should succeed");

    let width = js_sys::eval("screen.width")
        .unwrap()
        .as_f64()
        .unwrap();
    assert_eq!(width, 1920.0, "screen.width should be 1920");

    let height = js_sys::eval("screen.height")
        .unwrap()
        .as_f64()
        .unwrap();
    assert_eq!(height, 1080.0, "screen.height should be 1080");

    let dpr = js_sys::eval("window.devicePixelRatio")
        .unwrap()
        .as_f64()
        .unwrap();
    assert_eq!(dpr, 1.0, "devicePixelRatio should be 1.0");
}

// ===== WebGL Tests =====

#[wasm_bindgen_test]
fn webgl_debug_ext_blocked() {
    tor_wasm::fingerprint_defense::tier1_webgl::apply()
        .expect("webgl apply should succeed");

    let blocked = js_sys::eval(
        "try { var c=document.createElement('canvas'); var g=c.getContext('webgl'); \
         g ? g.getExtension('WEBGL_debug_renderer_info')===null : true } catch(e) { true }"
    ).unwrap();
    assert_eq!(blocked, JsValue::TRUE, "WEBGL_debug_renderer_info should be blocked");
}

// ===== Anti-Detection (toString) Tests =====

#[wasm_bindgen_test]
fn tostring_native_code() {
    // This is the key test — WASM closures must show "[native code]"
    // Apply navigator defense first to get getter installed
    tor_wasm::fingerprint_defense::tier1_navigator::apply()
        .expect("navigator apply should succeed");

    let result = js_sys::eval(
        "var d = Object.getOwnPropertyDescriptor(navigator, 'platform'); \
         d && d.get ? d.get.toString().includes('[native code]') : false"
    ).unwrap();
    assert_eq!(result, JsValue::TRUE, "Navigator getter toString should contain [native code]");
}

#[wasm_bindgen_test]
fn tostring_no_filename_leak() {
    // Error stack should show <wasm> not file paths
    let result = js_sys::eval(
        "var d = Object.getOwnPropertyDescriptor(navigator, 'platform'); \
         d && d.get ? !d.get.toString().includes('.js') && !d.get.toString().includes('.rs') : true"
    ).unwrap();
    assert_eq!(result, JsValue::TRUE, "Getter toString should not leak filenames");
}

// ===== Normalized Profile Test =====

#[wasm_bindgen_test]
fn normalized_profile_complete() {
    let profile = tor_wasm::fingerprint_defense::get_normalized_profile();
    assert!(!profile.is_undefined(), "Profile should not be undefined");

    let platform = Reflect::get(&profile, &JsValue::from_str("platform"))
        .unwrap()
        .as_string()
        .unwrap();
    assert_eq!(platform, "Linux x86_64");

    let ua = Reflect::get(&profile, &JsValue::from_str("userAgent"))
        .unwrap()
        .as_string()
        .unwrap();
    assert!(ua.contains("Firefox/115.0"), "UA should contain Firefox/115.0");

    let sr = Reflect::get(&profile, &JsValue::from_str("audioSampleRate"))
        .unwrap()
        .as_f64()
        .unwrap();
    assert_eq!(sr, 44100.0, "Audio sample rate should be 44100");
}

// ===== Check Defense Status Test =====

#[wasm_bindgen_test]
fn check_status_after_apply() {
    // Apply all defenses
    let _ = tor_wasm::fingerprint_defense::apply_fingerprint_defense(JsValue::UNDEFINED);

    let status = tor_wasm::fingerprint_defense::check_defense_status();
    assert!(!status.is_undefined(), "Status should not be undefined");

    let nav = Reflect::get(&status, &JsValue::from_str("navigator"))
        .unwrap_or(JsValue::FALSE);
    assert_eq!(nav, JsValue::TRUE, "Navigator defense should be active");
}

// ===== CSS Media Query Tests =====

#[wasm_bindgen_test]
fn css_media_queries_normalized() {
    tor_wasm::fingerprint_defense::tier3_hardening::apply_css_media_queries()
        .expect("css media queries apply should succeed");

    let light = js_sys::eval("window.matchMedia('(prefers-color-scheme: light)').matches")
        .unwrap();
    assert_eq!(light, JsValue::TRUE, "prefers-color-scheme should match light");

    let dark = js_sys::eval("window.matchMedia('(prefers-color-scheme: dark)').matches")
        .unwrap();
    assert_eq!(dark, JsValue::FALSE, "prefers-color-scheme should not match dark");
}

// ===== Gamepad Test =====

#[wasm_bindgen_test]
fn gamepad_empty() {
    tor_wasm::fingerprint_defense::tier3_hardening::apply_gamepad()
        .expect("gamepad apply should succeed");

    let gamepads = js_sys::eval("navigator.getGamepads ? navigator.getGamepads() : []")
        .unwrap();
    let arr: &Array = gamepads.unchecked_ref();
    assert_eq!(arr.length(), 0, "getGamepads should return empty array");
}
