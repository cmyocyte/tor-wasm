//! Navigator Property Normalization (Tier 1: Critical)
//!
//! Overrides navigator properties to match Tor Browser's Firefox ESR 115 on Linux.
//! All getters are WASM closures → native toString() automatically.

use super::profile::NormalizedProfile;
use super::proxy_helpers;
use js_sys::Reflect;
use wasm_bindgen::prelude::*;

pub fn apply() -> Result<(), JsValue> {
    let global = js_sys::global();
    let navigator = Reflect::get(&global, &JsValue::from_str("navigator"))?;

    if navigator.is_undefined() {
        return Ok(());
    }

    apply_to_navigator(&navigator)?;
    Ok(())
}

/// Apply navigator defenses to a specific navigator object.
/// Called by both the main apply() and iframe_observer for iframe patching.
pub fn apply_to_navigator(navigator: &JsValue) -> Result<(), JsValue> {
    // Simple property overrides
    let props: &[(&str, JsValue)] = &[
        ("platform", JsValue::from_str(NormalizedProfile::PLATFORM)),
        (
            "userAgent",
            JsValue::from_str(NormalizedProfile::USER_AGENT),
        ),
        ("vendor", JsValue::from_str(NormalizedProfile::VENDOR)),
        (
            "appVersion",
            JsValue::from_str(NormalizedProfile::APP_VERSION),
        ),
        ("language", JsValue::from_str(NormalizedProfile::LANGUAGE)),
        (
            "hardwareConcurrency",
            JsValue::from_f64(NormalizedProfile::HARDWARE_CONCURRENCY as f64),
        ),
        (
            "maxTouchPoints",
            JsValue::from_f64(NormalizedProfile::MAX_TOUCH_POINTS as f64),
        ),
        ("cookieEnabled", JsValue::TRUE),
        ("onLine", JsValue::TRUE),
        ("pdfViewerEnabled", JsValue::FALSE),
        ("webdriver", JsValue::FALSE),
    ];

    for (prop, value) in props {
        let val = value.clone();
        let getter = Closure::wrap(
            Box::new(move || -> JsValue { val.clone() }) as Box<dyn FnMut() -> JsValue>
        );
        proxy_helpers::patch_getter(navigator, prop, getter)?;
    }

    // doNotTrack = null (Tor Browser default — sending DNT is itself distinguishing)
    let getter =
        Closure::wrap(Box::new(|| -> JsValue { JsValue::NULL }) as Box<dyn FnMut() -> JsValue>);
    proxy_helpers::patch_getter(navigator, "doNotTrack", getter)?;

    // languages — frozen array
    let languages = proxy_helpers::frozen_string_array(NormalizedProfile::LANGUAGES);
    let getter = Closure::wrap(
        Box::new(move || -> JsValue { languages.clone() }) as Box<dyn FnMut() -> JsValue>
    );
    proxy_helpers::patch_getter(navigator, "languages", getter)?;

    // deviceMemory (not all browsers have this)
    let has_device_memory = Reflect::get(navigator, &JsValue::from_str("deviceMemory"))
        .map(|v| !v.is_undefined())
        .unwrap_or(false);
    if has_device_memory {
        let getter = Closure::wrap(Box::new(|| -> JsValue {
            JsValue::from_f64(NormalizedProfile::DEVICE_MEMORY as f64)
        }) as Box<dyn FnMut() -> JsValue>);
        proxy_helpers::patch_getter(navigator, "deviceMemory", getter)?;
    }

    // plugins — empty PluginArray
    let getter = Closure::wrap(
        Box::new(|| -> JsValue { proxy_helpers::empty_plugin_array() })
            as Box<dyn FnMut() -> JsValue>,
    );
    proxy_helpers::patch_getter(navigator, "plugins", getter)?;

    // mimeTypes — empty MimeTypeArray
    let getter = Closure::wrap(
        Box::new(|| -> JsValue { proxy_helpers::empty_plugin_array() })
            as Box<dyn FnMut() -> JsValue>,
    );
    proxy_helpers::patch_getter(navigator, "mimeTypes", getter)?;

    // sendBeacon — block (tracking vector)
    let send_beacon = Reflect::get(navigator, &JsValue::from_str("sendBeacon"));
    if let Ok(sb) = send_beacon {
        if !sb.is_undefined() {
            let replacement = Closure::wrap(
                Box::new(|| -> JsValue { JsValue::FALSE }) as Box<dyn FnMut() -> JsValue>
            );
            Reflect::set(
                navigator,
                &JsValue::from_str("sendBeacon"),
                replacement.as_ref(),
            )?;
            replacement.forget();
        }
    }

    Ok(())
}
