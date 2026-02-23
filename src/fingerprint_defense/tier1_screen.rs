//! Screen and Window Dimension Normalization (Tier 1: Critical)
//!
//! Reports standard 1920x1080 dimensions for all tor-wasm users.

use wasm_bindgen::prelude::*;
use js_sys::Reflect;
use super::profile::NormalizedProfile;
use super::proxy_helpers;

pub fn apply() -> Result<(), JsValue> {
    let global = js_sys::global();
    let screen = Reflect::get(&global, &JsValue::from_str("screen"))?;

    if !screen.is_undefined() {
        apply_to_screen(&screen)?;
    }

    apply_to_window(&global)?;
    Ok(())
}

/// Apply screen defenses to a specific screen object.
pub fn apply_to_screen(screen: &JsValue) -> Result<(), JsValue> {
    let screen_props: &[(&str, f64)] = &[
        ("width", NormalizedProfile::SCREEN_WIDTH as f64),
        ("height", NormalizedProfile::SCREEN_HEIGHT as f64),
        ("availWidth", NormalizedProfile::SCREEN_WIDTH as f64),
        ("availHeight", NormalizedProfile::SCREEN_HEIGHT as f64 - 40.0), // taskbar
        ("colorDepth", NormalizedProfile::SCREEN_COLOR_DEPTH as f64),
        ("pixelDepth", NormalizedProfile::SCREEN_PIXEL_DEPTH as f64),
        ("availLeft", 0.0),
        ("availTop", 0.0),
    ];

    for (prop, value) in screen_props {
        let val = *value;
        let getter = Closure::wrap(Box::new(move || -> JsValue {
            JsValue::from_f64(val)
        }) as Box<dyn FnMut() -> JsValue>);
        proxy_helpers::patch_getter(screen, prop, getter)?;
    }

    Ok(())
}

/// Apply window dimension defenses.
pub fn apply_to_window(window: &JsValue) -> Result<(), JsValue> {
    let window_props: &[(&str, f64)] = &[
        ("devicePixelRatio", 1.0),
        ("outerWidth", NormalizedProfile::SCREEN_WIDTH as f64),
        ("outerHeight", NormalizedProfile::SCREEN_HEIGHT as f64),
        ("innerWidth", NormalizedProfile::SCREEN_WIDTH as f64),
        ("innerHeight", NormalizedProfile::SCREEN_HEIGHT as f64 - 80.0),
        ("screenX", 0.0),
        ("screenY", 0.0),
        ("screenLeft", 0.0),
        ("screenTop", 0.0),
    ];

    for (prop, value) in window_props {
        let val = *value;
        let getter = Closure::wrap(Box::new(move || -> JsValue {
            JsValue::from_f64(val)
        }) as Box<dyn FnMut() -> JsValue>);
        proxy_helpers::patch_getter(window, prop, getter)?;
    }

    Ok(())
}
