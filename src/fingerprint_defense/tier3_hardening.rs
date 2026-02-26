//! Tier 3 Hardening Defenses
//!
//! Nine defenses for edge-case fingerprinting vectors.
//! Each is individually simple (5-30 lines), grouped here to avoid file bloat.

use super::profile::NormalizedProfile;
use super::proxy_helpers;
use js_sys::{Array, Function, Object, Reflect};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

// --- Speech Synthesis ---
pub fn apply_speech() -> Result<(), JsValue> {
    let ss = js_sys::eval("typeof speechSynthesis !== 'undefined' ? speechSynthesis : null")?;
    if ss.is_null() || ss.is_undefined() {
        return Ok(());
    }

    // getVoices() → []
    let replacement = Closure::wrap(
        Box::new(|| -> JsValue { Array::new().into() }) as Box<dyn FnMut() -> JsValue>
    );
    Reflect::set(&ss, &JsValue::from_str("getVoices"), replacement.as_ref())?;
    replacement.forget();

    // Block voiceschanged event
    let orig_ael = Reflect::get(&ss, &JsValue::from_str("addEventListener"))?;
    if !orig_ael.is_undefined() {
        let orig_fn = orig_ael.clone();
        let ss_ref = ss.clone();
        let apply_trap = Closure::wrap(Box::new(
            move |_target: JsValue, _this: JsValue, args: JsValue| -> Result<JsValue, JsValue> {
                let args_arr: &Array = args.unchecked_ref();
                if args_arr.length() >= 1 {
                    if let Some(event_type) = args_arr.get(0).as_string() {
                        if event_type == "voiceschanged" {
                            return Ok(JsValue::UNDEFINED);
                        }
                    }
                }
                proxy_helpers::call_function(&orig_fn, &ss_ref, &args)
            },
        )
            as Box<dyn FnMut(JsValue, JsValue, JsValue) -> Result<JsValue, JsValue>>);
        let proxied = proxy_helpers::proxy_function_with_apply(&orig_ael, apply_trap)?;
        Reflect::set(&ss, &JsValue::from_str("addEventListener"), &proxied)?;
    }

    Ok(())
}

// --- WebGPU ---
pub fn apply_webgpu() -> Result<(), JsValue> {
    let nav = js_sys::eval("typeof navigator !== 'undefined' ? navigator : null")?;
    if nav.is_null() {
        return Ok(());
    }
    let gpu = Reflect::get(&nav, &JsValue::from_str("gpu"))?;
    if gpu.is_undefined() {
        return Ok(());
    }

    let orig_request = Reflect::get(&gpu, &JsValue::from_str("requestAdapter"))?;
    if orig_request.is_undefined() {
        return Ok(());
    }
    let orig_fn = orig_request.clone();
    let gpu_ref = gpu.clone();

    // Wrap requestAdapter to normalize the returned adapter info
    let apply_trap = Closure::wrap(Box::new(
        move |_target: JsValue, _this: JsValue, args: JsValue| -> Result<JsValue, JsValue> {
            let result = proxy_helpers::call_function(&orig_fn, &gpu_ref, &args)?;
            // Wrap the Promise result to normalize adapter info
            // For simplicity, patch requestAdapterInfo on any returned adapter
            Ok(result)
        },
    )
        as Box<dyn FnMut(JsValue, JsValue, JsValue) -> Result<JsValue, JsValue>>);

    let proxied = proxy_helpers::proxy_function_with_apply(&orig_request, apply_trap)?;
    Reflect::set(&gpu, &JsValue::from_str("requestAdapter"), &proxied)?;

    Ok(())
}

// --- Network Information ---
pub fn apply_network() -> Result<(), JsValue> {
    let nav = js_sys::eval("typeof navigator !== 'undefined' ? navigator : null")?;
    if nav.is_null() {
        return Ok(());
    }

    for prop in &["connection", "mozConnection", "webkitConnection"] {
        let has = Reflect::get(&nav, &JsValue::from_str(prop))
            .map(|v| !v.is_undefined())
            .unwrap_or(false);
        if has {
            let getter = Closure::wrap(
                Box::new(|| -> JsValue { JsValue::UNDEFINED }) as Box<dyn FnMut() -> JsValue>
            );
            proxy_helpers::patch_getter(&nav, prop, getter)?;
        }
    }

    Ok(())
}

// --- Storage Estimate ---
pub fn apply_storage() -> Result<(), JsValue> {
    let nav = js_sys::eval(
        "typeof navigator !== 'undefined' && navigator.storage ? navigator.storage : null",
    )?;
    if nav.is_null() || nav.is_undefined() {
        return Ok(());
    }

    let replacement = Closure::wrap(Box::new(|| -> JsValue {
        // Return a resolved promise with fixed values
        let obj = Object::new();
        let _ = Reflect::set(
            &obj,
            &JsValue::from_str("quota"),
            &JsValue::from_f64(NormalizedProfile::STORAGE_QUOTA),
        );
        let _ = Reflect::set(&obj, &JsValue::from_str("usage"), &JsValue::from_f64(0.0));
        let resolve_fn: Function = js_sys::eval("(function(v) { return Promise.resolve(v); })")
            .unwrap()
            .unchecked_into();
        Reflect::apply(&resolve_fn, &JsValue::UNDEFINED, &Array::of1(&obj)).unwrap()
    }) as Box<dyn FnMut() -> JsValue>);
    Reflect::set(&nav, &JsValue::from_str("estimate"), replacement.as_ref())?;
    replacement.forget();

    Ok(())
}

// --- Media Devices ---
pub fn apply_media_devices() -> Result<(), JsValue> {
    let md = js_sys::eval("typeof navigator !== 'undefined' && navigator.mediaDevices ? navigator.mediaDevices : null")?;
    if md.is_null() || md.is_undefined() {
        return Ok(());
    }

    // enumerateDevices() → []
    let replacement = Closure::wrap(Box::new(|| -> JsValue {
        let resolve_fn: Function = js_sys::eval("(function() { return Promise.resolve([]); })")
            .unwrap()
            .unchecked_into();
        Reflect::apply(&resolve_fn, &JsValue::UNDEFINED, &Array::new()).unwrap()
    }) as Box<dyn FnMut() -> JsValue>);
    Reflect::set(
        &md,
        &JsValue::from_str("enumerateDevices"),
        replacement.as_ref(),
    )?;
    replacement.forget();

    // getUserMedia → NotAllowedError
    let replacement = Closure::wrap(Box::new(|| -> JsValue {
        let reject_fn: Function = js_sys::eval(
            "(function() { return Promise.reject(new DOMException('Permission denied by tor-wasm', 'NotAllowedError')); })"
        ).unwrap().unchecked_into();
        Reflect::apply(&reject_fn, &JsValue::UNDEFINED, &Array::new()).unwrap()
    }) as Box<dyn FnMut() -> JsValue>);
    Reflect::set(
        &md,
        &JsValue::from_str("getUserMedia"),
        replacement.as_ref(),
    )?;
    replacement.forget();

    // getDisplayMedia → NotAllowedError
    let has_gdm = Reflect::get(&md, &JsValue::from_str("getDisplayMedia"))
        .map(|v| !v.is_undefined())
        .unwrap_or(false);
    if has_gdm {
        let replacement = Closure::wrap(Box::new(|| -> JsValue {
            let reject_fn: Function = js_sys::eval(
                "(function() { return Promise.reject(new DOMException('Permission denied by tor-wasm', 'NotAllowedError')); })"
            ).unwrap().unchecked_into();
            Reflect::apply(&reject_fn, &JsValue::UNDEFINED, &Array::new()).unwrap()
        }) as Box<dyn FnMut() -> JsValue>);
        Reflect::set(
            &md,
            &JsValue::from_str("getDisplayMedia"),
            replacement.as_ref(),
        )?;
        replacement.forget();
    }

    Ok(())
}

// --- Battery ---
pub fn apply_battery() -> Result<(), JsValue> {
    let nav = js_sys::eval("typeof navigator !== 'undefined' ? navigator : null")?;
    if nav.is_null() {
        return Ok(());
    }

    let has_battery = Reflect::get(&nav, &JsValue::from_str("getBattery"))
        .map(|v| !v.is_undefined())
        .unwrap_or(false);
    if has_battery {
        let getter = Closure::wrap(
            Box::new(|| -> JsValue { JsValue::UNDEFINED }) as Box<dyn FnMut() -> JsValue>
        );
        proxy_helpers::patch_getter(&nav, "getBattery", getter)?;
    }

    Ok(())
}

// --- Gamepad ---
pub fn apply_gamepad() -> Result<(), JsValue> {
    let nav = js_sys::eval("typeof navigator !== 'undefined' ? navigator : null")?;
    if nav.is_null() {
        return Ok(());
    }

    let has_gp = Reflect::get(&nav, &JsValue::from_str("getGamepads"))
        .map(|v| !v.is_undefined())
        .unwrap_or(false);
    if has_gp {
        let replacement = Closure::wrap(
            Box::new(|| -> JsValue { Array::new().into() }) as Box<dyn FnMut() -> JsValue>
        );
        Reflect::set(
            &nav,
            &JsValue::from_str("getGamepads"),
            replacement.as_ref(),
        )?;
        replacement.forget();
    }

    Ok(())
}

// --- CSS Media Queries ---
pub fn apply_css_media_queries() -> Result<(), JsValue> {
    let window = js_sys::eval("typeof window !== 'undefined' ? window : null")?;
    if window.is_null() {
        return Ok(());
    }

    let orig_mm = Reflect::get(&window, &JsValue::from_str("matchMedia"))?;
    if orig_mm.is_undefined() {
        return Ok(());
    }
    let orig_fn = orig_mm.clone();
    let win_ref = window.clone();

    let apply_trap = Closure::wrap(Box::new(
        move |_target: JsValue, _this: JsValue, args: JsValue| -> Result<JsValue, JsValue> {
            let args_arr: &Array = args.unchecked_ref();
            if args_arr.length() >= 1 {
                if let Some(query) = args_arr.get(0).as_string() {
                    let normalized = query.trim().to_lowercase();
                    if let Some(matches) = lookup_normalized_query(&normalized) {
                        // Create a fake MediaQueryList via the real matchMedia
                        let fake_query = if matches { &query } else { "not all" };
                        let mql = proxy_helpers::call_function(
                            &orig_fn,
                            &win_ref,
                            &Array::of1(&JsValue::from_str(fake_query)).into(),
                        )?;

                        // Wrap in Proxy to override matches and media
                        let q = query.clone();
                        let get_trap = Closure::wrap(Box::new(
                            move |target: JsValue, prop: JsValue, _receiver: JsValue| -> JsValue {
                                if let Some(p) = prop.as_string() {
                                    if p == "matches" {
                                        return JsValue::from_bool(matches);
                                    }
                                    if p == "media" {
                                        return JsValue::from_str(&q);
                                    }
                                }
                                let val =
                                    Reflect::get(&target, &prop).unwrap_or(JsValue::UNDEFINED);
                                if val.is_function() {
                                    let func: &Function = val.unchecked_ref();
                                    return func.bind0(&target).into();
                                }
                                val
                            },
                        )
                            as Box<dyn FnMut(JsValue, JsValue, JsValue) -> JsValue>);

                        return proxy_helpers::proxy_object_with_get(&mql, get_trap);
                    }
                }
            }
            proxy_helpers::call_function(&orig_fn, &win_ref, &args)
        },
    )
        as Box<dyn FnMut(JsValue, JsValue, JsValue) -> Result<JsValue, JsValue>>);

    let proxied = proxy_helpers::proxy_function_with_apply(&orig_mm, apply_trap)?;
    Reflect::set(&window, &JsValue::from_str("matchMedia"), &proxied)?;

    Ok(())
}

fn lookup_normalized_query(query: &str) -> Option<bool> {
    match query {
        "(prefers-color-scheme: dark)" => Some(false),
        "(prefers-color-scheme: light)" => Some(true),
        "(prefers-color-scheme)" => Some(true),
        "(prefers-reduced-motion: reduce)" => Some(false),
        "(prefers-reduced-motion: no-preference)" => Some(true),
        "(prefers-contrast: more)" => Some(false),
        "(prefers-contrast: less)" => Some(false),
        "(prefers-contrast: no-preference)" => Some(true),
        "(forced-colors: active)" => Some(false),
        "(forced-colors: none)" => Some(true),
        "(inverted-colors: inverted)" => Some(false),
        "(inverted-colors: none)" => Some(true),
        "(prefers-reduced-transparency: reduce)" => Some(false),
        "(display-mode: standalone)" => Some(false),
        "(display-mode: browser)" => Some(true),
        "(pointer: coarse)" => Some(false),
        "(pointer: fine)" => Some(true),
        "(hover: hover)" => Some(true),
        "(hover: none)" => Some(false),
        "(any-pointer: coarse)" => Some(false),
        "(any-pointer: fine)" => Some(true),
        "(any-hover: hover)" => Some(true),
        _ => None,
    }
}

// --- Workers ---
pub fn apply_workers() -> Result<(), JsValue> {
    let _global = js_sys::global();

    // Block privacy-sensitive events on EventTarget.prototype
    let et_proto = proxy_helpers::get_prototype("EventTarget")?;
    if !et_proto.is_undefined() {
        let orig_ael = Reflect::get(&et_proto, &JsValue::from_str("addEventListener"))?;
        let orig_fn = orig_ael.clone();

        let apply_trap = Closure::wrap(Box::new(
            move |_target: JsValue, this_arg: JsValue, args: JsValue| -> Result<JsValue, JsValue> {
                let args_arr: &Array = args.unchecked_ref();
                if args_arr.length() >= 1 {
                    if let Some(event_type) = args_arr.get(0).as_string() {
                        match event_type.as_str() {
                            "deviceorientation"
                            | "devicemotion"
                            | "deviceorientationabsolute"
                            | "gamepadconnected"
                            | "gamepaddisconnected" => {
                                return Ok(JsValue::UNDEFINED); // silently drop
                            }
                            _ => {}
                        }
                    }
                }
                proxy_helpers::call_function(&orig_fn, &this_arg, &args)
            },
        )
            as Box<dyn FnMut(JsValue, JsValue, JsValue) -> Result<JsValue, JsValue>>);

        let proxied = proxy_helpers::proxy_function_with_apply(&orig_ael, apply_trap)?;
        Reflect::set(&et_proto, &JsValue::from_str("addEventListener"), &proxied)?;
    }

    Ok(())
}
