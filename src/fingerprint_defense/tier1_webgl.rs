//! WebGL Fingerprinting Defense (Tier 1: Critical)
//!
//! Normalizes WebGL vendor/renderer strings and blocks debug info extension.

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use js_sys::{Array, Reflect};
use super::profile::NormalizedProfile;
use super::proxy_helpers;

pub fn apply() -> Result<(), JsValue> {
    let gl_names = ["WebGLRenderingContext", "WebGL2RenderingContext"];

    for gl_name in &gl_names {
        let proto = proxy_helpers::get_prototype(gl_name);
        if let Ok(proto) = proto {
            if proto.is_undefined() {
                continue;
            }
            apply_to_gl_proto(&proto)?;
        }
    }

    Ok(())
}

fn apply_to_gl_proto(proto: &JsValue) -> Result<(), JsValue> {
    // --- getParameter ---
    let orig_get_param = Reflect::get(proto, &JsValue::from_str("getParameter"))?;
    let orig_gp = orig_get_param.clone();

    let apply_trap = Closure::wrap(Box::new(move |_target: JsValue, this_arg: JsValue, args: JsValue| -> Result<JsValue, JsValue> {
        let args_arr: &Array = args.unchecked_ref();
        if args_arr.length() >= 1 {
            let param = args_arr.get(0).as_f64().unwrap_or(0.0) as u32;
            match param {
                // UNMASKED_VENDOR_WEBGL (0x9245) and GL_VENDOR (0x1F00)
                0x9245 | 0x1F00 => return Ok(JsValue::from_str(NormalizedProfile::WEBGL_VENDOR)),
                // UNMASKED_RENDERER_WEBGL (0x9246) and GL_RENDERER (0x1F01)
                0x9246 | 0x1F01 => return Ok(JsValue::from_str(NormalizedProfile::WEBGL_RENDERER)),
                // MAX_TEXTURE_SIZE
                0x0D33 => return Ok(JsValue::from_f64(16384.0)),
                // MAX_VIEWPORT_DIMS
                0x0D3A => {
                    let arr = js_sys::Int32Array::new_with_length(2);
                    arr.set_index(0, 16384);
                    arr.set_index(1, 16384);
                    return Ok(arr.into());
                }
                // MAX_RENDERBUFFER_SIZE
                0x84E8 => return Ok(JsValue::from_f64(16384.0)),
                _ => {}
            }
        }
        proxy_helpers::call_function(&orig_gp, &this_arg, &args)
    }) as Box<dyn FnMut(JsValue, JsValue, JsValue) -> Result<JsValue, JsValue>>);

    let proxied = proxy_helpers::proxy_function_with_apply(&orig_get_param, apply_trap)?;
    Reflect::set(proto, &JsValue::from_str("getParameter"), &proxied)?;

    // --- getExtension ---
    let orig_get_ext = Reflect::get(proto, &JsValue::from_str("getExtension"))?;
    let orig_ge = orig_get_ext.clone();

    let apply_trap = Closure::wrap(Box::new(move |_target: JsValue, this_arg: JsValue, args: JsValue| -> Result<JsValue, JsValue> {
        let args_arr: &Array = args.unchecked_ref();
        if args_arr.length() >= 1 {
            if let Some(name) = args_arr.get(0).as_string() {
                if name == "WEBGL_debug_renderer_info" {
                    return Ok(JsValue::NULL);
                }
            }
        }
        proxy_helpers::call_function(&orig_ge, &this_arg, &args)
    }) as Box<dyn FnMut(JsValue, JsValue, JsValue) -> Result<JsValue, JsValue>>);

    let proxied = proxy_helpers::proxy_function_with_apply(&orig_get_ext, apply_trap)?;
    Reflect::set(proto, &JsValue::from_str("getExtension"), &proxied)?;

    // --- getSupportedExtensions ---
    let orig_gse = Reflect::get(proto, &JsValue::from_str("getSupportedExtensions"))?;
    let orig_gse2 = orig_gse.clone();

    let apply_trap = Closure::wrap(Box::new(move |_target: JsValue, this_arg: JsValue, args: JsValue| -> Result<JsValue, JsValue> {
        let result = proxy_helpers::call_function(&orig_gse2, &this_arg, &args)?;
        if result.is_null() {
            return Ok(result);
        }
        let arr: &Array = result.unchecked_ref();
        let filtered = Array::new();
        for i in 0..arr.length() {
            let ext = arr.get(i);
            if let Some(name) = ext.as_string() {
                if name != "WEBGL_debug_renderer_info" {
                    filtered.push(&ext);
                }
            }
        }
        Ok(filtered.into())
    }) as Box<dyn FnMut(JsValue, JsValue, JsValue) -> Result<JsValue, JsValue>>);

    let proxied = proxy_helpers::proxy_function_with_apply(&orig_gse, apply_trap)?;
    Reflect::set(proto, &JsValue::from_str("getSupportedExtensions"), &proxied)?;

    Ok(())
}
