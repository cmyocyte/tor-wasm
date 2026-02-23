//! Canvas Fingerprinting Defense (Tier 1: Critical)
//!
//! Applies session-stable deterministic pixel perturbation to canvas API outputs.
//! ~5% of pixels get ±1 perturbation on one RGB channel.
//!
//! The perturbation algorithm runs in WASM linear memory for:
//! - Binary opacity (the PRNG and perturbation logic is compiled)
//! - Near-native speed (no per-pixel FFI overhead)
//! - Consistent timing (eliminates timing-based detection)

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use js_sys::{Array, Reflect, Uint8ClampedArray, Uint8Array, Function};
use super::prng::SessionPrng;
use super::proxy_helpers;

pub fn apply() -> Result<(), JsValue> {
    let seed = SessionPrng::seed();

    apply_canvas_2d(seed)?;
    apply_webgl_read_pixels(seed)?;

    Ok(())
}

/// Perturb a pixel buffer in-place. Operates on raw bytes in WASM memory.
/// This is the hot path — runs entirely in compiled Rust.
fn perturb_pixels(data: &mut [u8], seed: u32) {
    let pixel_count = data.len() / 4;
    for px in 0..pixel_count {
        if !SessionPrng::should_perturb(seed, px as u32) {
            continue;
        }
        let channel = SessionPrng::perturb_channel(seed, px as u32) as usize;
        let delta = SessionPrng::perturb_delta(seed, px as u32);
        let idx = px * 4 + channel;
        let current = data[idx] as i32;
        data[idx] = (current + delta).clamp(0, 255) as u8;
    }
}

fn apply_canvas_2d(seed: u32) -> Result<(), JsValue> {
    let ctx2d_proto = proxy_helpers::get_prototype("CanvasRenderingContext2D")?;
    if ctx2d_proto.is_undefined() {
        return Ok(());
    }
    let canvas_proto = proxy_helpers::get_prototype("HTMLCanvasElement")?;

    // --- getImageData ---
    let orig_get_image_data = Reflect::get(&ctx2d_proto, &JsValue::from_str("getImageData"))?;
    let orig_gid = orig_get_image_data.clone();

    let apply_trap = Closure::wrap(Box::new(move |_target: JsValue, this_arg: JsValue, args: JsValue| -> Result<JsValue, JsValue> {
        // Call original getImageData
        let result = proxy_helpers::call_function(&orig_gid, &this_arg, &args)?;

        // Get the data property (Uint8ClampedArray)
        let data_val = Reflect::get(&result, &JsValue::from_str("data"))?;
        let data_arr: Uint8ClampedArray = data_val.unchecked_into();

        // Copy to WASM memory, perturb, copy back
        let mut buffer = vec![0u8; data_arr.length() as usize];
        data_arr.copy_to(&mut buffer);
        perturb_pixels(&mut buffer, seed);
        data_arr.copy_from(&buffer);

        Ok(result)
    }) as Box<dyn FnMut(JsValue, JsValue, JsValue) -> Result<JsValue, JsValue>>);

    let proxied = proxy_helpers::proxy_function_with_apply(&orig_get_image_data, apply_trap)?;
    Reflect::set(&ctx2d_proto, &JsValue::from_str("getImageData"), &proxied)?;

    // --- toDataURL ---
    let orig_to_data_url = Reflect::get(&canvas_proto, &JsValue::from_str("toDataURL"))?;
    let orig_tdu = orig_to_data_url.clone();

    let apply_trap = Closure::wrap(Box::new(move |_target: JsValue, this_arg: JsValue, args: JsValue| -> Result<JsValue, JsValue> {
        // Perturb the canvas content before serialization
        // Get 2d context and call getImageData (which is now our proxied version that perturbs)
        let get_ctx: Function = Reflect::get(&this_arg, &JsValue::from_str("getContext"))?.unchecked_into();
        let ctx = Reflect::apply(&get_ctx, &this_arg, &Array::of1(&JsValue::from_str("2d")))?;
        if !ctx.is_null() && !ctx.is_undefined() {
            let width = Reflect::get(&this_arg, &JsValue::from_str("width"))?.as_f64().unwrap_or(0.0);
            let height = Reflect::get(&this_arg, &JsValue::from_str("height"))?.as_f64().unwrap_or(0.0);
            if width > 0.0 && height > 0.0 {
                // getImageData triggers perturbation, putImageData writes back
                let get_id: Function = Reflect::get(&ctx, &JsValue::from_str("getImageData"))?.unchecked_into();
                let img_data = Reflect::apply(&get_id, &ctx, &Array::of4(
                    &JsValue::from_f64(0.0), &JsValue::from_f64(0.0),
                    &JsValue::from_f64(width), &JsValue::from_f64(height),
                ))?;
                let put_id: Function = Reflect::get(&ctx, &JsValue::from_str("putImageData"))?.unchecked_into();
                let _ = Reflect::apply(&put_id, &ctx, &Array::of3(
                    &img_data, &JsValue::from_f64(0.0), &JsValue::from_f64(0.0),
                ));
            }
        }
        // Call original toDataURL
        proxy_helpers::call_function(&orig_tdu, &this_arg, &args)
    }) as Box<dyn FnMut(JsValue, JsValue, JsValue) -> Result<JsValue, JsValue>>);

    let proxied = proxy_helpers::proxy_function_with_apply(&orig_to_data_url, apply_trap)?;
    Reflect::set(&canvas_proto, &JsValue::from_str("toDataURL"), &proxied)?;

    // --- toBlob ---
    let orig_to_blob = Reflect::get(&canvas_proto, &JsValue::from_str("toBlob"))?;
    let orig_tb = orig_to_blob.clone();

    let apply_trap = Closure::wrap(Box::new(move |_target: JsValue, this_arg: JsValue, args: JsValue| -> Result<JsValue, JsValue> {
        // Same perturbation approach as toDataURL
        let get_ctx: Function = Reflect::get(&this_arg, &JsValue::from_str("getContext"))?.unchecked_into();
        let ctx = Reflect::apply(&get_ctx, &this_arg, &Array::of1(&JsValue::from_str("2d")))?;
        if !ctx.is_null() && !ctx.is_undefined() {
            let width = Reflect::get(&this_arg, &JsValue::from_str("width"))?.as_f64().unwrap_or(0.0);
            let height = Reflect::get(&this_arg, &JsValue::from_str("height"))?.as_f64().unwrap_or(0.0);
            if width > 0.0 && height > 0.0 {
                let get_id: Function = Reflect::get(&ctx, &JsValue::from_str("getImageData"))?.unchecked_into();
                let img_data = Reflect::apply(&get_id, &ctx, &Array::of4(
                    &JsValue::from_f64(0.0), &JsValue::from_f64(0.0),
                    &JsValue::from_f64(width), &JsValue::from_f64(height),
                ))?;
                let put_id: Function = Reflect::get(&ctx, &JsValue::from_str("putImageData"))?.unchecked_into();
                let _ = Reflect::apply(&put_id, &ctx, &Array::of3(
                    &img_data, &JsValue::from_f64(0.0), &JsValue::from_f64(0.0),
                ));
            }
        }
        proxy_helpers::call_function(&orig_tb, &this_arg, &args)
    }) as Box<dyn FnMut(JsValue, JsValue, JsValue) -> Result<JsValue, JsValue>>);

    let proxied = proxy_helpers::proxy_function_with_apply(&orig_to_blob, apply_trap)?;
    Reflect::set(&canvas_proto, &JsValue::from_str("toBlob"), &proxied)?;

    Ok(())
}

fn apply_webgl_read_pixels(seed: u32) -> Result<(), JsValue> {
    let gl_names = ["WebGLRenderingContext", "WebGL2RenderingContext"];

    for gl_name in &gl_names {
        let proto = proxy_helpers::get_prototype(gl_name);
        if let Ok(proto) = proto {
            if proto.is_undefined() {
                continue;
            }

            let orig_read_pixels = Reflect::get(&proto, &JsValue::from_str("readPixels"))?;
            let orig_rp = orig_read_pixels.clone();

            let apply_trap = Closure::wrap(Box::new(move |_target: JsValue, this_arg: JsValue, args: JsValue| -> Result<JsValue, JsValue> {
                // Call original readPixels
                proxy_helpers::call_function(&orig_rp, &this_arg, &args)?;

                // Perturb the output buffer (7th argument)
                let args_arr: &Array = args.unchecked_ref();
                if args_arr.length() >= 7 {
                    let pixels = args_arr.get(6);
                    if !pixels.is_null() && !pixels.is_undefined() {
                        if let Ok(arr) = pixels.dyn_into::<Uint8Array>() {
                            let mut buffer = vec![0u8; arr.length() as usize];
                            arr.copy_to(&mut buffer);
                            perturb_pixels(&mut buffer, seed);
                            arr.copy_from(&buffer);
                        }
                    }
                }

                Ok(JsValue::UNDEFINED)
            }) as Box<dyn FnMut(JsValue, JsValue, JsValue) -> Result<JsValue, JsValue>>);

            let proxied = proxy_helpers::proxy_function_with_apply(&orig_read_pixels, apply_trap)?;
            Reflect::set(&proto, &JsValue::from_str("readPixels"), &proxied)?;
        }
    }

    Ok(())
}
