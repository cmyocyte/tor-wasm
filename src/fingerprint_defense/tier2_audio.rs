//! Audio Fingerprinting Defense (Tier 2: Important)
//!
//! Injects noise into AnalyserNode frequency/time-domain data and
//! normalizes AudioContext sample rate and channel count.

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use js_sys::{Array, Float32Array, Uint8Array, Reflect};
use super::prng::SessionPrng;
use super::profile::NormalizedProfile;
use super::proxy_helpers;

pub fn apply() -> Result<(), JsValue> {
    let seed = SessionPrng::seed();

    apply_analyser_node(seed)?;
    apply_audio_context_props()?;

    Ok(())
}

fn apply_analyser_node(seed: u32) -> Result<(), JsValue> {
    let proto = proxy_helpers::get_prototype("AnalyserNode");
    if let Ok(proto) = proto {
        if proto.is_undefined() {
            return Ok(());
        }

        // getFloatFrequencyData — add tiny noise
        let orig = Reflect::get(&proto, &JsValue::from_str("getFloatFrequencyData"))?;
        let orig_fn = orig.clone();

        let apply_trap = Closure::wrap(Box::new(move |_target: JsValue, this_arg: JsValue, args: JsValue| -> Result<JsValue, JsValue> {
            proxy_helpers::call_function(&orig_fn, &this_arg, &args)?;
            let args_arr: &Array = args.unchecked_ref();
            if args_arr.length() >= 1 {
                let arr_val = args_arr.get(0);
                if let Ok(arr) = arr_val.dyn_into::<Float32Array>() {
                    let mut buffer = vec![0f32; arr.length() as usize];
                    arr.copy_to(&mut buffer);
                    for (i, val) in buffer.iter_mut().enumerate() {
                        let noise = ((SessionPrng::seeded_random(seed, i as u32 + 0x700000) & 0xFF) as f32 - 128.0) * 0.00001;
                        *val += noise;
                    }
                    arr.copy_from(&buffer);
                }
            }
            Ok(JsValue::UNDEFINED)
        }) as Box<dyn FnMut(JsValue, JsValue, JsValue) -> Result<JsValue, JsValue>>);

        let proxied = proxy_helpers::proxy_function_with_apply(&orig, apply_trap)?;
        Reflect::set(&proto, &JsValue::from_str("getFloatFrequencyData"), &proxied)?;

        // getByteFrequencyData — add ±1 to ~6% of entries
        let orig = Reflect::get(&proto, &JsValue::from_str("getByteFrequencyData"))?;
        let orig_fn = orig.clone();

        let apply_trap = Closure::wrap(Box::new(move |_target: JsValue, this_arg: JsValue, args: JsValue| -> Result<JsValue, JsValue> {
            proxy_helpers::call_function(&orig_fn, &this_arg, &args)?;
            let args_arr: &Array = args.unchecked_ref();
            if args_arr.length() >= 1 {
                let arr_val = args_arr.get(0);
                if let Ok(arr) = arr_val.dyn_into::<Uint8Array>() {
                    let mut buffer = vec![0u8; arr.length() as usize];
                    arr.copy_to(&mut buffer);
                    for (i, val) in buffer.iter_mut().enumerate() {
                        if (SessionPrng::seeded_random(seed, i as u32 + 0x800000) & 0xF) == 0 {
                            let delta = if SessionPrng::seeded_random(seed, i as u32 + 0x900000) & 1 == 1 { 1i16 } else { -1 };
                            *val = (*val as i16 + delta).clamp(0, 255) as u8;
                        }
                    }
                    arr.copy_from(&buffer);
                }
            }
            Ok(JsValue::UNDEFINED)
        }) as Box<dyn FnMut(JsValue, JsValue, JsValue) -> Result<JsValue, JsValue>>);

        let proxied = proxy_helpers::proxy_function_with_apply(&orig, apply_trap)?;
        Reflect::set(&proto, &JsValue::from_str("getByteFrequencyData"), &proxied)?;

        // getFloatTimeDomainData — very small noise
        let orig = Reflect::get(&proto, &JsValue::from_str("getFloatTimeDomainData"))?;
        let orig_fn = orig.clone();

        let apply_trap = Closure::wrap(Box::new(move |_target: JsValue, this_arg: JsValue, args: JsValue| -> Result<JsValue, JsValue> {
            proxy_helpers::call_function(&orig_fn, &this_arg, &args)?;
            let args_arr: &Array = args.unchecked_ref();
            if args_arr.length() >= 1 {
                let arr_val = args_arr.get(0);
                if let Ok(arr) = arr_val.dyn_into::<Float32Array>() {
                    let mut buffer = vec![0f32; arr.length() as usize];
                    arr.copy_to(&mut buffer);
                    for (i, val) in buffer.iter_mut().enumerate() {
                        let noise = ((SessionPrng::seeded_random(seed, i as u32 + 0xA00000) & 0xFF) as f32 - 128.0) * 0.000001;
                        *val += noise;
                    }
                    arr.copy_from(&buffer);
                }
            }
            Ok(JsValue::UNDEFINED)
        }) as Box<dyn FnMut(JsValue, JsValue, JsValue) -> Result<JsValue, JsValue>>);

        let proxied = proxy_helpers::proxy_function_with_apply(&orig, apply_trap)?;
        Reflect::set(&proto, &JsValue::from_str("getFloatTimeDomainData"), &proxied)?;
    }

    Ok(())
}

fn apply_audio_context_props() -> Result<(), JsValue> {
    // Normalize sampleRate on BaseAudioContext.prototype
    let bac_proto = proxy_helpers::get_prototype("BaseAudioContext");
    if let Ok(proto) = bac_proto {
        if !proto.is_undefined() {
            let getter = Closure::wrap(Box::new(|| -> JsValue {
                JsValue::from_f64(NormalizedProfile::AUDIO_SAMPLE_RATE as f64)
            }) as Box<dyn FnMut() -> JsValue>);
            let _ = proxy_helpers::patch_getter(&proto, "sampleRate", getter);
        }
    }

    // Also try AudioContext.prototype directly
    let ac_proto = proxy_helpers::get_prototype("AudioContext");
    if let Ok(proto) = ac_proto {
        if !proto.is_undefined() {
            let getter = Closure::wrap(Box::new(|| -> JsValue {
                JsValue::from_f64(NormalizedProfile::AUDIO_SAMPLE_RATE as f64)
            }) as Box<dyn FnMut() -> JsValue>);
            let _ = proxy_helpers::patch_getter(&proto, "sampleRate", getter);
        }
    }

    Ok(())
}
