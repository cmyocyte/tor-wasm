//! Font Enumeration Defense (Tier 2: Important)
//!
//! Blocks detection of non-standard fonts via document.fonts.check()
//! and normalizes measureText() to return monospace fallback widths
//! for unknown fonts.

use super::proxy_helpers;
use js_sys::{Array, Function, Reflect};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

const STANDARD_FONTS: &[&str] = &[
    "serif",
    "sans-serif",
    "monospace",
    "cursive",
    "fantasy",
    "system-ui",
    "Arial",
    "Times New Roman",
    "Courier New",
    "Georgia",
    "Verdana",
    "Helvetica",
    "Times",
    "Courier",
    "Lucida Console",
];

fn is_standard_font(family: &str) -> bool {
    STANDARD_FONTS
        .iter()
        .any(|f| f.eq_ignore_ascii_case(family))
}

pub fn apply() -> Result<(), JsValue> {
    apply_fonts_check()?;
    apply_measure_text()?;
    Ok(())
}

fn apply_fonts_check() -> Result<(), JsValue> {
    // document.fonts.check() — only confirm standard fonts
    let doc = js_sys::eval("document")?;
    let fonts = Reflect::get(&doc, &JsValue::from_str("fonts"))?;
    if fonts.is_undefined() {
        return Ok(());
    }

    let orig_check = Reflect::get(&fonts, &JsValue::from_str("check"))?;
    if orig_check.is_undefined() {
        return Ok(());
    }
    let orig_fn = orig_check.clone();
    let fonts_ref = fonts.clone();

    let apply_trap = Closure::wrap(Box::new(
        move |_target: JsValue, _this_arg: JsValue, args: JsValue| -> Result<JsValue, JsValue> {
            let args_arr: &Array = args.unchecked_ref();
            if args_arr.length() >= 1 {
                if let Some(font_spec) = args_arr.get(0).as_string() {
                    // Extract family name from font spec (e.g., "16px 'CustomFont'" → "CustomFont")
                    let family = extract_font_family(&font_spec);
                    if !is_standard_font(&family) {
                        return Ok(JsValue::FALSE);
                    }
                }
            }
            proxy_helpers::call_function(&orig_fn, &fonts_ref, &args)
        },
    )
        as Box<dyn FnMut(JsValue, JsValue, JsValue) -> Result<JsValue, JsValue>>);

    let proxied = proxy_helpers::proxy_function_with_apply(&orig_check, apply_trap)?;
    Reflect::set(&fonts, &JsValue::from_str("check"), &proxied)?;

    Ok(())
}

fn apply_measure_text() -> Result<(), JsValue> {
    let proto = proxy_helpers::get_prototype("CanvasRenderingContext2D")?;
    if proto.is_undefined() {
        return Ok(());
    }

    let orig_measure = Reflect::get(&proto, &JsValue::from_str("measureText"))?;
    let orig_fn = orig_measure.clone();

    let apply_trap = Closure::wrap(Box::new(
        move |_target: JsValue, this_arg: JsValue, args: JsValue| -> Result<JsValue, JsValue> {
            let result = proxy_helpers::call_function(&orig_fn, &this_arg, &args)?;

            // Check if current font contains a non-standard family
            let font = Reflect::get(&this_arg, &JsValue::from_str("font"))?;
            if let Some(font_str) = font.as_string() {
                let families: Vec<&str> = font_str
                    .split(',')
                    .map(|f| f.trim().trim_matches(|c| c == '"' || c == '\'').trim())
                    .collect();
                let all_standard = families.iter().any(|f| is_standard_font(f));
                if !all_standard {
                    // Measure with monospace fallback instead
                    let saved_font = font_str.clone();
                    Reflect::set(
                        &this_arg,
                        &JsValue::from_str("font"),
                        &JsValue::from_str("16px monospace"),
                    )?;
                    let fallback = proxy_helpers::call_function(&orig_fn, &this_arg, &args)?;
                    Reflect::set(
                        &this_arg,
                        &JsValue::from_str("font"),
                        &JsValue::from_str(&saved_font),
                    )?;

                    // Return a proxy that overrides width with the fallback width
                    let fallback_width = Reflect::get(&fallback, &JsValue::from_str("width"))?;
                    let get_trap = Closure::wrap(Box::new(
                        move |target: JsValue, prop: JsValue, _receiver: JsValue| -> JsValue {
                            if let Some(p) = prop.as_string() {
                                if p == "width" {
                                    return fallback_width.clone();
                                }
                            }
                            let val = Reflect::get(&target, &prop).unwrap_or(JsValue::UNDEFINED);
                            if val.is_function() {
                                // Bind function to target
                                let func: &Function = val.unchecked_ref();
                                let bound = func.bind0(&target);
                                return bound.into();
                            }
                            val
                        },
                    )
                        as Box<dyn FnMut(JsValue, JsValue, JsValue) -> JsValue>);

                    return proxy_helpers::proxy_object_with_get(&result, get_trap);
                }
            }

            Ok(result)
        },
    )
        as Box<dyn FnMut(JsValue, JsValue, JsValue) -> Result<JsValue, JsValue>>);

    let proxied = proxy_helpers::proxy_function_with_apply(&orig_measure, apply_trap)?;
    Reflect::set(&proto, &JsValue::from_str("measureText"), &proxied)?;

    Ok(())
}

fn extract_font_family(spec: &str) -> String {
    // Extract the last font family from a CSS font spec like "bold 16px 'CustomFont', serif"
    if let Some(last) = spec.rsplit(',').next() {
        let trimmed = last
            .trim()
            .trim_matches(|c: char| c == '"' || c == '\'')
            .trim();
        // Skip the size/weight prefix if present
        if let Some(family) = trimmed.rsplit(' ').next() {
            return family
                .trim_matches(|c: char| c == '"' || c == '\'')
                .to_string();
        }
        return trimmed.to_string();
    }
    spec.to_string()
}
