//! ClientRects Defense (Tier 2: Important)
//!
//! Rounds getBoundingClientRect() and getClientRects() values to integers
//! on both Element and Range prototypes. Sub-pixel values are unique per
//! system due to font rendering, GPU rasterization, and display scaling.

use super::proxy_helpers;
use js_sys::{Array, Function, Reflect};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

pub fn apply() -> Result<(), JsValue> {
    apply_element_rects()?;
    apply_range_rects()?;
    Ok(())
}

fn apply_element_rects() -> Result<(), JsValue> {
    let proto = proxy_helpers::get_prototype("Element")?;
    if proto.is_undefined() {
        return Ok(());
    }

    // getBoundingClientRect
    let orig_gbcr = Reflect::get(&proto, &JsValue::from_str("getBoundingClientRect"))?;
    let orig_fn = orig_gbcr.clone();

    let apply_trap = Closure::wrap(Box::new(
        move |_target: JsValue, this_arg: JsValue, args: JsValue| -> Result<JsValue, JsValue> {
            let result = proxy_helpers::call_function(&orig_fn, &this_arg, &args)?;
            round_dom_rect(&result)
        },
    )
        as Box<dyn FnMut(JsValue, JsValue, JsValue) -> Result<JsValue, JsValue>>);

    let proxied = proxy_helpers::proxy_function_with_apply(&orig_gbcr, apply_trap)?;
    Reflect::set(
        &proto,
        &JsValue::from_str("getBoundingClientRect"),
        &proxied,
    )?;

    // getClientRects
    let orig_gcr = Reflect::get(&proto, &JsValue::from_str("getClientRects"))?;
    let orig_fn = orig_gcr.clone();

    let apply_trap = Closure::wrap(Box::new(
        move |_target: JsValue, this_arg: JsValue, args: JsValue| -> Result<JsValue, JsValue> {
            let result = proxy_helpers::call_function(&orig_fn, &this_arg, &args)?;
            round_dom_rect_list(&result)
        },
    )
        as Box<dyn FnMut(JsValue, JsValue, JsValue) -> Result<JsValue, JsValue>>);

    let proxied = proxy_helpers::proxy_function_with_apply(&orig_gcr, apply_trap)?;
    Reflect::set(&proto, &JsValue::from_str("getClientRects"), &proxied)?;

    Ok(())
}

fn apply_range_rects() -> Result<(), JsValue> {
    let proto = proxy_helpers::get_prototype("Range")?;
    if proto.is_undefined() {
        return Ok(());
    }

    // getBoundingClientRect
    let orig = Reflect::get(&proto, &JsValue::from_str("getBoundingClientRect"))?;
    let orig_fn = orig.clone();

    let apply_trap = Closure::wrap(Box::new(
        move |_target: JsValue, this_arg: JsValue, args: JsValue| -> Result<JsValue, JsValue> {
            let result = proxy_helpers::call_function(&orig_fn, &this_arg, &args)?;
            round_dom_rect(&result)
        },
    )
        as Box<dyn FnMut(JsValue, JsValue, JsValue) -> Result<JsValue, JsValue>>);

    let proxied = proxy_helpers::proxy_function_with_apply(&orig, apply_trap)?;
    Reflect::set(
        &proto,
        &JsValue::from_str("getBoundingClientRect"),
        &proxied,
    )?;

    // getClientRects
    let orig = Reflect::get(&proto, &JsValue::from_str("getClientRects"))?;
    let orig_fn = orig.clone();

    let apply_trap = Closure::wrap(Box::new(
        move |_target: JsValue, this_arg: JsValue, args: JsValue| -> Result<JsValue, JsValue> {
            let result = proxy_helpers::call_function(&orig_fn, &this_arg, &args)?;
            round_dom_rect_list(&result)
        },
    )
        as Box<dyn FnMut(JsValue, JsValue, JsValue) -> Result<JsValue, JsValue>>);

    let proxied = proxy_helpers::proxy_function_with_apply(&orig, apply_trap)?;
    Reflect::set(&proto, &JsValue::from_str("getClientRects"), &proxied)?;

    Ok(())
}

/// Create a new DOMRect with integer-rounded values.
fn round_dom_rect(rect: &JsValue) -> Result<JsValue, JsValue> {
    let dom_rect_ctor: Function = js_sys::eval("DOMRect")?.unchecked_into();
    let x = Reflect::get(rect, &JsValue::from_str("x"))?
        .as_f64()
        .unwrap_or(0.0)
        .round();
    let y = Reflect::get(rect, &JsValue::from_str("y"))?
        .as_f64()
        .unwrap_or(0.0)
        .round();
    let w = Reflect::get(rect, &JsValue::from_str("width"))?
        .as_f64()
        .unwrap_or(0.0)
        .round();
    let h = Reflect::get(rect, &JsValue::from_str("height"))?
        .as_f64()
        .unwrap_or(0.0)
        .round();

    Reflect::construct(
        &dom_rect_ctor,
        &Array::of4(
            &JsValue::from_f64(x),
            &JsValue::from_f64(y),
            &JsValue::from_f64(w),
            &JsValue::from_f64(h),
        ),
    )
}

/// Round all DOMRects in a DOMRectList.
fn round_dom_rect_list(list: &JsValue) -> Result<JsValue, JsValue> {
    let length = Reflect::get(list, &JsValue::from_str("length"))?
        .as_f64()
        .unwrap_or(0.0) as u32;

    let rounded = Array::new();
    for i in 0..length {
        let rect = Reflect::get_u32(list, i)?;
        rounded.push(&round_dom_rect(&rect)?);
    }

    // Add item() method for DOMRectList compatibility
    let rounded_clone = rounded.clone();
    let item_fn = Closure::wrap(Box::new(move |index: JsValue| -> JsValue {
        let i = index.as_f64().unwrap_or(-1.0) as u32;
        rounded_clone.get(i)
    }) as Box<dyn FnMut(JsValue) -> JsValue>);

    let result = Array::from(&rounded);
    Reflect::set(&result, &JsValue::from_str("item"), item_fn.as_ref())?;
    item_fn.forget();

    Ok(result.into())
}
