//! Iframe Protection via MutationObserver
//!
//! Watches the DOM for dynamically-created <iframe> and <frame> elements,
//! then applies fingerprint defenses to their contentWindow.
//! This defeats CreepJS's iframe extraction attack where it creates a
//! fresh iframe to get "untampered" API values.

use super::profile::DefenseConfig;
use js_sys::{Array, Function, Reflect};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

/// Start observing the DOM for iframe insertions.
pub fn start_iframe_protection(config: &DefenseConfig) -> Result<(), JsValue> {
    let window = web_sys::window().ok_or_else(|| JsValue::from_str("no window"))?;
    let document = window
        .document()
        .ok_or_else(|| JsValue::from_str("no document"))?;

    // Patch existing iframes
    patch_existing_iframes(&document)?;

    // Set up MutationObserver for future iframes
    let config_clone = config.clone();
    let observer_callback = Closure::wrap(Box::new(move |mutations: JsValue, _observer: JsValue| {
        let arr: &Array = mutations.unchecked_ref();
        for i in 0..arr.length() {
            let record = arr.get(i);
            let added = Reflect::get(&record, &JsValue::from_str("addedNodes"))
                .unwrap_or(JsValue::UNDEFINED);
            if added.is_undefined() {
                continue;
            }
            let added_len = Reflect::get(&added, &JsValue::from_str("length"))
                .unwrap_or(JsValue::from_f64(0.0))
                .as_f64()
                .unwrap_or(0.0) as u32;

            for j in 0..added_len {
                if let Ok(node) = Reflect::get_u32(&added, j) {
                    process_node(&node, &config_clone);
                }
            }
        }
    }) as Box<dyn FnMut(JsValue, JsValue)>);

    // Create MutationObserver via eval (simpler than web-sys feature chain)
    let create_observer: Function = js_sys::eval(
        "(function(callback) { \
            var obs = new MutationObserver(callback); \
            obs.observe(document.documentElement, { childList: true, subtree: true }); \
            return obs; \
        })",
    )?
    .unchecked_into();

    let _observer = Reflect::apply(
        &create_observer,
        &JsValue::UNDEFINED,
        &Array::of1(observer_callback.as_ref()),
    )?;
    observer_callback.forget();

    // Also intercept document.createElement to catch iframes before insertion
    intercept_create_element(config)?;

    Ok(())
}

fn patch_existing_iframes(document: &web_sys::Document) -> Result<(), JsValue> {
    let iframes = document.query_selector_all("iframe, frame")?;
    for i in 0..iframes.length() {
        if let Some(node) = iframes.get(i) {
            let node_js: JsValue = node.into();
            patch_iframe_on_load(&node_js);
        }
    }
    Ok(())
}

fn process_node(node: &JsValue, config: &DefenseConfig) {
    if node.is_null() || node.is_undefined() {
        return;
    }

    // Check tag name
    let node_name = Reflect::get(node, &JsValue::from_str("nodeName"))
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_default()
        .to_uppercase();

    if node_name == "IFRAME" || node_name == "FRAME" {
        patch_iframe_on_load(node);
    }

    // Check children recursively
    let children = Reflect::get(node, &JsValue::from_str("childNodes")).ok();
    if let Some(children) = children {
        let len = Reflect::get(&children, &JsValue::from_str("length"))
            .unwrap_or(JsValue::from_f64(0.0))
            .as_f64()
            .unwrap_or(0.0) as u32;
        for i in 0..len {
            if let Ok(child) = Reflect::get_u32(&children, i) {
                process_node(&child, config);
            }
        }
    }
}

fn patch_iframe_on_load(iframe: &JsValue) {
    // Attach a load listener that will patch the iframe's contentWindow
    let iframe_clone = iframe.clone();
    let onload = Closure::wrap(Box::new(move |_event: JsValue| {
        // Try to access contentWindow (only works for same-origin)
        if let Ok(cw) = Reflect::get(&iframe_clone, &JsValue::from_str("contentWindow")) {
            if !cw.is_null() && !cw.is_undefined() {
                let _ = patch_iframe_window(&cw);
            }
        }
    }) as Box<dyn FnMut(JsValue)>);

    let add_listener: Result<JsValue, _> =
        Reflect::get(iframe, &JsValue::from_str("addEventListener"));
    if let Ok(ael) = add_listener {
        if ael.is_function() {
            let ael_fn: &Function = ael.unchecked_ref();
            let _ = ael_fn.call2(iframe, &JsValue::from_str("load"), onload.as_ref());
        }
    }
    onload.forget();
}

fn patch_iframe_window(window: &JsValue) -> Result<(), JsValue> {
    // Apply critical defenses to the iframe's window
    let navigator = Reflect::get(window, &JsValue::from_str("navigator"))?;
    if !navigator.is_undefined() {
        super::tier1_navigator::apply_to_navigator(&navigator)?;
    }

    let screen = Reflect::get(window, &JsValue::from_str("screen"))?;
    if !screen.is_undefined() {
        super::tier1_screen::apply_to_screen(&screen)?;
    }

    super::tier1_screen::apply_to_window(window)?;

    let performance = Reflect::get(window, &JsValue::from_str("performance"))?;
    if !performance.is_undefined() {
        super::tier2_performance::apply_to_performance(&performance)?;
    }

    Ok(())
}

fn intercept_create_element(_config: &DefenseConfig) -> Result<(), JsValue> {
    let document: JsValue = web_sys::window()
        .ok_or_else(|| JsValue::from_str("no window"))?
        .document()
        .ok_or_else(|| JsValue::from_str("no document"))?
        .into();

    let orig_create = Reflect::get(&document, &JsValue::from_str("createElement"))?;
    if orig_create.is_undefined() {
        return Ok(());
    }
    let orig_fn = orig_create.clone();
    let doc_ref = document.clone();

    let apply_trap = Closure::wrap(Box::new(
        move |_target: JsValue, _this: JsValue, args: JsValue| -> Result<JsValue, JsValue> {
            let result = super::proxy_helpers::call_function(&orig_fn, &doc_ref, &args)?;

            // Check if we're creating an iframe
            let args_arr: &Array = args.unchecked_ref();
            if args_arr.length() >= 1 {
                if let Some(tag) = args_arr.get(0).as_string() {
                    let tag_upper = tag.to_uppercase();
                    if tag_upper == "IFRAME" || tag_upper == "FRAME" {
                        patch_iframe_on_load(&result);
                    }
                }
            }

            Ok(result)
        },
    )
        as Box<dyn FnMut(JsValue, JsValue, JsValue) -> Result<JsValue, JsValue>>);

    let proxied = super::proxy_helpers::proxy_function_with_apply(&orig_create, apply_trap)?;
    Reflect::set(&document, &JsValue::from_str("createElement"), &proxied)?;

    Ok(())
}
