//! Performance Timer Defense (Tier 2: Important)
//!
//! Reduces performance.now() precision to 100ms (matches Tor Browser),
//! fixes performance.memory to constant values, and rounds entry durations.

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use js_sys::{Array, Object, Reflect, Function};
use super::profile::NormalizedProfile;
use super::proxy_helpers;

pub fn apply() -> Result<(), JsValue> {
    let global = js_sys::global();
    let performance = Reflect::get(&global, &JsValue::from_str("performance"))?;
    if performance.is_undefined() {
        return Ok(());
    }

    apply_to_performance(&performance)?;
    Ok(())
}

/// Apply performance defenses. Used by both main apply() and iframe observer.
pub fn apply_to_performance(performance: &JsValue) -> Result<(), JsValue> {
    let precision = NormalizedProfile::PERFORMANCE_PRECISION_MS;

    // performance.now() — round to 100ms
    let orig_now = Reflect::get(performance, &JsValue::from_str("now"))?;
    let orig_fn = orig_now.clone();
    let perf_ref = performance.clone();

    let apply_trap = Closure::wrap(Box::new(move |_target: JsValue, _this_arg: JsValue, _args: JsValue| -> Result<JsValue, JsValue> {
        let result = proxy_helpers::call_function(&orig_fn, &perf_ref, &Array::new().into())?;
        let val = result.as_f64().unwrap_or(0.0);
        let rounded = (val / precision).round() * precision;
        Ok(JsValue::from_f64(rounded))
    }) as Box<dyn FnMut(JsValue, JsValue, JsValue) -> Result<JsValue, JsValue>>);

    let proxied = proxy_helpers::proxy_function_with_apply(&orig_now, apply_trap)?;
    Reflect::set(performance, &JsValue::from_str("now"), &proxied)?;

    // performance.timeOrigin — round
    let time_origin = Reflect::get(performance, &JsValue::from_str("timeOrigin"));
    if let Ok(to) = time_origin {
        if !to.is_undefined() {
            let rounded = (to.as_f64().unwrap_or(0.0) / precision).round() * precision;
            let getter = Closure::wrap(Box::new(move || -> JsValue {
                JsValue::from_f64(rounded)
            }) as Box<dyn FnMut() -> JsValue>);
            proxy_helpers::patch_getter(performance, "timeOrigin", getter)?;
        }
    }

    // performance.memory — fixed values (Chrome-only)
    let has_memory = Reflect::get(performance, &JsValue::from_str("memory"))
        .map(|v| !v.is_undefined())
        .unwrap_or(false);
    if has_memory {
        let getter = Closure::wrap(Box::new(|| -> JsValue {
            let obj = Object::new();
            let _ = Reflect::set(&obj, &JsValue::from_str("totalJSHeapSize"), &JsValue::from_f64(50.0 * 1024.0 * 1024.0));
            let _ = Reflect::set(&obj, &JsValue::from_str("usedJSHeapSize"), &JsValue::from_f64(25.0 * 1024.0 * 1024.0));
            let _ = Reflect::set(&obj, &JsValue::from_str("jsHeapSizeLimit"), &JsValue::from_f64(2.0 * 1024.0 * 1024.0 * 1024.0));
            obj.into()
        }) as Box<dyn FnMut() -> JsValue>);
        proxy_helpers::patch_getter(performance, "memory", getter)?;
    }

    // getEntries / getEntriesByType / getEntriesByName — round timing values
    for method_name in &["getEntries", "getEntriesByType", "getEntriesByName"] {
        let orig = Reflect::get(performance, &JsValue::from_str(method_name));
        if let Ok(orig) = orig {
            if orig.is_undefined() {
                continue;
            }
            let orig_fn = orig.clone();
            let perf_ref = performance.clone();

            let apply_trap = Closure::wrap(Box::new(move |_target: JsValue, _this_arg: JsValue, args: JsValue| -> Result<JsValue, JsValue> {
                let result = proxy_helpers::call_function(&orig_fn, &perf_ref, &args)?;
                // Round timing fields on each entry via inline JS for efficiency
                let round_code = format!(
                    "(function(entries, prec) {{ \
                        return Array.from(entries).map(function(e) {{ \
                            return new Proxy(e, {{ get: function(t, p) {{ \
                                var v = t[p]; \
                                if (typeof v === 'number' && \
                                    (p === 'startTime' || p === 'duration' || p === 'fetchStart' || \
                                     p === 'responseEnd' || p === 'domComplete' || p === 'loadEventEnd')) \
                                    return Math.round(v / prec) * prec; \
                                return typeof v === 'function' ? v.bind(t) : v; \
                            }}}}); \
                        }}); \
                    }})"
                );
                let round_fn: Function = js_sys::eval(&round_code)?.unchecked_into();
                Reflect::apply(&round_fn, &JsValue::UNDEFINED, &Array::of2(&result, &JsValue::from_f64(precision)))
            }) as Box<dyn FnMut(JsValue, JsValue, JsValue) -> Result<JsValue, JsValue>>);

            let proxied = proxy_helpers::proxy_function_with_apply(&orig, apply_trap)?;
            Reflect::set(performance, &JsValue::from_str(method_name), &proxied)?;
        }
    }

    Ok(())
}
