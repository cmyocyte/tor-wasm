//! Timezone Normalization (Tier 2: Important)
//!
//! Forces UTC timezone across all Date methods and Intl.DateTimeFormat.

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use js_sys::{Array, Object, Reflect, Function};
use super::proxy_helpers;

pub fn apply() -> Result<(), JsValue> {
    let global = js_sys::global();

    // Date.prototype.getTimezoneOffset → 0
    let date_proto = proxy_helpers::get_prototype("Date")?;
    let replacement = Closure::wrap(Box::new(|| -> JsValue {
        JsValue::from_f64(0.0)
    }) as Box<dyn FnMut() -> JsValue>);
    Reflect::set(&date_proto, &JsValue::from_str("getTimezoneOffset"), replacement.as_ref())?;
    replacement.forget();

    // toLocaleString / toLocaleDateString / toLocaleTimeString — inject timeZone: 'UTC'
    for method_name in &["toLocaleString", "toLocaleDateString", "toLocaleTimeString"] {
        let orig = Reflect::get(&date_proto, &JsValue::from_str(method_name))?;
        let orig_fn = orig.clone();

        let apply_trap = Closure::wrap(Box::new(move |_target: JsValue, this_arg: JsValue, args: JsValue| -> Result<JsValue, JsValue> {
            let args_arr: &Array = args.unchecked_ref();
            let locale = if args_arr.length() > 0 && !args_arr.get(0).is_undefined() {
                args_arr.get(0)
            } else {
                JsValue::from_str("en-US")
            };
            let options = if args_arr.length() > 1 && args_arr.get(1).is_object() {
                // Clone options and add timeZone
                let src = args_arr.get(1);
                let obj = js_sys::eval(&format!("Object.assign({{}}, {{}}, {{timeZone: 'UTC'}})"))?.unchecked_into::<Function>();
                Reflect::apply(&obj, &JsValue::UNDEFINED, &Array::of2(&src, &JsValue::UNDEFINED))?;
                // Simpler: use Object.assign
                let assign: Function = js_sys::eval("(src) => Object.assign({}, src, {timeZone: 'UTC'})")?.unchecked_into();
                Reflect::apply(&assign, &JsValue::UNDEFINED, &Array::of1(&src))?
            } else {
                let obj = Object::new();
                Reflect::set(&obj, &JsValue::from_str("timeZone"), &JsValue::from_str("UTC"))?;
                obj.into()
            };
            let new_args = Array::of2(&locale, &options);
            proxy_helpers::call_function(&orig_fn, &this_arg, &new_args.into())
        }) as Box<dyn FnMut(JsValue, JsValue, JsValue) -> Result<JsValue, JsValue>>);

        let proxied = proxy_helpers::proxy_function_with_apply(&orig, apply_trap)?;
        Reflect::set(&date_proto, &JsValue::from_str(method_name), &proxied)?;
    }

    // Date.prototype.toString — UTC representation
    let orig_to_string = Reflect::get(&date_proto, &JsValue::from_str("toString"))?;
    let replacement = Closure::wrap(Box::new(move |_target: JsValue, this_arg: JsValue, _args: JsValue| -> Result<JsValue, JsValue> {
        let to_utc: Function = Reflect::get(&this_arg, &JsValue::from_str("toUTCString"))?.unchecked_into();
        let utc_str = Reflect::apply(&to_utc, &this_arg, &Array::new())?;
        let s = utc_str.as_string().unwrap_or_default();
        Ok(JsValue::from_str(&s.replace("GMT", "GMT+0000 (Coordinated Universal Time)")))
    }) as Box<dyn FnMut(JsValue, JsValue, JsValue) -> Result<JsValue, JsValue>>);
    let proxied = proxy_helpers::proxy_function_with_apply(&orig_to_string, replacement)?;
    Reflect::set(&date_proto, &JsValue::from_str("toString"), &proxied)?;

    // Date.prototype.toTimeString — UTC time
    let orig_to_time = Reflect::get(&date_proto, &JsValue::from_str("toTimeString"))?;
    let replacement = Closure::wrap(Box::new(move |_target: JsValue, this_arg: JsValue, _args: JsValue| -> Result<JsValue, JsValue> {
        let code = "(function(d) { \
            var h = String(d.getUTCHours()).padStart(2,'0'); \
            var m = String(d.getUTCMinutes()).padStart(2,'0'); \
            var s = String(d.getUTCSeconds()).padStart(2,'0'); \
            return h+':'+m+':'+s+' GMT+0000 (Coordinated Universal Time)'; \
        })";
        let fn_: Function = js_sys::eval(code)?.unchecked_into();
        Reflect::apply(&fn_, &JsValue::UNDEFINED, &Array::of1(&this_arg))
    }) as Box<dyn FnMut(JsValue, JsValue, JsValue) -> Result<JsValue, JsValue>>);
    let proxied = proxy_helpers::proxy_function_with_apply(&orig_to_time, replacement)?;
    Reflect::set(&date_proto, &JsValue::from_str("toTimeString"), &proxied)?;

    // Intl.DateTimeFormat — inject timeZone: 'UTC'
    let intl = Reflect::get(&global, &JsValue::from_str("Intl"));
    if let Ok(intl) = intl {
        if !intl.is_undefined() {
            let dtf = Reflect::get(&intl, &JsValue::from_str("DateTimeFormat"))?;
            if !dtf.is_undefined() {
                // Patch resolvedOptions on the prototype
                let dtf_proto = Reflect::get(&dtf, &JsValue::from_str("prototype"))?;
                let orig_resolved = Reflect::get(&dtf_proto, &JsValue::from_str("resolvedOptions"))?;
                let orig_ro = orig_resolved.clone();

                let apply_trap = Closure::wrap(Box::new(move |_target: JsValue, this_arg: JsValue, args: JsValue| -> Result<JsValue, JsValue> {
                    let result = proxy_helpers::call_function(&orig_ro, &this_arg, &args)?;
                    Reflect::set(&result, &JsValue::from_str("timeZone"), &JsValue::from_str("UTC"))?;
                    Ok(result)
                }) as Box<dyn FnMut(JsValue, JsValue, JsValue) -> Result<JsValue, JsValue>>);

                let proxied = proxy_helpers::proxy_function_with_apply(&orig_resolved, apply_trap)?;
                Reflect::set(&dtf_proto, &JsValue::from_str("resolvedOptions"), &proxied)?;
            }
        }
    }

    Ok(())
}
