//! Proxy and Reflect utility wrappers for anti-detection API interception.
//!
//! All closures installed via these helpers are WASM-compiled functions.
//! When fingerprinting scripts call `.toString()` on them, browsers return
//! `"function() { [native code] }"` automatically — no spoofing needed.

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use js_sys::{Object, Reflect, Function, Array};

/// Get the global window object.
pub fn window() -> Result<JsValue, JsValue> {
    js_sys::global()
        .dyn_into::<web_sys::Window>()
        .map(|w| w.into())
        .map_err(|_| JsValue::from_str("no window"))
}

/// Get a global constructor's prototype (e.g., "HTMLCanvasElement" → HTMLCanvasElement.prototype).
pub fn get_prototype(constructor_name: &str) -> Result<JsValue, JsValue> {
    let global = js_sys::global();
    let ctor = Reflect::get(&global, &JsValue::from_str(constructor_name))?;
    Reflect::get(&ctor, &JsValue::from_str("prototype"))
}

/// Get a property from the global scope.
pub fn get_global(prop: &str) -> Result<JsValue, JsValue> {
    Reflect::get(&js_sys::global(), &JsValue::from_str(prop))
}

/// Override a property with a getter on an object using Object.defineProperty.
/// The getter closure is a WASM function → native toString().
pub fn patch_getter(
    obj: &JsValue,
    prop_name: &str,
    getter: Closure<dyn FnMut() -> JsValue>,
) -> Result<(), JsValue> {
    let descriptor = Object::new();
    Reflect::set(&descriptor, &JsValue::from_str("get"), getter.as_ref())?;
    Reflect::set(&descriptor, &JsValue::from_str("configurable"), &JsValue::TRUE)?;
    Reflect::set(&descriptor, &JsValue::from_str("enumerable"), &JsValue::TRUE)?;

    // Use js_sys eval to call Object.defineProperty since Reflect::define_property
    // has different semantics (returns bool, doesn't throw)
    let define_prop: Function = js_sys::eval("Object.defineProperty")?
        .dyn_into()
        .map_err(|_| JsValue::from_str("Object.defineProperty not found"))?;
    let args = Array::of3(obj, &JsValue::from_str(prop_name), &descriptor);
    Reflect::apply(&define_prop, &JsValue::UNDEFINED, &args)?;

    getter.forget();
    Ok(())
}

/// Replace a method on an object. Returns the original method.
/// The replacement is a WASM function → native toString().
pub fn patch_method(
    obj: &JsValue,
    method_name: &str,
    replacement: &JsValue,
) -> Result<JsValue, JsValue> {
    let original = Reflect::get(obj, &JsValue::from_str(method_name))?;
    Reflect::set(obj, &JsValue::from_str(method_name), replacement)?;
    Ok(original)
}

/// Create a Proxy around a target function with an `apply` trap.
/// The trap receives (target, thisArg, argumentsList).
/// Use this for method interception where you need to call the original
/// and post-process the result.
pub fn proxy_function_with_apply(
    target: &JsValue,
    apply_trap: Closure<dyn FnMut(JsValue, JsValue, JsValue) -> Result<JsValue, JsValue>>,
) -> Result<JsValue, JsValue> {
    let handler = Object::new();
    Reflect::set(&handler, &JsValue::from_str("apply"), apply_trap.as_ref())?;
    apply_trap.forget();

    let proxy_ctor: Function = Reflect::get(&js_sys::global(), &JsValue::from_str("Proxy"))?
        .dyn_into()
        .map_err(|_| JsValue::from_str("Proxy not found"))?;
    let args = Array::of2(target, &handler);
    Reflect::construct(&proxy_ctor, &args)
}

/// Create a Proxy around a constructor with a `construct` trap.
/// The trap receives (target, argumentsList, newTarget).
/// Use this for blocking constructors (e.g., RTCPeerConnection).
pub fn proxy_constructor_with_construct(
    target: &JsValue,
    construct_trap: Closure<dyn FnMut(JsValue, JsValue, JsValue) -> Result<JsValue, JsValue>>,
) -> Result<JsValue, JsValue> {
    let handler = Object::new();
    Reflect::set(&handler, &JsValue::from_str("construct"), construct_trap.as_ref())?;
    construct_trap.forget();

    // Also add an apply trap for when called without `new`
    let apply_trap = Closure::wrap(Box::new(|_target: JsValue, _this: JsValue, _args: JsValue| -> Result<JsValue, JsValue> {
        Err(throw_dom_exception("Blocked by tor-wasm fingerprint defense", "NotAllowedError")?)
    }) as Box<dyn FnMut(JsValue, JsValue, JsValue) -> Result<JsValue, JsValue>>);
    Reflect::set(&handler, &JsValue::from_str("apply"), apply_trap.as_ref())?;
    apply_trap.forget();

    let proxy_ctor: Function = Reflect::get(&js_sys::global(), &JsValue::from_str("Proxy"))?
        .dyn_into()
        .map_err(|_| JsValue::from_str("Proxy not found"))?;
    let args = Array::of2(target, &handler);
    Reflect::construct(&proxy_ctor, &args)
}

/// Create a Proxy around an object with a `get` trap.
/// The trap receives (target, property, receiver).
/// Use this for wrapping entire objects (e.g., navigator, screen).
pub fn proxy_object_with_get(
    target: &JsValue,
    get_trap: Closure<dyn FnMut(JsValue, JsValue, JsValue) -> JsValue>,
) -> Result<JsValue, JsValue> {
    let handler = Object::new();
    Reflect::set(&handler, &JsValue::from_str("get"), get_trap.as_ref())?;
    get_trap.forget();

    let proxy_ctor: Function = Reflect::get(&js_sys::global(), &JsValue::from_str("Proxy"))?
        .dyn_into()
        .map_err(|_| JsValue::from_str("Proxy not found"))?;
    let args = Array::of2(target, &handler);
    Reflect::construct(&proxy_ctor, &args)
}

/// Call a JS function with arguments via Reflect.apply.
pub fn call_function(
    func: &JsValue,
    this_arg: &JsValue,
    args: &JsValue,
) -> Result<JsValue, JsValue> {
    let func: &Function = func.unchecked_ref();
    Reflect::apply(func, this_arg, args.unchecked_ref())
}

/// Throw a DOMException. Returns a JsValue containing the exception.
pub fn throw_dom_exception(message: &str, name: &str) -> Result<JsValue, JsValue> {
    let code = format!("new DOMException('{}', '{}')", message, name);
    js_sys::eval(&code)
}

/// Create a frozen JS array from static string slices.
pub fn frozen_string_array(items: &[&str]) -> JsValue {
    let arr = Array::new();
    for item in items {
        arr.push(&JsValue::from_str(item));
    }
    let freeze: Function = Reflect::get(
        &Reflect::get(&js_sys::global(), &JsValue::from_str("Object")).unwrap(),
        &JsValue::from_str("freeze"),
    ).unwrap().unchecked_into();
    Reflect::apply(&freeze, &JsValue::UNDEFINED, &Array::of1(&arr)).unwrap()
}

/// Create an empty array-like object with item() and namedItem() methods.
/// Used for plugins and mimeTypes normalization.
pub fn empty_plugin_array() -> JsValue {
    let arr = Array::new();

    let item_fn = Closure::wrap(Box::new(|| -> JsValue {
        JsValue::NULL
    }) as Box<dyn FnMut() -> JsValue>);
    Reflect::set(&arr, &JsValue::from_str("item"), item_fn.as_ref()).unwrap();
    item_fn.forget();

    let named_item_fn = Closure::wrap(Box::new(|| -> JsValue {
        JsValue::NULL
    }) as Box<dyn FnMut() -> JsValue>);
    Reflect::set(&arr, &JsValue::from_str("namedItem"), named_item_fn.as_ref()).unwrap();
    named_item_fn.forget();

    let refresh_fn = Closure::wrap(Box::new(|| {}) as Box<dyn FnMut()>);
    Reflect::set(&arr, &JsValue::from_str("refresh"), refresh_fn.as_ref()).unwrap();
    refresh_fn.forget();

    arr.into()
}
