//! WebRTC IP Leak Prevention (Tier 1: Critical)
//!
//! RTCPeerConnection can discover the user's real local/public IP via STUN,
//! completely bypassing Tor. This is a SECURITY VULNERABILITY.
//! Tor Browser blocks WebRTC entirely.

use wasm_bindgen::prelude::*;
use js_sys::Reflect;
use super::proxy_helpers;

pub fn apply() -> Result<(), JsValue> {
    let global = js_sys::global();

    // Block all RTC constructors
    let rtc_names = [
        "RTCPeerConnection",
        "webkitRTCPeerConnection",
        "mozRTCPeerConnection",
    ];

    for name in &rtc_names {
        let exists = Reflect::get(&global, &JsValue::from_str(name));
        if let Ok(ctor) = exists {
            if ctor.is_undefined() || ctor.is_null() {
                continue;
            }

            // Save prototype for instanceof compatibility
            let proto = Reflect::get(&ctor, &JsValue::from_str("prototype")).ok();

            // Create blocking proxy with construct trap
            let construct_trap = Closure::wrap(Box::new(|_target: JsValue, _args: JsValue, _new_target: JsValue| -> Result<JsValue, JsValue> {
                Err(proxy_helpers::throw_dom_exception(
                    "RTCPeerConnection is blocked by tor-wasm fingerprint defense",
                    "NotAllowedError",
                )?)
            }) as Box<dyn FnMut(JsValue, JsValue, JsValue) -> Result<JsValue, JsValue>>);

            let proxied = proxy_helpers::proxy_constructor_with_construct(&ctor, construct_trap)?;

            // Restore prototype on the proxy for instanceof checks
            if let Some(p) = proto {
                let _ = Reflect::set(&proxied, &JsValue::from_str("prototype"), &p);
            }

            // Also block generateCertificate static method
            let gen_cert = Closure::wrap(Box::new(|| -> Result<JsValue, JsValue> {
                Err(proxy_helpers::throw_dom_exception("Blocked", "NotAllowedError")?)
            }) as Box<dyn FnMut() -> Result<JsValue, JsValue>>);
            let _ = Reflect::set(&proxied, &JsValue::from_str("generateCertificate"), gen_cert.as_ref());
            gen_cert.forget();

            Reflect::set(&global, &JsValue::from_str(name), &proxied)?;
        }
    }

    // Block RTCSessionDescription and RTCIceCandidate
    for name in &["RTCSessionDescription", "RTCIceCandidate"] {
        let exists = Reflect::get(&global, &JsValue::from_str(name));
        if let Ok(ctor) = exists {
            if ctor.is_undefined() || ctor.is_null() {
                continue;
            }
            let construct_trap = Closure::wrap(Box::new(|_target: JsValue, _args: JsValue, _new_target: JsValue| -> Result<JsValue, JsValue> {
                Err(proxy_helpers::throw_dom_exception("Blocked by tor-wasm", "NotAllowedError")?)
            }) as Box<dyn FnMut(JsValue, JsValue, JsValue) -> Result<JsValue, JsValue>>);
            let proxied = proxy_helpers::proxy_constructor_with_construct(&ctor, construct_trap)?;
            Reflect::set(&global, &JsValue::from_str(name), &proxied)?;
        }
    }

    Ok(())
}
