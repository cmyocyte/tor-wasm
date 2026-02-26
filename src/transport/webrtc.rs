//! WebRTC DataChannel transport for peer bridge connections.
//!
//! When a censored user cannot reach the bridge directly (IP blocked),
//! they connect through a volunteer's browser tab via WebRTC DataChannel.
//! The DataChannel looks like a video call to DPI equipment.
//!
//! Data flow:
//!   Client WASM ↔ WebRTC DataChannel ↔ Volunteer proxy ↔ WebSocket ↔ Bridge ↔ Guard
//!
//! The volunteer proxy sees only encrypted bytes (TLS end-to-end).

use futures::io::{AsyncRead, AsyncWrite};
use std::cell::UnsafeCell;
use std::collections::VecDeque;
use std::io::{self, Result as IoResult};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{
    MessageEvent, RtcConfiguration, RtcDataChannel, RtcDataChannelEvent, RtcIceCandidate,
    RtcIceCandidateInit, RtcPeerConnection, RtcSdpType, RtcSessionDescriptionInit,
};

/// Connection state for the WebRTC peer connection
#[derive(Debug, Clone, Copy, PartialEq)]
enum RtcState {
    /// Connecting to broker / negotiating WebRTC
    Connecting,
    /// DataChannel is open and ready for data
    Connected,
    /// DataChannel is closing
    Closing,
    /// DataChannel is closed
    Closed,
}

/// Inner state shared between callbacks and async methods.
/// UnsafeCell is safe because WASM is single-threaded.
struct RtcStreamState {
    state: RtcState,
    recv_buffer: VecDeque<u8>,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    error: Option<String>,
    /// ICE candidates collected during gathering
    ice_candidates: Vec<String>,
    /// Whether ICE gathering is complete
    ice_complete: bool,
    ice_waker: Option<Waker>,
}

impl RtcStreamState {
    fn new() -> Self {
        Self {
            state: RtcState::Connecting,
            recv_buffer: VecDeque::new(),
            read_waker: None,
            write_waker: None,
            error: None,
            ice_candidates: Vec::new(),
            ice_complete: false,
            ice_waker: None,
        }
    }
}

/// WebRTC DataChannel-based stream for peer bridge transport.
///
/// Provides the same AsyncRead/AsyncWrite interface as WasmTcpStream,
/// allowing transparent transport selection between WebSocket and WebRTC.
pub struct WasmRtcStream {
    _pc: RtcPeerConnection,
    dc: RtcDataChannel,
    state: Rc<UnsafeCell<RtcStreamState>>,
    // Store closures to prevent garbage collection
    _closures: Vec<Closure<dyn FnMut(JsValue)>>,
}

impl WasmRtcStream {
    /// Connect to a volunteer proxy via WebRTC.
    ///
    /// Steps:
    /// 1. Contact broker to get a proxy's SDP offer + ICE candidates
    /// 2. Create RTCPeerConnection, set remote description (proxy's offer)
    /// 3. Create answer, send back to proxy via broker
    /// 4. Wait for DataChannel to open
    /// 5. Send bridge URL + encrypted target as first message
    pub async fn connect(broker_url: &str, bridge_url: &str) -> IoResult<Self> {
        log::info!("Connecting to peer bridge via broker: {}", broker_url);

        // Contact broker to get a proxy
        let (proxy_offer, proxy_candidates, proxy_id) = Self::request_proxy(broker_url).await?;

        // Create peer connection
        let config = RtcConfiguration::new();
        let ice_servers = js_sys::Array::new();
        let stun = js_sys::Object::new();
        js_sys::Reflect::set(
            &stun,
            &"urls".into(),
            &"stun:stun.l.google.com:19302".into(),
        )
        .map_err(|_| io::Error::other("Failed to set STUN server"))?;
        ice_servers.push(&stun);
        config.set_ice_servers(&ice_servers);

        let pc = RtcPeerConnection::new_with_configuration(&config)
            .map_err(|e| io::Error::other(format!("RtcPeerConnection::new failed: {:?}", e)))?;

        let state = Rc::new(UnsafeCell::new(RtcStreamState::new()));
        let mut closures: Vec<Closure<dyn FnMut(JsValue)>> = Vec::new();

        // Set up ICE candidate handler
        {
            let state_clone = state.clone();
            let cb = Closure::wrap(Box::new(move |event: JsValue| {
                let event: web_sys::RtcPeerConnectionIceEvent = event.unchecked_into();
                unsafe {
                    let st = &mut *state_clone.get();
                    if let Some(candidate) = event.candidate() {
                        if let Ok(json) = js_sys::JSON::stringify(&candidate) {
                            st.ice_candidates.push(json.as_string().unwrap_or_default());
                        }
                    } else {
                        // ICE gathering complete
                        st.ice_complete = true;
                        if let Some(waker) = st.ice_waker.take() {
                            waker.wake();
                        }
                    }
                }
            }) as Box<dyn FnMut(JsValue)>);
            pc.set_onicecandidate(Some(cb.as_ref().unchecked_ref()));
            closures.push(cb);
        }

        // Set remote description (proxy's offer)
        let mut remote_desc = RtcSessionDescriptionInit::new(RtcSdpType::Offer);
        remote_desc.sdp(&proxy_offer);
        let set_remote = pc.set_remote_description(&remote_desc);
        wasm_bindgen_futures::JsFuture::from(set_remote)
            .await
            .map_err(|e| io::Error::other(format!("setRemoteDescription failed: {:?}", e)))?;

        // Add proxy's ICE candidates
        for candidate_json in &proxy_candidates {
            if let Ok(candidate_obj) = js_sys::JSON::parse(candidate_json) {
                let mut init = RtcIceCandidateInit::new("");
                if let Some(c) = js_sys::Reflect::get(&candidate_obj, &"candidate".into())
                    .ok()
                    .and_then(|v| v.as_string())
                {
                    init.candidate(&c);
                }
                if let Some(mid) = js_sys::Reflect::get(&candidate_obj, &"sdpMid".into())
                    .ok()
                    .and_then(|v| v.as_string())
                {
                    init.sdp_mid(Some(&mid));
                }
                if let Some(idx) = js_sys::Reflect::get(&candidate_obj, &"sdpMLineIndex".into())
                    .ok()
                    .and_then(|v| v.as_f64())
                {
                    init.sdp_m_line_index(Some(idx as u16));
                }
                if let Ok(ice) = RtcIceCandidate::new(&init) {
                    let _ = pc.add_ice_candidate_with_opt_rtc_ice_candidate(Some(&ice));
                }
            }
        }

        // Create answer
        let answer = wasm_bindgen_futures::JsFuture::from(pc.create_answer())
            .await
            .map_err(|e| io::Error::other(format!("createAnswer failed: {:?}", e)))?;

        let answer_desc: RtcSessionDescriptionInit = answer.unchecked_into();
        let set_local = pc.set_local_description(&answer_desc);
        wasm_bindgen_futures::JsFuture::from(set_local)
            .await
            .map_err(|e| io::Error::other(format!("setLocalDescription failed: {:?}", e)))?;

        // Wait for ICE gathering
        {
            let state_clone = state.clone();
            futures::future::poll_fn(|cx| {
                let st = unsafe { &mut *state_clone.get() };
                if st.ice_complete {
                    Poll::Ready(())
                } else {
                    st.ice_waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            })
            .await;
        }

        // Get our SDP answer and ICE candidates
        let local_desc = pc
            .local_description()
            .ok_or_else(|| io::Error::other("No local description after createAnswer"))?;
        let sdp_answer = local_desc.sdp();
        let our_candidates: Vec<String> = unsafe { (*state.get()).ice_candidates.clone() };

        // Send answer back to broker
        Self::send_answer(broker_url, &proxy_id, &sdp_answer, &our_candidates).await?;

        // Set up DataChannel handler (we receive the proxy's data channel)
        let dc_state = state.clone();
        let dc_ready = Rc::new(UnsafeCell::new(None::<RtcDataChannel>));
        let dc_ready_clone = dc_ready.clone();

        {
            let state_clone = state.clone();
            let dc_ready_inner = dc_ready.clone();
            let cb = Closure::wrap(Box::new(move |event: JsValue| {
                let event: RtcDataChannelEvent = event.unchecked_into();
                let channel = event.channel();
                let _ = js_sys::Reflect::set(&channel, &"binaryType".into(), &"arraybuffer".into());

                // Set up data handlers on the received channel
                let state_for_msg = state_clone.clone();
                let on_message = Closure::wrap(Box::new(move |event: JsValue| {
                    let event: MessageEvent = event.unchecked_into();
                    if let Ok(buffer) = event.data().dyn_into::<js_sys::ArrayBuffer>() {
                        let array = js_sys::Uint8Array::new(&buffer);
                        let data = array.to_vec();
                        unsafe {
                            let st = &mut *state_for_msg.get();
                            st.recv_buffer.extend(data);
                            if let Some(waker) = st.read_waker.take() {
                                waker.wake();
                            }
                        }
                    }
                }) as Box<dyn FnMut(JsValue)>);
                channel.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
                on_message.forget(); // Leak closure — lives for connection lifetime

                let state_for_open = dc_state.clone();
                let on_open = Closure::wrap(Box::new(move |_: JsValue| {
                    log::info!("Peer DataChannel opened");
                    unsafe {
                        let st = &mut *state_for_open.get();
                        st.state = RtcState::Connected;
                        if let Some(waker) = st.write_waker.take() {
                            waker.wake();
                        }
                        if let Some(waker) = st.read_waker.take() {
                            waker.wake();
                        }
                    }
                }) as Box<dyn FnMut(JsValue)>);
                channel.set_onopen(Some(on_open.as_ref().unchecked_ref()));
                on_open.forget();

                unsafe {
                    *dc_ready_inner.get() = Some(channel);
                }
            }) as Box<dyn FnMut(JsValue)>);
            pc.set_ondatachannel(Some(cb.as_ref().unchecked_ref()));
            closures.push(cb);
        }

        // Wait for DataChannel to open (with timeout)
        let timeout = gloo_timers::future::TimeoutFuture::new(30_000);
        let wait_connected = {
            let state_clone = state.clone();
            async move {
                loop {
                    let current = unsafe { (*state_clone.get()).state };
                    match current {
                        RtcState::Connected => return Ok(()),
                        RtcState::Closed | RtcState::Closing => {
                            return Err(io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                "DataChannel closed before connecting",
                            ));
                        }
                        RtcState::Connecting => {
                            crate::runtime::WasmRuntime::new()
                                .sleep(std::time::Duration::from_millis(50))
                                .await;
                        }
                    }
                }
            }
        };

        futures::pin_mut!(timeout);
        futures::pin_mut!(wait_connected);

        match futures::future::select(wait_connected, timeout).await {
            futures::future::Either::Left((result, _)) => result?,
            futures::future::Either::Right(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "WebRTC connection timed out (30s)",
                ));
            }
        }

        // Get the data channel
        let dc = unsafe {
            (*dc_ready_clone.get())
                .take()
                .ok_or_else(|| io::Error::other("No DataChannel received"))?
        };

        // Send bridge URL as first message so proxy knows where to connect
        let bridge_msg = bridge_url.as_bytes();
        let array = js_sys::Uint8Array::new_with_length(bridge_msg.len() as u32);
        array.copy_from(bridge_msg);
        dc.send_with_array_buffer(&array.buffer())
            .map_err(|e| io::Error::other(format!("Failed to send bridge URL: {:?}", e)))?;

        log::info!("WebRTC peer bridge connected successfully");

        Ok(Self {
            _pc: pc,
            dc,
            state,
            _closures: closures,
        })
    }

    /// Contact broker to request a volunteer proxy.
    /// Returns (sdp_offer, ice_candidates, proxy_id).
    async fn request_proxy(broker_url: &str) -> IoResult<(String, Vec<String>, String)> {
        // Connect to broker via WebSocket
        let ws = web_sys::WebSocket::new(broker_url).map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("Broker connect failed: {:?}", e),
            )
        })?;
        ws.set_binary_type(web_sys::BinaryType::Arraybuffer);

        let result: Rc<UnsafeCell<Option<IoResult<(String, Vec<String>, String)>>>> =
            Rc::new(UnsafeCell::new(None));
        let waker: Rc<UnsafeCell<Option<Waker>>> = Rc::new(UnsafeCell::new(None));

        // On open: send request
        {
            let ws_clone = ws.clone();
            let cb = Closure::wrap(Box::new(move |_: JsValue| {
                let msg = serde_json::json!({ "type": "request" }).to_string();
                let _ = ws_clone.send_with_str(&msg);
            }) as Box<dyn FnMut(JsValue)>);
            ws.set_onopen(Some(cb.as_ref().unchecked_ref()));
            cb.forget();
        }

        // On message: parse matched response
        {
            let result_clone = result.clone();
            let waker_clone = waker.clone();
            let ws_clone = ws.clone();
            let cb = Closure::wrap(Box::new(move |event: JsValue| {
                let event: MessageEvent = event.unchecked_into();
                if let Some(text) = event.data().as_string() {
                    if let Ok(msg) = serde_json::from_str::<serde_json::Value>(&text) {
                        let msg_type = msg["type"].as_str().unwrap_or("");
                        match msg_type {
                            "matched" => {
                                let offer = msg["sdp_offer"]["sdp"]
                                    .as_str()
                                    .unwrap_or_default()
                                    .to_string();
                                let candidates: Vec<String> = msg["ice_candidates"]
                                    .as_array()
                                    .map(|arr| {
                                        arr.iter()
                                            .map(|c| serde_json::to_string(c).unwrap_or_default())
                                            .collect()
                                    })
                                    .unwrap_or_default();
                                let proxy_id =
                                    msg["proxy_id"].as_str().unwrap_or_default().to_string();

                                unsafe {
                                    *result_clone.get() = Some(Ok((offer, candidates, proxy_id)));
                                    if let Some(w) = (*waker_clone.get()).take() {
                                        w.wake();
                                    }
                                }
                            }
                            "no_proxies" => unsafe {
                                *result_clone.get() = Some(Err(io::Error::new(
                                    io::ErrorKind::NotConnected,
                                    "No volunteer proxies available",
                                )));
                                if let Some(w) = (*waker_clone.get()).take() {
                                    w.wake();
                                }
                            },
                            _ => {}
                        }
                    }
                }
                let _ = ws_clone.close();
            }) as Box<dyn FnMut(JsValue)>);
            ws.set_onmessage(Some(cb.as_ref().unchecked_ref()));
            cb.forget();
        }

        // On error
        {
            let result_clone = result.clone();
            let waker_clone = waker.clone();
            let cb = Closure::wrap(Box::new(move |_: JsValue| unsafe {
                *result_clone.get() = Some(Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "Broker connection failed",
                )));
                if let Some(w) = (*waker_clone.get()).take() {
                    w.wake();
                }
            }) as Box<dyn FnMut(JsValue)>);
            ws.set_onerror(Some(cb.as_ref().unchecked_ref()));
            cb.forget();
        }

        // Wait for result
        let result_clone = result.clone();
        let waker_clone = waker.clone();
        futures::future::poll_fn(move |cx| {
            let val = unsafe { &*result_clone.get() };
            if val.is_some() {
                Poll::Ready(())
            } else {
                unsafe {
                    *waker_clone.get() = Some(cx.waker().clone());
                }
                Poll::Pending
            }
        })
        .await;

        unsafe {
            (*result.get())
                .take()
                .unwrap_or_else(|| Err(io::Error::other("No result from broker")))
        }
    }

    /// Send SDP answer back to broker for the matched proxy.
    async fn send_answer(
        broker_url: &str,
        proxy_id: &str,
        sdp_answer: &str,
        ice_candidates: &[String],
    ) -> IoResult<()> {
        let ws = web_sys::WebSocket::new(broker_url).map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("Broker reconnect failed: {:?}", e),
            )
        })?;

        let done: Rc<UnsafeCell<bool>> = Rc::new(UnsafeCell::new(false));
        let done_waker: Rc<UnsafeCell<Option<Waker>>> = Rc::new(UnsafeCell::new(None));

        let candidates_json: Vec<serde_json::Value> = ice_candidates
            .iter()
            .filter_map(|c| serde_json::from_str(c).ok())
            .collect();

        let msg = serde_json::json!({
            "type": "answer",
            "proxy_id": proxy_id,
            "sdp_answer": sdp_answer,
            "ice_candidates": candidates_json,
        })
        .to_string();

        {
            let done_clone = done.clone();
            let done_waker_clone = done_waker.clone();
            let ws_clone = ws.clone();
            let cb = Closure::wrap(Box::new(move |_: JsValue| {
                let _ = ws_clone.send_with_str(&msg);
                unsafe {
                    *done_clone.get() = true;
                    if let Some(w) = (*done_waker_clone.get()).take() {
                        w.wake();
                    }
                }
                let _ = ws_clone.close();
            }) as Box<dyn FnMut(JsValue)>);
            ws.set_onopen(Some(cb.as_ref().unchecked_ref()));
            cb.forget();
        }

        let done_clone = done.clone();
        let done_waker_clone = done_waker.clone();
        futures::future::poll_fn(move |cx| {
            if unsafe { *done_clone.get() } {
                Poll::Ready(Ok(()))
            } else {
                unsafe {
                    *done_waker_clone.get() = Some(cx.waker().clone());
                }
                Poll::Pending
            }
        })
        .await
    }
}

// --- AsyncRead / AsyncWrite implementation ---

impl AsyncRead for WasmRtcStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        let st = unsafe { &mut *self.state.get() };

        if let Some(ref err) = st.error {
            return Poll::Ready(Err(io::Error::other(err.clone())));
        }

        if !st.recv_buffer.is_empty() {
            let n = std::cmp::min(buf.len(), st.recv_buffer.len());
            for (i, byte) in st.recv_buffer.drain(..n).enumerate() {
                buf[i] = byte;
            }
            return Poll::Ready(Ok(n));
        }

        if st.state == RtcState::Closed || st.state == RtcState::Closing {
            return Poll::Ready(Ok(0)); // EOF
        }

        st.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for WasmRtcStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        let st = unsafe { &mut *self.state.get() };

        if let Some(ref err) = st.error {
            return Poll::Ready(Err(io::Error::other(err.clone())));
        }

        if st.state != RtcState::Connected {
            st.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }

        // Send data through DataChannel
        let array = js_sys::Uint8Array::new_with_length(buf.len() as u32);
        array.copy_from(buf);

        match self.dc.send_with_array_buffer(&array.buffer()) {
            Ok(_) => Poll::Ready(Ok(buf.len())),
            Err(e) => {
                let msg = format!("DataChannel send failed: {:?}", e);
                st.error = Some(msg.clone());
                Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, msg)))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Poll::Ready(Ok(())) // DataChannel flushes immediately
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.dc.close();
        let st = unsafe { &mut *self.state.get() };
        st.state = RtcState::Closing;
        Poll::Ready(Ok(()))
    }
}
