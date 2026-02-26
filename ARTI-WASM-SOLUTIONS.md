# Arti WASM Blockers: Solutions from tor-wasm

tor-wasm solved all 5 open WASM blockers for Arti. Here's what worked.

We built a minimal Tor client from scratch targeting `wasm32-unknown-unknown`, implementing the Tor protocol (ntor handshake, 3-hop circuits, onion encryption) in ~20,900 lines of Rust. Along the way, we had to solve each of the 5 sub-issues filed under [#103 "Port Arti to WASM"](https://gitlab.torproject.org/tpo/core/arti/-/issues/103). These have been open since February 2022 with 0/5 completed. Below are concrete solutions with code references.

---

## Issue #339: StateMgr requires filesystem access

**Problem:** Arti's `StateMgr` trait assumes filesystem access for persisting guard state, relay information, and client configuration. Browsers have no filesystem.

**tor-wasm's solution:** We replaced all filesystem storage with two browser-native persistence layers:

1. **IndexedDB** (`src/storage/indexeddb.rs`) -- A full async key-value store wrapping the browser's IndexedDB API via `web-sys`. The `WasmStorage` struct provides `get()`, `set()`, `delete()`, `list_keys()`, and `clear()` across 5 object stores: `consensus`, `relays`, `circuits`, `cache`, and `state`. All operations are async, using `IdbRequest` wrapped into `Future` via `Promise` callbacks.

2. **localStorage** (`src/guards.rs`) -- Guard node state (`GuardState` struct with selected guards, failure counts, bad-guard timeouts, rotation timestamps) is serialized to JSON and stored in `window.localStorage`. This provides fast synchronous reads for the critical path of guard selection on bootstrap.

3. **Arti adapter** (`src/storage/arti_adapter.rs`) -- `ArtiStateManager` wraps `WasmStorage` and provides a generic `load<T: DeserializeOwned>()` / `store<T: Serialize>()` interface backed by IndexedDB's `state` object store. This mimics what Arti's `StateMgr` does with files but uses `serde_json` serialization to IndexedDB instead. `GuardManager` sits on top of this, implementing guard persistence, failure tracking, pruning of stale guards, and the 90-day rotation lifecycle.

4. **High-level manager** (`src/storage/mod.rs`) -- `TorStorageManager` ties it all together: `store_consensus()` / `load_consensus()` with freshness checks, `store_relay()` / `load_relay()` for relay descriptors, `store_client_state()` / `load_client_state()` for arbitrary client state.

**Key code paths:**
- `src/storage/indexeddb.rs` -- `WasmStorage` (raw IndexedDB wrapper)
- `src/storage/arti_adapter.rs` -- `ArtiStateManager`, `GuardManager`
- `src/storage/mod.rs` -- `TorStorageManager`
- `src/guards.rs` -- `GuardState`, `GuardPersistence` (localStorage)

**What Arti could adopt:** Add an `IndexedDbStateMgr` behind a `#[cfg(target_arch = "wasm32")]` gate that implements `StateMgr` using `web-sys` IndexedDB bindings. The key insight is that all state operations can be made async without changing the data model. Guard state serializes cleanly to JSON. The `state` object store pattern (one store, keyed by state type) maps directly to Arti's existing file-per-state approach.

---

## Issue #340: dirmgr depends on SQLite (C library)

**Problem:** Arti's directory manager (`dirmgr`) uses SQLite via C bindings for storing and querying the Tor consensus and relay descriptors. C libraries cannot compile to `wasm32-unknown-unknown`.

**tor-wasm's solution:** We eliminated the SQLite dependency entirely by splitting directory management between bridge and client:

1. **Bridge-side consensus fetching** (`bridge-server/server-collector.js`) -- The bridge server fetches the consensus and server descriptors directly from `collector.torproject.org` over HTTPS. It parses the consensus to extract relay information (fingerprint, IP, port, flags) and fetches up to 15 descriptor files to extract `ntor-onion-key` values. These are merged into a JSON object and cached server-side (3-hour TTL). The bridge serves this pre-processed consensus at a configurable endpoint (default `/tor/consensus`), compressed and base64-encoded.

2. **Client-side consensus verification** (`src/protocol/consensus_verify.rs`) -- The WASM client fetches the pre-processed consensus from the bridge via `fetch()`, then verifies directory authority signatures (requiring >= 5 valid signatures). No SQLite needed -- the client receives the relay list as JSON, verifies it cryptographically, and stores it in IndexedDB (see #339 solution above).

3. **Decompression on the bridge** -- The bridge handles all zstd/xz2 decompression of raw Tor data server-side using Node.js's built-in `zlib`. The client never sees compressed Tor data (see #341 below).

**Key code paths:**
- `bridge-server/server-collector.js` -- `fetchAndCacheConsensus()`, `parseConsensus()`, `parseDescriptors()`
- `src/protocol/consensus_verify.rs` -- Client-side signature verification
- `src/storage/mod.rs` -- `TorStorageManager::store_consensus()` / `load_consensus()` (IndexedDB)

**What Arti could adopt:** For a full Arti WASM port, there are two paths: (a) replace SQLite with IndexedDB-backed storage using the `web-sys` IndexedDB API (our approach), or (b) use `sql.js` (SQLite compiled to WASM via Emscripten) as a drop-in replacement. Option (a) is simpler and avoids the 800KB `sql.js` binary. The consensus and descriptor data model is fundamentally key-value (fingerprint -> descriptor), which maps naturally to IndexedDB object stores without needing SQL queries.

---

## Issue #341: Compression libraries use C bindings (zstd, xz2)

**Problem:** Tor uses zstd and xz2 for compressing directory data. Both crates are wrappers around C libraries that cannot compile to WASM.

**tor-wasm's solution:** We eliminated the need for client-side decompression entirely:

1. **Bridge decompresses** -- The bridge server (`server-collector.js`) fetches raw Tor data from `collector.torproject.org` and handles all decompression server-side using Node.js built-in `zlib`. By the time the WASM client receives the consensus, it is already decompressed JSON.

2. **No compression crates in Cargo.toml** -- Our `Cargo.toml` has zero C-binding compression dependencies. The WASM binary contains no zstd, xz2, or zlib code.

3. **Client-side compression only for bridge transport** -- The bridge optionally compresses its HTTP response to the client using standard `zlib.deflateSync()` (built into Node.js), and the browser's native `fetch()` handles `Content-Encoding: deflate` transparently. No Rust-side decompression needed.

**What Arti could adopt:** Three options, from simplest to most complete:

- **Option A (our approach):** Move decompression to a WASM-external helper (bridge server, service worker, or JavaScript shim). The Tor data reaches the Rust WASM as already-decompressed bytes. Zero Rust changes needed.

- **Option B:** Use pure-Rust compression crates: `zstd-rs` (pure Rust, no C) for zstd, `lzma-rs` for xz2, `miniz_oxide` for deflate. These compile to WASM. Performance is 2-5x slower than C implementations but acceptable for the ~2MB consensus document that is fetched every 3 hours.

- **Option C:** Feature-gate the C-binding crates behind `#[cfg(not(target_arch = "wasm32"))]` and use pure-Rust fallbacks on WASM. This preserves native performance on desktop/mobile while enabling WASM compilation.

---

## Issue #342: Runtime requires tokio/async-std (not available in browser)

**Problem:** Arti depends on `tokio` or `async-std` for its async runtime (`tor-rtcompat`). Neither works in WASM because browsers are single-threaded and have no OS-level I/O primitives.

**tor-wasm's solution:** We built a cooperative scheduler from scratch that runs entirely on the browser's event loop:

1. **WasmRuntime** (`src/runtime/mod.rs`) -- A custom runtime struct that replaces tokio/async-std. Provides `sleep()` via `setTimeout` Promises (`src/runtime/sleep.rs`), task spawning via `wasm_bindgen_futures::spawn_local` (`src/runtime/spawn.rs`), and time via `js_sys::Date::now()` / `web_time::SystemTime` (`src/runtime/time.rs`).

2. **Cooperative circuit scheduler** (`src/cooperative/scheduler.rs`, ~850 lines) -- The core innovation. `CooperativeCircuit` owns the Tor circuit and multiplexes multiple streams using a **checkout/return pattern** that avoids the `RefCell` borrow-across-await problem:

   ```rust
   // Brief borrow to get work
   let work = { scheduler.borrow_mut().tick_sync() };
   // Borrow released!

   // Checkout circuit for async I/O (no borrow held)
   let mut circuit = { scheduler.borrow_mut().checkout_circuit() };
   let result = circuit.send_relay_cell(&cell).await;  // No borrow!

   // Return circuit (brief borrow)
   { scheduler.borrow_mut().return_circuit(circuit) };
   ```

   This pattern is critical because WASM is single-threaded (no `Mutex`), `RefCell` panics on nested borrows, and async code must never hold a `RefCell::borrow_mut()` across an `.await` point.

3. **Round-robin fair scheduling** -- The scheduler implements per-stream send queues, round-robin scheduling across streams, backpressure (max 50 cells/stream, 200 total), mandatory timeouts on all operations, and automatic circuit death propagation.

4. **`drive_scheduler()` and `drive_until_complete()`** (`src/cooperative/scheduler.rs`) -- Two async functions that drive the scheduler without holding borrows. `drive_until_complete()` polls a `oneshot::Receiver` while driving the scheduler, yielding to the browser event loop via `gloo_timers::future::TimeoutFuture::new(0)` between iterations.

5. **Stubs for unsupported primitives** (`src/runtime/compat.rs`) -- UDP sockets, Unix domain sockets, and blocking operations return `Unsupported` errors. These are not needed for Tor client operation.

**Key code paths:**
- `src/cooperative/mod.rs` -- Architecture overview, `open_cooperative_stream()`
- `src/cooperative/scheduler.rs` -- `CooperativeCircuit`, `drive_scheduler()`, `drive_until_complete()`
- `src/cooperative/stream.rs` -- `CooperativeStream` (per-stream AsyncRead/AsyncWrite)
- `src/runtime/sleep.rs` -- `WasmSleep` (setTimeout-based)
- `src/runtime/spawn.rs` -- `WasmSpawner` (spawn_local-based)

**What Arti could adopt:** The key architectural pattern is the checkout/return model for circuit ownership. Arti's `tor-rtcompat` already abstracts the runtime -- adding a WASM backend would require:

- A `WasmRuntime` implementing `SleepProvider` (via `setTimeout`), `Spawn` (via `spawn_local`), and `TcpProvider` (via WebSocket bridge).
- Replace `Mutex<Circuit>` with `Rc<RefCell<Circuit>>` behind a WASM feature gate, using the checkout/return pattern for all async operations.
- Use `futures` crate only (no tokio, no async-std). Our `Cargo.toml` depends on `futures = "0.3"` and `gloo-timers` for the timer primitives. We do pull in `tor-rtcompat` but only for trait definitions, not its runtime implementations.

---

## Issue #343: TCP sockets are forbidden in browsers

**Problem:** Browsers cannot open raw TCP connections. Tor requires TCP connections to relay nodes (guard, middle, exit).

**tor-wasm's solution:** A WebSocket-to-TCP bridge server with multiple transport modes and a unified transport abstraction:

1. **WebSocket bridge** (`bridge-server/server-collector.js`, ~100 lines of proxy logic) -- The bridge accepts WebSocket connections from the browser, opens a TCP+TLS connection to the target Tor relay, and bidirectionally forwards data. The bridge is protocol-unaware -- it sees only encrypted bytes after TLS is established. The WASM client sends `ws://bridge?addr=1.2.3.4:9001`, the bridge connects to `1.2.3.4:9001` via TCP, upgrades to TLS, and forwards.

2. **WasmTcpStream** (`src/transport/websocket.rs`) -- Implements `AsyncRead` and `AsyncWrite` over a WebSocket connection using `web-sys::WebSocket`. Event-driven: `onmessage` pushes to a receive buffer, `poll_read` drains it. Includes reconnection with exponential backoff (1s, 2s, 4s, 8s, 16s) and traffic shaping for DPI resistance.

3. **Transport failover chain** (`src/transport/mod.rs`, `src/transport/unified.rs`) -- The client tries transports in order:
   - **WebSocket** (direct) -- fastest, identifiable by protocol DPI
   - **WebTunnel** (`src/transport/webtunnel.rs`) -- HMAC-SHA256 probe-resistant WebSocket upgrade
   - **meek** (`src/transport/meek.rs`) -- HTTP POST bodies through a CDN (survives full protocol blocking)
   - **WebRTC** (`src/transport/webrtc.rs`) -- DataChannel through a volunteer browser tab (looks like a video call)

   All four implement `AsyncRead + AsyncWrite` and are unified under the `TransportStream` enum.

4. **Bridge blinding** (`src/transport/bridge_blind.rs`) -- In two-hop mode, the relay address is encrypted under Bridge B's X25519 public key (ephemeral ECDH + HKDF-SHA256 + AES-256-GCM). Bridge A forwards the opaque blob. Neither bridge alone can correlate client IP with guard relay IP.

5. **BridgeConfig** (`src/transport/mod.rs`) -- Unified configuration for all transport modes. `build_url()` handles both direct mode (`?addr=...`) and blinded mode (`?dest=<encrypted_blob>`).

**Key code paths:**
- `bridge-server/server-collector.js` -- WebSocket-to-TCP proxy (server side)
- `src/transport/websocket.rs` -- `WasmTcpStream` (AsyncRead/AsyncWrite over WebSocket)
- `src/transport/mod.rs` -- `BridgeConfig`, `TransportMode`
- `src/transport/unified.rs` -- `TransportStream` enum (all 4 transports)
- `src/transport/bridge_blind.rs` -- Two-hop bridge blinding
- `src/transport/meek.rs` -- HTTP POST/response transport
- `src/transport/webtunnel.rs` -- HMAC probe-resistant WebSocket
- `src/transport/webrtc.rs` -- WebRTC DataChannel transport

**What Arti could adopt:** The WebSocket bridge pattern is the standard approach (Snowflake uses a similar concept). Arti could:

- Define a `WasmTcpStream` type that wraps `web-sys::WebSocket` and implements `AsyncRead + AsyncWrite`, then plug it into the existing `TcpProvider` trait.
- The bridge server is ~100 lines of Node.js -- minimal operational surface. Alternatively, Arti could define a pluggable transport interface that accepts any `AsyncRead + AsyncWrite` stream, letting the WASM layer provide WebSocket/meek/WebRTC implementations without changing Arti core.
- The bridge is intentionally protocol-unaware (forwards raw TLS bytes), which means it cannot inspect, modify, or log Tor traffic. This is a security property worth preserving.

---

## Summary

| Arti Issue | Problem | tor-wasm Solution | Files |
|---|---|---|---|
| [#339](https://gitlab.torproject.org/tpo/core/arti/-/issues/339) | No filesystem | IndexedDB + localStorage | `src/storage/`, `src/guards.rs` |
| [#340](https://gitlab.torproject.org/tpo/core/arti/-/issues/340) | SQLite (C lib) | Bridge fetches consensus; client verifies + stores in IndexedDB | `bridge-server/server-collector.js`, `src/protocol/consensus_verify.rs` |
| [#341](https://gitlab.torproject.org/tpo/core/arti/-/issues/341) | zstd/xz2 (C libs) | Bridge decompresses; pure-Rust fallbacks available | `bridge-server/server-collector.js` |
| [#342](https://gitlab.torproject.org/tpo/core/arti/-/issues/342) | No tokio/async-std | Cooperative scheduler with checkout/return pattern, `futures` only | `src/cooperative/`, `src/runtime/` |
| [#343](https://gitlab.torproject.org/tpo/core/arti/-/issues/343) | No raw TCP | WebSocket/meek/WebRTC bridge with AsyncRead/AsyncWrite | `src/transport/`, `bridge-server/` |

---

## Draft GitLab Comment

The following is a ready-to-post comment for the Arti GitLab issue tracker (e.g., on [#103](https://gitlab.torproject.org/tpo/core/arti/-/issues/103) or individual sub-issues).

---

> **Subject: Solutions to all 5 WASM blockers (#339-#343) from tor-wasm**
>
> Hi Arti team,
>
> We've been working on [tor-wasm](https://github.com/user/tor-wasm), a minimal Tor client written from scratch for `wasm32-unknown-unknown`. It implements ntor handshakes, 3-hop circuit building, onion encryption, and connects to the real Tor network from a browser tab. Along the way, we had to solve each of the 5 WASM blockers listed under this issue. We wanted to share what worked for us in case any of it is useful for Arti's WASM target.
>
> **#339 (StateMgr / filesystem):** We replaced filesystem persistence with IndexedDB via `web-sys` bindings. Guard state, consensus, and relay descriptors all serialize to JSON and store in IndexedDB object stores. Guard state additionally uses `localStorage` for fast synchronous reads on bootstrap. The data model maps 1:1 from "file per state type" to "IndexedDB key per state type."
>
> **#340 (dirmgr / SQLite):** We moved consensus fetching to a bridge server that fetches from `collector.torproject.org`, parses relay information + ntor keys, and serves pre-processed JSON over HTTPS. The WASM client verifies directory authority signatures, then stores the verified relay list in IndexedDB. No SQLite needed on the client. An alternative for Arti would be `sql.js` (SQLite-to-WASM via Emscripten), though we found the key-value approach simpler.
>
> **#341 (Compression / C bindings):** Our bridge server handles all decompression server-side. The client never sees zstd/xz2-compressed data. For a full Arti port, pure-Rust alternatives exist: `zstd-rs` (no C), `lzma-rs`, `miniz_oxide`. Performance is acceptable for the ~2MB consensus fetched every 3 hours.
>
> **#342 (Runtime / tokio):** This was the hardest one. We built a cooperative scheduler (~850 lines) that runs on the browser's event loop using only `futures` + `gloo-timers` + `wasm-bindgen-futures::spawn_local`. The key innovation is a **checkout/return pattern** for circuit ownership: all async I/O happens with the circuit "checked out" of a `RefCell`, avoiding the borrow-across-await panic that makes naive `Rc<RefCell<_>>` unusable. Sleep uses `setTimeout` via `JsFuture`. Spawning uses `spawn_local`. Time uses `js_sys::Date::now()`.
>
> **#343 (TCP sockets):** We wrote a WebSocket-to-TCP bridge server (~100 lines of Node.js). The WASM client wraps `web-sys::WebSocket` in an `AsyncRead + AsyncWrite` implementation. We also support meek (HTTP POST through CDN), WebTunnel (HMAC-authenticated WebSocket), and WebRTC DataChannel transports, all behind a unified `TransportStream` enum. The bridge is protocol-unaware -- it forwards encrypted TLS bytes and cannot inspect Tor traffic.
>
> Our codebase is AGPL-3.0 and available for reference. We're happy to discuss any of these solutions in more detail or adapt them into patches if that would be helpful. We view our project as complementary to Arti -- Arti serves desktop/mobile embedding, tor-wasm serves browsers and sandboxed environments.
>
> Thanks for all the work on Arti and the Tor protocol specifications that made this possible.
