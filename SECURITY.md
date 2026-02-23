# Security Policy

## Important Disclaimer

**tor-wasm has not received an external security audit.** It is alpha-quality software intended for research and development. Do not rely on it for safety-critical anonymity needs until it has been professionally audited.

## Reporting Vulnerabilities

If you discover a security vulnerability in tor-wasm, please report it responsibly:

1. **Do NOT open a public GitHub issue** for security vulnerabilities
2. Email your report to the maintainers (see CONTRIBUTING.md for contact)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a timeline for a fix.

## Security Model

tor-wasm's security relies on:

- **Tor protocol correctness:** ntor handshake (Proposal 216), 3-hop onion routing, guard persistence
- **Audited cryptographic crates:** `ring`, `rustls`, `x25519-dalek`, `curve25519-dalek` (no custom crypto)
- **Bridge trust model:** Bridge operators observe strictly less than guard relay operators (TLS is end-to-end between browser and guard)
- **Browser sandbox:** WASM linear memory isolation, same-origin policy

### Known Limitations

- **Bridge operator visibility:** Bridge sees client IP and guard relay IP (but not destinations or content)
- **Single bridge per circuit:** Supports multiple bridges with fallback sequencing (`BridgeConfiguration`), but all hops in a circuit use the same bridge (per-hop bridge diversity planned)
- **No pluggable transports:** Bridge connections are identifiable as WebSocket traffic (obfs4 integration planned)
- **No onion services:** Only clearnet destinations supported currently
- **Browser fingerprinting:** tor-wasm includes a comprehensive fingerprint defense module (`src/fingerprint-defense.js`) covering 18 vectors across 3 tiers with anti-detection measures. See "Fingerprint Defense Module" section below for details

## Cryptographic Dependencies

| Crate | Version | Purpose | Audit Status |
|-------|---------|---------|-------------|
| `ring` | 0.17 | Core crypto (AES, SHA, ECDH) | Google-maintained, widely audited |
| `rustls` | 0.23 | TLS implementation | OSTIF/Cure53 audit (2020) |
| `x25519-dalek` | 2.0 | X25519 key exchange | dalek-cryptography audited |
| `curve25519-dalek` | 4.0 | Curve25519 operations | NCC Group audit (2019) |
| `sha2` | 0.10 | SHA-256 | RustCrypto, widely used |
| `aes` | 0.8 | AES block cipher | RustCrypto, constant-time |

## Fingerprint Defense Module

tor-wasm includes a comprehensive browser fingerprint defense (`src/fingerprint-defense.js`) covering 18 fingerprinting vectors across 3 tiers, with anti-detection measures that make overrides invisible to fingerprinting scripts.

```javascript
import { applyFingerprintDefense } from './fingerprint-defense.js';
applyFingerprintDefense(); // Apply all 18 defenses
applyFingerprintDefense({ canvas: true, webgl: true, webrtc: true, timezone: false }); // Selective
```

### Anti-Detection Layer

All API overrides use **native function toString spoofing**: `Function.prototype.toString` is intercepted so that patched functions return `"function name() { [native code] }"` when inspected. This defeats the primary detection method used by fingerprinting libraries to identify JavaScript-level API overrides.

### Tier 1: Critical (Security + Primary Fingerprint Vectors)

| Vector | Defense | Method |
|--------|---------|--------|
| **WebRTC IP Leak** | **API blocking** | Blocks `RTCPeerConnection`, `RTCSessionDescription`, `RTCIceCandidate` — prevents STUN-based real IP discovery that bypasses Tor entirely |
| Canvas (2D) | Noise injection | Session-stable deterministic pixel perturbation (~5% of pixels, +/-1) on `getImageData`, `toDataURL`, `toBlob` |
| Canvas (WebGL) | readPixels noise | Same perturbation applied to `WebGLRenderingContext.readPixels` |
| WebGL | Vendor/renderer | Returns "Mozilla" for all vendor/renderer queries, blocks `WEBGL_debug_renderer_info`, normalizes `MAX_TEXTURE_SIZE` |
| Navigator | Property normalization | UA, platform, language, hardwareConcurrency, deviceMemory, plugins, mimeTypes — all normalized to Linux/Firefox ESR 115 profile |
| Screen | Dimension normalization | Reports 1920x1080, devicePixelRatio=1, normalized inner/outer dimensions |

### Tier 2: Important (Secondary Fingerprint Vectors)

| Vector | Defense | Method |
|--------|---------|--------|
| Timezone | UTC normalization | `getTimezoneOffset()=0`, all `toLocale*String()` methods, `Intl.DateTimeFormat`, `toString()` — all report UTC |
| Audio | Output noise + normalization | Perturbs `AnalyserNode` frequency/time-domain data, normalizes sample rate (44100) and channel count (2) |
| Fonts | Enumeration + measurement | `document.fonts.check()` only confirms standard fonts; `measureText()` returns monospace-fallback widths for non-standard fonts via Proxy |
| Performance | Timer precision reduction | `performance.now()` rounded to 100ms (matches Tor Browser), `performance.memory` returns fixed values, entry durations rounded |
| ClientRects | Integer rounding | `getBoundingClientRect()` and `getClientRects()` on both `Element` and `Range` return integer-rounded `DOMRect` values |

### Tier 3: Hardening (API Blocking + Edge Cases)

| Vector | Defense | Method |
|--------|---------|--------|
| Speech synthesis | Voice blocking | `getVoices()` returns empty, `voiceschanged` event suppressed |
| WebGPU | Adapter info normalization | `requestAdapterInfo()` returns empty strings |
| Network info | API removal | `navigator.connection` returns undefined |
| Storage estimate | Fixed values | `navigator.storage.estimate()` returns fixed 1GB quota |
| Media devices | Enumeration + access blocking | `enumerateDevices()` returns empty, `getUserMedia`/`getDisplayMedia` throw NotAllowedError |
| Battery | API removal | `getBattery` removed, `BatteryManager` events blocked |
| Gamepad | API blocking | `getGamepads()` returns empty |
| CSS media queries | Preference normalization | `matchMedia()` returns normalized values for `prefers-color-scheme`, `prefers-reduced-motion`, `pointer`, `hover`, `display-mode`, and 10+ other queries |
| Workers | Event blocking + constructor wrapping | Blocks `deviceorientation`, `devicemotion`, `gamepadconnected` events; Worker/SharedWorker constructors preserved for URL-based workers |

### What it cannot defend against

- **TLS fingerprinting (JA3/JA4)** — below JavaScript layer, determined by browser's TLS implementation
- **HTTP header ordering** — controlled by browser engine, not accessible from JS
- **JavaScript engine microbenchmarks** — V8 vs SpiderMonkey execution timing differences
- **TCP/IP stack fingerprinting** — OS-level network behavior

### Threat model

**Effective against:** Commercial fingerprinting services (FingerprintJS, CreepJS, Panopticlick) that combine canvas + WebGL + navigator + audio + fonts. The anti-detection layer defeats `toString()` checks used to identify API overrides.

**Partially effective against:** Advanced tracking companies that use ClientRects + CSS probing + performance timing. The Tier 2 defenses address these but may not cover all edge cases.

**Not effective against:** State-level adversaries with browser-level instrumentation, or attackers who can correlate TLS fingerprints with other metadata. For these threat models, use Tor Browser.

## Scope

This security policy covers:
- The Rust WASM module (`src/`)
- The bridge server (`bridge-server/`)
- The tor-core library (`tor-core/`)
- The fingerprint defense module (`src/fingerprint-defense.js`)

It does not cover:
- Example HTML files (for demonstration only)
- Development tooling
