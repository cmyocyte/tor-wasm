# Threat Model

## Overview

tor-wasm is a browser-native Tor client implemented in Rust, compiled to WebAssembly. It provides onion-routed anonymity from within a standard web browser without requiring the Tor Browser or any native application.

## Trust Assumptions

### Trusted Components
- **Directory Authorities**: We hardcode the 9 Tor directory authority v3ident fingerprints. We trust the Tor consensus document when signed by >= 5 authorities.
- **Tor Network**: We trust the Tor relay infrastructure to the same degree as standard Tor — individual relays are untrusted, but the 3-hop circuit design provides anonymity assuming no single entity controls all hops.
- **Browser Sandbox**: We rely on the browser's WASM sandbox for memory safety isolation.

### Partially Trusted Components
- **Bridge Server**: The WebSocket bridge relays TCP traffic to Tor relays. It can observe connection metadata (timing, volume, destination relay IP) but cannot read encrypted relay traffic. A malicious bridge could:
  - Correlate connection times with relay traffic (traffic analysis)
  - Refuse to relay connections (DoS)
  - Inject a fake consensus (mitigated by consensus signature verification)
  - Log client IP addresses
- **WebSocket Transport**: Observable by network adversaries. TLS protects content but not metadata (timing, packet sizes).

### Untrusted Components
- **Individual Tor Relays**: Any relay may be malicious. The 3-hop design (guard → middle → exit) prevents any single relay from learning both client identity and destination.
- **Web Pages**: JavaScript running in the page context. Fingerprint defenses mitigate identification.
- **Network Observers**: ISPs, firewalls, and nation-state adversaries observing traffic between client and bridge.

## Attack Vectors and Mitigations

### Risk Summary

| # | Attack | Severity | Likelihood | Risk |
|---|--------|----------|------------|------|
| 1 | Relay Impersonation | Critical | Low | Medium |
| 2 | Traffic Analysis / Correlation | High | Medium | High |
| 3 | Browser Fingerprinting | High | High | High |
| 4 | Sybil Attack | Critical | Low | Medium |
| 5 | Certificate Forgery | Critical | Low | Low |
| 6 | Cell Injection / Modification | High | Low | Low |
| 7 | Replay Attacks | Medium | Low | Low |
| 8 | Bridge Server Abuse | Medium | Medium | Medium |
| 12 | Active Bridge Probing | High | High | Medium |
| 9 | WASM Binary Tampering | High | Low | Medium |
| 10 | IndexedDB State Poisoning | Medium | Low | Low |
| 11 | Browser Extension Key Extraction | Critical | Low | Medium |

### 1. Relay Impersonation
**Attack**: A malicious bridge injects fake relay data into the consensus.
**Severity**: Critical — would redirect all traffic through attacker-controlled relays.
**Likelihood**: Low — requires forging signatures from 5 of 9 independent directory authorities operated by distinct organizations across multiple jurisdictions (MIT, Tor Project, EFF, etc.).
**Mitigation**:
- Consensus signature verification against 9 hardcoded directory authority fingerprints
- Requires >= 5 valid authority signatures (structural + format + RSA verification when keys available)
- Certificate chain validation: Ed25519 signing key → identity key → RSA fingerprint

### 2. Traffic Analysis / Correlation
**Attack**: Correlating entry and exit traffic patterns to de-anonymize users.
**Severity**: High — breaks anonymity entirely.
**Likelihood**: Medium — requires observation points at both bridge and exit; nation-state capability.
**Mitigation**:
- Traffic shaping with PADDING cells (enabled by default, ~10% overhead)
- Configurable chaff traffic during idle periods
- Timing obfuscation with minimum cell intervals
- SENDME flow control prevents sender-side timing leaks
- Two-hop bridge blinding splits observation across Bridge A and Bridge B (see "Bridge Trust Elimination" in SECURITY-ARCHITECTURE.md)

### 3. Browser Fingerprinting
**Attack**: Websites identify the tor-wasm user through browser APIs.
**Severity**: High — defeats anonymity at application layer.
**Likelihood**: High — commercial fingerprinting services (FingerprintJS, CreepJS) are widely deployed.
**Mitigation**: 20 defense vectors implemented in WASM:
- **Tier 1** (6): Navigator, WebRTC, Canvas, Screen, WebGL, Audio
- **Tier 2** (4): Timezone (UTC), Performance (100ms rounding), Fonts, Client Rects
- **Tier 3** (9): Speech synthesis, WebGPU, Network Info, Storage, Media Devices, Battery, Gamepad, CSS Media Queries, Workers/Events
- **Iframe protection**: All defenses re-applied in iframes
- **Anti-detection**: WASM closures show `[native code]` in toString()

### 4. Sybil Attack
**Attack**: An adversary runs many relays to control multiple hops in a circuit.
**Severity**: Critical — controlling guard + exit breaks anonymity.
**Likelihood**: Low — bandwidth-weighted selection means controlling a significant fraction of network bandwidth is expensive (~$100K+/month at current relay costs).
**Mitigation**:
- Relay family constraints prevent two relays from the same operator in one circuit
- Guard node persistence (60-day rotation) reduces exposure to new malicious guards
- Bandwidth-weighted selection makes Sybil attacks proportionally expensive

### 5. Certificate Forgery
**Attack**: A relay presents forged certificates during handshake.
**Severity**: Critical — enables man-in-the-middle on circuit hops.
**Likelihood**: Low — requires breaking Ed25519 signatures (computationally infeasible with current technology).
**Mitigation**:
- Ed25519 signature verification on Type 4 (signing key) certificates
- Signing key cert signed by identity key
- TLS link cert signed by signing key
- Expiration checks on all certificates
- Cross-cert (Type 7) format validation

### 6. Cell Injection / Modification
**Attack**: An intermediate hop modifies relay cells in transit.
**Severity**: High — could inject content or disrupt circuits.
**Likelihood**: Low — requires compromising a relay in the circuit path.
**Mitigation**:
- Running SHA-1 digest verification on relay cell payloads
- AES-128-CTR encryption at each hop (onion encryption)
- Digest mismatch detection and logging

### 7. Replay Attacks
**Attack**: Replaying previously captured cells.
**Severity**: Medium — limited impact due to stateful encryption.
**Likelihood**: Low — requires network-level capture capability.
**Mitigation**:
- Stateful AES-CTR ciphers (counter-mode) make replayed cells decrypt to garbage
- SENDME flow control windows prevent cell injection

### 8. Bridge Server Abuse
**Attack**: Unauthorized use of bridge bandwidth, DoS against bridge.
**Severity**: Medium — degrades service for legitimate users.
**Likelihood**: Medium — bridge IPs are discoverable by design.
**Mitigation**:
- Per-IP rate limiting (10 connections/minute default)
- Global connection limit (1000 concurrent)
- Optional authentication via `BRIDGE_AUTH_TOKEN`
- Multiple bridge deployment with failover
- In-app bridge manager allows users to add/remove bridges without new app deployments

### 9. WASM Binary Tampering (tor-wasm-specific)
**Attack**: Attacker compromises the CDN or hosting provider and serves a modified WASM binary that exfiltrates keys or bypasses circuit construction.
**Severity**: High — complete compromise of all users loading from that host.
**Likelihood**: Low — requires CDN compromise or DNS hijacking.
**Mitigation**:
- Subresource Integrity (SRI) hashes on `<script>` tags loading the WASM module
- HTTPS-only serving with HSTS
- Multiple independent hosting mirrors allow cross-verification
- Open-source: users can build from source and compare hashes

### 10. IndexedDB State Poisoning (tor-wasm-specific)
**Attack**: Malicious JavaScript (from XSS or browser extension) modifies cached consensus or guard state in IndexedDB, forcing the client to use attacker-chosen relays.
**Severity**: Medium — could redirect traffic, but consensus signature verification limits impact.
**Likelihood**: Low — requires same-origin code execution (XSS) or browser extension access.
**Mitigation**:
- Consensus signatures are re-verified on load from IndexedDB
- Guard state includes relay fingerprints verified against consensus
- Private browsing mode bypasses IndexedDB entirely (no persistence)

### 11. Browser Extension Key Extraction (tor-wasm-specific)
**Attack**: A malicious browser extension reads WASM linear memory to extract ephemeral circuit keys (AES-128-CTR keys, X25519 private keys).
**Severity**: Critical — decrypts all circuit traffic for the session.
**Likelihood**: Low — requires user to install a malicious extension; browser extension review processes provide some (imperfect) protection.
**Mitigation**:
- Key material is zeroized on drop via the `zeroize` crate
- Ephemeral keys are short-lived (circuit lifetime, typically < 10 minutes)
- This is the same threat model as Tor Browser — a malicious extension can compromise any application running in the browser
- **Recommendation**: Use in a clean browser profile or private browsing mode

### 12. Active Bridge Probing
**Attack**: A censor discovers a bridge URL and connects to it to confirm it is a Tor bridge (as opposed to a regular website).
**Severity**: High — confirmed bridges are immediately blocked.
**Likelihood**: High — Russia (TSPU) and China (GFW) actively probe suspected bridges.
**Mitigation**:
- WebTunnel bridge uses HMAC-SHA256 challenge via `Sec-WebSocket-Protocol: v1.<hmac>.<timestamp>`
- Probers who know the secret path but not the HMAC protocol get an identical 404 response — indistinguishable from a wrong URL
- 5-minute timestamp window (generous for clock skew in censored regions)
- Timing-safe comparison prevents side-channel leaks
- Cover site served for all non-matching requests (identical nginx headers)
- Cloudflare Worker deployment makes the bridge indistinguishable from any other `*.workers.dev` service

## Known Limitations vs. Full Tor Browser

| Feature | Tor Browser | tor-wasm |
|---------|------------|----------|
| Pluggable Transports | obfs4, meek, snowflake | WebSocket, WebTunnel (HMAC), meek (CDN) |
| Bridge Discovery | BridgeDB | In-app bridge manager, Telegram bot, QR codes, offline bundle |
| Hidden Services (.onion) | Full support | Not implemented |
| Directory Downloads | Direct from authorities | Via bridge/collector |
| DNS Resolution | SOCKS5 remote DNS | Via exit relay (RELAY_RESOLVE) |
| Circuit Multiplexing | Multiple streams per circuit | Supported |
| Protocol Version | Link v5, Cell v5 | Link v4/v5, Cell v4/v5 |
| Guard Selection | Adaptive, persistent | Persistent, bandwidth-weighted |
| Padding | Negotiated (PADDING_NEGOTIATE) | Local only (PADDING cells) |

## Forensic Trace Analysis

**Claim: "Zero forensic trace"** — this requires qualification.

| Storage | Private Browsing | Normal Browsing |
|---------|-----------------|-----------------|
| WASM binary | Not cached | May be cached in browser HTTP cache |
| IndexedDB (consensus, guards) | Not written | Persists until cleared |
| localStorage | Not written | Persists until cleared |
| Browser history | Not recorded | URL bar entries may persist |
| Service Worker cache | Not registered | Persists until unregistered |
| DNS cache (OS-level) | Bridge domain cached | Bridge domain cached |

**Accurate statement**: In private/incognito browsing mode, tor-wasm leaves no persistent forensic trace on the device beyond OS-level DNS cache (which clears on reboot). In normal browsing mode, standard browser storage (IndexedDB, cache, history) may persist. Users in high-risk environments should use private browsing mode or clear site data after each session.

## What tor-wasm Does NOT Protect Against

1. **Global passive adversary**: An entity observing both client-bridge and exit-destination traffic can perform timing correlation. This is a fundamental Tor limitation, shared with Tor Browser.
2. **Compromised browser**: If the browser itself is compromised (e.g., zero-day exploit), all bets are off. This is equivalent to the Tor Browser threat model.
3. **Application-layer leaks**: WebSocket connections, fetch requests, or other browser APIs that bypass the Tor circuit. The Service Worker proxy mitigates this for sub-resource fetches but cannot intercept WebSocket connections initiated by page JavaScript.
4. **Physical observation**: Shoulder surfing, hardware keyloggers, etc.
5. **Bridge-level traffic analysis**: The bridge operator can observe timing patterns between client and guard relay. Mitigated by two-hop bridge blinding (see "Bridge Trust Elimination" in SECURITY-ARCHITECTURE.md).
6. **TLS fingerprinting (JA3/JA4)**: The browser's TLS implementation produces a distinctive fingerprint. This is below the JavaScript layer and cannot be modified by tor-wasm.
7. **Browser extension attacks**: Malicious extensions can read WASM memory, intercept network traffic, or modify page content. Use a clean browser profile.
8. **JavaScript engine fingerprinting**: V8 (Chrome) vs SpiderMonkey (Firefox) execution timing differences can identify the browser engine. Cannot be mitigated from JavaScript.
9. **Guard selection fingerprinting**: tor-wasm's guard selection algorithm (bandwidth-weighted with 60-day rotation) differs from Tor Browser's (which uses the full guard specification). A relay operator observing guard choices across many users could statistically distinguish tor-wasm users from Tor Browser users.
