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

### 1. Relay Impersonation
**Attack**: A malicious bridge injects fake relay data into the consensus.
**Mitigation**:
- Consensus signature verification against 9 hardcoded directory authority fingerprints
- Requires >= 5 valid authority signatures (structural + format + RSA verification when keys available)
- Certificate chain validation: Ed25519 signing key → identity key → RSA fingerprint

### 2. Traffic Analysis / Correlation
**Attack**: Correlating entry and exit traffic patterns to de-anonymize users.
**Mitigation**:
- Traffic shaping with PADDING cells (enabled by default, ~10% overhead)
- Configurable chaff traffic during idle periods
- Timing obfuscation with minimum cell intervals
- SENDME flow control prevents sender-side timing leaks

### 3. Browser Fingerprinting
**Attack**: Websites identify the tor-wasm user through browser APIs.
**Mitigation**: 20 defense vectors implemented in WASM:
- **Tier 1** (6): Navigator, WebRTC, Canvas, Screen, WebGL, Audio
- **Tier 2** (4): Timezone (UTC), Performance (100ms rounding), Fonts, Client Rects
- **Tier 3** (9): Speech synthesis, WebGPU, Network Info, Storage, Media Devices, Battery, Gamepad, CSS Media Queries, Workers/Events
- **Iframe protection**: All defenses re-applied in iframes
- **Anti-detection**: WASM closures show `[native code]` in toString()

### 4. Sybil Attack
**Attack**: An adversary runs many relays to control multiple hops in a circuit.
**Mitigation**:
- Relay family constraints prevent two relays from the same operator in one circuit
- Guard node persistence reduces exposure to new malicious guards
- Bandwidth-weighted selection makes Sybil attacks expensive

### 5. Certificate Forgery
**Attack**: A relay presents forged certificates during handshake.
**Mitigation**:
- Ed25519 signature verification on Type 4 (signing key) certificates
- Signing key cert signed by identity key
- TLS link cert signed by signing key
- Expiration checks on all certificates
- Cross-cert (Type 7) format validation

### 6. Cell Injection / Modification
**Attack**: An intermediate hop modifies relay cells in transit.
**Mitigation**:
- Running SHA-1 digest verification on relay cell payloads
- AES-128-CTR encryption at each hop (onion encryption)
- Digest mismatch detection and logging

### 7. Replay Attacks
**Attack**: Replaying previously captured cells.
**Mitigation**:
- Stateful AES-CTR ciphers (counter-mode) make replayed cells decrypt to garbage
- SENDME flow control windows prevent cell injection

### 8. Bridge Server Abuse
**Attack**: Unauthorized use of bridge bandwidth, DoS against bridge.
**Mitigation**:
- Per-IP rate limiting (10 connections/minute default)
- Global connection limit (1000 concurrent)
- Optional authentication via `BRIDGE_AUTH_TOKEN`

## Known Limitations vs. Full Tor Browser

| Feature | Tor Browser | tor-wasm |
|---------|------------|----------|
| Pluggable Transports | obfs4, meek, snowflake | WebSocket only |
| Bridge Discovery | BridgeDB | Single configured bridge |
| Hidden Services (.onion) | Full support | Not implemented |
| Directory Downloads | Direct from authorities | Via bridge/collector |
| DNS Resolution | SOCKS5 remote DNS | Via exit relay (RELAY_RESOLVE) |
| Circuit Multiplexing | Multiple streams per circuit | Supported |
| Protocol Version | Link v5, Cell v5 | Link v4/v5, Cell v4/v5 |
| Guard Selection | Adaptive, persistent | Persistent, bandwidth-weighted |
| Padding | Negotiated (PADDING_NEGOTIATE) | Local only (PADDING cells) |

## What tor-wasm Does NOT Protect Against

1. **Global passive adversary**: An entity observing both client-bridge and exit-destination traffic can perform timing correlation. This is a fundamental Tor limitation.
2. **Compromised browser**: If the browser itself is compromised (e.g., zero-day), all bets are off.
3. **Application-layer leaks**: WebSocket connections, fetch requests, or other browser APIs that bypass the Tor circuit.
4. **Physical observation**: Shoulder surfing, hardware keyloggers, etc.
5. **Bridge-level traffic analysis**: The bridge operator can observe timing patterns between client and guard relay.
