# Security Architecture

## Client Bootstrap: Zero DNS Leaks

The WASM client performs **zero DNS queries to Tor infrastructure**. All bootstrap data and relay connections are proxied through the bridge server:

- **Consensus fetch**: The client calls `fetch()` to `{bridge_url}/tor/consensus` — the only DNS query is for the bridge domain itself (protected by ECH via Cloudflare).
- **Relay connections**: All TCP connections to Tor relays go through the bridge's WebSocket-to-TCP proxy.
- **Fallback consensus**: Uses hardcoded relay IPs — no DNS resolution required.
- **No phone-home**: The WASM binary makes no requests to `torproject.org`, directory authorities, or any other identifiable Tor infrastructure.

This design ensures that even in environments with DNS monitoring (Russia, China, Iran), the client's DNS queries reveal nothing about Tor usage.

## Cryptographic Primitives

| Primitive | Algorithm | Library | Usage |
|-----------|-----------|---------|-------|
| Key Exchange | X25519 (Curve25519) | `x25519-dalek` | ntor handshake |
| HMAC | HMAC-SHA256 | `hmac` + `sha2` | ntor key derivation, WebTunnel probe resistance |
| Relay Encryption | AES-128-CTR | `aes` + `ctr` | Per-hop onion encryption |
| Relay Digest | SHA-1 | `sha1` | Cell integrity verification |
| Certificate Signing | Ed25519 | `ed25519-dalek` | Relay identity binding |
| Consensus Digest | SHA-256 + SHA-1 | `sha2` + `sha1` | Consensus integrity |
| RSA Verification | RSA-PKCS1-v1.5 | `ring` | Authority signature verification |
| Random | CSPRNG | `getrandom` (WASM) | Nonces, circuit IDs, padding |
| Key Zeroization | Zeroize-on-drop | `zeroize` | CircuitKeys cleanup |

## Circuit Building Flow

```
Client → Bridge (WebSocket/TLS) → Guard (TCP/TLS) → Middle → Exit → Destination
```

### 1. Bootstrap
1. Fetch consensus from bridge (`/tor/consensus`)
2. Verify consensus signatures (>= 5 directory authorities)
3. Parse relay list with flags, bandwidth, ntor keys

### 2. Path Selection
1. Select guard (persistent, bandwidth-weighted)
2. Select middle (random, excluding guard's family)
3. Select exit (random, excluding guard's and middle's families)
4. Validate path: no family conflicts, no deny-listed relays

### 3. Circuit Creation (per hop)
1. **Guard**: TCP → TLS → VERSIONS → CERTS (verified) → AUTH_CHALLENGE → NETINFO → CREATE2 (ntor) → CREATED2
2. **Middle**: EXTEND2 (ntor through encrypted circuit) → EXTENDED2
3. **Exit**: EXTEND2 (ntor through doubly-encrypted circuit) → EXTENDED2

### 4. ntor Handshake
```
Client generates: x (ephemeral X25519 secret)
Client sends:     X = g^x, relay_identity (20B), relay_ntor_key (32B)
Relay responds:   Y = g^y, AUTH = HMAC(secret_input, "verify")
Client derives:   CircuitKeys from HKDF(shared_secret)
```

## Encryption Layers

Each relay cell traverses the circuit with layered AES-128-CTR encryption:

```
Sending (client → exit):
  payload → encrypt(guard_key) → encrypt(middle_key) → encrypt(exit_key)
  Guard strips first layer, Middle strips second, Exit strips third

Receiving (exit → client):
  payload → encrypt(exit_key) → encrypt(middle_key) → encrypt(guard_key)
  Client decrypts all three layers
```

### Digest Verification
- Running SHA-1 hash of all relay cell payloads (forward and backward)
- 4-byte digest prefix in each relay cell header
- Detects cell injection or modification by intermediate hops

## Flow Control

### Stream-Level (per stream)
- **Window size**: 500 cells
- **SENDME increment**: 50 cells
- **Trigger**: After receiving 50 data cells, send RELAY_SENDME
- **Result**: Sender replenishes window by 50

### Circuit-Level (per circuit)
- **Window size**: 1000 cells
- **SENDME increment**: 100 cells
- **Same mechanism** as stream-level but aggregated across all streams

## Certificate Chain

```
RSA Identity Key (fingerprint in consensus)
    └── Ed25519 Identity Key (Type 7: cross-cert)
            └── Ed25519 Signing Key (Type 4: signed by identity)
                    └── TLS Link Key (Type 5: signed by signing key)
```

### Verification Steps
1. Parse CERTS cell from relay handshake
2. Extract Ed25519 identity from Type 4/7 certificates
3. Verify Type 4 cert: signing key signed by identity key, not expired
4. Verify Type 5 cert: TLS key signed by signing key, not expired
5. Verify Type 7 cert: cross-cert format (binds Ed25519 to RSA identity)
6. Match RSA fingerprint against consensus

## Fingerprint Defense Layers

### Architecture
All defenses are implemented in Rust compiled to WASM. Each defense:
1. Intercepts browser API via `Proxy` or property redefinition
2. Returns normalized values matching Tor Browser's fingerprint
3. Uses `[native code]` toString spoofing to prevent WASM detection

### Normalized Profile
| Property | Value | Rationale |
|----------|-------|-----------|
| `navigator.platform` | `Linux x86_64` | Tor Browser default |
| `navigator.userAgent` | `Firefox/115.0` | Tor Browser ESR |
| `navigator.hardwareConcurrency` | `4` | Most common |
| `navigator.language` | `en-US` | Tor Browser default |
| `screen.width/height` | `1920x1080` | Most common resolution |
| `devicePixelRatio` | `1.0` | Prevents DPI fingerprinting |
| `Date.getTimezoneOffset()` | `0` (UTC) | Tor Browser behavior |
| `performance.now()` | Rounded to 100ms | Prevents timing attacks |
| `RTCPeerConnection` | Blocked | Prevents IP leak |
| Canvas/WebGL | Noise injection | Prevents rendering fingerprint |
| `AudioContext` | Noise injection | Prevents audio fingerprint |

## Traffic Shaping

### Default Configuration (enabled)
- **Padding**: 10% probability per cell (PADDING command 0)
- **Chaff**: Disabled by default (enable via `paranoid()`)
- **Timing**: No minimum interval by default

### Paranoid Configuration
- **Padding**: 20% probability
- **Chaff**: Every 15 seconds during idle
- **Timing**: 10ms minimum between cells
- **Random delay**: Up to 50ms per cell
- **Overhead**: ~20% bandwidth increase

## Bridge Server Security

### Rate Limiting
- Per-IP: Max 10 new WebSocket connections per minute
- Global: Max 1000 concurrent connections
- Stale entries cleaned every 2 minutes

### Authentication
- Optional `BRIDGE_AUTH_TOKEN` environment variable
- Provided via `Authorization: Bearer <token>` header or `?token=<token>` query parameter
- If unset, anonymous access allowed (backward compatible)

### Transport Failover
The client tries transports in order of censorship resistance:

1. **WebSocket** (direct) — fastest, identifiable by protocol DPI
2. **WebTunnel** (WS + HMAC) — looks like normal HTTPS WebSocket upgrade, probe-resistant
3. **meek** (HTTP POST through CDN) — survives full protocol blocking (e.g., GFW)

All transports use TLS to relay (`rejectUnauthorized: false` for self-signed relay certs). No SNI for IP address targets.

### WebTunnel Probe Resistance (HMAC-SHA256)

Active probers (Russia TSPU, China GFW) connect to suspected bridges to confirm their identity. WebTunnel prevents this:

```
Client sends:  Sec-WebSocket-Protocol: v1.<HMAC-SHA256(secret_path, timestamp)[0:128bit]>.<timestamp>
Server checks: timestamp within 5 min, HMAC matches (timing-safe), upgrades if valid
Invalid:       identical 404 response (same headers, same cover page as wrong path)
```

**Implementation:**
- Server: `bridge-server/server-webtunnel.js` — `verifyHmacChallenge(req)` with `crypto.timingSafeEqual()`
- Client (Rust): `src/transport/webtunnel.rs` — `compute_hmac_challenge(secret_path)` using `hmac` + `sha2` crates
- Client (JS): `app/index.html` — `computeWebTunnelHmac(secretPath)` using Web Crypto API

**Security properties:**
- HMAC key = the secret path (user needs only one piece of information)
- Truncated to 128 bits (32 hex chars) — sufficient for authentication
- 5-minute timestamp window (generous for clock skew in censored regions)
- Prober with only the path gets identical 404 — indistinguishable from wrong URL
- Cover site mimics nginx/1.24.0 headers on all responses

### Cloudflare Worker Architecture

The Worker (`worker/src/index.ts`) solves the bootstrap problem: censors see HTTPS to `*.workers.dev` — blocking it causes collateral damage to thousands of legitimate services.

```
GET /           → cover site (convincing blog page)
GET /?v=1       → the WASM app (steganographic URL, configurable via APP_SECRET)
POST /          → meek bridge relay (X-Session-Id + X-Target headers)
GET /health     → cover site (unless HEALTH_TOKEN matches)
```

**Meek relay via Durable Objects:**
- Each `X-Session-Id` maps to a Durable Object holding a persistent TCP socket
- Durable Object uses Cloudflare's `connect()` API for TLS to Tor guard relay
- Session persists across HTTP POST requests (~60s idle timeout)
- Protocol mirrors `server-meek.js` — existing WASM meek client speaks it natively

**Client auto-detection:** When served from `*.workers.dev` or `*.pages.dev`, the app automatically adds `location.origin` to the meek bridge list (zero configuration).

### Bridge Distribution Channels

Multiple channels to solve the bridge URL distribution problem:

| Channel | Tool | Anti-Enumeration |
|---------|------|-----------------|
| Telegram bot | `distribution/telegram-bot.js` | Rate-limited (1/hour per user ID hash) |
| Email responder | `distribution/email-responder.js` | Rate-limited per sender |
| QR codes | `distribution/qr-generator.js` | Physical sharing only |
| Offline bundle | `tools/bundle-offline.js` | Sneakernet (USB/Bluetooth/AirDrop) |
| In-app bridge manager | `app/index.html` | User adds bridges via QR scan, paste, or JSON import |

Bridge configs use a common JSON format (`{u, k, m}`) compatible across all channels. The in-app bridge manager auto-detects format (WebSocket URL, WebTunnel `{url, path}`, meek URL, Lox credential `{i, c, a}`).

## Bridge Trust Elimination

### Two-Hop Bridge Blinding

The single-bridge model exposes both client IP and guard relay IP to the bridge operator. Two-hop blinding splits this knowledge across two independent operators:

```
Client → Bridge A (sees client IP, NOT guard) → Bridge B (sees guard IP, NOT client) → Guard
```

**Crypto mechanism:** The client encrypts the guard relay address under Bridge B's static X25519 public key using ephemeral ECDH + HKDF-SHA256 + AES-256-GCM. Bridge A receives an opaque blob it cannot decrypt. Bridge B decrypts to learn the guard address but only sees Bridge A's IP, not the client's.

| Entity | Sees Client IP? | Sees Guard IP? | Can Correlate? |
|--------|----------------|----------------|----------------|
| Bridge A | Yes | No (encrypted) | No |
| Bridge B | No (sees Bridge A) | Yes | No |
| Both colluding | Yes | Yes | Yes |

**Implementation:**
- Client: `src/transport/bridge_blind.rs` — `blind_target_address()` using `x25519-dalek`, `hkdf`, `aes-gcm`
- Bridge A: `bridge-server/server-bridge-a.js` — opaque WS-to-WS relay, does not interpret `?dest=` parameter
- Bridge B: `bridge-server/server-bridge-b.js` — X25519 ECDH + AES-256-GCM decryption using Node.js built-in `crypto`
- Key generation: `bridge-server/keygen.js`

**Fixed nonce safety:** A 12-byte fixed nonce (`bridge-blind`) is safe because each connection uses a fresh ephemeral X25519 keypair, making every (derived key, nonce) pair unique.

### ECH-Hidden Infrastructure

Both Bridge A and the signaling broker run behind Cloudflare with Encrypted Client Hello (ECH). The censor sees a TLS connection to Cloudflare's shared IP — the true destination (bridge domain) is encrypted in the ClientHello. Blocking the bridge requires blocking all Cloudflare traffic.

### Browser-Native Peer Bridges

Volunteer proxies run as browser tabs (no installation). The censored client connects via WebRTC DataChannel (appears as a video call to DPI), the proxy relays to Bridge A over WebSocket. The proxy sees only encrypted bytes — it has no Tor protocol knowledge and cannot decrypt traffic (TLS is end-to-end between WASM client and guard).

**Components:**
- Signaling broker: `broker/server.js` — matches clients with proxies, stateless after match
- Volunteer proxy: `proxy/proxy.js` + `proxy/index.html` — solidarity webpage
- Client transport: `src/transport/webrtc.rs` — Rust/WASM WebRTC DataChannel with AsyncRead/AsyncWrite

### Combined Visibility Matrix

| Entity | Client IP | Guard IP | Destination | Content |
|--------|-----------|----------|-------------|---------|
| Peer proxy | Yes | No | No | No |
| Bridge A | No (proxy IP) | No (encrypted) | No | No |
| Bridge B | No (Bridge A IP) | Yes | No | No |
| Guard | No (Bridge B IP) | — | No | No |
| Exit | No | No | Yes | If HTTP |

**No single entity can link client identity to destination.**

## Test Coverage

| Category | Tests | Type |
|----------|-------|------|
| Fingerprint Defense | 22 | WASM integration |
| Protocol Security | 32 | WASM integration |
| Module Unit Tests | 124+ | In-module |
| Censorship Simulation | 4 | Node.js integration |
| **Total** | **182+** | |

### Test Categories
- Cryptographic correctness (key derivation, zeroization)
- Protocol compliance (cell format, command values, flow control)
- Security enforcement (consensus verification, cert chain, family constraints)
- Edge cases (truncated data, malformed input, boundary conditions)
- Fingerprint defense validation (all 20 vectors)
- Censorship resistance (`tests/censorship-sim/`): DNS leak detection, traffic classification, signature scanning, active probing
