# Security Architecture

## Cryptographic Primitives

| Primitive | Algorithm | Library | Usage |
|-----------|-----------|---------|-------|
| Key Exchange | X25519 (Curve25519) | `x25519-dalek` | ntor handshake |
| HMAC | HMAC-SHA256 | `hmac` + `sha2` | ntor key derivation |
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

### Transport
- WebSocket over HTTP (upgradable to WSS with reverse proxy)
- TLS to relay (self-signed, `rejectUnauthorized: false`)
- No SNI for IP address targets

## Test Coverage

| Category | Tests | Type |
|----------|-------|------|
| Fingerprint Defense | 22 | WASM integration |
| Protocol Security | 32 | WASM integration |
| Module Unit Tests | 124+ | In-module |
| **Total** | **178+** | |

### Test Categories
- Cryptographic correctness (key derivation, zeroization)
- Protocol compliance (cell format, command values, flow control)
- Security enforcement (consensus verification, cert chain, family constraints)
- Edge cases (truncated data, malformed input, boundary conditions)
- Fingerprint defense validation (all 20 vectors)
