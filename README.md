# Tor WASM Client

**A minimal Tor client written from scratch for WebAssembly, enabling browser-native Tor connections.**

---

## 🙏 Acknowledgments & Attribution

### Implementation

This is a **minimal Tor client** written from scratch specifically for WebAssembly, implementing the [Tor Protocol Specification](https://spec.torproject.org/).

We referenced [**Arti**](https://gitlab.torproject.org/tpo/core/arti), the Tor Project's official Rust implementation, for design patterns and protocol correctness. Our implementation:

- Uses `tor-rtcompat` from Arti (runtime compatibility layer)
- Uses the same cryptographic primitives as Arti (`x25519-dalek`, `curve25519-dalek`, `sha1`, `aes`, etc.)
- Implements the Tor protocol (ntor handshake, circuit building, onion encryption) from scratch for WASM compatibility

### Why a New Implementation?

Neither the original C Tor client nor Arti can be directly compiled to WebAssembly:

| Project | WASM Compatible? | Reason |
|---------|------------------|--------|
| **Tor (C)** | ❌ | Heavy syscall dependencies, complex build |
| **Arti (Rust)** | ❌ | Depends on tokio, native networking |
| **This project** | ✅ | Written WASM-first, minimal dependencies |

### Tor Project

We gratefully acknowledge the [**Tor Project**](https://www.torproject.org/) for:

- The [Tor Protocol Specification](https://spec.torproject.org/) 
- [Arti](https://gitlab.torproject.org/tpo/core/arti) as a reference implementation
- Making online privacy possible for millions of people

### License

MIT / Apache 2.0

### Links

- [Tor Protocol Specification](https://spec.torproject.org/)
- [Arti GitLab Repository](https://gitlab.torproject.org/tpo/core/arti)
- [Tor Project](https://www.torproject.org/)

---

## 🎯 What This Is

A **real Tor client** compiled to WebAssembly that:

- ✅ Performs actual ntor cryptographic handshakes
- ✅ Builds real 3-hop circuits through the Tor network
- ✅ Connects to 9,000+ real Tor relays
- ✅ Does onion encryption/decryption in the browser
- ✅ Hides your IP from destination servers

## 🏗️ Architecture

### Direct Mode
```
Browser (WASM)  →  Bridge Server (WS→TCP)  →  Guard → Middle → Exit → Destination
```

### Blinded Mode (two-hop, recommended)
```
Browser (WASM)  →  Bridge A (WS→WS)  →  Bridge B (decrypt, TCP)  →  Guard → Middle → Exit
                   sees: client IP        sees: guard IP
                   cannot see: guard      cannot see: client
```

### Peer Bridge Mode (maximum censorship resistance)
```
Browser (WASM)  →  Volunteer Proxy (WebRTC→WS)  →  Bridge A  →  Bridge B  →  Guard → ...
                   looks like a video call
```

```
┌─────────────────────────────────────────────────────────────────┐
│                     BROWSER                                     │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  tor-wasm (Rust → WebAssembly, 1.2MB)                    │  │
│  │                                                          │  │
│  │  • ntor handshakes (X25519 + HKDF-SHA256)               │  │
│  │  • Onion encryption (3 layers AES-128-CTR)              │  │
│  │  • Circuit building (Guard → Middle → Exit)             │  │
│  │  • Bridge blinding (X25519 + AES-256-GCM)               │  │
│  │  • 20-vector fingerprint defense                        │  │
│  │  • Transport: WebSocket or WebRTC DataChannel           │  │
│  └──────────────────────────────────────────────────────────┘  │
└───────────────────────────┼────────────────────────────────────┘
                            │
                            ▼
                   REAL TOR NETWORK
          Guard → Middle → Exit → Destination
```

## 📦 Components

### `/src` - Rust WASM Library

The core Tor protocol implementation:

```
src/
├── lib.rs              # TorClient - main API
├── protocol/
│   ├── circuit_builder.rs   # Circuit establishment
│   ├── ntor.rs              # ntor handshake (from Arti)
│   ├── crypto.rs            # Key derivation
│   ├── relay.rs             # Relay selection
│   └── stream.rs            # TCP streams over Tor
└── runtime/
    ├── wasm_tcp.rs          # WebSocket→TCP bridge
    └── compat.rs            # Browser compatibility
```

### `/bridge-server` - Node.js Bridge

WebSocket to TCP proxy server:

```
bridge-server/
├── server-collector.js    # Main server (fetches consensus)
├── server-bridge-a.js     # Bridge A: client-facing relay (blinded mode)
├── server-bridge-b.js     # Bridge B: relay-facing decryptor (blinded mode)
├── keygen.js              # Generate Bridge B X25519 keypair
├── package.json
├── DEPLOY.md              # Single-bridge deployment
└── DEPLOY-BLINDED.md      # Two-hop blinded deployment + ECH
```

### `/broker` - Signaling Broker

Matches censored clients with volunteer peer proxies:

```
broker/
├── server.js     # WebSocket signaling broker
└── package.json
```

### `/proxy` - Volunteer Peer Proxy

Solidarity webpage — volunteer opens a browser tab to help censored users:

```
proxy/
├── proxy.js      # Browser-based WebRTC relay (~200 lines)
└── index.html    # Solidarity Bridge webpage
```

### `/pkg` - WASM Output

Generated WebAssembly and JavaScript bindings:

```
pkg/
├── tor_wasm_bg.wasm     # Compiled WASM (~428KB)
├── tor_wasm.js          # JavaScript bindings
└── tor_wasm.d.ts        # TypeScript definitions
```

## 🚀 Quick Start

### 1. Build the WASM module

```bash
cd tor-wasm
wasm-pack build --target web
```

### 2. Start the bridge server

```bash
cd bridge-server
npm install
node server-collector.js
```

### 3. Test in browser

Open `test-integrated.html` in your browser.

## 🔧 API

```javascript
import init, { TorClient } from './pkg/tor_wasm.js';

// Initialize WASM
await init();

// Create client
const client = await new TorClient('ws://localhost:8080');

// Bootstrap (fetch consensus)
await client.bootstrap();

// Check status
const status = client.get_status();
console.log(`Connected to ${status.get('consensus_relay_count')} relays`);

// Fetch through Tor (IP hidden!)
const response = await client.fetch('http://example.com');
```

## 🔐 Privacy Model

### Direct Mode (single bridge)

| Observer | What They See |
|----------|--------------|
| **Destination** | Tor exit node IP (NOT your IP) ✅ |
| **Your ISP** | Connection to bridge server |
| **Bridge Server** | Your IP + which guard (NOT your traffic) |
| **You run bridge** | Full privacy ✅ |

### Blinded Mode (two-hop bridge)

| Observer | What They See |
|----------|--------------|
| **Destination** | Tor exit node IP (NOT your IP) ✅ |
| **Your ISP** | Connection to Bridge A (ECH-hidden) |
| **Bridge A** | Your IP only (guard address encrypted) ✅ |
| **Bridge B** | Guard IP only (does not know your IP) ✅ |
| **Peer proxy** | Your IP only (guard and destination hidden) ✅ |

In blinded mode, **no single entity** can see both your IP and which guard relay you connect to. Correlation requires collusion between Bridge A and Bridge B operators.

## ⚠️ Important Notes

1. **Bridge Server Trust**: In direct mode, the bridge sees your IP and the guard relay. In blinded mode (two-hop), this trust is split — no single bridge sees both. See `papers/BRIDGE-TRUST-ELIMINATION.md` for details.
2. **Not Audited**: Use at your own risk until security audit

## 📚 References

- [Tor Protocol Specification](https://spec.torproject.org/)
- [ntor Handshake](https://spec.torproject.org/tor-spec/create-created-cells.html)
- [Arti Design](https://gitlab.torproject.org/tpo/core/arti/-/blob/main/doc/dev/Design.md)

---

## 📄 License

MIT / Apache 2.0 (compatible with Arti's licensing)

---

**Based on Arti by the Tor Project** 🧅

**Adapted for WebAssembly to enable browser-native privacy**

