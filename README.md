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

AGPL-3.0. For commercial licensing inquiries, contact cmyocyte@gmail.com

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
- ✅ Multiple transports: WebSocket, WebTunnel, meek (CDN relay)
- ✅ In-app bridge manager with QR scanning
- ✅ Probe-resistant WebTunnel handshake (HMAC-SHA256)
- ✅ Deployable as Cloudflare Worker (domain fronting + meek relay)
- ✅ 4 languages: English, Farsi, Russian, Chinese

## 🏗️ Architecture

### System Overview

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  BROWSER (any modern browser — Chrome, Firefox, Safari, iOS Safari)         │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  tor-wasm  (Rust → WebAssembly, 538KB gzipped)                        │  │
│  │                                                                        │  │
│  │  ┌─────────────┐  ┌──────────────┐  ┌──────────────────────────────┐  │  │
│  │  │ Fingerprint │  │ Service      │  │  Tor Protocol Engine         │  │  │
│  │  │ Defense     │  │ Worker Proxy │  │                              │  │  │
│  │  │ (20 vectors)│  │ (sub-resource│  │  ntor X25519 handshake      │  │  │
│  │  │             │  │  routing)    │  │  3-layer AES-128-CTR onion  │  │  │
│  │  └─────────────┘  └──────────────┘  │  SHA-1 cell digest          │  │  │
│  │                                      │  Tor-Vegas congestion ctrl  │  │  │
│  │  ┌─────────────┐  ┌──────────────┐  │  Channel padding            │  │  │
│  │  │ Consensus   │  │ TLS 1.3      │  │  Guard persistence (60d)    │  │  │
│  │  │ Signature   │  │ (rustls)     │  │  Circuit isolation/rotation │  │  │
│  │  │ Verifier    │  │ end-to-end   │  └──────────────────────────────┘  │  │
│  │  │ (9 DA keys) │  │ to guard     │                                    │  │
│  │  └─────────────┘  └──────────────┘                                    │  │
│  └──────────────────────────────┬─────────────────────────────────────────┘  │
│                                 │ encrypted TLS records                      │
└─────────────────────────────────┼────────────────────────────────────────────┘
                                  │
          ┌───────────────────────┼───────────────────────┐
          │                       │                       │
          ▼                       ▼                       ▼
   ┌─────────────┐      ┌──────────────┐      ┌──────────────────┐
   │  WebSocket  │      │  Cloudflare  │      │    meek relay    │
   │  Bridge     │      │  Worker      │      │  (HTTP POST      │
   │  (WS→TCP)   │      │  (WS→TCP +   │      │   through CDN)   │
   │             │      │   consensus  │      │                  │
   │             │      │   proxy +    │      │                  │
   │             │      │   meek)      │      │                  │
   └──────┬──────┘      └──────┬───────┘      └────────┬─────────┘
          │                    │  opaque bytes          │
          └────────────────────┼────────────────────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  REAL TOR NETWORK   │
                    │                     │
                    │  Guard ──→ Middle ──→ Exit ──→ Destination
                    │  (knows    (knows    (knows
                    │   bridge    neither)  destination,
                    │   IP only)           not client)
                    └─────────────────────┘
```

### Consensus Verification Pipeline

The WASM client verifies that the relay list was signed by at least 5 of 9 Tor directory authorities before trusting it. This prevents a compromised bridge from injecting fake relays.

```
 Tor Directory Authorities (9 hardcoded)
 ┌──────────┬──────────┬──────────┬──────────┐
 │ bastet   │ gabelmoo │ tor26    │ moria1   │ ...5 more
 └────┬─────┴────┬─────┴────┬─────┴────┬─────┘
      │          │          │          │   TCP (HTTP 1.0)
      └──────────┴──────┬───┴──────────┘
                        ▼
            ┌───────────────────────┐
            │   Cloudflare Worker   │
            │                       │
            │  1. TCP fetch from DA │
            │  2. Parse relay list  │
            │  3. Fetch ntor keys   │
            │  4. Return JSON with  │──→  CF Cache (1hr TTL)
            │     raw_consensus     │
            └───────────┬───────────┘
                        │  JSON: { consensus: {...}, raw_consensus: "..." }
                        ▼
            ┌───────────────────────┐
            │   WASM Client         │
            │                       │
            │  1. Parse relay JSON  │
            │  2. Extract raw text  │
            │  3. Verify 5+ DA sigs │ ← ConsensusVerifier (SHA-256 + RSA format)
            │  4. Reject if < 5    │
            │  5. Use relay list    │
            └───────────────────────┘
```

### Connection Modes

**Direct Mode:**
```
Browser (WASM)  →  Bridge Server (WS→TCP)  →  Guard → Middle → Exit → Destination
```

**Blinded Mode (two-hop, recommended):**
```
Browser (WASM)  →  Bridge A (WS→WS)  →  Bridge B (decrypt, TCP)  →  Guard → Middle → Exit
                   sees: client IP        sees: guard IP
                   cannot see: guard      cannot see: client
```

**Peer Bridge Mode (maximum censorship resistance):**
```
Browser (WASM)  →  Volunteer Proxy (WebRTC→WS)  →  Bridge A  →  Bridge B  →  Guard → ...
                   looks like a video call
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

WebSocket/WebTunnel/meek bridge servers:

```
bridge-server/
├── server-collector.js    # Main server (fetches consensus)
├── server-bridge-a.js     # Bridge A: client-facing relay (blinded mode)
├── server-bridge-b.js     # Bridge B: relay-facing decryptor (blinded mode)
├── server-webtunnel.js    # WebTunnel bridge (HMAC probe-resistant)
├── server-meek.js         # Meek bridge (HTTP POST through CDN)
├── keygen.js              # Generate Bridge B X25519 keypair
├── distribution/
│   ├── telegram-bot.js    # Telegram bridge distribution bot
│   ├── email-responder.js # Email auto-responder for bridges
│   └── qr-generator.js   # QR code bridge config generator
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

### `/app` - Browser UI (PWA)

The privacy browser frontend with i18n and bridge management:

```
app/
├── index.html         # Full app: boot sequence, bridge manager, settings panel
├── i18n/
│   ├── en.json        # English
│   ├── fa.json        # Farsi (RTL)
│   ├── ru.json        # Russian
│   └── zh.json        # Chinese
└── sw.js              # Service Worker for offline + sub-resource routing
```

### `/worker` - Cloudflare Worker

Censorship-resistant hosting — serves the app, acts as a WebSocket bridge, meek relay, and consensus proxy from `*.workers.dev`:

```
worker/
├── wrangler.toml      # Wrangler config (Durable Objects binding)
├── src/index.ts       # Router + WS bridge + consensus proxy + meek relay (~600 lines)
├── build.js           # Embeds WASM + HTML + JS into Worker for deployment
├── package.json
└── tsconfig.json
```

Routes:
- `GET /` — cover site (looks like a blog, mimics nginx/1.24.0)
- `GET /?v=1` — the WASM app (steganographic URL, configurable via APP_SECRET)
- `WS /?addr=h:p` — WebSocket-to-TCP bridge (runs at CF edge, real-time relay)
- `GET /tor/consensus` — proxy: fetches live consensus from Tor directory authorities
- `POST /` — meek bridge relay (X-Session-Id + X-Target headers, Durable Objects)
- `GET /test-relay` — TCP reachability probe for relay diagnostics

### `/tools` - Build & Distribution Tools

```
tools/
└── bundle-offline.js  # Generate self-contained offline HTML (~3-4MB)
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

## 🌐 Transport Failover Chain

The client automatically tries transports in order of censorship resistance:

```
1. WebSocket (direct)     → fastest, blocked by protocol DPI
2. WebTunnel (WS + HMAC)  → looks like normal HTTPS, probe-resistant
3. meek (HTTP POST + CDN) → survives full protocol blocking (GFW)
```

WebTunnel connections use HMAC-SHA256 probe resistance: `Sec-WebSocket-Protocol: v1.<hmac>.<timestamp>`. A prober who discovers the path but doesn't know the HMAC gets an identical 404 — indistinguishable from a wrong URL.

## 🔧 Deployment Options

### Self-hosted bridge
```bash
cd bridge-server && npm install && node server-collector.js
```

### Cloudflare Worker (recommended for censored regions)
```bash
cd worker && npx wrangler deploy
# Serves app + meek relay on *.workers.dev — blocking it causes collateral damage
```

### Offline bundle (sneakernet for shutdowns)
```bash
node tools/bundle-offline.js --bridges bridges.json --output offline.html
# Single ~3-4MB HTML file, share via USB/Bluetooth/AirDrop
```

### Bridge distribution
- **Telegram bot**: `bridge-server/distribution/telegram-bot.js` — `/start` to receive bridge URL
- **QR codes**: `bridge-server/distribution/qr-generator.js`
- **Email auto-responder**: `bridge-server/distribution/email-responder.js`

## ⚠️ Important Notes

1. **Bridge Server Trust**: In direct mode, the bridge sees your IP and the guard relay. In blinded mode (two-hop), this trust is split — no single bridge sees both. See `papers/BRIDGE-TRUST-ELIMINATION.md` for details.
2. **Not Audited**: Use at your own risk until security audit

## 📚 References

- [Tor Protocol Specification](https://spec.torproject.org/)
- [ntor Handshake](https://spec.torproject.org/tor-spec/create-created-cells.html)
- [Arti Design](https://gitlab.torproject.org/tpo/core/arti/-/blob/main/doc/dev/Design.md)

---

## 📄 License

AGPL-3.0 (open source, OSI-approved). For commercial licensing inquiries, contact cmyocyte@gmail.com

---

**Based on Arti by the Tor Project** 🧅

**Adapted for WebAssembly to enable browser-native privacy**

