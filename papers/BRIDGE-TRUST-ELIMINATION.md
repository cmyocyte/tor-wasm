# Bridge Trust Elimination: Design Document

**Project:** tor-wasm
**Date:** February 2026
**Status:** Implemented and tested (February 2026)

---

## 1. Problem Statement

tor-wasm's bridge server is a WebSocket-to-TCP proxy that enables browsers to reach Tor relays despite lacking raw TCP socket access. Our PETS paper proves (Theorem 1) that the bridge observes *strictly less* than a standard Tor guard relay. However, "strictly less" is not "nothing." The bridge still introduces trust in four specific ways:

### 1.1 What the Bridge Sees Today

| Information | Visible to Bridge? | Risk |
|---|---|---|
| Client IP address | Yes | Identifies the user |
| Guard relay IP address | Yes (`?addr=1.2.3.4:9001` in WebSocket URL) | Reveals which relay the user chose |
| Timing and volume | Yes (byte counts, inter-packet gaps) | Enables traffic correlation |
| Cell contents | No (TLS-encrypted end-to-end) | — |
| Destinations visited | No (onion-encrypted) | — |
| Circuit structure | No (encrypted CREATE2/EXTEND2) | — |

### 1.2 Attacks Enabled by Current Trust Model

**Attack 1 — Bridge-Guard Correlation:** An adversary who operates the bridge AND observes the exit relay can correlate traffic entering and leaving the circuit. The bridge provides the client IP; the exit provides the destination. Timing correlation links the two.

**Attack 2 — Targeted Denial of Service:** A malicious bridge can selectively deny service to specific client IPs or when connections are requested to specific guard relays.

**Attack 3 — Consensus Staleness:** While the bridge cannot forge a consensus (signature verification prevents this), it can serve a stale consensus, causing the client to use outdated relay information.

**Attack 4 — Bridge Enumeration:** Censors can discover and block fixed bridge server IPs, denying access to the entire system.

### 1.3 Design Goal

Eliminate or mitigate all four attacks through three complementary mechanisms:

1. **Browser-native peer bridges** (Snowflake model) — Eliminates Attack 4 by making bridges ephemeral and uncatalogable
2. **ECH-hidden bridge infrastructure** — Mitigates Attack 4 by making bridge connections indistinguishable from normal web traffic
3. **Two-hop bridge blinding** — Eliminates Attack 1 by ensuring no single bridge sees both client IP and guard IP

---

## 2. Innovation 1: Browser-Native Peer Bridges

### 2.1 Background

Tor's Snowflake project uses volunteer browsers as ephemeral proxies. As of 2026, Snowflake has ~140,000 volunteer proxies serving ~35,000 daily users. However, Snowflake has a critical limitation: the *client* must install a native Tor binary. The Snowflake proxy only handles the transport layer — it forwards traffic to a Snowflake server, which then connects to the Tor network. The client runs a full native Tor process locally.

### 2.2 Architecture

tor-wasm enables a fundamentally different design: the client runs the *complete* Tor protocol in WASM. This means the peer proxy does not need to understand Tor at all — it just copies bytes between a WebRTC DataChannel and a WebSocket connection.

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Censored user's browser                                                │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  tor-wasm (1.2MB WASM)                                            │  │
│  │  - Full ntor handshake (X25519 + HKDF-SHA256)                    │  │
│  │  - 3-hop circuit construction (CREATE2 + EXTEND2)                │  │
│  │  - AES-128-CTR onion encryption (3 layers)                       │  │
│  │  - Consensus signature verification (9 directory authorities)    │  │
│  │  - Certificate chain validation (Ed25519 Type 4/5/7)             │  │
│  │  - Stream multiplexing with SENDME flow control                  │  │
│  │  - 20-vector browser fingerprint defense                         │  │
│  └────────────────────┬──────────────────────────────────────────────┘  │
│                       │ WebRTC DataChannel (DTLS/SCTP over UDP)         │
│                       │ Looks like a video call to DPI equipment        │
└───────────────────────┼─────────────────────────────────────────────────┘
                        │
          ┌─────────────┼─────────────────────┐
          │             ▼                     │
          │  Volunteer's browser              │
          │  ┌─────────────────────────────┐  │
          │  │  Peer proxy (~200 lines JS) │  │
          │  │  - Accept WebRTC connection │  │
          │  │  - Open WebSocket to bridge │  │
          │  │  - Copy bytes bidirectionally│  │
          │  │  - No Tor protocol knowledge│  │
          │  │  - No cryptographic keys    │  │
          │  └──────────────┬──────────────┘  │
          │                 │ WebSocket        │
          └─────────────────┼─────────────────┘
                            │
                            ▼
                   ┌─────────────────┐
                   │  Bridge server  │  TCP to Tor relay
                   │  (behind ECH)   │──────────────────► Guard
                   └─────────────────┘
```

### 2.3 Signaling (Broker)

WebRTC requires a signaling channel to exchange SDP offers/answers and ICE candidates. We use a lightweight broker:

**Broker responsibilities:**
- Accept registrations from volunteer proxies (SDP offer + ICE candidates)
- Accept connection requests from censored clients
- Match clients with available proxies
- Relay SDP answer back to proxy
- Forget all state after match is made (no logging)

**Broker implementation:**
- ~300 lines of JavaScript (Express + WebSocket)
- Runs behind Cloudflare with ECH (see Innovation 2)
- Stateless after match — stores no connection history
- Multiple independent brokers for redundancy
- Broker URL embedded in WASM binary or distributed via QR codes, social media, DNS-over-HTTPS TXT records

**Signaling protocol:**
```
Proxy → Broker:   REGISTER { sdp_offer, ice_candidates, capacity }
Client → Broker:  REQUEST  { client_sdp_answer_placeholder }
Broker → Client:  MATCHED  { proxy_sdp_offer, proxy_ice_candidates }
Client → Broker:  ANSWER   { client_sdp_answer, client_ice_candidates }
Broker → Proxy:   CONNECT  { client_sdp_answer, client_ice_candidates }
                  (Broker forgets everything after this exchange)
```

### 2.4 Peer Proxy Implementation

The volunteer proxy runs as a plain webpage. No browser extension, no installation, no special permissions. The user visits a solidarity website and their browser tab becomes a bridge for censored users.

```javascript
// Simplified peer proxy (~200 lines in production)
const pc = new RTCPeerConnection(iceConfig);
const dc = pc.createDataChannel('tor-transport', { ordered: true });

// When a censored client connects via WebRTC:
dc.onmessage = (event) => {
  // First message contains the bridge URL + encrypted target
  if (!ws) {
    const bridgeUrl = parseBridgeUrl(event.data);
    ws = new WebSocket(bridgeUrl);
    ws.binaryType = 'arraybuffer';
    ws.onmessage = (e) => dc.send(e.data);  // Bridge → Client
    ws.onopen = () => dc.send(new Uint8Array([0x01])); // Ready signal
  } else {
    ws.send(event.data);  // Client → Bridge
  }
};
```

**What the proxy sees:** Encrypted bytes flowing in both directions. It cannot decrypt them (TLS is end-to-end between the WASM client and the guard relay). It does not know the client's intended destination, the circuit structure, or the guard relay's identity (if two-hop blinding is used).

**What the proxy knows:** The client's IP address (via WebRTC ICE) and the bridge server's URL. This is strictly less than what a standard Tor guard relay knows.

### 2.5 WebRTC in Rust/WASM

The client-side WebRTC connection is established from the WASM module using `web-sys` bindings:

**Available crates:**
- `web-sys`: Official Rust bindings to `RTCPeerConnection`, `RTCDataChannel`, `RTCIceCandidate`, `RTCSessionDescription`
- `matchbox` (crates.io): High-level WebRTC abstraction for Rust WASM, handles ICE/DTLS/SCTP
- `wasm-peers` (crates.io): Simplified WebRTC DataChannel API for WASM

**Implementation approach:**
- Add `web-sys` features: `RtcPeerConnection`, `RtcDataChannel`, `RtcConfiguration`, `RtcIceServer`
- New transport module: `src/transport/webrtc.rs` (parallel to existing `websocket.rs`)
- `WasmRtcStream` struct implementing the same `AsyncRead`/`AsyncWrite` traits as `WasmTcpStream`
- Transport selection: try WebRTC first (Snowflake mode), fall back to WebSocket (direct mode)

### 2.6 Why This Is Hard to Block

| Blocking strategy | Feasibility | Collateral damage |
|---|---|---|
| Block known bridge IPs | Ineffective — proxies are random browser tabs | None |
| Block WebRTC protocol | Breaks Google Meet, Zoom, Discord, Teams | Enormous |
| Block DTLS/SCTP patterns | Requires deep packet inspection of all UDP | Very high |
| Block the broker | Broker runs behind ECH on Cloudflare | Would block all Cloudflare sites |
| Enumerate proxy IPs | New proxies appear constantly, IPs rotate | Whack-a-mole |

### 2.7 Differences from Tor Snowflake

| Property | Tor Snowflake | tor-wasm Peer Bridges |
|---|---|---|
| **Client installation** | Requires native Tor binary | None — full Tor client in WASM |
| **Proxy installation** | Browser extension or Go binary | None — visit a website |
| **Proxy complexity** | Understands Snowflake protocol | Copies bytes — no protocol knowledge |
| **End-to-end path** | Client (native) → Proxy → Snowflake server → Tor | Client (WASM) → Proxy → Bridge → Tor |
| **Installation count** | 2 (client + proxy) | 0 (both are browser tabs) |
| **Tor protocol location** | Client-side (native process) | Client-side (WASM in browser) |

---

## 3. Innovation 2: ECH-Hidden Bridge Infrastructure

### 3.1 Background

Domain fronting — hiding the true destination behind a CDN's shared IP — was the standard approach for censorship-resistant signaling until 2018, when major CDNs (Google, Amazon, Cloudflare) began enforcing SNI/Host header consistency. Domain fronting is now effectively dead on all major CDNs.

Encrypted Client Hello (ECH) is the legitimate, standards-based successor. ECH encrypts the SNI field in the TLS ClientHello using the server's public key (distributed via DNS HTTPS/SVCB records). As of 2026:

- Chrome and Firefox enable ECH by default
- Cloudflare supports ECH on all plans (including free tier)
- IETF standardization at draft 25, RFC imminent
- 99.9% of top 10,000 websites use ECH-supporting CDNs

### 3.2 Architecture

```
Censored user's browser
         │
         │ TLS ClientHello with encrypted SNI
         │ (censor sees connection to Cloudflare IP,
         │  cannot determine which site)
         │
         ▼
┌─────────────────────────────────┐
│  Cloudflare CDN edge            │  Millions of websites behind
│  (shared IP address)            │  the same IP addresses
│                                 │
│  Decrypts ECH → sees true SNI  │
│  Routes to correct origin:     │
│    bridge.tor-wasm.example      │
└───────────────┬─────────────────┘
                │ (private Cloudflare ↔ origin tunnel)
                ▼
       ┌─────────────────┐
       │  Bridge server  │
       │  (origin)       │
       └─────────────────┘
```

### 3.3 What the Censor Sees

Without ECH: `TLS ClientHello { SNI: bridge.tor-wasm.example }` — trivially blocked.

With ECH: `TLS ClientHello { outer SNI: cloudflare-ech.example, encrypted_inner: [opaque] }` — the censor sees a connection to Cloudflare's shared infrastructure. The true destination is encrypted. Blocking this connection requires blocking all Cloudflare traffic.

### 3.4 Deployment

1. Register a domain (e.g., `bridge.tor-wasm.example`)
2. Configure Cloudflare as CDN proxy (free tier works)
3. Cloudflare automatically publishes HTTPS DNS records with ECH public keys
4. Bridge server runs as Cloudflare origin (WebSocket proxying enabled)
5. Client connects to `wss://bridge.tor-wasm.example/ws?addr=...`
6. Connection appears identical to visiting any Cloudflare-hosted website

**Cost:** $0 (Cloudflare free tier supports WebSocket proxying and ECH)

### 3.5 ECH for the Broker

The Snowflake broker (Section 2.3) also runs behind Cloudflare with ECH. The censored client's request for a peer proxy is indistinguishable from visiting any other Cloudflare-hosted website. The entire signaling channel is invisible to the censor.

### 3.6 Fallback: Multiple CDN Providers

If Cloudflare is blocked in a specific region, the system can fall back to other ECH-supporting CDNs:
- Fastly (co-author of ECH standard, full support)
- Amazon CloudFront (ECH adoption in progress)
- Akamai (ECH adoption in progress)

The WASM binary can embed multiple broker/bridge URLs across different CDNs.

---

## 4. Innovation 3: Two-Hop Bridge Blinding

### 4.1 Problem

Even with peer bridges and ECH, the bridge server still sees both the proxy's IP (which is *not* the client's IP, so this is already improved) and the guard relay's IP. In the direct-connection mode (no peer bridge), the bridge sees the client's IP and the guard's IP. This enables correlation.

### 4.2 Architecture

Split the bridge into two components operated by different parties:

```
Client                    Bridge A                    Bridge B              Guard
  │                      (client-facing)             (relay-facing)          │
  │   WebSocket          ┌──────────────┐            ┌──────────────┐  TCP  │
  │ ─────────────────►   │ Knows:       │  ────────► │ Knows:       │ ────► │
  │                      │  • Client IP │            │  • Guard IP  │       │
  │  ?dest=E_B(addr)     │  • Bridge B  │            │  • Bridge A  │       │
  │                      │ Cannot see:  │            │ Cannot see:  │       │
  │                      │  • Guard IP  │            │  • Client IP │       │
  │                      │  (encrypted) │            │  (only sees  │       │
  │                      └──────────────┘            │   Bridge A)  │       │
  │                                                  └──────────────┘       │
```

### 4.3 Protocol

**Setup (one-time):**
1. Bridge B generates a static X25519 keypair: `(b, B = g^b)`
2. Bridge B publishes its public key `B` (32 bytes) via the broker, DNS TXT record, or embedded in WASM binary
3. Bridge A is configured with Bridge B's address (but not its private key)

**Per-connection:**
1. Client selects a guard relay from the verified consensus: `guard_addr = "1.2.3.4:9001"`
2. Client generates an ephemeral X25519 keypair: `(e, E = g^e)`
3. Client computes shared secret: `ss = HKDF(g^{eb}, "tor-wasm-bridge-blind")`
4. Client encrypts the guard address: `encrypted_addr = AES-256-GCM(ss, guard_addr)`
5. Client sends to Bridge A: `?dest=<base64(E || encrypted_addr)>`
6. Bridge A receives the opaque blob, cannot decrypt it (doesn't have `b`)
7. Bridge A forwards the blob to Bridge B over a persistent connection
8. Bridge B decrypts: `ss = HKDF(g^{be}, "tor-wasm-bridge-blind")`, recovers `guard_addr`
9. Bridge B opens TCP connection to `guard_addr`, relays bytes back through Bridge A
10. All subsequent traffic flows: Client ↔ Bridge A ↔ Bridge B ↔ Guard (bytes copied, no inspection)

### 4.4 Formal Security Property

**Theorem 2 (Bridge Blinding):** Let $O_A$ denote the observations of Bridge A and $O_B$ denote the observations of Bridge B. Then:

- $O_A$ contains: client IP, Bridge B IP, encrypted (opaque) target address, traffic timing/volume
- $O_B$ contains: Bridge A IP, guard relay IP, traffic timing/volume
- $O_A \cap O_B$ with respect to identity-destination linkage: $\emptyset$

Neither bridge alone can determine both who the client is and which guard relay they connect to. Correlation requires collusion between Bridge A and Bridge B operators.

**Comparison with single-bridge model:**

| Property | Single bridge | Two-hop blinding |
|---|---|---|
| Client IP visible | Yes | Bridge A only |
| Guard IP visible | Yes | Bridge B only |
| Correlation possible | By bridge operator alone | Only if A and B collude |
| Formal guarantee | $O_{bridge} \subset O_{guard}$ | $O_A \cap O_B = \emptyset$ (linkage) |

### 4.5 Implementation

**Bridge B changes (~50 lines):**
```javascript
// In Bridge B's connection handler, before TCP connect:
// 1. Parse the encrypted blob from Bridge A
const { ephemeralPubKey, encryptedAddr } = parseBlob(blobFromBridgeA);

// 2. Compute shared secret using Bridge B's static private key
const sharedSecret = x25519(bridgeBPrivateKey, ephemeralPubKey);
const derivedKey = hkdf(sharedSecret, 'tor-wasm-bridge-blind');

// 3. Decrypt the target address
const guardAddr = aesGcmDecrypt(derivedKey, encryptedAddr);

// 4. Connect to the actual guard relay
const tcp = net.connect(parseAddr(guardAddr));
```

**Bridge A changes (~20 lines):**
```javascript
// Bridge A becomes even simpler — it doesn't parse the target address at all.
// It just forwards the entire query string to Bridge B.
wss.on('connection', (ws, req) => {
  const dest = req.url; // Opaque — Bridge A doesn't interpret it
  const bridgeB = new WebSocket(BRIDGE_B_URL + dest);

  // Bidirectional relay (same as current bridge, but to Bridge B instead of TCP)
  ws.on('message', data => bridgeB.send(data));
  bridgeB.on('message', data => ws.send(data));
});
```

**Client-side changes (Rust/WASM):**
- Add `x25519-dalek` encryption of target address (already a dependency for ntor)
- New function: `blind_target_address(guard_addr: &str, bridge_b_pubkey: &[u8; 32]) -> String`
- ~30 lines of Rust in `src/transport/bridge_blind.rs`

**Total new code:** ~100 lines across 3 files.

### 4.6 Operational Model

Bridge A and Bridge B should be operated by different entities to provide meaningful separation:

**Option 1 — Community operated:**
- Bridge A: Run by the tor-wasm project (or volunteers)
- Bridge B: Run by partnering organizations (digital rights groups, university labs)

**Option 2 — CDN-separated:**
- Bridge A: Behind Cloudflare (ECH-hidden)
- Bridge B: Behind Fastly or Amazon CloudFront (different CDN, different operator)

**Option 3 — Tor relay operator partnership:**
- Bridge B: Run by existing Tor relay operators alongside their relay infrastructure
- Natural fit — they already operate Tor infrastructure and understand the trust model

---

## 5. Combined Architecture

When all three innovations are deployed together:

```
┌──────────────────────────────────────────────────────────────────────┐
│  Censored user's browser                                             │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │  tor-wasm (1.2MB WASM)                                         │  │
│  │                                                                │  │
│  │  Transport selection (automatic, with fallback):               │  │
│  │  1. WebRTC → Peer proxy → Bridge A → Bridge B → Guard         │  │
│  │  2. WebSocket → Bridge A (ECH) → Bridge B → Guard             │  │
│  │  3. WebSocket → Single bridge (ECH) → Guard   [legacy]        │  │
│  │                                                                │  │
│  │  Bridge B's public key embedded in WASM binary                 │  │
│  │  Guard address encrypted under Bridge B's key                  │  │
│  └────────┬─────────────────────────┬─────────────────────────────┘  │
│           │ Path 1: WebRTC          │ Path 2: WebSocket (ECH)        │
└───────────┼─────────────────────────┼────────────────────────────────┘
            │                         │
            ▼                         │
   ┌──────────────┐                   │
   │  Volunteer   │ WebSocket         │
   │  browser tab │────────┐          │
   │  (proxy)     │        │          │
   └──────────────┘        │          │
      Knows: client IP     │          │
      Cannot see: guard,   ▼          ▼
      destination, content ┌──────────────────┐
                           │  Bridge A        │  Behind Cloudflare (ECH)
                           │  Knows: proxy IP │  Censor sees: "Cloudflare"
                           │  or client IP    │
                           │  Cannot see:     │
                           │  guard relay IP  │
                           └────────┬─────────┘
                                    │ Encrypted target address
                                    ▼
                           ┌──────────────────┐
                           │  Bridge B        │  Different operator
                           │  Knows: guard IP │  Does NOT know client IP
                           │  Cannot see:     │  (sees Bridge A's IP only)
                           │  client IP       │
                           └────────┬─────────┘
                                    │ TCP + TLS (end-to-end to WASM)
                                    ▼
                              Tor Guard Relay
                                    │
                              (standard 3-hop
                               onion circuit)
                                    │
                              Tor Exit Relay
                                    │
                                    ▼
                              Destination
```

### 5.1 Trust Analysis (Combined System)

| Entity | Knows Client IP? | Knows Guard IP? | Knows Destination? | Can Correlate? |
|---|---|---|---|---|
| Peer proxy | Yes | No | No | No |
| Bridge A | No (sees proxy IP) | No (encrypted) | No | No |
| Bridge B | No (sees Bridge A IP) | Yes | No | No |
| Guard relay | No (sees Bridge B IP) | — | No | No |
| Middle relay | No | No | No | No |
| Exit relay | No | No | Yes | No |

**No single entity in the entire chain can link client identity to destination.**

With the peer bridge path (Path 1), there are **5 layers of separation** between the user and their destination, and **4 independent entities** that would need to collude to break anonymity (proxy + Bridge A + Bridge B + exit relay).

### 5.2 Comparison with Existing Systems

| Property | Tor Browser | Snowflake + Tor | Lantern | **tor-wasm (full)** |
|---|---|---|---|---|
| Client installation | 50MB app | Native Tor | 15MB app | **None** |
| Proxy installation | N/A | Extension/binary | N/A | **None (webpage)** |
| Anonymity model | 3-hop onion | 3-hop onion | Single-hop proxy | **3-hop onion** |
| Bridge trust | N/A (direct TCP) | Snowflake server sees client+guard | Operator sees all | **Split: no single bridge sees both** |
| Censorship resistance | Pluggable transports | WebRTC (good) | Protocol obfuscation | **WebRTC + ECH (excellent)** |
| Forensic trace | App on device | App on device | App on device | **None (browser tab)** |
| iOS support | No | No | App Store dependent | **Yes (Safari)** |
| Formal security proof | tor-spec | Snowflake paper | None | **PETS 2026 + Theorem 2** |

---

## 6. Implementation Plan

### Phase 1: Two-Hop Bridge Blinding (1 week)

**Scope:** Smallest innovation, highest security impact, easiest to implement.

**Files:**
- `bridge-server/server-bridge-a.js` (~80 lines) — Client-facing relay, forwards opaque blobs to Bridge B
- `bridge-server/server-bridge-b.js` (~100 lines) — Relay-facing, decrypts target address, connects to guard
- `src/transport/bridge_blind.rs` (~50 lines) — Client-side X25519 encryption of target address
- `bridge-server/keygen.js` (~20 lines) — Generate Bridge B's X25519 keypair

**Dependencies:** Node.js built-in `crypto` module (X25519 + HKDF + AES-GCM, zero external dependencies), `x25519-dalek` (Rust, already a dependency)

**Testing:**
- Unit: Encrypt/decrypt roundtrip for target addresses
- Integration: Client connects through blinded two-hop bridge to real Tor relay
- Security: Verify Bridge A logs contain no guard relay IPs

### Phase 2: ECH Bridge Deployment (1 week)

**Scope:** Deploy existing bridge behind Cloudflare with ECH.

**Tasks:**
- Register domain, configure Cloudflare DNS with proxied records
- Enable WebSocket proxying in Cloudflare dashboard
- Verify ECH works: `openssl s_client -connect ... -ech_grease` shows encrypted SNI
- Update WASM binary with ECH-enabled bridge URL
- Test from simulated censored environment (block bridge origin IP, verify ECH bypasses)

**Dependencies:** Cloudflare account (free tier), domain registration

### Phase 3: Browser-Native Peer Bridges (2-3 weeks)

**Scope:** Full Snowflake-like peer bridge system.

**Files:**
- `broker/server.js` (~300 lines) — Signaling broker (match clients with proxies)
- `proxy/proxy.html` + `proxy/proxy.js` (~200 lines) — Volunteer proxy webpage
- `src/transport/webrtc.rs` (~400 lines) — Rust WASM WebRTC DataChannel transport
- `src/transport/mod.rs` — Transport selection logic (WebRTC → WebSocket fallback)

**Dependencies:**
- `web-sys` features: `RtcPeerConnection`, `RtcDataChannel`, `RtcConfiguration`, `RtcIceServer`, `RtcSessionDescription`, `RtcIceCandidate`
- `js-sys` for Promise/callback bridging
- STUN servers for ICE (Google's public STUN servers, or self-hosted)

**Testing:**
- Unit: WebRTC connection establishment in headless Chrome
- Integration: Full circuit build through peer proxy
- Load: Multiple simultaneous clients through single proxy
- Fallback: Verify WebSocket fallback when WebRTC is unavailable

### Phase 4: Solidarity Website (1 week)

**Scope:** Public website where volunteers can contribute their browser as a proxy.

**Deliverables:**
- Landing page explaining the cause and how it works
- One-click "Start Helping" button that activates the proxy
- Dashboard showing: active proxies, users helped, bandwidth contributed
- Privacy policy: what the proxy can and cannot see
- Localized to English, Farsi, Russian, Mandarin, Arabic

---

## 7. Security Considerations

### 7.1 WebRTC IP Leak via ICE

WebRTC ICE negotiation reveals the proxy's IP to the client and vice versa. This is necessary for the connection to work, but we must ensure the client's *local* IP (e.g., `192.168.x.x`) is not leaked to the proxy:

**Mitigation:** Configure `RTCPeerConnection` with `iceTransportPolicy: 'relay'` when available, forcing traffic through TURN servers. This hides both parties' IPs behind the TURN server, at the cost of slightly higher latency.

**Alternative:** Use mDNS ICE candidates (enabled by default in Chrome), which replace local IPs with random `.local` hostnames.

### 7.2 Broker as Single Point of Failure

The broker is a coordination point — if it goes down, new WebRTC connections cannot be established.

**Mitigation:**
- Multiple independent brokers (embedded list in WASM binary)
- Brokers behind different CDN providers (Cloudflare, Fastly)
- DNS-based broker discovery as fallback
- Cached proxy list for reconnection without broker

### 7.3 Malicious Proxies

A volunteer proxy could attempt to modify traffic or perform traffic analysis.

**Mitigation:**
- TLS is end-to-end between WASM client and guard relay — proxy cannot read or modify cell contents
- Proxy sees the same encrypted bytes as the current bridge (strictly less than a guard relay)
- Traffic analysis by proxy is no different than traffic analysis by any network hop
- If proxy drops/corrupts packets, TLS integrity check fails and circuit is torn down

### 7.4 Bridge B Key Compromise

If Bridge B's X25519 private key is compromised, the adversary can decrypt target addresses for all sessions.

**Mitigation:**
- Bridge B rotates its keypair periodically (monthly)
- Client embeds multiple Bridge B public keys (one per operator)
- Key rotation announced via broker, DNS TXT record, and WASM binary updates
- Forward secrecy: each session uses ephemeral client key `(e, E)`, so compromising `b` alone does not reveal past session keys if the adversary did not record the ephemeral public key `E`

### 7.5 Timing Correlation Across Bridge Hops

An adversary observing both Bridge A → Bridge B and Bridge B → Guard could correlate timing.

**Mitigation:**
- Traffic padding between Bridge A and Bridge B (same mechanism as Tor's padding)
- Bridge B batches/delays relay connections slightly (adds noise to timing)
- This is fundamentally the same timing correlation challenge as standard Tor — our design does not make it worse

---

## 8. Relevance to OTF Mission

### 8.1 Direct Impact on Internet Freedom

These innovations directly serve OTF's mission of supporting open, free, and secure internet access:

1. **Zero-installation on all sides:** Neither censored users nor volunteers need to install anything. This eliminates the single largest barrier to adoption in censored environments — the risk of downloading circumvention software.

2. **Community-powered infrastructure:** Every person in a free country can contribute to internet freedom by keeping a browser tab open. This creates a distributed, resilient network that grows organically and cannot be shut down by targeting individual servers.

3. **Provably stronger security:** The two-hop bridge blinding provides a formal guarantee (Theorem 2) that goes beyond any existing circumvention tool's trust model. No single entity can link censored users to their destinations.

4. **Resistance to all known blocking strategies:** The combination of ephemeral WebRTC proxies (uncatalogable IPs) and ECH-hidden infrastructure (indistinguishable from normal web traffic) creates a system that cannot be blocked without massive collateral damage to legitimate internet services.

### 8.2 Academic Contributions

The innovations described here represent publishable research:

- **Browser-native Snowflake:** First system where both client and proxy run entirely in the browser with zero installation
- **Two-hop bridge blinding:** Formal separation-of-knowledge guarantee for browser-based Tor transport
- **Combined architecture:** First anonymity system achieving 5-layer separation between user and destination with zero software installation

These results strengthen the existing PETS 2026 submission and could form the basis of a follow-up publication.

---

*This document accompanies the tor-wasm OTF Internet Freedom Fund application and PETS 2026 paper submission.*
