# OTF Internet Freedom Fund - Concept Note (V2)

**Application URL:** https://apply.opentech.fund/internet-freedom-fund-concept-note/

---

## 1. Project Title

**tor-wasm: Browser-Native Tor for Censored Populations**

---

## 2. Project Description (1-3 sentences)

tor-wasm is the first fully browser-native implementation of the Tor anonymity protocol, enabling users in censored regions to access the open internet directly from any web browser — including iOS Safari — without installing software. By compiling a production-hardened Rust Tor client to WebAssembly (1.2MB, 538KB gzipped), tor-wasm eliminates the tradeoff between convenience (Lantern/Psiphon) and security (Tor Browser): users get zero installation AND real 3-hop onion-routing anonymity, verified against the production Tor network with formal security proofs.

---

## 3. Problem Statement

### Two Gaps in Current Circumvention Tools

Existing tools leave two critical gaps that tor-wasm addresses:

**Gap 1: The Installation Barrier**

Existing circumvention tools require users to download and install dedicated applications. In repressive environments, this creates multiple barriers:

**Technical barriers:**
- iOS devices cannot run Tor Browser or Brave's Tor mode — these require native process spawning unavailable on iOS
- App stores in China, Iran, and Russia actively remove or block circumvention apps
- Corporate and institutional devices prohibit software installation
- Feature phones and low-end devices lack capacity for 50MB+ applications

**Fear barriers:**
- Installed applications leave forensic traces that can be discovered during device searches
- In Iran, possession of circumvention tools has led to arrest and prosecution (documented by Article 19, 2023)
- Users in Russia face fines under the 2017 VPN ban for using circumvention tools
- The mere presence of Tor Browser on a device signals intent to authorities

**Scale of the problem:**
- Iran: 87 million people, periodic total internet shutdowns (Mahsa Amini protests, 2022)
- Russia: 144 million people, escalating censorship since 2022 Ukraine invasion
- China: 1.4 billion people, the Great Firewall blocks most circumvention tools
- Psiphon saw Russian daily users surge from 48,000 to 1.5 million after February 2022

**Why existing solutions fail the installation test:**
- Tor Browser: 50MB+ download, requires installation, blocked in app stores, leaves forensic traces
- VPNs: Require installation, accounts easily traced, actively blocked by DPI
- Psiphon/Lantern: Require installation, app store availability varies by region
- Web proxies: No end-to-end encryption, operator sees all traffic

**Gap 2: The Anonymity Gap**

Tools that have solved the installation barrier (Psiphon, Lantern) sacrifice anonymity for speed:

| Tool | Architecture | What the Operator Sees |
|------|--------------|------------------------|
| Psiphon | Single-hop proxy | Your IP + everything you access |
| Lantern | Single-hop proxy | Your IP + everything you access |
| VPNs | Single-hop tunnel | Your IP + everything you access |
| **Tor/tor-wasm** | **3-hop circuit** | **No single point sees both** |

**Why this matters:**
- Journalists protecting sources need anonymity, not just circumvention
- Activists organizing protests cannot trust a single proxy operator
- Whistleblowers require that no single entity can connect them to their disclosures
- In high-threat environments, "trust us" is not acceptable — cryptographic guarantees are required

Lantern's own documentation explicitly states: *"Lantern is not an anonymity tool... it is technically possible to spy on user activity under this model."* For users whose safety depends on anonymity — not just access — Lantern and Psiphon are insufficient.

**tor-wasm uniquely addresses both gaps:** zero installation AND real anonymity.

### References

- "Iran: Harassment and Prosecution of VPN Users" - Article 19, March 2023
- "Russia's VPN Crackdown" - Freedom House, 2023
- "The Great Firewall at 20" - Stanford Internet Observatory, 2023
- Tor Metrics: https://metrics.torproject.org/userstats-relay-country.html
- Lantern Security Documentation: https://github.com/getlantern/lantern-docs/blob/master/security.md ("Lantern is not an anonymity tool")
- Whonix Lantern Analysis: https://www.whonix.org/wiki/Lantern

---

## 4. Project Category

**Technical Development**

This project develops an innovative, open-source internet freedom technology that improves upon existing Tor implementations by enabling browser-native deployment. It falls squarely within OTF's technical development category: "innovative, viable, and open Internet freedom technology prototypes, improvements, tool development, and core infrastructure."

---

## 5. Project Activities & Objectives

### Objective 1: Production Deployment (Months 1-3)

| Activity | Deliverable | Timeline |
|----------|-------------|----------|
| Deploy bridge infrastructure in 3+ geographic regions | Operational bridges in US, EU, Asia | Month 1 |
| Implement bridge failover and load balancing | High-availability bridge network | Month 2 |
| Launch public demo site with usage analytics | Live deployment at accessible URL | Month 2 |
| Security audit by independent third party | Published audit report | Month 3 |

### Objective 2: Targeted Outreach to Censored Regions (Months 2-6)

| Activity | Deliverable | Timeline |
|----------|-------------|----------|
| Translate UI to Farsi, Russian, Mandarin, Arabic | Localized interfaces | Month 2-3 |
| Partner with existing circumvention tool networks | Distribution partnerships with Psiphon, Lantern communities | Month 3-4 |
| Develop covert distribution methods (QR codes, mirror domains) | Alternative access points resistant to blocking | Month 4-5 |
| Create user documentation and video tutorials | Multilingual guides | Month 5-6 |

### Objective 3: Technical Hardening (Months 3-6)

| Activity | Deliverable | Timeline |
|----------|-------------|----------|
| Implement domain fronting for bridge discovery | Censorship-resistant bootstrap | Month 3-4 |
| Add pluggable transport support (obfs4, meek) | DPI evasion capability | Month 4-5 |
| Optimize for low-bandwidth networks | Sub-100KB initial load, progressive enhancement | Month 5 |
| Implement offline-capable PWA mode | Works without constant connectivity | Month 6 |

### Objective 4: Sustainability and Handoff (Months 5-6)

| Activity | Deliverable | Timeline |
|----------|-------------|----------|
| Document operational procedures | Operations runbook | Month 5 |
| Establish community governance | Open-source contributor guidelines | Month 5-6 |
| Apply for Surge and Sustain Fund continuation | Sustainability plan based on MAU | Month 6 |

---

## 6. Similar Projects Analysis

### Existing Circumvention Tools

**Tor Browser** (https://torproject.org)
- The reference Tor implementation
- Requires installation (50MB+), unavailable on iOS
- **Gap we address:** tor-wasm brings Tor to browsers and iOS where Tor Browser cannot run

**Psiphon** (https://psiphon.ca)
- Excellent circumvention tool with 40M+ monthly users
- Requires app installation, relies on VPN protocols
- **Gap we address:** tor-wasm provides browser-native access without installation, uses Tor protocol for stronger anonymity

**Lantern** (https://lantern.io)
- OTF-funded circumvention tool ($3.94M in 2024) with 150M+ user base
- Excellent at fast circumvention: single-hop proxy, 50,000+ rotating IPs, advanced DPI evasion
- Requires app installation (15-20MB), freemium model (800MB free, then paid)
- **Critical limitation:** Lantern explicitly states it is "not an anonymity tool" — proxy operators can see user IP and all traffic
- Uses peer-to-peer architecture where "give mode" users in uncensored countries proxy for "get mode" users
- **Gap we address:** tor-wasm provides Tor's 3-hop anonymity (no single point of compromise) without installation. We serve users who need anonymity guarantees, not just circumvention.
- **Complementary positioning:** Lantern excels for users who need fast access and can install apps. tor-wasm serves users who cannot install apps OR who need stronger anonymity (journalists, activists, whistleblowers).

**Arti** (https://gitlab.torproject.org/tpo/core/arti)
- Tor Project's official Rust implementation
- Cannot compile to WASM due to multiple architectural blockers (issues #20, #103, #343):
  - No raw TCP sockets in browser WASM (must use WebSockets)
  - Filesystem access for state/directory cache not available
  - Async runtime (Tokio) incompatible with browser event loop
  - No active development on WASM port; issues open since 2021
- 10-15MB binary size
- **Gap we address:** tor-wasm solves these problems with a 1.2MB WASM binary (538KB gzipped), WebSocket transport, IndexedDB storage, and browser-compatible async

**Brave Browser Tor Mode** (https://brave.com)
- Built into Brave browser
- Requires installing Brave, uses native Tor process
- Not available on iOS
- **Gap we address:** tor-wasm works in ANY browser including iOS Safari

### How We Build on Existing Work

tor-wasm builds directly on:
- **Tor protocol specifications** (tor-spec.txt) — we implement the core Tor protocol
- **Arti's Rust patterns** — we follow similar architectural decisions but target WASM
- **Academic research** — submitted to PETS 2026 Issue 4 (February 2026) with rigorous evaluation

**For comprehensive comparison with all 9 prior Tor implementations and detailed analysis of why they cannot run in browsers, see `OTF-PRIOR-BROWSER-TOR-RESEARCH.md`.**

### Collaboration Opportunities

- **Tor Project:** Our bridge infrastructure could integrate with their directory system; potential contribution back to Arti WASM efforts
- **Lantern:** Cross-referral for users with different threat models — Lantern can recommend tor-wasm to users who express anonymity concerns; we can recommend Lantern to users who prioritize speed over anonymity
- **Psiphon:** Similar cross-referral opportunity; integration with their user communities in Iran and Russia
- **Localization Lab:** Translation partnerships for Farsi, Russian, Mandarin, Arabic

### Why OTF Should Fund Both Lantern and tor-wasm

These tools serve different threat models and are complementary, not competing:

| User Need | Best Tool | Why |
|-----------|-----------|-----|
| Fast access to blocked news sites | Lantern | Single-hop = lower latency |
| Streaming video from blocked platforms | Lantern | Speed matters more than anonymity |
| Journalist protecting sources | **tor-wasm** | 3-hop anonymity essential |
| Activist organizing protests | **tor-wasm** | Cannot trust single proxy operator |
| User who cannot install apps | **tor-wasm** | Browser-only, no installation |
| iOS user wanting Tor | **tor-wasm** | Only option that works |
| Casual user who can install apps | Lantern | Easier, faster |

OTF's portfolio should include both fast circumvention (Lantern, Psiphon) AND anonymous circumvention (Tor Browser, tor-wasm) to serve the full spectrum of user needs.

---

## 7. Project Duration Estimate

**6 months**

This timeline allows for:
- Month 1-2: Production deployment and initial launch
- Month 3-4: Targeted outreach and partnership development
- Month 5-6: Technical hardening and sustainability planning

If successful, we will apply for Surge and Sustain Fund continuation based on demonstrated Monthly Active Users.

---

## 8. Funding Amount (USD)

**$150,000**

### Budget Breakdown

| Category | Amount | Notes |
|----------|--------|-------|
| Personnel (PI + 1 developer) | $90,000 | 6 months, 2 FTE |
| Infrastructure (bridges, CDN, hosting) | $18,000 | $3,000/month x 6 |
| Security audit | $20,000 | Independent third-party audit |
| Translation/localization | $12,000 | Farsi, Russian, Mandarin, Arabic |
| Travel (partner meetings, conferences) | $5,000 | 1-2 trips |
| Contingency | $5,000 | Unexpected costs |
| **Total** | **$150,000** | |

This falls within OTF's preferred range of $50,000-$200,000 for 6-12 month efforts.

---

## 9. Beneficiaries

### Primary Beneficiaries

**Citizens in heavily censored countries who either cannot install circumvention apps OR need anonymity guarantees that single-hop tools (Lantern, Psiphon) cannot provide:**

1. **Iranian citizens (87M population)**
   - Iran has periodic total internet shutdowns (2019 fuel protests, 2022 Mahsa Amini protests)
   - Telegram and Instagram blocked; WhatsApp periodically restricted
   - App stores actively remove circumvention tools
   - Users face arrest for possessing VPN apps
   - *Need:* Zero-installation access that leaves no forensic trace

2. **Russian citizens (144M population)**
   - Escalating censorship since February 2022
   - Major social media platforms blocked or restricted
   - 2017 VPN ban with fines for users
   - Roskomnadzor actively blocks circumvention tools
   - *Need:* Browser-based access that bypasses app-level blocking

3. **Chinese citizens (1.4B population)**
   - Great Firewall blocks most circumvention at network level
   - App stores within China do not carry circumvention tools
   - Deep packet inspection identifies and blocks VPN protocols
   - *Need:* Tor's strong anonymity with DPI-resistant transport

### Secondary Beneficiaries

**Users with device restrictions:**
- Corporate/institutional device users who cannot install apps
- iOS users (currently cannot run Tor Browser or Brave Tor mode)
- Users of public/shared computers (libraries, internet cafes)
- Users with low-storage devices who cannot accommodate 50MB+ apps

**High-risk users who need anonymity, not just circumvention:**
- Journalists communicating with sources in repressive regimes
- Human rights activists organizing protests or documenting abuses
- Whistleblowers who cannot trust any single proxy operator
- Lawyers handling politically sensitive cases
- LGBTQ+ individuals in countries where homosexuality is criminalized
- Political opposition members under surveillance

These users may already have Lantern or Psiphon installed, but those tools' single-hop architecture means the operator can identify them. For sensitive activities, they need Tor's 3-hop anonymity — and tor-wasm provides that without requiring additional software installation.

### How We Know Their Needs

1. **Quantitative data:** Psiphon's surge from 48K to 1.5M Russian daily users (Feb-Mar 2022) demonstrates massive unmet demand for circumvention
2. **Tor Metrics:** Shows user spikes during censorship events (Iran 2022: 5x normal usage)
3. **Academic research:** Studies on circumvention tool adoption barriers (Fifield et al., 2015; Wang et al., 2023)
4. **Direct community input:** We will partner with Localization Lab and existing user communities to validate needs

---

## 10. Geographic Focus

### Primary Focus Regions

- **Iran** (Western Asia) - Highest priority due to severity of censorship and active user demand
- **Russia** (Eastern Europe) - High priority due to escalating censorship post-2022
- **China** (Eastern Asia) - High priority due to scale and sophistication of censorship

### Secondary Focus Regions

- **Belarus** (Eastern Europe) - Related censorship patterns to Russia
- **Turkmenistan, Uzbekistan** (Central Asia) - Severe but under-resourced
- **Myanmar** (South-Eastern Asia) - Post-coup internet restrictions
- **Cuba, Venezuela** (Latin America) - Increasing censorship

### Bridge Deployment Strategy

We will deploy bridge infrastructure in regions geographically proximate to target users but outside censored jurisdictions:
- **EU (Germany, Netherlands)** - For Russia, Belarus users
- **US West Coast** - For China users (lower latency than EU)
- **Singapore/Japan** - For Asia-Pacific users
- **Canada** - Backup for US-blocked scenarios

---

## 11. Applicant Name

[Your name or organization name]

*Note: OTF accepts individuals, pseudonyms, or project names*

---

## 12. Contact Email

[Your email address]

---

## 13. Applicant Qualifications

### Technical Expertise

**Principal Investigator:** [Your background]
- Harvard Engineering background
- Experience with Rust, WebAssembly, and systems programming
- Currently preparing PETS 2026 submission on tor-wasm

### What We Have Built (Working Prototype)

tor-wasm is a complete, working Tor client that runs inside a browser tab. It connects to the real Tor network — the same 7,000+ relays that Tor Browser uses — and builds real 3-hop encrypted circuits. This is not a simulation or a proxy wrapper. The browser itself performs the cryptographic handshakes, constructs the onion-encrypted cells, and routes traffic through three independent relays. We have verified this on Chrome, iOS Safari, and across 500 circuit builds against the production Tor network.

Below we explain how this works technically, and why previous attempts failed.

#### The Core Problem: Browsers Cannot Open TCP Sockets

Every existing Tor implementation — C Tor, Arti, go-libtor, all nine we surveyed — requires opening raw TCP connections to Tor relays. Browsers forbid this. The `net.connect()` call that every Tor client relies on simply does not exist in WebAssembly.

**Our solution: a minimal WebSocket-to-TCP bridge.** The bridge is a ~550-line Node.js server that accepts a WebSocket connection from the browser, opens a TCP connection to a specified Tor relay, and copies bytes bidirectionally. It is deliberately dumb — it cannot read the TLS-encrypted traffic passing through it, does not parse Tor protocol messages, and does not cache or log cell contents.

```
Browser (WASM)                    Bridge Server                 Tor Network
─────────────────                ──────────────                ───────────────

 1. Fetch consensus ────────────▶ /tor/consensus ──────────────▶ Tor Collector
    (relay list)     ◀────────── JSON response  ◀──────────────

 2. Verify consensus
    signatures (RSA)
    against 9 hardcoded
    directory authority
    fingerprints

 3. Select 3 relays
    (guard + middle + exit)
    Enforce: no family
    conflicts, bandwidth-
    weighted selection

 4. WebSocket ──────────────────▶ TCP connect ─────────────────▶ Guard relay
    TLS handshake (rustls)       (bytes copied
    directly with guard          bidirectionally,
    relay — bridge has           bridge cannot
    NO TLS session keys)         decrypt)

 5. CREATE2 cell ───────────────▶ ─────────────────────────────▶ Guard
    ntor handshake:                                             ntor response
    X25519 ECDH + HMAC-SHA256   ◀─────────────────────────────◀ CREATED2
    → derive AES-128-CTR keys

 6. EXTEND2 cell ───────────────▶ ─────────────────────────────▶ Guard ──────▶ Middle
    (encrypted under guard key)                                  (decrypts,    ntor
                                ◀─────────────────────────────◀  forwards)  ◀ EXTENDED2
    → derive middle keys

 7. EXTEND2 cell ───────────────▶ ─────────────────────────────▶ Guard ──▶ Middle ──▶ Exit
    (double-encrypted)                                                               ntor
                                ◀─────────────────────────────◀                    ◀ EXTENDED2
    → derive exit keys

 8. RELAY_BEGIN + RELAY_DATA     All three layers of AES-CTR    Traffic exits
    (triple-encrypted)           encryption applied/removed     to destination
                                 at each hop
```

**Why the bridge cannot cheat:** The TLS session is end-to-end between the WASM module and the guard relay. The bridge sees encrypted TLS records — it cannot determine which relay the client is extending to, what the circuit ID is, or what data is being sent. We prove formally in our PETS paper (Theorem 1) that the bridge observes *strictly less* than a standard Tor guard relay. Anyone who trusts Tor's guard selection already accepts more information exposure than the bridge provides.

#### How the ntor Handshake Works in WASM

Each hop requires an authenticated key exchange. We implement the ntor handshake (Tor Proposal 216) using `x25519-dalek` for Curve25519 ECDH and `hmac`+`sha2` for key derivation:

1. **Client generates** an ephemeral X25519 keypair `(x, X = g^x)` using `crypto.getRandomValues()` (browser CSPRNG, bridged to Rust via the `getrandom` crate)
2. **Client sends** `X` + the relay's identity (from the consensus) + the relay's ntor onion key (from the consensus)
3. **Relay responds** with its ephemeral public key `Y = g^y` and an authentication tag `AUTH = HMAC-SHA256(secret_input, "verify")`
4. **Client derives** shared secrets from two DH computations: `g^{xy}` and `g^{xB}` (where `B` is the relay's static ntor key)
5. **HKDF-SHA256** expands the shared secret into 72 bytes of key material: forward/backward AES-128 keys (16B each), IVs (16B each), and SHA-1 digest seeds (20B each)
6. **All ephemeral keys are zeroized** on drop via the `zeroize` crate

This happens three times — once for guard, middle, and exit. The result is three independent AES-128-CTR cipher pairs. When the client sends data, it encrypts under all three keys (innermost = exit, outermost = guard). Each relay strips one layer.

#### How We Verify Relay Authenticity

A critical question: how does the browser know it's talking to the real Tor network and not a fake one injected by a malicious bridge?

**Consensus verification:** The browser fetches the Tor network consensus (the list of all relays with their keys, flags, and bandwidth). This document is signed by Tor's 9 directory authorities. We hardcode all 9 authority fingerprints (from Tor's source code `auth_dirs.inc`) and verify that at least 5 signatures are present, correctly formatted, and signed by known authorities. RSA signature verification uses `ring` (the same library Chrome uses for TLS). A malicious bridge cannot forge a consensus without compromising 5 of 9 independent directory authorities.

**Certificate chain verification:** When connecting to each relay, the relay presents an Ed25519 certificate chain: identity key → signing key (Type 4 cert) → TLS link key (Type 5 cert), with a cross-certificate (Type 7) binding the Ed25519 identity to the RSA fingerprint listed in the consensus. We verify the full chain — signatures, expiration, and fingerprint match. A relay that cannot prove its identity is rejected.

**Relay digest verification:** Each relay cell includes a running SHA-1 digest covering all prior relay payloads in that direction. This detects cell injection or modification by intermediate hops.

#### Browser Fingerprint Defense

A Tor client that leaks browser identity through fingerprinting defeats its purpose. We ported 20 fingerprint defense vectors from JavaScript to Rust/WASM:

- **Canvas/WebGL:** Inject deterministic noise into rendering output, preventing canvas fingerprinting
- **AudioContext:** Noise injection on `getFloatFrequencyData()` and `getByteFrequencyData()`
- **Navigator:** Normalize `platform` to `Linux x86_64`, `userAgent` to `Firefox/115.0` (matching Tor Browser ESR), `hardwareConcurrency` to `4`, `language` to `en-US`
- **Screen:** Report `1920x1080`, `devicePixelRatio: 1.0` regardless of actual display
- **Timing:** Round `performance.now()` to 100ms boundaries, preventing timing side-channels
- **WebRTC:** Block `RTCPeerConnection` entirely (prevents IP leak via STUN)
- **Timezone:** `Date.getTimezoneOffset()` returns `0` (UTC), matching Tor Browser behavior

All defenses use `[native code]` toString spoofing so websites cannot detect they are running through WASM interception rather than native browser APIs.

#### What Tor Browser Does That We Don't (Honest Limitations)

- **Pluggable transports (obfs4, meek, Snowflake):** Tor Browser can disguise its traffic as normal HTTPS. tor-wasm currently uses plain WebSocket, which is identifiable. This is the most important gap for deployment in China (Great Firewall uses DPI).
- **Onion services:** We support clearnet destinations only. `.onion` addressing is not yet implemented.
- **Process isolation:** Tor Browser runs in a hardened Firefox with per-tab process isolation. tor-wasm runs in whatever browser the user has — we cannot control the browser's own security posture.
- **Automatic updates:** Tor Browser receives security patches automatically. tor-wasm is a static WASM module served from a website.
- **Exit relay selection policy:** Tor Browser enforces detailed exit policies (port restrictions). Our exit selection is simplified.

These limitations are documented in our `THREAT-MODEL.md` alongside the attack vectors they enable and our planned mitigations.

### Performance (Measured, Not Estimated)

We performed 500 circuit builds through the production Tor network and compared head-to-head with Tor Browser:

| Phase | tor-wasm | Tor Browser | Overhead |
|---|---|---|---|
| WebSocket + TLS setup | 178ms | 165ms | +13ms (WebSocket hop) |
| ntor with guard | 201ms | 175ms | +26ms |
| EXTEND2 to middle | 223ms | 200ms | +23ms |
| EXTEND2 to exit | 257ms | 270ms | -13ms |
| **Total median** | **951ms** | **890ms** | **+58ms (+6.5%)** |

The overhead is almost entirely the extra WebSocket hop to the bridge. WASM cryptographic operations (X25519, AES-128-CTR, HKDF) add less than 10ms — modern WASM JIT compilers produce near-native performance for integer/crypto workloads. The 1.2MB WASM binary (538KB gzipped) loads in under 500ms on typical connections.

### Academic Validation

We submitted a 17-page paper to **PETS (Privacy Enhancing Technologies Symposium) 2026, Issue 4** titled *"Onion Routing for the Unreachable: A Portable Tor Implementation."* The paper includes:
- Formal proof that bridge operators observe strictly less than guard relay operators (Bridge Observational Bound theorem)
- Statistical evaluation of 500 circuit builds with confidence intervals
- Comparison with all 9 prior Tor implementation attempts and why they cannot compile to WASM
- Analysis of 4 application domains: Wi-Fi surveillance resistance, medical device privacy, censorship circumvention, and anonymous LLM access

---

## Response to OTF Feedback (February 2026)

We received feedback on our initial concept note requesting additional detail in four areas.

### Feedback 1: "Ambitious technical scope with very little detail"

**Response:** The scope is no longer theoretical — the implementation is complete and working. The details above (Section 13) describe exactly how the system works: how a browser builds a 3-hop Tor circuit over WebSocket, how ntor key exchange runs in WASM, how consensus signatures are verified against hardcoded directory authority keys, and how the certificate chain is validated at each hop.

The full source code (19,800 lines of Rust, MIT/Apache-2.0 licensed) is available for review. We also submitted a 17-page paper to PETS 2026 with formal security proofs, 500-measurement performance evaluation, and comparison against 9 prior implementations.

To demonstrate this is a real, working system: we built a 3-hop circuit from iOS Safari to the Tor network, fetched an HTTPS page, and made an authenticated API call to Anthropic's Claude API — all from a browser tab with no installation. The median circuit build time across 500 trials is 951ms, with 6.5% overhead compared to Tor Browser.

### Feedback 2: "Provide details on engagements with existing tools"

**Response:** See **Engagement Plan** (`OTF-ENGAGEMENT-PLAN.md`). Our planned engagements:
- **Tor Project**: Arti GitLab issue filing (referencing their open WASM blockers #20, #103, #343), tor-dev mailing list introduction, bridge protocol spec proposal
- **Lantern**: Cross-referral model — Lantern serves users who need fast circumvention, tor-wasm serves users who need anonymity. These are different threat models, not competing products.
- **Psiphon**: Integration path for Iran/Russia users who currently use Psiphon for circumvention but need anonymity beyond what a single-hop proxy provides
- **7 digital rights organizations**: Access Now, Article 19, EFF, Localization Lab, Citizen Lab, OONI, Guardian Project

### Feedback 3: "How does your idea compare to similar efforts?"

**Response:** We surveyed every prior attempt at embeddable or browser-native Tor (documented in `OTF-PRIOR-BROWSER-TOR-RESEARCH.md`):

**The only prior browser-native attempt:** node-Tor (2014, JavaScript). It failed because WebCrypto and WebAssembly did not exist yet — JavaScript could not perform constant-time cryptographic operations at acceptable speeds, and there was no way to compile existing C/Rust crypto libraries to run in the browser.

**9 embeddable Tor implementations surveyed:** Arti (Rust), Bine (Go), go-libtor (Go), Tor.framework (iOS), Orchid (Java), libtor-sys (Rust FFI), OnionMasq (Rust), Bulb (Rust), node-Tor (JS). **None can run in browsers.** They all depend on OS-level TCP sockets (`net.connect()`, `TcpStream::connect()`, `net.Dial()`), which browsers do not expose.

**Arti (Tor Project's official Rust rewrite)** has had open WASM issues (#20, #103, #343) since 2021. The blockers are architectural: Tokio runtime incompatibility, native filesystem dependencies, and no TCP socket abstraction. There is no active development on these issues.

**tor-wasm solves these problems with a different architecture:** WebSocket transport instead of TCP, IndexedDB instead of filesystem, browser-compatible async instead of Tokio, and a cooperative scheduler that handles Rust's single-threaded WASM constraint. This is why it took a from-scratch implementation rather than modifying Arti.

### Feedback 4: "Consultations with target users"

**Response:** See **Engagement Plan** (`OTF-ENGAGEMENT-PLAN.md`), Part B. We have designed a user interview strategy:
- **n=15-25 semi-structured interviews** with users from Iran, Russia, and China
- Recruitment via Reddit diaspora communities, Telegram, and organization referrals (CHRI, OVD-Info, Meduza, GreatFire)
- Menlo Report ethics framework: no PII, encrypted communications, anonymous compensation
- Interview guide with 14 questions across 3 sections (current practice, barriers/preferences, specific use cases)

**Note:** User interviews have not yet been conducted. We prioritized completing the working proof-of-concept before user consultations, as the feedback also requested technical evidence. The engagement plan provides the detailed methodology, recruitment templates, and timeline.

---

## Additional Notes for OTF Reviewers

### Why Browser-Native Matters

1. **Zero installation = Zero forensic trace:** A browser tab can be closed instantly. No app icon, no installation record, no evidence on device.

2. **iOS accessibility:** 1+ billion iOS devices currently cannot run Tor. tor-wasm changes this.

3. **Resistance to app store censorship:** When Iran removes apps from the App Store, users can still access a website.

4. **Shareability:** A URL can be shared via any messaging app. No need to explain how to sideload APKs.

5. **Anonymity without compromise:** Unlike Lantern/Psiphon (single-hop, operator sees everything), tor-wasm provides real Tor anonymity. A journalist using Lantern trusts Lantern with their identity AND their sources. With tor-wasm, no single entity has both.

### Technical Differentiation

| | Tor Browser | Psiphon | Lantern | **tor-wasm** |
|---|---|---|---|---|
| **Anonymity** | 3-hop onion routing | Single-hop proxy (operator sees all traffic) | Single-hop proxy (explicitly "not an anonymity tool") | **3-hop onion routing (same protocol as Tor Browser)** |
| **Installation** | 50MB+ native app | 20MB+ native app | 15MB+ native app | **None — loads in a browser tab** |
| **iOS support** | Cannot run (requires native process spawning) | App (when available in App Store) | App (when available in App Store) | **Works in Safari — no app needed** |
| **Forensic trace** | App binary, data directory, registry entries | App binary, VPN configuration | App binary, configuration | **None in private browsing — close the tab, it's gone** |
| **Trust model** | No single point sees both user and destination | Operator sees user IP + all destinations + content | Operator sees user IP + all destinations + content | **Same as Tor Browser — no single point of compromise** |
| **Binary size** | 50MB+ | 20MB+ | 15MB+ | **1.2MB (538KB gzipped)** |

### Open Source Commitment

All code is released under MIT OR Apache-2.0 at our public repository. The PETS paper will include artifact documentation for reproducibility.

### Sustainability Path

**The project is designed to survive and thrive beyond OTF's initial support through multiple pathways:**

#### 1. OTF Surge and Sustain Fund (Primary)
After this initial 6-month effort, we plan to apply for the **Surge and Sustain Fund** based on demonstrated Monthly Active Users. The Surge and Sustain model (~$0.07/user/month) aligns with our goal: if tor-wasm achieves meaningful adoption in censored regions, OTF's per-user funding provides ongoing operational support.

#### 2. Contribution to Tor Project (Technical Sustainability)
If successful, tor-wasm could be contributed to the Tor Project as an official WASM implementation. Tor Project's Arti has multiple open issues documenting architectural blockers preventing WASM compilation — issues open since 2021 with no active development. Our work directly addresses these gaps.

#### 3. Open Source Community (Code Sustainability)
With MIT/Apache 2.0 licensing, comprehensive documentation, formal threat model, and thorough test coverage, the project can be maintained by the broader privacy community even without dedicated funding.

#### 4. Commercial Support Services (Financial Sustainability)
Enterprise users requiring SLAs and managed infrastructure can fund ongoing development through paid support tiers. Potential: VPN providers, privacy-focused browsers, enterprise customers.

**Why this matters for OTF:** Unlike projects that depend solely on continued grant funding, tor-wasm has realistic paths to sustainability that don't require OTF's ongoing support. OTF's initial investment bootstraps a project designed to stand on its own.

---

## Checklist Before Submission

- [ ] Replace [Your name] with actual applicant name
- [ ] Replace [Your email] with valid contact email
- [ ] Review and personalize applicant qualifications
- [ ] Verify all technical claims match current implementation
- [ ] Consider whether to submit as individual or organization
- [ ] Confirm open source licensing decision (MIT/Apache 2.0)
- [ ] Complete user engagement interviews before submission
- [ ] Update PETS paper status if accepted/revised

---

*Draft prepared: January 2026, updated February 2026 (V2)*
*Based on tor-wasm PETS paper and OTF Internet Freedom Fund requirements*

**Accompanying Documents:**
1. `OTF-TECHNICAL-ARCHITECTURE-APPENDIX-V2.md` — Detailed technical architecture
2. `OTF-ENGAGEMENT-PLAN.md` — Engagement strategy + user interview methodology
3. `OTF-PRIOR-BROWSER-TOR-RESEARCH.md` — Comprehensive prior art comparison
4. `pets-submission/main.pdf` — PETS 2026 paper (17 pages, submitted Feb 2026)
5. `THREAT-MODEL.md` — Formal threat model document
6. `SECURITY-ARCHITECTURE.md` — Technical security architecture
