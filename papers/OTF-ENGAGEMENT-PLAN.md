# tor-wasm: Engagement Plan & User Consultation Strategy

**Prepared for:** Open Technology Fund Internet Freedom Fund Application
**Date:** February 2026

---

## Part A: Engagements with Existing Tools and Organizations

### 1. The Tor Project

**Relationship:** tor-wasm is built to interoperate with the existing Tor network. We use the same relays, the same protocol, and the same cryptographic handshakes as Tor Browser and Arti. Our bridge architecture is designed so existing Tor relay operators can run bridges alongside their relays with minimal effort.

**Planned Engagements:**

| Action | Timeline | Contact |
|---|---|---|
| File consolidated issue on Arti GitLab sharing solutions to all 5 WASM blockers (#339-#343) | Week 1 | gitlab.torproject.org/tpo/core/arti/-/issues |
| Post project introduction to tor-dev mailing list | Week 1 | lists.torproject.org/cgi-bin/mailman/listinfo/tor-dev |
| Share PETS paper draft for security review | Week 2 | Email to Tor research team |
| Propose WebSocket bridge specification | Month 2 | tor-dev mailing list |
| Discuss bridge distribution integration (BridgeDB/Lox) | Month 2 | Tor anti-censorship team |

**Specific Arti WASM blockers we've solved:** In February 2022, Nick Mathewson filed 5 sub-issues under [#103 "Port Arti to WASM"](https://gitlab.torproject.org/tpo/core/arti/-/issues/103) (estimated 80 hours). As of February 2026, all 5 remain open with 0/5 completed:

| Arti Issue | Problem | tor-wasm Solution |
|---|---|---|
| [#339](https://gitlab.torproject.org/tpo/core/arti/-/issues/339) StateMgr | No filesystem in WASM | IndexedDB + localStorage for guard persistence |
| [#340](https://gitlab.torproject.org/tpo/core/arti/-/issues/340) dirmgr/SQLite | SQLite (C lib) can't compile to WASM | Bridge fetches consensus, serves over WebSocket; client verifies signatures |
| [#341](https://gitlab.torproject.org/tpo/core/arti/-/issues/341) Compression | C bindings for zstd/xz2 | Eliminated (bridge decompresses); pure-Rust fallbacks available |
| [#342](https://gitlab.torproject.org/tpo/core/arti/-/issues/342) Runtime | No tokio/async-std in browser | Cooperative scheduler with checkout/return pattern, `futures` only |
| [#343](https://gitlab.torproject.org/tpo/core/arti/-/issues/343) TCP sockets | Browsers forbid raw TCP | WebSocket-to-TCP bridge (~100 lines, protocol-unaware, formally proven less visibility than guard) |

**See `ARTI-WASM-SOLUTIONS.md` for:** detailed solution descriptions, draft GitLab issue text ready to post, mailing list engagement plan, and tone guidelines.

**Technical alignment:** tor-wasm implements Tor's ntor handshake (Proposal 216), channel padding (padding-spec.txt), congestion control (Proposal 324), and guard persistence model. We will adopt CGO encryption (Proposal 308/359) when the network mandates it.

**Why this matters for both projects:** Arti serves desktop/mobile embedding (300,000 lines, full protocol). tor-wasm serves browsers and sandboxed environments (17,000 lines, client-only). These are complementary — our solutions to #339-#343 could inform Arti's approach if WASM is eventually prioritized, and we benefit from Arti's protocol expertise and security review.

---

### 2. Lantern

**What Lantern does:** Fast, reliable internet access tool used by millions. Explicitly states it is "not an anonymity tool" — prioritizes speed over privacy.

**Complementary relationship:** Lantern and tor-wasm serve different needs on the same spectrum. Users who need speed use Lantern; users who need anonymity use tor-wasm. There is no competitive overlap.

**Planned Engagement:**

| Action | Timeline | Contact |
|---|---|---|
| Email introducing tor-wasm, propose cross-referral | Week 2 | team@getlantern.org |
| Discuss user research collaboration | Week 3 | Via introduction |
| Explore technical integration (Lantern as fallback transport) | Month 2 | Technical team |

**Referral model:** When users need anonymity (not just circumvention), Lantern could recommend tor-wasm. When users need speed, tor-wasm documentation could recommend Lantern. Both tools benefit from clear positioning.

---

### 3. Psiphon

**What Psiphon does:** Censorship circumvention tool with massive scale (millions of daily users in Iran, China, Russia). Like Lantern, focuses on access rather than anonymity.

**Complementary relationship:** Psiphon has deep deployment experience in exactly the regions tor-wasm targets. Their user base includes people who need anonymity but settle for circumvention because Tor is too difficult to install.

**Planned Engagement:**

| Action | Timeline | Contact |
|---|---|---|
| Email introducing tor-wasm as anonymity complement | Week 2 | info@psiphon.ca |
| Request anonymized user research data on anonymity needs | Week 3 | Via introduction |
| Discuss potential integration (Psiphon transport + tor-wasm anonymity) | Month 2 | Technical team |

**Context:** Psiphon saw its Russian user base surge from 48K to 1.5M during the 2022 invasion of Ukraine. Many of these users need anonymity (whistleblowers, journalists, activists) but use Psiphon because it's available and easy. tor-wasm could provide the anonymity layer.

---

### 4. Snowflake (Tor Project)

**What Snowflake does:** Enables browsers to donate bandwidth as Tor bridges via WebRTC proxies. Browsers running Snowflake help censored users reach the Tor network.

**Complementary relationship:** Snowflake lets browsers help others connect to Tor. tor-wasm lets browsers use Tor directly. These are opposite sides of the same coin — a user could run both.

**Planned Engagement:**

| Action | Timeline | Contact |
|---|---|---|
| Discuss complementary architecture on tor-dev | Week 2 | tor-dev mailing list |
| Explore Snowflake-bridge integration | Month 2 | Snowflake maintainers |

---

### 5. Digital Rights Organizations

| Organization | Focus | Engagement Purpose | Contact |
|---|---|---|---|
| **Access Now** | Digital security helpline | User referrals for testing, threat model feedback | accessnow.org/help |
| **Article 19** | Freedom of expression | Policy context for medical device privacy | article19.org |
| **EFF** | Digital civil liberties | Legal/policy review of dual-use considerations | eff.org/about/contact |
| **Localization Lab** | Tool translation | Future localization of tor-wasm documentation | localizationlab.org |
| **Citizen Lab** | Internet censorship research | Censorship measurement collaboration | citizenlab.ca |
| **OONI** | Open Observatory of Network Interference | Bridge reachability testing in censored regions | ooni.org |
| **Guardian Project** | Mobile security tools | Android/iOS WebView deployment testing | guardianproject.info |

---

### 6. Medical Device Stakeholders

tor-wasm's 72KB minimal core targets medical device telemetry privacy — a novel application domain.

| Stakeholder | Engagement Purpose | Timeline |
|---|---|---|
| **FDA CDRH** | Pre-submission feedback on Tor integration for cybersecurity guidance compliance | Month 3 |
| **AAMI** | Technical committee input on TIR57 risk management for anonymization | Month 3 |
| **Medical device manufacturers** (via MDCG) | Pilot testing on ARM Cortex-A7+ embedded platforms | Month 4 |
| **Patient advocacy groups** | Input on telemetry privacy needs and trust requirements | Month 2 |

---

## Part B: User Interview Strategy

### Target Demographics

We plan to conduct **n=15-25 semi-structured interviews** with users from censored regions who have firsthand experience with circumvention tools.

| Region | Target n | Recruitment Channel | Key Questions |
|---|---|---|---|
| **Iran** | 5-8 | Reddit (r/iran, r/NewIran), Telegram diaspora groups, CHRI referrals | VPN blocking experience, Tor adoption barriers, "browser tab vs app install" preference |
| **Russia** | 5-8 | Reddit (r/liberta), Telegram, Meduza reader community, OVD-Info referrals | Post-2022 circumvention changes, forensic trace concerns, VPN vs Tor trust |
| **China** | 3-5 | Reddit (r/China), Signal groups, GreatFire.org referrals | GFW detection techniques, tool switching behavior, mobile-first needs |
| **General** | 2-4 | EFF mailing list, Tor community, privacy-focused forums | Journalist/activist use cases, medical privacy concerns |

### Interview Protocol

**Format:** 30-minute semi-structured interviews via Signal (voice or text, participant's choice)

**Ethics Framework:** Menlo Report principles
- **Informed consent:** Written consent form explaining purpose, risks, data handling
- **No PII collection:** No names, locations, or identifying information recorded
- **Participant safety:** No questions about specific activities; focus on tool preferences and barriers
- **Data handling:** Transcripts anonymized immediately, stored encrypted, deleted after analysis
- **Right to withdraw:** Participants can withdraw at any time with no consequences

**Compensation:** $25-50 anonymous compensation via cryptocurrency or gift card (participant's choice)

### Interview Guide

**Section 1: Current Circumvention Practice (10 minutes)**

1. What tools do you currently use to access blocked content? (Probe: VPN, Tor, Psiphon, Lantern, Shadowsocks, custom solutions)
2. How did you first learn about these tools? Who taught you?
3. What do you like about your current tools? What frustrates you?
4. Have you ever tried Tor? If yes, what was your experience? If no, why not?
5. How worried are you about your internet provider seeing what tools you use?

**Section 2: Barriers and Preferences (10 minutes)**

6. If you could access Tor anonymity from a regular browser tab — no download, no installation — would that change your willingness to use it? Why or why not?
7. How important is it that a tool leaves no trace on your device? (Probe: device seizure scenarios, shared computers)
8. Would you trust a tool that works through a "bridge" server run by volunteers? What would you need to know about the bridge operator?
9. How much latency (delay) would you accept for anonymous access? (Probe: 1 second? 5 seconds? 30 seconds?)
10. Do you prefer tools that anonymize everything or tools that let you choose which activities to anonymize?

**Section 3: Specific Use Cases (10 minutes)**

11. What specific activities would you use anonymous browsing for? (Probe: news, social media, communication, research, financial)
12. Have you ever needed to access an AI chatbot (ChatGPT, Claude) anonymously? Would that be valuable?
13. Do you use any health monitoring devices that connect to the internet? How concerned are you about that health data being linked to your identity?
14. Is there anything else about your privacy and circumvention needs that we haven't discussed?

### Recruitment Templates

**Reddit Post (for r/iran, r/NewIran, r/liberta, r/China):**

> **Research participants needed: Internet privacy tools study**
>
> We are researchers developing new privacy tools for people in censored regions. We're looking for people with experience using VPNs, Tor, or other circumvention tools to participate in a 30-minute interview via Signal.
>
> - Completely anonymous — no names or identifying information collected
> - $25-50 compensation (cryptocurrency or gift card)
> - Your input directly shapes tool design for people in your situation
>
> If interested, send a Signal message to [Signal number] with the word "INTERVIEW"
>
> This research follows Menlo Report ethical principles. IRB protocol [number] at [institution].

**Organization Referral Email (for CHRI, OVD-Info, Meduza, GreatFire):**

> Subject: Research collaboration — user needs for browser-based Tor access
>
> Dear [Name],
>
> We are developing tor-wasm, a browser-native Tor implementation that enables anonymous internet access without installing any software. This is particularly relevant for users in [Iran/Russia/China] who face both censorship and surveillance.
>
> We are conducting user interviews (n=15-25) with people from censored regions to understand:
> - Current circumvention tool preferences and barriers
> - Whether browser-based Tor access would address unmet needs
> - Trust requirements for bridge-based architectures
>
> Would your organization be willing to help us reach potential interview participants through your networks? We follow Menlo Report ethical principles — no PII collection, anonymous compensation, encrypted communications only.
>
> Our technical work is documented in a forthcoming PETS 2026 paper. I'd be happy to share the draft for your review.
>
> Best regards,
> [Name]

### Analysis Plan

1. **Transcription:** Anonymized notes during interview (no audio recording unless participant consents)
2. **Coding:** Thematic analysis using open coding → axial coding → selective coding
3. **Key themes to extract:**
   - Barrier categories (technical, trust, awareness, legal)
   - Preference rankings (speed vs. anonymity vs. ease of use)
   - Browser-native value proposition validation or rejection
   - Bridge trust model acceptance or concerns
4. **Reporting:** Anonymized findings with direct quotes (with consent), no demographic detail beyond region
5. **Timeline:**

| Phase | Timeline | Deliverable |
|---|---|---|
| Recruitment | Weeks 1-2 | 15-25 confirmed participants |
| Interviews | Weeks 3-4 | Anonymized transcripts |
| Analysis | Week 5 | Coded themes and findings |
| Report | Week 6 | User needs report for OTF and PETS camera-ready |

### Expected Outcomes

Based on preliminary conversations and existing research (Psiphon/Lantern user surveys, Tor Project usability studies), we hypothesize:

1. **Installation barrier is real:** Users in censored regions avoid Tor specifically because downloading it signals intent to authorities
2. **Browser-native is valued:** The ability to use Tor from a regular browser tab, leaving no forensic trace, addresses a real unmet need
3. **Speed vs. anonymity tradeoff:** Users will accept 1-3 second latency for anonymous access to specific sensitive operations, but not for general browsing
4. **Bridge trust concern exists but is manageable:** Users will express concern about bridge operators, but the "less than guard" security guarantee may alleviate this
5. **Medical privacy is underserved:** Health device users are largely unaware of metadata exposure risks

These hypotheses will be tested and refined through the interview data.

---

*This engagement plan accompanies our OTF Internet Freedom Fund application for tor-wasm. Planned engagements are concrete and actionable — several can begin immediately upon funding confirmation.*
