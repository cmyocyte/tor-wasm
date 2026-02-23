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
- **Single bridge:** Current implementation uses one bridge per circuit (bridge diversity planned)
- **No pluggable transports:** Bridge connections are identifiable as WebSocket traffic (obfs4 integration planned)
- **No onion services:** Only clearnet destinations supported currently
- **Browser fingerprinting:** tor-wasm does not modify browser fingerprint (unlike Tor Browser)

## Cryptographic Dependencies

| Crate | Version | Purpose | Audit Status |
|-------|---------|---------|-------------|
| `ring` | 0.17 | Core crypto (AES, SHA, ECDH) | Google-maintained, widely audited |
| `rustls` | 0.23 | TLS implementation | OSTIF/Cure53 audit (2020) |
| `x25519-dalek` | 2.0 | X25519 key exchange | dalek-cryptography audited |
| `curve25519-dalek` | 4.0 | Curve25519 operations | NCC Group audit (2019) |
| `sha2` | 0.10 | SHA-256 | RustCrypto, widely used |
| `aes` | 0.8 | AES block cipher | RustCrypto, constant-time |

## Scope

This security policy covers:
- The Rust WASM module (`src/`)
- The bridge server (`bridge-server/`)
- The tor-core library (`tor-core/`)

It does not cover:
- Example HTML files (for demonstration only)
- Development tooling
