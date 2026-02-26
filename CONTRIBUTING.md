# Contributing to tor-wasm

Thank you for your interest in contributing to tor-wasm! This project aims to bring Tor anonymity to web browsers through WebAssembly.

## Getting Started

### Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Rust | stable 1.75+ | [rustup.rs](https://rustup.rs/) |
| wasm-pack | 0.12+ | `cargo install wasm-pack` |
| Node.js | 18+ | [nodejs.org](https://nodejs.org/) |
| wasm32 target | — | `rustup target add wasm32-unknown-unknown` |

### Building

```bash
# Build WASM module
wasm-pack build --target web --release

# Run bridge server
cd bridge-server
npm install
node server-collector.js
```

### Testing

```bash
# Run Rust unit tests (no browser required)
cargo test

# Run WASM tests in headless browser
wasm-pack test --headless --chrome

# Check formatting + lints
cargo fmt --check
cargo clippy --lib -- -D warnings

# Compile check (works without WASM target)
cargo check --lib
```

### Troubleshooting

**`wasm-pack build` fails with "error[E0463]: can't find crate"**
Ensure the wasm32 target is installed: `rustup target add wasm32-unknown-unknown`

**`ring` fails to compile for WASM**
Ensure you're using `ring` 0.17+ with the `wasm32_unknown_unknown_js` feature (already configured in Cargo.toml).

**Bridge server can't reach Tor directory authorities**
Some networks block direct connections to Tor infrastructure. The `server-collector.js` falls back to the Tor Collector HTTPS mirror. If all fail, check your network/firewall.

**WASM module too large (> 2MB)**
Ensure you're building with `--release`. The release profile uses `opt-level = "z"` and LTO for size optimization. Expected size: ~1.2MB uncompressed, ~543KB gzipped.

**`cargo test` fails with linker errors**
Some integration tests require browser APIs not available in native test runners. Use `cargo test --lib` to run only unit tests, or `wasm-pack test --headless --chrome` for full WASM tests.

## How to Contribute

### Bug Reports

Open an issue with:
- Steps to reproduce
- Expected vs. actual behavior
- Browser and OS version
- Bridge server logs (if relevant)

### Code Contributions

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make your changes
4. Run `cargo fmt` and `cargo clippy --lib`
5. Ensure tests pass (`cargo test --lib`)
6. Submit a pull request

PRs are typically reviewed within 1 week. For large changes, please open an issue first to discuss the approach.

### Security Issues

See [SECURITY.md](SECURITY.md) for responsible disclosure guidelines. **Do not open public issues for security vulnerabilities.**

## Code Style

- Follow standard Rust formatting (`cargo fmt`)
- Run `cargo clippy` before submitting
- No custom cryptographic implementations — use audited crates only
- All key material must use `zeroize` for cleanup
- Use `subtle::ConstantTimeEq` for security-critical comparisons
- Prefer `log::debug!` / `log::info!` over `println!` — output goes to browser console

## CI Pipeline

Every push and PR runs automated checks via GitHub Actions:
- `cargo fmt --check` — formatting
- `cargo clippy --lib` — linting
- `cargo check --lib` — compilation
- `wasm-pack build --target web --release` — WASM build
- Node.js syntax checks for bridge-server and broker

## Architecture

```
tor-wasm-public/
├── src/                  # Rust WASM module (~20,900 lines)
│   ├── lib.rs            # TorClient — main API + WASM bindings
│   ├── protocol/         # Tor protocol (ntor, cells, circuits, consensus)
│   ├── transport/        # WebSocket + WebTunnel + meek + WebRTC + bridge blinding
│   ├── cooperative/      # Browser-compatible async scheduler (no tokio)
│   ├── storage/          # IndexedDB/localStorage persistence
│   ├── runtime/          # WASM runtime compatibility layer
│   ├── fingerprint_defense/ # 20-vector browser fingerprint defense
│   ├── crypto/           # Protocol-level crypto helpers
│   └── network/          # TLS, connection management
├── bridge-server/        # Bridge servers (Node.js)
│   ├── server-collector.js  # Production server (consensus + relay)
│   ├── server-bridge-a.js   # Blinded mode: client-facing
│   ├── server-bridge-b.js   # Blinded mode: relay-facing
│   ├── server-webtunnel.js  # WebTunnel bridge (HMAC probe-resistant)
│   ├── server-meek.js       # Meek bridge (HTTP POST through CDN)
│   └── distribution/       # Bridge distribution tools
│       ├── telegram-bot.js  # Telegram bridge bot
│       ├── email-responder.js # Email auto-responder
│       └── qr-generator.js # QR code generator
├── broker/               # WebRTC signaling for peer bridges
├── proxy/                # Volunteer peer proxy (browser tab)
├── tor-core/             # Platform-agnostic core crypto primitives
├── app/                  # Browser UI (PWA) + i18n (en/fa/ru/zh)
├── worker/               # Cloudflare Worker (meek relay + app host)
├── tools/                # Build tools (offline bundle generator)
├── examples/             # Demo HTML applications
├── tests/                # Integration + censorship simulation tests
└── papers/               # Security papers + OTF documentation
```

### Key Design Decisions

- **No tokio**: WASM is single-threaded. We use a cooperative async scheduler (`src/cooperative/`) instead.
- **No `window()` in core**: Transport and timer code accesses browser APIs through abstraction layers, enabling future Service Worker support.
- **WebSocket bridge**: Browsers cannot open raw TCP sockets. The bridge server converts WebSocket to TCP for Tor relay connections.
- **All crypto from audited crates**: `ring`, `rustls`, `x25519-dalek`, `curve25519-dalek`, `sha2`, `aes` — no custom implementations.

## License

By contributing, you agree that your contributions will be licensed under the AGPL-3.0 license.
