# Contributing to tor-wasm

Thank you for your interest in contributing to tor-wasm! This project aims to bring Tor anonymity to web browsers through WebAssembly.

## Getting Started

### Prerequisites

- Rust (stable, 1.75+)
- wasm-pack (`cargo install wasm-pack`)
- Node.js 18+ (for bridge server)

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
# Run Rust tests
cargo test

# Run WASM tests
wasm-pack test --headless --chrome
```

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
4. Ensure tests pass
5. Submit a pull request

### Security Issues

See [SECURITY.md](SECURITY.md) for responsible disclosure guidelines. **Do not open public issues for security vulnerabilities.**

## Code Style

- Follow standard Rust formatting (`cargo fmt`)
- Run `cargo clippy` before submitting
- No custom cryptographic implementations - use audited crates
- All key material must use `zeroize` for cleanup

## Architecture

- `src/` - Main WASM module (Rust)
  - `protocol/` - Tor protocol implementation (ntor, cells, circuits)
  - `transport/` - WebSocket transport layer
  - `cooperative/` - Browser-compatible async scheduler
  - `storage/` - IndexedDB/localStorage persistence
  - `runtime/` - WASM runtime compatibility layer
- `bridge-server/` - WebSocket-to-TCP bridge (Node.js)
- `tor-core/` - Core cryptographic primitives
- `examples/` - Demo HTML applications
- `tests/` - Integration tests

## License

By contributing, you agree that your contributions will be licensed under the MIT/Apache-2.0 dual license.
