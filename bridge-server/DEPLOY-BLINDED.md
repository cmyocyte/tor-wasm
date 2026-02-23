# Deploying Two-Hop Blinded Bridges with ECH

This guide deploys the blinded bridge architecture where **no single operator** can see both the client's IP and the guard relay's IP.

```
Client ──WSS/ECH──► Bridge A ──WS──► Bridge B ──TLS──► Guard Relay
         (sees client IP)      (sees guard IP)
         (NOT guard IP)        (NOT client IP)
```

## Prerequisites

- Two servers (different operators/networks for meaningful separation)
- Node.js 18+ on each server
- A domain name (for ECH via Cloudflare)
- Cloudflare account (free tier is sufficient)

## Step 1: Generate Bridge B Keypair

On any machine:

```bash
cd bridge-server
node keygen.js
```

Output:
```
Public key (hex):  <32-byte-hex-public-key>
Private key (hex): <32-byte-hex-private-key>
```

Save the private key securely — it goes on Bridge B's server.
The public key is embedded in the WASM binary or served via the broker.

## Step 2: Deploy Bridge B

Bridge B connects to Tor guard relays. It should be on a separate network from Bridge A.

```bash
# On Bridge B's server
export BRIDGE_B_PRIVATE_KEY=<private-key-hex-from-step-1>
export PORT=9090

node server-bridge-b.js
```

Or with Docker:
```bash
docker build -f Dockerfile.bridge-b -t bridge-b .
docker run -d \
  -e BRIDGE_B_PRIVATE_KEY=<key> \
  -e PORT=9090 \
  -p 9090:9090 \
  --name bridge-b \
  bridge-b
```

Verify: `curl http://bridge-b-host:9090/health`

## Step 3: Deploy Bridge A

Bridge A is the client-facing server. It forwards encrypted blobs to Bridge B.

```bash
# On Bridge A's server
export BRIDGE_B_URL=ws://bridge-b-host:9090
export PORT=8080

# Optional authentication
export BRIDGE_AUTH_TOKEN=<random-secret>

node server-bridge-a.js
```

Or with Docker Compose (both on same machine for testing):
```bash
# Create .env file
echo "BRIDGE_B_PRIVATE_KEY=<key>" > .env

docker compose -f docker-compose-blinded.yml up -d
```

Verify: `curl http://bridge-a-host:8080/health`

## Step 4: Enable ECH via Cloudflare

This makes Bridge A's connections indistinguishable from normal web traffic.

### 4.1 Add Domain to Cloudflare

1. Register a domain (e.g., `bridge.example.com`)
2. Add it to Cloudflare (free plan works)
3. Update nameservers at your registrar to Cloudflare's

### 4.2 Configure DNS

In Cloudflare dashboard → DNS:

```
Type: A
Name: bridge
Content: <Bridge A's IP address>
Proxy: ON (orange cloud)  ← This enables ECH
TTL: Auto
```

The orange cloud (proxy enabled) is critical — it routes traffic through Cloudflare's edge, which handles ECH automatically.

### 4.3 Enable WebSocket Proxying

Cloudflare dashboard → Network → WebSockets: **ON** (enabled by default on all plans)

### 4.4 SSL/TLS Configuration

Cloudflare dashboard → SSL/TLS:
- Mode: **Full (strict)** if Bridge A has a valid cert, or **Full** with self-signed
- For simplest setup: use **Flexible** (Cloudflare handles TLS, talks HTTP to origin)

### 4.5 Verify ECH

From a network where ECH is supported (Chrome/Firefox):

```bash
# Check that HTTPS DNS records include ECH keys
dig bridge.example.com HTTPS +short
# Expected: 1 . alpn="h2,h3" ech=<base64-ECH-config>

# Verify TLS connection uses ECH
openssl s_client -connect bridge.example.com:443 \
  -servername bridge.example.com 2>&1 | grep -i ech

# Test bridge health through ECH
curl https://bridge.example.com/health

# Test WebSocket
wscat -c "wss://bridge.example.com?addr=test"
```

### 4.6 What the Censor Sees

**Without ECH:**
```
TLS ClientHello { SNI: "bridge.example.com" }
→ Censor blocks bridge.example.com
```

**With ECH:**
```
TLS ClientHello { outer_SNI: "cloudflare-ech.com", inner: [encrypted] }
→ Censor sees connection to Cloudflare (shared by millions of sites)
→ Cannot determine the real destination
→ Blocking requires blocking ALL Cloudflare traffic
```

## Step 5: Update WASM Client

In the Rust client, configure `BridgeConfig` for blinded mode:

```rust
use tor_wasm::transport::BridgeConfig;

// Bridge B's public key (from Step 1)
let bridge_b_pubkey: [u8; 32] = [
    // paste the byte array from keygen.js output
];

let config = BridgeConfig::blinded(
    "wss://bridge.example.com".to_string(),  // Bridge A (behind ECH)
    bridge_b_pubkey,
);
```

The client automatically encrypts the guard relay address under Bridge B's key.
Bridge A sees only an opaque blob. Bridge B sees only Bridge A's IP (Cloudflare's IP with ECH).

## Security Verification

### Verify Bridge A Cannot See Guard IPs

Check Bridge A's logs:
```bash
# Should show only "Forwarding to Bridge B" — NO relay IP addresses
docker logs bridge-a 2>&1 | grep -E "target|relay|guard|addr"
# Expected: only "[N] Forwarding to Bridge B: ws://...?..."
```

### Verify Bridge B Cannot See Client IPs

Check Bridge B's logs:
```bash
# Should show only Bridge A's IP (or Cloudflare's IP)
docker logs bridge-b 2>&1 | grep "New connection"
# Expected: "[N] New connection from <bridge-a-ip>"
# NOT: "[N] New connection from <client-ip>"
```

## Production Recommendations

### Operator Separation

For meaningful trust separation, Bridge A and Bridge B should be:
- **Different operators** (different organizations or individuals)
- **Different networks** (different hosting providers)
- **Different jurisdictions** (different countries, if possible)

Example:
- Bridge A: Cloudflare (ECH-hidden), operated by project team
- Bridge B: DigitalOcean/Hetzner, operated by partnering digital rights org

### Key Rotation

Bridge B should rotate its X25519 keypair periodically:
```bash
# Generate new keypair
node keygen.js > new-keys.txt

# Update Bridge B with new private key
# Update client WASM with new public key
# Both old and new keys should work during transition
```

### Monitoring

Both bridges expose `/health` endpoints for monitoring:
```json
// Bridge A
{"status":"ok","role":"bridge-a","connections":42,"consensusCached":true}

// Bridge B
{"status":"ok","role":"bridge-b","connections":42}
```

### Fallback

If Bridge B is unavailable, clients can fall back to direct mode:
```rust
// Fallback configuration (single bridge, no blinding)
let config = BridgeConfig::new("wss://bridge.example.com".to_string());
```
