#!/usr/bin/env node

/**
 * Bridge B — Relay-facing bridge that decrypts blinded target addresses.
 *
 * In the two-hop bridge blinding architecture:
 *   Client → Bridge A (sees client IP, NOT guard IP)
 *          → Bridge B (sees guard IP, NOT client IP)
 *          → Guard relay
 *
 * Bridge B receives opaque encrypted blobs from Bridge A, decrypts them
 * using its X25519 private key to learn the target relay address, then
 * opens a TCP/TLS connection to the relay.
 *
 * Crypto: X25519 ECDH + HKDF-SHA256 + AES-256-GCM (matches Rust client)
 *
 * Usage:
 *   BRIDGE_B_PRIVATE_KEY=<hex> node server-bridge-b.js [--port PORT]
 */

const WebSocket = require('ws');
const net = require('net');
const tls = require('tls');
const http = require('http');
const url = require('url');
const crypto = require('crypto');

// --- Configuration ---
const args = process.argv.slice(2);
const config = {
  port: parseInt(process.env.PORT) || 9090,
  privateKeyHex: process.env.BRIDGE_B_PRIVATE_KEY || null,
  maxConnections: parseInt(process.env.MAX_CONNECTIONS) || 1000,
};

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--port') config.port = parseInt(args[++i]);
  if (args[i] === '--key') config.privateKeyHex = args[++i];
}

if (!config.privateKeyHex) {
  console.error('ERROR: BRIDGE_B_PRIVATE_KEY environment variable is required.');
  console.error('Generate a keypair with: node keygen.js');
  process.exit(1);
}

const privateKeyRaw = Buffer.from(config.privateKeyHex, 'hex');
if (privateKeyRaw.length !== 32) {
  console.error('ERROR: Private key must be exactly 32 bytes (64 hex chars).');
  process.exit(1);
}

// DER headers for importing raw X25519 keys into Node.js crypto
const X25519_SPKI_HEADER = Buffer.from('302a300506032b656e032100', 'hex');
const X25519_PKCS8_HEADER = Buffer.from('302e020100300506032b656e04220420', 'hex');

// Must match the Rust client's constants in bridge_blind.rs
const HKDF_INFO = Buffer.from('tor-wasm-bridge-blind-v1');
const FIXED_NONCE = Buffer.from('bridge-blind'); // 12 bytes

/**
 * Decrypt a blinded relay address.
 *
 * Input: base64url-encoded blob = ephemeral_pubkey(32) || ciphertext || tag(16)
 * Output: plaintext relay address string (e.g. "1.2.3.4:9001")
 */
function decryptBlindedAddress(blobB64) {
  const blob = Buffer.from(blobB64, 'base64url');

  if (blob.length < 32 + 16) {
    throw new Error(`Blob too short: ${blob.length} bytes (need >= 48)`);
  }

  // Parse ephemeral public key (first 32 bytes)
  const ephemeralPubRaw = blob.subarray(0, 32);
  const combined = blob.subarray(32);

  // Import keys
  const ephemeralPub = crypto.createPublicKey({
    key: Buffer.concat([X25519_SPKI_HEADER, ephemeralPubRaw]),
    format: 'der',
    type: 'spki',
  });

  const bridgePriv = crypto.createPrivateKey({
    key: Buffer.concat([X25519_PKCS8_HEADER, privateKeyRaw]),
    format: 'der',
    type: 'pkcs8',
  });

  // X25519 ECDH → shared secret
  const sharedSecret = crypto.diffieHellman({
    publicKey: ephemeralPub,
    privateKey: bridgePriv,
  });

  // HKDF-SHA256 → AES-256 key
  const aesKey = Buffer.from(
    crypto.hkdfSync('sha256', sharedSecret, Buffer.alloc(0), HKDF_INFO, 32)
  );

  // AES-256-GCM decrypt (tag is last 16 bytes)
  const authTag = combined.subarray(combined.length - 16);
  const encrypted = combined.subarray(0, combined.length - 16);

  const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, FIXED_NONCE);
  decipher.setAuthTag(authTag);

  let plaintext = decipher.update(encrypted);
  plaintext = Buffer.concat([plaintext, decipher.final()]);

  return plaintext.toString('utf8');
}

// --- HTTP + WebSocket server ---
const server = http.createServer();
const wss = new WebSocket.Server({ server });

let connectionId = 0;

wss.on('connection', (ws, req) => {
  const id = ++connectionId;
  const peerIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress;
  console.log(`[${id}] New connection from ${peerIp}`);

  if (wss.clients.size > config.maxConnections) {
    console.log(`[${id}] Connection limit reached`);
    ws.close(1013, 'Server at capacity');
    return;
  }

  const query = url.parse(req.url, true).query;

  // Determine target address
  let target;
  try {
    if (query.dest) {
      // Blinded mode — decrypt to learn target
      target = decryptBlindedAddress(query.dest);
      console.log(`[${id}] Decrypted target: ${target}`);
    } else if (query.addr) {
      // Legacy/direct mode — target in plaintext (backward compat)
      target = query.addr;
      console.log(`[${id}] Direct target: ${target}`);
    } else {
      console.log(`[${id}] No target specified`);
      ws.close(1008, 'Target address required (?dest= or ?addr=)');
      return;
    }
  } catch (err) {
    console.log(`[${id}] Decryption failed: ${err.message}`);
    ws.close(1008, 'Invalid encrypted target');
    return;
  }

  // Parse host:port
  const [host, portStr] = target.split(':');
  const port = parseInt(portStr);

  if (!host || !port || isNaN(port)) {
    console.log(`[${id}] Invalid target: ${target}`);
    ws.close(1008, 'Invalid target address');
    return;
  }

  // Connect to relay via TCP → TLS
  const tcpSocket = net.connect(port, host);
  let tlsSocket = null;
  let tlsReady = false;
  let queuedData = [];

  tcpSocket.on('connect', () => {
    console.log(`[${id}] TCP connected to ${host}:${port}`);
    tcpSocket.setNoDelay(true);

    const tlsOptions = {
      socket: tcpSocket,
      rejectUnauthorized: false, // Tor relays use self-signed certs
      minVersion: 'TLSv1.2',
      maxVersion: 'TLSv1.3',
      ...(!/^\d+\.\d+\.\d+\.\d+$/.test(host) ? { servername: host } : {}),
    };
    tlsSocket = tls.connect(tlsOptions);

    tlsSocket.on('secureConnect', () => {
      console.log(`[${id}] TLS established (${tlsSocket.getProtocol()})`);
      tlsReady = true;
      for (const data of queuedData) tlsSocket.write(data);
      queuedData = [];
    });

    // TLS → WebSocket (back to Bridge A → client)
    tlsSocket.on('data', (data) => {
      if (ws.readyState === WebSocket.OPEN) ws.send(data);
    });

    tlsSocket.on('error', (err) => {
      console.log(`[${id}] TLS error: ${err.message}`);
      if (ws.readyState === WebSocket.OPEN) ws.close(1011, 'TLS error');
    });

    tlsSocket.on('close', () => {
      if (ws.readyState === WebSocket.OPEN) ws.close();
    });
  });

  // WebSocket → TLS (from Bridge A → relay)
  ws.on('message', (data) => {
    if (tlsReady) {
      tlsSocket.write(data);
    } else {
      queuedData.push(data);
    }
  });

  tcpSocket.on('error', (err) => {
    console.log(`[${id}] TCP error: ${err.message}`);
    if (ws.readyState === WebSocket.OPEN) ws.close(1011, 'TCP error');
  });

  ws.on('close', () => {
    if (tlsSocket) tlsSocket.destroy();
    tcpSocket.destroy();
  });

  ws.on('error', () => {
    if (tlsSocket) tlsSocket.destroy();
    tcpSocket.destroy();
  });
});

// --- HTTP endpoints ---
server.on('request', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');

  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'ok',
      role: 'bridge-b',
      uptime: process.uptime(),
      connections: wss.clients.size,
    }));
    return;
  }

  res.writeHead(404);
  res.end('Not found');
});

// --- Start ---
server.listen(config.port, '0.0.0.0', () => {
  console.log('');
  console.log('============================================');
  console.log('  Bridge B (Relay-Facing, Blinded)');
  console.log('============================================');
  console.log(`  Port: ${config.port}`);
  console.log(`  Private key loaded: ${config.privateKeyHex.substring(0, 8)}...`);
  console.log(`  Health: http://localhost:${config.port}/health`);
  console.log('============================================');
  console.log('');
  console.log('Waiting for connections from Bridge A...');
});
