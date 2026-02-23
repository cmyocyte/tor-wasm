#!/usr/bin/env node

/**
 * Generate X25519 keypair for Bridge B.
 *
 * The public key is shared with clients (embedded in WASM or served by broker).
 * The private key is kept secret on Bridge B's server.
 *
 * Usage:
 *   node keygen.js
 */

const crypto = require('crypto');

const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');

// Export raw 32-byte keys (strip DER headers)
const rawPublic = publicKey.export({ format: 'der', type: 'spki' }).subarray(12);
const rawPrivate = privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(16);

console.log('Bridge B X25519 Keypair');
console.log('======================\n');
console.log(`Public key (hex):  ${rawPublic.toString('hex')}`);
console.log(`Private key (hex): ${rawPrivate.toString('hex')}\n`);
console.log('Environment variables:');
console.log(`  # Set on Bridge B:`);
console.log(`  BRIDGE_B_PRIVATE_KEY=${rawPrivate.toString('hex')}`);
console.log(`  # Set on Bridge A (so it knows where to forward):`);
console.log(`  BRIDGE_B_URL=ws://bridge-b-host:9090\n`);
console.log('For the WASM client (BridgeConfig::blinded), embed this public key:');
console.log(`  [${Array.from(rawPublic).join(', ')}]`);
