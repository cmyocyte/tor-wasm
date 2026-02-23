#!/usr/bin/env node

/**
 * Test: Verify Bridge B's decryption is compatible with the Rust client's encryption.
 *
 * This simulates the Rust client's blind_target_address() in JavaScript and
 * verifies that Bridge B's decryptBlindedAddress() can decrypt the result.
 */

const crypto = require('crypto');

const X25519_SPKI_HEADER = Buffer.from('302a300506032b656e032100', 'hex');
const X25519_PKCS8_HEADER = Buffer.from('302e020100300506032b656e04220420', 'hex');
const HKDF_INFO = Buffer.from('tor-wasm-bridge-blind-v1');
const FIXED_NONCE = Buffer.from('bridge-blind'); // 12 bytes — must match Rust

/**
 * Simulate the Rust client's blind_target_address() in JavaScript.
 */
function encryptBlindedAddress(relayAddr, bridgeBPubRaw) {
  // Generate ephemeral X25519 keypair
  const { publicKey: ephPub, privateKey: ephPriv } = crypto.generateKeyPairSync('x25519');
  const ephPubRaw = ephPub.export({ format: 'der', type: 'spki' }).subarray(12);

  // Import Bridge B's public key
  const bridgeBPub = crypto.createPublicKey({
    key: Buffer.concat([X25519_SPKI_HEADER, bridgeBPubRaw]),
    format: 'der',
    type: 'spki',
  });

  // X25519 ECDH → shared secret
  const sharedSecret = crypto.diffieHellman({ publicKey: bridgeBPub, privateKey: ephPriv });

  // HKDF-SHA256 → AES-256 key
  const aesKey = Buffer.from(crypto.hkdfSync('sha256', sharedSecret, Buffer.alloc(0), HKDF_INFO, 32));

  // AES-256-GCM encrypt
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, FIXED_NONCE);
  let encrypted = cipher.update(Buffer.from(relayAddr, 'utf8'));
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Concatenate: ephemeral_pubkey (32) || ciphertext || tag (16)
  const blob = Buffer.concat([ephPubRaw, encrypted, authTag]);

  // Base64url encode (no padding)
  return blob.toString('base64url');
}

/**
 * Bridge B's decryption (same as server-bridge-b.js).
 */
function decryptBlindedAddress(blobB64, privateKeyRaw) {
  const blob = Buffer.from(blobB64, 'base64url');
  if (blob.length < 48) throw new Error('Blob too short');

  const ephemeralPubRaw = blob.subarray(0, 32);
  const combined = blob.subarray(32);

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

  const sharedSecret = crypto.diffieHellman({ publicKey: ephemeralPub, privateKey: bridgePriv });
  const aesKey = Buffer.from(crypto.hkdfSync('sha256', sharedSecret, Buffer.alloc(0), HKDF_INFO, 32));

  const authTag = combined.subarray(combined.length - 16);
  const encrypted = combined.subarray(0, combined.length - 16);

  const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, FIXED_NONCE);
  decipher.setAuthTag(authTag);
  let plaintext = decipher.update(encrypted);
  plaintext = Buffer.concat([plaintext, decipher.final()]);

  return plaintext.toString('utf8');
}

// --- Tests ---
let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  PASS: ${name}`);
    passed++;
  } catch (err) {
    console.log(`  FAIL: ${name} — ${err.message}`);
    failed++;
  }
}

function assert(condition, msg) {
  if (!condition) throw new Error(msg || 'Assertion failed');
}

console.log('Bridge Blinding Compatibility Tests\n');

// Generate a Bridge B keypair for testing
const { publicKey: bPub, privateKey: bPriv } = crypto.generateKeyPairSync('x25519');
const bPubRaw = bPub.export({ format: 'der', type: 'spki' }).subarray(12);
const bPrivRaw = bPriv.export({ format: 'der', type: 'pkcs8' }).subarray(16);

test('Roundtrip: encrypt then decrypt', () => {
  const addr = '192.168.1.100:9001';
  const blob = encryptBlindedAddress(addr, bPubRaw);
  const decrypted = decryptBlindedAddress(blob, bPrivRaw);
  assert(decrypted === addr, `Expected "${addr}", got "${decrypted}"`);
});

test('Wrong key fails to decrypt', () => {
  const { privateKey: wrongPriv } = crypto.generateKeyPairSync('x25519');
  const wrongPrivRaw = wrongPriv.export({ format: 'der', type: 'pkcs8' }).subarray(16);

  const blob = encryptBlindedAddress('10.0.0.1:443', bPubRaw);
  try {
    decryptBlindedAddress(blob, wrongPrivRaw);
    throw new Error('Should have thrown');
  } catch (err) {
    assert(err.message !== 'Should have thrown', 'Decryption should fail with wrong key');
  }
});

test('Different addresses all roundtrip', () => {
  const addrs = ['1.2.3.4:9001', '192.0.2.1:443', '[::1]:9050', 'relay.example.com:9001'];
  for (const addr of addrs) {
    const blob = encryptBlindedAddress(addr, bPubRaw);
    const decrypted = decryptBlindedAddress(blob, bPrivRaw);
    assert(decrypted === addr, `Expected "${addr}", got "${decrypted}"`);
  }
});

test('Each encryption produces unique ciphertext', () => {
  const addr = '1.2.3.4:9001';
  const blob1 = encryptBlindedAddress(addr, bPubRaw);
  const blob2 = encryptBlindedAddress(addr, bPubRaw);
  assert(blob1 !== blob2, 'Blobs should differ (ephemeral keys)');
  assert(decryptBlindedAddress(blob1, bPrivRaw) === addr, 'blob1 decrypt failed');
  assert(decryptBlindedAddress(blob2, bPrivRaw) === addr, 'blob2 decrypt failed');
});

test('Blob is base64url-safe (no +, /, =)', () => {
  const blob = encryptBlindedAddress('10.0.0.1:9001', bPubRaw);
  assert(!/[+/=]/.test(blob), `Blob contains non-URL-safe chars: ${blob}`);
});

test('Nonce is exactly 12 bytes', () => {
  assert(FIXED_NONCE.length === 12, `Nonce is ${FIXED_NONCE.length} bytes, expected 12`);
});

console.log(`\nResults: ${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
