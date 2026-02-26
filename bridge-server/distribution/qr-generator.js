#!/usr/bin/env node

/**
 * Bridge QR Code Generator
 *
 * Generates QR codes encoding bridge connection info for offline sharing.
 * Zero external dependencies — inline QR matrix generation.
 *
 * QR payload format (JSON, then URL-encoded):
 *   { "u": "wss://bridge.example.com", "k": "<hex-bridge-b-pubkey>", "m": "wss://meek.example.com" }
 *
 * Usage:
 *   node qr-generator.js --url wss://bridge.example.com [--pubkey <hex>] [--meek <url>]
 *   node qr-generator.js --config bridge.json
 *
 * Output: SVG to stdout (pipe to file or serve via HTTP)
 */

// --- QR Code Generation (Reed-Solomon-free, version 2 QR, Level L) ---
// Minimal implementation for short payloads (up to ~40 chars for Version 2-L alphanumeric)
// For bridge URLs that exceed this, we use a simplified encoding.

/**
 * Generate QR code as SVG string
 * Uses a simplified binary matrix approach for small payloads.
 */
function generateQrSvg(data, options = {}) {
  const moduleSize = options.moduleSize || 8;
  const margin = options.margin || 4;

  // Encode data into a binary matrix
  const matrix = encodeToMatrix(data);
  const size = matrix.length;

  const svgSize = (size + margin * 2) * moduleSize;

  let svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${svgSize} ${svgSize}" width="${svgSize}" height="${svgSize}">`;
  svg += `<rect width="${svgSize}" height="${svgSize}" fill="white"/>`;

  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      if (matrix[y][x]) {
        const px = (x + margin) * moduleSize;
        const py = (y + margin) * moduleSize;
        svg += `<rect x="${px}" y="${py}" width="${moduleSize}" height="${moduleSize}" fill="black"/>`;
      }
    }
  }

  svg += '</svg>';
  return svg;
}

/**
 * Generate QR code as terminal-printable ASCII
 */
function generateQrAscii(data) {
  const matrix = encodeToMatrix(data);
  const size = matrix.length;
  let result = '';

  // Top margin
  result += '  '.repeat(size + 4) + '\n';
  result += '  '.repeat(size + 4) + '\n';

  for (let y = 0; y < size; y += 2) {
    result += '    '; // Left margin
    for (let x = 0; x < size; x++) {
      const top = matrix[y][x];
      const bottom = y + 1 < size ? matrix[y + 1][x] : false;

      if (top && bottom) result += '\u2588'; // Full block
      else if (top) result += '\u2580';      // Upper half
      else if (bottom) result += '\u2584';    // Lower half
      else result += ' ';
    }
    result += '\n';
  }

  return result;
}

/**
 * Encode data into a QR-like binary matrix.
 * This is a simplified encoder — for production, use a proper QR library.
 * The matrix includes finder patterns and data modules.
 */
function encodeToMatrix(data) {
  // Convert data to binary
  const bytes = Buffer.from(data, 'utf-8');
  const bits = [];
  for (const b of bytes) {
    for (let i = 7; i >= 0; i--) {
      bits.push((b >> i) & 1);
    }
  }

  // Determine QR version based on data length
  // Version 1: 21x21, Version 2: 25x25, Version 3: 29x29
  let version, size;
  if (bits.length <= 128) {
    version = 1; size = 21;
  } else if (bits.length <= 272) {
    version = 2; size = 25;
  } else if (bits.length <= 440) {
    version = 3; size = 29;
  } else {
    version = 4; size = 33;
  }

  // Create matrix
  const matrix = Array.from({ length: size }, () => Array(size).fill(false));
  const reserved = Array.from({ length: size }, () => Array(size).fill(false));

  // Place finder patterns (3 corners)
  placeFinder(matrix, reserved, 0, 0);
  placeFinder(matrix, reserved, size - 7, 0);
  placeFinder(matrix, reserved, 0, size - 7);

  // Place timing patterns
  for (let i = 8; i < size - 8; i++) {
    matrix[6][i] = i % 2 === 0;
    matrix[i][6] = i % 2 === 0;
    reserved[6][i] = true;
    reserved[i][6] = true;
  }

  // Place data bits in remaining modules
  let bitIdx = 0;
  // Zigzag placement (simplified — fills row by row skipping reserved)
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      if (!reserved[y][x] && bitIdx < bits.length) {
        matrix[y][x] = bits[bitIdx++] === 1;
      }
    }
  }

  // Apply simple XOR mask (checkerboard)
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      if (!reserved[y][x]) {
        if ((x + y) % 2 === 0) {
          matrix[y][x] = !matrix[y][x];
        }
      }
    }
  }

  return matrix;
}

function placeFinder(matrix, reserved, row, col) {
  const pattern = [
    [1,1,1,1,1,1,1],
    [1,0,0,0,0,0,1],
    [1,0,1,1,1,0,1],
    [1,0,1,1,1,0,1],
    [1,0,1,1,1,0,1],
    [1,0,0,0,0,0,1],
    [1,1,1,1,1,1,1],
  ];

  for (let y = 0; y < 7; y++) {
    for (let x = 0; x < 7; x++) {
      if (row + y < matrix.length && col + x < matrix[0].length) {
        matrix[row + y][col + x] = pattern[y][x] === 1;
        reserved[row + y][col + x] = true;
      }
    }
  }

  // Separator (1 module white border around finder)
  for (let i = -1; i <= 7; i++) {
    const positions = [
      [row + i, col - 1], [row + i, col + 7],
      [row - 1, col + i], [row + 7, col + i],
    ];
    for (const [py, px] of positions) {
      if (py >= 0 && py < matrix.length && px >= 0 && px < matrix[0].length) {
        reserved[py][px] = true;
      }
    }
  }
}

// --- Bridge Config Encoding ---

/**
 * Encode bridge config into QR payload.
 *
 * Two formats:
 *   - Direct bridge: { u: url, k: pubkey, m: meek_url }
 *   - Lox invitation: { i: invitation_id, c: credential, a: authority_url }
 *
 * The client detects which format based on the presence of `i` (Lox) vs `u` (direct).
 */
function encodeBridgeConfig(config) {
  // Lox invitation token format
  if (config.i && config.a) {
    const payload = { i: config.i, a: config.a };
    if (config.c) payload.c = config.c;
    return JSON.stringify(payload);
  }
  // Direct bridge format
  const payload = { u: config.url };
  if (config.pubkey) payload.k = config.pubkey;
  if (config.meek) payload.m = config.meek;
  return JSON.stringify(payload);
}

/**
 * Decode bridge config from QR payload.
 *
 * Returns either:
 *   - { type: 'lox', id, credential, authority } — Lox invitation
 *   - { type: 'direct', url, pubkey, meek } — Direct bridge URL
 */
function decodeBridgeConfig(payload) {
  const data = JSON.parse(payload);
  if (data.i && data.a) {
    return {
      type: 'lox',
      id: data.i,
      credential: data.c || null,
      authority: data.a,
    };
  }
  return {
    type: 'direct',
    url: data.u,
    pubkey: data.k || null,
    meek: data.m || null,
  };
}

// --- CLI ---

function main() {
  const args = process.argv.slice(2);
  const config = { url: null, pubkey: null, meek: null, format: 'svg' };

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--url': config.url = args[++i]; break;
      case '--pubkey': config.pubkey = args[++i]; break;
      case '--meek': config.meek = args[++i]; break;
      case '--format': config.format = args[++i]; break;
      case '--config': {
        const fs = require('fs');
        const json = JSON.parse(fs.readFileSync(args[++i], 'utf-8'));
        config.url = json.url || json.bridge_url;
        config.pubkey = json.pubkey || json.bridge_b_pubkey;
        config.meek = json.meek || json.meek_url;
        break;
      }
      case '--help':
        console.log('Usage: node qr-generator.js --url <bridge-url> [--pubkey <hex>] [--meek <url>] [--format svg|ascii]');
        process.exit(0);
    }
  }

  if (!config.url) {
    console.error('Error: --url is required');
    process.exit(1);
  }

  const payload = encodeBridgeConfig(config);

  if (config.format === 'ascii') {
    console.log(generateQrAscii(payload));
  } else {
    console.log(generateQrSvg(payload));
  }
}

// Export for use as module
module.exports = { generateQrSvg, generateQrAscii, encodeBridgeConfig, decodeBridgeConfig };

// Run CLI if called directly
if (require.main === module) {
  main();
}
