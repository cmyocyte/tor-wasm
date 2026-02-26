#!/usr/bin/env node

/**
 * Tor Signature Scanner
 *
 * Captures raw bytes from a WebSocket connection and scans for
 * known Tor protocol signatures that a DPI system might detect.
 *
 * Known Tor fingerprints scanned for:
 *   - 514-byte frames (standard Tor cell size)
 *   - Cell command bytes at known offsets
 *   - Relay early/extend patterns
 *   - Consensus document headers
 *
 * Usage:
 *   node signature-scanner.js --bridge ws://localhost:8080
 *   node signature-scanner.js --bridge ws://localhost:8080 --profile chat
 */

const WebSocket = require('ws');

const args = process.argv.slice(2);
let bridgeUrl = 'ws://localhost:8080';
let profile = 'none';
let numFrames = 100;

for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
        case '--bridge': bridgeUrl = args[++i]; break;
        case '--profile': profile = args[++i]; break;
        case '--frames': numFrames = parseInt(args[++i]); break;
    }
}

console.log('\nTor Signature Scanner');
console.log('====================');
console.log(`Bridge:  ${bridgeUrl}`);
console.log(`Profile: ${profile}`);
console.log(`Frames:  ${numFrames}\n`);

// --- Signature Definitions ---

// Standard Tor cell commands (at byte offset 4 for link-protocol cells)
const TOR_CELL_COMMANDS = {
    0: 'PADDING',
    1: 'CREATE',
    2: 'CREATED',
    3: 'RELAY',
    4: 'DESTROY',
    5: 'CREATE_FAST',
    6: 'CREATED_FAST',
    7: 'VERSIONS',
    8: 'NETINFO',
    9: 'RELAY_EARLY',
    10: 'CREATE2',
    11: 'CREATED2',
    12: 'PADDING_NEGOTIATE',
    128: 'VPADDING',
    129: 'CERTS',
    130: 'AUTH_CHALLENGE',
    131: 'AUTHENTICATE',
    132: 'AUTHORIZE',
};

// Variable-length cell commands (have 2-byte length after circuit ID)
const VARIABLE_LENGTH_COMMANDS = new Set([7, 128, 129, 130, 131, 132]);

// Consensus document signatures
const CONSENSUS_SIGNATURES = [
    Buffer.from('network-status-version'),
    Buffer.from('dir-source'),
    Buffer.from('r '),  // relay line in consensus
    Buffer.from('directory-signature'),
];

let passed = 0;
let failed = 0;

function report(name, ok, details) {
    const status = ok ? 'PASS' : 'FAIL';
    if (ok) passed++; else failed++;
    console.log(`  [${status}] ${name}${details ? ': ' + details : ''}`);
}

// --- Capture ---

const frames = [];

const ws = new WebSocket(bridgeUrl);
ws.binaryType = 'arraybuffer';

ws.on('open', () => console.log('Connected, capturing frames...'));

ws.on('message', (data) => {
    const buf = Buffer.from(data);
    frames.push(buf);

    if (frames.length >= numFrames) {
        ws.close();
    }
});

ws.on('close', () => analyze());

ws.on('error', (e) => {
    console.error('WebSocket error:', e.message);
    if (frames.length > 10) {
        analyze();
    } else {
        process.exit(1);
    }
});

setTimeout(() => {
    console.warn(`\nTimeout: captured ${frames.length}/${numFrames} frames`);
    ws.close();
}, 30000);

// --- Analysis ---

function analyze() {
    if (frames.length === 0) {
        console.error('No frames captured');
        process.exit(1);
    }

    console.log(`\nCaptured ${frames.length} frames\n`);

    // --- Test 1: 514-byte frame detection ---
    const exact514 = frames.filter(f => f.length === 514).length;
    const pct514 = (exact514 / frames.length * 100).toFixed(1);

    if (profile === 'none') {
        // Without shaping, we expect raw Tor cells
        report('514-byte Tor cells present (no shaping)',
            exact514 > 0,
            `${exact514}/${frames.length} (${pct514}%)`);
    } else {
        // With shaping, Tor cell fingerprint should be eliminated
        const threshold = 10; // Allow <10% residual
        report('514-byte Tor cell fingerprint eliminated',
            parseFloat(pct514) < threshold,
            `${exact514}/${frames.length} (${pct514}%) — threshold: <${threshold}%`);
    }

    // --- Test 2: Cell command byte detection ---
    let cellCommandMatches = 0;
    for (const frame of frames) {
        if (frame.length >= 5) {
            const cmd = frame[4]; // Command byte at offset 4
            if (TOR_CELL_COMMANDS[cmd] !== undefined) {
                cellCommandMatches++;
            }
        }
    }
    const pctCmd = (cellCommandMatches / frames.length * 100).toFixed(1);

    if (profile !== 'none') {
        // With shaping, cell commands at offset 4 should not be detectable
        // (because frames are fragmented, offset 4 is unlikely to be a real command byte)
        report('Cell command bytes at offset 4 not consistently detectable',
            parseFloat(pctCmd) < 50,
            `${cellCommandMatches}/${frames.length} (${pctCmd}%) matched known commands`);
    }

    // --- Test 3: Consensus document signatures ---
    let consensusSigFound = false;
    const allData = Buffer.concat(frames);

    for (const sig of CONSENSUS_SIGNATURES) {
        if (allData.includes(sig)) {
            consensusSigFound = true;
            report('No consensus signatures in wire data',
                false,
                `Found: "${sig.toString('utf-8')}"`);
            break;
        }
    }
    if (!consensusSigFound) {
        report('No consensus signatures in wire data', true, 'Clean');
    }

    // --- Test 4: Frame size entropy ---
    // A shaped profile should have varied frame sizes (high entropy)
    // Raw Tor has very low entropy (mostly 514)
    const sizes = frames.map(f => f.length);
    const uniqueSizes = new Set(sizes).size;
    const sizeEntropy = uniqueSizes / sizes.length;

    if (profile !== 'none') {
        report('Frame size distribution has sufficient entropy',
            sizeEntropy > 0.1,
            `${uniqueSizes} unique sizes out of ${sizes.length} frames (ratio: ${sizeEntropy.toFixed(3)})`);
    }

    // --- Test 5: No VERSIONS cell leak ---
    // Tor VERSIONS cell: command 7, contains protocol version list
    // If traffic shaping is on, this should be fragmented/padded
    let versionsFound = 0;
    for (const frame of frames) {
        if (frame.length >= 5 && frame[4] === 7) {
            // Check if it looks like a real VERSIONS cell (has reasonable length)
            if (frame.length < 30 || frame.length === 514) {
                versionsFound++;
            }
        }
    }

    if (profile !== 'none') {
        report('No obvious VERSIONS cell leak',
            versionsFound === 0,
            versionsFound > 0 ? `${versionsFound} potential VERSIONS cells detected` : 'Clean');
    }

    // --- Summary ---
    console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
    console.log(`${failed === 0 ? 'PASS' : 'FAIL'}: Wire traffic ${failed === 0 ? 'does NOT' : 'DOES'} contain detectable Tor signatures\n`);

    process.exit(failed === 0 ? 0 : 1);
}
