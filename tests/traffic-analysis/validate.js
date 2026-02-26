#!/usr/bin/env node

/**
 * Traffic Shaping Validation
 *
 * Verifies that traffic profiles produce frame size distributions matching
 * their target applications. Connects to a bridge, captures WebSocket frame
 * sizes, and computes distribution statistics.
 *
 * Usage:
 *   node validate.js --bridge ws://localhost:8080 --profile chat
 *   node validate.js --bridge ws://localhost:8080 --profile ticker
 *   node validate.js --bridge ws://localhost:8080 --profile video
 *   node validate.js --bridge ws://localhost:8080 --profile none
 *
 * Expected results:
 *   none:   >80% frames at exactly 514 bytes (raw Tor cells)
 *   chat:   >80% frames in 50-200 byte range
 *   ticker: >80% frames in 20-100 byte range
 *   video:  >80% frames in 800-1200 byte range
 */

const WebSocket = require('ws');

// --- Configuration ---
const args = process.argv.slice(2);
let bridgeUrl = 'ws://localhost:8080';
let profile = 'none';
let numFrames = 200;

for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
        case '--bridge': bridgeUrl = args[++i]; break;
        case '--profile': profile = args[++i]; break;
        case '--frames': numFrames = parseInt(args[++i]); break;
    }
}

// Profile-specific expected frame size ranges
const PROFILES = {
    none: { min: 514, max: 514, label: 'Raw Tor cells' },
    chat: { min: 50, max: 200, label: 'Chat (WhatsApp-like)' },
    ticker: { min: 20, max: 100, label: 'Ticker (data feed)' },
    video: { min: 800, max: 1200, label: 'Video call' },
};

const expected = PROFILES[profile];
if (!expected) {
    console.error(`Unknown profile: ${profile}. Use: none, chat, ticker, video`);
    process.exit(1);
}

console.log(`\nTraffic Shaping Validation`);
console.log(`=========================`);
console.log(`Bridge:   ${bridgeUrl}`);
console.log(`Profile:  ${profile} (${expected.label})`);
console.log(`Expected: ${expected.min}-${expected.max} byte frames`);
console.log(`Frames:   ${numFrames}\n`);

// --- Capture ---
const frameSizes = [];
let startTime = null;
const interArrivals = [];
let lastFrameTime = null;

const ws = new WebSocket(bridgeUrl);
ws.binaryType = 'arraybuffer';

ws.on('open', () => {
    console.log('Connected to bridge');
    startTime = Date.now();
});

ws.on('message', (data) => {
    const size = data.byteLength || data.length;
    frameSizes.push(size);

    const now = Date.now();
    if (lastFrameTime !== null) {
        interArrivals.push(now - lastFrameTime);
    }
    lastFrameTime = now;

    if (frameSizes.length >= numFrames) {
        ws.close();
    }
});

ws.on('close', () => {
    analyze();
});

ws.on('error', (e) => {
    console.error('WebSocket error:', e.message);
    if (frameSizes.length > 10) {
        analyze();
    } else {
        process.exit(1);
    }
});

// Timeout after 60 seconds
setTimeout(() => {
    console.warn(`\nTimeout: captured ${frameSizes.length}/${numFrames} frames`);
    ws.close();
}, 60000);

// --- Analysis ---
function analyze() {
    if (frameSizes.length === 0) {
        console.error('No frames captured');
        process.exit(1);
    }

    console.log(`\nCaptured ${frameSizes.length} frames in ${((Date.now() - startTime) / 1000).toFixed(1)}s\n`);

    // Frame size statistics
    const sorted = [...frameSizes].sort((a, b) => a - b);
    const mean = frameSizes.reduce((a, b) => a + b, 0) / frameSizes.length;
    const median = sorted[Math.floor(sorted.length / 2)];
    const min = sorted[0];
    const max = sorted[sorted.length - 1];
    const variance = frameSizes.reduce((a, b) => a + (b - mean) ** 2, 0) / frameSizes.length;
    const stddev = Math.sqrt(variance);

    console.log('Frame Size Statistics:');
    console.log(`  Mean:    ${mean.toFixed(1)} bytes`);
    console.log(`  Median:  ${median} bytes`);
    console.log(`  Min:     ${min} bytes`);
    console.log(`  Max:     ${max} bytes`);
    console.log(`  StdDev:  ${stddev.toFixed(1)} bytes`);

    // Distribution check
    const inRange = frameSizes.filter(s => s >= expected.min && s <= expected.max).length;
    const pctInRange = (inRange / frameSizes.length * 100).toFixed(1);
    console.log(`\nFrames in expected range [${expected.min}-${expected.max}]: ${inRange}/${frameSizes.length} (${pctInRange}%)`);

    // Histogram
    const buckets = [0, 50, 100, 200, 400, 514, 600, 800, 1000, 1200, 1500, 2000];
    console.log('\nFrame Size Histogram:');
    for (let i = 0; i < buckets.length; i++) {
        const lo = buckets[i];
        const hi = i + 1 < buckets.length ? buckets[i + 1] : Infinity;
        const count = frameSizes.filter(s => s >= lo && s < hi).length;
        const bar = '#'.repeat(Math.ceil(count / frameSizes.length * 50));
        console.log(`  [${String(lo).padStart(5)}-${String(hi === Infinity ? '...' : hi).padStart(5)}): ${String(count).padStart(4)} ${bar}`);
    }

    // Inter-arrival timing
    if (interArrivals.length > 1) {
        const iaSorted = [...interArrivals].sort((a, b) => a - b);
        const iaMean = interArrivals.reduce((a, b) => a + b, 0) / interArrivals.length;
        const iaMedian = iaSorted[Math.floor(iaSorted.length / 2)];
        console.log('\nInter-Arrival Timing:');
        console.log(`  Mean:    ${iaMean.toFixed(1)}ms`);
        console.log(`  Median:  ${iaMedian}ms`);
        console.log(`  Min:     ${iaSorted[0]}ms`);
        console.log(`  Max:     ${iaSorted[iaSorted.length - 1]}ms`);
    }

    // Pass/fail
    const threshold = 80;
    const passed = parseFloat(pctInRange) >= threshold;
    console.log(`\n${passed ? 'PASS' : 'FAIL'}: ${pctInRange}% of frames in expected range (threshold: ${threshold}%)`);

    // Specific fingerprint check for 'none' profile
    if (profile !== 'none') {
        const exact514 = frameSizes.filter(s => s === 514).length;
        const pct514 = (exact514 / frameSizes.length * 100).toFixed(1);
        console.log(`Tor cell fingerprint: ${exact514} frames at exactly 514 bytes (${pct514}%)`);
        if (parseFloat(pct514) > 10) {
            console.log('WARNING: >10% frames at 514 bytes — profile shaping may not be effective');
        }
    }

    process.exit(passed ? 0 : 1);
}
