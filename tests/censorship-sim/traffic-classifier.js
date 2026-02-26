#!/usr/bin/env node

/**
 * Traffic Classifier Simulation
 *
 * Simple statistical classifier that attempts to distinguish Tor traffic
 * from legitimate application traffic. Tests that our traffic shaping
 * profiles produce distributions that defeat classification.
 *
 * Classification features:
 *   1. Frame size distribution (mean, stddev, % at 514 bytes)
 *   2. Inter-arrival timing distribution
 *   3. Burst rate (frames per second)
 *   4. Frame size regularity (coefficient of variation)
 *
 * Expected behavior:
 *   - Profile "none":  classifier SHOULD detect Tor (raw cells)
 *   - Profile "chat":  classifier should NOT detect Tor
 *   - Profile "ticker": classifier should NOT detect Tor
 *   - Profile "video":  classifier should NOT detect Tor
 *
 * Usage:
 *   node traffic-classifier.js --bridge ws://localhost:8080 --profile chat
 *   node traffic-classifier.js --bridge ws://localhost:8080 --profile none
 */

const WebSocket = require('ws');

const args = process.argv.slice(2);
let bridgeUrl = 'ws://localhost:8080';
let profile = 'chat';
let numFrames = 200;

for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
        case '--bridge': bridgeUrl = args[++i]; break;
        case '--profile': profile = args[++i]; break;
        case '--frames': numFrames = parseInt(args[++i]); break;
    }
}

// Profile-specific expected ranges
const PROFILES = {
    none:   { min: 514, max: 514, label: 'Raw Tor cells' },
    chat:   { min: 50,  max: 200, label: 'Chat (WhatsApp-like)' },
    ticker: { min: 20,  max: 100, label: 'Ticker (data feed)' },
    video:  { min: 800, max: 1200, label: 'Video call' },
};

const expected = PROFILES[profile];
if (!expected) {
    console.error(`Unknown profile: ${profile}`);
    process.exit(1);
}

console.log('\nTraffic Classifier Simulation');
console.log('============================');
console.log(`Bridge:   ${bridgeUrl}`);
console.log(`Profile:  ${profile} (${expected.label})`);
console.log(`Frames:   ${numFrames}\n`);

// --- Capture ---

const frameSizes = [];
const interArrivals = [];
let lastTime = null;

const ws = new WebSocket(bridgeUrl);
ws.binaryType = 'arraybuffer';

ws.on('open', () => console.log('Connected, capturing traffic...'));

ws.on('message', (data) => {
    const size = data.byteLength || data.length;
    frameSizes.push(size);

    const now = Date.now();
    if (lastTime !== null) {
        interArrivals.push(now - lastTime);
    }
    lastTime = now;

    if (frameSizes.length >= numFrames) {
        ws.close();
    }
});

ws.on('close', () => classify());
ws.on('error', (e) => {
    console.error('WebSocket error:', e.message);
    if (frameSizes.length > 20) classify();
    else process.exit(1);
});

setTimeout(() => {
    console.warn(`Timeout: captured ${frameSizes.length}/${numFrames} frames`);
    ws.close();
}, 60000);

// --- Classification ---

function classify() {
    if (frameSizes.length < 10) {
        console.error('Too few frames for classification');
        process.exit(1);
    }

    console.log(`\nCaptured ${frameSizes.length} frames\n`);

    // --- Feature Extraction ---

    // 1. Frame size statistics
    const mean = frameSizes.reduce((a, b) => a + b, 0) / frameSizes.length;
    const variance = frameSizes.reduce((a, b) => a + (b - mean) ** 2, 0) / frameSizes.length;
    const stddev = Math.sqrt(variance);
    const cv = mean > 0 ? stddev / mean : 0; // Coefficient of variation

    // 2. 514-byte frame percentage (Tor fingerprint)
    const pct514 = frameSizes.filter(s => s === 514).length / frameSizes.length;

    // 3. Frame size in expected range
    const pctInRange = frameSizes.filter(s => s >= expected.min && s <= expected.max).length / frameSizes.length;

    // 4. Inter-arrival timing stats
    let iaMean = 0, iaStddev = 0;
    if (interArrivals.length > 0) {
        iaMean = interArrivals.reduce((a, b) => a + b, 0) / interArrivals.length;
        const iaVar = interArrivals.reduce((a, b) => a + (b - iaMean) ** 2, 0) / interArrivals.length;
        iaStddev = Math.sqrt(iaVar);
    }

    // 5. Burst rate (frames/sec)
    const totalTime = interArrivals.reduce((a, b) => a + b, 0);
    const fps = totalTime > 0 ? (frameSizes.length / totalTime * 1000) : 0;

    // --- Print Features ---
    console.log('Classification Features:');
    console.log(`  Frame size mean:    ${mean.toFixed(1)}`);
    console.log(`  Frame size stddev:  ${stddev.toFixed(1)}`);
    console.log(`  Frame size CV:      ${cv.toFixed(3)}`);
    console.log(`  % at 514 bytes:     ${(pct514 * 100).toFixed(1)}%`);
    console.log(`  % in expected range: ${(pctInRange * 100).toFixed(1)}%`);
    console.log(`  Inter-arrival mean: ${iaMean.toFixed(1)}ms`);
    console.log(`  Inter-arrival std:  ${iaStddev.toFixed(1)}ms`);
    console.log(`  Burst rate:         ${fps.toFixed(1)} frames/sec`);

    // --- Decision Tree Classifier ---
    // A simple classifier that a censor might use

    let torScore = 0;
    const reasons = [];

    // Rule 1: >30% frames at exactly 514 bytes → strong Tor signal
    if (pct514 > 0.3) {
        torScore += 40;
        reasons.push(`${(pct514 * 100).toFixed(0)}% frames at 514 bytes`);
    } else if (pct514 > 0.1) {
        torScore += 20;
        reasons.push(`${(pct514 * 100).toFixed(0)}% frames at 514 bytes`);
    }

    // Rule 2: Very low frame size variance (CV < 0.1) → uniform cell sizes
    if (cv < 0.1) {
        torScore += 30;
        reasons.push(`Low variance (CV=${cv.toFixed(3)})`);
    }

    // Rule 3: Mean frame size close to 514 → Tor cells
    if (Math.abs(mean - 514) < 50) {
        torScore += 20;
        reasons.push(`Mean ${mean.toFixed(0)} near 514`);
    }

    // Rule 4: Frame sizes clustered outside expected range
    if (pctInRange < 0.5 && profile !== 'none') {
        torScore += 10;
        reasons.push(`Only ${(pctInRange * 100).toFixed(0)}% in expected range`);
    }

    const isTor = torScore >= 50;

    console.log('\nClassifier Decision:');
    console.log(`  Tor score: ${torScore}/100`);
    console.log(`  Verdict:   ${isTor ? 'TOR DETECTED' : 'LEGITIMATE TRAFFIC'}`);
    if (reasons.length > 0) {
        console.log(`  Reasons:   ${reasons.join('; ')}`);
    }

    // --- Pass/Fail ---
    let testPassed;

    if (profile === 'none') {
        // Without shaping, classifier SHOULD detect Tor
        testPassed = isTor;
        console.log(`\n${testPassed ? 'PASS' : 'FAIL'}: Unmasked Tor traffic ${isTor ? 'correctly' : 'incorrectly'} classified`);
    } else {
        // With shaping, classifier should NOT detect Tor
        testPassed = !isTor;
        console.log(`\n${testPassed ? 'PASS' : 'FAIL'}: ${profile} profile ${!isTor ? 'successfully defeats' : 'FAILS to defeat'} classifier (score: ${torScore})`);

        // Additional check: frames should be in expected range
        const rangePass = pctInRange >= 0.6;
        console.log(`${rangePass ? 'PASS' : 'FAIL'}: ${(pctInRange * 100).toFixed(1)}% frames in expected range [${expected.min}-${expected.max}] (threshold: 60%)`);

        if (!rangePass) testPassed = false;
    }

    process.exit(testPassed ? 0 : 1);
}
