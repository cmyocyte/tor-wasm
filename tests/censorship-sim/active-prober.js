#!/usr/bin/env node

/**
 * Active Prober Simulation
 *
 * Simulates a censor's active prober against our bridge server.
 * Verifies that no HTTP endpoint, header, or response body reveals
 * that this is a Tor bridge rather than a normal website.
 *
 * What censors do:
 *   1. Scan for known Tor fingerprints in headers (X-Powered-By: Express)
 *   2. Probe common Tor endpoints (/tor/consensus, /tor/server, etc.)
 *   3. Send garbage WebSocket upgrades to see error messages
 *   4. Check server banners and error pages
 *
 * Usage:
 *   node active-prober.js --bridge http://localhost:8080
 *   node active-prober.js --bridge https://bridge.example.com
 */

const http = require('http');
const https = require('https');

const args = process.argv.slice(2);
let bridgeUrl = 'http://localhost:8080';

for (let i = 0; i < args.length; i++) {
    if (args[i] === '--bridge') bridgeUrl = args[++i];
}

const parsed = new URL(bridgeUrl);
const client = parsed.protocol === 'https:' ? https : http;

let passed = 0;
let failed = 0;
const results = [];

function report(name, ok, details) {
    const status = ok ? 'PASS' : 'FAIL';
    results.push({ name, status, details });
    if (ok) passed++; else failed++;
    console.log(`  [${status}] ${name}${details ? ': ' + details : ''}`);
}

// --- Forbidden strings in any response ---
const FORBIDDEN_STRINGS = [
    'tor', 'onion', 'relay', 'circuit', 'guard',
    'exit node', 'directory authority', 'consensus',
    'arti', 'obfs4', 'snowflake', 'meek',
    'X-Powered-By', 'Express',
];

// Case-insensitive check (but skip common false positives like "editor", "motor", etc.)
function containsForbidden(text) {
    const lower = text.toLowerCase();
    for (const word of FORBIDDEN_STRINGS) {
        const wl = word.toLowerCase();
        // Word boundary check to avoid false positives
        const regex = new RegExp(`\\b${wl.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i');
        if (regex.test(lower)) {
            // Filter common false positives
            if (wl === 'tor' && (lower.includes('editor') || lower.includes('motor') || lower.includes('history') || lower.includes('store') || lower.includes('factor'))) continue;
            return word;
        }
    }
    return null;
}

function makeRequest(path, options = {}) {
    return new Promise((resolve, reject) => {
        const reqOpts = {
            hostname: parsed.hostname,
            port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
            path: path,
            method: options.method || 'GET',
            headers: options.headers || {},
            timeout: 5000,
            rejectUnauthorized: false,
        };

        const req = client.request(reqOpts, (res) => {
            let body = '';
            res.on('data', (chunk) => body += chunk);
            res.on('end', () => resolve({
                statusCode: res.statusCode,
                headers: res.headers,
                body,
            }));
        });

        req.on('error', (e) => reject(e));
        req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });

        if (options.body) req.write(options.body);
        req.end();
    });
}

async function runTests() {
    console.log('\nActive Prober Simulation');
    console.log('========================');
    console.log(`Target: ${bridgeUrl}\n`);

    // --- Test 1: Root page returns HTML cover site ---
    try {
        const res = await makeRequest('/');
        report('GET / returns HTML',
            res.statusCode === 200 && res.headers['content-type']?.includes('text/html'),
            `Status: ${res.statusCode}, CT: ${res.headers['content-type']}`);

        // Check body for forbidden strings
        const forbidden = containsForbidden(res.body);
        report('Root page has no Tor-identifying strings',
            !forbidden,
            forbidden ? `Found: "${forbidden}"` : 'Clean');
    } catch (e) {
        report('GET / reachable', false, e.message);
    }

    // --- Test 2: Server header looks like nginx ---
    try {
        const res = await makeRequest('/');
        const server = res.headers['server'] || '';
        report('Server header is nginx',
            server.startsWith('nginx'),
            `Server: "${server}"`);

        report('No X-Powered-By header',
            !res.headers['x-powered-by'],
            res.headers['x-powered-by'] || 'Not present');
    } catch (e) {
        report('Server headers check', false, e.message);
    }

    // --- Test 3: Known Tor endpoints return cover page ---
    const torEndpoints = [
        '/tor/consensus',
        '/tor/server/all',
        '/tor/status-vote/current/consensus',
        '/tor/keys/all',
        '/tor/micro/d/',
        '/tor/',
    ];

    for (const ep of torEndpoints) {
        try {
            const res = await makeRequest(ep);
            // Should return cover page (HTML), not JSON or consensus data
            const isSafe = res.headers['content-type']?.includes('text/html') ||
                           res.statusCode === 404 || res.statusCode === 403;
            const forbidden = containsForbidden(res.body);
            report(`${ep} returns cover page`,
                isSafe && !forbidden,
                `Status: ${res.statusCode}, CT: ${res.headers['content-type']?.split(';')[0]}${forbidden ? `, LEAK: "${forbidden}"` : ''}`);
        } catch (e) {
            report(`${ep} safe`, false, e.message);
        }
    }

    // --- Test 4: Random paths return cover page ---
    const randomPaths = [
        '/api/v1/health',
        '/admin',
        '/debug',
        '/.env',
        '/config.json',
        '/health',
    ];

    for (const p of randomPaths) {
        try {
            const res = await makeRequest(p);
            const isCover = res.headers['content-type']?.includes('text/html') ||
                            res.statusCode === 404;
            report(`${p} returns cover page`,
                isCover,
                `Status: ${res.statusCode}, CT: ${res.headers['content-type']?.split(';')[0]}`);
        } catch (e) {
            report(`${p} safe`, false, e.message);
        }
    }

    // --- Test 5: POST with random data doesn't crash ---
    try {
        const garbage = Buffer.alloc(256);
        for (let i = 0; i < garbage.length; i++) garbage[i] = Math.random() * 256;

        const res = await makeRequest('/', {
            method: 'POST',
            body: garbage,
            headers: { 'Content-Type': 'application/octet-stream' },
        });
        report('POST with garbage data handled safely',
            res.statusCode < 500,
            `Status: ${res.statusCode}`);
    } catch (e) {
        report('POST garbage handled', false, e.message);
    }

    // --- Test 6: All response headers clean ---
    try {
        const res = await makeRequest('/');
        const headerStr = Object.entries(res.headers)
            .map(([k, v]) => `${k}: ${v}`)
            .join('\n');
        const forbidden = containsForbidden(headerStr);
        report('Response headers have no Tor-identifying strings',
            !forbidden,
            forbidden ? `Found: "${forbidden}"` : 'Clean');
    } catch (e) {
        report('Headers check', false, e.message);
    }

    // --- Test 7: favicon.ico returns something ---
    try {
        const res = await makeRequest('/favicon.ico');
        report('/favicon.ico returns valid response',
            res.statusCode === 200 || res.statusCode === 404,
            `Status: ${res.statusCode}, Size: ${res.body.length}`);
    } catch (e) {
        report('/favicon.ico', false, e.message);
    }

    // --- Test 8: robots.txt returns valid response ---
    try {
        const res = await makeRequest('/robots.txt');
        report('/robots.txt returns valid response',
            res.statusCode === 200 || res.statusCode === 404,
            `Status: ${res.statusCode}`);
        if (res.statusCode === 200) {
            const forbidden = containsForbidden(res.body);
            report('/robots.txt has no Tor strings',
                !forbidden,
                forbidden ? `Found: "${forbidden}"` : 'Clean');
        }
    } catch (e) {
        report('/robots.txt', false, e.message);
    }

    // --- Summary ---
    console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
    console.log(`${failed === 0 ? 'PASS' : 'FAIL'}: Bridge server is ${failed === 0 ? '' : 'NOT '}indistinguishable from a normal website\n`);

    process.exit(failed === 0 ? 0 : 1);
}

runTests().catch((e) => {
    console.error('Test runner error:', e);
    process.exit(1);
});
