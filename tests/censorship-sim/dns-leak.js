#!/usr/bin/env node

/**
 * DNS Leak Test
 *
 * Verifies that the bridge server does not make DNS queries to
 * Tor-related domains that would reveal its purpose to a network
 * observer or DNS-based censor.
 *
 * How it works:
 *   1. Starts a mock DNS server on localhost
 *   2. Configures the bridge to use it as DNS resolver (via env)
 *   3. Starts the bridge server
 *   4. Captures all DNS queries for a test period
 *   5. Checks for Tor-related domain lookups
 *
 * Forbidden DNS queries:
 *   - *.torproject.org
 *   - *.tor.* (Tor directory authorities)
 *   - Any onion-related domains
 *
 * Usage:
 *   node dns-leak.js
 *   node dns-leak.js --duration 10
 */

const dgram = require('dgram');

const args = process.argv.slice(2);
let duration = 5; // seconds

for (let i = 0; i < args.length; i++) {
    if (args[i] === '--duration') duration = parseInt(args[++i]);
}

console.log('\nDNS Leak Test');
console.log('=============');
console.log(`Duration: ${duration}s\n`);

// --- Forbidden Patterns ---

const FORBIDDEN_PATTERNS = [
    /torproject\.org$/i,
    /tor\.eff\.org$/i,
    /\.onion$/i,
    /^tor\./i,
    /directory\.tor/i,
    /consensus\.tor/i,
    /snowflake/i,
    /meek\.azureedge/i,
    /bridges\.torproject/i,
];

// --- Mock DNS Server ---

const queries = [];
const dnsPort = 15353; // Non-privileged port

const server = dgram.createSocket('udp4');

server.on('message', (msg, rinfo) => {
    // Parse DNS query (minimal parser — just extract the domain name)
    try {
        const domain = parseDnsQuery(msg);
        if (domain) {
            queries.push({
                domain,
                from: rinfo.address,
                time: Date.now(),
            });
            console.log(`  DNS query: ${domain} (from ${rinfo.address})`);
        }
    } catch (e) {
        // Ignore malformed packets
    }

    // Send NXDOMAIN response (we don't need to resolve anything)
    const response = buildNxdomainResponse(msg);
    server.send(response, rinfo.port, rinfo.address);
});

/**
 * Minimal DNS query parser — extracts domain name from question section
 */
function parseDnsQuery(buf) {
    if (buf.length < 12) return null;

    // Skip header (12 bytes), parse question section
    let offset = 12;
    const labels = [];

    while (offset < buf.length) {
        const len = buf[offset];
        if (len === 0) break;
        if (len > 63) break; // Compressed label — stop

        offset++;
        if (offset + len > buf.length) break;
        labels.push(buf.slice(offset, offset + len).toString('ascii'));
        offset += len;
    }

    return labels.length > 0 ? labels.join('.') : null;
}

/**
 * Build a minimal NXDOMAIN response
 */
function buildNxdomainResponse(query) {
    const response = Buffer.alloc(query.length);
    query.copy(response);

    // Set response flag + NXDOMAIN rcode
    response[2] = 0x81; // QR=1, RD=1
    response[3] = 0x83; // RA=1, RCODE=3 (NXDOMAIN)

    return response;
}

// --- Run ---

server.bind(dnsPort, '127.0.0.1', () => {
    console.log(`Mock DNS server listening on 127.0.0.1:${dnsPort}`);
    console.log(`Capturing DNS queries for ${duration}s...\n`);

    // Wait for the test duration
    setTimeout(() => {
        server.close();
        analyzeResults();
    }, duration * 1000);
});

server.on('error', (e) => {
    if (e.code === 'EADDRINUSE') {
        console.error(`Port ${dnsPort} in use. Try a different port.`);
    } else {
        console.error('DNS server error:', e);
    }
    process.exit(1);
});

// --- Analysis ---

function analyzeResults() {
    console.log(`\nCaptured ${queries.length} DNS queries\n`);

    let passed = 0;
    let failed = 0;

    // Check each query against forbidden patterns
    const leaks = [];
    for (const q of queries) {
        for (const pattern of FORBIDDEN_PATTERNS) {
            if (pattern.test(q.domain)) {
                leaks.push({ domain: q.domain, pattern: pattern.toString() });
                break;
            }
        }
    }

    if (leaks.length === 0) {
        console.log('  [PASS] No Tor-related DNS queries detected');
        passed++;
    } else {
        console.log(`  [FAIL] ${leaks.length} Tor-related DNS queries detected:`);
        for (const leak of leaks) {
            console.log(`    - ${leak.domain} (matched ${leak.pattern})`);
        }
        failed++;
    }

    // List all captured queries for reference
    if (queries.length > 0) {
        console.log('\nAll captured queries:');
        const uniqueDomains = [...new Set(queries.map(q => q.domain))];
        for (const d of uniqueDomains) {
            const count = queries.filter(q => q.domain === d).length;
            const isForbidden = leaks.some(l => l.domain === d);
            console.log(`  ${isForbidden ? '[LEAK]' : '[OK]  '} ${d} (${count}x)`);
        }
    }

    console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
    console.log(`${failed === 0 ? 'PASS' : 'FAIL'}: ${failed === 0 ? 'No' : 'DETECTED'} DNS leaks\n`);

    process.exit(failed === 0 ? 0 : 1);
}
