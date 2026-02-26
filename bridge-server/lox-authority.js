/**
 * Lox Bridge Authority — Trust-Tiered Bridge Distribution
 *
 * Phase 1: HMAC-based credentials (fast, simple, same API as future BBS+ version).
 * Phase 2 (future): Replace HMAC with BBS+ blind signatures for unlinkability.
 *
 * Trust tiers:
 *   Level 0: New user (shared bridges, ~1000 users/bridge, expect blocking)
 *   Level 1: 7 days use (semi-private, ~100 users/bridge)
 *   Level 2: 30 days use (private, ~10 users/bridge)
 *   Level 3: 90 days use (reserved, ~3 users/bridge)
 *
 * Enumeration resistance:
 *   - Censors who create many accounts get level-0 bridges (expendable)
 *   - Level-0 bridges get blocked → expected, users migrate to level 1
 *   - Reaching level 1+ requires 7+ days of sustained use (expensive for censors)
 *   - Private bridges (level 2+) effectively invisible to censors
 *
 * API:
 *   POST /lox/open-invite     → initial credential (rate-limited)
 *   POST /lox/get-bridge      → exchange credential for bridge URL
 *   POST /lox/trust-migration → upgrade trust level
 *   POST /lox/check-blockage  → report blocked bridge, get migration token
 *
 * All endpoints hidden behind cover site for unauthenticated requests.
 */

const http = require('http');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// --- Configuration ---

const PORT = parseInt(process.env.LOX_PORT || '9090', 10);
const SERVER_SECRET = process.env.LOX_SECRET || crypto.randomBytes(32).toString('hex');
const BRIDGE_POOLS_FILE = process.env.BRIDGE_POOLS_FILE || path.join(__dirname, 'bridge-pools.json');
const RATE_LIMIT_WINDOW_MS = 24 * 60 * 60 * 1000; // 24 hours
const RATE_LIMIT_MAX = 3; // max invites per IP per window

// Trust migration thresholds (days)
const TRUST_THRESHOLDS = [0, 7, 30, 90];
const MAX_TRUST_LEVEL = 3;

// --- In-Memory State ---

// Credential store: id → { trust_level, created_at, bridge_fingerprint, last_use }
const credentials = new Map();

// Rate limiter: IP → [timestamp, ...]
const rateLimits = new Map();

// Blockage reports: bridge_fingerprint → count
const blockageReports = new Map();

// --- Bridge Pool ---

let bridgePools = {
    0: [], // Shared bridges (expendable)
    1: [], // Semi-private
    2: [], // Private
    3: [], // Reserved
};

function loadBridgePools() {
    try {
        if (fs.existsSync(BRIDGE_POOLS_FILE)) {
            const data = JSON.parse(fs.readFileSync(BRIDGE_POOLS_FILE, 'utf8'));
            bridgePools = data;
            const total = Object.values(bridgePools).flat().length;
            console.log(`Loaded ${total} bridges from ${BRIDGE_POOLS_FILE}`);
        } else {
            console.log(`No bridge pools file at ${BRIDGE_POOLS_FILE}, using empty pools`);
            // Create a sample pools file
            const sample = {
                0: [
                    { url: 'wss://shared-1.example.com', fingerprint: 'shared-1' },
                    { url: 'wss://shared-2.example.com', fingerprint: 'shared-2' },
                ],
                1: [
                    { url: 'wss://semi-private-1.example.com', fingerprint: 'semi-1' },
                ],
                2: [
                    { url: 'wss://private-1.example.com', fingerprint: 'priv-1' },
                ],
                3: [
                    { url: 'wss://reserved-1.example.com', fingerprint: 'res-1' },
                ],
            };
            fs.writeFileSync(BRIDGE_POOLS_FILE, JSON.stringify(sample, null, 2));
            bridgePools = sample;
            console.log(`Created sample bridge pools at ${BRIDGE_POOLS_FILE}`);
        }
    } catch (e) {
        console.error(`Failed to load bridge pools: ${e.message}`);
    }
}

// --- Credential Functions ---

function generateCredential(id) {
    // HMAC(server_secret, id) — Phase 1 only. Phase 2 replaces with BBS+ blind sig.
    const hmac = crypto.createHmac('sha256', SERVER_SECRET);
    hmac.update(id);
    return hmac.digest('hex');
}

function validateCredential(id, credential) {
    const expected = generateCredential(id);
    return crypto.timingSafeEqual(
        Buffer.from(credential, 'hex'),
        Buffer.from(expected, 'hex')
    );
}

function selectBridge(trustLevel) {
    // Select from the appropriate pool (fall back to lower tiers if empty)
    for (let level = trustLevel; level >= 0; level--) {
        const pool = bridgePools[level];
        if (pool && pool.length > 0) {
            // Round-robin selection (simple, avoids hotspots)
            const idx = Math.floor(Math.random() * pool.length);
            return pool[idx];
        }
    }
    return null;
}

function isRateLimited(ip) {
    const now = Date.now();
    let timestamps = rateLimits.get(ip) || [];

    // Clean old entries
    timestamps = timestamps.filter(ts => now - ts < RATE_LIMIT_WINDOW_MS);
    rateLimits.set(ip, timestamps);

    return timestamps.length >= RATE_LIMIT_MAX;
}

function recordRateLimit(ip) {
    const timestamps = rateLimits.get(ip) || [];
    timestamps.push(Date.now());
    rateLimits.set(ip, timestamps);
}

function canMigrate(credId, targetLevel) {
    const cred = credentials.get(credId);
    if (!cred) return false;
    if (cred.trust_level >= targetLevel) return false;
    if (targetLevel > MAX_TRUST_LEVEL) return false;

    const daysSinceCreation = (Date.now() - cred.created_at) / (24 * 60 * 60 * 1000);
    return daysSinceCreation >= TRUST_THRESHOLDS[targetLevel];
}

// --- Request Handlers ---

function handleOpenInvite(req, res, body, clientIp) {
    if (isRateLimited(clientIp)) {
        res.writeHead(429, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'rate_limited', retry_after_hours: 24 }));
        return;
    }

    const id = crypto.randomBytes(16).toString('hex');
    const credential = generateCredential(id);

    credentials.set(id, {
        trust_level: 0,
        created_at: Date.now(),
        bridge_fingerprint: null,
        last_use: Date.now(),
    });

    recordRateLimit(clientIp);

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
        id,
        credential,
        trust_level: 0,
    }));
}

function handleGetBridge(req, res, body) {
    let parsed;
    try {
        parsed = JSON.parse(body);
    } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid_json' }));
        return;
    }

    const { id, credential } = parsed;
    if (!id || !credential) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'missing_fields' }));
        return;
    }

    if (!validateCredential(id, credential)) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid_credential' }));
        return;
    }

    const cred = credentials.get(id);
    if (!cred) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'unknown_credential' }));
        return;
    }

    const bridge = selectBridge(cred.trust_level);
    if (!bridge) {
        res.writeHead(503, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'no_bridges_available' }));
        return;
    }

    // Update last use and assign bridge
    cred.last_use = Date.now();
    cred.bridge_fingerprint = bridge.fingerprint;

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
        bridge_url: bridge.url,
        bridge_fingerprint: bridge.fingerprint,
        trust_level: cred.trust_level,
    }));
}

function handleTrustMigration(req, res, body) {
    let parsed;
    try {
        parsed = JSON.parse(body);
    } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid_json' }));
        return;
    }

    const { id, credential } = parsed;
    if (!id || !credential) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'missing_fields' }));
        return;
    }

    if (!validateCredential(id, credential)) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid_credential' }));
        return;
    }

    const cred = credentials.get(id);
    if (!cred) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'unknown_credential' }));
        return;
    }

    const nextLevel = cred.trust_level + 1;
    if (!canMigrate(id, nextLevel)) {
        const daysNeeded = TRUST_THRESHOLDS[nextLevel] || '?';
        const daysSoFar = ((Date.now() - cred.created_at) / (24 * 60 * 60 * 1000)).toFixed(1);
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            error: 'not_eligible',
            current_level: cred.trust_level,
            days_needed: daysNeeded,
            days_used: parseFloat(daysSoFar),
        }));
        return;
    }

    // Upgrade
    cred.trust_level = nextLevel;
    cred.last_use = Date.now();

    // Generate new credential for upgraded level
    const newCredential = generateCredential(id);

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
        id,
        credential: newCredential,
        trust_level: nextLevel,
    }));
}

function handleCheckBlockage(req, res, body) {
    let parsed;
    try {
        parsed = JSON.parse(body);
    } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid_json' }));
        return;
    }

    const { id, credential, bridge_fingerprint } = parsed;
    if (!id || !credential || !bridge_fingerprint) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'missing_fields' }));
        return;
    }

    if (!validateCredential(id, credential)) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid_credential' }));
        return;
    }

    const cred = credentials.get(id);
    if (!cred) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'unknown_credential' }));
        return;
    }

    // Record blockage report
    const count = (blockageReports.get(bridge_fingerprint) || 0) + 1;
    blockageReports.set(bridge_fingerprint, count);

    // Generate migration token — allows getting a new bridge without losing trust
    const migrationToken = crypto.randomBytes(16).toString('hex');

    // Clear the blocked bridge from the credential
    cred.bridge_fingerprint = null;

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
        blocked: true,
        reports: count,
        migration_token: migrationToken,
        trust_level: cred.trust_level,
    }));
}

// --- Cover Site (for unauthenticated requests) ---

function serveCoverPage(res) {
    res.writeHead(200, {
        'Content-Type': 'text/html',
        'Server': 'nginx/1.24.0',
    });
    res.end(`<!DOCTYPE html>
<html><head><title>Welcome</title></head>
<body><h1>Welcome</h1><p>Nothing to see here.</p></body>
</html>`);
}

// --- Server ---

function startServer() {
    loadBridgePools();

    const server = http.createServer((req, res) => {
        // Strip identifying headers
        res.removeHeader('X-Powered-By');

        const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim()
            || req.socket.remoteAddress
            || '0.0.0.0';

        // Only POST to /lox/* endpoints with correct Content-Type
        if (req.method === 'POST' && req.url.startsWith('/lox/')) {
            const contentType = req.headers['content-type'] || '';
            if (!contentType.includes('application/json')) {
                serveCoverPage(res);
                return;
            }

            let body = '';
            req.on('data', chunk => { body += chunk; });
            req.on('end', () => {
                if (body.length > 4096) {
                    res.writeHead(413);
                    res.end();
                    return;
                }

                switch (req.url) {
                    case '/lox/open-invite':
                        handleOpenInvite(req, res, body, clientIp);
                        break;
                    case '/lox/get-bridge':
                        handleGetBridge(req, res, body);
                        break;
                    case '/lox/trust-migration':
                        handleTrustMigration(req, res, body);
                        break;
                    case '/lox/check-blockage':
                        handleCheckBlockage(req, res, body);
                        break;
                    default:
                        serveCoverPage(res);
                }
            });
        } else {
            // All non-Lox requests → cover page (active probe resistance)
            serveCoverPage(res);
        }
    });

    server.listen(PORT, () => {
        console.log(`Lox authority listening on :${PORT}`);
        console.log(`Bridge pools: ${Object.values(bridgePools).flat().length} bridges across ${Object.keys(bridgePools).length} tiers`);
    });

    return server;
}

// --- Cleanup (periodic) ---

setInterval(() => {
    const now = Date.now();
    const staleThreshold = 180 * 24 * 60 * 60 * 1000; // 180 days

    let cleaned = 0;
    for (const [id, cred] of credentials) {
        if (now - cred.last_use > staleThreshold) {
            credentials.delete(id);
            cleaned++;
        }
    }

    // Clean rate limit entries
    for (const [ip, timestamps] of rateLimits) {
        const fresh = timestamps.filter(ts => now - ts < RATE_LIMIT_WINDOW_MS);
        if (fresh.length === 0) {
            rateLimits.delete(ip);
        } else {
            rateLimits.set(ip, fresh);
        }
    }

    if (cleaned > 0) {
        console.log(`Cleaned ${cleaned} stale credentials`);
    }
}, 60 * 60 * 1000); // Every hour

// --- Exports (for testing) ---

module.exports = {
    startServer,
    generateCredential,
    validateCredential,
    selectBridge,
    isRateLimited,
    canMigrate,
    credentials,
    bridgePools,
    TRUST_THRESHOLDS,
};

// Start if run directly
if (require.main === module) {
    startServer();
}
