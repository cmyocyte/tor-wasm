#!/usr/bin/env node

/**
 * Bridge A — Client-facing bridge that relays to Bridge B.
 *
 * In the two-hop bridge blinding architecture:
 *   Client → Bridge A (sees client IP, NOT guard IP)
 *          → Bridge B (sees guard IP, NOT client IP)
 *          → Guard relay
 *
 * Bridge A does NOT interpret encrypted target addresses. It forwards
 * the client's query string opaquely to Bridge B via WebSocket. This
 * ensures Bridge A cannot learn which guard relay the client connects to.
 *
 * Also serves Tor consensus data (fetched from Tor Collector) so clients
 * can bootstrap without a separate endpoint.
 *
 * Usage:
 *   BRIDGE_B_URL=ws://bridge-b:9090 node server-bridge-a.js [--port PORT]
 */

const WebSocket = require('ws');
const http = require('http');
const https = require('https');
const url = require('url');

// --- Configuration ---
const args = process.argv.slice(2);
const config = {
  port: parseInt(process.env.PORT) || 8080,
  bridgeBUrl: process.env.BRIDGE_B_URL || null,
  authToken: process.env.BRIDGE_AUTH_TOKEN || null,
  rateLimitMax: parseInt(process.env.RATE_LIMIT_MAX) || 10,
  rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 60_000,
  maxConnections: parseInt(process.env.MAX_CONNECTIONS) || 1000,
};

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--port') config.port = parseInt(args[++i]);
  if (args[i] === '--bridge-b') config.bridgeBUrl = args[++i];
}

if (!config.bridgeBUrl) {
  console.error('ERROR: BRIDGE_B_URL environment variable is required.');
  console.error('Example: BRIDGE_B_URL=ws://bridge-b-host:9090 node server-bridge-a.js');
  process.exit(1);
}

console.log(`Configuration:`);
console.log(`  PORT: ${config.port}`);
console.log(`  BRIDGE_B_URL: ${config.bridgeBUrl}`);
console.log(`  AUTH: ${config.authToken ? 'ENABLED' : 'DISABLED'}`);
console.log(`  RATE LIMIT: ${config.rateLimitMax} per ${config.rateLimitWindowMs / 1000}s per IP`);

// --- Rate Limiter ---
const rateLimitMap = new Map();

function checkRateLimit(ip) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);
  if (!entry || (now - entry.firstSeen) > config.rateLimitWindowMs) {
    rateLimitMap.set(ip, { count: 1, firstSeen: now });
    return true;
  }
  entry.count++;
  return entry.count <= config.rateLimitMax;
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of rateLimitMap) {
    if ((now - entry.firstSeen) > config.rateLimitWindowMs * 2) {
      rateLimitMap.delete(ip);
    }
  }
}, 120_000);

// --- Consensus Cache (fetched from Tor Collector) ---
let consensusCache = null;
let consensusCacheTime = 0;
const CACHE_TTL = 3 * 60 * 60 * 1000; // 3 hours

function httpsGet(targetUrl) {
  return new Promise((resolve, reject) => {
    https.get(targetUrl, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => resolve(data));
      res.on('error', reject);
    }).on('error', reject);
  });
}

async function fetchAndCacheConsensus() {
  try {
    // Fetch latest consensus filename
    const indexHtml = await httpsGet('https://collector.torproject.org/recent/relay-descriptors/consensuses/');
    const matches = [...indexHtml.matchAll(/href="([^"]+consensus)"/g)];
    if (matches.length === 0) throw new Error('No consensus files found');
    const filename = matches[matches.length - 1][1];

    // Fetch consensus
    const consensusData = await httpsGet(
      `https://collector.torproject.org/recent/relay-descriptors/consensuses/${filename}`
    );

    // Parse relays
    const relays = [];
    let current = null;
    for (const line of consensusData.split('\n')) {
      const t = line.trim();
      if (t.startsWith('r ')) {
        if (current) relays.push(current);
        const p = t.split(/\s+/);
        if (p.length >= 9) {
          current = {
            nickname: p[1],
            fingerprint: Buffer.from(p[2], 'base64').toString('hex').toUpperCase(),
            address: p[6],
            port: parseInt(p[7]),
            flags: { guard: false, exit: false, stable: false, fast: false, running: false, valid: false },
            ntor_onion_key: null,
          };
        }
      } else if (t.startsWith('s ') && current) {
        for (const flag of t.substring(2).split(/\s+/)) {
          const lf = flag.toLowerCase();
          if (current.flags.hasOwnProperty(lf)) current.flags[lf] = true;
        }
      }
    }
    if (current) relays.push(current);

    // Fetch descriptors for ntor keys (last 10 files)
    const descIndex = await httpsGet('https://collector.torproject.org/recent/relay-descriptors/server-descriptors/');
    const descFiles = [...descIndex.matchAll(/href="([^"]+server-descriptors)"/g)].map(m => m[1]).slice(-10);

    const ntorKeys = {};
    for (const df of descFiles) {
      try {
        const descData = await httpsGet(
          `https://collector.torproject.org/recent/relay-descriptors/server-descriptors/${df}`
        );
        let fp = null;
        for (const line of descData.split('\n')) {
          const t = line.trim();
          if (t.startsWith('fingerprint ')) fp = t.substring(12).split(/\s+/).join('').toUpperCase();
          else if (t.startsWith('ntor-onion-key ') && fp) {
            const key = t.substring(15).trim();
            ntorKeys[fp] = key + '='.repeat((4 - key.length % 4) % 4);
          }
          else if (t.startsWith('router ')) fp = null;
        }
      } catch (_) { /* skip failed descriptor files */ }
    }

    // Merge ntor keys
    let merged = 0;
    for (const r of relays) {
      if (ntorKeys[r.fingerprint]) { r.ntor_onion_key = ntorKeys[r.fingerprint]; merged++; }
    }

    consensusCache = {
      consensus: {
        version: 3,
        valid_after: new Date().toISOString(),
        fresh_until: new Date(Date.now() + 3600000).toISOString(),
        valid_until: new Date(Date.now() + 10800000).toISOString(),
        relays,
        relay_count: relays.length,
        guard_count: relays.filter(r => r.flags.guard).length,
        exit_count: relays.filter(r => r.flags.exit).length,
        relays_with_ntor_keys: merged,
      },
      timestamp: Date.now(),
      cacheAge: 0,
      source: 'collector',
    };
    consensusCacheTime = Date.now();
    console.log(`Consensus cached: ${relays.length} relays, ${merged} ntor keys`);
  } catch (err) {
    console.error(`Consensus fetch failed: ${err.message}`);
  }
}

// --- HTTP + WebSocket Server ---
const server = http.createServer();
const wss = new WebSocket.Server({ server });

let connectionId = 0;

wss.on('connection', (clientWs, req) => {
  const id = ++connectionId;
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress;
  console.log(`[${id}] Client connection from ${clientIp}`);

  // Global limit
  if (wss.clients.size > config.maxConnections) {
    console.log(`[${id}] Connection limit reached`);
    clientWs.close(1013, 'Server at capacity');
    return;
  }

  // Rate limit
  if (!checkRateLimit(clientIp)) {
    console.log(`[${id}] Rate limited: ${clientIp}`);
    clientWs.close(1008, 'Rate limit exceeded');
    return;
  }

  // Auth
  const query = url.parse(req.url, true).query;
  if (config.authToken) {
    const token = req.headers['authorization']?.replace('Bearer ', '') || query.token;
    if (token !== config.authToken) {
      console.log(`[${id}] Auth failed`);
      clientWs.close(1008, 'Authentication required');
      return;
    }
  }

  // Forward the entire query string opaquely to Bridge B.
  // Bridge A does NOT interpret ?dest= or ?addr= — it just relays.
  const queryString = url.parse(req.url).search || '';
  const bridgeBFullUrl = config.bridgeBUrl + queryString;

  console.log(`[${id}] Forwarding to Bridge B: ${config.bridgeBUrl}?...`);

  // Open WebSocket to Bridge B
  const bridgeWs = new WebSocket(bridgeBFullUrl);
  let bridgeReady = false;
  let pendingMessages = [];

  bridgeWs.on('open', () => {
    console.log(`[${id}] Bridge B connected`);
    bridgeReady = true;
    // Flush any messages that arrived before Bridge B was ready
    for (const msg of pendingMessages) bridgeWs.send(msg);
    pendingMessages = [];
  });

  // Client → Bridge B (queue if Bridge B not yet connected)
  clientWs.on('message', (data) => {
    if (bridgeReady) {
      bridgeWs.send(data);
    } else {
      pendingMessages.push(data);
    }
  });

  // Bridge B → Client
  bridgeWs.on('message', (data) => {
    if (clientWs.readyState === WebSocket.OPEN) {
      clientWs.send(data);
    }
  });

  // Cleanup on either side closing
  clientWs.on('close', () => {
    console.log(`[${id}] Client disconnected`);
    bridgeWs.close();
  });

  bridgeWs.on('close', () => {
    console.log(`[${id}] Bridge B disconnected`);
    if (clientWs.readyState === WebSocket.OPEN) clientWs.close();
  });

  clientWs.on('error', (err) => {
    console.log(`[${id}] Client error: ${err.message}`);
    bridgeWs.close();
  });

  bridgeWs.on('error', (err) => {
    console.log(`[${id}] Bridge B error: ${err.message}`);
    if (clientWs.readyState === WebSocket.OPEN) clientWs.close(1011, 'Bridge B error');
  });
});

// --- HTTP Endpoints ---
server.on('request', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') { res.writeHead(200); res.end(); return; }

  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'ok',
      role: 'bridge-a',
      uptime: process.uptime(),
      connections: wss.clients.size,
      maxConnections: config.maxConnections,
      authEnabled: !!config.authToken,
      consensusCached: !!consensusCache,
      relayCount: consensusCache ? consensusCache.consensus.relay_count : 0,
    }, null, 2));
    return;
  }

  if (req.url === '/tor/consensus') {
    if (!consensusCache) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Consensus not yet fetched' }));
      return;
    }
    consensusCache.cacheAge = Math.floor((Date.now() - consensusCache.timestamp) / 1000);
    if (Date.now() - consensusCacheTime > CACHE_TTL) {
      fetchAndCacheConsensus().catch(() => {});
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(consensusCache, null, 2));
    return;
  }

  res.writeHead(404);
  res.end('Not found');
});

// --- Start ---
server.listen(config.port, '0.0.0.0', () => {
  console.log('');
  console.log('============================================');
  console.log('  Bridge A (Client-Facing, Blinded Relay)');
  console.log('============================================');
  console.log(`  Port: ${config.port}`);
  console.log(`  Bridge B: ${config.bridgeBUrl}`);
  console.log(`  WebSocket: ws://localhost:${config.port}?dest=<blob>`);
  console.log(`  Health: http://localhost:${config.port}/health`);
  console.log(`  Consensus: http://localhost:${config.port}/tor/consensus`);
  console.log('============================================');
  console.log('');

  fetchAndCacheConsensus().catch(() => {});
  setInterval(() => fetchAndCacheConsensus().catch(() => {}), CACHE_TTL);
});
