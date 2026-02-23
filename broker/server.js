#!/usr/bin/env node

/**
 * Signaling Broker for Browser-Native Peer Bridges
 *
 * Matches censored clients with volunteer proxies via WebRTC signaling.
 * The broker facilitates the SDP offer/answer exchange, then forgets everything.
 *
 * Signaling flow:
 *   Proxy  → REGISTER { sdp_offer, ice_candidates, capacity }
 *   Client → REQUEST  {}
 *   Broker → Client:  MATCHED  { proxy_id, sdp_offer, ice_candidates }
 *   Client → ANSWER   { proxy_id, sdp_answer, ice_candidates }
 *   Broker → Proxy:   CONNECT  { sdp_answer, ice_candidates }
 *   (Broker forgets all state after the match)
 *
 * Runs behind Cloudflare with ECH — censors cannot see broker traffic.
 *
 * Usage:
 *   node server.js [--port PORT]
 */

const WebSocket = require('ws');
const http = require('http');
const crypto = require('crypto');

const config = {
  port: parseInt(process.env.PORT) || 8088,
  maxProxies: parseInt(process.env.MAX_PROXIES) || 10000,
  // How long a proxy registration stays valid before expiring
  proxyTtlMs: parseInt(process.env.PROXY_TTL_MS) || 5 * 60 * 1000, // 5 minutes
};

const args = process.argv.slice(2);
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--port') config.port = parseInt(args[++i]);
}

// --- Available proxy pool ---
// Map<proxyId, { ws, sdpOffer, iceCandidates, registeredAt }>
const availableProxies = new Map();

// Map<proxyId, ws> for proxies waiting for a client answer
const pendingProxies = new Map();

// Periodic cleanup of stale proxy registrations
setInterval(() => {
  const now = Date.now();
  let cleaned = 0;
  for (const [id, proxy] of availableProxies) {
    if (now - proxy.registeredAt > config.proxyTtlMs) {
      availableProxies.delete(id);
      cleaned++;
    }
  }
  if (cleaned > 0) {
    console.log(`Cleaned ${cleaned} stale proxy registrations. Active: ${availableProxies.size}`);
  }
}, 60_000);

// --- HTTP + WebSocket server ---
const server = http.createServer();
const wss = new WebSocket.Server({ server });

wss.on('connection', (ws, req) => {
  let role = null; // 'proxy' or 'client'
  let proxyId = null;

  ws.on('message', (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch {
      ws.send(JSON.stringify({ type: 'error', message: 'Invalid JSON' }));
      return;
    }

    switch (msg.type) {
      // --- Proxy registers as available ---
      case 'register': {
        if (!msg.sdp_offer || !msg.ice_candidates) {
          ws.send(JSON.stringify({ type: 'error', message: 'Missing sdp_offer or ice_candidates' }));
          return;
        }

        if (availableProxies.size >= config.maxProxies) {
          ws.send(JSON.stringify({ type: 'error', message: 'Proxy pool full' }));
          return;
        }

        proxyId = crypto.randomBytes(16).toString('hex');
        role = 'proxy';

        availableProxies.set(proxyId, {
          ws,
          sdpOffer: msg.sdp_offer,
          iceCandidates: msg.ice_candidates,
          registeredAt: Date.now(),
        });

        ws.send(JSON.stringify({
          type: 'registered',
          proxy_id: proxyId,
          pool_size: availableProxies.size,
        }));

        console.log(`Proxy ${proxyId.substring(0, 8)} registered. Pool: ${availableProxies.size}`);
        break;
      }

      // --- Client requests a proxy ---
      case 'request': {
        role = 'client';

        // Find an available proxy (FIFO)
        let matched = null;
        let matchedId = null;
        for (const [id, proxy] of availableProxies) {
          if (proxy.ws.readyState === WebSocket.OPEN) {
            matched = proxy;
            matchedId = id;
            break;
          }
          // Clean up dead proxies
          availableProxies.delete(id);
        }

        if (!matched) {
          ws.send(JSON.stringify({ type: 'no_proxies', message: 'No volunteer proxies available' }));
          return;
        }

        // Remove from available pool
        availableProxies.delete(matchedId);
        pendingProxies.set(matchedId, matched.ws);

        // Send proxy's SDP offer to client
        ws.send(JSON.stringify({
          type: 'matched',
          proxy_id: matchedId,
          sdp_offer: matched.sdpOffer,
          ice_candidates: matched.iceCandidates,
        }));

        console.log(`Client matched with proxy ${matchedId.substring(0, 8)}`);
        break;
      }

      // --- Client sends SDP answer back to proxy ---
      case 'answer': {
        if (!msg.proxy_id || !msg.sdp_answer || !msg.ice_candidates) {
          ws.send(JSON.stringify({ type: 'error', message: 'Missing proxy_id, sdp_answer, or ice_candidates' }));
          return;
        }

        const proxyWs = pendingProxies.get(msg.proxy_id);
        if (!proxyWs || proxyWs.readyState !== WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'error', message: 'Proxy no longer available' }));
          pendingProxies.delete(msg.proxy_id);
          return;
        }

        // Forward SDP answer to proxy
        proxyWs.send(JSON.stringify({
          type: 'connect',
          sdp_answer: msg.sdp_answer,
          ice_candidates: msg.ice_candidates,
        }));

        // Forget everything — broker's job is done
        pendingProxies.delete(msg.proxy_id);

        ws.send(JSON.stringify({ type: 'answer_sent' }));
        console.log(`Answer relayed to proxy ${msg.proxy_id.substring(0, 8)}. Match complete.`);
        break;
      }

      default:
        ws.send(JSON.stringify({ type: 'error', message: `Unknown type: ${msg.type}` }));
    }
  });

  ws.on('close', () => {
    // If a proxy disconnects, remove from pool
    if (role === 'proxy' && proxyId) {
      availableProxies.delete(proxyId);
      pendingProxies.delete(proxyId);
    }
  });

  ws.on('error', () => {
    if (role === 'proxy' && proxyId) {
      availableProxies.delete(proxyId);
      pendingProxies.delete(proxyId);
    }
  });
});

// --- HTTP endpoints ---
server.on('request', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') { res.writeHead(200); res.end(); return; }

  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'ok',
      role: 'broker',
      uptime: process.uptime(),
      available_proxies: availableProxies.size,
      pending_matches: pendingProxies.size,
    }));
    return;
  }

  // Stats endpoint for solidarity page
  if (req.url === '/stats') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      proxies: availableProxies.size,
    }));
    return;
  }

  res.writeHead(404);
  res.end('Not found');
});

// --- Start ---
server.listen(config.port, '0.0.0.0', () => {
  console.log('');
  console.log('============================================');
  console.log('  Signaling Broker (Peer Bridge Matching)');
  console.log('============================================');
  console.log(`  Port: ${config.port}`);
  console.log(`  Max proxies: ${config.maxProxies}`);
  console.log(`  Proxy TTL: ${config.proxyTtlMs / 1000}s`);
  console.log(`  Health: http://localhost:${config.port}/health`);
  console.log('============================================');
  console.log('');
  console.log('Waiting for proxy registrations...');
});
