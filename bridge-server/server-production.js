#!/usr/bin/env node

/**
 * Production WebSocket → TCP Bridge for Tor WASM
 * 
 * Proxies WebSocket connections from browser WASM clients to raw TCP sockets.
 * Supports both WS (local dev) and WSS (production with SSL).
 * 
 * Usage:
 *   node server-production.js [--port PORT] [--ssl-cert PATH] [--ssl-key PATH]
 */

const WebSocket = require('ws');
const net = require('net');
const tls = require('tls');
const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const { serveCoverSite, setStandardHeaders } = require('./cover-site');
const { handleHealth, startManagementServer } = require('./health-auth');
const logger = require('./logger');
const { TrafficMonitor } = require('./traffic-monitor');

// Static file root (parent directory of bridge-server/)
const STATIC_ROOT = path.resolve(__dirname, '..');

// MIME types for static files
const MIME_TYPES = {
  '.html': 'text/html',
  '.js': 'application/javascript',
  '.wasm': 'application/wasm',
  '.json': 'application/json',
  '.css': 'text/css',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

// Tor consensus/descriptor cache
let consensusCache = null;
let consensusCacheTime = 0;
const CACHE_TTL = 3 * 60 * 60 * 1000; // 3 hours

// Tor directory authorities (verified reachable Feb 2026)
const DIRECTORY_AUTHORITIES = [
  ['gabelmoo', '131.188.40.189:80'],
  ['bastet', '204.13.164.118:80'],
  ['moria1', '128.31.0.34:9131'],
  ['tor26', '86.59.21.38:80'],
  ['dizum', '194.109.206.212:80'],
];

// Parse command line arguments
const args = process.argv.slice(2);
const config = {
  port: 8080,
  sslCert: null,
  sslKey: null,
};

for (let i = 0; i < args.length; i++) {
  switch (args[i]) {
    case '--port':
      config.port = parseInt(args[++i]);
      break;
    case '--ssl-cert':
      config.sslCert = args[++i];
      break;
    case '--ssl-key':
      config.sslKey = args[++i];
      break;
    case '--help':
      console.log(`
WebSocket → TCP Bridge Server

Usage: node server-production.js [options]

Options:
  --port PORT          WebSocket server port (default: 8080)
  --ssl-cert PATH      SSL certificate file for WSS (optional)
  --ssl-key PATH       SSL private key file for WSS (optional)
  --help               Show this help message

Examples:
  # HTTP (local development)
  node server-production.js --port 8080

  # HTTPS with Let's Encrypt
  node server-production.js --port 443 \\
    --ssl-cert /etc/letsencrypt/live/yourdomain.com/fullchain.pem \\
    --ssl-key /etc/letsencrypt/live/yourdomain.com/privkey.pem
`);
      process.exit(0);
  }
}

// Determine if SSL is enabled
const useSSL = config.sslCert && config.sslKey;

// Create HTTP/HTTPS server
let server;
if (useSSL) {
  try {
    const sslOptions = {
      cert: fs.readFileSync(config.sslCert),
      key: fs.readFileSync(config.sslKey),
    };
    server = https.createServer(sslOptions);
    console.log('🔒 SSL enabled');
  } catch (err) {
    console.error('❌ Failed to load SSL certificates:', err.message);
    process.exit(1);
  }
} else {
  server = http.createServer();
  console.log('⚠️  SSL disabled (local development mode)');
}

/**
 * Fetch Tor consensus from directory authority
 */
async function fetchConsensusFromAuthority(name, address) {
  return new Promise((resolve, reject) => {
    const [host, portStr] = address.split(':');
    const port = parseInt(portStr);
    
    console.log(`📡 Fetching consensus from ${name} (${host}:${port})...`);
    
    const socket = net.connect(port, host, () => {
      const request = `GET /tor/status-vote/current/consensus HTTP/1.0\r\nHost: ${host}\r\n\r\n`;
      socket.write(request);
    });
    
    let data = '';
    socket.on('data', (chunk) => {
      data += chunk.toString();
    });
    
    socket.on('end', () => {
      // Parse HTTP response
      const headerEnd = data.indexOf('\r\n\r\n');
      if (headerEnd === -1) {
        reject(new Error('Invalid HTTP response'));
        return;
      }
      
      const body = data.substring(headerEnd + 4);
      console.log(`✅ Received consensus from ${name} (${Math.floor(body.length / 1024)}KB)`);
      resolve(body);
    });
    
    socket.on('error', (err) => {
      console.log(`❌ ${name} failed: ${err.message}`);
      reject(err);
    });
    
    socket.setTimeout(15000);
    socket.on('timeout', () => {
      socket.destroy();
      reject(new Error('Timeout'));
    });
  });
}

/**
 * Fetch relay descriptors from directory authority
 */
async function fetchDescriptors(authority, fingerprints) {
  const [name, address] = authority;
  const [host, portStr] = address.split(':');
  const port = parseInt(portStr);
  
  return new Promise((resolve, reject) => {
    const fpParam = fingerprints.join('+');
    console.log(`🔑 Fetching descriptors for ${fingerprints.length} relays from ${name}...`);
    
    const socket = net.connect(port, host, () => {
      const request = `GET /tor/server/fp/${fpParam} HTTP/1.0\r\nHost: ${host}\r\n\r\n`;
      socket.write(request);
    });
    
    let data = '';
    socket.on('data', (chunk) => {
      data += chunk.toString();
    });
    
    socket.on('end', () => {
      const headerEnd = data.indexOf('\r\n\r\n');
      if (headerEnd === -1) {
        reject(new Error('Invalid HTTP response'));
        return;
      }
      
      const body = data.substring(headerEnd + 4);
      console.log(`✅ Received descriptors from ${name} (${Math.floor(body.length / 1024)}KB)`);
      resolve(body);
    });
    
    socket.on('error', reject);
    socket.setTimeout(20000);
    socket.on('timeout', () => {
      socket.destroy();
      reject(new Error('Timeout'));
    });
  });
}

/**
 * Parse raw consensus text into structured relay array
 * Format: r Nickname B64Identity B64Digest Date Time IP ORPort DirPort
 *         s Flag1 Flag2 ...
 *         w Bandwidth=N
 */
function parseConsensusToRelays(rawConsensus, ntorKeys) {
  const relays = [];
  const lines = rawConsensus.split('\n');
  let current = null;

  for (const line of lines) {
    if (line.startsWith('r ')) {
      // Save previous relay
      if (current) relays.push(current);

      const parts = line.split(/\s+/);
      // r nickname identity digest date time ip orport dirport
      if (parts.length < 9) continue;

      const nickname = parts[1];
      const identityB64 = parts[2];
      const ip = parts[6];
      const orPort = parseInt(parts[7]);
      const dirPort = parseInt(parts[8]) || 0;

      // Convert base64 identity to hex fingerprint
      let fingerprint = '';
      try {
        fingerprint = Buffer.from(identityB64 + '=', 'base64').toString('hex').toUpperCase();
      } catch (e) {
        continue;
      }

      // Look up ntor key
      const ntorKey = ntorKeys[fingerprint] || null;

      current = {
        nickname,
        fingerprint,
        address: ip,
        port: orPort,
        dir_port: dirPort,
        ntor_onion_key: ntorKey,
        bandwidth: 0,
        published: 0,
        flags: {
          exit: false, fast: false, guard: false, hsdir: false,
          running: false, stable: false, v2dir: false, valid: false,
        },
      };
    } else if (line.startsWith('s ') && current) {
      const flags = line.substring(2).split(/\s+/);
      for (const f of flags) {
        const fl = f.toLowerCase();
        if (fl === 'exit') current.flags.exit = true;
        else if (fl === 'fast') current.flags.fast = true;
        else if (fl === 'guard') current.flags.guard = true;
        else if (fl === 'hsdir') current.flags.hsdir = true;
        else if (fl === 'running') current.flags.running = true;
        else if (fl === 'stable') current.flags.stable = true;
        else if (fl === 'v2dir') current.flags.v2dir = true;
        else if (fl === 'valid') current.flags.valid = true;
      }
    } else if (line.startsWith('w ') && current) {
      const bwMatch = line.match(/Bandwidth=(\d+)/);
      if (bwMatch) current.bandwidth = parseInt(bwMatch[1]);
    }
  }

  // Don't forget the last relay
  if (current) relays.push(current);

  // Filter: only running relays with valid fingerprints
  const filtered = relays.filter(r =>
    r.flags.running && r.flags.valid && r.fingerprint.length === 40
  );

  console.log(`📊 Parsed ${relays.length} total relays, ${filtered.length} running+valid`);
  const withKeys = filtered.filter(r => r.ntor_onion_key).length;
  console.log(`🔑 ${withKeys} relays have ntor keys`);

  return filtered;
}

/**
 * Parse descriptors and extract ntor keys
 */
function parseDescriptors(data) {
  const descriptors = {};
  let currentFingerprint = null;
  
  const lines = data.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    
    // Parse fingerprint
    if (trimmed.startsWith('fingerprint ')) {
      const parts = trimmed.split(/\s+/).slice(1);
      currentFingerprint = parts.join('').toUpperCase();
    }
    
    // Parse ntor key (Tor uses base64 without padding, add it for standard decoders)
    else if (trimmed.startsWith('ntor-onion-key ') && currentFingerprint) {
      let key = trimmed.split(/\s+/)[1];
      // Add base64 padding if missing
      const pad = (4 - (key.length % 4)) % 4;
      if (pad > 0) key += '='.repeat(pad);
      descriptors[currentFingerprint] = key;
      console.log(`  📝 ${currentFingerprint.substring(0, 16)}... → ${key.substring(0, 20)}...`);
      currentFingerprint = null; // Reset for next relay
    }
    
    // Reset on new router
    else if (trimmed.startsWith('router ')) {
      currentFingerprint = null;
    }
  }
  
  return descriptors;
}

/**
 * Extract relay fingerprints and flags from raw consensus text.
 * Returns array of { fingerprint, flags: Set<string>, bandwidth }
 */
function extractRelayMeta(rawConsensus) {
  const relays = [];
  const lines = rawConsensus.split('\n');
  let current = null;

  for (const line of lines) {
    if (line.startsWith('r ')) {
      if (current) relays.push(current);
      const parts = line.split(/\s+/);
      if (parts.length < 9) continue;
      try {
        const hex = Buffer.from(parts[2] + '=', 'base64').toString('hex').toUpperCase();
        current = { fingerprint: hex, flags: new Set(), bandwidth: 0 };
      } catch (e) {
        current = null;
      }
    } else if (line.startsWith('s ') && current) {
      line.substring(2).split(/\s+/).forEach(f => current.flags.add(f));
    } else if (line.startsWith('w ') && current) {
      const m = line.match(/Bandwidth=(\d+)/);
      if (m) current.bandwidth = parseInt(m[1]);
    }
  }
  if (current) relays.push(current);
  return relays;
}

/**
 * Fetch and cache Tor consensus with real ntor keys
 */
async function fetchAndCacheConsensus() {
  console.log('\n🔄 Fetching fresh Tor consensus...\n');

  try {
    // Try each authority
    let consensus = null;
    let workingAuthority = null;
    for (const auth of DIRECTORY_AUTHORITIES) {
      try {
        consensus = await fetchConsensusFromAuthority(auth[0], auth[1]);
        workingAuthority = auth;
        break;
      } catch (err) {
        continue;
      }
    }

    if (!consensus) {
      throw new Error('All directory authorities failed');
    }

    // Parse consensus to identify guard and exit relays
    const relayMeta = extractRelayMeta(consensus);
    console.log(`📊 Parsed ${relayMeta.length} relays from consensus`);

    // Prioritize: guards first, then exits, then high-bandwidth middles
    const guards = relayMeta
      .filter(r => r.flags.has('Guard') && r.flags.has('Running') && r.flags.has('Valid'))
      .sort((a, b) => b.bandwidth - a.bandwidth);
    const exits = relayMeta
      .filter(r => r.flags.has('Exit') && r.flags.has('Running') && r.flags.has('Valid') && !r.flags.has('BadExit'))
      .sort((a, b) => b.bandwidth - a.bandwidth);
    const middles = relayMeta
      .filter(r => r.flags.has('Running') && r.flags.has('Valid') && r.flags.has('Fast'))
      .sort((a, b) => b.bandwidth - a.bandwidth);

    console.log(`  Guards: ${guards.length}, Exits: ${exits.length}, Fast middles: ${middles.length}`);

    // Collect fingerprints to fetch: top guards + exits + middles (deduped)
    const seen = new Set();
    const toFetch = [];
    const addFps = (list, limit) => {
      for (const r of list) {
        if (seen.has(r.fingerprint)) continue;
        seen.add(r.fingerprint);
        toFetch.push(r.fingerprint);
        if (toFetch.length >= limit) return;
      }
    };
    addFps(guards, 200);   // Top 200 guards
    addFps(exits, 400);    // + top 200 exits
    addFps(middles, 600);  // + top 200 middles

    console.log(`🔑 Fetching descriptors for ${toFetch.length} relays...`);

    // Fetch in batches of 100
    const allNtorKeys = {};
    const BATCH_SIZE = 100;
    for (let i = 0; i < toFetch.length; i += BATCH_SIZE) {
      const batch = toFetch.slice(i, i + BATCH_SIZE);
      try {
        const data = await fetchDescriptors(workingAuthority, batch);
        const keys = parseDescriptors(data);
        Object.assign(allNtorKeys, keys);
        console.log(`  Batch ${Math.floor(i / BATCH_SIZE) + 1}: ${Object.keys(keys).length} keys (total: ${Object.keys(allNtorKeys).length})`);
      } catch (err) {
        console.log(`  Batch ${Math.floor(i / BATCH_SIZE) + 1} failed: ${err.message}`);
      }
    }

    console.log(`✅ Extracted ${Object.keys(allNtorKeys).length} ntor keys total\n`);

    // Cache the result
    consensusCache = {
      consensus,
      ntorKeys: allNtorKeys,
      parsedRelays: null, // Will be parsed on first request
      timestamp: Date.now(),
    };
    consensusCacheTime = Date.now();

  } catch (err) {
    console.error(`❌ Failed to fetch consensus: ${err.message}\n`);
  }
}

// Create WebSocket server
const wss = new WebSocket.Server({ server });

// Connection counter for logging
let connectionId = 0;
const trafficMonitor = new TrafficMonitor();

// HTTP endpoints
server.on('request', (req, res) => {
  // Enable CORS for all requests
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  
  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }
  
  // Health endpoint — hidden from probers, auth-gated
  if (req.url === '/health' || req.url.startsWith('/health?')) {
    const handled = handleHealth(req, res, {
      status: 'ok',
      uptime: process.uptime(),
      connections: wss.clients.size,
    });
    if (handled) return;
    return serveCoverSite(req, res);
  }

  // Consensus endpoint — auth-gated + obfuscated
  const consensusPath = process.env.CONSENSUS_PATH || '/tor/consensus';
  if (req.url === consensusPath || req.url.startsWith(consensusPath + '?')) {
    // Require auth token if configured
    const authToken = process.env.BRIDGE_AUTH_TOKEN;
    if (authToken) {
      const reqUrl = new URL(req.url, 'http://localhost');
      const token = reqUrl.searchParams.get('token') ||
        (req.headers['authorization'] || '').replace('Bearer ', '');
      if (token !== authToken) {
        return serveCoverSite(req, res);
      }
    }
    if (!consensusCache) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not ready' }));
      return;
    }

    const cacheAge = Date.now() - consensusCacheTime;
    if (cacheAge > CACHE_TTL) {
      fetchAndCacheConsensus().catch(logger.error);
    }

    if (!consensusCache.parsedRelays) {
      consensusCache.parsedRelays = parseConsensusToRelays(
        consensusCache.consensus, consensusCache.ntorKeys || {}
      );
    }

    // Obfuscated response — compress + base64
    const zlib = require('zlib');
    const rawData = {
      consensus: { version: 3, relays: consensusCache.parsedRelays },
      ntorKeys: consensusCache.ntorKeys,
      timestamp: consensusCache.timestamp,
      cacheAge: Math.floor(cacheAge / 1000),
    };
    const compressed = zlib.deflateSync(Buffer.from(JSON.stringify(rawData)));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ v: '2', d: compressed.toString('base64'), t: Date.now() }));
    return;
  }

  // Static file serving (app + pkg) — then cover site fallback
  let reqPath = url.parse(req.url).pathname;
  if (reqPath.endsWith('/')) reqPath += 'index.html';

  const filePath = path.join(STATIC_ROOT, reqPath);
  if (!filePath.startsWith(STATIC_ROOT)) {
    return serveCoverSite(req, res);
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      return serveCoverSite(req, res);
    }
    const ext = path.extname(filePath);
    const mime = MIME_TYPES[ext] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': mime });
    res.end(data);
  });
});

wss.on('connection', (ws, req) => {
  const id = ++connectionId;
  const clientIp = req.socket.remoteAddress;

  console.log(`[${id}] 🔌 New WebSocket connection from ${clientIp}`);
  trafficMonitor.openConnection(id);

  // Parse target address from query string
  const params = url.parse(req.url, true).query;
  const targetAddr = params.addr;

  if (!targetAddr) {
    console.log(`[${id}] ❌ No target address specified`);
    ws.close(1008, 'No target address specified in query string');
    return;
  }

  // Parse host and port
  const match = targetAddr.match(/^([^:]+):(\d+)$/);
  if (!match) {
    console.log(`[${id}] ❌ Invalid address format: ${targetAddr}`);
    ws.close(1008, 'Invalid address format (expected HOST:PORT)');
    return;
  }

  const [, host, portStr] = match;
  const port = parseInt(portStr);

  console.log(`[${id}] 🎯 Target: ${host}:${port}`);

  // Create TLS connection to Tor relay (relays use self-signed certs,
  // authentication happens via CERTS cell inside the Tor protocol)
  let tcpConnected = false;

  console.log(`[${id}] 📞 Connecting to Tor relay via TLS...`);

  const tcpSocket = tls.connect({
    host,
    port,
    rejectUnauthorized: false, // Tor relays use self-signed certificates
  }, () => {
    tcpConnected = true;
    console.log(`[${id}] ✅ TLS connection established to ${host}:${port}`);
    const proto = tcpSocket.getProtocol && tcpSocket.getProtocol();
    if (proto) console.log(`[${id}]    TLS protocol: ${proto}`);
  });

  // TCP → WebSocket
  tcpSocket.on('data', (data) => {
    trafficMonitor.recordFrame(id, data.length, 'down');
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(data);
      console.log(`[${id}] ⬅️  TCP → WS: ${data.length} bytes`);
    }
  });

  // WebSocket → TCP
  ws.on('message', (data) => {
    trafficMonitor.recordFrame(id, data.length, 'up');
    if (tcpConnected) {
      tcpSocket.write(Buffer.from(data));
      console.log(`[${id}] ➡️  WS → TCP: ${data.length} bytes`);
    } else {
      console.log(`[${id}] ⚠️  Received data before TCP connected, buffering...`);
      // Buffer will be sent once connected
      tcpSocket.once('connect', () => {
        tcpSocket.write(Buffer.from(data));
      });
    }
  });

  // Error handling
  tcpSocket.on('error', (err) => {
    console.log(`[${id}] ❌ TCP error: ${err.message}`);
    ws.close(1011, `TCP connection failed: ${err.message}`);
  });

  ws.on('error', (err) => {
    console.log(`[${id}] ❌ WebSocket error: ${err.message}`);
  });

  // Cleanup on close
  tcpSocket.on('close', () => {
    console.log(`[${id}] 🔌 TCP connection closed`);
    if (ws.readyState === WebSocket.OPEN) {
      ws.close(1000, 'TCP connection closed');
    }
  });

  ws.on('close', (code, reason) => {
    console.log(`[${id}] 🔌 WebSocket connection closed (${code}${reason ? ': ' + reason : ''})`);
    trafficMonitor.closeConnection(id);
    if (tcpConnected) {
      tcpSocket.destroy();
    }
  });

  // Set timeouts
  tcpSocket.setTimeout(300000); // 5 minutes idle timeout
  tcpSocket.on('timeout', () => {
    console.log(`[${id}] ⏱️  TCP connection timeout`);
    tcpSocket.destroy();
    ws.close(1000, 'Timeout');
  });
});

// Start management server (localhost-only health endpoint)
startManagementServer(() => ({
  status: 'ok',
  uptime: process.uptime(),
  connections: wss.clients.size,
}));

// Start server
server.listen(config.port, '0.0.0.0', () => {
  logger.banner([
    '',
    `  WebSocket Bridge Server Started`,
    `  Listening on ${useSSL ? 'wss' : 'ws'}://0.0.0.0:${config.port}`,
    `  Ready to proxy connections`,
    '',
  ]);

  // Fetch consensus on startup
  logger.log('Initializing config cache...');
  fetchAndCacheConsensus().catch(err => {
    logger.error(`Failed to fetch initial config: ${err.message}`);
    logger.log('Server will continue without config cache');
  });

  // Refresh consensus every 3 hours
  setInterval(() => {
    logger.log('Time to refresh config cache...');
    fetchAndCacheConsensus().catch(err => {
      logger.error(`Config refresh failed: ${err.message}`);
    });
  }, CACHE_TTL);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n\n🛑 Shutting down gracefully...');
  wss.clients.forEach(client => {
    client.close(1001, 'Server shutting down');
  });
  server.close(() => {
    console.log('✅ Server closed');
    process.exit(0);
  });
});

// Error handling
process.on('uncaughtException', (err) => {
  console.error('💥 Uncaught exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('💥 Unhandled rejection at:', promise, 'reason:', reason);
});

