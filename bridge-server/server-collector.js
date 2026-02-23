#!/usr/bin/env node

/**
 * Production Tor Bridge Server with Tor Collector API
 * 
 * Fetches consensus + descriptors (WITH ntor keys!) from Tor Collector HTTPS mirror
 * This works even when directory authorities are blocked!
 * 
 * Usage:
 *   node server-collector.js [--port PORT]
 */

const WebSocket = require('ws');
const net = require('net');
const tls = require('tls');
const https = require('https');
const http = require('http');
const url = require('url');

// Tor consensus/descriptor cache
let consensusCache = null;
let consensusCacheTime = 0;
const CACHE_TTL = 3 * 60 * 60 * 1000; // 3 hours

// Parse command line arguments and environment variables
const args = process.argv.slice(2);
const config = {
  // PORT env var is standard for cloud platforms (Railway, Heroku, Render, etc.)
  port: parseInt(process.env.PORT) || 8080,
  // Allow custom CORS origins for production
  corsOrigins: process.env.CORS_ORIGINS ? process.env.CORS_ORIGINS.split(',') : ['*'],
  // Optional auth token — if set, all WebSocket connections must provide it
  authToken: process.env.BRIDGE_AUTH_TOKEN || null,
  // Rate limiting: max new WebSocket connections per IP per window
  rateLimitMax: parseInt(process.env.RATE_LIMIT_MAX) || 10,
  rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 60_000, // 1 minute
  // Global connection limit
  maxConnections: parseInt(process.env.MAX_CONNECTIONS) || 1000,
};

// --- Rate Limiter ---
// Tracks connection attempts per IP with TTL cleanup
const rateLimitMap = new Map(); // IP -> { count, firstSeen }

function checkRateLimit(ip) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);

  if (!entry || (now - entry.firstSeen) > config.rateLimitWindowMs) {
    // New window
    rateLimitMap.set(ip, { count: 1, firstSeen: now });
    return true; // allowed
  }

  entry.count++;
  if (entry.count > config.rateLimitMax) {
    return false; // rate limited
  }
  return true; // allowed
}

// Periodic cleanup of stale rate limit entries (every 2 minutes)
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of rateLimitMap) {
    if ((now - entry.firstSeen) > config.rateLimitWindowMs * 2) {
      rateLimitMap.delete(ip);
    }
  }
}, 120_000);

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--port') {
    config.port = parseInt(args[++i]);
  }
}

console.log(`🔧 Configuration:`);
console.log(`   PORT: ${config.port} (from ${process.env.PORT ? 'env' : 'default'})`);
console.log(`   CORS: ${config.corsOrigins.join(', ')}`);
console.log(`   AUTH: ${config.authToken ? 'ENABLED (token set)' : 'DISABLED (anonymous)'}`);
console.log(`   RATE LIMIT: ${config.rateLimitMax} connections per ${config.rateLimitWindowMs / 1000}s per IP`);
console.log(`   MAX CONNECTIONS: ${config.maxConnections}`);

// Create HTTP server
const server = http.createServer();

/**
 * Fetch the latest consensus file name from Tor Collector
 */
async function fetchLatestConsensusFilename() {
  return new Promise((resolve, reject) => {
    https.get('https://collector.torproject.org/recent/relay-descriptors/consensuses/', (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        // Parse HTML for most recent consensus file
        const regex = /href="([^"]+consensus)"/g;
        const matches = [...data.matchAll(regex)];
        if (matches.length === 0) {
          reject(new Error('No consensus files found'));
          return;
        }
        const latestFile = matches[matches.length - 1][1];
        resolve(latestFile);
      });
      res.on('error', reject);
    }).on('error', reject);
  });
}

/**
 * Fetch consensus from Tor Collector
 */
async function fetchConsensus(filename) {
  return new Promise((resolve, reject) => {
    const consensusUrl = `https://collector.torproject.org/recent/relay-descriptors/consensuses/${filename}`;
    console.log(`📡 Fetching consensus: ${filename}...`);
    
    https.get(consensusUrl, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        console.log(`✅ Consensus fetched: ${(data.length / 1024).toFixed(1)}KB`);
        resolve(data);
      });
      res.on('error', reject);
    }).on('error', reject);
  });
}

/**
 * Fetch the latest server descriptors file names from Tor Collector
 * Returns multiple files to get more ntor keys (they update frequently)
 */
async function fetchLatestDescriptorsFilenames(count = 10) {
  return new Promise((resolve, reject) => {
    https.get('https://collector.torproject.org/recent/relay-descriptors/server-descriptors/', (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        // Parse HTML for descriptor files
        const regex = /href="([^"]+server-descriptors)"/g;
        const matches = [...data.matchAll(regex)];
        if (matches.length === 0) {
          reject(new Error('No descriptor files found'));
          return;
        }
        // Get the most recent N files (they're sorted by date)
        const files = matches.map(m => m[1]).slice(-count);
        console.log(`📁 Found ${matches.length} descriptor files, using last ${files.length}`);
        resolve(files);
      });
      res.on('error', reject);
    }).on('error', reject);
  });
}

/**
 * Fetch server descriptors from Tor Collector
 */
async function fetchDescriptors(filename) {
  return new Promise((resolve, reject) => {
    const descriptorsUrl = `https://collector.torproject.org/recent/relay-descriptors/server-descriptors/${filename}`;
    console.log(`🔑 Fetching descriptors: ${filename}...`);
    
    https.get(descriptorsUrl, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        console.log(`✅ Descriptors fetched: ${(data.length / 1024).toFixed(1)}KB`);
        resolve(data);
      });
      res.on('error', reject);
    }).on('error', reject);
  });
}

/**
 * Parse consensus to extract relay information
 */
function parseConsensus(consensusData) {
  const lines = consensusData.split('\n');
  const relays = [];
  
  let currentRelay = null;
  
  for (const line of lines) {
    const trimmed = line.trim();
    
    // r nickname identity digest published IP ORPort DirPort
    if (trimmed.startsWith('r ')) {
      if (currentRelay) {
        relays.push(currentRelay);
      }
      
      const parts = trimmed.split(/\s+/);
      if (parts.length >= 9) {
        currentRelay = {
          nickname: parts[1],
          fingerprint: Buffer.from(parts[2], 'base64').toString('hex').toUpperCase(),
          address: parts[6],
          port: parseInt(parts[7]),
          flags: {
            guard: false,
            exit: false,
            stable: false,
            fast: false,
            running: false,
            valid: false,
            v2dir: false,
            hsdir: false,
          },
          ntor_onion_key: null,
        };
      }
    }
    
    // s [flags...]
    else if (trimmed.startsWith('s ') && currentRelay) {
      const flags = trimmed.substring(2).split(/\s+/);
      for (const flag of flags) {
        const lowerFlag = flag.toLowerCase();
        if (currentRelay.flags.hasOwnProperty(lowerFlag)) {
          currentRelay.flags[lowerFlag] = true;
        }
      }
    }
  }
  
  if (currentRelay) {
    relays.push(currentRelay);
  }
  
  console.log(`📊 Parsed ${relays.length} relays from consensus`);
  
  return relays;
}

/**
 * Parse descriptors to extract ntor-onion-key values
 */
function parseDescriptors(descriptorData) {
  const lines = descriptorData.split('\n');
  const ntorKeys = {};
  
  let currentFingerprint = null;
  
  for (const line of lines) {
    const trimmed = line.trim();
    
    // fingerprint XXXX XXXX ...
    if (trimmed.startsWith('fingerprint ')) {
      const fpParts = trimmed.substring(12).split(/\s+/);
      currentFingerprint = fpParts.join('').toUpperCase();
    }
    
    // ntor-onion-key BASE64KEY
    else if (trimmed.startsWith('ntor-onion-key ') && currentFingerprint) {
      const ntorKey = trimmed.substring(15).trim();  // Trim whitespace from base64 key
      // Normalize base64 padding (add = if needed to make length multiple of 4)
      const paddedKey = ntorKey + '='.repeat((4 - ntorKey.length % 4) % 4);
      ntorKeys[currentFingerprint] = paddedKey;
    }
    
    // router starts a new descriptor
    else if (trimmed.startsWith('router ')) {
      currentFingerprint = null;
    }
  }
  
  console.log(`🔑 Extracted ${Object.keys(ntorKeys).length} ntor keys from descriptors`);
  
  return ntorKeys;
}

/**
 * Fetch and cache consensus + descriptors from Tor Collector
 */
async function fetchAndCacheConsensus() {
  console.log('\n🔄 Fetching fresh Tor consensus from Collector...\n');
  
  try {
    // Fetch latest consensus
    const consensusFilename = await fetchLatestConsensusFilename();
    const consensusData = await fetchConsensus(consensusFilename);
    
    // Parse consensus to get relay list
    const relays = parseConsensus(consensusData);
    
    // Fetch MULTIPLE server descriptor files to get more ntor keys
    const descriptorFilenames = await fetchLatestDescriptorsFilenames(15);
    console.log(`📥 Fetching ${descriptorFilenames.length} descriptor files...`);
    
    // Merge all ntor keys from all descriptor files
    const ntorKeys = {};
    for (const filename of descriptorFilenames) {
      try {
        const descriptorData = await fetchDescriptors(filename);
        const keys = parseDescriptors(descriptorData);
        Object.assign(ntorKeys, keys);
        console.log(`   ✓ ${filename}: ${Object.keys(keys).length} keys`);
      } catch (err) {
        console.warn(`   ⚠️ ${filename}: ${err.message}`);
      }
    }
    
    console.log(`\n🔑 Total unique ntor keys collected: ${Object.keys(ntorKeys).length}`);
    
    // Merge ntor keys into relay data
    let keysMerged = 0;
    for (const relay of relays) {
      if (ntorKeys[relay.fingerprint]) {
        relay.ntor_onion_key = ntorKeys[relay.fingerprint];
        keysMerged++;
      }
    }
    
    console.log(`✅ Merged ${keysMerged} ntor keys into relay data\n`);
    
    // Count relays with keys by type
    const guardsWithKeys = relays.filter(r => r.flags.guard && r.ntor_onion_key).length;
    const exitsWithKeys = relays.filter(r => r.flags.exit && r.ntor_onion_key).length;
    console.log(`📊 Guards with ntor keys: ${guardsWithKeys}`);
    console.log(`📊 Exits with ntor keys: ${exitsWithKeys}`);
    
    // Create consensus object
    const consensus = {
      version: 3,
      valid_after: new Date().toISOString(),
      fresh_until: new Date(Date.now() + 3600000).toISOString(),
      valid_until: new Date(Date.now() + 10800000).toISOString(),
      relays: relays,
      relay_count: relays.length,
      guard_count: relays.filter(r => r.flags.guard).length,
      exit_count: relays.filter(r => r.flags.exit).length,
      middle_count: relays.filter(r => !r.flags.guard && !r.flags.exit).length,
      relays_with_ntor_keys: keysMerged,
    };
    
    // Cache it
    consensusCache = {
      consensus,
      timestamp: Date.now(),
      cacheAge: 0,
      source: 'collector',
    };
    consensusCacheTime = Date.now();
    
    console.log('\n✅ Consensus cached successfully!\n');
    
  } catch (err) {
    console.error(`❌ Failed to fetch consensus: ${err.message}\n`);
  }
}

// =======================
// WebSocket → TCP Proxy
// =======================

const wss = new WebSocket.Server({ server });

let connectionId = 0;

wss.on('connection', (ws, req) => {
  const id = ++connectionId;
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress;
  console.log(`[${id}] 🔌 New WebSocket connection from ${clientIp}`);

  // --- Global connection limit ---
  if (wss.clients.size > config.maxConnections) {
    console.log(`[${id}] ❌ Global connection limit reached (${wss.clients.size}/${config.maxConnections})`);
    ws.close(1013, 'Server at capacity');
    return;
  }

  // --- Per-IP rate limiting ---
  if (!checkRateLimit(clientIp)) {
    console.log(`[${id}] ❌ Rate limited: ${clientIp}`);
    ws.close(1008, 'Rate limit exceeded');
    return;
  }

  // Extract query string (used for both auth and target)
  const query = url.parse(req.url, true).query;

  // --- Authentication ---
  if (config.authToken) {
    const authHeader = req.headers['authorization'];
    const queryToken = query.token;
    const providedToken = authHeader?.replace('Bearer ', '') || queryToken;

    if (providedToken !== config.authToken) {
      console.log(`[${id}] ❌ Authentication failed from ${clientIp}`);
      ws.close(1008, 'Authentication required');
      return;
    }
    console.log(`[${id}] ✅ Authenticated`);
  }

  const target = query.addr;
  
  if (!target) {
    console.log(`[${id}] ❌ No target address specified`);
    ws.close(1008, 'Target address required');
    return;
  }
  
  console.log(`[${id}] 🎯 Target: ${target}`);
  
  // Parse target address
  const [host, portStr] = target.split(':');
  const port = parseInt(portStr);
  
  if (!host || !port || isNaN(port)) {
    console.log(`[${id}] ❌ Invalid target address: ${target}`);
    ws.close(1008, 'Invalid target address');
    return;
  }
  
  // Connect to target TCP socket
  console.log(`[${id}] 📞 Connecting to TCP socket...`);
  const tcpSocket = net.connect(port, host);
  
  let tlsSocket = null;
  let queuedData = []; // Queue for data received before TLS is ready
  
  tcpSocket.on('connect', () => {
    console.log(`[${id}] ✅ TCP connection established to ${host}:${port}`);
    
    // Disable Nagle algorithm for immediate delivery
    tcpSocket.setNoDelay(true);
    
    console.log(`[${id}] 🔐 Upgrading to TLS...`);
    
    // Upgrade to TLS
    // Note: Don't send SNI for IP addresses (Tor relays may reject it)
    const tlsOptions = {
      socket: tcpSocket,
      rejectUnauthorized: false, // Tor uses self-signed certs
      minVersion: 'TLSv1.2',
      maxVersion: 'TLSv1.3',
      // Only set servername if host is not an IP address
      ...(!/^\d+\.\d+\.\d+\.\d+$/.test(host) ? { servername: host } : {}),
    };
    tlsSocket = tls.connect(tlsOptions);
    
    tlsSocket.on('secureConnect', () => {
      console.log(`[${id}] ✅ TLS handshake complete`);
      console.log(`[${id}]    Protocol: ${tlsSocket.getProtocol()}`);
      console.log(`[${id}]    Cipher: ${tlsSocket.getCipher()?.name}`);
      
      // Send any queued data
      if (queuedData.length > 0) {
        console.log(`[${id}] 📤 Sending ${queuedData.length} queued messages`);
        for (const data of queuedData) {
          tlsSocket.write(data);
        }
        queuedData = [];
      }
    });
    
    // Forward TLS data to WebSocket
    tlsSocket.on('data', (data) => {
      console.log(`[${id}] ⬅️  TLS → WS: ${data.length} bytes`);
      // Debug: show first 20 bytes for 514-byte cells (likely CREATE2 response)
      if (data.length === 514) {
        console.log(`[${id}]    First 20: ${data.slice(0, 20).toString('hex')}`);
      }
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(data);
      }
    });
    
    // Handle TLS errors
    tlsSocket.on('error', (err) => {
      console.log(`[${id}] ❌ TLS error: ${err.message}`);
      if (ws.readyState === WebSocket.OPEN) {
        ws.close(1011, `TLS error: ${err.message}`);
      }
    });
    
    // Handle TLS close
    tlsSocket.on('close', () => {
      console.log(`[${id}] 🔌 TLS connection closed`);
      if (ws.readyState === WebSocket.OPEN) {
        ws.close();
      }
    });
  });
  
  // Forward WebSocket messages to TLS (after TLS is established)
  ws.on('message', (data) => {
    if (tlsSocket && tlsSocket.authorized !== undefined) {
      // TLS is ready, send immediately
      console.log(`[${id}] ➡️  WS → TLS: ${data.length} bytes`);
      // Debug: show first 20 bytes for 514-byte cells (likely CREATE2)
      if (data.length === 514) {
        const buf = Buffer.from(data);
        const cmd = buf[4];
        console.log(`[${id}]    Cell: CircID=${buf.readUInt32BE(0)}, Cmd=${cmd}`);
        if (cmd === 10) {
          // CREATE2 cell - show handshake data
          console.log(`[${id}]    HTYPE=${buf.readUInt16BE(5)}, HLEN=${buf.readUInt16BE(7)}`);
          console.log(`[${id}]    ID (fingerprint): ${buf.slice(9, 29).toString('hex')}`);
          console.log(`[${id}]    B (ntor key): ${buf.slice(29, 61).toString('hex')}`);
          console.log(`[${id}]    X (client pub): ${buf.slice(61, 93).toString('hex')}`);
        }
      }
      tlsSocket.write(data);
    } else {
      // TLS not ready yet, queue the data
      console.log(`[${id}] ⚠️  TLS not ready, queuing ${data.length} bytes`);
      queuedData.push(data);
    }
  });
  
  // Handle TCP errors
  tcpSocket.on('error', (err) => {
    console.log(`[${id}] ❌ TCP error: ${err.message}`);
    if (ws.readyState === WebSocket.OPEN) {
      ws.close(1011, `TCP error: ${err.message}`);
    }
  });
  
  // Handle WebSocket close
  ws.on('close', () => {
    console.log(`[${id}] 🔌 WebSocket connection closed`);
    if (tlsSocket) tlsSocket.destroy();
    tcpSocket.destroy();
  });
  
  // Handle WebSocket errors
  ws.on('error', (err) => {
    console.log(`[${id}] ❌ WebSocket error: ${err.message}`);
    if (tlsSocket) tlsSocket.destroy();
    tcpSocket.destroy();
  });
});

// ======================
// HTTP Request Handler
// ======================

server.on('request', (req, res) => {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  
  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }
  
  if (req.url === '/health') {
    const cacheAge = consensusCache ? Math.floor((Date.now() - consensusCache.timestamp) / 1000) : null;
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'ok',
      uptime: process.uptime(),
      connections: wss.clients.size,
      maxConnections: config.maxConnections,
      rateLimitTracked: rateLimitMap.size,
      authEnabled: !!config.authToken,
      consensusCached: !!consensusCache,
      consensusAge: cacheAge,
      relayCount: consensusCache ? consensusCache.consensus.relay_count : 0,
      source: 'collector',
    }, null, 2));
    return;
  }
  
  if (req.url === '/tor/consensus') {
    if (!consensusCache) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: 'Consensus not yet fetched',
        message: 'Please wait a few seconds and try again',
      }));
      return;
    }
    
    // Update cache age
    consensusCache.cacheAge = Math.floor((Date.now() - consensusCache.timestamp) / 1000);
    
    // Trigger background refresh if stale
    if (Date.now() - consensusCacheTime > CACHE_TTL) {
      console.log('⏰ Consensus cache is stale, triggering background refresh...');
      fetchAndCacheConsensus().catch(err => {
        console.error(`Background refresh failed: ${err.message}`);
      });
    }
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(consensusCache, null, 2));
    return;
  }
  
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not found');
});

// Start server
server.listen(config.port, '0.0.0.0', () => {
  console.log('');
  console.log('============================================');
  console.log('🌉 Tor Bridge Server (Tor Collector)');
  console.log('============================================');
  console.log(`Port: ${config.port}`);
  console.log(`WebSocket: ws://localhost:${config.port}?addr=HOST:PORT`);
  console.log(`Health: http://localhost:${config.port}/health`);
  console.log(`Consensus: http://localhost:${config.port}/tor/consensus`);
  console.log('============================================');
  console.log('');
  
  // Initial consensus fetch
  console.log('🔄 Initializing Tor consensus cache...\n');
  fetchAndCacheConsensus().catch(err => {
    console.error(`Initial consensus fetch failed: ${err.message}`);
  });
  
  // Periodic refresh (every 3 hours)
  setInterval(() => {
    fetchAndCacheConsensus().catch(err => {
      console.error(`Scheduled refresh failed: ${err.message}`);
    });
  }, CACHE_TTL);
});

