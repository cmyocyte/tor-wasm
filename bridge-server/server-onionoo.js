#!/usr/bin/env node

/**
 * Production WebSocket → TCP Bridge for Tor WASM (with Onionoo API)
 * 
 * Proxies WebSocket connections AND provides Tor consensus via Onionoo API.
 * This works even when directory authorities are blocked!
 * 
 * Usage:
 *   node server-onionoo.js [--port PORT]
 */

const WebSocket = require('ws');
const net = require('net');
const https = require('https');
const http = require('http');
const url = require('url');
const { serveCoverSite } = require('./cover-site');
const { handleHealth, startManagementServer } = require('./health-auth');
const logger = require('./logger');
const { TrafficMonitor } = require('./traffic-monitor');

// Tor consensus/descriptor cache
let consensusCache = null;
let consensusCacheTime = 0;
const CACHE_TTL = 3 * 60 * 60 * 1000; // 3 hours

// Parse command line arguments
const args = process.argv.slice(2);
const config = {
  port: 8080,
};

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--port') {
    config.port = parseInt(args[++i]);
  }
}

// Create HTTP server
const server = http.createServer();

/**
 * Fetch relay data from Tor Project's Onionoo API
 */
async function fetchFromOnionoo() {
  return new Promise((resolve, reject) => {
    console.log('📡 Fetching relay data from Onionoo API...');
    
    https.get('https://onionoo.torproject.org/details?limit=200', (res) => {
      let data = '';
      
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          console.log(`✅ Fetched ${json.relays.length} relays from Onionoo`);
          resolve(json);
        } catch (err) {
          reject(new Error(`Failed to parse Onionoo response: ${err.message}`));
        }
      });
    }).on('error', reject);
  });
}

/**
 * Convert Onionoo relay format to our consensus format
 */
function convertOnionooToConsensus(onionooData) {
  const relays = onionooData.relays
    .filter(r => r.running)  // Only running relays
    .map(r => {
      // Extract IPv4 address and port
      let address = '0.0.0.0';
      let port = 9001;
      
      if (r.or_addresses && r.or_addresses.length > 0) {
        // Find first IPv4 address
        const ipv4 = r.or_addresses.find(a => !a.includes('['));
        if (ipv4) {
          const parts = ipv4.split(':');
          address = parts[0];
          port = parseInt(parts[1]) || 9001;
        }
      }
      
      // Parse flags
      const flags = {
        guard: r.flags?.includes('Guard') || false,
        exit: r.flags?.includes('Exit') || false,
        stable: r.flags?.includes('Stable') || false,
        fast: r.flags?.includes('Fast') || false,
        running: r.running || false,
        valid: r.flags?.includes('Valid') || false,
        v2dir: r.flags?.includes('V2Dir') || false,
        hsdir: r.flags?.includes('HSDir') || false,
      };
      
      return {
        nickname: r.nickname || r.n || 'Unnamed',
        fingerprint: r.fingerprint || r.f || '',
        address: address,
        port: port,
        flags: flags,
        ntor_onion_key: null, // Onionoo doesn't provide this, will use mock
        bandwidth: r.observed_bandwidth || 0,
        country: r.country || null,
      };
    });
  
  // Separate into categories
  const guards = relays.filter(r => r.flags.guard);
  const exits = relays.filter(r => r.flags.exit);
  const middles = relays.filter(r => !r.flags.guard && !r.flags.exit);
  
  console.log(`📊 Relay breakdown: ${guards.length} guards, ${middles.length} middles, ${exits.length} exits`);
  
  return {
    version: 3,
    valid_after: new Date().toISOString(),
    fresh_until: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    valid_until: new Date(Date.now() + 3 * 60 * 60 * 1000).toISOString(),
    relays: relays,
    relay_count: relays.length,
    guard_count: guards.length,
    exit_count: exits.length,
    middle_count: middles.length,
  };
}

/**
 * Fetch and cache Tor consensus from Onionoo
 */
async function fetchAndCacheConsensus() {
  console.log('\n🔄 Fetching fresh Tor consensus from Onionoo...\n');
  
  try {
    const onionooData = await fetchFromOnionoo();
    const consensus = convertOnionooToConsensus(onionooData);
    
    // Cache the result
    consensusCache = {
      consensus: consensus,
      timestamp: Date.now(),
      source: 'onionoo',
    };
    consensusCacheTime = Date.now();
    
    console.log(`✅ Consensus cached: ${consensus.relay_count} relays\n`);
    
  } catch (err) {
    console.error(`❌ Failed to fetch from Onionoo: ${err.message}\n`);
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

    const zlib = require('zlib');
    const rawData = {
      consensus: consensusCache.consensus,
      timestamp: consensusCache.timestamp,
      cacheAge: Math.floor(cacheAge / 1000),
    };
    const compressed = zlib.deflateSync(Buffer.from(JSON.stringify(rawData)));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ v: '2', d: compressed.toString('base64'), t: Date.now() }));
    return;
  }

  // All other paths — serve cover site
  serveCoverSite(req, res);
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

  // Create TCP connection
  const tcpSocket = new net.Socket();
  let tcpConnected = false;

  // Connect to target
  console.log(`[${id}] 📞 Connecting to TCP socket...`);
  
  tcpSocket.connect(port, host, () => {
    tcpConnected = true;
    console.log(`[${id}] ✅ TCP connection established to ${host}:${port}`);
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

// Start server
server.listen(config.port, '0.0.0.0', () => {
  console.log('\n🚀 WebSocket → TCP Bridge Server Started (Onionoo-powered)\n');
  console.log(`📡 Listening on ws://0.0.0.0:${config.port}`);
  console.log(`📡 Ready to proxy WebSocket → TCP connections`);
  console.log(`🌐 Tor consensus endpoint: http://YOUR_DOMAIN:${config.port}/tor/consensus`);
  console.log(`🏥 Health check: http://localhost:${config.port}/health`);
  console.log(`🔥 Using Tor Project's Onionoo API (works everywhere!)`);
  console.log('Press Ctrl+C to stop the server\n');
  
  // Fetch consensus on startup
  console.log('🔄 Initializing Tor consensus cache from Onionoo...\n');
  fetchAndCacheConsensus().catch(err => {
    console.error('❌ Failed to fetch initial consensus:', err.message);
    console.log('⚠️  Server will continue without consensus cache');
    console.log('    Clients can still use WebSocket proxy\n');
  });
  
  // Refresh consensus every 3 hours
  setInterval(() => {
    console.log('\n⏰ Time to refresh consensus cache...');
    fetchAndCacheConsensus().catch(err => {
      console.error('❌ Consensus refresh failed:', err.message);
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

