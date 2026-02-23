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
const https = require('https');
const http = require('http');
const fs = require('fs');
const url = require('url');

// Tor consensus/descriptor cache
let consensusCache = null;
let consensusCacheTime = 0;
const CACHE_TTL = 3 * 60 * 60 * 1000; // 3 hours

// Tor directory authorities
const DIRECTORY_AUTHORITIES = [
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
    const fpParam = fingerprints.slice(0, 20).join('+');
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
    
    // Parse ntor key
    else if (trimmed.startsWith('ntor-onion-key ') && currentFingerprint) {
      const key = trimmed.split(/\s+/)[1];
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
 * Fetch and cache Tor consensus with real ntor keys
 */
async function fetchAndCacheConsensus() {
  console.log('\n🔄 Fetching fresh Tor consensus...\n');
  
  try {
    // Try each authority
    let consensus = null;
    for (const [name, address] of DIRECTORY_AUTHORITIES) {
      try {
        consensus = await fetchConsensusFromAuthority(name, address);
        break; // Success!
      } catch (err) {
        // Try next authority
        continue;
      }
    }
    
    if (!consensus) {
      throw new Error('All directory authorities failed');
    }
    
    // Parse consensus to extract fingerprints
    const fingerprintRegex = /^r\s+\S+\s+(\S+)/gm;
    const fingerprints = [];
    let match;
    
    while ((match = fingerprintRegex.exec(consensus)) !== null) {
      // Base64 decode fingerprint (it's in consensus as base64)
      try {
        const b64 = match[1];
        const hex = Buffer.from(b64, 'base64').toString('hex').toUpperCase();
        fingerprints.push(hex);
      } catch (e) {
        // Skip invalid fingerprints
      }
    }
    
    console.log(`📊 Parsed ${fingerprints.length} relays from consensus`);
    
    // Fetch descriptors for first 50 relays (mix of guards/middles/exits)
    if (fingerprints.length > 0) {
      try {
        const descriptorData = await fetchDescriptors(DIRECTORY_AUTHORITIES[0], fingerprints.slice(0, 50));
        const ntorKeys = parseDescriptors(descriptorData);
        
        console.log(`✅ Extracted ${Object.keys(ntorKeys).length} ntor keys\n`);
        
        // Cache the result
        consensusCache = {
          consensus,
          ntorKeys,
          timestamp: Date.now(),
        };
        consensusCacheTime = Date.now();
        
      } catch (err) {
        console.log(`⚠️  Failed to fetch descriptors: ${err.message}`);
        console.log(`   Using consensus without ntor keys\n`);
        
        // Cache consensus even without descriptors
        consensusCache = {
          consensus,
          ntorKeys: {},
          timestamp: Date.now(),
        };
        consensusCacheTime = Date.now();
      }
    }
    
  } catch (err) {
    console.error(`❌ Failed to fetch consensus: ${err.message}\n`);
  }
}

// Create WebSocket server
const wss = new WebSocket.Server({ server });

// Connection counter for logging
let connectionId = 0;

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
  
  // Health check endpoint
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'ok',
      uptime: process.uptime(),
      connections: wss.clients.size,
      consensusCached: consensusCache !== null,
      consensusAge: consensusCache ? Math.floor((Date.now() - consensusCacheTime) / 1000) : null,
    }));
    return;
  }
  
  // Tor consensus endpoint
  if (req.url === '/tor/consensus') {
    if (!consensusCache) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: 'Consensus not yet fetched',
        message: 'Please wait a moment and try again',
      }));
      return;
    }
    
    // Check if cache is stale
    const cacheAge = Date.now() - consensusCacheTime;
    if (cacheAge > CACHE_TTL) {
      // Trigger refresh in background
      fetchAndCacheConsensus().catch(console.error);
    }
    
    // Return cached data
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      consensus: consensusCache.consensus,
      ntorKeys: consensusCache.ntorKeys,
      timestamp: consensusCache.timestamp,
      cacheAge: Math.floor(cacheAge / 1000),
    }));
    return;
  }
  
  // 404 for all other routes
  res.writeHead(404);
  res.end('Not Found');
});

wss.on('connection', (ws, req) => {
  const id = ++connectionId;
  const clientIp = req.socket.remoteAddress;
  
  console.log(`[${id}] 🔌 New WebSocket connection from ${clientIp}`);

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
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(data);
      console.log(`[${id}] ⬅️  TCP → WS: ${data.length} bytes`);
    }
  });

  // WebSocket → TCP
  ws.on('message', (data) => {
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
  console.log('\n🚀 WebSocket → TCP Bridge Server Started\n');
  console.log(`📡 Listening on ${useSSL ? 'wss' : 'ws'}://0.0.0.0:${config.port}`);
  console.log(`📡 Ready to proxy WebSocket → TCP connections`);
  console.log(`💡 WASM clients should connect to: ${useSSL ? 'wss' : 'ws'}://YOUR_DOMAIN:${config.port}?addr=HOST:PORT`);
  console.log(`🌐 Tor consensus endpoint: http://YOUR_DOMAIN:${config.port}/tor/consensus`);
  if (!useSSL) {
    console.log(`🏥 Health check: http://localhost:${config.port}/health`);
  }
  console.log('Press Ctrl+C to stop the server\n');
  
  // Fetch consensus on startup
  console.log('🔄 Initializing Tor consensus cache...\n');
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

