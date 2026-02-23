#!/usr/bin/env node

/**
 * Tor WASM Bridge Server - TLS Proxy Mode
 * 
 * This server acts as a TLS proxy between the browser and Tor relays.
 * Browser sends raw Tor protocol cells over WebSocket, bridge wraps them in TLS.
 * 
 * This solves the incompatibility between browser TLS and Tor relay expectations.
 */

const WebSocket = require('ws');
const https = require('https');
const http = require('http');
const tls = require('tls');
const net = require('net');

// Parse port from command line
const port = parseInt(process.argv.find(arg => arg.startsWith('--port='))?.split('=')[1]) || 
             parseInt(process.argv[process.argv.indexOf('--port') + 1]) || 
             8080;

// Statistics
let connectionCounter = 0;
const stats = {
  totalConnections: 0,
  activeConnections: 0,
  totalBytesIn: 0,
  totalBytesOut: 0,
  startTime: Date.now(),
};

// HTTP server for health checks and consensus endpoint
const httpServer = http.createServer((req, res) => {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  
  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }
  
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'ok',
      mode: 'tls-proxy',
      uptime: Math.floor((Date.now() - stats.startTime) / 1000),
      connections: {
        total: stats.totalConnections,
        active: stats.activeConnections,
      },
      traffic: {
        bytesIn: stats.totalBytesIn,
        bytesOut: stats.totalBytesOut,
      },
    }));
  } else if (req.url === '/tor/consensus') {
    // Serve cached consensus (from Tor Collector)
    if (cachedConsensus) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        consensus: cachedConsensus,
        timestamp: consensusCacheTime,
        cacheAge: Math.floor((Date.now() - consensusCacheTime) / 1000),
      }));
    } else {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: 'Consensus not yet fetched',
        message: 'Server is still fetching initial consensus data',
      }));
    }
  } else {
    res.writeHead(404);
    res.end('Not found');
  }
});

// WebSocket server for TLS proxy connections
const wss = new WebSocket.Server({ server: httpServer });

wss.on('connection', (ws, req) => {
  const connId = ++connectionCounter;
  stats.totalConnections++;
  stats.activeConnections++;
  
  // Parse target address from query string
  const url = new URL(req.url, `http://${req.headers.host}`);
  const targetAddr = url.searchParams.get('addr');
  
  if (!targetAddr) {
    console.log(`[${connId}] ❌ No target address specified`);
    ws.close();
    stats.activeConnections--;
    return;
  }
  
  const [host, portStr] = targetAddr.split(':');
  const targetPort = parseInt(portStr);
  
  console.log(`[${connId}] 🔌 New TLS proxy connection from ${req.socket.remoteAddress}`);
  console.log(`[${connId}] 🎯 Target: ${host}:${targetPort}`);
  
  let tlsSocket = null;
  let isConnected = false;
  
  // Connect to Tor relay with TLS
  const connectToRelay = () => {
    console.log(`[${connId}] 🔐 Establishing TLS connection to ${host}:${targetPort}...`);
    
    // First establish TCP connection
    const tcpSocket = net.connect({
      host,
      port: targetPort,
      timeout: 10000, // 10 second timeout
    });
    
    tcpSocket.on('connect', () => {
      console.log(`[${connId}] ✅ TCP connected, starting TLS handshake...`);
      
      // Upgrade to TLS
      tlsSocket = tls.connect({
        socket: tcpSocket,
        servername: host, // For SNI
        rejectUnauthorized: false, // Tor uses self-signed certs
        // Tor-compatible TLS options
        minVersion: 'TLSv1.2',
        maxVersion: 'TLSv1.3',
      });
      
      tlsSocket.on('secureConnect', () => {
        console.log(`[${connId}] ✅ TLS handshake complete`);
        console.log(`[${connId}]    Protocol: ${tlsSocket.getProtocol()}`);
        console.log(`[${connId}]    Cipher: ${tlsSocket.getCipher()?.name}`);
        isConnected = true;
        
        // Notify browser that connection is ready
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'connected' }));
        }
      });
      
      tlsSocket.on('data', (data) => {
        if (ws.readyState === WebSocket.OPEN) {
          stats.totalBytesOut += data.length;
          // Send raw bytes to browser
          ws.send(data);
          console.log(`[${connId}] ⬅️  Relay → Browser: ${data.length} bytes`);
        }
      });
      
      tlsSocket.on('error', (err) => {
        console.log(`[${connId}] ❌ TLS error: ${err.message}`);
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'error', message: err.message }));
        }
      });
      
      tlsSocket.on('end', () => {
        console.log(`[${connId}] 🔌 TLS connection closed by relay`);
        if (ws.readyState === WebSocket.OPEN) {
          ws.close();
        }
      });
    });
    
    tcpSocket.on('error', (err) => {
      console.log(`[${connId}] ❌ TCP error: ${err.message}`);
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'error', message: err.message }));
        ws.close();
      }
      stats.activeConnections--;
    });
    
    tcpSocket.on('timeout', () => {
      console.log(`[${connId}] ⏱️  TCP connection timeout`);
      tcpSocket.destroy();
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'error', message: 'Connection timeout' }));
        ws.close();
      }
      stats.activeConnections--;
    });
  };
  
  // Handle messages from browser (raw Tor protocol cells)
  ws.on('message', (data) => {
    if (!isConnected) {
      console.log(`[${connId}] ⚠️  Received data before connection ready, queuing...`);
      // Start connection if not already started
      if (!tlsSocket) {
        connectToRelay();
      }
      return;
    }
    
    // Forward raw bytes to relay
    if (tlsSocket && !tlsSocket.destroyed) {
      stats.totalBytesIn += data.length;
      tlsSocket.write(data);
      console.log(`[${connId}] ➡️  Browser → Relay: ${data.length} bytes`);
    }
  });
  
  ws.on('close', () => {
    console.log(`[${connId}] 🔌 WebSocket closed`);
    if (tlsSocket && !tlsSocket.destroyed) {
      tlsSocket.end();
    }
    stats.activeConnections--;
  });
  
  ws.on('error', (err) => {
    console.log(`[${connId}] ❌ WebSocket error: ${err.message}`);
  });
  
  // Start connection immediately
  connectToRelay();
});

// Consensus caching (from Tor Collector)
let cachedConsensus = null;
let consensusCacheTime = null;

async function fetchAndCacheConsensus() {
  console.log('📡 Fetching consensus from Tor Collector...');
  
  try {
    const https = require('https');
    
    // Fetch recent consensus
    const consensusUrl = 'https://collector.torproject.org/recent/relay-descriptors/consensuses/';
    
    // Fetch the index page to get the latest consensus
    const indexData = await new Promise((resolve, reject) => {
      https.get(consensusUrl, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => resolve(data));
      }).on('error', reject);
    });
    
    // Parse the latest consensus filename
    const consensusFiles = indexData.match(/href="(\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}-consensus)"/g);
    if (!consensusFiles || consensusFiles.length === 0) {
      throw new Error('No consensus files found');
    }
    
    const latestFile = consensusFiles[consensusFiles.length - 1].match(/"(.*)"/)[1];
    console.log(`📄 Latest consensus: ${latestFile}`);
    
    // Fetch the consensus
    const consensusData = await new Promise((resolve, reject) => {
      https.get(`${consensusUrl}${latestFile}`, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => resolve(data));
      }).on('error', reject);
    });
    
    // Parse consensus and extract relay info
    const relays = parseConsensus(consensusData);
    console.log(`✅ Parsed ${relays.length} relays from consensus`);
    
    // Fetch descriptors for ntor keys
    console.log('📡 Fetching relay descriptors for ntor keys...');
    const ntorKeys = await fetchNtorKeys(relays.slice(0, 100)); // Get first 100
    console.log(`✅ Fetched ${Object.keys(ntorKeys).length} ntor keys`);
    
    // Build final consensus object
    cachedConsensus = {
      relays: relays.map(relay => ({
        ...relay,
        ntor_onion_key: ntorKeys[relay.fingerprint] || null,
      })),
    };
    
    consensusCacheTime = Date.now();
    console.log(`✅ Consensus cached at ${new Date(consensusCacheTime).toISOString()}`);
    
  } catch (error) {
    console.error('❌ Failed to fetch consensus:', error.message);
  }
}

function parseConsensus(data) {
  const relays = [];
  const lines = data.split('\n');
  
  for (const line of lines) {
    if (line.startsWith('r ')) {
      const parts = line.split(' ');
      const nickname = parts[1];
      const fingerprint = parts[2]; // Base64, needs decoding
      const address = parts[6];
      const orPort = parseInt(parts[7]);
      
      // Decode fingerprint from base64
      const fingerprintHex = Buffer.from(fingerprint, 'base64').toString('hex').toUpperCase();
      
      relays.push({
        nickname,
        fingerprint: fingerprintHex,
        address,
        port: orPort,
        flags: {},
      });
    } else if (line.startsWith('s ') && relays.length > 0) {
      const flags = line.substring(2).split(' ');
      const relay = relays[relays.length - 1];
      relay.flags = {
        exit: flags.includes('Exit'),
        fast: flags.includes('Fast'),
        guard: flags.includes('Guard'),
        hsdir: flags.includes('HSDir'),
        running: flags.includes('Running'),
        stable: flags.includes('Stable'),
        v2dir: flags.includes('V2Dir'),
        valid: flags.includes('Valid'),
      };
    }
  }
  
  return relays;
}

async function fetchNtorKeys(relays) {
  console.log(`📡 Fetching descriptors from Tor Collector...`);
  
  try {
    const https = require('https');
    
    // Fetch recent server descriptors
    const descriptorUrl = 'https://collector.torproject.org/recent/relay-descriptors/server-descriptors/';
    
    // Fetch the index page
    const indexData = await new Promise((resolve, reject) => {
      https.get(descriptorUrl, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => resolve(data));
      }).on('error', reject);
    });
    
    // Get the latest descriptor file
    const descriptorFiles = indexData.match(/href="(\d{4}-\d{2}\/\d{2}\/\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}-server-descriptors)"/g);
    if (!descriptorFiles || descriptorFiles.length === 0) {
      console.log('⚠️  No descriptor files found');
      return {};
    }
    
    const latestFile = descriptorFiles[descriptorFiles.length - 1].match(/"(.*)"/)[1];
    console.log(`📄 Latest descriptors: ${latestFile}`);
    
    // Fetch the descriptors
    const descriptorData = await new Promise((resolve, reject) => {
      https.get(`${descriptorUrl}${latestFile}`, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => resolve(data));
      }).on('error', reject);
    });
    
    // Parse descriptors
    const ntorKeys = parseDescriptors(descriptorData);
    console.log(`✅ Parsed ${Object.keys(ntorKeys).length} ntor keys`);
    
    return ntorKeys;
    
  } catch (error) {
    console.error('❌ Failed to fetch descriptors:', error.message);
    return {};
  }
}

function parseDescriptors(data) {
  const ntorKeys = {};
  const lines = data.split('\n');
  
  let currentFingerprint = null;
  
  for (const line of lines) {
    const trimmed = line.trim();
    
    // fingerprint FINGERPRINT
    if (trimmed.startsWith('fingerprint ')) {
      const fp = trimmed.substring(12).replace(/\s/g, '');
      currentFingerprint = fp;
    }
    // ntor-onion-key BASE64KEY
    else if (trimmed.startsWith('ntor-onion-key ') && currentFingerprint) {
      const ntorKey = trimmed.substring(15).trim();
      // Normalize base64 padding
      const paddedKey = ntorKey + '='.repeat((4 - ntorKey.length % 4) % 4);
      ntorKeys[currentFingerprint] = paddedKey;
    }
    // router-signature marks end of descriptor
    else if (trimmed.startsWith('router-signature')) {
      currentFingerprint = null;
    }
  }
  
  return ntorKeys;
}

// Start fetching consensus immediately and refresh every 3 hours
fetchAndCacheConsensus();
setInterval(fetchAndCacheConsensus, 3 * 60 * 60 * 1000);

// Start server
httpServer.listen(port, () => {
  console.log('🚀 Tor WASM Bridge Server (TLS Proxy Mode)');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`📡 Listening on port ${port}`);
  console.log(`🔐 TLS proxy enabled for Tor relay connections`);
  console.log('');
  console.log('Endpoints:');
  console.log(`  ws://localhost:${port}?addr=HOST:PORT - TLS proxy to Tor relay`);
  console.log(`  http://localhost:${port}/health - Health check`);
  console.log(`  http://localhost:${port}/tor/consensus - Cached consensus`);
  console.log('');
  console.log('💡 WASM clients connect via WebSocket, bridge handles TLS');
  console.log('Press Ctrl+C to stop the server');
});

