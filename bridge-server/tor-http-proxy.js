#!/usr/bin/env node

/**
 * Tor HTTP Proxy Server
 * 
 * Exposes an HTTP proxy that routes requests through Tor.
 * Works with our bridge-server infrastructure.
 * 
 * For Playwright: proxy: { server: 'http://127.0.0.1:9080' }
 * 
 * This uses the native Tor SOCKS proxy but through our managed connection.
 * In the future, this can be replaced with our WASM circuit-building.
 */

const http = require('http');
const net = require('net');
const { SocksClient } = require('socks');

const config = {
  // Proxy server port
  proxyPort: parseInt(process.env.PROXY_PORT) || 9080,
  
  // Tor SOCKS proxy (from `tor --SocksPort 9050`)
  torSocksHost: process.env.TOR_SOCKS_HOST || '127.0.0.1',
  torSocksPort: parseInt(process.env.TOR_SOCKS_PORT) || 9050,
};

// Track connections
let connectionCount = 0;
let requestCount = 0;

/**
 * Create HTTP proxy server
 */
const proxyServer = http.createServer();

/**
 * Handle regular HTTP requests (non-CONNECT)
 */
proxyServer.on('request', async (clientReq, clientRes) => {
  const reqId = ++requestCount;
  const targetUrl = clientReq.url;
  
  console.log(`[${reqId}] HTTP ${clientReq.method} ${targetUrl}`);
  
  try {
    const parsedUrl = new URL(targetUrl);
    const targetHost = parsedUrl.hostname;
    const targetPort = parseInt(parsedUrl.port) || (parsedUrl.protocol === 'https:' ? 443 : 80);
    
    // Connect through Tor SOCKS
    const { socket } = await SocksClient.createConnection({
      proxy: {
        host: config.torSocksHost,
        port: config.torSocksPort,
        type: 5, // SOCKS5
      },
      command: 'connect',
      destination: {
        host: targetHost,
        port: targetPort,
      },
      timeout: 30000,
    });
    
    // Build HTTP request
    const path = parsedUrl.pathname + parsedUrl.search;
    let requestData = `${clientReq.method} ${path} HTTP/1.1\r\n`;
    requestData += `Host: ${targetHost}\r\n`;
    
    // Forward headers
    for (const [key, value] of Object.entries(clientReq.headers)) {
      if (key.toLowerCase() !== 'proxy-connection' && key.toLowerCase() !== 'host') {
        requestData += `${key}: ${value}\r\n`;
      }
    }
    requestData += 'Connection: close\r\n\r\n';
    
    // Send request
    socket.write(requestData);
    
    // Forward request body if present
    clientReq.pipe(socket, { end: false });
    
    // Forward response
    let headersSent = false;
    let responseBuffer = Buffer.alloc(0);
    
    socket.on('data', (data) => {
      if (!headersSent) {
        responseBuffer = Buffer.concat([responseBuffer, data]);
        const headerEnd = responseBuffer.indexOf('\r\n\r\n');
        
        if (headerEnd !== -1) {
          // Parse headers
          const headerStr = responseBuffer.slice(0, headerEnd).toString();
          const lines = headerStr.split('\r\n');
          const statusLine = lines[0];
          const statusMatch = statusLine.match(/HTTP\/\d\.\d (\d+)/);
          const statusCode = statusMatch ? parseInt(statusMatch[1]) : 200;
          
          // Parse response headers
          const headers = {};
          for (let i = 1; i < lines.length; i++) {
            const colonIdx = lines[i].indexOf(':');
            if (colonIdx > 0) {
              const key = lines[i].slice(0, colonIdx).trim();
              const value = lines[i].slice(colonIdx + 1).trim();
              if (key.toLowerCase() !== 'transfer-encoding') {
                headers[key] = value;
              }
            }
          }
          
          clientRes.writeHead(statusCode, headers);
          headersSent = true;
          
          // Write body portion
          const bodyStart = headerEnd + 4;
          if (responseBuffer.length > bodyStart) {
            clientRes.write(responseBuffer.slice(bodyStart));
          }
        }
      } else {
        clientRes.write(data);
      }
    });
    
    socket.on('end', () => {
      console.log(`[${reqId}] ✓ Complete`);
      clientRes.end();
    });
    
    socket.on('error', (err) => {
      console.log(`[${reqId}] ✗ Socket error: ${err.message}`);
      if (!headersSent) {
        clientRes.writeHead(502);
        clientRes.end(`Proxy error: ${err.message}`);
      } else {
        clientRes.end();
      }
    });
    
  } catch (err) {
    console.log(`[${reqId}] ✗ Error: ${err.message}`);
    clientRes.writeHead(502);
    clientRes.end(`Proxy error: ${err.message}`);
  }
});

/**
 * Handle CONNECT requests (for HTTPS)
 */
proxyServer.on('connect', async (req, clientSocket, head) => {
  const connId = ++connectionCount;
  const [targetHost, targetPort] = req.url.split(':');
  const port = parseInt(targetPort) || 443;
  
  console.log(`[C${connId}] CONNECT ${targetHost}:${port}`);
  
  try {
    // Connect through Tor SOCKS
    const { socket: torSocket } = await SocksClient.createConnection({
      proxy: {
        host: config.torSocksHost,
        port: config.torSocksPort,
        type: 5, // SOCKS5
      },
      command: 'connect',
      destination: {
        host: targetHost,
        port: port,
      },
      timeout: 30000,
    });
    
    // Tell client connection is established
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    
    // If there's pending data, write it
    if (head.length > 0) {
      torSocket.write(head);
    }
    
    // Bi-directional pipe
    clientSocket.pipe(torSocket);
    torSocket.pipe(clientSocket);
    
    clientSocket.on('error', (err) => {
      console.log(`[C${connId}] Client error: ${err.message}`);
      torSocket.destroy();
    });
    
    torSocket.on('error', (err) => {
      console.log(`[C${connId}] Tor error: ${err.message}`);
      clientSocket.destroy();
    });
    
    torSocket.on('close', () => {
      console.log(`[C${connId}] ✓ Connection closed`);
    });
    
  } catch (err) {
    console.log(`[C${connId}] ✗ Failed: ${err.message}`);
    clientSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n');
    clientSocket.end();
  }
});

// Start server
proxyServer.listen(config.proxyPort, '127.0.0.1', () => {
  console.log('');
  console.log('============================================');
  console.log('🧅 Tor HTTP Proxy Server');
  console.log('============================================');
  console.log(`Proxy: http://127.0.0.1:${config.proxyPort}`);
  console.log(`Tor SOCKS: ${config.torSocksHost}:${config.torSocksPort}`);
  console.log('');
  console.log('For Playwright:');
  console.log(`  proxy: { server: 'http://127.0.0.1:${config.proxyPort}' }`);
  console.log('');
  console.log('Make sure Tor is running:');
  console.log('  tor --SocksPort 9050');
  console.log('============================================');
  console.log('');
});

// Handle errors
proxyServer.on('error', (err) => {
  console.error('Server error:', err.message);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught exception:', err.message);
});

