#!/usr/bin/env node

/**
 * meek Transport Bridge
 *
 * Tunnels Tor protocol cells inside HTTP POST request/response bodies.
 * Designed to run behind a CDN (Cloudflare, Fastly, etc.) so the censor
 * sees only HTTPS traffic to a CDN IP — indistinguishable from millions
 * of other websites.
 *
 * Protocol:
 *   Client sends:  POST / with X-Session-Id header, body = raw Tor cells
 *   Server sends:  200 OK, body = raw Tor cells from relay
 *
 * No WebSocket upgrade, no long-lived connections — each exchange is a
 * standard HTTP request/response. This defeats WebSocket-based blocking.
 *
 * Usage:
 *   node server-meek.js [--port PORT]
 *
 * Env vars:
 *   PORT               — Listen port (default: 8443)
 *   MEEK_MAX_SESSIONS  — Max concurrent sessions (default: 500)
 *   MEEK_SESSION_TTL   — Session timeout in seconds (default: 300)
 *   MANAGEMENT_PORT    — Localhost-only health endpoint
 *   QUIET_MODE         — Suppress identifying log strings
 */

const http = require('http');
const net = require('net');
const tls = require('tls');
const { serveCoverSite } = require('./cover-site');
const { handleHealth, startManagementServer } = require('./health-auth');
const logger = require('./logger');
const { TrafficMonitor } = require('./traffic-monitor');

// --- Configuration ---
const config = {
  port: parseInt(process.env.PORT) || 8443,
  maxSessions: parseInt(process.env.MEEK_MAX_SESSIONS) || 500,
  sessionTtl: (parseInt(process.env.MEEK_SESSION_TTL) || 300) * 1000,
  maxBodySize: 65536,  // 64KB max POST body
};

// Parse CLI args
const args = process.argv.slice(2);
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--port') config.port = parseInt(args[++i]);
}

// --- Session Management ---
// Each session maps a session ID to a TLS connection to a Tor relay.
// Sessions are created on first POST and persist across multiple requests.
const sessions = new Map();
const trafficMonitor = new TrafficMonitor();
let sessionCounter = 0;

class MeekSession {
  constructor(id, host, port) {
    this.id = id;
    this.connId = ++sessionCounter;
    this.host = host;
    this.port = port;
    this.created = Date.now();
    this.lastActivity = Date.now();
    this.recvBuffer = Buffer.alloc(0);
    this.tlsSocket = null;
    this.tcpSocket = null;
    this.connected = false;
    this.error = null;

    trafficMonitor.openConnection(this.connId);
    this._connect();
  }

  _connect() {
    logger.log(`[${this.connId}] Connecting to ${this.host}:${this.port}`);

    this.tcpSocket = net.connect(this.port, this.host);

    this.tcpSocket.on('connect', () => {
      this.tcpSocket.setNoDelay(true);

      const tlsOptions = {
        socket: this.tcpSocket,
        rejectUnauthorized: false,
        minVersion: 'TLSv1.2',
        maxVersion: 'TLSv1.3',
        ...(!/^\d+\.\d+\.\d+\.\d+$/.test(this.host) ? { servername: this.host } : {}),
      };

      this.tlsSocket = tls.connect(tlsOptions);

      this.tlsSocket.on('secureConnect', () => {
        logger.log(`[${this.connId}] TLS established`);
        this.connected = true;
      });

      this.tlsSocket.on('data', (data) => {
        trafficMonitor.recordFrame(this.connId, data.length, 'down');
        this.recvBuffer = Buffer.concat([this.recvBuffer, data]);
        this.lastActivity = Date.now();
      });

      this.tlsSocket.on('error', (err) => {
        logger.log(`[${this.connId}] TLS error: ${err.message}`);
        this.error = err.message;
      });

      this.tlsSocket.on('close', () => {
        logger.log(`[${this.connId}] TLS closed`);
        this.connected = false;
      });
    });

    this.tcpSocket.on('error', (err) => {
      logger.log(`[${this.connId}] TCP error: ${err.message}`);
      this.error = err.message;
    });
  }

  /**
   * Send data upstream and return buffered downstream data.
   */
  exchange(data) {
    this.lastActivity = Date.now();

    // Send upstream
    if (data.length > 0 && this.tlsSocket && this.connected) {
      trafficMonitor.recordFrame(this.connId, data.length, 'up');
      this.tlsSocket.write(data);
    }

    // Drain receive buffer
    const response = this.recvBuffer;
    this.recvBuffer = Buffer.alloc(0);
    return response;
  }

  destroy() {
    trafficMonitor.closeConnection(this.connId);
    if (this.tlsSocket) this.tlsSocket.destroy();
    if (this.tcpSocket) this.tcpSocket.destroy();
  }

  isExpired() {
    return Date.now() - this.lastActivity > config.sessionTtl;
  }
}

// --- Session Cleanup ---
setInterval(() => {
  for (const [id, session] of sessions) {
    if (session.isExpired()) {
      logger.log(`[${session.connId}] Session expired`);
      session.destroy();
      sessions.delete(id);
    }
  }
}, 30000);

// --- HTTP Server ---
const server = http.createServer();

server.on('request', (req, res) => {
  // Standard headers — look like a normal web server
  res.setHeader('Server', 'nginx/1.24.0');
  res.removeHeader('X-Powered-By');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Session-Id, X-Target');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  // Health endpoint
  if (req.url === '/health' || req.url.startsWith('/health?')) {
    const handled = handleHealth(req, res, {
      status: 'ok',
      uptime: process.uptime(),
      sessions: sessions.size,
    });
    if (handled) return;
    return serveCoverSite(req, res);
  }

  // meek transport: POST with X-Session-Id header
  if (req.method === 'POST') {
    const sessionId = req.headers['x-session-id'];
    const target = req.headers['x-target'];

    if (!sessionId) {
      // No session ID — serve cover site (looks like normal POST to website)
      return serveCoverSite(req, res);
    }

    // Collect request body
    const chunks = [];
    let bodySize = 0;

    req.on('data', (chunk) => {
      bodySize += chunk.length;
      if (bodySize > config.maxBodySize) {
        res.writeHead(413);
        res.end();
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      const body = Buffer.concat(chunks);

      // Get or create session
      let session = sessions.get(sessionId);

      if (!session) {
        // New session — need target address
        if (!target) {
          // Missing target — return cover site
          return serveCoverSite(req, res);
        }

        if (sessions.size >= config.maxSessions) {
          res.writeHead(503, { 'Content-Type': 'application/octet-stream' });
          res.end();
          return;
        }

        const [host, portStr] = target.split(':');
        const port = parseInt(portStr);

        if (!host || !port || isNaN(port)) {
          return serveCoverSite(req, res);
        }

        session = new MeekSession(sessionId, host, port);
        sessions.set(sessionId, session);
      }

      // Exchange data
      // Small delay to let relay data arrive before responding
      const respond = () => {
        const response = session.exchange(body);

        // Return relay data (or empty body if nothing yet)
        res.writeHead(200, {
          'Content-Type': 'application/octet-stream',
          'Content-Length': response.length,
          'Cache-Control': 'no-store',
        });
        res.end(response);
      };

      if (session.connected) {
        // If data was sent, wait briefly for relay response
        if (body.length > 0) {
          setTimeout(respond, 50);
        } else {
          // Polling request — respond immediately with buffered data
          respond();
        }
      } else {
        // Not connected yet — wait up to 5s
        const waitForConnect = (attempts) => {
          if (session.connected || session.error || attempts >= 50) {
            respond();
          } else {
            setTimeout(() => waitForConnect(attempts + 1), 100);
          }
        };
        waitForConnect(0);
      }
    });

    return;
  }

  // GET and all other methods — serve cover site
  serveCoverSite(req, res);
});

// --- Start ---
startManagementServer(() => ({
  status: 'ok',
  uptime: process.uptime(),
  sessions: sessions.size,
}));

server.listen(config.port, '0.0.0.0', () => {
  logger.banner([
    '',
    `  meek Transport Bridge Started`,
    `  Port: ${config.port}`,
    `  Max sessions: ${config.maxSessions}`,
    `  Session TTL: ${config.sessionTtl / 1000}s`,
    '',
  ]);
});

// --- Graceful Shutdown ---
process.on('SIGINT', () => {
  logger.log('Shutting down...');
  for (const [, session] of sessions) session.destroy();
  server.close(() => process.exit(0));
});

process.on('uncaughtException', (err) => {
  logger.error('Uncaught exception:', err);
});

process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled rejection:', reason);
});
