#!/usr/bin/env node

/**
 * WebTunnel Bridge Server
 *
 * Disguises a Tor bridge as a normal HTTPS website. To DPI equipment,
 * the server looks like a regular website that uses WebSocket for
 * legitimate features (chat, notifications, etc.).
 *
 * How it works:
 *   - All HTTP requests → cover site (blog, docs, default page)
 *   - WebSocket upgrade on the secret path → bidirectional Tor relay
 *   - Non-matching WebSocket upgrades → rejected (looks like auth failure)
 *
 * Configuration (env vars):
 *   WEBTUNNEL_PATH     — Secret path for WS upgrade (default: random UUID)
 *   WEBTUNNEL_PORT     — Listen port (default: 443)
 *   SSL_CERT           — Path to TLS certificate (required for production)
 *   SSL_KEY            — Path to TLS private key (required for production)
 *   COVER_SITE_DIR     — Static site directory (for cover-site.js)
 *   COVER_SITE_URL     — Reverse-proxy URL (alternative to COVER_SITE_DIR)
 *   COVER_SITE_TITLE   — Title for default cover page
 *
 * Usage:
 *   # Development (HTTP, auto-generated secret path)
 *   node server-webtunnel.js
 *
 *   # Production (HTTPS with cover site)
 *   WEBTUNNEL_PATH=/ws-a1b2c3d4 \
 *   SSL_CERT=/etc/letsencrypt/live/blog.example.com/fullchain.pem \
 *   SSL_KEY=/etc/letsencrypt/live/blog.example.com/privkey.pem \
 *   COVER_SITE_DIR=/var/www/blog \
 *   node server-webtunnel.js
 */

const WebSocket = require('ws');
const net = require('net');
const tls = require('tls');
const http = require('http');
const https = require('https');
const fs = require('fs');
const crypto = require('crypto');
const url = require('url');
const { serveCoverSite, setStandardHeaders } = require('./cover-site');

// --- Configuration ---

const SECRET_PATH = process.env.WEBTUNNEL_PATH || `/${crypto.randomUUID()}`;
const PORT = parseInt(process.env.WEBTUNNEL_PORT || process.env.PORT || '443');
const SSL_CERT = process.env.SSL_CERT || null;
const SSL_KEY = process.env.SSL_KEY || null;

// --- Server Setup ---

let server;
const useSSL = SSL_CERT && SSL_KEY;

if (useSSL) {
    try {
        server = https.createServer({
            cert: fs.readFileSync(SSL_CERT),
            key: fs.readFileSync(SSL_KEY),
        });
    } catch (err) {
        console.error(`Failed to load SSL certificates: ${err.message}`);
        process.exit(1);
    }
} else {
    server = http.createServer();
    console.log('WARNING: Running without TLS — development mode only');
}

// --- Cover Site (all HTTP requests) ---
// Every non-upgrade request serves the cover site. Active probers see a
// normal website with nginx headers. No endpoint reveals bridge functionality.

server.on('request', (req, res) => {
    // Remove any identifying headers before cover-site adds nginx ones
    res.removeHeader('X-Powered-By');
    serveCoverSite(req, res);
});

// --- HMAC Challenge Verification ---
// Clients must prove knowledge of the secret path via HMAC-SHA256.
// Format in Sec-WebSocket-Protocol: v1.<hmac_hex_32chars>.<unix_timestamp>
// HMAC key = SECRET_PATH, message = timestamp string.
// Timestamp must be within 5 minutes (generous for clock skew in censored regions).
// Without this, a censor who discovers the path can confirm the bridge simply
// by connecting to it. With HMAC, the path alone is not sufficient.

const HMAC_WINDOW_SECONDS = 300; // 5 minutes

function verifyHmacChallenge(req) {
    const raw = req.headers['sec-websocket-protocol'] || '';
    const protocols = raw.split(',').map(s => s.trim());

    for (const proto of protocols) {
        const parts = proto.split('.');
        if (parts.length !== 3 || parts[0] !== 'v1') continue;

        const [, hmacHex, tsStr] = parts;
        const ts = parseInt(tsStr, 10);
        if (isNaN(ts)) continue;

        // Timestamp window check
        const now = Math.floor(Date.now() / 1000);
        if (Math.abs(now - ts) > HMAC_WINDOW_SECONDS) continue;

        // Compute expected HMAC-SHA256, truncated to 128 bits (32 hex chars)
        const expected = crypto
            .createHmac('sha256', SECRET_PATH)
            .update(tsStr)
            .digest('hex')
            .slice(0, 32);

        if (hmacHex.length !== 32) continue;

        // Timing-safe comparison to prevent side-channel leaks
        try {
            if (crypto.timingSafeEqual(Buffer.from(hmacHex, 'hex'), Buffer.from(expected, 'hex'))) {
                return proto;
            }
        } catch (e) {
            // Invalid hex — skip
        }
    }
    return null;
}

function reject404(socket) {
    setStandardHeaders({ setHeader: (k, v) => socket.write(`${k}: ${v}\r\n`), removeHeader: () => {} });
    socket.write('HTTP/1.1 404 Not Found\r\n');
    socket.write('Content-Type: text/html; charset=utf-8\r\n');
    socket.write('Server: nginx/1.24.0\r\n');
    socket.write('Connection: close\r\n');
    socket.write('\r\n');
    socket.write('<!DOCTYPE html><html><head><title>404</title></head><body><h1>Not Found</h1></body></html>');
    socket.destroy();
}

// --- WebSocket Upgrade (secret path + HMAC challenge) ---

const wss = new WebSocket.Server({ noServer: true });
let connectionId = 0;

server.on('upgrade', (req, socket, head) => {
    const pathname = url.parse(req.url).pathname;

    // Wrong path — identical 404
    if (pathname !== SECRET_PATH) {
        reject404(socket);
        return;
    }

    // Right path but no/invalid HMAC — identical 404
    // Active prober with just the path cannot distinguish this from wrong path
    const matchedProto = verifyHmacChallenge(req);
    if (!matchedProto) {
        reject404(socket);
        return;
    }

    // Path + HMAC valid — upgrade to WebSocket
    wss.handleUpgrade(req, socket, head, (ws) => {
        wss.emit('connection', ws, req);
    });
});

// --- Tor Relay Connection ---
// After WebSocket upgrade on the secret path, we relay raw bytes
// to the Tor guard relay. The client sends the target relay address
// as the first WebSocket message (format: "host:port").

wss.on('connection', (ws, req) => {
    const id = ++connectionId;
    const clientIp = req.socket.remoteAddress;
    console.log(`[${id}] WebTunnel connection from ${clientIp}`);

    let tcpSocket = null;
    let targetConnected = false;
    let pendingData = [];

    // First message contains the target relay address
    let gotTarget = false;

    ws.on('message', (data) => {
        if (!gotTarget) {
            // First message: target address as UTF-8 string "host:port"
            gotTarget = true;
            const targetAddr = data.toString('utf-8').trim();

            const match = targetAddr.match(/^([^:]+):(\d+)$/);
            if (!match) {
                console.log(`[${id}] Invalid target: ${targetAddr}`);
                ws.close(1008, 'Invalid target');
                return;
            }

            const [, host, portStr] = match;
            const port = parseInt(portStr);
            console.log(`[${id}] Relaying to ${host}:${port}`);

            // TLS connect to Tor relay (self-signed certs, Tor handles auth)
            tcpSocket = tls.connect({
                host,
                port,
                rejectUnauthorized: false,
            }, () => {
                targetConnected = true;
                console.log(`[${id}] TLS connected to ${host}:${port}`);

                // Send any data that arrived before TCP connected
                for (const buf of pendingData) {
                    tcpSocket.write(buf);
                }
                pendingData = [];
            });

            // TCP → WebSocket
            tcpSocket.on('data', (chunk) => {
                if (ws.readyState === WebSocket.OPEN) {
                    ws.send(chunk);
                }
            });

            tcpSocket.on('error', (err) => {
                console.log(`[${id}] TCP error: ${err.message}`);
                ws.close(1011, 'Relay connection failed');
            });

            tcpSocket.on('close', () => {
                console.log(`[${id}] TCP closed`);
                if (ws.readyState === WebSocket.OPEN) {
                    ws.close(1000, 'Relay disconnected');
                }
            });

            tcpSocket.setTimeout(300000); // 5 min idle timeout
            tcpSocket.on('timeout', () => {
                console.log(`[${id}] TCP timeout`);
                tcpSocket.destroy();
                ws.close(1000, 'Timeout');
            });

            return;
        }

        // Subsequent messages: raw Tor cells → relay
        if (targetConnected && tcpSocket) {
            tcpSocket.write(Buffer.from(data));
        } else {
            pendingData.push(Buffer.from(data));
        }
    });

    ws.on('close', (code, reason) => {
        console.log(`[${id}] WebSocket closed (${code})`);
        if (tcpSocket) {
            tcpSocket.destroy();
        }
    });

    ws.on('error', (err) => {
        console.log(`[${id}] WebSocket error: ${err.message}`);
    });
});

// --- Start Server ---

server.listen(PORT, '0.0.0.0', () => {
    console.log('');
    console.log('  WebTunnel Bridge Server');
    console.log(`  Listening on ${useSSL ? 'wss' : 'ws'}://0.0.0.0:${PORT}`);
    console.log(`  Secret path: ${SECRET_PATH}`);
    console.log(`  Cover site: ${process.env.COVER_SITE_DIR || process.env.COVER_SITE_URL || 'default page'}`);
    console.log('');
    console.log(`  HMAC challenge: enabled (${HMAC_WINDOW_SECONDS}s window)`);
    console.log('');
    console.log('  Client config:');
    console.log(`    URL:  ${useSSL ? 'wss' : 'ws'}://your-domain.com`);
    console.log(`    Path: ${SECRET_PATH}`);
    console.log('');
});

// --- Graceful Shutdown ---

process.on('SIGINT', () => {
    console.log('\nShutting down...');
    wss.clients.forEach(client => client.close(1001, 'Server shutdown'));
    server.close(() => {
        console.log('Server closed');
        process.exit(0);
    });
});

process.on('uncaughtException', (err) => {
    console.error('Uncaught exception:', err);
});

process.on('unhandledRejection', (reason) => {
    console.error('Unhandled rejection:', reason);
});

module.exports = { SECRET_PATH };
