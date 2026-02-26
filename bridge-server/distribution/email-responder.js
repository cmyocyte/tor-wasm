#!/usr/bin/env node

/**
 * Bridge Email Responder
 *
 * Minimal SMTP server that responds to emails with bridge connection URLs.
 * Users send any email to the bridge address; the auto-reply contains the
 * bridge URL, public key, and a QR code (as SVG attachment).
 *
 * Rate limited: 1 response per sender per 24 hours.
 * Does not store email content — only tracks sender hashes for rate limiting.
 *
 * Usage:
 *   BRIDGE_URL=wss://bridge.example.com node email-responder.js [--port 25]
 *
 * Env vars:
 *   BRIDGE_URL       — Bridge WebSocket URL (required)
 *   BRIDGE_B_PUBKEY  — Bridge B public key hex (optional, for blinded mode)
 *   MEEK_URL         — meek fallback URL (optional)
 *   SMTP_PORT        — SMTP listen port (default: 2525, use 25 for production)
 *   SMTP_DOMAIN      — SMTP domain for EHLO (default: bridge.localhost)
 *   RATE_LIMIT_HOURS — Hours between responses to same sender (default: 24)
 *   QUIET_MODE       — Suppress identifying log strings
 */

const net = require('net');
const crypto = require('crypto');
const { generateQrSvg, encodeBridgeConfig } = require('./qr-generator');

// --- Configuration ---
const config = {
  bridgeUrl: process.env.BRIDGE_URL,
  bridgeBPubkey: process.env.BRIDGE_B_PUBKEY || null,
  meekUrl: process.env.MEEK_URL || null,
  loxAuthorityUrl: process.env.LOX_AUTHORITY_URL || null,
  smtpPort: parseInt(process.env.SMTP_PORT) || 2525,
  smtpDomain: process.env.SMTP_DOMAIN || 'bridge.localhost',
  rateLimitMs: (parseInt(process.env.RATE_LIMIT_HOURS) || 24) * 60 * 60 * 1000,
  quiet: process.env.QUIET_MODE === '1',
};

// Parse CLI args
const args = process.argv.slice(2);
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--port') config.smtpPort = parseInt(args[++i]);
}

if (!config.bridgeUrl) {
  console.error('Error: BRIDGE_URL environment variable is required');
  process.exit(1);
}

// --- Rate Limiting ---
// Store SHA-256 hashes of sender addresses (not raw emails)
const senderHistory = new Map();

function hashSender(email) {
  return crypto.createHash('sha256').update(email.toLowerCase().trim()).digest('hex').slice(0, 16);
}

function isRateLimited(email) {
  const hash = hashSender(email);
  const lastSent = senderHistory.get(hash);
  if (lastSent && Date.now() - lastSent < config.rateLimitMs) {
    return true;
  }
  return false;
}

function recordSend(email) {
  const hash = hashSender(email);
  senderHistory.set(hash, Date.now());
}

// Cleanup old entries every hour
setInterval(() => {
  const cutoff = Date.now() - config.rateLimitMs;
  for (const [hash, time] of senderHistory) {
    if (time < cutoff) senderHistory.delete(hash);
  }
}, 60 * 60 * 1000);

// --- Lox Invitation Token ---
// When LOX_AUTHORITY_URL is configured, fetch an invitation token from the
// Lox authority instead of sending the bridge URL directly. This provides
// enumeration resistance — censors scraping emails only get one-time tokens,
// not reusable bridge URLs.
async function fetchLoxInviteToken() {
  if (!config.loxAuthorityUrl) return null;

  try {
    const http = require(config.loxAuthorityUrl.startsWith('https') ? 'https' : 'http');
    const url = `${config.loxAuthorityUrl}/lox/open-invite`;

    return new Promise((resolve) => {
      const req = http.request(url, { method: 'POST', headers: { 'Content-Type': 'application/json' } }, (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          try {
            const parsed = JSON.parse(data);
            resolve({ id: parsed.id, credential: parsed.credential });
          } catch {
            resolve(null);
          }
        });
      });
      req.on('error', () => resolve(null));
      req.write('{}');
      req.end();
    });
  } catch {
    return null;
  }
}

// --- Response Email ---
function buildResponse(sender, loxToken) {
  const qrPayload = loxToken
    ? encodeBridgeConfig({
        i: loxToken.id,           // Lox invitation ID
        c: loxToken.credential,   // Lox credential token
        a: config.loxAuthorityUrl, // Lox authority URL
      })
    : encodeBridgeConfig({
        url: config.bridgeUrl,
        pubkey: config.bridgeBPubkey,
        meek: config.meekUrl,
      });
  const qrSvg = generateQrSvg(qrPayload, { moduleSize: 4 });

  const boundary = `----=_Part_${Date.now()}`;
  const date = new Date().toUTCString();

  let bodyText = `Connection Information\n`;
  bodyText += `=====================\n\n`;
  if (loxToken) {
    bodyText += `This is a one-time invitation token for secure bridge access.\n`;
    bodyText += `Scan the QR code or enter these credentials in the app:\n\n`;
    bodyText += `Authority: ${config.loxAuthorityUrl}\n`;
    bodyText += `Token ID: ${loxToken.id}\n`;
    bodyText += `\nYour access will improve over time as trust is established.\n`;
  } else {
    bodyText += `Bridge URL: ${config.bridgeUrl}\n`;
    if (config.bridgeBPubkey) {
      bodyText += `Public Key: ${config.bridgeBPubkey}\n`;
    }
    if (config.meekUrl) {
      bodyText += `Fallback (meek): ${config.meekUrl}\n`;
    }
  }
  bodyText += `\nScan the attached QR code to configure automatically.\n`;
  bodyText += `\nThis is an automated response. Do not reply.\n`;

  let email = '';
  email += `From: noreply@${config.smtpDomain}\r\n`;
  email += `To: ${sender}\r\n`;
  email += `Date: ${date}\r\n`;
  email += `Subject: Your connection info\r\n`;
  email += `MIME-Version: 1.0\r\n`;
  email += `Content-Type: multipart/mixed; boundary="${boundary}"\r\n`;
  email += `\r\n`;
  email += `--${boundary}\r\n`;
  email += `Content-Type: text/plain; charset=utf-8\r\n`;
  email += `Content-Transfer-Encoding: 7bit\r\n`;
  email += `\r\n`;
  email += bodyText;
  email += `\r\n`;
  email += `--${boundary}\r\n`;
  email += `Content-Type: image/svg+xml; name="connection.svg"\r\n`;
  email += `Content-Disposition: attachment; filename="connection.svg"\r\n`;
  email += `Content-Transfer-Encoding: base64\r\n`;
  email += `\r\n`;
  // Base64 encode SVG in 76-char lines
  const svgB64 = Buffer.from(qrSvg).toString('base64');
  for (let i = 0; i < svgB64.length; i += 76) {
    email += svgB64.slice(i, i + 76) + '\r\n';
  }
  email += `--${boundary}--\r\n`;

  return email;
}

// --- Minimal SMTP Server ---
const server = net.createServer((socket) => {
  let sender = null;
  let recipient = null;
  let inData = false;
  let dataBuffer = '';

  const log = config.quiet
    ? () => {}
    : (msg) => console.log(`[SMTP] ${msg}`);

  socket.write(`220 ${config.smtpDomain} Service ready\r\n`);

  socket.on('data', (chunk) => {
    const lines = chunk.toString().split('\r\n');

    for (const line of lines) {
      if (!line && !inData) continue;

      if (inData) {
        if (line === '.') {
          // End of DATA
          inData = false;
          socket.write('250 OK\r\n');

          // Process the email
          if (sender) {
            if (isRateLimited(sender)) {
              log(`Rate limited: ${hashSender(sender)}`);
            } else {
              log(`Sending response to ${hashSender(sender)}`);
              recordSend(sender);
              // Fetch Lox token if authority is configured, then build response
              (async () => {
                try {
                  const loxToken = await fetchLoxInviteToken();
                  if (loxToken) log(`Lox token obtained for response`);
                  const response = buildResponse(sender, loxToken);
                  log(`Response built (${response.length} bytes)`);
                  // In a real deployment, send via an outbound SMTP relay.
                } catch (e) {
                  log(`Response build error: ${e.message}`);
                }
              })();
            }
          }

          sender = null;
          recipient = null;
          dataBuffer = '';
        } else {
          dataBuffer += line + '\n';
        }
        continue;
      }

      const cmd = line.toUpperCase();

      if (cmd.startsWith('EHLO') || cmd.startsWith('HELO')) {
        socket.write(`250-${config.smtpDomain}\r\n`);
        socket.write('250-SIZE 10240\r\n');
        socket.write('250 OK\r\n');
      } else if (cmd.startsWith('MAIL FROM:')) {
        sender = line.match(/<([^>]+)>/)?.[1] || line.slice(10).trim();
        socket.write('250 OK\r\n');
      } else if (cmd.startsWith('RCPT TO:')) {
        recipient = line.match(/<([^>]+)>/)?.[1] || line.slice(8).trim();
        socket.write('250 OK\r\n');
      } else if (cmd === 'DATA') {
        inData = true;
        socket.write('354 Start mail input\r\n');
      } else if (cmd === 'QUIT') {
        socket.write('221 Bye\r\n');
        socket.end();
      } else if (cmd === 'RSET') {
        sender = null;
        recipient = null;
        dataBuffer = '';
        socket.write('250 OK\r\n');
      } else if (cmd === 'NOOP') {
        socket.write('250 OK\r\n');
      } else {
        socket.write('500 Unrecognized command\r\n');
      }
    }
  });

  socket.on('error', (err) => {
    log(`Socket error: ${err.message}`);
  });

  socket.setTimeout(60000);
  socket.on('timeout', () => {
    socket.write('421 Timeout\r\n');
    socket.end();
  });
});

server.listen(config.smtpPort, '0.0.0.0', () => {
  if (!config.quiet) {
    console.log(`\nBridge Email Responder`);
    console.log(`SMTP listening on port ${config.smtpPort}`);
    console.log(`Bridge: ${config.bridgeUrl}`);
    if (config.bridgeBPubkey) console.log(`Public key: ${config.bridgeBPubkey.slice(0, 16)}...`);
    if (config.meekUrl) console.log(`meek fallback: ${config.meekUrl}`);
    console.log(`Rate limit: ${config.rateLimitMs / 3600000}h per sender\n`);
  }
});

server.on('error', (err) => {
  console.error(`SMTP server error: ${err.message}`);
  if (err.code === 'EACCES') {
    console.error('Hint: Port 25 requires root. Use --port 2525 or SMTP_PORT=2525');
  }
});
