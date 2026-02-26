/**
 * Cloudflare Worker — Tor Bridge + App Host
 *
 * Solves the bootstrap problem: serves the WASM privacy browser AND acts
 * as a meek bridge relay from the same domain. Censors see HTTPS traffic
 * to *.workers.dev — blocking it would cause collateral damage to thousands
 * of legitimate Cloudflare services.
 *
 * Routes:
 *   GET /           → cover site (looks like a blog)
 *   GET /?v=1       → the actual WASM app (steganographic URL)
 *   POST /          → meek bridge relay (X-Session-Id + X-Target headers)
 *   GET /health     → cover site (unless HEALTH_TOKEN matches)
 *   Everything else → cover site
 *
 * The meek relay uses Durable Objects to maintain TCP sessions across
 * HTTP requests (Durable Objects survive ~60s of idle time).
 */

export interface Env {
  MEEK_SESSION: DurableObjectNamespace;
  COVER_TITLE: string;
  TOR_GUARD_HOST?: string;
  TOR_GUARD_PORT?: string;
  APP_SECRET?: string;
  HEALTH_TOKEN?: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // meek bridge: POST requests with X-Session-Id
    if (request.method === 'POST' && request.headers.has('x-session-id')) {
      return handleMeekPost(request, env);
    }

    // App delivery: GET /?v=1 (or custom secret)
    if (request.method === 'GET' && url.searchParams.has('v')) {
      const v = url.searchParams.get('v');
      const secret = env.APP_SECRET || '1';
      if (v === secret) {
        return serveApp(env);
      }
    }

    // Health check (authenticated)
    if (url.pathname === '/health' && env.HEALTH_TOKEN) {
      const token = url.searchParams.get('token') || request.headers.get('x-health-token');
      if (token === env.HEALTH_TOKEN) {
        return new Response(JSON.stringify({
          status: 'ok',
          guard: env.TOR_GUARD_HOST ? 'configured' : 'not configured',
          timestamp: Date.now(),
        }), {
          headers: coverHeaders('application/json'),
        });
      }
    }

    // Everything else: cover site
    return serveCover(env);
  },
};

// --- Cover Site ---
// A minimal but convincing blog page. Active probers see this for every
// path, every method (except meek POST). Headers mimic nginx.

function coverHeaders(contentType = 'text/html; charset=utf-8'): Record<string, string> {
  return {
    'content-type': contentType,
    'server': 'nginx/1.24.0',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'SAMEORIGIN',
    'cache-control': 'public, max-age=3600',
  };
}

function serveCover(env: Env): Response {
  const title = env.COVER_TITLE || "Alex's Blog";
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title}</title>
  <style>
    body { font-family: Georgia, serif; max-width: 680px; margin: 40px auto; padding: 0 20px; color: #333; line-height: 1.7; }
    h1 { font-size: 2em; margin-bottom: 0.3em; }
    .meta { color: #888; font-size: 0.9em; margin-bottom: 2em; }
    p { margin-bottom: 1.2em; }
    footer { margin-top: 4em; padding-top: 1em; border-top: 1px solid #eee; color: #aaa; font-size: 0.85em; }
    a { color: #2563eb; }
  </style>
</head>
<body>
  <h1>${title}</h1>
  <div class="meta">Personal thoughts on technology and design</div>

  <h2>On Building Things That Last</h2>
  <p class="meta">February 2026</p>
  <p>There is a certain satisfaction in building software that withstands the test of time.
  Not because it is complex, but because it is simple enough to remain useful as the world
  around it changes.</p>
  <p>The best tools I have used share a common trait: they do one thing well and stay out
  of the way. A good text editor, a reliable version control system, a fast compiler &mdash;
  these are the building blocks of productive work.</p>
  <p>I have been thinking about this a lot lately as I work on a new project. The temptation
  to add features is constant, but restraint is what separates a tool from a toy.</p>

  <footer>&copy; 2026 ${title}. Built with care.</footer>
</body>
</html>`;

  return new Response(html, {
    status: 200,
    headers: coverHeaders(),
  });
}

// --- App Delivery ---
// Serves the WASM privacy browser. In production, this would embed the built
// app assets (HTML + WASM + JS) directly in the Worker. For development,
// it returns a bootstrap page that loads from the app/ directory.

function serveApp(env: Env): Response {
  // In production, this would serve the embedded app bundle.
  // For now, serve a bootstrap page that explains deployment.
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>Browse</title>
  <style>
    body { background: #1a1a2e; color: #e2e8f0; font-family: system-ui, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
    .setup { text-align: center; max-width: 400px; padding: 20px; }
    h2 { color: #6366f1; margin-bottom: 16px; }
    p { color: #718096; line-height: 1.6; }
    code { background: #16213e; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; }
  </style>
</head>
<body>
  <div class="setup">
    <h2>Worker Deployed</h2>
    <p>To serve the app from this Worker, run the build script to embed app assets:</p>
    <p><code>cd worker && node build.sh</code></p>
    <p>This will inline the WASM module, JavaScript, and HTML into the Worker bundle.</p>
    <p>The meek bridge relay is already active on <code>POST /</code>.</p>
  </div>
</body>
</html>`;

  return new Response(html, {
    status: 200,
    headers: coverHeaders(),
  });
}

// --- Meek Bridge Relay ---
// Each POST carries Tor data. X-Session-Id identifies the persistent session.
// X-Target is the initial relay target (host:port). The Durable Object holds
// the TCP socket to the Tor guard across multiple HTTP requests.
//
// Protocol (matches server-meek.js and WASM meek client):
//   POST / with X-Session-Id: <uuid> and X-Target: <host:port>
//   Body: raw Tor cells (binary)
//   Response: buffered Tor cells from the relay (binary)

async function handleMeekPost(request: Request, env: Env): Promise<Response> {
  const sessionId = request.headers.get('x-session-id');
  if (!sessionId || sessionId.length > 128) {
    return serveCover(env); // Invalid session — look like cover site
  }

  // Route to Durable Object by session ID
  const id = env.MEEK_SESSION.idFromName(sessionId);
  const stub = env.MEEK_SESSION.get(id);

  // Forward the request to the Durable Object
  const target = request.headers.get('x-target') || '';
  const guardHost = env.TOR_GUARD_HOST || '';
  const guardPort = env.TOR_GUARD_PORT || '443';

  const doRequest = new Request(request.url, {
    method: 'POST',
    headers: {
      'x-target': target || `${guardHost}:${guardPort}`,
      'content-type': 'application/octet-stream',
    },
    body: request.body,
  });

  try {
    return await stub.fetch(doRequest);
  } catch (e) {
    // Durable Object error — return empty response (meek client will retry)
    return new Response(new Uint8Array(0), {
      status: 200,
      headers: {
        'content-type': 'application/octet-stream',
        'server': 'nginx/1.24.0',
      },
    });
  }
}

// --- Meek Session Durable Object ---
// Maintains a persistent TCP connection to a Tor guard relay across
// multiple HTTP POST requests. Uses Cloudflare's `connect()` TCP API.
//
// Session lifecycle:
//   1. First POST with X-Target → connect to relay
//   2. Subsequent POSTs → relay data, return buffered response
//   3. Idle timeout (~60s) → Durable Object hibernates, TCP closes

export class MeekSession {
  private state: DurableObjectState;
  private socket: any | null = null;
  private recvBuffer: Uint8Array[] = [];
  private connected = false;
  private target = '';

  constructor(state: DurableObjectState) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    const target = request.headers.get('x-target') || '';
    const body = await request.arrayBuffer();

    // Connect on first request (or reconnect if target changed)
    if (!this.connected || (target && target !== this.target)) {
      await this.connectToRelay(target);
    }

    // Send data to relay
    if (this.socket && body.byteLength > 0) {
      try {
        const writer = this.socket.writable.getWriter();
        await writer.write(new Uint8Array(body));
        writer.releaseLock();
      } catch (e) {
        this.connected = false;
        return new Response(new Uint8Array(0), {
          status: 200,
          headers: { 'content-type': 'application/octet-stream' },
        });
      }
    }

    // Read buffered response data (non-blocking)
    // Give the relay a brief moment to respond
    await new Promise(r => setTimeout(r, 50));
    const responseData = this.drainRecvBuffer();

    return new Response(responseData, {
      status: 200,
      headers: {
        'content-type': 'application/octet-stream',
        'server': 'nginx/1.24.0',
      },
    });
  }

  private async connectToRelay(target: string): Promise<void> {
    if (this.socket) {
      try { this.socket.close(); } catch (e) { /* ignore */ }
    }

    this.target = target;
    this.recvBuffer = [];
    this.connected = false;

    if (!target || !target.includes(':')) {
      return;
    }

    const [host, portStr] = target.split(':');
    const port = parseInt(portStr);
    if (!host || isNaN(port)) return;

    try {
      // Cloudflare Workers connect() API for raw TCP
      this.socket = connect({ hostname: host, port }, { secureTransport: 'on' });
      this.connected = true;

      // Background read loop
      this.readLoop();
    } catch (e) {
      this.connected = false;
    }
  }

  private async readLoop(): Promise<void> {
    if (!this.socket) return;

    try {
      const reader = this.socket.readable.getReader();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          this.recvBuffer.push(new Uint8Array(value));
        }
      }
    } catch (e) {
      // Socket closed or errored
    }
    this.connected = false;
  }

  private drainRecvBuffer(): Uint8Array {
    if (this.recvBuffer.length === 0) return new Uint8Array(0);

    const totalLen = this.recvBuffer.reduce((sum, buf) => sum + buf.length, 0);
    const result = new Uint8Array(totalLen);
    let offset = 0;
    for (const buf of this.recvBuffer) {
      result.set(buf, offset);
      offset += buf.length;
    }
    this.recvBuffer = [];
    return result;
  }
}
