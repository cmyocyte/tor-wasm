/**
 * Cloudflare Worker — Tor Bridge + App Host
 *
 * Routes:
 *   GET /              → cover site (looks like a blog)
 *   GET /?v=1          → the actual WASM app (steganographic URL)
 *   WS  /?addr=h:p     → WebSocket bridge to relay (runs at edge)
 *   GET /tor/consensus  → proxy: fetches real Tor consensus from directory authorities
 *   POST /             → meek bridge relay (X-Session-Id + X-Target headers)
 *   GET /test-relay    → TCP reachability probe
 *   GET /health        → cover site (unless HEALTH_TOKEN matches)
 *   Everything else    → cover site
 */

import { connect } from 'cloudflare:sockets';

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

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'access-control-allow-origin': '*',
          'access-control-allow-methods': 'GET, POST, OPTIONS',
          'access-control-allow-headers': 'content-type, x-session-id, x-target, x-health-token',
          'access-control-max-age': '86400',
        },
      });
    }

    // WebSocket bridge: upgrade requests with ?addr=host:port
    if (request.headers.get('upgrade') === 'websocket' && url.searchParams.has('addr')) {
      return handleWebSocketBridge(url.searchParams.get('addr')!);
    }

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

    // Consensus proxy: fetch real relay data from Tor directory authorities
    if (url.pathname === '/tor/consensus') {
      return handleConsensusProxy();
    }

    // Test relay reachability
    if (url.pathname === '/test-relay' && url.searchParams.has('addr')) {
      return handleTestRelay(url.searchParams.get('addr')!);
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
          headers: corsHeaders('application/json'),
        });
      }
    }

    // Everything else: cover site
    return serveCover(env);
  },
};

// --- Cover Site ---

function coverHeaders(contentType = 'text/html; charset=utf-8'): Record<string, string> {
  return {
    'content-type': contentType,
    'server': 'nginx/1.24.0',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'SAMEORIGIN',
    'cache-control': 'public, max-age=3600',
  };
}

function corsHeaders(contentType = 'application/json'): Record<string, string> {
  return {
    ...coverHeaders(contentType),
    'access-control-allow-origin': '*',
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
// build.js replaces this function with embedded HTML + WASM + JS.
// The placeholder below is used during development.

function serveApp(env: Env): Response {
  return new Response('App not built. Run: cd worker && node build.js', {
    status: 500,
    headers: coverHeaders('text/plain'),
  });
} // end serveApp

// --- WebSocket Bridge ---

async function handleWebSocketBridge(addr: string): Promise<Response> {
  const colonIdx = addr.lastIndexOf(':');
  if (colonIdx <= 0) return new Response('Bad addr', { status: 400 });
  const host = addr.substring(0, colonIdx);
  const port = parseInt(addr.substring(colonIdx + 1));
  if (!host || isNaN(port)) return new Response('Bad addr', { status: 400 });

  const pair = new WebSocketPair();
  const [client, server] = pair;
  server.accept();

  let socket: any;
  try {
    socket = connect({ hostname: host, port }, { secureTransport: 'off' });
  } catch (e) {
    server.close(1011, 'TCP connect failed');
    return new Response(null, { status: 101, webSocket: client });
  }

  // WS → TCP
  server.addEventListener('message', async (event: MessageEvent) => {
    try {
      const writer = socket.writable.getWriter();
      if (event.data instanceof ArrayBuffer) {
        await writer.write(new Uint8Array(event.data));
      } else if (typeof event.data === 'string') {
        await writer.write(new TextEncoder().encode(event.data));
      }
      writer.releaseLock();
    } catch (e) {
      try { server.close(1011, 'TCP write failed'); } catch (_) {}
    }
  });

  server.addEventListener('close', () => { try { socket.close(); } catch (_) {} });
  server.addEventListener('error', () => { try { socket.close(); } catch (_) {} });

  // TCP → WS
  (async () => {
    try {
      const reader = socket.readable.getReader();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value && value.byteLength > 0) {
          try { server.send(value); } catch (e) { break; }
        }
      }
    } catch (e) {}
    try { server.close(1000, 'relay disconnected'); } catch (_) {}
  })();

  return new Response(null, { status: 101, webSocket: client });
}

// --- Consensus Proxy ---

interface ParsedRelay {
  nickname: string;
  fingerprint: string;
  address: string;
  port: number;
  bandwidth: number;
  flags: string[];
}

const DIRECTORY_AUTHORITIES = [
  { name: 'bastet', host: '204.13.164.118', port: 80 },
  { name: 'gabelmoo', host: '131.188.40.189', port: 80 },
  { name: 'tor26', host: '86.59.21.38', port: 80 },
  { name: 'moria1', host: '128.31.0.34', port: 9131 },
];

async function handleConsensusProxy(): Promise<Response> {
  const cache = caches.default;
  const cacheKey = new Request('https://tor-consensus-cache.internal/v2');
  const cached = await cache.match(cacheKey);
  if (cached) {
    return new Response(cached.body, {
      headers: corsHeaders(),
    });
  }

  for (const da of DIRECTORY_AUTHORITIES) {
    try {
      const result = await fetchConsensusFromDA(da);
      if (result) {
        const response = new Response(result, {
          headers: { ...corsHeaders(), 'cache-control': 'public, max-age=3600' },
        });
        await cache.put(cacheKey, response.clone());
        return response;
      }
    } catch (e) {
      continue;
    }
  }

  return new Response(JSON.stringify({ error: 'Failed to fetch consensus from directory authorities' }), {
    status: 503,
    headers: corsHeaders(),
  });
}

async function fetchConsensusFromDA(da: { name: string; host: string; port: number }): Promise<string | null> {
  const consensusText = await tcpFetchHttp(da.host, da.port, '/tor/status-vote/current/consensus', 15000, 4 * 1024 * 1024);

  const allRelays = parseConsensusRelays(consensusText);
  if (allRelays.length === 0) return null;

  const standardPorts = new Set([443, 80, 8080, 8443, 9001, 9030]);
  const filtered = allRelays
    .filter(r => r.flags.includes('Running') && r.flags.includes('Valid') && r.flags.includes('Fast'))
    .filter(r => r.flags.includes('Guard') || r.flags.includes('Exit'))
    .filter(r => standardPorts.has(r.port))
    .sort((a, b) => b.bandwidth - a.bandwidth)
    .slice(0, 200);

  if (filtered.length === 0) return null;

  const ntorKeys = await fetchNtorKeys(da.host, da.port, filtered.map(r => r.fingerprint));

  const responseRelays = filtered
    .filter(r => ntorKeys[r.fingerprint])
    .map(r => ({
      nickname: r.nickname,
      fingerprint: r.fingerprint,
      address: r.address,
      port: r.port,
      bandwidth: r.bandwidth,
      published: Math.floor(Date.now() / 1000),
      ntor_onion_key: ntorKeys[r.fingerprint],
      flags: {
        exit: r.flags.includes('Exit'),
        fast: r.flags.includes('Fast'),
        guard: r.flags.includes('Guard'),
        hsdir: r.flags.includes('HSDir'),
        running: r.flags.includes('Running'),
        stable: r.flags.includes('Stable'),
        v2dir: r.flags.includes('V2Dir'),
        valid: r.flags.includes('Valid'),
      },
    }));

  return JSON.stringify({
    consensus: {
      version: 3,
      relays: responseRelays,
    },
    raw_consensus: consensusText,
  });
}

function parseConsensusRelays(text: string): ParsedRelay[] {
  const relays: ParsedRelay[] = [];
  const lines = text.split('\n');
  let current: ParsedRelay | null = null;

  for (const line of lines) {
    if (line.startsWith('r ')) {
      const parts = line.split(' ');
      if (parts.length >= 9) {
        const fingerprint = b64ToHex(parts[2]);
        if (fingerprint) {
          current = {
            nickname: parts[1],
            fingerprint,
            address: parts[6],
            port: parseInt(parts[7]),
            bandwidth: 0,
            flags: [],
          };
          relays.push(current);
        }
      }
    } else if (line.startsWith('s ') && current) {
      current.flags = line.substring(2).trim().split(' ');
    } else if (line.startsWith('w ') && current) {
      const match = line.match(/Bandwidth=(\d+)/);
      if (match) current.bandwidth = parseInt(match[1]);
    }
  }

  return relays;
}

function b64ToHex(b64: string): string | null {
  try {
    let padded = b64;
    while (padded.length % 4 !== 0) padded += '=';
    const binary = atob(padded);
    if (binary.length !== 20) return null;
    return Array.from(binary)
      .map(c => c.charCodeAt(0).toString(16).padStart(2, '0'))
      .join('')
      .toUpperCase();
  } catch {
    return null;
  }
}

async function fetchNtorKeys(host: string, port: number, fingerprints: string[]): Promise<Record<string, string>> {
  const keys: Record<string, string> = {};

  for (let i = 0; i < fingerprints.length; i += 40) {
    const batch = fingerprints.slice(i, i + 40);
    const fpParam = batch.join('+');

    try {
      const text = await tcpFetchHttp(host, port, `/tor/server/fp/${fpParam}`, 15000, 2 * 1024 * 1024);

      let currentFp: string | null = null;
      for (const line of text.split('\n')) {
        const trimmed = line.trim();
        if (trimmed.startsWith('fingerprint ')) {
          const parts = trimmed.split(/\s+/).slice(1);
          currentFp = parts.join('').toUpperCase();
        } else if (trimmed.startsWith('ntor-onion-key ') && currentFp) {
          const key = trimmed.split(/\s+/)[1];
          if (key) {
            keys[currentFp] = key;
            currentFp = null;
          }
        } else if (trimmed.startsWith('router ')) {
          currentFp = null;
        }
      }
    } catch (e) {
      // Skip failed batch
    }
  }

  return keys;
}

async function tcpFetchHttp(host: string, port: number, path: string, timeoutMs: number, maxBytes: number): Promise<string> {
  const socket = connect({ hostname: host, port }, { secureTransport: 'off' });

  const request = `GET ${path} HTTP/1.0\r\nHost: ${host}\r\nUser-Agent: tor-wasm-proxy/1.0\r\n\r\n`;
  const writer = socket.writable.getWriter();
  await writer.write(new TextEncoder().encode(request));
  writer.releaseLock();

  const reader = socket.readable.getReader();
  const chunks: Uint8Array[] = [];
  let totalSize = 0;
  const deadline = Date.now() + timeoutMs;

  try {
    while (totalSize < maxBytes) {
      const remaining = deadline - Date.now();
      if (remaining <= 0) break;

      const timeoutPromise = new Promise<{ done: true; value: undefined }>(resolve =>
        setTimeout(() => resolve({ done: true, value: undefined }), remaining)
      );
      const readPromise = reader.read();
      const result = await Promise.race([readPromise, timeoutPromise]);

      if (result.done) break;
      if (result.value) {
        chunks.push(new Uint8Array(result.value));
        totalSize += result.value.byteLength;
      }
    }
  } finally {
    try { reader.releaseLock(); } catch (_) {}
    try { socket.close(); } catch (_) {}
  }

  const combined = new Uint8Array(totalSize);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.length;
  }

  const text = new TextDecoder().decode(combined);
  const headerEnd = text.indexOf('\r\n\r\n');
  if (headerEnd < 0) throw new Error('No HTTP header terminator');

  const statusLine = text.substring(0, text.indexOf('\r\n'));
  if (!statusLine.includes(' 200 ')) throw new Error(`HTTP error: ${statusLine}`);

  return text.substring(headerEnd + 4);
}

// --- Test Relay Reachability ---

async function handleTestRelay(addr: string): Promise<Response> {
  const colonIdx = addr.lastIndexOf(':');
  if (colonIdx <= 0) {
    return new Response(JSON.stringify({ error: 'bad addr' }), { headers: corsHeaders() });
  }
  const host = addr.substring(0, colonIdx);
  const port = parseInt(addr.substring(colonIdx + 1));

  const start = Date.now();
  try {
    const socket = connect({ hostname: host, port }, { secureTransport: 'off' });
    const reader = socket.readable.getReader();
    const timeout = new Promise<null>(r => setTimeout(() => r(null), 5000));
    const read = reader.read().then(r => r);
    const result = await Promise.race([read, timeout]);
    try { reader.releaseLock(); socket.close(); } catch (_) {}

    return new Response(JSON.stringify({
      addr, reachable: true, elapsed_ms: Date.now() - start,
      got_data: result !== null && !(result as any).done,
    }), { headers: corsHeaders() });
  } catch (e: any) {
    return new Response(JSON.stringify({
      addr, reachable: false, elapsed_ms: Date.now() - start, error: e?.message || String(e),
    }), { headers: corsHeaders() });
  }
}

// --- Meek Bridge Relay ---

async function handleMeekPost(request: Request, env: Env): Promise<Response> {
  const sessionId = request.headers.get('x-session-id');
  if (!sessionId || sessionId.length > 128) {
    return serveCover(env);
  }

  const id = env.MEEK_SESSION.idFromName(sessionId);
  const stub = env.MEEK_SESSION.get(id);

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
    return new Response(new Uint8Array(0), {
      status: 200,
      headers: { 'content-type': 'application/octet-stream', 'server': 'nginx/1.24.0' },
    });
  }
}

// --- Meek Session Durable Object ---

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

    if (!this.connected || (target && target !== this.target)) {
      await this.connectToRelay(target);
    }

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

    await new Promise(r => setTimeout(r, 300));
    const responseData = this.drainRecvBuffer();

    return new Response(responseData, {
      status: 200,
      headers: { 'content-type': 'application/octet-stream', 'server': 'nginx/1.24.0' },
    });
  }

  private async connectToRelay(target: string): Promise<void> {
    if (this.socket) {
      try { this.socket.close(); } catch (e) {}
    }

    this.target = target;
    this.recvBuffer = [];
    this.connected = false;

    if (!target || !target.includes(':')) return;

    const [host, portStr] = target.split(':');
    const port = parseInt(portStr);
    if (!host || isNaN(port)) return;

    try {
      this.socket = connect({ hostname: host, port }, { secureTransport: 'off' });
      this.connected = true;
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
        if (value) this.recvBuffer.push(new Uint8Array(value));
      }
    } catch (e) {}
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
