const CACHE = 'v22';
const ASSETS = [
    './',
    './index.html',
    './manifest.json',
    '../pkg/tor_wasm.js',
    '../pkg/tor_wasm_bg.wasm',
];

// --- Tor Proxy State ---
let coordinatorId = null;
const pending = new Map();
let nextId = 0;
const PROXY_TIMEOUT = 30000;

// --- Session Cache (in-memory, within SW lifetime) ---
const sessionCache = new Map();
const SESSION_CACHE_MAX = 500;
const STATIC_CACHE_TTL = 30 * 60 * 1000;   // 30 min for fonts, images, CSS, JS
const HTML_CACHE_TTL = 5 * 60 * 1000;       // 5 min for HTML/dynamic

// --- In-flight Dedup ---
const inflight = new Map();

// --- Resource Progress Tracking ---
let resourceStats = { pending: 0, completed: 0, blocked: 0 };
let broadcastTimer = null;

// --- Tracker/Ad Blocking ---
// Suffix-match on hostname (covers subdomains automatically)
const TRACKER_SUFFIXES = [
    '.doubleclick.net', '.googlesyndication.com', '.google-analytics.com',
    '.googletagmanager.com', '.googleadservices.com',
    '.facebook.net', '.fbcdn.net',
    '.onesignal.com', '.permutive.com', '.parsely.com',
    '.btloader.com', '.pub.network', '.viafoura.co',
    '.chartbeat.com', '.scorecardresearch.com', '.quantserve.com',
    '.taboola.com', '.outbrain.com', '.newrelic.com', '.nr-data.net',
    '.hotjar.com', '.clarity.ms', '.fullstory.com',
    '.segment.io', '.segment.com', '.amplitude.com', '.mixpanel.com',
    '.optimizely.com', '.crazyegg.com', '.mouseflow.com',
    '.moatads.com', '.adsrvr.org', '.adnxs.com',
];

// Exact hostname matches (obfuscated tracker domains, etc.)
const TRACKER_EXACT = new Set([
    'bat.bing.com', 'tr.snapchat.com',
    // Obfuscated tracker domains seen in AP News
    'soup.ickfinallyonly.com', 'rule.witharound.com',
    'cope.whenmehany.com', 'epic.decryptionjunior.com',
]);

function isBlocked(hostname) {
    if (TRACKER_EXACT.has(hostname)) return true;
    for (const suffix of TRACKER_SUFFIXES) {
        if (hostname.endsWith(suffix) || hostname === suffix.substring(1)) return true;
    }
    return false;
}

function isStaticAsset(url) {
    const ext = new URL(url).pathname.split('.').pop().split('?')[0].toLowerCase();
    return ['woff', 'woff2', 'ttf', 'otf', 'eot',
            'png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'ico', 'avif',
            'css', 'js', 'mjs'].includes(ext);
}

function getCacheTTL(url) {
    return isStaticAsset(url) ? STATIC_CACHE_TTL : HTML_CACHE_TTL;
}

// Priority: lower = higher priority (CSS first, images last)
function getPriority(request) {
    switch (request.destination) {
        case 'style': return 0;
        case 'script': return 1;
        case 'font': return 2;
        case 'document': return 2;
        case 'image': return 4;
        default: return 3;
    }
}

// --- Install: cache app assets ---
self.addEventListener('install', (e) => {
    e.waitUntil(
        caches.open(CACHE)
            .then(cache => cache.addAll(ASSETS))
            .then(() => self.skipWaiting())
    );
});

// --- Activate: clean old caches, claim all clients ---
self.addEventListener('activate', (e) => {
    e.waitUntil(
        caches.keys()
            .then(keys => Promise.all(
                keys.filter(k => k !== CACHE).map(k => caches.delete(k))
            ))
            .then(() => self.clients.claim())
    );
});

// --- Messages from main page ---
self.addEventListener('message', (e) => {
    if (e.data.type === 'register-coordinator') {
        coordinatorId = e.source.id;
        return;
    }

    if (e.data.type === 'clear-session-cache') {
        sessionCache.clear();
        resourceStats = { pending: 0, completed: 0, blocked: 0 };
        return;
    }

    if (e.data.type === 'tor-response') {
        const p = pending.get(e.data.id);
        if (!p) return;
        pending.delete(e.data.id);

        if (e.data.error) {
            resourceStats.pending = Math.max(0, resourceStats.pending - 1);
            broadcastProgress();
            p.reject(new Error(e.data.error));
            return;
        }

        const rawHeaders = sanitizeHeaders(e.data.headers || {});
        const status = e.data.status || 200;
        const body = e.data.body;
        const binary = !!e.data.binary;

        // Cache before resolving
        if (status >= 200 && status < 400) {
            const cc = (rawHeaders['cache-control'] || '').toLowerCase();
            if (!cc.includes('no-store')) {
                if (sessionCache.size >= SESSION_CACHE_MAX) {
                    // Evict oldest entry
                    sessionCache.delete(sessionCache.keys().next().value);
                }
                let bodyBuf;
                if (binary && body instanceof ArrayBuffer) {
                    bodyBuf = body.slice(0);
                } else if (typeof body === 'string') {
                    bodyBuf = new TextEncoder().encode(body).buffer;
                } else {
                    bodyBuf = null;
                }
                if (bodyBuf && p.url) {
                    sessionCache.set(p.url, {
                        body: bodyBuf, status, headers: rawHeaders, binary, ts: Date.now()
                    });
                }
            }
        }

        // Update progress
        resourceStats.pending = Math.max(0, resourceStats.pending - 1);
        resourceStats.completed++;
        broadcastProgress();

        p.resolve(new Response(body, { status, headers: new Headers(rawHeaders) }));
    }
});

// --- Broadcast resource progress to clients (throttled) ---
function broadcastProgress() {
    if (broadcastTimer) return;
    broadcastTimer = setTimeout(async () => {
        broadcastTimer = null;
        const clients = await self.clients.matchAll({ type: 'window' });
        clients.forEach(c => c.postMessage({
            type: 'resource-progress',
            pending: resourceStats.pending,
            completed: resourceStats.completed,
            blocked: resourceStats.blocked,
        }));
    }, 150);
}

// --- Fetch interception ---
self.addEventListener('fetch', (e) => {
    const url = new URL(e.request.url);

    // Same-origin requests: serve app assets from cache
    if (url.origin === self.location.origin) {
        const isAsset = ASSETS.some(a => {
            const clean = a.replace(/^\.\//, '/').replace(/^\.\./, '');
            return url.pathname === clean || url.pathname.endsWith(clean);
        });
        if (isAsset) {
            e.respondWith(
                caches.match(e.request).then(cached => cached || fetch(e.request))
            );
        }
        return;
    }

    // Block trackers/ads — return empty 204 immediately (saves Tor bandwidth)
    if (isBlocked(url.hostname)) {
        resourceStats.blocked++;
        e.respondWith(new Response('', { status: 204 }));
        return;
    }

    // OPTIONS preflight — auto-respond with CORS headers (no Tor round-trip needed)
    if (e.request.method === 'OPTIONS') {
        e.respondWith(new Response(null, {
            status: 204,
            headers: new Headers({
                'access-control-allow-origin': self.location.origin,
                'access-control-allow-methods': 'GET, POST, PUT, DELETE, PATCH, OPTIONS',
                'access-control-allow-headers': '*',
                'access-control-allow-credentials': 'true',
                'access-control-max-age': '86400',
            })
        }));
        return;
    }

    // Cross-origin requests: proxy through Tor with priority
    e.respondWith(proxyViaTor(e.request));
});

// --- Build a fresh Response from cached data ---
function responseFromCache(entry) {
    const body = entry.binary
        ? entry.body.slice(0)             // clone ArrayBuffer
        : new TextDecoder().decode(entry.body); // back to string
    return new Response(body, {
        status: entry.status,
        headers: new Headers(entry.headers),
    });
}

// --- Proxy a request through Tor with caching + dedup ---
async function proxyViaTor(request) {
    const url = request.url;
    const isGet = request.method === 'GET';

    // 1. Session cache hit (GET only) — type-aware TTL
    if (isGet) {
        const cached = sessionCache.get(url);
        if (cached) {
            const ttl = getCacheTTL(url);
            if ((Date.now() - cached.ts) < ttl) {
                return responseFromCache(cached);
            }
            sessionCache.delete(url); // stale
        }
    }

    // 2. In-flight dedup: piggyback on existing request for same URL
    if (isGet && inflight.has(url)) {
        return new Promise((resolve, reject) => {
            inflight.get(url).waiters.push({ resolve, reject });
        });
    }

    // 3. Track progress (only for requests that actually go to Tor)
    resourceStats.pending++;
    broadcastProgress();

    // 4. Actual Tor fetch
    return doTorFetch(request);
}

// --- Perform the actual Tor fetch via postMessage to main page ---
async function doTorFetch(request) {
    // Find coordinator
    if (!coordinatorId) {
        const clients = await self.clients.matchAll({ type: 'window' });
        if (clients.length > 0) {
            coordinatorId = clients[0].id;
        } else {
            resourceStats.pending = Math.max(0, resourceStats.pending - 1);
            broadcastProgress();
            return new Response('Tor proxy not ready', { status: 503 });
        }
    }

    const coordinator = await self.clients.get(coordinatorId);
    if (!coordinator) {
        coordinatorId = null;
        resourceStats.pending = Math.max(0, resourceStats.pending - 1);
        broadcastProgress();
        return new Response('Tor proxy lost connection', { status: 503 });
    }

    const binary = isBinaryRequest(request);
    const url = request.url;
    const id = nextId++;
    const isGet = request.method === 'GET';
    const priority = getPriority(request);

    // Register in-flight for dedup
    let inflightEntry;
    if (isGet) {
        inflightEntry = { waiters: [] };
        inflight.set(url, inflightEntry);
    }

    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
            pending.delete(id);
            if (isGet) inflight.delete(url);
            resourceStats.pending = Math.max(0, resourceStats.pending - 1);
            broadcastProgress();
            const resp = new Response('Tor fetch timeout', { status: 504 });
            resolve(resp);
            if (inflightEntry) {
                inflightEntry.waiters.forEach(w => w.resolve(
                    new Response('Tor fetch timeout', { status: 504 })
                ));
            }
        }, PROXY_TIMEOUT);

        pending.set(id, {
            url,
            resolve: (resp) => {
                clearTimeout(timer);
                if (isGet) inflight.delete(url);
                resolve(resp);

                // Resolve dedup waiters with fresh Response from cache
                if (inflightEntry && inflightEntry.waiters.length > 0) {
                    const cached = sessionCache.get(url);
                    inflightEntry.waiters.forEach(w => {
                        if (cached) {
                            w.resolve(responseFromCache(cached));
                        } else {
                            w.resolve(new Response('', { status: resp.status }));
                        }
                    });
                }
            },
            reject: (err) => {
                clearTimeout(timer);
                if (isGet) inflight.delete(url);
                resolve(new Response(err.message, { status: 502 }));
                if (inflightEntry) {
                    inflightEntry.waiters.forEach(w => w.resolve(
                        new Response(err.message, { status: 502 })
                    ));
                }
            },
        });

        coordinator.postMessage({
            type: 'tor-fetch',
            id,
            url,
            binary,
            priority,
        });
    });
}

// --- Strip/replace headers for iframe embedding + CORS ---
function sanitizeHeaders(headers) {
    const clean = {};
    for (const [k, v] of Object.entries(headers)) {
        const lower = k.toLowerCase();
        // Strip embedding-blocking headers
        if (lower === 'x-frame-options') continue;
        if (lower === 'content-security-policy') continue;
        if (lower === 'content-security-policy-report-only') continue;
        // Strip existing CORS headers — we'll set our own
        if (lower === 'access-control-allow-origin') continue;
        if (lower === 'access-control-allow-credentials') continue;
        if (lower === 'access-control-allow-methods') continue;
        if (lower === 'access-control-allow-headers') continue;
        if (lower === 'access-control-expose-headers') continue;
        clean[k] = v;
    }
    // Set comprehensive CORS headers
    // Use explicit origin (not *) so credentialed requests (XHR with withCredentials) also work
    clean['access-control-allow-origin'] = self.location.origin;
    clean['access-control-allow-methods'] = 'GET, POST, PUT, DELETE, PATCH, OPTIONS';
    clean['access-control-allow-headers'] = '*';
    clean['access-control-allow-credentials'] = 'true';
    clean['access-control-expose-headers'] = '*';
    return clean;
}

// --- Detect binary content by request destination or URL extension ---
function isBinaryRequest(request) {
    const dest = request.destination;
    if (['image', 'font', 'audio', 'video'].includes(dest)) return true;

    const ext = new URL(request.url).pathname.split('.').pop().split('?')[0].toLowerCase();
    return ['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'ico', 'avif',
            'woff', 'woff2', 'ttf', 'otf', 'eot',
            'mp3', 'mp4', 'webm', 'ogg', 'pdf'].includes(ext);
}
