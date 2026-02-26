/**
 * Cover Site Module
 *
 * Makes bridge servers indistinguishable from normal websites to active probers.
 *
 * Configuration (env vars):
 *   COVER_SITE_DIR   — Path to static site directory (serves files from disk)
 *   COVER_SITE_URL   — URL to reverse-proxy (makes bridge look like that site)
 *   COVER_SITE_TITLE — Title for the default page (default: "Welcome")
 *
 * Priority: COVER_SITE_DIR > COVER_SITE_URL > default page
 */

const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');

const COVER_DIR = process.env.COVER_SITE_DIR || null;
const COVER_URL = process.env.COVER_SITE_URL || null;
const COVER_TITLE = process.env.COVER_SITE_TITLE || 'Welcome';

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain',
  '.xml': 'text/xml',
  '.webp': 'image/webp',
};

// Standard headers that make us look like nginx
const STANDARD_HEADERS = {
  'Server': 'nginx/1.24.0',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'SAMEORIGIN',
  'Cache-Control': 'public, max-age=3600',
};

function setStandardHeaders(res) {
  for (const [k, v] of Object.entries(STANDARD_HEADERS)) {
    res.setHeader(k, v);
  }
  // Remove any identifying headers
  res.removeHeader('X-Powered-By');
}

/**
 * Default HTML page — looks like a generic web service
 */
function getDefaultPage(statusCode) {
  const is404 = statusCode === 404;
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${is404 ? 'Page Not Found' : COVER_TITLE}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
background:#f8f9fa;color:#333;min-height:100vh;display:flex;align-items:center;justify-content:center}
.container{text-align:center;padding:2rem}
h1{font-size:1.5rem;font-weight:400;margin-bottom:.5rem;color:#555}
p{color:#888;font-size:.9rem}
</style>
</head>
<body>
<div class="container">
<h1>${is404 ? '404 — Page Not Found' : COVER_TITLE}</h1>
<p>${is404 ? 'The page you requested could not be found.' : ''}</p>
</div>
</body>
</html>`;
}

/**
 * Generate a robots.txt response
 */
function getRobotsTxt() {
  return 'User-agent: *\nDisallow: /\n';
}

/**
 * Generate a minimal favicon (1x1 transparent ICO)
 */
const EMPTY_FAVICON = Buffer.from(
  'AAABAAEAAQEAAAEAGAAwAAAAFgAAACgAAAABAAAAAgAAAAEAGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP8AAAA=',
  'base64'
);

/**
 * Serve static files from COVER_SITE_DIR
 */
function serveStatic(req, res) {
  let reqPath = req.url.split('?')[0];
  if (reqPath === '/') reqPath = '/index.html';

  const resolved = path.resolve(COVER_DIR, '.' + reqPath);
  if (!resolved.startsWith(path.resolve(COVER_DIR))) {
    setStandardHeaders(res);
    res.writeHead(403, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(getDefaultPage(404));
    return;
  }

  fs.readFile(resolved, (err, data) => {
    setStandardHeaders(res);
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(getDefaultPage(404));
      return;
    }
    const ext = path.extname(resolved).toLowerCase();
    const mime = MIME_TYPES[ext] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': mime });
    res.end(data);
  });
}

/**
 * Reverse-proxy to COVER_SITE_URL
 */
function serveProxy(req, res) {
  const target = new URL(req.url, COVER_URL);
  const mod = target.protocol === 'https:' ? https : http;

  const proxyReq = mod.request(target.href, {
    method: req.method,
    headers: {
      ...req.headers,
      host: target.host,
    },
    timeout: 5000,
  }, (proxyRes) => {
    setStandardHeaders(res);
    // Copy status and selected headers from upstream
    const copyHeaders = ['content-type', 'content-length', 'etag', 'last-modified'];
    for (const h of copyHeaders) {
      if (proxyRes.headers[h]) res.setHeader(h, proxyRes.headers[h]);
    }
    res.writeHead(proxyRes.statusCode);
    proxyRes.pipe(res);
  });

  proxyReq.on('error', () => {
    // Upstream failed — serve default page instead of exposing error
    setStandardHeaders(res);
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(getDefaultPage(200));
  });

  proxyReq.on('timeout', () => {
    proxyReq.destroy();
    setStandardHeaders(res);
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(getDefaultPage(200));
  });

  if (req.method === 'POST' || req.method === 'PUT') {
    req.pipe(proxyReq);
  } else {
    proxyReq.end();
  }
}

/**
 * Serve default page
 */
function serveDefault(req, res, statusCode = 200) {
  const reqPath = req.url.split('?')[0];

  setStandardHeaders(res);

  if (reqPath === '/robots.txt') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(getRobotsTxt());
    return;
  }

  if (reqPath === '/favicon.ico') {
    res.writeHead(200, { 'Content-Type': 'image/x-icon', 'Cache-Control': 'public, max-age=86400' });
    res.end(EMPTY_FAVICON);
    return;
  }

  const code = (reqPath === '/' || reqPath === '/index.html') ? 200 : statusCode;
  res.writeHead(code, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(getDefaultPage(code));
}

/**
 * Main entry point — serve a cover response for any unhandled HTTP request.
 * Call this instead of returning 404.
 */
function serveCoverSite(req, res) {
  if (COVER_DIR) {
    return serveStatic(req, res);
  }
  if (COVER_URL) {
    return serveProxy(req, res);
  }
  return serveDefault(req, res, 404);
}

module.exports = { serveCoverSite, setStandardHeaders, STANDARD_HEADERS };
