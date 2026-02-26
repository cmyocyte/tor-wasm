#!/usr/bin/env node
/**
 * Build script: embeds app/index.html into the Worker's serveApp() function.
 *
 * Usage: node build.js
 *
 * This reads app/index.html, escapes it for a template literal, and patches
 * worker/src/index.ts so that serveApp() returns the real app instead of a
 * placeholder. The WASM module is loaded from WASM_BASE_URL (defaults to
 * the GitHub repo's pkg/ directory via GitHub Pages or raw.githubusercontent).
 */

const fs = require('fs');
const path = require('path');

const APP_HTML_PATH = path.join(__dirname, '..', 'app', 'index.html');
const WORKER_SRC = path.join(__dirname, 'src', 'index.ts');
const SW_PATH = path.join(__dirname, '..', 'app', 'sw.js');
const MANIFEST_PATH = path.join(__dirname, '..', 'app', 'manifest.json');

// Read app HTML
let html = fs.readFileSync(APP_HTML_PATH, 'utf-8');

// Rewrite WASM import path: ../pkg/ -> served from Worker routes
// The Worker will serve /pkg/tor_wasm.js and /pkg/tor_wasm_bg.wasm
// via a WASM_BASE_URL (GitHub raw or R2 bucket)
html = html.replace(
  `from '../pkg/tor_wasm.js'`,
  `from './pkg/tor_wasm.js'`
);

// Remove manifest link (Worker serves inline)
html = html.replace(
  `<link rel="manifest" href="manifest.json">`,
  `<link rel="manifest" href="./manifest.json">`
);

// Escape backticks and ${} for template literal embedding
const escaped = html
  .replace(/\\/g, '\\\\')
  .replace(/`/g, '\\`')
  .replace(/\$\{/g, '\\${');

// Read the Worker source
let workerSrc = fs.readFileSync(WORKER_SRC, 'utf-8');

// Find and replace the serveApp function
const serveAppRegex = /function serveApp\(env: Env\): Response \{[\s\S]*?^}/m;
const newServeApp = `function serveApp(env: Env): Response {
  const html = \`${escaped}\`;

  return new Response(html, {
    status: 200,
    headers: coverHeaders(),
  });
}`;

if (!serveAppRegex.test(workerSrc)) {
  console.error('Could not find serveApp() function in worker/src/index.ts');
  process.exit(1);
}

workerSrc = workerSrc.replace(serveAppRegex, newServeApp);

// Also add routes for manifest.json and sw.js
const manifest = fs.readFileSync(MANIFEST_PATH, 'utf-8');
const sw = fs.readFileSync(SW_PATH, 'utf-8');

// Add static asset routes before the cover site fallback
const routeInsert = `
    // Static app assets (embedded by build.js)
    if (url.pathname === '/manifest.json') {
      return new Response(${JSON.stringify(manifest)}, {
        headers: { ...coverHeaders('application/manifest+json'), 'cache-control': 'public, max-age=86400' },
      });
    }
    if (url.pathname === '/sw.js') {
      return new Response(${JSON.stringify(sw)}, {
        headers: { ...coverHeaders('application/javascript'), 'service-worker-allowed': '/' },
      });
    }

    // Everything else: cover site`;

workerSrc = workerSrc.replace(
  '    // Everything else: cover site',
  routeInsert
);

fs.writeFileSync(WORKER_SRC, workerSrc);

console.log('Build complete:');
console.log(`  - Embedded app/index.html (${(html.length / 1024).toFixed(1)} KB)`);
console.log(`  - Embedded app/manifest.json (${(manifest.length / 1024).toFixed(1)} KB)`);
console.log(`  - Embedded app/sw.js (${(sw.length / 1024).toFixed(1)} KB)`);
console.log('  - Patched worker/src/index.ts');
console.log('');
console.log('Next: npx wrangler deploy');
