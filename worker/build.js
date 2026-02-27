#!/usr/bin/env node
/**
 * Build script: embeds the full app (HTML + WASM + JS) into the Worker.
 *
 * Usage: node build.js
 *
 * Reads app/index.html, app/sw.js, app/manifest.json, pkg/tor_wasm.js,
 * and pkg/tor_wasm_bg.wasm, then patches worker/src/index.ts to serve
 * everything from the Worker — no external dependencies.
 *
 * Total gzipped size: ~600KB (well under 1MB free tier limit).
 */

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const APP_HTML_PATH = path.join(__dirname, '..', 'app', 'index.html');
const WORKER_SRC = path.join(__dirname, 'src', 'index.ts');
const SW_PATH = path.join(__dirname, '..', 'app', 'sw.js');
const MANIFEST_PATH = path.join(__dirname, '..', 'app', 'manifest.json');
const WASM_JS_PATH = path.join(__dirname, '..', 'pkg', 'tor_wasm.js');
const WASM_BIN_PATH = path.join(__dirname, '..', 'pkg', 'tor_wasm_bg.wasm');

// Check all files exist
for (const [name, p] of [['app/index.html', APP_HTML_PATH], ['pkg/tor_wasm.js', WASM_JS_PATH], ['pkg/tor_wasm_bg.wasm', WASM_BIN_PATH]]) {
  if (!fs.existsSync(p)) {
    console.error(`Missing: ${name} — run 'wasm-pack build --target web --release' first`);
    process.exit(1);
  }
}

// Read app HTML
let html = fs.readFileSync(APP_HTML_PATH, 'utf-8');

// Rewrite WASM import path: ../pkg/ -> /pkg/ (served by Worker)
html = html.replace(
  `from '../pkg/tor_wasm.js'`,
  `from '/pkg/tor_wasm.js'`
);

// Fix manifest path for Worker-served route
html = html.replace(
  `<link rel="manifest" href="manifest.json">`,
  `<link rel="manifest" href="/manifest.json">`
);

// Escape backticks and ${} for template literal embedding
const escaped = html
  .replace(/\\/g, '\\\\')
  .replace(/`/g, '\\`')
  .replace(/\$\{/g, '\\${');

// Read the Worker source
let workerSrc = fs.readFileSync(WORKER_SRC, 'utf-8');

// Replace serveApp() with embedded HTML — use no-store to prevent caching issues
const serveAppRegex = /function serveApp\(env: Env\): Response \{[\s\S]*?^} \/\/ end serveApp/m;
const newServeApp = `function serveApp(env: Env): Response {
  const html = \`${escaped}\`;

  return new Response(html, {
    status: 200,
    headers: { ...coverHeaders(), 'cache-control': 'no-store' },
  });
} // end serveApp`;

if (!serveAppRegex.test(workerSrc)) {
  console.error('Could not find serveApp() function in worker/src/index.ts');
  process.exit(1);
}

workerSrc = workerSrc.replace(serveAppRegex, newServeApp);

// Read all assets
const manifest = fs.readFileSync(MANIFEST_PATH, 'utf-8');
let sw = fs.readFileSync(SW_PATH, 'utf-8');
const wasmJs = fs.readFileSync(WASM_JS_PATH, 'utf-8');
const wasmBin = fs.readFileSync(WASM_BIN_PATH);
const wasmGz = zlib.gzipSync(wasmBin, { level: 9 });
const wasmB64 = wasmGz.toString('base64');

// Patch SW: fix asset paths for Worker (../pkg/ -> /pkg/)
// and bump cache version to invalidate stale caches
sw = sw.replace(`'../pkg/tor_wasm.js'`, `'/pkg/tor_wasm.js'`);
sw = sw.replace(`'../pkg/tor_wasm_bg.wasm'`, `'/pkg/tor_wasm_bg.wasm'`);
sw = sw.replace(`'./'`, `'/'`);
sw = sw.replace(`'./index.html'`, `'/?v=1'`);
sw = sw.replace(`'./manifest.json'`, `'/manifest.json'`);
sw = sw.replace(/const CACHE = '[^']+';/, `const CACHE = 'worker-v1';`);

// Escape for embedding as a string
const wasmJsEscaped = wasmJs
  .replace(/\\/g, '\\\\')
  .replace(/`/g, '\\`')
  .replace(/\$\{/g, '\\${');

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
        headers: { ...coverHeaders('application/javascript'), 'service-worker-allowed': '/', 'cache-control': 'no-store' },
      });
    }
    if (url.pathname === '/pkg/tor_wasm.js') {
      const js = \`${wasmJsEscaped}\`;
      return new Response(js, {
        headers: { ...coverHeaders('application/javascript'), 'cache-control': 'public, max-age=86400' },
      });
    }
    if (url.pathname === '/pkg/tor_wasm_bg.wasm') {
      const wasmGz = Uint8Array.from(atob("${wasmB64}"), c => c.charCodeAt(0));
      const ds = new DecompressionStream('gzip');
      const decompressed = new Response(wasmGz).body!.pipeThrough(ds);
      return new Response(decompressed, {
        headers: { ...coverHeaders('application/wasm'), 'cache-control': 'public, max-age=86400' },
      });
    }

    // Everything else: cover site`;

workerSrc = workerSrc.replace(
  '    // Everything else: cover site',
  routeInsert
);

fs.writeFileSync(WORKER_SRC, workerSrc);

console.log('Build complete:');
console.log(`  - app/index.html:        ${(html.length / 1024).toFixed(1)} KB`);
console.log(`  - app/manifest.json:     ${(manifest.length / 1024).toFixed(1)} KB`);
console.log(`  - app/sw.js:             ${(sw.length / 1024).toFixed(1)} KB (paths patched)`);
console.log(`  - pkg/tor_wasm.js:       ${(wasmJs.length / 1024).toFixed(1)} KB`);
console.log(`  - pkg/tor_wasm_bg.wasm:  ${(wasmBin.length / 1024).toFixed(1)} KB → ${(wasmGz.length / 1024).toFixed(1)} KB gzipped (${(wasmB64.length / 1024).toFixed(1)} KB base64)`);
console.log(`  - Total embedded:        ${((html.length + manifest.length + sw.length + wasmJs.length + wasmB64.length) / 1024).toFixed(1)} KB`);
console.log('  - Patched worker/src/index.ts');
console.log('');
console.log('Next: npx wrangler deploy');
