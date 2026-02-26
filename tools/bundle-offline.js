#!/usr/bin/env node
// bundle-offline.js — Generates a single self-contained HTML file (~3-4MB)
// containing the entire Tor-based privacy browser. The output can be shared
// via USB, Bluetooth, AirDrop, or Telegram during internet shutdowns.

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const APP = path.join(ROOT, 'app');
const PKG = path.join(ROOT, 'pkg');

// ---- CLI argument parsing ----

const args = process.argv.slice(2);
let bridgesFile = null;
let outputFile = 'offline.html';

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--help' || args[i] === '-h') {
    console.log(`Usage: node tools/bundle-offline.js [options]

Options:
  --bridges <file>   JSON file with bridge configs (optional)
  --output <file>    Output HTML path (default: offline.html)
  --help             Show this help`);
    process.exit(0);
  } else if (args[i] === '--bridges' && args[i + 1]) {
    bridgesFile = args[++i];
  } else if (args[i] === '--output' && args[i + 1]) {
    outputFile = args[++i];
  } else {
    console.error(`Unknown option: ${args[i]}`);
    process.exit(1);
  }
}

// ---- Helper: read a file or exit with a helpful message ----

function readFile(relPath, description) {
  const full = path.resolve(ROOT, relPath);
  if (!fs.existsSync(full)) {
    console.error(`Missing ${description}: ${full}`);
    if (relPath.startsWith('pkg/')) {
      console.error('  Build WASM first:  wasm-pack build --target web --release');
    }
    process.exit(1);
  }
  return fs.readFileSync(full);
}

// ---- 1. Read source files ----

console.log('Reading source files...');
let html = readFile('app/index.html', 'app HTML').toString('utf-8');
const wasmBytes = readFile('pkg/tor_wasm_bg.wasm', 'WASM binary');
const wasmJs = readFile('pkg/tor_wasm.js', 'WASM JS glue').toString('utf-8');
const swJs = readFile('app/sw.js', 'service worker').toString('utf-8');

// ---- 2. Embed i18n translations ----

const i18nDir = path.join(APP, 'i18n');
const i18n = {};
if (fs.existsSync(i18nDir)) {
  for (const file of fs.readdirSync(i18nDir).filter(f => f.endsWith('.json'))) {
    const lang = path.basename(file, '.json');
    i18n[lang] = JSON.parse(fs.readFileSync(path.join(i18nDir, file), 'utf-8'));
    console.log(`  i18n: ${lang} (${Object.keys(i18n[lang]).length} keys)`);
  }
}

// Replace the async fetch-based loadTranslation with a synchronous lookup.
// The original pattern:  const resp = await fetch(`i18n/${lang}.json`);
html = html.replace(
  /async function loadTranslation\(lang\)\s*\{[\s\S]*?return null;\s*\}\s*\}/,
  `async function loadTranslation(lang) {
                if (TRANSLATIONS[lang]) return TRANSLATIONS[lang];
                const EMBEDDED_I18N = ${JSON.stringify(i18n)};
                if (EMBEDDED_I18N[lang]) { TRANSLATIONS[lang] = EMBEDDED_I18N[lang]; return EMBEDDED_I18N[lang]; }
                return null;
            }`
);

// ---- 3. Embed WASM as base64 data URI ----

const wasmBase64 = wasmBytes.toString('base64');
console.log(`  WASM: ${(wasmBytes.length / 1024 / 1024).toFixed(2)} MB -> ${(wasmBase64.length / 1024 / 1024).toFixed(2)} MB base64`);

// Replace the ES module import with an inline WASM loader.
// Original: import init, { TorClient, apply_fingerprint_defense } from '../pkg/tor_wasm.js';
const wasmLoader = `
        // --- Inline WASM loader (offline bundle) ---
        const _wasmBase64 = '${wasmBase64}';
        const _wasmBytes = Uint8Array.from(atob(_wasmBase64), c => c.charCodeAt(0));

        // Inline the JS glue as a module blob so named exports work
        const _glueBlob = new Blob([${JSON.stringify(wasmJs)}], { type: 'text/javascript' });
        const _glueUrl = URL.createObjectURL(_glueBlob);
        const { default: init, TorClient, apply_fingerprint_defense } = await import(_glueUrl);
        URL.revokeObjectURL(_glueUrl);

        await init(_wasmBytes);
        // --- End inline WASM loader ---`;

html = html.replace(
  /import init,\s*\{[^}]*\}\s*from\s*['"][^'"]*tor_wasm\.js['"];/,
  wasmLoader
);

// ---- 4. Inject bridge configs (optional) ----

if (bridgesFile) {
  const bp = path.resolve(bridgesFile);
  if (!fs.existsSync(bp)) { console.error(`Bridge file not found: ${bp}`); process.exit(1); }
  const bridges = JSON.parse(fs.readFileSync(bp, 'utf-8'));
  console.log('  Injecting bridge configs...');

  if (bridges.ws) {
    html = html.replace(
      /const BRIDGES\s*=\s*\[[\s\S]*?\];/,
      `const BRIDGES = ${JSON.stringify(bridges.ws)};`
    );
  }
  if (bridges.webtunnel) {
    html = html.replace(
      /const WEBTUNNEL_BRIDGES\s*=\s*\[[\s\S]*?\];/,
      `const WEBTUNNEL_BRIDGES = ${JSON.stringify(bridges.webtunnel)};`
    );
  }
  if (bridges.meek) {
    html = html.replace(
      /const MEEK_BRIDGES\s*=\s*\[[\s\S]*?\];/,
      `const MEEK_BRIDGES = ${JSON.stringify(bridges.meek)};`
    );
  }
}

// ---- 5. Patch service worker for file:// protocol ----
// Service workers cannot register under file://, so wrap the registration.

html = html.replace(
  /if \('serviceWorker' in navigator\) \{/,
  `if ('serviceWorker' in navigator && location.protocol !== 'file:') {`
);

// Also embed the SW source as a comment for reference (useful if served over HTTP later)
html = html.replace(
  '</body>',
  `<!-- Embedded service worker source (inactive in file:// mode) -->\n` +
  `<script id="embedded-sw" type="text/plain">\n${swJs}\n</script>\n</body>`
);

// ---- 6. Write output ----

const outputPath = path.resolve(outputFile);
fs.writeFileSync(outputPath, html, 'utf-8');

// ---- 7. Print stats ----

const htmlOrigSize = fs.statSync(path.join(APP, 'index.html')).size;
const totalSize = Buffer.byteLength(html, 'utf-8');

console.log('\n--- Bundle Stats ---');
console.log(`  Original HTML:  ${(htmlOrigSize / 1024).toFixed(1)} KB`);
console.log(`  WASM binary:    ${(wasmBytes.length / 1024).toFixed(1)} KB`);
console.log(`  WASM JS glue:   ${(wasmJs.length / 1024).toFixed(1)} KB`);
console.log(`  Service worker: ${(swJs.length / 1024).toFixed(1)} KB`);
console.log(`  i18n langs:     ${Object.keys(i18n).join(', ') || 'none'}`);
console.log(`  Total bundle:   ${(totalSize / 1024 / 1024).toFixed(2)} MB`);
console.log(`  Output:         ${outputPath}`);
console.log('\nShare this file via USB, Bluetooth, AirDrop, or any file transfer.');
console.log('Open in any modern browser — no server or internet required.');
