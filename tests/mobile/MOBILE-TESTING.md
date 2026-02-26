# Mobile Browser Testing Matrix

## Target Browsers

### Priority 1 (Critical Markets)
| Browser | Platform | Market | WASM | WebSocket | Service Worker |
|---------|----------|--------|------|-----------|----------------|
| Mobile Safari | iOS 17+ | Iran, China | Yes | Yes | Yes |
| Chrome Mobile | Android 12+ | All | Yes | Yes | Yes |
| WeChat Browser | iOS/Android | China | Partial* | Yes | No |
| Yandex Browser | Android | Russia | Yes | Yes | Yes |

### Priority 2 (Coverage)
| Browser | Platform | Market | WASM | WebSocket | Service Worker |
|---------|----------|--------|------|-----------|----------------|
| Firefox Mobile | Android | All | Yes | Yes | Yes |
| Samsung Internet | Android | Global | Yes | Yes | Yes |
| Chrome iOS | iOS | All | Yes** | Yes | Limited |
| Atom Browser | Android | Russia | Yes | Yes | TBD |

\* WeChat's built-in browser has restricted WASM support and no Service Worker.
\** Chrome iOS uses WebKit (not Blink), so behavior matches Safari.

## Test Cases

### T1: WASM Load
- [ ] WASM binary loads within 10s on 3G (1.5Mbps)
- [ ] WASM binary loads within 3s on 4G (10Mbps)
- [ ] Memory usage stays under 100MB during initialization
- [ ] No crashes on low-memory devices (2GB RAM)

### T2: WebSocket Connection
- [ ] WebSocket connects to bridge on port 443 (standard HTTPS)
- [ ] WebSocket connects to bridge on port 8080 (non-standard)
- [ ] Connection survives network switch (Wi-Fi → cellular)
- [ ] Connection survives brief network interruption (< 5s)

### T3: Consensus Fetch
- [ ] Consensus fetches successfully through bridge
- [ ] Obfuscated consensus (base64+zlib) decodes correctly
- [ ] Fallback consensus works when bridge is unreachable

### T4: Circuit Building
- [ ] 3-hop circuit builds within 15s on 4G
- [ ] 3-hop circuit builds within 30s on 3G
- [ ] Circuit survives app backgrounding for 30s
- [ ] Circuit survives app backgrounding for 60s

### T5: Page Loading
- [ ] Simple HTML page loads through Tor circuit
- [ ] CSS/JS sub-resources load via Service Worker
- [ ] Images load correctly
- [ ] HTTPS sites work (TLS through exit relay)

### T6: Fingerprint Defense
- [ ] All 20 defense vectors apply on mobile
- [ ] Canvas perturbation works on mobile GPU
- [ ] WebRTC blocking works (no ICE leak)
- [ ] Timezone shows UTC

### T7: UI/UX
- [ ] Boot sequence displays correctly on small screens
- [ ] URL bar is usable with mobile keyboard
- [ ] Navigation buttons work (back, forward, reload)
- [ ] Status indicator is visible

## Mobile-Specific Concerns

### Memory
- WASM linear memory on mobile is typically limited to 256MB-1GB
- Our WASM binary uses ~20MB at peak during circuit building
- Multiple browser tabs may cause OOM on low-end devices

### Background Throttling
- iOS Safari suspends JavaScript after ~30s in background
- Android Chrome throttles timers to 1/minute after 5 minutes
- Circuit keepalive may fail if backgrounded too long
- Solution: Use `visibilitychange` event to reconnect on return

### Service Worker Limitations
- WeChat browser: No Service Worker support at all
- Safari: Service Workers cleared after 7 days without visit
- Samsung Internet: Service Worker may be cleared by "Smart Anti-Tracking"

### Network
- Cellular connections have higher latency (50-200ms vs 10-30ms Wi-Fi)
- Carrier-grade NAT may interfere with WebSocket connections
- Some carriers inject HTTP headers (X-WAP-Profile) that could fingerprint

## Automated Testing

### BrowserStack Configuration
```yaml
# .github/workflows/mobile-test.yml
name: Mobile Browser Tests
on:
  workflow_dispatch:
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday 6am UTC

jobs:
  mobile-test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        browser:
          - { os: ios, os_version: "17", browser: safari }
          - { os: android, os_version: "14.0", browser: chrome }
          - { os: android, os_version: "13.0", browser: samsung }
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - run: npm ci
      - run: npm run build:wasm
      - name: Run mobile tests on BrowserStack
        env:
          BROWSERSTACK_USERNAME: ${{ secrets.BROWSERSTACK_USERNAME }}
          BROWSERSTACK_ACCESS_KEY: ${{ secrets.BROWSERSTACK_ACCESS_KEY }}
        run: |
          npx wdio run tests/mobile/wdio.conf.js \
            --browser ${{ matrix.browser.browser }} \
            --os ${{ matrix.browser.os }} \
            --os-version "${{ matrix.browser.os_version }}"
```

## Automated Test Infrastructure

### Files
- `browserstack.config.js` — BrowserStack device matrix (5 real devices)
- `core-suite.js` — 7 automated tests (WASM load, WS connect, consensus, circuit, fetch, memory, backgrounding)
- `../../.github/workflows/mobile-test.yml` — Weekly CI (Monday 06:00 UTC)

### Running Tests
```bash
# BrowserStack (needs BROWSERSTACK_USERNAME + BROWSERSTACK_ACCESS_KEY)
npx browserstack-runner --config tests/mobile/browserstack.config.js

# Local (open app/index.html in mobile browser, then):
window.__runMobileTests()
```

### WeChat Browser Limitations
WeChat's built-in browser has restricted WASM support (no streaming compilation) and no Service Worker. Full tor-wasm functionality requires a WeChat mini-program wrapper, which is out of scope. Users should be directed to use the system browser via a "Open in Safari/Chrome" link.

## Results Log

| Date | Browser | Platform | T1 | T2 | T3 | T4 | T5 | T6 | T7 | Notes |
|------|---------|----------|----|----|----|----|----|----|----|----|
| (pending — run BrowserStack) | | | | | | | | | | |
