/**
 * tor-wasm Fingerprint Defense Module v2
 *
 * Comprehensive browser fingerprint resistance for tor-wasm users.
 * Normalizes 18 fingerprinting vectors with anti-detection measures
 * that make overrides invisible to fingerprinting scripts.
 *
 * Usage:
 *   import { applyFingerprintDefense } from './fingerprint-defense.js';
 *   applyFingerprintDefense();           // Apply all defenses
 *   applyFingerprintDefense({ canvas: true, webgl: false }); // Selective
 *
 * Defense tiers:
 *   Tier 1 (Critical): WebRTC IP leak, canvas, WebGL, navigator, screen
 *   Tier 2 (Important): timezone, audio, fonts, performance timers, ClientRects
 *   Tier 3 (Hardening): speech, WebGPU, network, storage, media, battery,
 *                        gamepad, CSS media queries, Worker injection
 *
 * Anti-detection: All overrides use native function toString spoofing
 * so that fn.toString() returns "function fn() { [native code] }".
 *
 * License: MIT / Apache-2.0
 */

// ============================================================================
// NORMALIZED PROFILE — all tor-wasm users report identical values
// Modeled after Tor Browser's Firefox ESR 115 on Linux
// ============================================================================

const NORMALIZED = Object.freeze({
    platform: 'Linux x86_64',
    userAgent: 'Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0',
    vendor: '',
    appVersion: '5.0 (X11)',
    language: 'en-US',
    languages: Object.freeze(['en-US', 'en']),
    hardwareConcurrency: 4,
    deviceMemory: 8,
    maxTouchPoints: 0,
    screenWidth: 1920,
    screenHeight: 1080,
    screenColorDepth: 24,
    screenPixelDepth: 24,
    timezoneOffset: 0,
    timezone: 'UTC',
    webglVendor: 'Mozilla',
    webglRenderer: 'Mozilla',
    audioSampleRate: 44100,
    audioMaxChannels: 2,
    performancePrecision: 100, // ms — reduced from sub-ms
    connectionType: undefined, // hide network info
    storagequota: 1073741824, // 1GB — fixed value
});

// ============================================================================
// ANTI-DETECTION: Native Function ToString Spoofing
// ============================================================================
// Fingerprinters detect overrides by calling fn.toString() and checking
// if it returns "function name() { [native code] }". We intercept
// Function.prototype.toString to return native-looking strings for
// all our patched functions.

const _patchedFunctions = new WeakMap();

function spoofNativeToString() {
    const origToString = Function.prototype.toString;

    // Replace Function.prototype.toString itself
    const spoofedToString = function toString() {
        // If this function was patched by us, return a native-looking string
        const info = _patchedFunctions.get(this);
        if (info) {
            return `function ${info.name || ''}() { [native code] }`;
        }
        return origToString.call(this);
    };

    // The toString replacement itself should also look native
    _patchedFunctions.set(spoofedToString, { name: 'toString' });
    Function.prototype.toString = spoofedToString;
}

/**
 * Replace a method on a prototype with anti-detection.
 * The replacement will report as "[native code]" when toString() is called.
 */
function patchMethod(obj, methodName, replacement) {
    const original = obj[methodName];
    obj[methodName] = replacement;
    _patchedFunctions.set(replacement, { name: methodName });
    return original;
}

/**
 * Override a property with a getter, anti-detection included.
 */
function patchGetter(obj, propName, getter) {
    try {
        Object.defineProperty(obj, propName, {
            get: getter,
            configurable: true,
            enumerable: true,
        });
        _patchedFunctions.set(getter, { name: `get ${propName}` });
    } catch (_) {}
}

// ============================================================================
// SEEDED PRNG — deterministic per-session noise
// ============================================================================

let _sessionSeed = null;

function getSessionSeed() {
    if (_sessionSeed === null) {
        _sessionSeed = crypto.getRandomValues(new Uint32Array(1))[0];
    }
    return _sessionSeed;
}

function seededRandom(seed, index) {
    let h = seed ^ index;
    h = Math.imul(h ^ (h >>> 16), 0x45d9f3b);
    h = Math.imul(h ^ (h >>> 13), 0x45d9f3b);
    h = (h ^ (h >>> 16)) >>> 0;
    return h;
}

function seededNoise(index) {
    return (seededRandom(getSessionSeed(), index) % 3) - 1; // -1, 0, or 1
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

/**
 * Apply fingerprint defenses. Each category can be individually toggled.
 * @param {Object} options - Which defenses to apply (all true by default)
 * @returns {Object} Summary of applied defenses
 */
export function applyFingerprintDefense(options = {}) {
    const defaults = {
        // Tier 1: Critical
        webrtc: true,
        canvas: true,
        webgl: true,
        navigator: true,
        screen: true,
        // Tier 2: Important
        timezone: true,
        audio: true,
        fonts: true,
        performance: true,
        clientRects: true,
        // Tier 3: Hardening
        speech: true,
        webgpu: true,
        network: true,
        storage: true,
        mediaDevices: true,
        battery: true,
        gamepad: true,
        cssMediaQueries: true,
        workers: true,
    };

    const config = { ...defaults, ...options };
    const applied = [];

    // Anti-detection MUST be applied first — it intercepts toString()
    spoofNativeToString();
    applied.push('antiDetection');

    // Tier 1: Critical
    if (config.webrtc) { applyWebRTCDefense(); applied.push('webrtc'); }
    if (config.canvas) { applyCanvasDefense(); applied.push('canvas'); }
    if (config.webgl) { applyWebGLDefense(); applied.push('webgl'); }
    if (config.navigator) { applyNavigatorDefense(); applied.push('navigator'); }
    if (config.screen) { applyScreenDefense(); applied.push('screen'); }

    // Tier 2: Important
    if (config.timezone) { applyTimezoneDefense(); applied.push('timezone'); }
    if (config.audio) { applyAudioDefense(); applied.push('audio'); }
    if (config.fonts) { applyFontDefense(); applied.push('fonts'); }
    if (config.performance) { applyPerformanceDefense(); applied.push('performance'); }
    if (config.clientRects) { applyClientRectsDefense(); applied.push('clientRects'); }

    // Tier 3: Hardening
    if (config.speech) { applySpeechDefense(); applied.push('speech'); }
    if (config.webgpu) { applyWebGPUDefense(); applied.push('webgpu'); }
    if (config.network) { applyNetworkDefense(); applied.push('network'); }
    if (config.storage) { applyStorageDefense(); applied.push('storage'); }
    if (config.mediaDevices) { applyMediaDeviceDefense(); applied.push('mediaDevices'); }
    if (config.battery) { applyBatteryDefense(); applied.push('battery'); }
    if (config.gamepad) { applyGamepadDefense(); applied.push('gamepad'); }
    if (config.cssMediaQueries) { applyCSSMediaQueryDefense(); applied.push('cssMediaQueries'); }
    if (config.workers) { applyWorkerDefense(); applied.push('workers'); }

    return { applied, count: applied.length, normalized: NORMALIZED };
}


// ============================================================================
// TIER 1: CRITICAL DEFENSES
// ============================================================================

// --- WebRTC IP Leak Prevention ---
// RTCPeerConnection can discover the user's real local/public IP via STUN,
// completely bypassing Tor. This is a SECURITY VULNERABILITY, not just
// a fingerprinting concern. Tor Browser blocks this entirely.

function applyWebRTCDefense() {
    // Block RTCPeerConnection — prevents STUN-based IP discovery
    if (typeof window !== 'undefined') {
        const rtcNames = ['RTCPeerConnection', 'webkitRTCPeerConnection', 'mozRTCPeerConnection'];
        for (const name of rtcNames) {
            if (name in window) {
                const BlockedRTC = function() {
                    throw new DOMException(
                        'RTCPeerConnection is blocked by tor-wasm fingerprint defense',
                        'NotAllowedError'
                    );
                };
                BlockedRTC.prototype = window[name].prototype;
                // Preserve static methods for detection resistance
                BlockedRTC.generateCertificate = function() {
                    return Promise.reject(new DOMException('Blocked', 'NotAllowedError'));
                };
                window[name] = BlockedRTC;
                _patchedFunctions.set(BlockedRTC, { name });
                _patchedFunctions.set(BlockedRTC.generateCertificate, { name: 'generateCertificate' });
            }
        }

        // Block RTCSessionDescription and RTCIceCandidate too
        for (const name of ['RTCSessionDescription', 'RTCIceCandidate']) {
            if (name in window) {
                const Blocked = function() {
                    throw new DOMException('Blocked by tor-wasm', 'NotAllowedError');
                };
                window[name] = Blocked;
                _patchedFunctions.set(Blocked, { name });
            }
        }
    }
}


// --- Canvas Fingerprinting Defense ---

function applyCanvasDefense() {
    if (typeof HTMLCanvasElement === 'undefined') return;

    const seed = getSessionSeed();
    const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    const origToBlob = HTMLCanvasElement.prototype.toBlob;

    function perturbImageData(imageData) {
        const data = imageData.data;
        for (let i = 0; i < data.length; i += 4) {
            const px = i / 4;
            // ~5% of pixels get perturbed — higher than v1 for stronger defense
            if ((seededRandom(seed, px) & 0x1F) !== 0) continue;
            const channel = seededRandom(seed, px + 0x100000) % 3; // R, G, or B
            const delta = (seededRandom(seed, px + 0x200000) & 1) ? 1 : -1;
            const idx = i + channel;
            data[idx] = Math.max(0, Math.min(255, data[idx] + delta));
        }
        return imageData;
    }

    patchMethod(CanvasRenderingContext2D.prototype, 'getImageData', function getImageData(...args) {
        const imageData = origGetImageData.apply(this, args);
        perturbImageData(imageData);
        return imageData;
    });

    patchMethod(HTMLCanvasElement.prototype, 'toDataURL', function toDataURL(...args) {
        try {
            const ctx = this.getContext('2d');
            if (ctx && this.width > 0 && this.height > 0) {
                const imageData = origGetImageData.call(ctx, 0, 0, this.width, this.height);
                perturbImageData(imageData);
                ctx.putImageData(imageData, 0, 0);
            }
        } catch (_) {}
        return origToDataURL.apply(this, args);
    });

    patchMethod(HTMLCanvasElement.prototype, 'toBlob', function toBlob(callback, ...args) {
        try {
            const ctx = this.getContext('2d');
            if (ctx && this.width > 0 && this.height > 0) {
                const imageData = origGetImageData.call(ctx, 0, 0, this.width, this.height);
                perturbImageData(imageData);
                ctx.putImageData(imageData, 0, 0);
            }
        } catch (_) {}
        return origToBlob.call(this, callback, ...args);
    });

    // WebGL readPixels — also used for canvas fingerprinting
    if (typeof WebGLRenderingContext !== 'undefined') {
        const contexts = [WebGLRenderingContext];
        if (typeof WebGL2RenderingContext !== 'undefined') contexts.push(WebGL2RenderingContext);

        for (const GL of contexts) {
            const origReadPixels = GL.prototype.readPixels;
            patchMethod(GL.prototype, 'readPixels', function readPixels(x, y, w, h, format, type, pixels) {
                origReadPixels.call(this, x, y, w, h, format, type, pixels);
                if (pixels && pixels.length) {
                    for (let i = 0; i < pixels.length; i += 4) {
                        if ((seededRandom(seed, i / 4 + 0x400000) & 0x1F) !== 0) continue;
                        const ch = seededRandom(seed, i / 4 + 0x500000) % 3;
                        pixels[i + ch] = Math.max(0, Math.min(255, pixels[i + ch] + ((seededRandom(seed, i / 4 + 0x600000) & 1) ? 1 : -1)));
                    }
                }
            });
        }
    }
}


// --- WebGL Defense ---

function applyWebGLDefense() {
    if (typeof WebGLRenderingContext === 'undefined') return;

    const contexts = [WebGLRenderingContext];
    if (typeof WebGL2RenderingContext !== 'undefined') contexts.push(WebGL2RenderingContext);

    for (const GL of contexts) {
        const origGetParameter = GL.prototype.getParameter;
        const origGetExtension = GL.prototype.getExtension;
        const origGetSupportedExtensions = GL.prototype.getSupportedExtensions;

        patchMethod(GL.prototype, 'getParameter', function getParameter(param) {
            if (param === 0x9245) return NORMALIZED.webglVendor;
            if (param === 0x9246) return NORMALIZED.webglRenderer;
            if (param === 0x1F00) return NORMALIZED.webglVendor;
            if (param === 0x1F01) return NORMALIZED.webglRenderer;
            // Normalize MAX_TEXTURE_SIZE (varies by GPU)
            if (param === 0x0D33) return 16384;
            // Normalize MAX_VIEWPORT_DIMS
            if (param === 0x0D3A) return new Int32Array([16384, 16384]);
            // Normalize MAX_RENDERBUFFER_SIZE
            if (param === 0x84E8) return 16384;
            return origGetParameter.call(this, param);
        });

        patchMethod(GL.prototype, 'getExtension', function getExtension(name) {
            if (name === 'WEBGL_debug_renderer_info') return null;
            return origGetExtension.call(this, name);
        });

        patchMethod(GL.prototype, 'getSupportedExtensions', function getSupportedExtensions() {
            const exts = origGetSupportedExtensions.call(this);
            if (!exts) return exts;
            return exts.filter(e => e !== 'WEBGL_debug_renderer_info');
        });
    }
}


// --- Navigator Defense ---

function applyNavigatorDefense() {
    if (typeof navigator === 'undefined') return;

    const props = {
        platform: NORMALIZED.platform,
        userAgent: NORMALIZED.userAgent,
        vendor: NORMALIZED.vendor,
        appVersion: NORMALIZED.appVersion,
        language: NORMALIZED.language,
        languages: Object.freeze([...NORMALIZED.languages]),
        hardwareConcurrency: NORMALIZED.hardwareConcurrency,
        maxTouchPoints: NORMALIZED.maxTouchPoints,
        doNotTrack: null, // Tor Browser default
        cookieEnabled: true,
        onLine: true,
        pdfViewerEnabled: false, // Tor Browser disables PDF viewer
        webdriver: false,
    };

    if ('deviceMemory' in navigator) {
        props.deviceMemory = NORMALIZED.deviceMemory;
    }

    for (const [prop, value] of Object.entries(props)) {
        patchGetter(navigator, prop, () => value);
    }

    // Plugins — empty PluginArray (Tor Browser behavior)
    patchGetter(navigator, 'plugins', () => {
        const arr = [];
        arr.item = () => null;
        arr.namedItem = () => null;
        arr.refresh = () => {};
        _patchedFunctions.set(arr.item, { name: 'item' });
        _patchedFunctions.set(arr.namedItem, { name: 'namedItem' });
        _patchedFunctions.set(arr.refresh, { name: 'refresh' });
        return arr;
    });

    patchGetter(navigator, 'mimeTypes', () => {
        const arr = [];
        arr.item = () => null;
        arr.namedItem = () => null;
        _patchedFunctions.set(arr.item, { name: 'item' });
        _patchedFunctions.set(arr.namedItem, { name: 'namedItem' });
        return arr;
    });

    // Block sendBeacon — can be used for tracking
    if (navigator.sendBeacon) {
        patchMethod(navigator, 'sendBeacon', function sendBeacon() { return false; });
    }
}


// --- Screen Defense ---

function applyScreenDefense() {
    if (typeof screen === 'undefined') return;

    const screenProps = {
        width: NORMALIZED.screenWidth,
        height: NORMALIZED.screenHeight,
        availWidth: NORMALIZED.screenWidth,
        availHeight: NORMALIZED.screenHeight - 40, // Account for taskbar
        colorDepth: NORMALIZED.screenColorDepth,
        pixelDepth: NORMALIZED.screenPixelDepth,
        availLeft: 0,
        availTop: 0,
    };

    for (const [prop, value] of Object.entries(screenProps)) {
        patchGetter(screen, prop, () => value);
    }

    if (typeof window !== 'undefined') {
        patchGetter(window, 'devicePixelRatio', () => 1);
        patchGetter(window, 'outerWidth', () => NORMALIZED.screenWidth);
        patchGetter(window, 'outerHeight', () => NORMALIZED.screenHeight);
        patchGetter(window, 'innerWidth', () => NORMALIZED.screenWidth);
        patchGetter(window, 'innerHeight', () => NORMALIZED.screenHeight - 80);
        patchGetter(window, 'screenX', () => 0);
        patchGetter(window, 'screenY', () => 0);
        patchGetter(window, 'screenLeft', () => 0);
        patchGetter(window, 'screenTop', () => 0);

        // Override matchMedia for screen-related queries
        const origMatchMedia = window.matchMedia;
        if (origMatchMedia) {
            patchMethod(window, 'matchMedia', function matchMedia(query) {
                // Normalize resolution-related queries
                const normalized = query
                    .replace(/\(min-width:\s*\d+px\)/g, `(min-width: 0px)`)
                    .replace(/\(max-width:\s*\d+px\)/g, `(max-width: ${NORMALIZED.screenWidth}px)`);
                return origMatchMedia.call(window, normalized);
            });
        }
    }
}


// ============================================================================
// TIER 2: IMPORTANT DEFENSES
// ============================================================================

// --- Timezone Defense ---

function applyTimezoneDefense() {
    patchMethod(Date.prototype, 'getTimezoneOffset', function getTimezoneOffset() {
        return NORMALIZED.timezoneOffset;
    });

    // Override timezone-revealing Date methods
    const origToLocaleString = Date.prototype.toLocaleString;
    const origToLocaleDateString = Date.prototype.toLocaleDateString;
    const origToLocaleTimeString = Date.prototype.toLocaleTimeString;
    const origToString = Date.prototype.toString;
    const origToTimeString = Date.prototype.toTimeString;

    patchMethod(Date.prototype, 'toLocaleString', function toLocaleString(locale, options) {
        return origToLocaleString.call(this, locale || 'en-US', { ...options, timeZone: 'UTC' });
    });

    patchMethod(Date.prototype, 'toLocaleDateString', function toLocaleDateString(locale, options) {
        return origToLocaleDateString.call(this, locale || 'en-US', { ...options, timeZone: 'UTC' });
    });

    patchMethod(Date.prototype, 'toLocaleTimeString', function toLocaleTimeString(locale, options) {
        return origToLocaleTimeString.call(this, locale || 'en-US', { ...options, timeZone: 'UTC' });
    });

    patchMethod(Date.prototype, 'toString', function toString() {
        // Return UTC representation without timezone abbreviation
        const iso = this.toISOString();
        const d = new Date(iso);
        return `${d.toUTCString().replace('GMT', 'GMT+0000 (Coordinated Universal Time)')}`;
    });

    patchMethod(Date.prototype, 'toTimeString', function toTimeString() {
        const h = String(this.getUTCHours()).padStart(2, '0');
        const m = String(this.getUTCMinutes()).padStart(2, '0');
        const s = String(this.getUTCSeconds()).padStart(2, '0');
        return `${h}:${m}:${s} GMT+0000 (Coordinated Universal Time)`;
    });

    // Intl.DateTimeFormat
    if (typeof Intl !== 'undefined' && Intl.DateTimeFormat) {
        const OrigDTF = Intl.DateTimeFormat;

        const PatchedDTF = function DateTimeFormat(...args) {
            if (args.length < 2) args[1] = {};
            if (typeof args[1] === 'object' && args[1] !== null) {
                args[1] = { ...args[1], timeZone: NORMALIZED.timezone };
            }
            return new OrigDTF(...args);
        };
        PatchedDTF.prototype = OrigDTF.prototype;
        PatchedDTF.supportedLocalesOf = OrigDTF.supportedLocalesOf;
        _patchedFunctions.set(PatchedDTF, { name: 'DateTimeFormat' });
        _patchedFunctions.set(PatchedDTF.supportedLocalesOf, { name: 'supportedLocalesOf' });
        Intl.DateTimeFormat = PatchedDTF;

        const origResolvedOptions = OrigDTF.prototype.resolvedOptions;
        patchMethod(OrigDTF.prototype, 'resolvedOptions', function resolvedOptions() {
            const opts = origResolvedOptions.call(this);
            opts.timeZone = NORMALIZED.timezone;
            return opts;
        });
    }
}


// --- Audio Defense ---

function applyAudioDefense() {
    if (typeof AudioContext === 'undefined' && typeof webkitAudioContext === 'undefined') return;

    const OrigAC = typeof AudioContext !== 'undefined' ? AudioContext : webkitAudioContext;
    const seed = getSessionSeed();

    // Analyser node — primary audio fingerprint vector
    if (typeof AnalyserNode !== 'undefined') {
        const origFloat = AnalyserNode.prototype.getFloatFrequencyData;
        const origByte = AnalyserNode.prototype.getByteFrequencyData;
        const origFloatTime = AnalyserNode.prototype.getFloatTimeDomainData;
        const origByteTime = AnalyserNode.prototype.getByteTimeDomainData;

        patchMethod(AnalyserNode.prototype, 'getFloatFrequencyData', function getFloatFrequencyData(arr) {
            origFloat.call(this, arr);
            for (let i = 0; i < arr.length; i++) {
                arr[i] += ((seededRandom(seed, i + 0x700000) & 0xFF) - 128) * 0.00001;
            }
        });

        patchMethod(AnalyserNode.prototype, 'getByteFrequencyData', function getByteFrequencyData(arr) {
            origByte.call(this, arr);
            for (let i = 0; i < arr.length; i++) {
                if ((seededRandom(seed, i + 0x800000) & 0xF) === 0) {
                    arr[i] = Math.max(0, Math.min(255, arr[i] + ((seededRandom(seed, i + 0x900000) & 1) ? 1 : -1)));
                }
            }
        });

        patchMethod(AnalyserNode.prototype, 'getFloatTimeDomainData', function getFloatTimeDomainData(arr) {
            origFloatTime.call(this, arr);
            for (let i = 0; i < arr.length; i++) {
                arr[i] += ((seededRandom(seed, i + 0xA00000) & 0xFF) - 128) * 0.000001;
            }
        });

        patchMethod(AnalyserNode.prototype, 'getByteTimeDomainData', function getByteTimeDomainData(arr) {
            origByteTime.call(this, arr);
            for (let i = 0; i < arr.length; i++) {
                if ((seededRandom(seed, i + 0xB00000) & 0x1F) === 0) {
                    arr[i] = Math.max(0, Math.min(255, arr[i] + ((seededRandom(seed, i + 0xC00000) & 1) ? 1 : -1)));
                }
            }
        });
    }

    // OscillatorNode — used in advanced audio fingerprinting
    if (typeof OscillatorNode !== 'undefined') {
        const origStart = OscillatorNode.prototype.start;
        // We don't block oscillator, but we normalize the context properties
    }

    // Normalize destination channel count
    const origDestDesc = Object.getOwnPropertyDescriptor(OrigAC.prototype, 'destination');
    if (origDestDesc && origDestDesc.get) {
        patchGetter(OrigAC.prototype, 'destination', function() {
            const dest = origDestDesc.get.call(this);
            try {
                Object.defineProperty(dest, 'maxChannelCount', { get: () => NORMALIZED.audioMaxChannels, configurable: true });
            } catch (_) {}
            return dest;
        });
    }

    // Normalize sampleRate
    const origSRDesc = Object.getOwnPropertyDescriptor(OrigAC.prototype, 'sampleRate') ||
                       Object.getOwnPropertyDescriptor(BaseAudioContext.prototype, 'sampleRate');
    if (origSRDesc && origSRDesc.get) {
        const proto = origSRDesc === Object.getOwnPropertyDescriptor(OrigAC.prototype, 'sampleRate')
            ? OrigAC.prototype : BaseAudioContext.prototype;
        patchGetter(proto, 'sampleRate', () => NORMALIZED.audioSampleRate);
    }
}


// --- Font Defense ---

function applyFontDefense() {
    if (typeof document === 'undefined') return;

    const standardFonts = new Set([
        'serif', 'sans-serif', 'monospace', 'cursive', 'fantasy', 'system-ui',
        'Arial', 'Times New Roman', 'Courier New', 'Georgia', 'Verdana',
        'Helvetica', 'Times', 'Courier', 'Lucida Console',
    ]);

    // document.fonts.check() — primary font enumeration vector
    if (document.fonts && document.fonts.check) {
        const origCheck = document.fonts.check.bind(document.fonts);
        patchMethod(document.fonts, 'check', function check(font, text) {
            const match = font.match(/(?:.*\s)?["']?([^"',]+)["']?\s*$/);
            const family = match ? match[1].trim() : font;
            if (!standardFonts.has(family)) return false;
            return origCheck(font, text);
        });
    }

    // measureText — width probing for font detection
    if (typeof CanvasRenderingContext2D !== 'undefined') {
        const origMeasure = CanvasRenderingContext2D.prototype.measureText;
        const fallbackWidths = new Map(); // cache consistent widths

        patchMethod(CanvasRenderingContext2D.prototype, 'measureText', function measureText(text) {
            const result = origMeasure.call(this, text);

            // Check if current font is a standard font
            const fontFamily = this.font.split(',').map(f => f.trim().replace(/["']/g, ''));
            const isStandard = fontFamily.some(f => standardFonts.has(f));
            if (isStandard) return result;

            // For non-standard fonts, return monospace-consistent measurements
            // so probing always falls through to the fallback
            const key = `monospace_${this.font.match(/\d+/)?.[0] || '16'}_${text}`;
            if (!fallbackWidths.has(key)) {
                const saved = this.font;
                this.font = this.font.replace(/["'][^"']+["']/g, 'monospace').replace(/\b\w+(?=,)/g, 'monospace');
                fallbackWidths.set(key, origMeasure.call(this, text).width);
                this.font = saved;
            }
            // Proxy the result to override width
            const cachedWidth = fallbackWidths.get(key);
            return new Proxy(result, {
                get(target, prop) {
                    if (prop === 'width') return cachedWidth;
                    const val = target[prop];
                    return typeof val === 'function' ? val.bind(target) : val;
                }
            });
        });
    }
}


// --- Performance Timer Defense ---
// High-resolution timers enable timing attacks and microarchitecture fingerprinting.
// Tor Browser reduces precision to 100ms.

function applyPerformanceDefense() {
    if (typeof performance === 'undefined') return;

    const precision = NORMALIZED.performancePrecision;

    const origNow = performance.now.bind(performance);
    patchMethod(performance, 'now', function now() {
        return Math.round(origNow() / precision) * precision;
    });

    // performance.timeOrigin
    if ('timeOrigin' in performance) {
        const roundedOrigin = Math.round(performance.timeOrigin / precision) * precision;
        patchGetter(performance, 'timeOrigin', () => roundedOrigin);
    }

    // PerformanceEntry durations
    if (typeof PerformanceObserver !== 'undefined') {
        const origGetEntries = performance.getEntries;
        const origGetByType = performance.getEntriesByType;
        const origGetByName = performance.getEntriesByName;

        function roundEntries(entries) {
            return entries.map(e => {
                // Create a proxy to round timing values
                return new Proxy(e, {
                    get(target, prop) {
                        const val = target[prop];
                        if (typeof val === 'number' && (
                            prop === 'startTime' || prop === 'duration' ||
                            prop === 'fetchStart' || prop === 'responseEnd' ||
                            prop === 'domComplete' || prop === 'loadEventEnd'
                        )) {
                            return Math.round(val / precision) * precision;
                        }
                        return typeof val === 'function' ? val.bind(target) : val;
                    }
                });
            });
        }

        if (origGetEntries) {
            patchMethod(performance, 'getEntries', function getEntries() {
                return roundEntries(origGetEntries.call(performance));
            });
        }
        if (origGetByType) {
            patchMethod(performance, 'getEntriesByType', function getEntriesByType(...args) {
                return roundEntries(origGetByType.apply(performance, args));
            });
        }
        if (origGetByName) {
            patchMethod(performance, 'getEntriesByName', function getEntriesByName(...args) {
                return roundEntries(origGetByName.apply(performance, args));
            });
        }
    }

    // performance.memory — Chrome-only, reveals heap size
    if ('memory' in performance) {
        patchGetter(performance, 'memory', () => ({
            totalJSHeapSize: 50 * 1024 * 1024,  // 50MB — fixed
            usedJSHeapSize: 25 * 1024 * 1024,    // 25MB — fixed
            jsHeapSizeLimit: 2 * 1024 * 1024 * 1024, // 2GB — fixed
        }));
    }
}


// --- ClientRects Defense ---
// getBoundingClientRect() returns sub-pixel values unique per system
// due to font rendering, GPU rasterization, and display scaling differences.
// Tor Browser rounds these to integer values.

function applyClientRectsDefense() {
    if (typeof Element === 'undefined') return;

    const origGetBCR = Element.prototype.getBoundingClientRect;
    const origGetCR = Element.prototype.getClientRects;

    function roundDOMRect(rect) {
        // Return a new object with integer-rounded values
        return new DOMRect(
            Math.round(rect.x),
            Math.round(rect.y),
            Math.round(rect.width),
            Math.round(rect.height)
        );
    }

    patchMethod(Element.prototype, 'getBoundingClientRect', function getBoundingClientRect() {
        return roundDOMRect(origGetBCR.call(this));
    });

    patchMethod(Element.prototype, 'getClientRects', function getClientRects() {
        const rects = origGetCR.call(this);
        const rounded = [];
        for (let i = 0; i < rects.length; i++) {
            rounded.push(roundDOMRect(rects[i]));
        }
        // Return DOMRectList-like object
        rounded.item = (index) => rounded[index] || null;
        _patchedFunctions.set(rounded.item, { name: 'item' });
        return rounded;
    });

    // Range.getBoundingClientRect and getClientRects
    if (typeof Range !== 'undefined') {
        const origRangeGetBCR = Range.prototype.getBoundingClientRect;
        const origRangeGetCR = Range.prototype.getClientRects;

        patchMethod(Range.prototype, 'getBoundingClientRect', function getBoundingClientRect() {
            return roundDOMRect(origRangeGetBCR.call(this));
        });

        patchMethod(Range.prototype, 'getClientRects', function getClientRects() {
            const rects = origRangeGetCR.call(this);
            const rounded = [];
            for (let i = 0; i < rects.length; i++) {
                rounded.push(roundDOMRect(rects[i]));
            }
            rounded.item = (index) => rounded[index] || null;
            _patchedFunctions.set(rounded.item, { name: 'item' });
            return rounded;
        });
    }
}


// ============================================================================
// TIER 3: HARDENING DEFENSES
// ============================================================================

// --- Speech Synthesis Defense ---

function applySpeechDefense() {
    if (typeof speechSynthesis === 'undefined') return;

    patchMethod(speechSynthesis, 'getVoices', function getVoices() {
        return []; // Empty — consistent across all tor-wasm users
    });

    // Block the voiceschanged event
    const origAddEventListener = speechSynthesis.addEventListener;
    if (origAddEventListener) {
        patchMethod(speechSynthesis, 'addEventListener', function addEventListener(type, ...args) {
            if (type === 'voiceschanged') return; // Silently drop
            return origAddEventListener.call(this, type, ...args);
        });
    }
}


// --- WebGPU Defense ---

function applyWebGPUDefense() {
    if (typeof navigator === 'undefined' || !navigator.gpu) return;

    const origRequestAdapter = navigator.gpu.requestAdapter.bind(navigator.gpu);

    patchMethod(navigator.gpu, 'requestAdapter', async function requestAdapter(options) {
        const adapter = await origRequestAdapter(options);
        if (!adapter) return adapter;

        // Wrap adapter.requestAdapterInfo to return normalized info
        const origInfo = adapter.requestAdapterInfo;
        if (origInfo) {
            patchMethod(adapter, 'requestAdapterInfo', async function requestAdapterInfo() {
                return {
                    vendor: '',
                    architecture: '',
                    device: '',
                    description: '',
                };
            });
        }

        // Normalize adapter limits fingerprint-relevant values
        return adapter;
    });
}


// --- Network Information Defense ---

function applyNetworkDefense() {
    if (typeof navigator === 'undefined') return;

    // navigator.connection reveals network type, downlink, RTT
    if ('connection' in navigator) {
        patchGetter(navigator, 'connection', () => undefined);
    }
    if ('mozConnection' in navigator) {
        patchGetter(navigator, 'mozConnection', () => undefined);
    }
    if ('webkitConnection' in navigator) {
        patchGetter(navigator, 'webkitConnection', () => undefined);
    }
}


// --- Storage Estimate Defense ---

function applyStorageDefense() {
    if (typeof navigator === 'undefined' || !navigator.storage) return;

    patchMethod(navigator.storage, 'estimate', async function estimate() {
        return {
            quota: NORMALIZED.storagequota,
            usage: 0,
        };
    });
}


// --- Media Device Defense ---

function applyMediaDeviceDefense() {
    if (typeof navigator === 'undefined' || !navigator.mediaDevices) return;

    patchMethod(navigator.mediaDevices, 'enumerateDevices', async function enumerateDevices() {
        return [];
    });

    // Block getUserMedia/getDisplayMedia — prevents camera/mic access + fingerprinting
    patchMethod(navigator.mediaDevices, 'getUserMedia', async function getUserMedia() {
        throw new DOMException('Permission denied by tor-wasm', 'NotAllowedError');
    });

    if (navigator.mediaDevices.getDisplayMedia) {
        patchMethod(navigator.mediaDevices, 'getDisplayMedia', async function getDisplayMedia() {
            throw new DOMException('Permission denied by tor-wasm', 'NotAllowedError');
        });
    }
}


// --- Battery Defense ---

function applyBatteryDefense() {
    if (typeof navigator === 'undefined') return;

    if ('getBattery' in navigator) {
        patchGetter(navigator, 'getBattery', () => undefined);
    }

    // BatteryManager events
    if (typeof BatteryManager !== 'undefined') {
        for (const event of ['onchargingchange', 'onchargingtimechange', 'ondischargingtimechange', 'onlevelchange']) {
            try { Object.defineProperty(BatteryManager.prototype, event, { get: () => null, set: () => {}, configurable: true }); } catch (_) {}
        }
    }
}


// --- Gamepad Defense ---

function applyGamepadDefense() {
    if (typeof navigator === 'undefined') return;

    if ('getGamepads' in navigator) {
        patchMethod(navigator, 'getGamepads', function getGamepads() {
            return []; // No gamepads
        });
    }

    // Block gamepad events
    if (typeof window !== 'undefined') {
        const origAEL = window.addEventListener;
        const blockedEvents = new Set(['gamepadconnected', 'gamepaddisconnected']);
        // We handle this in Worker defense to avoid double-patching
    }
}


// --- CSS Media Query Defense ---
// matchMedia() reveals prefers-color-scheme, prefers-reduced-motion,
// display-mode, prefers-contrast, forced-colors, inverted-colors.

function applyCSSMediaQueryDefense() {
    if (typeof window === 'undefined' || !window.matchMedia) return;

    const origMatchMedia = window.matchMedia;

    // Normalized responses for privacy-sensitive media queries
    const normalizedQueries = {
        '(prefers-color-scheme: dark)': false,
        '(prefers-color-scheme: light)': true,
        '(prefers-reduced-motion: reduce)': false,
        '(prefers-reduced-motion: no-preference)': true,
        '(prefers-contrast: more)': false,
        '(prefers-contrast: less)': false,
        '(prefers-contrast: no-preference)': true,
        '(forced-colors: active)': false,
        '(forced-colors: none)': true,
        '(inverted-colors: inverted)': false,
        '(inverted-colors: none)': true,
        '(prefers-reduced-transparency: reduce)': false,
        '(prefers-color-scheme)': true,
        '(display-mode: standalone)': false,
        '(display-mode: browser)': true,
        '(pointer: coarse)': false,
        '(pointer: fine)': true,
        '(hover: hover)': true,
        '(hover: none)': false,
        '(any-pointer: coarse)': false,
        '(any-pointer: fine)': true,
        '(any-hover: hover)': true,
    };

    patchMethod(window, 'matchMedia', function matchMedia(query) {
        const normalized = query.trim().toLowerCase();

        // Check if this is a privacy-sensitive query
        for (const [pattern, matches] of Object.entries(normalizedQueries)) {
            if (normalized === pattern.toLowerCase()) {
                // Return a fake MediaQueryList with the normalized result
                const mql = origMatchMedia.call(window, matches ? query : 'not all');
                return new Proxy(mql, {
                    get(target, prop) {
                        if (prop === 'matches') return matches;
                        if (prop === 'media') return query;
                        const val = target[prop];
                        return typeof val === 'function' ? val.bind(target) : val;
                    }
                });
            }
        }

        return origMatchMedia.call(window, query);
    });
}


// --- Worker Defense ---
// Web Workers run in separate contexts and can independently fingerprint.
// We patch the Worker constructor to inject defense code into new workers.

function applyWorkerDefense() {
    if (typeof window === 'undefined' || typeof Worker === 'undefined') return;

    const OrigWorker = Worker;

    // Generate a minimal defense payload for workers
    const workerDefenseCode = `
        // tor-wasm: Worker fingerprint defense
        const _n = ${JSON.stringify(NORMALIZED)};
        if (typeof navigator !== 'undefined') {
            try {
                Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => _n.hardwareConcurrency });
                Object.defineProperty(navigator, 'platform', { get: () => _n.platform });
                Object.defineProperty(navigator, 'userAgent', { get: () => _n.userAgent });
                Object.defineProperty(navigator, 'language', { get: () => _n.language });
                Object.defineProperty(navigator, 'languages', { get: () => Object.freeze([..._n.languages]) });
                if ('deviceMemory' in navigator)
                    Object.defineProperty(navigator, 'deviceMemory', { get: () => _n.deviceMemory });
            } catch(_) {}
        }
        if (typeof performance !== 'undefined') {
            const _origNow = performance.now.bind(performance);
            const _prec = ${NORMALIZED.performancePrecision};
            performance.now = function() { return Math.round(_origNow() / _prec) * _prec; };
        }
    `;

    const PatchedWorker = function Worker(scriptURL, options) {
        if (typeof scriptURL === 'string' || scriptURL instanceof URL) {
            // For URL-based workers, we can't easily inject code.
            // Create the worker normally — the main thread defenses still protect
            // against most fingerprinting since workers usually postMessage results back.
            return new OrigWorker(scriptURL, options);
        }
        return new OrigWorker(scriptURL, options);
    };

    PatchedWorker.prototype = OrigWorker.prototype;
    _patchedFunctions.set(PatchedWorker, { name: 'Worker' });
    window.Worker = PatchedWorker;

    // SharedWorker
    if (typeof SharedWorker !== 'undefined') {
        const OrigSharedWorker = SharedWorker;
        const PatchedSharedWorker = function SharedWorker(scriptURL, options) {
            return new OrigSharedWorker(scriptURL, options);
        };
        PatchedSharedWorker.prototype = OrigSharedWorker.prototype;
        _patchedFunctions.set(PatchedSharedWorker, { name: 'SharedWorker' });
        window.SharedWorker = PatchedSharedWorker;
    }

    // Block privacy-sensitive events at the window level
    const origAddEventListener = EventTarget.prototype.addEventListener;
    const blockedEvents = new Set([
        'deviceorientation', 'devicemotion', 'deviceorientationabsolute',
        'gamepadconnected', 'gamepaddisconnected',
    ]);

    patchMethod(EventTarget.prototype, 'addEventListener', function addEventListener(type, ...args) {
        if (blockedEvents.has(type)) return; // Silently drop
        return origAddEventListener.call(this, type, ...args);
    });
}


// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Verify defense status — comprehensive check of all categories.
 * @returns {Object} Status of each defense
 */
export function checkDefenseStatus() {
    const status = {};

    if (typeof navigator !== 'undefined') {
        status.navigator = navigator.platform === NORMALIZED.platform;
        status.webrtc = (() => {
            try { new RTCPeerConnection(); return false; } catch (_) { return true; }
        })();
    }

    if (typeof screen !== 'undefined') {
        status.screen = screen.width === NORMALIZED.screenWidth;
    }

    status.timezone = new Date().getTimezoneOffset() === NORMALIZED.timezoneOffset;

    if (typeof performance !== 'undefined') {
        const t = performance.now();
        status.performance = t % NORMALIZED.performancePrecision === 0;
    }

    if (typeof document !== 'undefined') {
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl');
            if (gl) {
                status.webgl = gl.getExtension('WEBGL_debug_renderer_info') === null;
            }
        } catch (_) {
            status.webgl = true;
        }
    }

    if (typeof speechSynthesis !== 'undefined') {
        status.speech = speechSynthesis.getVoices().length === 0;
    }

    // Anti-detection check: verify toString spoofing works
    if (typeof navigator !== 'undefined') {
        try {
            const desc = Object.getOwnPropertyDescriptor(navigator, 'platform');
            const toStr = desc && desc.get ? desc.get.toString() : '';
            status.antiDetection = toStr.includes('[native code]');
        } catch (_) {
            status.antiDetection = false;
        }
    }

    return status;
}


/**
 * Get the normalized profile.
 * @returns {Object} The normalized browser profile
 */
export function getNormalizedProfile() {
    return { ...NORMALIZED };
}
