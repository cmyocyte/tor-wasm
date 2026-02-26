/**
 * Quiet-Mode Logger
 *
 * When QUIET_MODE=1, strips all Tor-identifying terms from logs.
 * Useful for operators in hostile environments where log access
 * by a shared hosting provider or cloud platform could reveal
 * the server's purpose.
 *
 * Configuration:
 *   QUIET_MODE=1  — Enable quiet mode (generic terms, no banners, no emojis)
 */

const QUIET = process.env.QUIET_MODE === '1' || process.env.QUIET_MODE === 'true';

// Terms that identify the server as Tor-related
const REPLACEMENTS = [
  [/\bTor\b/gi, 'upstream'],
  [/\bconsensus\b/gi, 'config'],
  [/\brelay[s]?\b/gi, 'peer'],
  [/\bntor[\s-]?(?:onion[\s-]?)?key[s]?\b/gi, 'auth-key'],
  [/\bguard[s]?\b/gi, 'type-a'],
  [/\bexit[s]?\b/gi, 'type-b'],
  [/\bfingerprint[s]?\b/gi, 'id'],
  [/\bcircuit[s]?\b/gi, 'session'],
  [/\bonion\b/gi, 'layer'],
  [/\bbridge[\s-]?[ab]?\b/gi, 'node'],
  [/\bblind(?:ed|ing)?\b/gi, 'routed'],
  [/\bWebSocket\b/gi, 'connection'],
  // Strip emojis
  [/[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\u{FE00}-\u{FE0F}\u{1F900}-\u{1F9FF}]/gu, ''],
];

/**
 * Sanitize a log message by replacing Tor-specific terms.
 */
function sanitize(msg) {
  if (!QUIET) return msg;
  let result = String(msg);
  for (const [pattern, replacement] of REPLACEMENTS) {
    result = result.replace(pattern, replacement);
  }
  return result.trim();
}

/**
 * Log a message. In quiet mode, sanitizes the content.
 */
function log(...args) {
  if (QUIET) {
    const sanitized = args.map(a => typeof a === 'string' ? sanitize(a) : a);
    console.log(...sanitized);
  } else {
    console.log(...args);
  }
}

/**
 * Log an error. In quiet mode, sanitizes the content.
 */
function error(...args) {
  if (QUIET) {
    const sanitized = args.map(a => {
      if (typeof a === 'string') return sanitize(a);
      if (a instanceof Error) return sanitize(a.message);
      return a;
    });
    console.error(...sanitized);
  } else {
    console.error(...args);
  }
}

/**
 * Log a warning. In quiet mode, sanitizes the content.
 */
function warn(...args) {
  if (QUIET) {
    const sanitized = args.map(a => typeof a === 'string' ? sanitize(a) : a);
    console.warn(...sanitized);
  } else {
    console.warn(...args);
  }
}

/**
 * Print a startup banner. Suppressed entirely in quiet mode.
 */
function banner(lines) {
  if (QUIET) {
    log(`Service started on port ${process.env.PORT || 'default'}`);
    return;
  }
  for (const line of lines) {
    console.log(line);
  }
}

/**
 * Sanitize an IP address for logging.
 * In quiet mode, hashes IP to a short connection ID.
 */
function ip(addr) {
  if (!QUIET) return addr;
  if (!addr) return 'unknown';
  // Simple hash to 6-char hex ID
  let hash = 0;
  for (let i = 0; i < addr.length; i++) {
    hash = ((hash << 5) - hash) + addr.charCodeAt(i);
    hash |= 0;
  }
  return 'conn-' + Math.abs(hash).toString(16).slice(0, 6);
}

module.exports = { log, error, warn, banner, ip, sanitize, QUIET };
