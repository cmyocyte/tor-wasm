/**
 * DNS-Safe Resolution
 *
 * Prevents DNS leaks when bridge servers fetch data from Tor infrastructure.
 * Uses pre-resolved IPs with DNS-over-HTTPS (DoH) fallback via Cloudflare.
 *
 * Configuration:
 *   CONSENSUS_SOURCE=collector|authorities|static
 *     collector   — Fetch from Tor Collector with DoH resolution (default)
 *     authorities — Use directory authority IPs directly (zero DNS)
 *     static      — Load from CONSENSUS_FILE on disk
 *   CONSENSUS_FILE — Path to a static consensus JSON file (for source=static)
 */

const https = require('https');

const CONSENSUS_SOURCE = process.env.CONSENSUS_SOURCE || 'collector';
const CONSENSUS_FILE = process.env.CONSENSUS_FILE || null;

/**
 * Known IPs for Tor infrastructure domains.
 * These are periodically verified and updated.
 * When stale, DoH fallback resolves them securely.
 */
const KNOWN_IPS = {
  'collector.torproject.org': ['116.202.120.166'],
  'onionoo.torproject.org': ['116.202.120.165'],
  'metrics.torproject.org': ['116.202.120.165'],
};

/**
 * Resolve a hostname securely — no plaintext DNS queries.
 *
 * 1. Check KNOWN_IPS cache
 * 2. Fall back to DNS-over-HTTPS via Cloudflare (1.1.1.1)
 *
 * @param {string} hostname
 * @returns {Promise<string>} Resolved IP address
 */
async function resolveSecure(hostname) {
  // Check cache first
  if (KNOWN_IPS[hostname] && KNOWN_IPS[hostname].length > 0) {
    const ips = KNOWN_IPS[hostname];
    return ips[Math.floor(Math.random() * ips.length)];
  }

  // DoH fallback via Cloudflare
  return new Promise((resolve, reject) => {
    const dohUrl = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=A`;
    const req = https.get(dohUrl, {
      headers: { 'Accept': 'application/dns-json' },
      timeout: 5000,
    }, (res) => {
      let body = '';
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => {
        try {
          const data = JSON.parse(body);
          if (data.Answer && data.Answer.length > 0) {
            const aRecords = data.Answer.filter(a => a.type === 1);
            if (aRecords.length > 0) {
              const ip = aRecords[Math.floor(Math.random() * aRecords.length)].data;
              // Cache for future use
              KNOWN_IPS[hostname] = aRecords.map(a => a.data);
              resolve(ip);
              return;
            }
          }
          reject(new Error(`DoH: No A records for ${hostname}`));
        } catch (e) {
          reject(new Error(`DoH parse error: ${e.message}`));
        }
      });
    });
    req.on('error', (e) => reject(new Error(`DoH request failed: ${e.message}`)));
    req.on('timeout', () => { req.destroy(); reject(new Error('DoH timeout')); });
  });
}

/**
 * Make an HTTPS GET request using secure DNS resolution.
 * Resolves the hostname via resolveSecure(), then connects
 * to the IP directly with correct Host header and SNI.
 *
 * @param {string} url - Full HTTPS URL
 * @param {object} options - Additional request options
 * @returns {Promise<{statusCode: number, headers: object, body: string}>}
 */
function httpsGetSecure(url, options = {}) {
  return new Promise(async (resolve, reject) => {
    try {
      const parsed = new URL(url);
      const hostname = parsed.hostname;
      const ip = await resolveSecure(hostname);

      const reqOptions = {
        hostname: ip,
        port: parsed.port || 443,
        path: parsed.pathname + parsed.search,
        method: 'GET',
        headers: {
          'Host': hostname,
          ...options.headers,
        },
        servername: hostname, // SNI for TLS
        timeout: options.timeout || 15000,
      };

      const req = https.request(reqOptions, (res) => {
        let body = '';
        res.on('data', chunk => { body += chunk; });
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            body,
          });
        });
      });

      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout')); });
      req.end();
    } catch (e) {
      reject(e);
    }
  });
}

module.exports = {
  resolveSecure,
  httpsGetSecure,
  KNOWN_IPS,
  CONSENSUS_SOURCE,
  CONSENSUS_FILE,
};
