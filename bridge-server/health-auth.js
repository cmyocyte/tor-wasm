/**
 * Health Endpoint Authentication
 *
 * Hides the /health endpoint from active probers.
 *
 * Configuration (env vars):
 *   HEALTH_AUTH_TOKEN  — Token required for /health access (if unset, /health is hidden)
 *   MANAGEMENT_PORT    — Serve health on a separate localhost-only port (not exposed externally)
 */

const http = require('http');

const HEALTH_TOKEN = process.env.HEALTH_AUTH_TOKEN || null;
const MANAGEMENT_PORT = process.env.MANAGEMENT_PORT ? parseInt(process.env.MANAGEMENT_PORT, 10) : null;

/**
 * Check if a request is authorized for health data.
 * Returns true if:
 *   - Request has ?token=<HEALTH_AUTH_TOKEN>
 *   - Request has Authorization: Bearer <HEALTH_AUTH_TOKEN>
 * Returns false otherwise.
 */
function isHealthAuthorized(req) {
  if (!HEALTH_TOKEN) return false;

  // Check query parameter
  const url = new URL(req.url, 'http://localhost');
  if (url.searchParams.get('token') === HEALTH_TOKEN) return true;

  // Check Authorization header
  const auth = req.headers['authorization'];
  if (auth && auth === `Bearer ${HEALTH_TOKEN}`) return true;

  return false;
}

/**
 * Build a sanitized health response (no identifying fields).
 * @param {object} stats - Raw stats from the server
 * @returns {object} Sanitized health object
 */
function sanitizeHealth(stats) {
  return {
    status: stats.status || 'ok',
    uptime: stats.uptime || Math.floor(process.uptime()),
    connections: stats.connections || 0,
  };
}

/**
 * Start a management server on localhost-only port.
 * Only accessible from the machine itself (127.0.0.1).
 * @param {function} getStats - Returns raw health stats
 */
function startManagementServer(getStats) {
  if (!MANAGEMENT_PORT) return null;

  const mgmtServer = http.createServer((req, res) => {
    if (req.url === '/health' || req.url === '/') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(sanitizeHealth(getStats()), null, 2));
      return;
    }
    res.writeHead(404);
    res.end('Not found');
  });

  mgmtServer.listen(MANAGEMENT_PORT, '127.0.0.1', () => {
    // Intentionally quiet — use logger if available
  });

  return mgmtServer;
}

/**
 * Handle a /health request on the main port.
 * If authorized → return sanitized health JSON.
 * If not authorized → return false (caller should serve cover site).
 *
 * @param {http.IncomingMessage} req
 * @param {http.ServerResponse} res
 * @param {object} stats - Raw health stats
 * @returns {boolean} true if handled, false if caller should serve cover site
 */
function handleHealth(req, res, stats) {
  // If management port is configured, never serve health on main port
  if (MANAGEMENT_PORT) return false;

  // If auth token is set, check authorization
  if (HEALTH_TOKEN) {
    if (isHealthAuthorized(req)) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(sanitizeHealth(stats), null, 2));
      return true;
    }
    return false; // Unauthorized — serve cover site
  }

  // No auth configured — hide health entirely (serve cover site)
  return false;
}

module.exports = {
  isHealthAuthorized,
  sanitizeHealth,
  startManagementServer,
  handleHealth,
  HEALTH_TOKEN,
  MANAGEMENT_PORT,
};
