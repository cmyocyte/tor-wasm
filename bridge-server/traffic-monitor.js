/**
 * Traffic Monitor
 *
 * Records per-connection traffic statistics for DPI fingerprint analysis.
 * Data is logged to file (never exposed via HTTP) so operators can compare
 * their bridge's traffic distribution against legitimate WebSocket apps.
 *
 * Usage:
 *   const { TrafficMonitor } = require('./traffic-monitor');
 *   const monitor = new TrafficMonitor();
 *
 *   // On each WebSocket message:
 *   monitor.recordFrame(connId, frameSize, direction);
 *
 *   // On connection close:
 *   const stats = monitor.closeConnection(connId);
 *
 *   // Get aggregate statistics:
 *   const report = monitor.getReport();
 */

const fs = require('fs');
const path = require('path');

const LOG_FILE = process.env.TRAFFIC_LOG || null;
const ENABLE_MONITOR = process.env.TRAFFIC_MONITOR === '1' || process.env.TRAFFIC_MONITOR === 'true';

// Histogram bucket boundaries for frame sizes (bytes)
const SIZE_BUCKETS = [64, 128, 256, 512, 514, 768, 1024, 2048, 4096, 8192, 16384, 65536];

// Histogram bucket boundaries for inter-arrival times (ms)
const TIMING_BUCKETS = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 5000];

class ConnectionStats {
  constructor(connId) {
    this.connId = connId;
    this.startTime = Date.now();
    this.lastFrameTime = this.startTime;
    this.frameCount = { up: 0, down: 0 };
    this.totalBytes = { up: 0, down: 0 };
    this.sizeHistogram = { up: new Array(SIZE_BUCKETS.length + 1).fill(0), down: new Array(SIZE_BUCKETS.length + 1).fill(0) };
    this.timingHistogram = new Array(TIMING_BUCKETS.length + 1).fill(0);
    this.burstFrames = []; // frames per second samples
    this._burstStart = Date.now();
    this._burstCount = 0;
  }

  recordFrame(size, direction) {
    const dir = direction === 'up' ? 'up' : 'down';
    this.frameCount[dir]++;
    this.totalBytes[dir] += size;

    // Size histogram
    let bucket = SIZE_BUCKETS.length;
    for (let i = 0; i < SIZE_BUCKETS.length; i++) {
      if (size <= SIZE_BUCKETS[i]) { bucket = i; break; }
    }
    this.sizeHistogram[dir][bucket]++;

    // Inter-arrival timing
    const now = Date.now();
    const delta = now - this.lastFrameTime;
    this.lastFrameTime = now;

    let timeBucket = TIMING_BUCKETS.length;
    for (let i = 0; i < TIMING_BUCKETS.length; i++) {
      if (delta <= TIMING_BUCKETS[i]) { timeBucket = i; break; }
    }
    this.timingHistogram[timeBucket]++;

    // Burst tracking (frames per second)
    this._burstCount++;
    if (now - this._burstStart >= 1000) {
      this.burstFrames.push(this._burstCount);
      this._burstCount = 0;
      this._burstStart = now;
    }
  }

  toSummary() {
    const duration = (Date.now() - this.startTime) / 1000;
    return {
      connId: this.connId,
      duration_s: Math.round(duration * 10) / 10,
      frames: this.frameCount,
      bytes: this.totalBytes,
      ratio: this.totalBytes.down > 0 ? Math.round((this.totalBytes.up / this.totalBytes.down) * 100) / 100 : 0,
      avgFrameSize: {
        up: this.frameCount.up > 0 ? Math.round(this.totalBytes.up / this.frameCount.up) : 0,
        down: this.frameCount.down > 0 ? Math.round(this.totalBytes.down / this.frameCount.down) : 0,
      },
      sizeDistribution: {
        buckets: SIZE_BUCKETS,
        up: this.sizeHistogram.up,
        down: this.sizeHistogram.down,
      },
      timingDistribution: {
        buckets: TIMING_BUCKETS,
        counts: this.timingHistogram,
      },
      burstRate: {
        samples: this.burstFrames.length,
        avg: this.burstFrames.length > 0 ? Math.round(this.burstFrames.reduce((a, b) => a + b, 0) / this.burstFrames.length * 10) / 10 : 0,
        max: this.burstFrames.length > 0 ? Math.max(...this.burstFrames) : 0,
      },
    };
  }
}

class TrafficMonitor {
  constructor() {
    this.connections = new Map();
    this.completedStats = [];
    this.enabled = ENABLE_MONITOR;
  }

  /**
   * Start tracking a new connection.
   */
  openConnection(connId) {
    if (!this.enabled) return;
    this.connections.set(connId, new ConnectionStats(connId));
  }

  /**
   * Record a WebSocket frame.
   * @param {number|string} connId
   * @param {number} frameSize - Size in bytes
   * @param {'up'|'down'} direction - 'up' = client→relay, 'down' = relay→client
   */
  recordFrame(connId, frameSize, direction) {
    if (!this.enabled) return;
    const stats = this.connections.get(connId);
    if (stats) stats.recordFrame(frameSize, direction);
  }

  /**
   * Close a connection and return its summary.
   */
  closeConnection(connId) {
    if (!this.enabled) return null;
    const stats = this.connections.get(connId);
    if (!stats) return null;

    this.connections.delete(connId);
    const summary = stats.toSummary();
    this.completedStats.push(summary);

    // Keep only last 1000 completed connections
    if (this.completedStats.length > 1000) {
      this.completedStats = this.completedStats.slice(-500);
    }

    // Write to log file if configured
    if (LOG_FILE) {
      try {
        fs.appendFileSync(LOG_FILE, JSON.stringify(summary) + '\n');
      } catch (e) {
        // Silently ignore write failures
      }
    }

    return summary;
  }

  /**
   * Get aggregate report across all completed connections.
   */
  getReport() {
    if (this.completedStats.length === 0) return { connections: 0 };

    const totalUp = this.completedStats.reduce((s, c) => s + c.bytes.up, 0);
    const totalDown = this.completedStats.reduce((s, c) => s + c.bytes.down, 0);
    const avgDuration = this.completedStats.reduce((s, c) => s + c.duration_s, 0) / this.completedStats.length;

    // Aggregate size distribution
    const aggSizeUp = new Array(SIZE_BUCKETS.length + 1).fill(0);
    const aggSizeDown = new Array(SIZE_BUCKETS.length + 1).fill(0);
    for (const c of this.completedStats) {
      for (let i = 0; i < c.sizeDistribution.up.length; i++) {
        aggSizeUp[i] += c.sizeDistribution.up[i];
        aggSizeDown[i] += c.sizeDistribution.down[i];
      }
    }

    return {
      connections: this.completedStats.length,
      active: this.connections.size,
      totalBytes: { up: totalUp, down: totalDown },
      avgDuration_s: Math.round(avgDuration * 10) / 10,
      aggregateSizeDistribution: {
        buckets: SIZE_BUCKETS,
        up: aggSizeUp,
        down: aggSizeDown,
      },
    };
  }
}

module.exports = { TrafficMonitor };
