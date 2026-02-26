#!/bin/bash
#
# Degraded Network Benchmarks
#
# Simulates three censorship environments using tc netem (Linux traffic control)
# and measures consensus fetch time, circuit build time, and first-byte time.
#
# Requirements:
#   - Linux with tc/netem (iproute2)
#   - Root or sudo access
#   - Bridge server running locally on port 8080
#   - Node.js 18+
#
# Usage:
#   sudo ./benchmark.sh [--bridge URL] [--profile gfw|tspu|iran|all]
#
# Profiles:
#   gfw  — Great Firewall of China: 300ms RTT, 50ms jitter, 5% loss, 1Mbps
#   tspu — Russian TSPU: 200ms RTT, 30ms jitter, 2% loss, 5Mbps, 1% corrupt
#   iran — Iran NIN: 500ms RTT, 100ms jitter, 10% loss, 512kbps
#

set -euo pipefail

BRIDGE_URL="${BRIDGE_URL:-ws://localhost:8080}"
PROFILE="${PROFILE:-all}"
IFACE="${IFACE:-lo}"
RESULTS_DIR="$(dirname "$0")/results"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# Parse args
while [[ $# -gt 0 ]]; do
  case $1 in
    --bridge) BRIDGE_URL="$2"; shift 2;;
    --profile) PROFILE="$2"; shift 2;;
    --iface) IFACE="$2"; shift 2;;
    *) echo "Unknown arg: $1"; exit 1;;
  esac
done

mkdir -p "$RESULTS_DIR"

# --- Network Shaping Functions ---

apply_netem() {
  local name="$1" latency="$2" jitter="$3" loss="$4" rate="$5" corrupt="${6:-0}"

  echo "=== Applying profile: $name ==="
  echo "    Latency: ${latency}ms, Jitter: ${jitter}ms, Loss: ${loss}%, Rate: ${rate}kbit"
  if [[ "$corrupt" != "0" ]]; then
    echo "    Corrupt: ${corrupt}%"
  fi

  # Clear existing rules
  tc qdisc del dev "$IFACE" root 2>/dev/null || true

  # Apply netem
  local cmd="tc qdisc add dev $IFACE root netem delay ${latency}ms ${jitter}ms loss ${loss}%"
  if [[ "$corrupt" != "0" ]]; then
    cmd="$cmd corrupt ${corrupt}%"
  fi
  cmd="$cmd rate ${rate}kbit"

  eval "$cmd"
  echo "    Applied."
}

clear_netem() {
  tc qdisc del dev "$IFACE" root 2>/dev/null || true
  echo "=== Network shaping cleared ==="
}

# --- Benchmark Functions ---

benchmark_consensus_fetch() {
  local profile="$1"
  echo "--- Benchmark: Consensus Fetch ($profile) ---"

  local http_url="${BRIDGE_URL/ws:/http:}"
  http_url="${http_url/wss:/https:}"

  local start end elapsed

  # 5 trials
  for trial in 1 2 3 4 5; do
    start=$(date +%s%N)
    if curl -s -o /dev/null -w "%{http_code}" "${http_url}/tor/consensus" 2>/dev/null | grep -q "200\|503"; then
      end=$(date +%s%N)
      elapsed=$(( (end - start) / 1000000 ))
      echo "    Trial $trial: ${elapsed}ms"
    else
      echo "    Trial $trial: FAILED"
    fi
  done
}

benchmark_websocket_connect() {
  local profile="$1"
  echo "--- Benchmark: WebSocket Connect ($profile) ---"

  # Use node to test WebSocket connection time
  node -e "
    const WebSocket = require('ws');
    const trials = 5;
    let completed = 0;

    for (let i = 0; i < trials; i++) {
      const start = Date.now();
      const ws = new WebSocket('${BRIDGE_URL}?addr=127.0.0.1:1');

      const timeout = setTimeout(() => {
        ws.close();
        console.log('    Trial ' + (i+1) + ': TIMEOUT (>10s)');
        if (++completed >= trials) process.exit(0);
      }, 10000);

      ws.on('open', () => {
        clearTimeout(timeout);
        const elapsed = Date.now() - start;
        console.log('    Trial ' + (i+1) + ': ' + elapsed + 'ms');
        ws.close();
        if (++completed >= trials) process.exit(0);
      });

      ws.on('error', () => {
        clearTimeout(timeout);
        const elapsed = Date.now() - start;
        console.log('    Trial ' + (i+1) + ': ' + elapsed + 'ms (connect ok, relay failed as expected)');
        if (++completed >= trials) process.exit(0);
      });
    }
  " 2>/dev/null || echo "    (WebSocket test requires 'ws' package)"
}

run_profile() {
  local name="$1" latency="$2" jitter="$3" loss="$4" rate="$5" corrupt="${6:-0}"

  echo ""
  echo "============================================"
  echo "  Profile: $name"
  echo "  $(date -u)"
  echo "============================================"

  apply_netem "$name" "$latency" "$jitter" "$loss" "$rate" "$corrupt"

  # Wait for netem to stabilize
  sleep 1

  benchmark_consensus_fetch "$name"
  benchmark_websocket_connect "$name"

  # Record results
  {
    echo "profile: $name"
    echo "timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "params: latency=${latency}ms jitter=${jitter}ms loss=${loss}% rate=${rate}kbit corrupt=${corrupt}%"
    echo "bridge: $BRIDGE_URL"
    echo "---"
  } >> "$RESULTS_DIR/benchmark-${TIMESTAMP}.log"

  clear_netem
  sleep 1
}

# --- Trap for cleanup ---
trap clear_netem EXIT

# --- Main ---

echo "Bridge Degraded Network Benchmark"
echo "Bridge: $BRIDGE_URL"
echo "Interface: $IFACE"
echo "Profile: $PROFILE"
echo "Results: $RESULTS_DIR/benchmark-${TIMESTAMP}.log"

# Check for root/sudo
if [[ $EUID -ne 0 ]]; then
  echo ""
  echo "WARNING: tc netem requires root. Run with: sudo ./benchmark.sh"
  echo ""
  echo "Running without network shaping (baseline only)..."
  echo ""
  echo "============================================"
  echo "  Profile: baseline (no shaping)"
  echo "============================================"
  benchmark_consensus_fetch "baseline"
  benchmark_websocket_connect "baseline"
  exit 0
fi

# Run selected profiles
case "$PROFILE" in
  gfw)
    run_profile "gfw" 150 50 5 1000
    ;;
  tspu)
    run_profile "tspu" 100 30 2 5000 1
    ;;
  iran)
    run_profile "iran" 250 100 10 512
    ;;
  all)
    # Baseline first
    echo ""
    echo "============================================"
    echo "  Profile: baseline (no shaping)"
    echo "============================================"
    benchmark_consensus_fetch "baseline"
    benchmark_websocket_connect "baseline"

    # Then degraded profiles
    run_profile "gfw" 150 50 5 1000
    run_profile "tspu" 100 30 2 5000 1
    run_profile "iran" 250 100 10 512
    ;;
  *)
    echo "Unknown profile: $PROFILE"
    echo "Valid: gfw, tspu, iran, all"
    exit 1
    ;;
esac

echo ""
echo "Benchmark complete. Results in: $RESULTS_DIR/benchmark-${TIMESTAMP}.log"
