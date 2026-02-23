#!/bin/bash

# Verify ECH (Encrypted Client Hello) is working for a bridge domain.
#
# Usage:
#   ./verify-ech.sh bridge.example.com
#   ./verify-ech.sh bridge.example.com 443

DOMAIN="${1:?Usage: $0 DOMAIN [PORT]}"
PORT="${2:-443}"

echo "ECH Verification for ${DOMAIN}:${PORT}"
echo "======================================="
echo ""

# 1. Check HTTPS DNS record for ECH config
echo "1. Checking HTTPS DNS record for ECH keys..."
HTTPS_RECORD=$(dig "${DOMAIN}" HTTPS +short 2>/dev/null)
if [ -z "${HTTPS_RECORD}" ]; then
  echo "   WARNING: No HTTPS DNS record found"
  echo "   ECH requires HTTPS/SVCB DNS records with ech= parameter"
else
  echo "   ${HTTPS_RECORD}"
  if echo "${HTTPS_RECORD}" | grep -qi "ech="; then
    echo "   PASS: ECH config found in DNS"
  else
    echo "   WARNING: HTTPS record exists but no ech= parameter"
  fi
fi
echo ""

# 2. Test TLS connection
echo "2. Testing TLS connection..."
TLS_OUTPUT=$(echo | openssl s_client -connect "${DOMAIN}:${PORT}" -servername "${DOMAIN}" 2>&1)
TLS_VERSION=$(echo "${TLS_OUTPUT}" | grep "Protocol" | head -1)
CIPHER=$(echo "${TLS_OUTPUT}" | grep "Cipher" | head -1)
echo "   ${TLS_VERSION}"
echo "   ${CIPHER}"
echo ""

# 3. Check if server is behind Cloudflare
echo "3. Checking CDN headers..."
HEADERS=$(curl -sI "https://${DOMAIN}/" 2>/dev/null)
if echo "${HEADERS}" | grep -qi "cloudflare\|cf-ray"; then
  echo "   PASS: Behind Cloudflare (ECH supported)"
  CF_RAY=$(echo "${HEADERS}" | grep -i "cf-ray")
  echo "   ${CF_RAY}"
elif echo "${HEADERS}" | grep -qi "fastly"; then
  echo "   INFO: Behind Fastly (ECH support varies)"
else
  echo "   WARNING: No CDN detected — ECH requires CDN support"
fi
echo ""

# 4. Test bridge health endpoint
echo "4. Testing bridge health endpoint..."
HEALTH=$(curl -s "https://${DOMAIN}/health" 2>/dev/null)
if [ -n "${HEALTH}" ]; then
  echo "   ${HEALTH}"
  if echo "${HEALTH}" | grep -q '"status":"ok"'; then
    echo "   PASS: Bridge is healthy"
  fi
else
  echo "   WARNING: No response from /health"
fi
echo ""

# 5. Test WebSocket upgrade
echo "5. Testing WebSocket upgrade..."
WS_RESPONSE=$(curl -sI \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGVzdA==" \
  "https://${DOMAIN}/" 2>/dev/null)
if echo "${WS_RESPONSE}" | grep -qi "101\|upgrade"; then
  echo "   PASS: WebSocket upgrade supported"
else
  echo "   INFO: WebSocket upgrade requires ?addr= or ?dest= parameter"
  echo "   (This is expected — the bridge requires a target)"
fi
echo ""

# 6. Test consensus endpoint
echo "6. Testing consensus endpoint..."
CONSENSUS=$(curl -s "https://${DOMAIN}/tor/consensus" 2>/dev/null | head -c 200)
if echo "${CONSENSUS}" | grep -q "relay_count"; then
  RELAY_COUNT=$(echo "${CONSENSUS}" | grep -o '"relay_count":[0-9]*' | head -1)
  echo "   PASS: Consensus cached (${RELAY_COUNT})"
elif echo "${CONSENSUS}" | grep -q "not yet fetched"; then
  echo "   INFO: Consensus not yet cached (bridge just started)"
else
  echo "   WARNING: Unexpected consensus response"
fi
echo ""

echo "======================================="
echo "Summary: If steps 1 and 3 pass, ECH is active."
echo "A censor sees a connection to Cloudflare — not to your bridge."
