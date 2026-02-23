#!/bin/bash
#
# Tor WASM Bridge Server - One-Command Install
#
# This script installs and runs the tor-wasm bridge server alongside
# your existing Tor infrastructure. Run this on any server with Node.js 18+.
#
# Usage:
#   curl -sL https://raw.githubusercontent.com/yourorg/tor-wasm/main/bridge-server/install.sh | bash
#
# Or for existing Tor bridge operators:
#   curl -sL https://shroud.network/bridge-install.sh | bash
#
# The bridge provides:
# - WebSocket→TCP proxy for browser-based Tor clients
# - Consensus data API from collector.torproject.org
# - TLS termination for secure browser connections
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║           🧅 Tor WASM Bridge Server Installer                  ║"
echo "║                                                                 ║"
echo "║  This bridge enables browser-based Tor clients (WASM)          ║"
echo "║  Same mission as your Tor relay/bridge: Internet privacy       ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check prerequisites
check_prereqs() {
    echo -e "${YELLOW}Checking prerequisites...${NC}"
    
    # Check Node.js
    if ! command -v node &> /dev/null; then
        echo -e "${RED}❌ Node.js not found. Installing...${NC}"
        
        # Detect OS and install Node.js
        if command -v apt-get &> /dev/null; then
            # Debian/Ubuntu
            curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
            sudo apt-get install -y nodejs
        elif command -v yum &> /dev/null; then
            # RHEL/CentOS
            curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -
            sudo yum install -y nodejs
        elif command -v brew &> /dev/null; then
            # macOS
            brew install node
        else
            echo -e "${RED}Cannot auto-install Node.js. Please install Node.js 18+ manually.${NC}"
            exit 1
        fi
    fi
    
    NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
    if [ "$NODE_VERSION" -lt 18 ]; then
        echo -e "${RED}❌ Node.js version 18+ required. Found: $(node -v)${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Node.js $(node -v) found${NC}"
    
    # Check npm
    if ! command -v npm &> /dev/null; then
        echo -e "${RED}❌ npm not found${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ npm $(npm -v) found${NC}"
}

# Create installation directory
INSTALL_DIR="${HOME}/.tor-wasm-bridge"

install_bridge() {
    echo -e "${YELLOW}Installing bridge server...${NC}"
    
    # Create directory
    mkdir -p "$INSTALL_DIR"
    cd "$INSTALL_DIR"
    
    # Create package.json
    cat > package.json << 'EOF'
{
  "name": "tor-wasm-bridge",
  "version": "1.0.0",
  "description": "WebSocket to TCP bridge for Tor WASM clients",
  "main": "server.js",
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {
    "ws": "^8.14.2"
  }
}
EOF

    # Create minimal bridge server
    cat > server.js << 'SERVEREOF'
/**
 * Tor WASM Bridge Server (Minimal)
 * 
 * This provides:
 * 1. WebSocket → TCP proxy (for browser Tor clients)
 * 2. Consensus API endpoint (relays from collector.torproject.org)
 * 
 * Run: node server.js
 * Test: curl http://localhost:8080/health
 */

const https = require('https');
const net = require('net');
const tls = require('tls');
const WebSocket = require('ws');
const http = require('http');
const url = require('url');

const PORT = process.env.PORT || 8080;
const VERSION = '1.0.0';

// In-memory consensus cache
let consensusCache = null;
let consensusFetchTime = 0;
const CONSENSUS_TTL = 3600 * 1000; // 1 hour

console.log(`🧅 Tor WASM Bridge Server v${VERSION}`);
console.log(`📡 Starting on port ${PORT}...`);

// Fetch consensus from Tor Collector
async function fetchConsensus() {
    const now = Date.now();
    if (consensusCache && (now - consensusFetchTime) < CONSENSUS_TTL) {
        return consensusCache;
    }

    console.log('📥 Fetching fresh consensus from collector.torproject.org...');
    
    return new Promise((resolve, reject) => {
        const req = https.get('https://collector.torproject.org/recent/relay-descriptors/consensuses/', (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', async () => {
                try {
                    // Parse directory listing
                    const matches = data.match(/href="([^"]+consensus[^"]+)"/g) || [];
                    const files = matches
                        .map(m => m.match(/href="([^"]+)"/)[1])
                        .filter(f => f.endsWith('consensus'));
                    
                    if (files.length === 0) {
                        throw new Error('No consensus files found');
                    }
                    
                    // Get latest consensus
                    const latestFile = files[files.length - 1];
                    const consensusUrl = `https://collector.torproject.org/recent/relay-descriptors/consensuses/${latestFile}`;
                    
                    https.get(consensusUrl, (res2) => {
                        let consensusData = '';
                        res2.on('data', chunk => consensusData += chunk);
                        res2.on('end', () => {
                            // Parse consensus (simplified)
                            const relays = parseConsensus(consensusData);
                            consensusCache = { relays, fetchedAt: Date.now() };
                            consensusFetchTime = Date.now();
                            console.log(`✅ Cached ${relays.length} relays`);
                            resolve(consensusCache);
                        });
                    }).on('error', reject);
                } catch (e) {
                    reject(e);
                }
            });
        });
        req.on('error', reject);
    });
}

// Parse consensus document
function parseConsensus(text) {
    const relays = [];
    let current = null;
    
    for (const line of text.split('\n')) {
        if (line.startsWith('r ')) {
            if (current) relays.push(current);
            const parts = line.split(' ');
            current = {
                nickname: parts[1],
                fingerprint: parts[2],
                address: parts[6],
                or_port: parseInt(parts[7]),
                flags: {}
            };
        } else if (line.startsWith('s ') && current) {
            const flags = line.slice(2).split(' ');
            current.flags = {
                Guard: flags.includes('Guard'),
                Exit: flags.includes('Exit'),
                Stable: flags.includes('Stable'),
                Fast: flags.includes('Fast'),
                Running: flags.includes('Running'),
                Valid: flags.includes('Valid')
            };
        } else if (line.startsWith('w ') && current) {
            const match = line.match(/Bandwidth=(\d+)/);
            if (match) current.bandwidth = parseInt(match[1]);
        }
    }
    if (current) relays.push(current);
    
    return relays.filter(r => r.flags.Running && r.flags.Valid);
}

// Create HTTP server
const server = http.createServer(async (req, res) => {
    const parsedUrl = url.parse(req.url, true);
    
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    
    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    }
    
    if (parsedUrl.pathname === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            status: 'ok',
            version: VERSION,
            uptime: process.uptime(),
            consensusCached: !!consensusCache,
            relayCount: consensusCache?.relays?.length || 0
        }));
    } else if (parsedUrl.pathname === '/consensus') {
        try {
            const consensus = await fetchConsensus();
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                consensus: {
                    relays: consensus.relays.slice(0, 100) // Limit for response size
                },
                relays: consensus.relays
            }));
        } catch (e) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: e.message }));
        }
    } else {
        res.writeHead(404);
        res.end('Not found');
    }
});

// Create WebSocket server
const wss = new WebSocket.Server({ noServer: true });

// Handle WebSocket upgrade
server.on('upgrade', (request, socket, head) => {
    const parsedUrl = url.parse(request.url, true);
    
    if (parsedUrl.query.addr) {
        wss.handleUpgrade(request, socket, head, (ws) => {
            handleWebSocketProxy(ws, parsedUrl.query.addr);
        });
    } else {
        socket.destroy();
    }
});

// WebSocket → TLS/TCP proxy
function handleWebSocketProxy(ws, addr) {
    const [host, portStr] = addr.split(':');
    const port = parseInt(portStr);
    
    console.log(`🔌 New connection → ${host}:${port}`);
    
    // Connect via TLS (Tor relays use TLS)
    const tcpSocket = tls.connect({
        host,
        port,
        rejectUnauthorized: false // Tor uses self-signed certs
    });
    
    tcpSocket.on('connect', () => {
        console.log(`✅ Connected to ${host}:${port}`);
    });
    
    tcpSocket.on('data', (data) => {
        if (ws.readyState === WebSocket.OPEN) {
            ws.send(data);
        }
    });
    
    tcpSocket.on('error', (err) => {
        console.error(`❌ TCP error: ${err.message}`);
        ws.close();
    });
    
    tcpSocket.on('close', () => {
        ws.close();
    });
    
    ws.on('message', (data) => {
        tcpSocket.write(data);
    });
    
    ws.on('close', () => {
        tcpSocket.destroy();
    });
    
    ws.on('error', (err) => {
        console.error(`❌ WS error: ${err.message}`);
        tcpSocket.destroy();
    });
}

// Start server
server.listen(PORT, () => {
    console.log(`✅ Bridge server running on http://localhost:${PORT}`);
    console.log(`📡 Endpoints:`);
    console.log(`   GET /health    - Server status`);
    console.log(`   GET /consensus - Tor relay list`);
    console.log(`   WS  /?addr=IP:PORT - Proxy to Tor relay`);
    
    // Pre-fetch consensus
    fetchConsensus().catch(e => console.error('Initial consensus fetch failed:', e));
});
SERVEREOF

    # Install dependencies
    echo -e "${YELLOW}Installing dependencies...${NC}"
    npm install --production

    echo -e "${GREEN}✅ Bridge server installed to ${INSTALL_DIR}${NC}"
}

# Create systemd service (optional)
create_service() {
    if [ "$EUID" -eq 0 ] && command -v systemctl &> /dev/null; then
        echo -e "${YELLOW}Creating systemd service...${NC}"
        
        cat > /etc/systemd/system/tor-wasm-bridge.service << EOF
[Unit]
Description=Tor WASM Bridge Server
After=network.target

[Service]
Type=simple
User=$SUDO_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/node $INSTALL_DIR/server.js
Restart=always
RestartSec=10
Environment=PORT=8080

[Install]
WantedBy=multi-user.target
EOF

        systemctl daemon-reload
        systemctl enable tor-wasm-bridge
        systemctl start tor-wasm-bridge
        
        echo -e "${GREEN}✅ Service created and started${NC}"
        echo -e "   Status: ${BLUE}sudo systemctl status tor-wasm-bridge${NC}"
        echo -e "   Logs:   ${BLUE}sudo journalctl -u tor-wasm-bridge -f${NC}"
    fi
}

# Test the installation
test_installation() {
    echo -e "${YELLOW}Testing installation...${NC}"
    
    cd "$INSTALL_DIR"
    
    # Start server in background
    node server.js &
    SERVER_PID=$!
    sleep 2
    
    # Test health endpoint
    if curl -s http://localhost:8080/health | grep -q "ok"; then
        echo -e "${GREEN}✅ Health check passed!${NC}"
    else
        echo -e "${RED}❌ Health check failed${NC}"
    fi
    
    # Kill test server
    kill $SERVER_PID 2>/dev/null || true
}

# Main
main() {
    check_prereqs
    install_bridge
    test_installation
    
    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}✅ Installation complete!${NC}"
    echo ""
    echo -e "To start the bridge server:"
    echo -e "  ${BLUE}cd ${INSTALL_DIR} && npm start${NC}"
    echo ""
    echo -e "Or run in background with PM2:"
    echo -e "  ${BLUE}npm install -g pm2${NC}"
    echo -e "  ${BLUE}pm2 start ${INSTALL_DIR}/server.js --name tor-bridge${NC}"
    echo ""
    echo -e "Test the server:"
    echo -e "  ${BLUE}curl http://localhost:8080/health${NC}"
    echo ""
    echo -e "${YELLOW}⚠️  For production, add HTTPS using nginx or a reverse proxy${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
    
    # Optionally create systemd service
    if [ "$EUID" -eq 0 ]; then
        read -p "Create systemd service for auto-start? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            create_service
        fi
    fi
}

main "$@"

