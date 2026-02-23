/**
 * Volunteer Peer Proxy for tor-wasm
 *
 * This runs in a volunteer's browser tab. It creates a WebRTC DataChannel
 * and registers with the broker. When a censored client connects, the proxy
 * relays bytes between the client's WebRTC DataChannel and a WebSocket
 * connection to the bridge server.
 *
 * The proxy sees only encrypted bytes — it cannot decrypt them (TLS is
 * end-to-end between the WASM client and the Tor guard relay).
 *
 * No installation required. The volunteer visits a webpage and their
 * browser tab becomes a bridge for censored users.
 */

const ICE_SERVERS = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' },
];

// State
let pc = null;
let brokerWs = null;
let bridgeWs = null;
let proxyId = null;
let bytesRelayed = 0;
let connectionsServed = 0;
let status = 'idle';

/**
 * Start the proxy: register with broker and wait for clients.
 */
async function startProxy(brokerUrl, bridgeUrl) {
  updateStatus('connecting');

  // Create WebRTC peer connection
  pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });

  // Create data channel for binary transport
  const dc = pc.createDataChannel('tor-transport', {
    ordered: true,
    protocol: 'binary',
  });
  dc.binaryType = 'arraybuffer';

  // Collect ICE candidates
  const iceCandidates = [];
  const iceComplete = new Promise((resolve) => {
    pc.onicecandidate = (event) => {
      if (event.candidate) {
        iceCandidates.push(event.candidate.toJSON());
      } else {
        resolve(); // ICE gathering complete
      }
    };
  });

  // Create offer
  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);

  // Wait for ICE candidates
  await iceComplete;

  // Connect to broker
  brokerWs = new WebSocket(brokerUrl);

  brokerWs.onopen = () => {
    // Register as available proxy
    brokerWs.send(JSON.stringify({
      type: 'register',
      sdp_offer: pc.localDescription.toJSON(),
      ice_candidates: iceCandidates,
    }));
  };

  brokerWs.onmessage = async (event) => {
    const msg = JSON.parse(event.data);

    switch (msg.type) {
      case 'registered':
        proxyId = msg.proxy_id;
        updateStatus('waiting');
        log(`Registered with broker. Pool size: ${msg.pool_size}`);
        break;

      case 'connect':
        // Broker matched us with a censored client
        log('Client matched! Setting remote description...');
        updateStatus('connecting-client');

        try {
          await pc.setRemoteDescription(new RTCSessionDescription(msg.sdp_answer));
          for (const candidate of msg.ice_candidates) {
            await pc.addIceCandidate(new RTCIceCandidate(candidate));
          }
          log('Remote description set. Waiting for DataChannel...');
        } catch (err) {
          log('Failed to set remote description: ' + err.message);
          updateStatus('error');
        }
        break;

      case 'error':
        log('Broker error: ' + msg.message);
        break;
    }
  };

  brokerWs.onclose = () => {
    log('Broker connection closed');
    if (status === 'waiting') updateStatus('disconnected');
  };

  // Handle incoming data channel (from client's answer)
  pc.ondatachannel = (event) => {
    const clientDc = event.channel;
    clientDc.binaryType = 'arraybuffer';
    log('Client DataChannel opened');
    setupRelay(clientDc, bridgeUrl);
  };

  // Also handle if our created channel opens (depends on who created it)
  dc.onopen = () => {
    log('DataChannel opened');
    setupRelay(dc, bridgeUrl);
  };
}

/**
 * Set up bidirectional relay: WebRTC DataChannel ↔ WebSocket to bridge.
 */
function setupRelay(dc, bridgeUrl) {
  let firstMessage = true;
  connectionsServed++;
  updateStatus('relaying');

  dc.onmessage = (event) => {
    const data = event.data;

    if (firstMessage) {
      // First message may contain bridge URL override
      // For now, use the configured bridge URL
      firstMessage = false;

      // Open WebSocket to bridge
      bridgeWs = new WebSocket(bridgeUrl);
      bridgeWs.binaryType = 'arraybuffer';

      bridgeWs.onopen = () => {
        log('Bridge WebSocket connected');
        // Forward the first message
        bridgeWs.send(data);
        bytesRelayed += data.byteLength;
        updateStats();
      };

      // Bridge → Client
      bridgeWs.onmessage = (e) => {
        if (dc.readyState === 'open') {
          dc.send(e.data);
          bytesRelayed += e.data.byteLength;
          updateStats();
        }
      };

      bridgeWs.onclose = () => {
        log('Bridge disconnected');
        dc.close();
        updateStatus('waiting');
        reregister();
      };

      bridgeWs.onerror = () => {
        log('Bridge error');
        dc.close();
      };

      return;
    }

    // Subsequent messages: Client → Bridge
    if (bridgeWs && bridgeWs.readyState === WebSocket.OPEN) {
      bridgeWs.send(data);
      bytesRelayed += data.byteLength;
      updateStats();
    }
  };

  dc.onclose = () => {
    log('Client DataChannel closed');
    if (bridgeWs) bridgeWs.close();
    updateStatus('waiting');
    reregister();
  };
}

/**
 * Re-register with broker after a client disconnects.
 */
async function reregister() {
  // Clean up old peer connection
  if (pc) pc.close();
  pc = null;
  bridgeWs = null;

  // Wait a moment then re-register
  setTimeout(() => {
    const brokerUrl = document.getElementById('broker-url')?.value;
    const bridgeUrl = document.getElementById('bridge-url')?.value;
    if (brokerUrl && bridgeUrl) {
      log('Re-registering with broker...');
      startProxy(brokerUrl, bridgeUrl);
    }
  }, 2000);
}

// --- UI helpers ---

function updateStatus(newStatus) {
  status = newStatus;
  const el = document.getElementById('status');
  if (el) {
    const labels = {
      'idle': 'Idle',
      'connecting': 'Connecting to broker...',
      'waiting': 'Ready — waiting for censored users',
      'connecting-client': 'Client connecting...',
      'relaying': 'Relaying traffic for a censored user',
      'disconnected': 'Disconnected from broker',
      'error': 'Error',
    };
    el.textContent = labels[newStatus] || newStatus;
    el.className = 'status-' + newStatus;
  }
}

function updateStats() {
  const el = document.getElementById('stats');
  if (el) {
    const kb = (bytesRelayed / 1024).toFixed(1);
    el.textContent = `${connectionsServed} users helped | ${kb} KB relayed`;
  }
}

function log(msg) {
  console.log(`[proxy] ${msg}`);
  const el = document.getElementById('log');
  if (el) {
    const line = document.createElement('div');
    line.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
    el.appendChild(line);
    el.scrollTop = el.scrollHeight;
  }
}

// Export for use in HTML
if (typeof window !== 'undefined') {
  window.startProxy = startProxy;
}
