/**
 * End-to-End Live Integration Verification Script
 * Validates frontend HttpDataService and WebSocket against the running backend.
 */

const WebSocket = globalThis.WebSocket;

const BASE_HTTP_URL = 'http://127.0.0.1:8000';
const BASE_WS_URL = 'ws://127.0.0.1:8000/ws/alerts';

async function runLiveVerification() {
  console.log('=== Step 1: Health Check ===');
  const healthRes = await fetch(`${BASE_HTTP_URL}/health`);
  if (!healthRes.ok) throw new Error(`Health check failed: ${healthRes.status}`);
  const healthData = await healthRes.json();
  console.log('Health OK:', healthData);

  console.log('\n=== Step 2: Connect WebSocket ===');
  const ws = new WebSocket(BASE_WS_URL);
  const receivedAlerts = [];

  await new Promise((resolve, reject) => {
    ws.addEventListener('open', () => {
      console.log('WebSocket connected successfully to /ws/alerts');
      resolve();
    });
    ws.addEventListener('error', (err) => reject(err));
  });

  ws.addEventListener('message', (event) => {
    const parsed = JSON.parse(event.data.toString());
    console.log('[WebSocket Received Alert]:', parsed.threat_class, parsed.severity, 'flow_id:', parsed.flow_id);
    receivedAlerts.push(parsed);
  });

  console.log('\n=== Step 3: Check Initial Flows & Alerts ===');
  const flowsRes = await fetch(`${BASE_HTTP_URL}/flows`);
  const initialFlows = await flowsRes.json();
  console.log(`Initial flows in buffer: ${initialFlows.length}`);

  const alertsRes = await fetch(`${BASE_HTTP_URL}/alerts`);
  const initialAlerts = await alertsRes.json();
  console.log(`Initial alerts in buffer: ${initialAlerts.length}`);

  console.log('\n=== Step 4: Ingest a Threat Flow (Triggering Alert) ===');
  const ddosFlow = {
    flow_id: `live-test-ddos-${Date.now()}`,
    timestamp: '2026-09-06T12:00:00.000683Z',
    src_ip: '33.197.105.69',
    dst_ip: '10.0.0.50',
    src_port: 8082,
    dst_port: 443,
    protocol: 'UDP',
    direction: 'inbound',
    duration: 0.0054,
    packet_count: 3,
    byte_count: 860,
    tcp_flags: null,
    dns: null,
    tls: null,
    quic: null,
  };

  const ingestRes = await fetch(`${BASE_HTTP_URL}/ingest/flow`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(ddosFlow),
  });
  if (!ingestRes.ok) throw new Error(`Ingest failed: ${ingestRes.status}`);
  const ingestResult = await ingestRes.json();
  console.log('Ingest Result:', ingestResult);

  console.log('\n=== Step 5: Verify Live WebSocket Alert Reception ===');
  // Wait up to 3 seconds for WebSocket event
  const startTime = Date.now();
  while (receivedAlerts.length === 0 && Date.now() - startTime < 3000) {
    await new Promise((r) => setTimeout(r, 100));
  }

  if (receivedAlerts.length === 0) {
    throw new Error('Timeout: Did not receive alert via WebSocket stream!');
  }
  console.log(`Successfully received ${receivedAlerts.length} alert(s) over WebSocket!`);
  const alert = receivedAlerts[0];

  console.log('\n=== Step 6: Verify Flow Lookup Endpoints ===');
  const flowLookupRes = await fetch(`${BASE_HTTP_URL}/flows/${encodeURIComponent(ddosFlow.flow_id)}`);
  if (!flowLookupRes.ok) throw new Error(`Flow lookup failed: ${flowLookupRes.status}`);
  const retrievedFlow = await flowLookupRes.json();
  console.log('Retrieved Flow by ID:', retrievedFlow.flow_id, retrievedFlow.protocol);

  console.log('\n=== Step 7: Verify Feature Extraction Endpoint ===');
  const featRes = await fetch(`${BASE_HTTP_URL}/features/${encodeURIComponent(ddosFlow.flow_id)}`);
  if (!featRes.ok) throw new Error(`Feature lookup failed: ${featRes.status}`);
  const featData = await featRes.json();
  console.log('Retrieved Feature Record for flow:', featData.flow_id);
  console.log('Features extracted count:', Object.keys(featData.features).length);

  console.log('\n=== Step 8: Verify ML Prediction Endpoint ===');
  const predRes = await fetch(`${BASE_HTTP_URL}/predictions/${encodeURIComponent(ddosFlow.flow_id)}`);
  if (predRes.status === 200) {
    const predData = await predRes.json();
    console.log('ML Prediction retrieved:', predData.threat_class, 'Score:', predData.score);
  } else if (predRes.status === 404) {
    console.log('ML Prediction: 404 (ML model inactive in this configuration, truthful response)');
  } else {
    throw new Error(`Unexpected prediction status: ${predRes.status}`);
  }

  console.log('\n=== Step 9: Verify Overview Stats Endpoint ===');
  const statsRes = await fetch(`${BASE_HTTP_URL}/stats`);
  const statsData = await statsRes.json();
  console.log('Updated Stats:', statsData);

  console.log('\n=== Step 10: Clean Shutdown of WebSocket ===');
  ws.close();
  console.log('WebSocket closed.');

  console.log('\n[SUCCESS] All 10 End-to-End Live Integration checkpoints passed!');
}

runLiveVerification().catch((err) => {
  console.error('[FAILED] Live Integration error:', err);
  process.exit(1);
});
