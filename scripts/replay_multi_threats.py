#!/usr/bin/env python3
"""
scripts/replay_multi_threats.py
===============================

Replays diverse threat scenarios into the live UniThreat AI backend:
  - Benign background traffic (0 alerts)
  - Port Scan / Reconnaissance (Reconnaissance alert, ~0.75 confidence)
  - C2 Beaconing (C2_BEACONING / ENCRYPTED_ANOMALY, 0.55 - 0.76 confidence)
  - DGA (Algorithmic Domain Generation, 0.66 - 0.86 confidence)
  - Encrypted Session Anomaly (ENCRYPTED_ANOMALY, ~0.74 confidence)
  - DNS Tunneling (DNS_TUNNELING, ~0.98 confidence)
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys
import time

import httpx
import websockets

from unithreat.generator.traffic import generate_flows

SCENARIOS = [
    ("benign", 8, "Benign Background Traffic (HTTP/DNS/NTP)"),
    ("port_scan", 25, "Reconnaissance / Port Scan (Nmap SYN Sweep)"),
    ("c2_beacon", 20, "Botnet C2 Beaconing (Periodic Outbound)"),
    ("dga", 15, "DGA (Algorithmic Domain Generation Queries)"),
    ("encrypted_anomaly", 15, "Malware In Encrypted Session (Obsolete TLS Ciphers)"),
    ("dns_tunnel", 15, "DNS Tunneling (Base32/Hex Encapsulated Payloads)"),
]

BASE_URL = "http://127.0.0.1:8000"
WS_URL = "ws://127.0.0.1:8000/ws/alerts"


async def main():
    print("=" * 80)
    print("UniThreat AI — Live Multi-Threat & Varied Confidence Replay Demonstration")
    print("=" * 80)
    print(f"Target Backend: {BASE_URL}")
    print(f"WebSocket URL:  {WS_URL}")
    print(f"Live Dashboard: http://localhost:5173\n")

    # Connect WebSocket listener to display streamed alerts in real time
    received_alerts: list[dict] = []
    ws_ready = asyncio.Event()

    async def ws_listener():
        async with websockets.connect(WS_URL) as ws:
            ws_ready.set()
            try:
                while True:
                    msg = await ws.recv()
                    alert = json.loads(msg)
                    received_alerts.append(alert)
                    conf_pct = f"{alert.get('confidence', 0) * 100:.1f}%"
                    print(
                        f"  ⚡ [LIVE WS ALERT] {alert.get('threat_class'):<20} | "
                        f"Sev: {alert.get('severity'):<8} | "
                        f"Conf: {conf_pct:>6} | "
                        f"Flow: {alert.get('flow_id'):<18} | "
                        f"Src: {alert.get('source_ip', 'N/A')}"
                    )
            except asyncio.CancelledError:
                pass

    listener_task = asyncio.create_task(ws_listener())
    await ws_ready.wait()
    print("[*] Connected to live WebSocket stream. Replaying scenarios...\n")

    async with httpx.AsyncClient(timeout=10.0) as client:
        # Pre-check health
        health = (await client.get(f"{BASE_URL}/health")).json()
        print(f"[*] Initial Backend Health: {health['status']} | Active WS Subscribers: {health['active_stream_subscribers']}\n")

        for scenario_name, count, desc in SCENARIOS:
            print(f">>> Replaying Scenario: {scenario_name.upper()} ({count} flows)")
            print(f"    Description: {desc}")

            flows = list(generate_flows(scenario=scenario_name, count=count, seed=int(time.time()) % 10000))
            scenario_alerts_before = len(received_alerts)

            for idx, flow in enumerate(flows, 1):
                # Ensure unique flow IDs across replays
                flow["flow_id"] = f"{scenario_name[:6]}-{int(time.time()*1000)%1000000:06d}-{idx:02d}"
                res = await client.post(f"{BASE_URL}/ingest/flow", json=flow)
                if res.status_code != 200:
                    print(f"    [!] Error ingesting {flow['flow_id']}: {res.status_code}")
                # Inter-flow streaming delay to observe live SOC dashboard updates
                await asyncio.sleep(0.12)

            scenario_alerts_after = len(received_alerts)
            new_alerts_count = scenario_alerts_after - scenario_alerts_before
            print(f"    -> Finished {scenario_name}. New alerts triggered: {new_alerts_count}\n")
            await asyncio.sleep(0.3)

    # Let final WS notifications flush
    await asyncio.sleep(0.5)
    listener_task.cancel()
    try:
        await listener_task
    except asyncio.CancelledError:
        pass

    print("=" * 80)
    print("REPLAY COMPLETE — SUMMARY OF DETECTIONS ACROSS THREAT CLASSES")
    print("=" * 80)
    by_class: dict[str, list[float]] = {}
    by_sev: dict[str, int] = {}
    for a in received_alerts:
        tc = a.get("threat_class", "UNKNOWN")
        conf = float(a.get("confidence", 0.0))
        sev = a.get("severity", "UNKNOWN")
        by_class.setdefault(tc, []).append(conf)
        by_sev[sev] = by_sev.get(sev, 0) + 1

    print(f"Total Live Streamed Alerts: {len(received_alerts)}")
    print("\nThreat Classes & Confidence Distributions:")
    for tc, confs in sorted(by_class.items()):
        min_c = min(confs) * 100
        max_c = max(confs) * 100
        avg_c = (sum(confs) / len(confs)) * 100
        print(f"  - {tc:<22} : {len(confs):2} alert(s) | Confidence Range: {min_c:5.1f}% – {max_c:5.1f}% (Avg: {avg_c:5.1f}%)")

    print("\nSeverities:")
    for sev, count in sorted(by_sev.items()):
        print(f"  - {sev:<10} : {count}")

    print("\nCheck your browser at http://localhost:5173 to view the diverse alerts!")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())
