"""
tests/api/test_stream.py
========================

Tests for WebSocket live alert streaming and AlertStreamManager:
  - WebSocket subscription and real-time alert delivery
  - Clean disconnect handling
  - Bounded per-subscriber queue drop-oldest behavior
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from fastapi.testclient import TestClient
import pytest

from unithreat.alerts.pipeline import IntegratedPipeline
from unithreat.api.app import create_app
from unithreat.api.stream import AlertStreamManager


def _sample_alert(flow_id: str) -> dict:
    return {
        "timestamp": "2026-09-08T08:00:00.000000Z",
        "flow_id": flow_id,
        "threat_class": "DDOS",
        "confidence": 0.9,
        "severity": "CRITICAL",
        "evidence": [],
    }


class TestAlertStreamManager:
    def test_bounded_queue_drop_oldest(self):
        manager = AlertStreamManager(max_queue_size=3)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=3)
        manager.register(queue)

        # Broadcast 4 alerts into a queue of maxsize=3
        manager.broadcast(_sample_alert("alert-1"))
        manager.broadcast(_sample_alert("alert-2"))
        manager.broadcast(_sample_alert("alert-3"))
        # 4th should drop alert-1 and keep 2, 3, 4
        manager.broadcast(_sample_alert("alert-4"))

        assert queue.qsize() == 3
        items = []
        while not queue.empty():
            items.append(queue.get_nowait()["flow_id"])

        assert items == ["alert-2", "alert-3", "alert-4"]
        manager.unregister(queue)
        loop.close()


class TestWebSocketStreaming:
    def test_websocket_receives_broadcast_alert(self):
        stream_mgr = AlertStreamManager(max_queue_size=10)
        pipeline = IntegratedPipeline(stream_manager=stream_mgr)
        app = create_app(pipeline=pipeline, stream_manager=stream_mgr)

        client = TestClient(app)

        with client.websocket_connect("/ws/alerts") as ws:
            # Broadcast an alert through stream manager
            alert = _sample_alert("ws-test-alert-001")
            stream_mgr.broadcast(alert)

            # Client receives message
            data = ws.receive_text()
            received = json.loads(data)
            assert received["flow_id"] == "ws-test-alert-001"
            assert received["threat_class"] == "DDOS"

    def test_websocket_clean_disconnect(self):
        stream_mgr = AlertStreamManager(max_queue_size=10)
        pipeline = IntegratedPipeline(stream_manager=stream_mgr)
        app = create_app(pipeline=pipeline, stream_manager=stream_mgr)

        client = TestClient(app)

        with client.websocket_connect("/ws/alerts") as ws:
            assert stream_mgr.subscriber_count() == 1
            ws.close()

        # After context manager exits, subscriber is cleaned up
        assert stream_mgr.subscriber_count() == 0
