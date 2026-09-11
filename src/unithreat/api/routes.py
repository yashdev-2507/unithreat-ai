"""
unithreat.api.routes
====================

REST and WebSocket route handlers for UniThreat AI dashboard and backend interfaces.

Endpoints:
  - GET  /health
  - GET  /alerts
  - GET  /alerts/{flow_id}
  - GET  /flows
  - GET  /flows/{flow_id}
  - GET  /features/{flow_id}
  - GET  /predictions/{flow_id}
  - GET  /stats
  - POST /ingest/flow
  - WS   /ws/alerts
"""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

from unithreat.alerts.pipeline import IntegratedPipeline

logger = logging.getLogger(__name__)


def create_router(pipeline: IntegratedPipeline) -> APIRouter:
    """Create FastAPI APIRouter configured with the integrated pipeline."""
    router = APIRouter()

    @router.get("/health")
    async def get_health() -> dict[str, Any]:
        """Health check and system status."""
        return {
            "status": "ok",
            "version": "0.1.0",
            "ml_active": pipeline.ml_engine is not None,
            "total_flows_processed": pipeline.total_flows_processed,
            "total_alerts_stored": pipeline.alert_store.count(),
            "active_stream_subscribers": pipeline.stream_manager.subscriber_count() if pipeline.stream_manager else 0,
        }

    @router.get("/alerts")
    async def get_alerts(
        threat_class: str | None = Query(None, description="Filter by threat class (e.g. DDOS, C2_BEACONING)"),
        severity: str | None = Query(None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
        min_confidence: float | None = Query(None, ge=0.0, le=1.0, description="Minimum confidence score"),
        limit: int = Query(100, ge=1, le=1000, description="Maximum number of alerts to return (newest first)"),
    ) -> list[dict[str, Any]]:
        """
        Query stored threat alerts. Returns newest alerts first.
        Strictly conforms to contracts/alert-schema.json.
        """
        return pipeline.alert_store.get_all(
            threat_class=threat_class,
            severity=severity,
            min_confidence=min_confidence,
            limit=limit,
        )

    @router.get("/alerts/{flow_id}")
    async def get_alert_by_flow_id(flow_id: str) -> dict[str, Any]:
        """Retrieve a specific alert by flow_id."""
        alert = pipeline.alert_store.get_by_flow_id(flow_id)
        if alert is None:
            raise HTTPException(status_code=404, detail=f"Alert with flow_id '{flow_id}' not found.")
        return alert

    @router.get("/flows")
    async def get_flows(
        protocol: str | None = Query(None, description="Filter by protocol (e.g. TCP, UDP)"),
        src_ip: str | None = Query(None, description="Filter by source IP"),
        dst_ip: str | None = Query(None, description="Filter by destination IP"),
        limit: int = Query(100, ge=1, le=2000, description="Maximum number of flows to return (newest first)"),
    ) -> list[dict[str, Any]]:
        """
        Query stored recent passive flows. Returns newest flows first.
        Each flow strictly conforms to contracts/flow-schema.json.
        """
        return pipeline.flow_store.get_all(
            protocol=protocol,
            src_ip=src_ip,
            dst_ip=dst_ip,
            limit=limit,
        )

    @router.get("/flows/{flow_id}")
    async def get_flow_by_id(flow_id: str) -> dict[str, Any]:
        """Retrieve raw stored flow by flow_id."""
        flow = pipeline.flow_store.get(flow_id)
        if flow is None:
            raise HTTPException(status_code=404, detail=f"Flow with flow_id '{flow_id}' not found in recent buffer.")
        return flow

    @router.get("/features/{flow_id}")
    async def get_features_by_flow_id(flow_id: str) -> dict[str, Any]:
        """
        Retrieve extracted network feature record by flow_id.
        Strictly conforms to contracts/feature-schema.json.
        """
        feature_record = pipeline.feature_store.get(flow_id)
        if feature_record is None:
            raise HTTPException(status_code=404, detail=f"Feature record for flow_id '{flow_id}' not found.")
        return feature_record

    @router.get("/predictions/{flow_id}")
    async def get_prediction_by_flow_id(flow_id: str) -> dict[str, Any]:
        """
        Retrieve ML prediction result by flow_id.
        Strictly conforms to contracts/ml-prediction-schema.json.
        """
        prediction = pipeline.prediction_store.get(flow_id)
        if prediction is None:
            raise HTTPException(status_code=404, detail=f"ML prediction for flow_id '{flow_id}' not found.")
        return prediction

    @router.get("/stats")
    async def get_stats() -> dict[str, Any]:
        """Summary statistics of processed flows and detected threat alerts."""
        store_stats = pipeline.alert_store.stats()
        return {
            "total_flows_processed": pipeline.total_flows_processed,
            "total_alerts_stored": store_stats["total_alerts"],
            "by_threat_class": store_stats["by_threat_class"],
            "by_severity": store_stats["by_severity"],
        }

    @router.post("/ingest/flow")
    async def ingest_flow(flow: dict[str, Any]) -> dict[str, Any]:
        """
        Ingest a single network flow record into the detection and alerting pipeline.

        SECURITY BOUNDARY:
        This endpoint is strictly for local test, replay, and application ingestion.
        It operates purely in-memory and has NO connection, active probe, or return path
        to monitored network systems.
        """
        flow_id = flow.get("flow_id", "unknown")
        alerts = pipeline.process_flow(flow)
        return {
            "status": "accepted",
            "flow_id": flow_id,
            "alerts_generated": len(alerts),
            "alerts": alerts,
        }

    @router.websocket("/ws/alerts")
    async def websocket_alert_stream(websocket: WebSocket) -> None:
        """
        Live WebSocket stream delivering standardized threat alerts in real time.
        Subscribers receive alerts conforming to contracts/alert-schema.json.
        """
        if pipeline.stream_manager is None:
            await websocket.close(code=1011, reason="Stream manager not configured")
            return

        await websocket.accept()
        try:
            async for alert in pipeline.stream_manager.subscribe():
                await websocket.send_text(json.dumps(alert))
        except WebSocketDisconnect:
            logger.info("Alert stream client disconnected.")
        except Exception as exc:
            logger.warning("Error in alert stream client connection: %s", exc)

    return router
