"""
unithreat.api.app
=================

FastAPI application factory for UniThreat AI.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from unithreat.alerts.pipeline import IntegratedPipeline
from unithreat.api.routes import create_router
from unithreat.api.stream import AlertStreamManager


def create_app(
    pipeline: IntegratedPipeline | None = None,
    stream_manager: AlertStreamManager | None = None,
) -> FastAPI:
    """
    Factory creating a FastAPI instance wired to the threat intelligence pipeline.
    """
    if stream_manager is None:
        stream_manager = AlertStreamManager()

    if pipeline is None:
        pipeline = IntegratedPipeline.with_default_models(stream_manager=stream_manager)
    elif pipeline.stream_manager is None:
        pipeline.stream_manager = stream_manager

    app = FastAPI(
        title="UniThreat AI — Threat Intelligence API",
        description="Local passive threat detection and real-time alert streaming API for UniThreat AI (SIH PS 26145).",
        version="0.1.0",
    )

    # CORS configuration for dashboard web applications
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.state.pipeline = pipeline
    router = create_router(pipeline)
    app.include_router(router)

    return app
