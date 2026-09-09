"""
unithreat.api
=============

REST and streaming API layer for UniThreat AI.
"""

from unithreat.api.app import create_app
from unithreat.api.routes import create_router
from unithreat.api.stream import AlertStreamManager

__all__ = [
    "AlertStreamManager",
    "create_app",
    "create_router",
]
