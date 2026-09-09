"""
unithreat.api.stream
====================

Live alert streaming manager over WebSockets.

Maintains bounded per-subscriber queues with drop-oldest policy to guarantee
slow subscribers cannot cause unbounded memory growth.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
import json
import logging
import threading
from typing import Any

logger = logging.getLogger(__name__)


class AlertStreamManager:
    """
    Manages live streaming subscribers and broadcasts standardized alerts.
    """

    def __init__(self, max_queue_size: int = 100) -> None:
        self.max_queue_size = max_queue_size
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
        self._lock = threading.Lock()

    def register(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        with self._lock:
            self._subscribers.add(queue)

    def unregister(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        with self._lock:
            self._subscribers.discard(queue)

    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)

    def broadcast(self, alert_dict: dict[str, Any]) -> int:
        """
        Broadcast an alert dictionary to all registered subscribers.
        If a subscriber's queue is full, evicts the oldest item (drop-oldest).
        """
        with self._lock:
            subscribers = list(self._subscribers)

        delivered = 0
        for queue in subscribers:
            if queue.full():
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            try:
                queue.put_nowait(dict(alert_dict))
                delivered += 1
            except asyncio.QueueFull:
                # Queue still full; skip to preserve server performance
                pass

        return delivered

    async def subscribe(self) -> AsyncIterator[dict[str, Any]]:
        """
        Async generator yielding newly broadcast alerts for a connected client.
        """
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=self.max_queue_size)
        self.register(queue)
        try:
            while True:
                alert = await queue.get()
                yield alert
                queue.task_done()
        finally:
            self.unregister(queue)
