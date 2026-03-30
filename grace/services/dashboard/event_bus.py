"""Async event bus for streaming events from PR resolver to dashboard."""

import asyncio
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Optional


@dataclass
class Event:
    type: str
    data: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_sse(self) -> str:
        payload = {"type": self.type, "timestamp": self.timestamp, **self.data}
        return f"data: {json.dumps(payload, default=str)}\n\n"


class EventBus:
    """Fan-out event bus: service emits, multiple SSE clients receive."""

    def __init__(self):
        self._subscribers: list[asyncio.Queue] = []
        self._recent: list[Event] = []  # Last 200 events for new subscribers
        self._max_recent = 200

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        # Send recent events to catch up
        for event in self._recent[-50:]:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                break
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        if q in self._subscribers:
            self._subscribers.remove(q)

    async def emit(self, event_type: str, **data: Any) -> None:
        event = Event(type=event_type, data=data)
        self._recent.append(event)
        if len(self._recent) > self._max_recent:
            self._recent = self._recent[-self._max_recent:]

        for q in self._subscribers:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass  # Drop if client is slow

    def get_recent(self, n: int = 50) -> list[Event]:
        return self._recent[-n:]

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)


# Global singleton
_bus: Optional[EventBus] = None


def get_event_bus() -> EventBus:
    global _bus
    if _bus is None:
        _bus = EventBus()
    return _bus
