import asyncio
import time
from typing import Callable


class EventBus:
    def __init__(self):
        self._subscribers: list[Callable] = []

    def subscribe(self, cb: Callable):
        self._subscribers.append(cb)

    def unsubscribe(self, cb: Callable):
        self._subscribers = [s for s in self._subscribers if s != cb]

    async def emit(self, event: str, data: dict):
        for cb in self._subscribers:
            try:
                await cb({"type": event, "data": data, "ts": time.time()})
            except Exception:
                pass

    def emit_sync(self, event: str, data: dict):
        for cb in self._subscribers:
            try:
                cb({"type": event, "data": data, "ts": time.time()})
            except Exception:
                pass


event_bus = EventBus()
