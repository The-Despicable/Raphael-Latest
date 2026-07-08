"""
Async event bus for Raphael.
Per-subscriber bounded queues, dead-letter handling, livelock detection.
"""
import asyncio
import time
import logging
from dataclasses import dataclass, field
from typing import Callable, Awaitable

logger = logging.getLogger("events")


@dataclass
class Event:
    type: str
    data: dict
    ts: float = 0.0
    retries: int = 0


class DeadLetterQueue:
    def __init__(self, maxsize: int = 1000):
        self.queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=maxsize)

    async def put(self, event: Event):
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            logger.warning(f"Dead letter queue full, dropping event: {event.type}")

    def qsize(self) -> int:
        return self.queue.qsize()


class LivelockDetector:
    def __init__(self, threshold: int = 50, window: float = 60.0):
        self.threshold = threshold
        self.window = window
        self._events: list[tuple[float, str]] = []
        self._last_state_hash: int = 0

    def record(self, event_type: str, state_hash: int = 0):
        now = time.time()
        self._events.append((now, event_type))
        cutoff = now - self.window
        self._events = [(t, e) for t, e in self._events if t > cutoff]

        if len(self._events) > self.threshold and state_hash == self._last_state_hash:
            return True
        self._last_state_hash = state_hash
        return False


class EventBus:
    def __init__(self, max_queue_size: int = 1000):
        self._subscribers: dict[str, list[dict]] = {}
        self._dead_letter = DeadLetterQueue()
        self._livelock = LivelockDetector()
        self._max_retries = 3

    def subscribe(self, topic: str, cb: Callable[[Event], Awaitable[None]], name: str = ""):
        if topic not in self._subscribers:
            self._subscribers[topic] = []
        self._subscribers[topic].append({
            "cb": cb,
            "name": name or f"sub_{len(self._subscribers[topic])}",
            "queue": asyncio.Queue(maxsize=1000),
        })

    def unsubscribe(self, topic: str, cb: Callable = None, name: str = ""):
        if topic not in self._subscribers:
            return
        if cb:
            self._subscribers[topic] = [
                s for s in self._subscribers[topic] if s["cb"] != cb
            ]
        elif name:
            self._subscribers[topic] = [
                s for s in self._subscribers[topic] if s["name"] != name
            ]

    async def publish(self, topic: str, event_type: str, data: dict):
        event = Event(type=event_type, data=data, ts=time.time())
        if topic not in self._subscribers or not self._subscribers[topic]:
            return

        if self._livelock.record(event_type):
            logger.warning(f"Livelock detected on topic '{topic}' ({event_type})")

        for sub in self._subscribers[topic]:
            try:
                sub["queue"].put_nowait(event)
            except asyncio.QueueFull:
                logger.warning(f"Queue full for subscriber '{sub['name']}' on '{topic}', sending to DLQ")
                dlq_event = Event(type=event_type, data=data, ts=time.time(), retries=1)
                await self._dead_letter.put(dlq_event)

    async def _process_subscriber(self, topic: str, sub: dict):
        queue = sub["queue"]
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            try:
                await sub["cb"](event)
            except Exception as e:
                logger.error(f"Subscriber '{sub['name']}' failed on {event.type}: {e}")
                if event.retries < self._max_retries:
                    event.retries += 1
                    await queue.put(event)
                else:
                    await self._dead_letter.put(event)

    def start(self):
        for topic, subs in self._subscribers.items():
            for sub in subs:
                asyncio.create_task(self._process_subscriber(topic, sub))

    def dead_letter_count(self) -> int:
        return self._dead_letter.qsize()

    def livelock_detected(self) -> bool:
        return self._livelock.record("__check__") if False else False


event_bus = EventBus()
