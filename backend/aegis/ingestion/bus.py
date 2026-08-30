"""Event bus abstraction: Redis Streams in production, an in-memory queue for tests/dev.

Producers (collectors, the ingest API) publish JSON-encoded ``SecurityEvent``s; the detection worker
consumes them through a consumer group so multiple workers can share the load and acknowledge
processing (at-least-once semantics).
"""

from __future__ import annotations

import json
import queue
from collections.abc import Iterator
from typing import Protocol

from aegis.schemas.events import SecurityEvent


class EventBus(Protocol):
    def publish(self, event: SecurityEvent) -> str: ...
    def publish_many(self, events: list[SecurityEvent]) -> int: ...
    def consume(self, consumer: str, block_ms: int = 1000, count: int = 100) -> Iterator[tuple[str, SecurityEvent]]: ...
    def ack(self, message_id: str) -> None: ...
    def depth(self) -> int: ...


class InMemoryBus:
    def __init__(self) -> None:
        self.q: queue.Queue[tuple[str, SecurityEvent]] = queue.Queue()
        self._n = 0

    def publish(self, event: SecurityEvent) -> str:
        self._n += 1
        mid = f"mem-{self._n}"
        self.q.put((mid, event))
        return mid

    def publish_many(self, events: list[SecurityEvent]) -> int:
        for e in events:
            self.publish(e)
        return len(events)

    def consume(self, consumer: str, block_ms: int = 1000, count: int = 100) -> Iterator[tuple[str, SecurityEvent]]:
        for _ in range(count):
            try:
                yield self.q.get(timeout=block_ms / 1000.0)
            except queue.Empty:
                return

    def ack(self, message_id: str) -> None:
        return None

    def depth(self) -> int:
        return self.q.qsize()


class RedisStreamBus:
    def __init__(self, url: str, stream: str = "aegis:events", group: str = "aegis-detectors", maxlen: int = 1_000_000):
        import redis

        self.r = redis.Redis.from_url(url, decode_responses=True)
        self.stream = stream
        self.group = group
        self.maxlen = maxlen
        try:
            self.r.xgroup_create(self.stream, self.group, id="0", mkstream=True)
        except redis.ResponseError as exc:  # BUSYGROUP = already exists
            if "BUSYGROUP" not in str(exc):
                raise

    def publish(self, event: SecurityEvent) -> str:
        return self.r.xadd(self.stream, {"e": event.model_dump_json()}, maxlen=self.maxlen, approximate=True)

    def publish_many(self, events: list[SecurityEvent]) -> int:
        pipe = self.r.pipeline()
        for e in events:
            pipe.xadd(self.stream, {"e": e.model_dump_json()}, maxlen=self.maxlen, approximate=True)
        pipe.execute()
        return len(events)

    def consume(self, consumer: str, block_ms: int = 1000, count: int = 100) -> Iterator[tuple[str, SecurityEvent]]:
        resp = self.r.xreadgroup(self.group, consumer, {self.stream: ">"}, count=count, block=block_ms)
        for _stream, messages in resp or []:
            for mid, fields in messages:
                try:
                    yield mid, SecurityEvent.model_validate_json(fields["e"])
                except Exception:
                    # poison message: ack and drop, never block the stream
                    self.r.xack(self.stream, self.group, mid)

    def ack(self, message_id: str) -> None:
        self.r.xack(self.stream, self.group, message_id)

    def depth(self) -> int:
        return int(self.r.xlen(self.stream))

    def pending(self) -> int:
        info = self.r.xpending(self.stream, self.group)
        return int(info.get("pending", 0)) if isinstance(info, dict) else 0


def make_bus(redis_url: str | None, stream: str, group: str) -> EventBus:
    if redis_url:
        return RedisStreamBus(redis_url, stream, group)
    return InMemoryBus()


def encode(event: SecurityEvent) -> str:
    return event.model_dump_json()


def decode(payload: str) -> SecurityEvent:
    return SecurityEvent.model_validate(json.loads(payload))
