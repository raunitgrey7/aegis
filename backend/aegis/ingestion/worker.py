"""Streaming detection worker.

Consumes normalized events from the Redis Streams consumer group, runs them through a shared Platform,
and periodically correlates. Multiple workers can run against the same group to share load
(at-least-once delivery with explicit acks). Falls back to a no-op if no Redis is configured.

    python -m aegis.ingestion.worker           # runs against AEGIS_REDIS_URL
"""

from __future__ import annotations

import logging
import signal
import time

from aegis.config import get_settings
from aegis.ingestion.bus import RedisStreamBus
from aegis.pipeline import Platform

log = logging.getLogger("aegis.worker")


class Worker:
    def __init__(self, consumer_name: str = "worker-1", correlate_every: float = 5.0):
        self.settings = get_settings()
        if not self.settings.redis_url:
            raise SystemExit("AEGIS_REDIS_URL is not set — the worker needs Redis Streams")
        self.bus = RedisStreamBus(self.settings.redis_url, self.settings.event_stream, self.settings.consumer_group)
        self.platform = Platform()
        self.consumer = consumer_name
        self.correlate_every = correlate_every
        self._running = True
        self._last_correlate = time.monotonic()

    def stop(self, *_):
        log.info("shutdown requested")
        self._running = False

    def run(self) -> None:
        signal.signal(signal.SIGINT, self.stop)
        signal.signal(signal.SIGTERM, self.stop)
        log.info("worker %s consuming from %s/%s", self.consumer, self.settings.event_stream, self.settings.consumer_group)
        processed = 0
        while self._running:
            got = 0
            for mid, event in self.bus.consume(self.consumer, block_ms=1000, count=200):
                self.platform.ingest(event)
                self.bus.ack(mid)
                got += 1
                processed += 1
            now = time.monotonic()
            if now - self._last_correlate >= self.correlate_every:
                incidents = self.platform.correlate()
                self._last_correlate = now
                if got:
                    log.info("processed=%d depth=%d incidents=%d", processed, self.bus.depth(), len(incidents))
        self.platform.correlate(force=True)
        log.info("worker stopped, %d events processed, %d incidents", processed, len(self.platform.incidents))


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    Worker().run()


if __name__ == "__main__":
    main()
