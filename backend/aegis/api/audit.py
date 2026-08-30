"""Append-only, hash-chained audit log.

Each entry references the previous entry's hash, so tampering with any record breaks the chain and is
detectable via ``verify()``. This is the platform holding *itself* to the evidentiary standard it
demands of the systems it monitors.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections import deque
from datetime import UTC, datetime
from typing import Any

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, maxlen: int = 50_000):
        self._entries: deque[dict] = deque(maxlen=maxlen)
        self._last_hash = GENESIS
        self._lock = threading.Lock()

    def record(self, actor: str, action: str, target: str = "", outcome: str = "success", **meta: Any) -> dict:
        with self._lock:
            entry = {
                "seq": len(self._entries),
                "timestamp": datetime.now(UTC).isoformat(),
                "actor": actor,
                "action": action,
                "target": target,
                "outcome": outcome,
                "meta": meta,
                "prev_hash": self._last_hash,
            }
            entry["hash"] = self._hash(entry)
            self._last_hash = entry["hash"]
            self._entries.append(entry)
            return entry

    @staticmethod
    def _hash(entry: dict) -> str:
        payload = json.dumps({k: entry[k] for k in entry if k != "hash"}, sort_keys=True, default=str)
        return hashlib.sha256(payload.encode()).hexdigest()

    def verify(self) -> dict:
        prev = GENESIS
        for e in self._entries:
            if e["prev_hash"] != prev or e["hash"] != self._hash(e):
                return {"valid": False, "broken_at": e["seq"]}
            prev = e["hash"]
        return {"valid": True, "entries": len(self._entries), "head": self._last_hash}

    def tail(self, n: int = 100) -> list[dict]:
        return list(self._entries)[-n:]
