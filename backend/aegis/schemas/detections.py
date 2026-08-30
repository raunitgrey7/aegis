"""Detection objects emitted by the rule, statistical, behavioural and threat-intel engines."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from aegis.schemas.events import Severity


class DetectionKind(StrEnum):
    RULE = "rule"
    THRESHOLD = "threshold"
    SEQUENCE = "sequence"
    ANOMALY = "anomaly"
    THREAT_INTEL = "threat_intel"


class Detection(BaseModel):
    detection_id: str = Field(default_factory=lambda: f"det_{uuid.uuid4().hex[:10]}")
    tenant_id: str = "default"
    kind: DetectionKind
    rule_id: str
    title: str
    description: str = ""
    severity: Severity
    score: float = Field(ge=0, le=100, description="Contribution to incident risk")
    confidence: float = Field(ge=0, le=1, default=0.8)
    techniques: list[str] = Field(default_factory=list, description="MITRE ATT&CK technique IDs")
    phase: str | None = Field(default=None, description="Kill-chain phase label")
    timestamp: datetime
    entities: dict[str, str] = Field(default_factory=dict, description="user/host/ip/domain/process")
    evidence_event_ids: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)

    def entity_keys(self) -> set[str]:
        keys: set[str] = set()
        for k, v in self.entities.items():
            if not v:
                continue
            if k == "user":
                keys.add(f"user:{v.lower()}")
            elif k == "host":
                keys.add(f"host:{v.upper()}")
            elif k in ("ip", "dst_ip"):
                keys.add(f"ip:{v}")
            elif k == "session":
                keys.add(f"session:{v}")
        return keys
