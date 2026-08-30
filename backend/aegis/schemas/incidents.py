"""Incidents, attack graphs and kill-chain phases."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from aegis.schemas.detections import Detection
from aegis.schemas.events import Severity


class KillChainPhase(StrEnum):
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


PHASE_ORDER: list[KillChainPhase] = list(KillChainPhase)
PHASE_LABEL: dict[str, str] = {
    p.value: p.value.replace("_", " ").title().replace("And", "&") for p in KillChainPhase
}


class IncidentStatus(StrEnum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class GraphNode(BaseModel):
    id: str
    type: str  # user | host | process | file | ip | domain | ioc | service
    label: str
    layer: int = 0
    risk: float = 0.0
    attributes: dict[str, Any] = Field(default_factory=dict)
    evidence_event_ids: list[str] = Field(default_factory=list)


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    relation: str  # logged_into | executed | spawned | connected_to | resolved | wrote | known_as ...
    timestamp: datetime | None = None
    phase: str | None = None
    techniques: list[str] = Field(default_factory=list)
    evidence_event_ids: list[str] = Field(default_factory=list)


class AttackGraph(BaseModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)


class PhaseEvidence(BaseModel):
    phase: str
    label: str
    present: bool
    techniques: list[str] = Field(default_factory=list)
    detection_ids: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None


class Incident(BaseModel):
    incident_id: str = Field(default_factory=lambda: f"SEC-{uuid.uuid4().int % 10000:04d}")
    tenant_id: str = "default"
    title: str
    status: IncidentStatus = IncidentStatus.OPEN
    severity: Severity
    risk_score: float = Field(ge=0, le=100)
    confidence: float = Field(ge=0, le=1)
    created_at: datetime
    first_event_at: datetime
    last_event_at: datetime
    affected_users: list[str] = Field(default_factory=list)
    affected_hosts: list[str] = Field(default_factory=list)
    external_ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    phases: list[PhaseEvidence] = Field(default_factory=list)
    detections: list[Detection] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    graph: AttackGraph = Field(default_factory=AttackGraph)
    score_breakdown: dict[str, float] = Field(default_factory=dict)
    summary: str = ""
    tags: list[str] = Field(default_factory=list)

    @property
    def present_phases(self) -> list[str]:
        return [p.phase for p in self.phases if p.present]
