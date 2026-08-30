"""The analyst-facing investigation report object."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class EvidenceItem(BaseModel):
    time: str
    event_id: str
    summary: str
    phase: str | None = None
    techniques: list[str] = Field(default_factory=list)


class AgentFinding(BaseModel):
    agent: str
    headline: str
    detail: str
    confidence: float
    evidence_event_ids: list[str] = Field(default_factory=list)


class InvestigationReport(BaseModel):
    incident_id: str
    title: str
    severity: str
    risk_score: float
    confidence: float
    generated_at: datetime
    llm_used: bool
    model: str | None = None
    summary: str
    attack_narrative: str
    affected_users: list[str] = Field(default_factory=list)
    affected_hosts: list[str] = Field(default_factory=list)
    external_ips: list[str] = Field(default_factory=list)
    phases_present: list[str] = Field(default_factory=list)
    techniques: list[dict] = Field(default_factory=list)
    timeline: list[EvidenceItem] = Field(default_factory=list)
    agent_findings: list[AgentFinding] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    injection_warnings: list[dict] = Field(default_factory=list)
    grounding: dict = Field(default_factory=dict)
