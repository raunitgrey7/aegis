"""Request/response models for the API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    expires_in_minutes: int


class RawEvent(BaseModel):
    """A raw collector record. Either already-normalised fields, or a vendor shape + collector name."""

    collector: str | None = Field(default=None, description="windows|linux|zeek|dns|... (autodetected if omitted)")
    record: dict[str, Any] = Field(default_factory=dict)


class IngestRequest(BaseModel):
    collector: str | None = None
    events: list[dict[str, Any]] = Field(default_factory=list)
    correlate: bool = True


class IngestResponse(BaseModel):
    accepted: int
    deduplicated: int
    detections: int
    incidents_open: int


class CopilotRequest(BaseModel):
    question: str = Field(max_length=1000)


class StatusUpdate(BaseModel):
    status: str


class SimulateRequest(BaseModel):
    scenario: str = Field(description="A-H")
    correlate: bool = True
