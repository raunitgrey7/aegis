"""The normalised security-event schema.

Every collector (Windows Event Log, auditd, Zeek, DNS, cloud audit, EDR) is mapped onto this one
shape by ``aegis.ingestion.normalizer``. Downstream engines only ever see ``SecurityEvent``.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SourceType(StrEnum):
    WINDOWS = "windows"
    LINUX = "linux"
    NETWORK = "network"
    DNS = "dns"
    CLOUD = "cloud"
    APPLICATION = "application"
    EDR = "edr"
    IDENTITY = "identity"
    SIMULATOR = "simulator"


class EventType(StrEnum):
    AUTHENTICATION = "authentication"
    PROCESS_START = "process_start"
    PROCESS_END = "process_end"
    FILE_CREATE = "file_create"
    FILE_MODIFY = "file_modify"
    FILE_DELETE = "file_delete"
    FILE_READ = "file_read"
    NETWORK_CONNECTION = "network_connection"
    DNS_QUERY = "dns_query"
    PRIVILEGE_CHANGE = "privilege_change"
    USER_CREATED = "user_created"
    USER_DELETED = "user_deleted"
    GROUP_CHANGE = "group_change"
    SERVICE_STARTED = "service_started"
    SERVICE_STOPPED = "service_stopped"
    SCHEDULED_TASK = "scheduled_task"
    REGISTRY_CHANGE = "registry_change"
    PROCESS_ACCESS = "process_access"
    SECURITY_ALERT = "security_alert"
    APPLICATION_LOG = "application_log"
    SYSTEM_LOG = "system_log"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.INFO: 0.0,
    Severity.LOW: 10.0,
    Severity.MEDIUM: 25.0,
    Severity.HIGH: 45.0,
    Severity.CRITICAL: 70.0,
}


def _now() -> datetime:
    return datetime.now(tz=UTC)


class SecurityEvent(BaseModel):
    """One normalised telemetry record.

    All string fields are treated as *untrusted* — they may contain attacker-controlled content
    (command lines, file names, DNS labels). Nothing here is ever interpolated into a prompt
    without passing through ``aegis.llm.guard``.
    """

    model_config = ConfigDict(str_max_length=8192, extra="forbid")

    event_id: str = Field(default_factory=lambda: f"evt_{uuid.uuid4().hex[:12]}")
    tenant_id: str = "default"
    timestamp: datetime = Field(default_factory=_now)
    source: SourceType
    event_type: EventType
    action: str = Field(description="Verb-like action, e.g. login_success, login_failure, connect, create")
    outcome: str | None = Field(default=None, description="success | failure | blocked | unknown")

    # --- entities ---
    host: str | None = None
    user: str | None = None
    session_id: str | None = None
    process_name: str | None = None
    process_id: int | None = None
    parent_process_name: str | None = None
    parent_process_id: int | None = None
    command_line: str | None = None
    file_path: str | None = None
    file_hash: str | None = None
    file_size: int | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    domain: str | None = None
    url: str | None = None
    bytes_in: int | None = None
    bytes_out: int | None = None
    geo_country: str | None = None
    privilege: str | None = None
    target_user: str | None = None
    service_name: str | None = None
    message: str | None = None
    severity_hint: Severity = Severity.INFO
    tags: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict, description="Original record for forensics")

    @field_validator("timestamp")
    @classmethod
    def _tz_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=UTC)
        return v

    @field_validator("tags")
    @classmethod
    def _limit_tags(cls, v: list[str]) -> list[str]:
        return v[:32]

    # ---- helpers --------------------------------------------------------------------------------
    def entity_keys(self) -> set[str]:
        """Entity identifiers used by the correlation engine to cluster related activity."""
        keys: set[str] = set()
        if self.user:
            keys.add(f"user:{self.user.lower()}")
        if self.host:
            keys.add(f"host:{self.host.upper()}")
        if self.session_id:
            keys.add(f"session:{self.session_id}")
        if self.dst_ip and not self.dst_ip.startswith(("10.", "192.168.", "172.16.")):
            keys.add(f"ip:{self.dst_ip}")
        return keys

    def fingerprint(self) -> str:
        """Stable dedup key across re-ingestion of the same record."""
        payload = "|".join(
            str(x)
            for x in (
                self.tenant_id,
                self.timestamp.isoformat(),
                self.source,
                self.event_type,
                self.action,
                self.host,
                self.user,
                self.process_name,
                self.command_line,
                self.dst_ip,
                self.domain,
                self.file_path,
            )
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:24]

    def short(self) -> str:
        """Compact single-line rendering used in reports and prompts."""
        parts = [self.timestamp.strftime("%H:%M:%S"), self.event_type.value, self.action]
        if self.user:
            parts.append(f"user={self.user}")
        if self.host:
            parts.append(f"host={self.host}")
        if self.process_name:
            parts.append(f"proc={self.process_name}")
        if self.dst_ip:
            parts.append(f"dst={self.dst_ip}:{self.dst_port or ''}")
        if self.domain:
            parts.append(f"domain={self.domain}")
        if self.file_path:
            parts.append(f"file={self.file_path}")
        if self.bytes_out:
            parts.append(f"out={self.bytes_out}B")
        return " ".join(parts)
