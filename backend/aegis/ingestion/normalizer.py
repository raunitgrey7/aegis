"""Normalisers: raw collector records -> ``SecurityEvent``.

Each collector format has a small adapter. Unknown shapes fall back to a best-effort field mapper.
Every adapter *keeps the raw record* so nothing is lost for forensics.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from aegis.schemas.events import EventType, SecurityEvent, Severity, SourceType

# ------------------------------------------------------------------ Windows Security / Sysmon
WIN_EVENT_MAP: dict[int, tuple[EventType, str]] = {
    4624: (EventType.AUTHENTICATION, "login_success"),
    4625: (EventType.AUTHENTICATION, "login_failure"),
    4634: (EventType.AUTHENTICATION, "logoff"),
    4648: (EventType.AUTHENTICATION, "explicit_credentials"),
    4672: (EventType.PRIVILEGE_CHANGE, "special_privileges_assigned"),
    4688: (EventType.PROCESS_START, "start"),
    4689: (EventType.PROCESS_END, "end"),
    4720: (EventType.USER_CREATED, "created"),
    4726: (EventType.USER_DELETED, "deleted"),
    4728: (EventType.GROUP_CHANGE, "member_added"),
    4732: (EventType.GROUP_CHANGE, "member_added"),
    4756: (EventType.GROUP_CHANGE, "member_added"),
    4698: (EventType.SCHEDULED_TASK, "created"),
    7045: (EventType.SERVICE_STARTED, "installed"),
    1102: (EventType.SECURITY_ALERT, "audit_log_cleared"),  # v2.2: make matchable by a rule
    4662: (EventType.SECURITY_ALERT, "directory_object_access"),  # v2.2: LSA secrets / DCSync
    # Sysmon
    1: (EventType.PROCESS_START, "start"),
    3: (EventType.NETWORK_CONNECTION, "connect"),
    8: (EventType.PROCESS_ACCESS, "remote_thread"),        # v2.2: CreateRemoteThread (process injection)
    10: (EventType.PROCESS_ACCESS, "process_access"),      # v2.1: LSASS access / cred dumping signal
    11: (EventType.FILE_CREATE, "create"),
    12: (EventType.REGISTRY_CHANGE, "key_change"),         # v2.1: registry key create/delete (persistence)
    13: (EventType.REGISTRY_CHANGE, "set_value"),
    22: (EventType.DNS_QUERY, "query"),
    # Windows Filtering Platform network (real EDR emits these, not Sysmon 3)  -- v2.1
    5156: (EventType.NETWORK_CONNECTION, "connect"),
    5158: (EventType.NETWORK_CONNECTION, "bind"),
    # PowerShell logging: script block / module / pipeline carry the payload rules look for  -- v2.1
    4104: (EventType.PROCESS_START, "script_block"),
    4103: (EventType.PROCESS_START, "script_block"),
    800: (EventType.PROCESS_START, "script_block"),
    4663: (EventType.FILE_READ, "object_access"),          # v2.1: handle access (NTDS.dit / SAM reads)
}

# Sysmon-10 GrantedAccess masks that indicate credential theft intent against LSASS.
LSASS_ACCESS_MASKS = {"0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff", "0x1f1fff", "0x1f3fff"}
POWERSHELL_EIDS = {800, 4103, 4104}

LOGON_TYPE = {2: "interactive", 3: "network", 4: "batch", 5: "service", 7: "unlock", 8: "network_cleartext", 9: "new_credentials", 10: "rdp", 11: "cached"}


def _ts(v: Any) -> datetime:
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=UTC)
    if isinstance(v, int | float):
        return datetime.fromtimestamp(v, tz=UTC)
    if isinstance(v, str):
        s = v.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(s)
        except ValueError:
            pass
    return datetime.now(tz=UTC)


def _windows(rec: dict[str, Any], tenant: str) -> SecurityEvent:
    try:
        eid = int(rec.get("EventID") or rec.get("event_id_win") or rec.get("id") or 0)
    except (TypeError, ValueError):
        eid = 0
    et, action = WIN_EVENT_MAP.get(eid, (EventType.SYSTEM_LOG, f"win_{eid}"))
    data = rec.get("EventData") or rec
    logon_type = data.get("LogonType")
    # Accept the field names used by Winlogbeat/NXLog exports and the OTRF "Mordor" security datasets
    # (flat records: Hostname / @timestamp / EventTime / UtcTime) as well as raw Windows XML-to-JSON shapes.
    ts_raw = (
        rec.get("TimeCreated") or rec.get("timestamp") or rec.get("@timestamp") or rec.get("EventTime")
        or data.get("UtcTime") or rec.get("SystemTime")
    )
    # --- field extraction with real-EDR fallbacks (Sysmon 10/5156/PowerShell/registry) -- v2.1 ---
    process_name = _basename(
        data.get("NewProcessName") or data.get("Image") or data.get("SourceImage")
        or data.get("Application") or data.get("ProcessName")
    )
    command_line = data.get("CommandLine")
    if eid in POWERSHELL_EIDS:
        # script-block / pipeline events carry the payload the execution rules look for
        process_name = process_name or "powershell.exe"
        command_line = (
            data.get("ScriptBlockText") or data.get("Payload") or data.get("CommandLine")
            or data.get("ContextInfo") or data.get("Message")
        )
    file_path = (
        data.get("TargetFilename") or data.get("TargetObject") or data.get("TargetImage")
        or data.get("ObjectName") or data.get("NewProcessName") or data.get("Image")
    )
    dst_ip = data.get("DestinationIp") or data.get("DestAddress")
    tags: list[str] = []
    target_lower = (data.get("TargetImage") or "").lower()
    if eid == 10 and target_lower.endswith("lsass.exe"):
        # surface the credential-theft intent so a rule can match on it
        mask = str(data.get("GrantedAccess") or "").lower()
        tags = ["lsass_access"] + (["suspicious_access"] if mask in LSASS_ACCESS_MASKS else [])
    if eid == 8:  # CreateRemoteThread -- process injection (v2.2)
        tags = ["remote_thread"] + (["lsass_inject"] if target_lower.endswith("lsass.exe") else [])

    return SecurityEvent(
        tenant_id=tenant,
        timestamp=_ts(ts_raw),
        source=SourceType.WINDOWS,
        event_type=et,
        action=action,
        outcome="success" if eid in (4624, 4688, 4720) else ("failure" if eid == 4625 else None),
        host=rec.get("Computer") or rec.get("Hostname") or rec.get("host") or rec.get("hostname"),
        user=data.get("TargetUserName") or data.get("SubjectUserName") or data.get("User"),
        session_id=str(data.get("TargetLogonId") or data.get("LogonId") or "") or None,
        process_name=process_name,
        process_id=_int(data.get("NewProcessId") or data.get("ProcessId")),
        parent_process_name=_basename(data.get("ParentProcessName") or data.get("ParentImage")),
        command_line=command_line,
        file_path=file_path,
        file_hash=_hash(data.get("Hashes")),
        src_ip=data.get("IpAddress") or data.get("SourceIp") or data.get("SourceAddress"),
        src_port=_int(data.get("IpPort") or data.get("SourcePort")),
        dst_ip=dst_ip,
        dst_port=_int(data.get("DestinationPort") or data.get("DestPort")),
        protocol=data.get("Protocol") or (data.get("AuthenticationPackageName") or "").lower() or None,
        domain=data.get("QueryName"),
        privilege=LOGON_TYPE.get(_int(logon_type) or -1) if logon_type is not None else data.get("PrivilegeList") or data.get("TargetGroup") or data.get("GroupName"),
        target_user=data.get("MemberName") or (data.get("TargetUserName") if eid in (4720, 4726) else None),
        service_name=data.get("ServiceName") or data.get("TaskName"),
        message=rec.get("Message"),
        severity_hint=Severity.INFO,
        tags=tags,
        raw=rec,
    )


def _linux(rec: dict[str, Any], tenant: str) -> SecurityEvent:
    kind = (rec.get("type") or rec.get("event_type") or "").lower()
    et = EventType.SYSTEM_LOG
    action = rec.get("action") or kind or "log"
    if kind in ("user_login", "user_auth", "cred_acq", "sshd_login"):
        et = EventType.AUTHENTICATION
        action = "login_success" if str(rec.get("res", rec.get("result", "success"))).lower() in ("success", "1") else "login_failure"
    elif kind in ("execve", "syscall", "proctitle", "process"):
        et = EventType.PROCESS_START
        action = "start"
    elif kind in ("path", "file"):
        et = EventType.FILE_MODIFY
        action = "modify"
    elif kind in ("sockaddr", "connect", "network"):
        et = EventType.NETWORK_CONNECTION
        action = "connect"
    elif kind in ("user_cmd", "sudo"):
        et = EventType.PRIVILEGE_CHANGE
        action = "sudo_success" if str(rec.get("res", "success")).lower() in ("success", "1") else "sudo_failure"
    return SecurityEvent(
        tenant_id=tenant,
        timestamp=_ts(rec.get("timestamp") or rec.get("time")),
        source=SourceType.LINUX,
        event_type=et,
        action=action,
        host=rec.get("hostname") or rec.get("host"),
        user=rec.get("acct") or rec.get("auid_name") or rec.get("user"),
        process_name=_basename(rec.get("exe") or rec.get("comm")),
        process_id=_int(rec.get("pid")),
        parent_process_id=_int(rec.get("ppid")),
        command_line=rec.get("proctitle") or rec.get("cmd") or rec.get("command_line"),
        file_path=rec.get("name") or rec.get("path"),
        src_ip=rec.get("addr") or rec.get("src_ip"),
        dst_ip=rec.get("dst_ip"),
        dst_port=_int(rec.get("dst_port")),
        privilege="root" if str(rec.get("uid", "")) in ("0", "root") or kind in ("user_cmd", "sudo") else rec.get("privilege"),
        message=rec.get("msg") or rec.get("message"),
        raw=rec,
    )


def _zeek_conn(rec: dict[str, Any], tenant: str) -> SecurityEvent:
    return SecurityEvent(
        tenant_id=tenant,
        timestamp=_ts(rec.get("ts") or rec.get("timestamp")),
        source=SourceType.NETWORK,
        event_type=EventType.NETWORK_CONNECTION,
        action="connect",
        outcome="success" if rec.get("conn_state", "SF") in ("SF", "S1", "S2", "S3", "RSTO") else "failure",
        host=rec.get("host") or rec.get("orig_host"),
        src_ip=rec.get("id.orig_h") or rec.get("src_ip"),
        src_port=_int(rec.get("id.orig_p") or rec.get("src_port")),
        dst_ip=rec.get("id.resp_h") or rec.get("dst_ip"),
        dst_port=_int(rec.get("id.resp_p") or rec.get("dst_port")),
        protocol=rec.get("proto") or rec.get("service"),
        bytes_out=_int(rec.get("orig_bytes") or rec.get("bytes_out")),
        bytes_in=_int(rec.get("resp_bytes") or rec.get("bytes_in")),
        raw=rec,
    )


def _dns(rec: dict[str, Any], tenant: str) -> SecurityEvent:
    rcode = str(rec.get("rcode_name") or rec.get("rcode") or rec.get("outcome") or "NOERROR").upper()
    return SecurityEvent(
        tenant_id=tenant,
        timestamp=_ts(rec.get("ts") or rec.get("timestamp")),
        source=SourceType.DNS,
        event_type=EventType.DNS_QUERY,
        action="query",
        outcome="nxdomain" if rcode in ("NXDOMAIN", "3", "FAILURE") else "success",
        host=rec.get("host") or rec.get("client_host"),
        src_ip=rec.get("id.orig_h") or rec.get("client_ip") or rec.get("src_ip"),
        domain=rec.get("query") or rec.get("domain"),
        protocol=rec.get("qtype_name") or rec.get("qtype") or rec.get("record_type"),
        dst_ip=(rec.get("answers") or [None])[0] if isinstance(rec.get("answers"), list) else rec.get("answer"),
        raw=rec,
    )


def _generic(rec: dict[str, Any], tenant: str) -> SecurityEvent:
    """Best effort for records already close to the canonical schema."""
    data = {k: v for k, v in rec.items() if k in SecurityEvent.model_fields}
    data.setdefault("tenant_id", tenant)
    data.setdefault("source", rec.get("source", SourceType.APPLICATION))
    data.setdefault("event_type", rec.get("event_type", EventType.APPLICATION_LOG))
    data.setdefault("action", rec.get("action", "log"))
    if "timestamp" in data:
        data["timestamp"] = _ts(data["timestamp"])
    data.setdefault("raw", {k: v for k, v in rec.items() if k not in SecurityEvent.model_fields})
    return SecurityEvent(**data)


ADAPTERS = {
    "windows": _windows,
    "sysmon": _windows,
    "linux": _linux,
    "auditd": _linux,
    "zeek": _zeek_conn,
    "zeek_conn": _zeek_conn,
    "netflow": _zeek_conn,
    "dns": _dns,
    "zeek_dns": _dns,
}


def normalize(rec: dict[str, Any], collector: str | None = None, tenant: str = "default") -> SecurityEvent:
    fmt = (collector or rec.get("collector") or rec.get("format") or "").lower()
    if fmt in ADAPTERS:
        return ADAPTERS[fmt](rec, tenant)
    if "EventID" in rec or "Computer" in rec:
        return _windows(rec, tenant)
    if "id.orig_h" in rec and "query" in rec:
        return _dns(rec, tenant)
    if "id.orig_h" in rec:
        return _zeek_conn(rec, tenant)
    if "auid" in rec or "proctitle" in rec or "acct" in rec:
        return _linux(rec, tenant)
    return _generic(rec, tenant)


def normalize_batch(records: list[dict[str, Any]], collector: str | None = None, tenant: str = "default") -> list[SecurityEvent]:
    return [normalize(r, collector, tenant) for r in records]


# ------------------------------------------------------------------ helpers
def _basename(p: Any) -> str | None:
    if not p:
        return None
    s = str(p)
    return s.replace("\\", "/").rsplit("/", 1)[-1] or None


def _int(v: Any) -> int | None:
    if v is None or v == "":
        return None
    try:
        return int(str(v), 0) if isinstance(v, str) and v.lower().startswith("0x") else int(v)
    except (TypeError, ValueError):
        return None


def _hash(v: Any) -> str | None:
    if not v:
        return None
    s = str(v)
    for part in s.split(","):
        if part.upper().startswith("SHA256="):
            return part.split("=", 1)[1].lower()
    return s.split("=")[-1].lower() if "=" in s else s.lower()
