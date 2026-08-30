"""A tiny, safe condition DSL used by YAML rules.

A condition is a mapping of ``field -> matcher``. A matcher is either a scalar (equality) or a
mapping of operators::

    process_name: powershell.exe                 # equality (case-insensitive for strings)
    process_name: {in: [powershell.exe, pwsh.exe]}
    command_line: {regex: "(?i)-enc\\s+[A-Za-z0-9+/=]{20,}"}
    dst_ip: {private: false}
    bytes_out: {gte: 50000000}
    file_path: {endswith: [".zip", ".7z", ".rar"]}
    user: {exists: true}
    domain: {entropy_gte: 3.8}

Regexes are compiled once and evaluated with a length cap to defuse ReDoS on hostile telemetry.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from collections.abc import Callable
from typing import Any

from aegis.schemas.events import SecurityEvent

MAX_REGEX_INPUT = 4096


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_private_ip(value: str | None) -> bool:
    if not value:
        return True
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return True
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved


def _norm(v: Any) -> Any:
    return v.lower() if isinstance(v, str) else v


class Matcher:
    """Compiled matcher for one field."""

    def __init__(self, field: str, spec: Any):
        self.field = field
        self.checks: list[Callable[[Any], bool]] = []
        if not isinstance(spec, dict):
            expected = _norm(spec)
            self.checks.append(lambda v, e=expected: _norm(v) == e)
            return
        for op, arg in spec.items():
            self.checks.append(self._build(op, arg))

    def _build(self, op: str, arg: Any) -> Callable[[Any], bool]:  # noqa: C901 - dispatch table
        if op == "eq":
            e = _norm(arg)
            return lambda v: _norm(v) == e
        if op == "neq":
            e = _norm(arg)
            return lambda v: _norm(v) != e
        if op == "in":
            s = {_norm(a) for a in arg}
            return lambda v: _norm(v) in s
        if op == "not_in":
            s = {_norm(a) for a in arg}
            return lambda v: v is not None and _norm(v) not in s
        if op == "regex":
            rx = re.compile(arg)
            return lambda v: v is not None and bool(rx.search(str(v)[:MAX_REGEX_INPUT]))
        if op == "contains":
            items = [_norm(a) for a in (arg if isinstance(arg, list) else [arg])]
            return lambda v: v is not None and any(i in _norm(str(v)) for i in items)
        if op == "startswith":
            items = tuple(_norm(a) for a in (arg if isinstance(arg, list) else [arg]))
            return lambda v: v is not None and _norm(str(v)).startswith(items)
        if op == "endswith":
            items = tuple(_norm(a) for a in (arg if isinstance(arg, list) else [arg]))
            return lambda v: v is not None and _norm(str(v)).endswith(items)
        if op == "gte":
            return lambda v: v is not None and float(v) >= float(arg)
        if op == "lte":
            return lambda v: v is not None and float(v) <= float(arg)
        if op == "gt":
            return lambda v: v is not None and float(v) > float(arg)
        if op == "lt":
            return lambda v: v is not None and float(v) < float(arg)
        if op == "exists":
            want = bool(arg)
            return lambda v: (v is not None and v != "") == want
        if op == "private":
            want = bool(arg)
            return lambda v: v is not None and is_private_ip(v) == want
        if op == "entropy_gte":
            thr = float(arg)
            return lambda v: v is not None and shannon_entropy(str(v).split(".")[0]) >= thr
        if op == "len_gte":
            n = int(arg)
            return lambda v: v is not None and len(str(v)) >= n
        raise ValueError(f"Unknown condition operator: {op}")

    def __call__(self, event: SecurityEvent) -> bool:
        value = getattr(event, self.field, None)
        if value is None and self.field in event.raw:
            value = event.raw.get(self.field)
        return all(check(value) for check in self.checks)


class Condition:
    """AND of field matchers, with optional ``any_of`` (OR) and ``not`` blocks."""

    def __init__(self, spec: dict[str, Any] | None):
        spec = dict(spec or {})
        self.any_of = [Condition(s) for s in spec.pop("any_of", [])]
        self.negate = Condition(spec.pop("not")) if "not" in spec else None
        self.matchers = [Matcher(field, m) for field, m in spec.items()]

    def __call__(self, event: SecurityEvent) -> bool:
        if not all(m(event) for m in self.matchers):
            return False
        if self.any_of and not any(c(event) for c in self.any_of):
            return False
        if self.negate is not None and self.negate(event):
            return False
        return True

    @property
    def is_empty(self) -> bool:
        return not self.matchers and not self.any_of and self.negate is None
