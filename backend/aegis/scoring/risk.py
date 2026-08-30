"""Explainable risk scoring for incidents.

    risk = noisy-OR(detection scores)          -- independent evidence compounds, never exceeds 100
         + chain bonus (distinct kill-chain phases)
         + threat-intel bonus
         + asset-criticality bonus
         + breadth bonus (multiple hosts / users)
    capped at 100. Every term is returned in ``breakdown`` so the UI can show *why* it's a 91.
"""

from __future__ import annotations

from aegis.schemas.detections import Detection, DetectionKind
from aegis.schemas.events import Severity

CRITICAL_HOST_PREFIXES = ("DC-", "DB-", "FS-", "API-", "PRD-", "SRV-", "ERP-")
CRITICAL_USER_PREFIXES = ("adm-", "da-", "administrator", "svc-backup", "svc-sql")

PHASE_WEIGHT = {
    "initial_access": 4,
    "execution": 4,
    "persistence": 5,
    "privilege_escalation": 6,
    "defense_evasion": 5,
    "credential_access": 6,
    "discovery": 3,
    "lateral_movement": 7,
    "collection": 5,
    "command_and_control": 6,
    "exfiltration": 9,
    "impact": 10,
}


def _noisy_or(scores: list[float]) -> float:
    p_clean = 1.0
    for s in scores:
        p_clean *= 1.0 - min(max(s, 0.0), 100.0) / 100.0
    return 100.0 * (1.0 - p_clean)


def score_incident(
    detections: list[Detection],
    phases: list[str],
    hosts: list[str],
    users: list[str],
) -> tuple[float, float, Severity, dict[str, float]]:
    if not detections:
        return 0.0, 0.0, Severity.INFO, {}
    # weight each detection by its confidence to dampen speculative anomalies
    weighted = [d.score * (0.6 + 0.4 * d.confidence) for d in detections]
    base = _noisy_or(weighted)

    distinct_phases = sorted(set(phases))
    chain_bonus = 0.0
    if len(distinct_phases) >= 2:
        chain_bonus = sum(PHASE_WEIGHT.get(p, 3) for p in distinct_phases) * 0.6
    chain_bonus = min(chain_bonus, 25.0)

    ti_hits = [d for d in detections if d.kind == DetectionKind.THREAT_INTEL]
    ti_bonus = min(12.0, 6.0 * len(ti_hits)) if ti_hits else 0.0

    asset_bonus = 0.0
    if any(h.upper().startswith(CRITICAL_HOST_PREFIXES) for h in hosts):
        asset_bonus += 8.0
    if any(u.lower().startswith(CRITICAL_USER_PREFIXES) for u in users):
        asset_bonus += 6.0

    breadth_bonus = min(10.0, 3.0 * (len(hosts) - 1)) if len(hosts) > 1 else 0.0

    raw = base + chain_bonus + ti_bonus + asset_bonus + breadth_bonus
    risk = round(min(100.0, raw), 1)

    # confidence: evidence diversity (kinds), number of independent detections and their own confidence
    kinds = {d.kind for d in detections}
    mean_conf = sum(d.confidence for d in detections) / len(detections)
    diversity = min(1.0, 0.55 + 0.15 * len(kinds))
    volume = min(1.0, 0.6 + 0.1 * len(detections))
    confidence = round(min(0.99, mean_conf * diversity * volume + (0.05 if ti_hits else 0.0)), 2)

    if risk >= 85:
        sev = Severity.CRITICAL
    elif risk >= 65:
        sev = Severity.HIGH
    elif risk >= 40:
        sev = Severity.MEDIUM
    elif risk >= 20:
        sev = Severity.LOW
    else:
        sev = Severity.INFO

    breakdown = {
        "detections_noisy_or": round(base, 1),
        "kill_chain_bonus": round(chain_bonus, 1),
        "threat_intel_bonus": round(ti_bonus, 1),
        "asset_criticality_bonus": round(asset_bonus, 1),
        "breadth_bonus": round(breadth_bonus, 1),
        "raw_total": round(raw, 1),
        "capped": risk,
    }
    return risk, confidence, sev, breakdown
