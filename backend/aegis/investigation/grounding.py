"""Evidence-grounding validator.

Rule: every event ID an agent or the synthesizer cites must exist in the incident's evidence set, and
every factual claim in the narrative should be traceable. We can't parse arbitrary prose perfectly, so
we enforce the machine-checkable invariant — cited IDs must be real — and compute a grounding score the
UI displays. A fabricated ``evt_xxxx`` is dropped and lowers the score, which is exactly how you contain
a hallucinating or injection-steered model.
"""

from __future__ import annotations

import re

EVENT_ID_RE = re.compile(r"evt_[0-9a-f]{6,}")


def validate_ids(cited: list[str], valid: set[str]) -> tuple[list[str], list[str]]:
    good = [c for c in cited if c in valid]
    bad = [c for c in cited if c not in valid]
    return good, bad


def extract_cited_ids(text: str) -> list[str]:
    return EVENT_ID_RE.findall(text or "")


def grounding_score(narrative: str, findings_ids: list[str], valid_ids: set[str]) -> dict:
    cited = set(extract_cited_ids(narrative)) | set(findings_ids)
    real = cited & valid_ids
    fabricated = cited - valid_ids
    coverage = len(real) / len(valid_ids) if valid_ids else 0.0
    fidelity = len(real) / len(cited) if cited else 1.0
    return {
        "evidence_total": len(valid_ids),
        "evidence_cited": len(real),
        "fabricated_ids": sorted(fabricated),
        "coverage": round(coverage, 3),
        "fidelity": round(fidelity, 3),
        "grounded": len(fabricated) == 0,
    }
