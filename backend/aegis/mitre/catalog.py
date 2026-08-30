"""MITRE ATT&CK technique catalogue and tactic-coverage computation."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from aegis.schemas.incidents import PHASE_LABEL, PHASE_ORDER, KillChainPhase


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str

    @property
    def url(self) -> str:
        base, _, sub = self.id.partition(".")
        return f"https://attack.mitre.org/techniques/{base}/{sub}/" if sub else f"https://attack.mitre.org/techniques/{base}/"

    @property
    def parent_id(self) -> str:
        return self.id.split(".")[0]


class MitreCatalog:
    def __init__(self, techniques: list[Technique]):
        self.by_id: dict[str, Technique] = {t.id: t for t in techniques}

    @classmethod
    def load(cls, path: Path) -> MitreCatalog:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return cls([Technique(t["id"], t["name"], t["tactic"]) for t in data["techniques"]])

    def get(self, tid: str) -> Technique | None:
        t = self.by_id.get(tid)
        if t is None and "." in tid:
            t = self.by_id.get(tid.split(".")[0])
        return t

    def describe(self, tid: str) -> str:
        t = self.get(tid)
        return f"{tid} {t.name}" if t else tid

    def tactic_for(self, tid: str) -> str | None:
        t = self.get(tid)
        return t.tactic if t else None

    def coverage(self, technique_ids: list[str]) -> list[dict]:
        """Tactic-level coverage for a set of observed techniques (for the ATT&CK bar chart)."""
        counts: Counter[str] = Counter()
        for tid in technique_ids:
            tac = self.tactic_for(tid)
            if tac:
                counts[tac] += 1
        return [
            {"tactic": p.value, "label": PHASE_LABEL[p.value], "count": counts.get(p.value, 0)} for p in PHASE_ORDER
        ]

    def rule_coverage(self, rules_techniques: dict[str, list[str]]) -> dict:
        """How many catalogue techniques do the loaded rules cover, per tactic (the 'ATT&CK Coverage' view)."""
        covered: set[str] = set()
        for tids in rules_techniques.values():
            for tid in tids:
                t = self.get(tid)
                if t:
                    covered.add(t.id)
        per_tactic: dict[str, dict] = {}
        for p in PHASE_ORDER:
            total = [t for t in self.by_id.values() if t.tactic == p.value]
            hit = [t for t in total if t.id in covered]
            per_tactic[p.value] = {
                "label": PHASE_LABEL[p.value],
                "total": len(total),
                "covered": len(hit),
                "techniques": [{"id": t.id, "name": t.name, "covered": t.id in covered} for t in total],
            }
        return {
            "techniques_total": len(self.by_id),
            "techniques_covered": len(covered),
            "tactics": per_tactic,
        }

    def all(self) -> list[Technique]:
        return list(self.by_id.values())

    def phases(self) -> list[dict]:
        return [{"id": p.value, "label": PHASE_LABEL[p.value]} for p in KillChainPhase]


@lru_cache
def get_catalog() -> MitreCatalog:
    from aegis.config import get_settings

    return MitreCatalog.load(get_settings().mitre_catalog)
