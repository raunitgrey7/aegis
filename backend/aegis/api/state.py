"""Application state: the singleton Platform, investigation engine, audit log and seed loader."""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

from aegis.api.audit import AuditLog
from aegis.api.security import RateLimiter, UserStore
from aegis.config import get_settings
from aegis.investigation.engine import InvestigationEngine
from aegis.llm.client import get_llm
from aegis.pipeline import Platform


class AppState:
    def __init__(self, seed_demo: bool = True):
        self.settings = get_settings()
        self.platform = Platform()
        llm = get_llm()
        self.llm = llm if self.settings.llm_enabled else None
        self.investigator = InvestigationEngine(self.platform.catalog, llm=self.llm)
        self.audit = AuditLog()
        self.users = UserStore()
        self.limiter = RateLimiter(self.settings.rate_limit_per_minute)
        self._report_cache: dict[str, dict] = {}
        if seed_demo:
            self.seed_demo_data()

    def seed_demo_data(self) -> None:
        """Populate a realistic demo dataset so the UI is alive on first boot."""
        from aegis_sim.benign import BenignGenerator
        from aegis_sim.enterprise import Enterprise
        from aegis_sim.scenarios import generate_scenario

        ent = Enterprise(seed=7)
        gen = BenignGenerator(ent, random.Random(7))
        base = datetime(2026, 8, 25, tzinfo=UTC)
        for d in range(2):
            self.platform.ingest_many(gen.day(base + timedelta(days=d), density=0.5), correlate=False)
        # inject a handful of attacks across the environment
        day = base + timedelta(days=2)
        for i, sid in enumerate("CADFHEBG"):
            t = day + timedelta(hours=2 + i * 2, minutes=random.Random(i).randint(0, 40))
            sc = generate_scenario(sid, ent, random.Random(100 + i), t)
            self.platform.ingest_many(sc.events, correlate=False)
        self.platform.correlate(force=True)
        self.enterprise = ent

    def invalidate_reports(self) -> None:
        self._report_cache.clear()


_state: AppState | None = None


def get_state() -> AppState:
    global _state
    if _state is None:
        _state = AppState()
    return _state


def set_state(state: AppState) -> None:
    global _state
    _state = state
