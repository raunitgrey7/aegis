import random
from datetime import UTC, datetime, timedelta

import pytest
from aegis.pipeline import Platform
from aegis.schemas.events import EventType, SecurityEvent, SourceType


@pytest.fixture
def platform():
    return Platform(enable_anomaly=True)


@pytest.fixture
def clean_platform():
    return Platform(enable_anomaly=False)


def make_event(**kw) -> SecurityEvent:
    kw.setdefault("source", SourceType.WINDOWS)
    kw.setdefault("event_type", EventType.AUTHENTICATION)
    kw.setdefault("action", "login_success")
    kw.setdefault("timestamp", datetime(2026, 8, 30, 2, 0, tzinfo=UTC))
    return SecurityEvent(**kw)


@pytest.fixture
def base_time():
    return datetime(2026, 8, 30, 2, 0, tzinfo=UTC)


@pytest.fixture
def trained_platform():
    """A platform with a benign baseline so anomaly detectors are warmed up."""
    from aegis_sim.benign import BenignGenerator
    from aegis_sim.enterprise import Enterprise

    ent = Enterprise(seed=1)
    gen = BenignGenerator(ent, random.Random(1))
    p = Platform(enable_anomaly=True)
    base = datetime(2026, 8, 1, tzinfo=UTC)
    for d in range(2):
        p.ingest_many(gen.day(base + timedelta(days=d), density=0.5), correlate=False)
    p.correlate(force=True)
    return p, ent, gen
