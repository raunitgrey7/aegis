"""Push a demo attack scenario into a running Aegis API via the ingest endpoint.

    python scripts/seed_demo.py --scenario C --url http://localhost:8000

Demonstrates the real ingest path (raw records -> /api/ingest with the API key), not the in-process seed.
"""

from __future__ import annotations

import argparse
import random
from datetime import UTC, datetime

import httpx

from aegis_sim.enterprise import Enterprise
from aegis_sim.scenarios import SCENARIOS, generate_scenario


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default="C", choices=list(SCENARIOS))
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--api-key", default="aegis-dev-ingest-key")
    ap.add_argument("--count", type=int, default=1, help="how many scenario instances to push")
    args = ap.parse_args()

    ent = Enterprise(seed=7)
    all_events = []
    for i in range(args.count):
        sc = generate_scenario(args.scenario, ent, random.Random(i), datetime.now(UTC))
        all_events.extend(json_events(sc.events))
    r = httpx.post(
        f"{args.url}/api/ingest",
        headers={"x-api-key": args.api_key},
        json={"events": all_events, "correlate": True},
        timeout=60,
    )
    r.raise_for_status()
    print(f"scenario {args.scenario} x{args.count} -> {r.json()}")


def json_events(events) -> list[dict]:
    """Serialize SecurityEvents to the normalized-record shape the ingest endpoint accepts."""
    out = []
    for e in events:
        d = e.model_dump(mode="json", exclude_none=True)
        d.pop("event_id", None)
        d.pop("raw", None)
        out.append(d)
    return out


if __name__ == "__main__":
    main()
