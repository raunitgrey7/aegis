"""Prometheus metrics."""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

EVENTS_INGESTED = Counter("aegis_events_ingested_total", "Events ingested", ["tenant", "source"])
DETECTIONS = Counter("aegis_detections_total", "Detections raised", ["rule_id", "severity"])
INCIDENTS = Gauge("aegis_incidents_open", "Currently open incidents", ["severity"])
INGEST_LATENCY = Histogram("aegis_ingest_seconds", "Ingest batch latency (s)", buckets=(0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5))
INVESTIGATION_LATENCY = Histogram("aegis_investigation_seconds", "Investigation latency (s)")
API_REQUESTS = Counter("aegis_api_requests_total", "API requests", ["method", "path", "status"])
