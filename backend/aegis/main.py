"""FastAPI application factory and entrypoint."""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from aegis import __version__
from aegis.api import metrics
from aegis.api.routers import router
from aegis.api.state import get_state
from aegis.config import get_settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("aegis")

DESCRIPTION = """
**Aegis** — AI-powered cybersecurity investigation & threat-intelligence platform.

Ingest security telemetry → deterministic detection (rules + statistics + threat intel) →
correlation into incidents → attack-graph reconstruction → MITRE ATT&CK mapping → risk scoring →
evidence-grounded AI investigation.

Detection is deterministic. The local LLM only explains — every claim is validated against real evidence.
"""


@asynccontextmanager
async def _lifespan(app: FastAPI):
    get_state()  # eagerly build state + seed demo data
    log.info("Aegis %s ready — demo data seeded", __version__)
    yield


def create_app(seed_demo: bool = True) -> FastAPI:
    s = get_settings()
    app = FastAPI(
        title="Aegis Platform API",
        version=__version__,
        description=DESCRIPTION,
        docs_url="/docs",
        openapi_url="/openapi.json",
        lifespan=_lifespan,
    )
    # Wildcard origins can't be combined with credentialed CORS per the Fetch spec. Auth is by
    # bearer token (not cookies), so when a deployment opens origins to "*" we disable credentials.
    wildcard = "*" in s.cors_origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=s.cors_origins,
        allow_credentials=not wildcard,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def security_and_metrics(request: Request, call_next):
        # request size guard
        cl = request.headers.get("content-length")
        if cl and int(cl) > s.max_request_bytes:
            return JSONResponse({"detail": "request too large"}, status_code=413)
        t0 = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:  # never leak stack traces to clients
            log.exception("unhandled error on %s %s", request.method, request.url.path)
            return JSONResponse({"detail": "internal server error"}, status_code=500)
        dur = time.perf_counter() - t0
        response.headers["X-Response-Time-ms"] = f"{dur * 1000:.1f}"
        # security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        try:
            metrics.API_REQUESTS.labels(request.method, request.url.path, response.status_code).inc()
        except Exception:
            pass
        return response

    app.include_router(router, prefix="/api")

    @app.get("/", tags=["ops"])
    def root():
        return {"name": "Aegis Platform", "version": __version__, "docs": "/docs", "api": "/api"}

    return app


app = create_app()


def run() -> None:
    import uvicorn

    s = get_settings()
    uvicorn.run("aegis.main:app", host=s.api_host, port=s.api_port, reload=False)


if __name__ == "__main__":
    run()
