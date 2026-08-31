"""Vercel Python entrypoint for the Aegis API.

Vercel detects the ASGI ``app`` and serves it via Fluid Compute. The demo environment is seeded on the
first (cold) request per instance; because the seed is deterministic, every instance is identical.
"""

from aegis.main import app  # noqa: F401  (Vercel serves this ASGI app)
