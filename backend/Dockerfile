FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUTF8=1

WORKDIR /app

# --- dependencies (cached layer) ---
COPY backend/pyproject.toml /app/backend/pyproject.toml
COPY README.md /app/README.md
RUN pip install --upgrade pip && pip install /app/backend

# --- source ---
COPY backend /app/backend
COPY simulator /app/simulator
RUN pip install /app/backend /app/simulator

# non-root user
RUN useradd --create-home --uid 10001 aegis && chown -R aegis /app
USER aegis

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import httpx,sys; sys.exit(0 if httpx.get('http://127.0.0.1:8000/api/healthz').status_code==200 else 1)"

CMD ["uvicorn", "aegis.main:app", "--host", "0.0.0.0", "--port", "8000"]
