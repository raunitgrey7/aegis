# Hugging Face Space (Docker SDK) — Aegis API backend.
# HF Spaces route external traffic to port 7860. The app seeds a demo environment on startup.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUTF8=1 \
    AEGIS_ENV=production \
    AEGIS_LLM_ENABLED=false \
    AEGIS_API_PORT=7860 \
    HOME=/home/aegis

# HF Spaces run as a non-root user (uid 1000)
RUN useradd -m -u 1000 aegis
WORKDIR /app

# Dependencies first (layer cache)
COPY --chown=aegis backend/pyproject.toml /app/backend/pyproject.toml
COPY --chown=aegis README.md /app/README.md
RUN pip install --upgrade pip && pip install /app/backend

# Source
COPY --chown=aegis backend /app/backend
COPY --chown=aegis simulator /app/simulator
RUN pip install /app/backend /app/simulator

USER aegis
EXPOSE 7860

# CORS is wide-open here on purpose: this is a public demo API with no sensitive data, and the
# frontend authenticates with bearer tokens (not cookies), so credentialed CORS is off.
ENV AEGIS_CORS_ORIGINS='["*"]'

CMD ["uvicorn", "aegis.main:app", "--host", "0.0.0.0", "--port", "7860"]
