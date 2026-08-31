#!/usr/bin/env bash
# Deploy the Aegis API to a Hugging Face Docker Space.
#
#   export HF_TOKEN=hf_xxx            # a WRITE token from https://huggingface.co/settings/tokens
#   export HF_USER=<your-hf-username>
#   bash deploy/hf-space/push.sh
#
# Creates (or updates) the Space <HF_USER>/aegis-api and pushes the repo with the Space's
# Dockerfile/README at the root so HF builds the backend image.
set -euo pipefail

: "${HF_TOKEN:?set HF_TOKEN to a write token}"
: "${HF_USER:?set HF_USER to your HF username}"
SPACE="${HF_SPACE_NAME:-aegis-api}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"

python -m pip install --quiet --upgrade "huggingface_hub[cli]"
python - <<PY
from huggingface_hub import create_repo
create_repo("${HF_USER}/${SPACE}", repo_type="space", space_sdk="docker", exist_ok=True, token="${HF_TOKEN}")
print("space ready: ${HF_USER}/${SPACE}")
PY

# Assemble the Space repo: backend + simulator + Space Dockerfile/README at root.
mkdir -p "$WORK"
cp -r "$ROOT/backend" "$WORK/backend"
cp -r "$ROOT/simulator" "$WORK/simulator"
cp "$ROOT/deploy/hf-space/Dockerfile" "$WORK/Dockerfile"
cp "$ROOT/deploy/hf-space/README.md" "$WORK/README.md"
# a top-level README is referenced by backend/pyproject; keep a copy
cp "$ROOT/README.md" "$WORK/PROJECT_README.md" 2>/dev/null || true
# strip local build/venv artifacts
find "$WORK" -type d -name "__pycache__" -prune -exec rm -rf {} + 2>/dev/null || true
find "$WORK" -type d -name "*.egg-info" -prune -exec rm -rf {} + 2>/dev/null || true
rm -f "$WORK/backend/aegis.db" 2>/dev/null || true

python - <<PY
from huggingface_hub import upload_folder
upload_folder(
    repo_id="${HF_USER}/${SPACE}", repo_type="space", folder_path="${WORK}",
    commit_message="Deploy Aegis API", token="${HF_TOKEN}",
    ignore_patterns=["**/__pycache__/**", "**/*.pyc", "**/.venv/**", "**/node_modules/**"],
)
print("pushed. Space building at: https://huggingface.co/spaces/${HF_USER}/${SPACE}")
print("API will be live at: https://${HF_USER}-${SPACE}.hf.space")
PY

rm -rf "$WORK"
