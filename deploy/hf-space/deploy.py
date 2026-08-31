"""Deploy the Aegis API to a Hugging Face Docker Space.

Works with a token from `hf auth login` (no env vars needed), or HF_TOKEN if set.

    python deploy/hf-space/deploy.py [--space aegis-api]
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
from pathlib import Path

from huggingface_hub import create_repo, get_token, upload_folder, whoami

ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--space", default="aegis-api")
    ap.add_argument("--user", default=None, help="HF username (auto-detected from login if omitted)")
    args = ap.parse_args()

    token = os.environ.get("HF_TOKEN") or get_token()
    if not token:
        sys.exit("No HF token found. Run `hf auth login` first (or set HF_TOKEN).")

    me = whoami(token=token)
    user = args.user or me.get("name")
    if not user:
        sys.exit("Could not determine HF username; pass --user.")
    repo_id = f"{user}/{args.space}"
    print(f"Deploying to Space: {repo_id}")

    create_repo(repo_id, repo_type="space", space_sdk="docker", exist_ok=True, token=token)

    work = Path(tempfile.mkdtemp(prefix="aegis-space-"))
    try:
        shutil.copytree(ROOT / "backend", work / "backend",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.egg-info", "aegis.db", ".pytest_cache"))
        shutil.copytree(ROOT / "simulator", work / "simulator",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.egg-info"))
        shutil.copy(ROOT / "deploy" / "hf-space" / "Dockerfile", work / "Dockerfile")
        shutil.copy(ROOT / "deploy" / "hf-space" / "README.md", work / "README.md")

        upload_folder(
            repo_id=repo_id, repo_type="space", folder_path=str(work),
            commit_message="Deploy Aegis API", token=token,
            ignore_patterns=["**/__pycache__/**", "**/*.pyc", "**/.venv/**", "**/node_modules/**"],
        )
    finally:
        shutil.rmtree(work, ignore_errors=True)

    api_host = f"{user}-{args.space}".replace("_", "-").lower()
    print("\n✅ Pushed. HF is building the Docker image now (a few minutes).")
    print(f"   Space page: https://huggingface.co/spaces/{repo_id}")
    print(f"   API base:   https://{api_host}.hf.space")
    print(f"   Health:     https://{api_host}.hf.space/api/healthz")


if __name__ == "__main__":
    main()
