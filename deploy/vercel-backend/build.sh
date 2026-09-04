#!/usr/bin/env bash
# Assemble the self-contained Vercel backend project (copies the aegis + aegis_sim packages in),
# so `vercel deploy` from this directory ships everything the function needs.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

rm -rf "$HERE/aegis" "$HERE/aegis_sim"
cp -r "$ROOT/backend/aegis" "$HERE/aegis"
cp -r "$ROOT/simulator/aegis_sim" "$HERE/aegis_sim"
find "$HERE/aegis" "$HERE/aegis_sim" -type d -name "__pycache__" -prune -exec rm -rf {} + 2>/dev/null || true
rm -rf "$HERE/aegis/data/external/real" 2>/dev/null || true
rm -f "$HERE/aegis.db" 2>/dev/null || true
echo "assembled backend project at $HERE"
