#!/usr/bin/env bash
# Read-only cleanup candidate inventory. It never deletes anything.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/lib/select-profile.sh"
PROFILE="$(select_profile "${1:-}")"
OUT="${2:-/tmp/zvps-${PROFILE}-cleanup-$(date +%F-%H%M%S).txt}"
exec "$ROOT/lib/cleanup-scan.sh" "$PROFILE" "$OUT"
