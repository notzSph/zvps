#!/usr/bin/env bash
# The health check is the complete, single-file read-only host snapshot.
# Keep one collector: health and audit must never drift into conflicting scans.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/lib/select-profile.sh"
PROFILE="$(select_profile "${1:-}")"
OUT="${2:-/tmp/zvps-${PROFILE}-health-$(date +%F-%H%M%S).txt}"
exec "$ROOT/profiles/audit.sh" "$PROFILE" "$OUT"
