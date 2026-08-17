#!/usr/bin/env bash
set -Eeuo pipefail

report_section() { printf '\n===== %s =====\n' "$*"; }
report_run() {
  local label="$1" command="$2"
  printf '\n--- %s\n' "$label"
  bash -lc "$command" 2>&1 || true
}
report_meta() {
  printf 'Started: %s\nHost: %s\nUser: %s (uid %s)\nProfile: %s\n' \
    "$(date -Is)" "$(hostname 2>/dev/null || true)" "$(id -un)" "$(id -u)" "$1"
}
