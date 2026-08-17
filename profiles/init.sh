#!/usr/bin/env bash
# Explicitly destructive fresh-host bootstrap. Shared because SSH, firewall,
# patching and Docker baselines must not drift between host roles.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/lib/select-profile.sh"
if [[ "${1:-}" == "openclaw" || "${1:-}" == "apps" || "${1:-}" == "websites" ]]; then
  PROFILE="$1"
  CONFIRM="${2:-}"
else
  PROFILE="$(select_profile)"
  CONFIRM="${1:-}"
fi
if [[ "$CONFIRM" != "--apply" ]]; then
  echo "Refusing to modify a host. Run $0 [profile] --apply after reviewing the selected profile." >&2
  exit 2
fi
case "$PROFILE" in
  openclaw) echo "OpenClaw policy: do not publish 80/443; retain only approved SSH/tunnel access." ;;
  apps) echo "Apps policy: inventory every domain, runtime, database and public port before confirming firewall prompts." ;;
  websites) echo "Website policy: inventory production/staging domains, TLS, PHP and database before confirming firewall prompts." ;;
esac
exec env ZVPS_PROFILE="$PROFILE" "$ROOT/lib/bootstrap.sh"
