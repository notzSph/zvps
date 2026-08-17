#!/usr/bin/env bash

select_profile() {
  local supplied="${1:-}" choice
  case "$supplied" in
    openclaw|apps|websites) printf '%s\n' "$supplied"; return 0 ;;
    "") ;;
    *) echo "unknown profile: $supplied" >&2; return 2 ;;
  esac

  echo "Select machine profile:" >&2
  echo "  1) openclaw — private, no public 80/443" >&2
  echo "  2) apps      — zHub/custom applications" >&2
  echo "  3) websites  — zOfficial/zFCRAT/WordPress" >&2
  read -r -p "Choice [1-3]: " choice
  case "$choice" in
    1) printf 'openclaw\n' ;;
    2) printf 'apps\n' ;;
    3) printf 'websites\n' ;;
    *) echo "invalid profile choice" >&2; return 2 ;;
  esac
}
