#!/usr/bin/env bash
# Read-only cleanup candidate inventory. Never deletes files.
set -Eeuo pipefail

PROFILE="${1:?usage: cleanup-scan.sh <openclaw|apps|websites> [report-path]}"
OUT="${2:-/tmp/zvps-${PROFILE}-cleanup-$(date +%F-%H%M%S).txt}"
case "$PROFILE" in openclaw|apps|websites) ;; *) echo "unknown profile: $PROFILE" >&2; exit 2;; esac

section(){ printf '\n===== %s =====\n' "$*"; }
scan_candidates(){
  local path="$1"
  echo
  echo "--- $path"
  [ -e "$path" ] && find "$path" -maxdepth 1 -type f \
    \( -name '*.bak*' -o -name '*bak-*' -o -name '*backup*' -o -name '*.old' \
       -o -name '*.orig' -o -name '*.new' -o -name '*healthcheck*' \
       -o -name '*audit*' -o -name '*scan*' \) \
    -printf '%TY-%Tm-%Td %TH:%TM %s %p\n' 2>/dev/null | sort || true
}

{
  section "SCAN META"
  echo "Profile: $PROFILE"
  echo "Report: $OUT"
  echo "Mode: read-only; this lists candidates and never deletes anything."

  section "COMMON BACKUP / TEMP CANDIDATES"
  for path in /etc/ssh /etc/ssh/sshd_config.d /etc/systemd/system /tmp /root /home; do
    scan_candidates "$path"
  done

  section "COMMON ACTIVE CONFIGS — DO NOT DELETE"
  ls -la /etc/ssh/sshd_config.d /etc/systemd/system /etc/audit/rules.d /etc/fail2ban 2>/dev/null || true

  case "$PROFILE" in
    openclaw)
      section "OPENCLAW CANDIDATES"
      for path in /opt /srv /var/lib; do scan_candidates "$path"; done
      echo
      echo "--- containers/images (inventory only)"
      docker system df 2>/dev/null || true
      ;;
    apps)
      section "APPS / ZHUB CANDIDATES"
      for path in /opt /srv /var/www; do scan_candidates "$path"; done
      echo
      echo "--- compose/build artefact candidates"
      find /opt /srv /var/www -xdev -maxdepth 5 -type f \
        \( -name '*.bak*' -o -name '*.old' -o -name '*.orig' -o -name '*.log.*' \) \
        -printf '%TY-%Tm-%Td %TH:%TM %s %p\n' 2>/dev/null | sort | sed -n '1,400p' || true
      ;;
    websites)
      section "WEBSITES / WORDPRESS CANDIDATES"
      for path in /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/apache2/sites-available /etc/apache2/sites-enabled /var/www; do scan_candidates "$path"; done
      echo
      echo "--- site backup archives (review before deletion)"
      find /var/www -xdev -maxdepth 5 -type f \
        \( -iname '*.sql' -o -iname '*.sql.gz' -o -iname '*.zip' -o -iname '*.tar' -o -iname '*.tar.gz' -o -iname '*.tgz' \) \
        -printf '%TY-%Tm-%Td %TH:%TM %s %p\n' 2>/dev/null | sort | sed -n '1,400p' || true
      echo
      echo "--- active web configs — DO NOT DELETE"
      ls -la /etc/nginx/sites-enabled /etc/apache2/sites-enabled 2>/dev/null || true
      ;;
  esac

  section "DONE"
  echo "Finished: $(date -Is)"
  echo "Report: $OUT"
} | tee "$OUT"
