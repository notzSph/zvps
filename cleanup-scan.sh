#!/usr/bin/env bash
set -u

OUT="/tmp/zofficial-cleanup-scan.txt"

{
  echo "===== BACKUP / TEMP FILE CANDIDATES ====="

  for d in \
    /etc/nginx/sites-available \
    /etc/nginx/sites-enabled \
    /etc/ssh \
    /etc/ssh/sshd_config.d \
    /etc/systemd/system/ssh.socket.d \
    /etc \
    /lib/apparmor \
    /usr/lib/apparmor \
    /tmp \
    /root \
    /home/zsph
  do
    echo
    echo "--- $d"

    [ -e "$d" ] && find "$d" -maxdepth 1 -type f \
      \( -name '*.bak*' \
      -o -name '*bak-*' \
      -o -name '*backup*' \
      -o -name '*.old' \
      -o -name '*.orig' \
      -o -name '*.new' \
      -o -name '*zofficial*scan*' \
      -o -name '*healthcheck*' \
      -o -name 'rc.apparmor.functions.new' \) \
      -printf '%TY-%Tm-%Td %TH:%TM %s %p\n' 2>/dev/null | sort || true
  done

  echo
  echo "===== NGINX BACKUPS SPECIFIC ====="
  find /etc/nginx -type f \
    \( -name '*.bak*' \
    -o -name '*bak-*' \
    -o -name '*backup*' \
    -o -name '*.old' \
    -o -name '*.orig' \) \
    -printf '%TY-%Tm-%Td %TH:%TM %s %p\n' 2>/dev/null | sort || true

  echo
  echo "===== APPARMOR BACKUPS SPECIFIC ====="
  find /lib/apparmor /usr/lib/apparmor -maxdepth 1 -type f \
    \( -name '*bak*' \
    -o -name '*.new' \
    -o -name '*.old' \
    -o -name '*.orig' \) \
    -printf '%TY-%Tm-%Td %TH:%TM %s %p\n' 2>/dev/null | sort || true

  echo
  echo "===== /TMP CLEANUP CANDIDATES ====="
  find /tmp -maxdepth 1 -type f \
    \( -name 'zofficial-*' \
    -o -name '*zofficial*' \
    -o -name 'nginx-sites-enabled.txt' \
    -o -name 'nginx-test-warnings.txt' \
    -o -name 'rc.apparmor.functions.new' \
    -o -name 'vps_health_check.sh' \) \
    -printf '%TY-%Tm-%Td %TH:%TM %s %p\n' 2>/dev/null | sort || true

  echo
  echo "===== ACTIVE SYMLINKS / CONFIGS DO NOT DELETE ====="
  ls -la /etc/nginx/sites-enabled 2>/dev/null || true
  ls -la /etc/ssh/sshd_config.d /etc/systemd/system/ssh.socket.d 2>/dev/null || true
  ls -la /etc/audit/rules.d /etc/fail2ban 2>/dev/null || true

} | tee "$OUT"

echo
echo "Wrote $OUT"
