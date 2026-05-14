#!/usr/bin/env bash

LOG_FILE="/root/vps-postcheck-$(date +%F-%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  echo "[PASS] $*"
}

warn() {
  WARN_COUNT=$((WARN_COUNT + 1))
  echo "[WARN] $*"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  echo "[FAIL] $*"
}

section() {
  echo
  echo "============================================================================"
  echo "$1"
  echo "============================================================================"
}

check_file_exists() {
  local path="$1"
  local label="$2"

  if [[ -e "$path" ]]; then
    pass "$label exists: $path"
  else
    fail "$label missing: $path"
  fi
}

check_systemd_active() {
  local unit="$1"

  if systemctl is-active --quiet "$unit"; then
    pass "$unit is active"
  else
    warn "$unit is not active"
    systemctl status "$unit" --no-pager || true
  fi
}

check_sshd_t_value() {
  local key="$1"
  local expected="$2"
  local actual

  actual="$(sshd -T 2>/dev/null | awk -v k="$key" '$1 == k {print $2; exit}')"

  if [[ "$actual" == "$expected" ]]; then
    pass "sshd $key = $expected"
  else
    fail "sshd $key expected '$expected', got '${actual:-missing}'"
  fi
}

section "0. Basic context"

echo "Hostname: $(hostname)"
echo "Date:     $(date --iso-8601=seconds)"
echo "Kernel:   $(uname -a)"
echo "Log file: $LOG_FILE"

if [[ "$(id -u)" -eq 0 ]]; then
  pass "Running as root"
else
  fail "Run this script as root"
fi

section "1. SSH daemon config"

if sshd -t; then
  pass "sshd -t syntax check passed"
else
  fail "sshd -t syntax check failed"
fi

SSH_PORT="$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2; exit}')"
SSH_PORT="${SSH_PORT:-2222}"

echo "Detected SSH port: $SSH_PORT"

check_sshd_t_value "permitrootlogin" "no"
check_sshd_t_value "passwordauthentication" "no"
check_sshd_t_value "kbdinteractiveauthentication" "no"
check_sshd_t_value "pubkeyauthentication" "yes"
check_sshd_t_value "authenticationmethods" "publickey"
check_sshd_t_value "x11forwarding" "no"
check_sshd_t_value "allowagentforwarding" "no"
check_sshd_t_value "loglevel" "VERBOSE"

AUTHORIZED_KEYS_FILE="$(sshd -T 2>/dev/null | awk '$1 == "authorizedkeysfile" {$1=""; sub(/^ /,""); print; exit}')"
ALLOW_USERS="$(sshd -T 2>/dev/null | awk '$1 == "allowusers" {$1=""; sub(/^ /,""); print; exit}')"

echo "AuthorizedKeysFile: ${AUTHORIZED_KEYS_FILE:-missing}"
echo "AllowUsers:         ${ALLOW_USERS:-missing}"

if [[ "$AUTHORIZED_KEYS_FILE" == "/etc/ssh/authorized_keys/%u" ]]; then
  pass "AuthorizedKeysFile points to root-controlled key directory"
else
  fail "AuthorizedKeysFile is not /etc/ssh/authorized_keys/%u"
fi

if [[ -n "$ALLOW_USERS" ]]; then
  pass "AllowUsers is configured"
else
  fail "AllowUsers is missing"
fi

section "2. SSH socket/listening state"

check_systemd_active "ssh.socket"
check_systemd_active "ssh"

if ss -tlnp | grep -Eq "[:.]$SSH_PORT[[:space:]]"; then
  pass "SSH is listening on TCP $SSH_PORT"
else
  fail "SSH does not appear to be listening on TCP $SSH_PORT"
fi

echo
echo "SSH listeners:"
ss -tlnp | grep -E "(:|\\.)$SSH_PORT[[:space:]]|ssh" || true

section "3. Users and authorized keys"

check_file_exists "/etc/ssh/authorized_keys" "Authorized keys directory"

DIR_OWNER="$(stat -c '%U:%G %a' /etc/ssh/authorized_keys 2>/dev/null || true)"
echo "/etc/ssh/authorized_keys ownership/mode: ${DIR_OWNER:-missing}"

if [[ "$DIR_OWNER" == "root:root 755" ]]; then
  pass "/etc/ssh/authorized_keys has expected root:root 755"
else
  warn "/etc/ssh/authorized_keys expected root:root 755"
fi

for user in $ALLOW_USERS; do
  echo
  echo "User: $user"

  if id "$user" >/dev/null 2>&1; then
    pass "User exists: $user"
    groups "$user" || true
  else
    fail "User missing: $user"
    continue
  fi

  if id -nG "$user" | grep -qw "sshusers"; then
    pass "$user is in sshusers"
  else
    fail "$user is not in sshusers"
  fi

  key_file="/etc/ssh/authorized_keys/$user"

  if [[ -s "$key_file" ]]; then
    pass "$key_file exists and is non-empty"
  else
    fail "$key_file missing or empty"
    continue
  fi

  key_meta="$(stat -c '%U:%G %a' "$key_file" 2>/dev/null || true)"
  echo "$key_file ownership/mode: $key_meta"

  if [[ "$key_meta" == "root:root 644" ]]; then
    pass "$key_file has expected root:root 644"
  else
    fail "$key_file expected root:root 644"
  fi

  key_count="$(grep -E '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com)' "$key_file" | wc -l)"
  comment_count="$(grep -E '^# ' "$key_file" | wc -l)"

  echo "Key count:     $key_count"
  echo "Comment count: $comment_count"

  if [[ "$key_count" -ge 1 ]]; then
    pass "$user has at least one public key"
  else
    fail "$user has no recognizable public keys"
  fi

  if [[ "$comment_count" -ge "$key_count" ]]; then
    pass "$user has comments above keys or at least matching comment count"
  else
    warn "$user has fewer comments than keys"
  fi
done

section "4. UFW firewall"

if ufw status | grep -q "Status: active"; then
  pass "UFW is active"
else
  fail "UFW is not active"
fi

echo
ufw status verbose || true

if ufw status numbered | grep -Eq "$SSH_PORT/tcp|$SSH_PORT[[:space:]]"; then
  pass "UFW has a rule involving SSH port $SSH_PORT"
else
  fail "UFW does not show an SSH rule for port $SSH_PORT"
fi

if ufw status verbose | grep -q "Default: deny (incoming), allow (outgoing)"; then
  pass "UFW default policy is deny incoming / allow outgoing"
else
  warn "UFW default policy differs from expected deny incoming / allow outgoing"
fi

section "5. Fail2ban"

check_systemd_active "fail2ban"

if fail2ban-client status sshd >/dev/null 2>&1; then
  pass "Fail2ban sshd jail exists"
  fail2ban-client status sshd || true
else
  fail "Fail2ban sshd jail is not available"
  fail2ban-client status || true
fi

section "6. Unattended upgrades"

if dpkg -s unattended-upgrades >/dev/null 2>&1; then
  pass "unattended-upgrades package is installed"
else
  fail "unattended-upgrades package is missing"
fi

check_file_exists "/etc/apt/apt.conf.d/20auto-upgrades" "APT auto-upgrades config"
check_file_exists "/etc/apt/apt.conf.d/52unattended-upgrades-local" "Local unattended-upgrades config"

echo
systemctl list-timers --all | grep -E 'apt|unattended' || warn "No apt/unattended timers shown"

section "7. Sudo hardening"

if visudo -c; then
  pass "sudoers validation passed"
else
  fail "sudoers validation failed"
fi

check_file_exists "/etc/sudoers.d/99-hardening" "sudo hardening file"

section "8. AppArmor"

check_systemd_active "apparmor"

if aa-status >/dev/null 2>&1; then
  pass "aa-status runs successfully"
  aa-status || true
else
  fail "aa-status failed"
fi

section "9. sysctl hardening"

declare -A EXPECTED_SYSCTL=(
  ["net.ipv4.conf.all.rp_filter"]="1"
  ["net.ipv4.conf.default.rp_filter"]="1"
  ["net.ipv4.conf.all.accept_redirects"]="0"
  ["net.ipv4.conf.default.accept_redirects"]="0"
  ["net.ipv6.conf.all.accept_redirects"]="0"
  ["net.ipv6.conf.default.accept_redirects"]="0"
  ["net.ipv4.conf.all.send_redirects"]="0"
  ["net.ipv4.conf.default.send_redirects"]="0"
  ["net.ipv4.conf.all.accept_source_route"]="0"
  ["net.ipv4.conf.default.accept_source_route"]="0"
  ["net.ipv6.conf.all.accept_source_route"]="0"
  ["net.ipv6.conf.default.accept_source_route"]="0"
  ["net.ipv4.tcp_syncookies"]="1"
  ["kernel.kptr_restrict"]="2"
  ["kernel.dmesg_restrict"]="1"
  ["fs.protected_hardlinks"]="1"
  ["fs.protected_symlinks"]="1"
  ["fs.protected_fifos"]="2"
  ["fs.protected_regular"]="2"
  ["kernel.yama.ptrace_scope"]="1"
  ["kernel.unprivileged_bpf_disabled"]="1"
  ["net.core.bpf_jit_harden"]="2"
  ["kernel.unprivileged_userns_clone"]="0"
)

for key in "${!EXPECTED_SYSCTL[@]}"; do
  expected="${EXPECTED_SYSCTL[$key]}"
  actual="$(sysctl -n "$key" 2>/dev/null || true)"

  if [[ "$actual" == "$expected" ]]; then
    pass "$key = $expected"
  else
    fail "$key expected $expected, got ${actual:-missing}"
  fi
done

section "10. Kernel module blocklists"

check_file_exists "/etc/modprobe.d/99-disable-rare-filesystems.conf" "Rare filesystem blocklist"
check_file_exists "/etc/modprobe.d/99-disable-usb-storage.conf" "USB storage blocklist"
check_file_exists "/etc/modprobe.d/99-disable-algif-aead.conf" "algif_aead blocklist"

if lsmod | grep -Eq 'cramfs|freevxfs|jffs2|hfs|hfsplus|udf|usb_storage|algif_aead'; then
  warn "One or more blocked modules appear loaded"
  lsmod | grep -E 'cramfs|freevxfs|jffs2|hfs|hfsplus|udf|usb_storage|algif_aead' || true
else
  pass "Blocked modules are not currently loaded"
fi

section "11. auditd"

check_systemd_active "auditd"

if auditctl -l >/dev/null 2>&1; then
  pass "auditctl rules can be listed"
  auditctl -l || true
else
  fail "auditctl -l failed"
fi

if auditctl -l | grep -q "sshd"; then
  pass "audit rules include sshd monitoring"
else
  warn "audit rules do not visibly include sshd monitoring"
fi

section "12. Package/service cleanup"

for pkg in avahi-daemon cups rpcbind nfs-common telnet inetutils-telnet rsh-client talk snapd packagekit; do
  if dpkg -s "$pkg" >/dev/null 2>&1; then
    warn "Package still installed: $pkg"
  else
    pass "Package absent: $pkg"
  fi
done

for unit in ModemManager.service udisks2.service multipathd.service open-iscsi.service; do
  if systemctl list-unit-files "$unit" >/dev/null 2>&1; then
    state="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
    active="$(systemctl is-active "$unit" 2>/dev/null || true)"
    echo "$unit enabled=$state active=$active"
  fi
done

section "13. Docker"

if command -v docker >/dev/null 2>&1; then
  pass "docker command exists"
else
  fail "docker command missing"
fi

check_systemd_active "docker"
check_file_exists "/etc/docker/daemon.json" "Docker daemon config"

if python3 -m json.tool /etc/docker/daemon.json >/dev/null 2>&1; then
  pass "/etc/docker/daemon.json is valid JSON"
else
  fail "/etc/docker/daemon.json is invalid JSON"
fi

echo
docker info 2>/dev/null | sed -n '/Security Options:/,/Kernel Version:/p' || warn "docker info failed"
docker info 2>/dev/null | sed -n '/Default Address Pools:/,/CDI spec directories:/p' || true
docker info 2>/dev/null | grep -E 'Live Restore Enabled|Logging Driver' || true

if docker info 2>/dev/null | grep -q "Live Restore Enabled: true"; then
  pass "Docker live-restore is enabled"
else
  warn "Docker live-restore not confirmed"
fi

if docker info 2>/dev/null | grep -q "Logging Driver: json-file"; then
  pass "Docker logging driver is json-file"
else
  warn "Docker logging driver not confirmed as json-file"
fi

if ss -tulpen | grep -Eq ':(2375|2376)[[:space:]]'; then
  fail "Docker TCP API appears exposed on 2375/2376"
  ss -tulpen | grep -E ':(2375|2376)[[:space:]]' || true
else
  pass "Docker TCP API is not listening on 2375/2376"
fi

section "14. DOCKER-USER firewall guard"

check_file_exists "/usr/local/sbin/docker-user-firewall-apply" "Docker firewall apply script"
check_file_exists "/etc/systemd/system/docker-user-firewall.service" "Docker firewall systemd service"
check_systemd_active "docker-user-firewall.service"

if iptables -S DOCKER-USER >/dev/null 2>&1; then
  pass "DOCKER-USER chain exists"
  iptables -S DOCKER-USER || true
else
  fail "DOCKER-USER chain missing"
fi

if iptables -S DOCKER-USER 2>/dev/null | grep -q -- "-j DROP"; then
  pass "DOCKER-USER contains a DROP rule"
else
  fail "DOCKER-USER does not contain a DROP rule"
fi

section "15. AIDE"

if dpkg -s aide >/dev/null 2>&1 || dpkg -s aide-common >/dev/null 2>&1; then
  pass "AIDE package is installed"
else
  fail "AIDE package missing"
fi

check_file_exists "/var/lib/aide/aide.db" "AIDE baseline database"

if [[ -f /var/lib/aide/aide.db ]]; then
  aide_meta="$(stat -c '%U:%G %a' /var/lib/aide/aide.db 2>/dev/null || true)"
  echo "/var/lib/aide/aide.db ownership/mode: $aide_meta"
fi

systemctl list-timers --all | grep aide || warn "No AIDE timer shown"

section "16. Listening ports"

echo "Current listening sockets:"
ss -tulpen

section "17. Summary"

echo "PASS: $PASS_COUNT"
echo "WARN: $WARN_COUNT"
echo "FAIL: $FAIL_COUNT"
echo "Log:  $LOG_FILE"

if [[ "$FAIL_COUNT" -eq 0 ]]; then
  echo
  echo "Internal validation completed with no FAIL items."
  exit 0
else
  echo
  echo "Internal validation found FAIL items. Review the log before rebooting."
  exit 1
fi