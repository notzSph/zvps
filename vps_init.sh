#!/usr/bin/env bash
set -Eeuo pipefail
shopt -s extglob

# ============================================================================
# Harden fresh Ubuntu VPS for SSH-only admin + Docker workloads
# Tested target: Ubuntu 26.04
# Editor preference: vim
# ============================================================================

SCRIPT_NAME="$(basename "$0")"
LOG_DIR="/var/log/harden-vps"
LOG_FILE=""

init_logging() {
  local timestamp
  timestamp="$(date +%F-%H%M%S)"

  if [[ "$(id -u)" -eq 0 ]]; then
    mkdir -p "$LOG_DIR"
    chmod 700 "$LOG_DIR"
    LOG_FILE="$LOG_DIR/${SCRIPT_NAME%.sh}-$timestamp.log"
  else
    LOG_FILE="./${SCRIPT_NAME%.sh}-$timestamp.log"
  fi

  touch "$LOG_FILE"
  chmod 600 "$LOG_FILE" 2>/dev/null || true

  exec > >(tee -a "$LOG_FILE") 2>&1

  echo "============================================================================"
  echo "Log file: $LOG_FILE"
  echo "Started:  $(date --iso-8601=seconds)"
  echo "Script:   $0"
  echo "============================================================================"
}

on_error() {
  local exit_code="$?"
  local line_no="${1:-unknown}"
  local command="${2:-unknown}"

  echo
  echo "============================================================================"
  echo "ERROR"
  echo "============================================================================"
  echo "Exit code: $exit_code"
  echo "Line:      $line_no"
  echo "Command:   $command"
  echo "Log file:  $LOG_FILE"
  echo "Stopped:   $(date --iso-8601=seconds)"
  echo "============================================================================"

  exit "$exit_code"
}

on_interrupt() {
  echo
  echo "============================================================================"
  echo "INTERRUPTED"
  echo "============================================================================"
  echo "Log file: $LOG_FILE"
  echo "Stopped:  $(date --iso-8601=seconds)"
  echo "============================================================================"
  exit 130
}

trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR
trap 'on_interrupt' INT TERM

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "Run this script as root."
    exit 1
  fi
}

ask() {
  local prompt="$1"
  local default="${2:-}"
  local value

  if [[ -n "$default" ]]; then
    read -r -p "$prompt [$default]: " value
    echo "${value:-$default}"
  else
    read -r -p "$prompt: " value
    echo "$value"
  fi
}

ask_yes_no() {
  local prompt="$1"
  local default="${2:-y}"
  local value

  while true; do
    read -r -p "$prompt [$default]: " value
    value="${value:-$default}"
    case "$value" in
      y|Y|yes|YES) return 0 ;;
      n|N|no|NO) return 1 ;;
      *) echo "Answer y or n." ;;
    esac
  done
}

pause() {
  echo
  read -r -p "Press Enter to continue..."
}

trim_whitespace() {
  local value="$1"
  value="${value//$'\r'/}"
  value="${value##+([[:space:]])}"
  value="${value%%+([[:space:]])}"
  printf '%s' "$value"
}

comma_to_array_compact() {
  local input="$1"
  local item
  OUT_ARRAY=()

  input="${input//[[:space:]]/}"

  IFS=',' read -r -a RAW_ARRAY <<< "$input"
  for item in "${RAW_ARRAY[@]}"; do
    [[ -n "$item" ]] && OUT_ARRAY+=("$item")
  done
}

comma_to_array_trim() {
  local input="$1"
  local item
  OUT_ARRAY=()

  IFS=',' read -r -a RAW_ARRAY <<< "$input"
  for item in "${RAW_ARRAY[@]}"; do
    item="$(trim_whitespace "$item")"
    [[ -n "$item" ]] && OUT_ARRAY+=("$item")
  done
}

detect_default_iface() {
  ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}'
}

validate_required_csv() {
  local label="$1"
  local value="$2"

  if [[ -z "$(trim_whitespace "$value")" ]]; then
    echo "$label is required."
    exit 1
  fi
}

validate_ssh_port() {
  local port="$1"

  if ! [[ "$port" =~ ^[0-9]+$ ]]; then
    echo "SSH port must be numeric."
    exit 1
  fi

  if (( port < 1 || port > 65535 )); then
    echo "SSH port must be between 1 and 65535."
    exit 1
  fi
}

validate_ssh_key_roughly() {
  local key="$1"

  if [[ "$key" =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com)[[:space:]]+ ]]; then
    return 0
  fi

  return 1
}

sanitize_comment() {
  local comment="$1"

  comment="${comment//$'\r'/}"
  comment="${comment//$'\n'/ }"
  comment="$(trim_whitespace "$comment")"

  if [[ -z "$comment" ]]; then
    comment="SSH key"
  fi

  printf '%s' "$comment"
}

collect_authorized_keys_for_user() {
  local user="$1"
  local keys_csv
  local key
  local comment
  local idx
  local tmpfile

  tmpfile="$(mktemp)"

  while true; do
    echo
    echo "SSH public keys for user: $user"
    echo "Paste keys comma-separated on one line."
    echo "Example:"
    echo "ssh-ed25519 AAAA... user-device-1, ssh-ed25519 AAAA... user-device-2"
    echo "Do not include commas inside key comments."
    keys_csv="$(ask "Public keys for $user")"

    comma_to_array_trim "$keys_csv"
    USER_KEYS=("${OUT_ARRAY[@]}")

    if [[ "${#USER_KEYS[@]}" -eq 0 ]]; then
      echo "At least one SSH public key is required for $user."
      continue
    fi

    break
  done

  idx=1
  for key in "${USER_KEYS[@]}"; do
    if ! validate_ssh_key_roughly "$key"; then
      echo
      echo "WARNING: This does not look like a standard OpenSSH public key:"
      echo "$key"
      if ! ask_yes_no "Install this key anyway?" "n"; then
        echo "Skipped key $idx for $user."
        idx=$((idx + 1))
        continue
      fi
    fi

    comment="$(ask "Comment for $user key $idx" "$user key $idx")"
    comment="$(sanitize_comment "$comment")"

    {
      echo "# $comment"
      echo "$key"
      echo
    } >> "$tmpfile"

    idx=$((idx + 1))
  done

  if [[ ! -s "$tmpfile" ]]; then
    rm -f "$tmpfile"
    echo "No usable SSH keys were installed for $user."
    exit 1
  fi

  install -o root -g root -m 0644 "$tmpfile" "/etc/ssh/authorized_keys/$user"
  rm -f "$tmpfile"

  echo
  echo "Installed authorized keys for $user:"
  cat "/etc/ssh/authorized_keys/$user"
}

init_logging
require_root

echo "============================================================================"
echo "Fresh VPS hardening bootstrap"
echo "============================================================================"
echo
echo "This script will:"
echo "- set hostname/timezone"
echo "- create SSH users"
echo "- configure root-controlled SSH keys"
echo "- disable root/password SSH"
echo "- move SSH to port 2222 by default"
echo "- enable UFW with optional SSH admin-IP allowlist"
echo "- configure Fail2ban, unattended upgrades, sudo hardening"
echo "- enable AppArmor, sysctl hardening, module blocklists"
echo "- install auditd and AIDE"
echo "- remove unnecessary services/packages"
echo "- install/harden Docker"
echo "- add a DOCKER-USER firewall guard"
echo
echo "It will NOT clone OpenClaw or any application repo."
echo

HOSTNAME_NEW="$(ask 'Hostname' 'zMainX')"
TIMEZONE_NEW="$(ask 'Timezone' 'America/New_York')"
SSH_PORT="$(ask 'SSH port' '2222')"
USERS_CSV="$(ask 'SSH users, comma-separated' 'zsph')"
ADMIN_IPS_CSV="$(ask 'Trusted admin public IPs for SSH/UFW, comma-separated; leave blank to allow SSH from anywhere')"
PUBLIC_IFACE_DEFAULT="$(detect_default_iface || true)"
PUBLIC_IFACE="$(ask 'Public network interface' "${PUBLIC_IFACE_DEFAULT:-ens6}")"
PERMIT_OPEN_CSV="$(ask 'Allowed SSH local tunnel targets, comma-separated; use none to disable forwarding' '127.0.0.1:18789,127.0.0.1:18790')"
DOCKER_POOL_BASE="$(ask 'Docker default address pool base' '172.30.0.0/16')"
DOCKER_POOL_SIZE="$(ask 'Docker default address pool size' '24')"

validate_ssh_port "$SSH_PORT"
validate_required_csv "SSH users" "$USERS_CSV"

comma_to_array_compact "$USERS_CSV"
USERS=("${OUT_ARRAY[@]}")

if [[ "${#USERS[@]}" -eq 0 ]]; then
  echo "At least one SSH user is required."
  exit 1
fi

ADMIN_IPS_CSV="$(trim_whitespace "$ADMIN_IPS_CSV")"
if [[ -n "$ADMIN_IPS_CSV" ]]; then
  comma_to_array_compact "$ADMIN_IPS_CSV"
  ADMIN_IPS=("${OUT_ARRAY[@]}")
  SSH_ACCESS_MODE="restricted"
else
  ADMIN_IPS=()
  SSH_ACCESS_MODE="public"
fi

if [[ "$PERMIT_OPEN_CSV" != "none" && "$PERMIT_OPEN_CSV" != "NONE" ]]; then
  comma_to_array_compact "$PERMIT_OPEN_CSV"
  PERMIT_OPENS=("${OUT_ARRAY[@]}")
else
  PERMIT_OPENS=()
fi

echo
echo "Configuration summary:"
echo "Hostname: $HOSTNAME_NEW"
echo "Timezone: $TIMEZONE_NEW"
echo "SSH port: $SSH_PORT"
echo "Users: ${USERS[*]}"
if [[ "$SSH_ACCESS_MODE" == "restricted" ]]; then
  echo "SSH access mode: restricted to trusted IPs"
  echo "Trusted admin IPs: ${ADMIN_IPS[*]}"
else
  echo "SSH access mode: public, any source IP can reach TCP $SSH_PORT"
  echo "Trusted admin IPs: none"
fi
echo "Public interface: $PUBLIC_IFACE"
echo "PermitOpen targets: ${PERMIT_OPENS[*]:-none}"
echo "Docker pool: $DOCKER_POOL_BASE size $DOCKER_POOL_SIZE"
echo "Log file: $LOG_FILE"
echo

if ! ask_yes_no "Continue" "y"; then
  exit 0
fi

echo
echo "============================================================================"
echo "1. Base packages and system identity"
echo "============================================================================"

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get full-upgrade -y
apt-get autoremove --purge -y
apt-get install -y ca-certificates curl wget gnupg lsb-release vim git unzip htop jq openssl

hostnamectl set-hostname "$HOSTNAME_NEW"
timedatectl set-timezone "$TIMEZONE_NEW"
timedatectl set-ntp true

echo
hostnamectl
timedatectl

echo
echo "============================================================================"
echo "2. Users and SSH authorized keys"
echo "============================================================================"

groupadd sshusers 2>/dev/null || true

for user in "${USERS[@]}"; do
  if id "$user" >/dev/null 2>&1; then
    echo "User exists: $user"
  else
    adduser --gecos "" "$user"
  fi

  usermod -aG sshusers "$user"

  if ask_yes_no "Should $user have sudo access?" "y"; then
    usermod -aG sudo "$user"
  fi
done

mkdir -p /etc/ssh/authorized_keys
chown root:root /etc/ssh/authorized_keys
chmod 755 /etc/ssh/authorized_keys

for user in "${USERS[@]}"; do
  collect_authorized_keys_for_user "$user"
done

echo
echo "============================================================================"
echo "3. SSH hardening"
echo "============================================================================"

cat > /etc/ssh/sshd_config.d/00-hardening.conf <<EOF
# ============================================================================
# OpenSSH server hardening profile
# Managed by harden-vps.sh
# ============================================================================

Port $SSH_PORT
Protocol 2

PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
PermitEmptyPasswords no
UsePAM yes

AllowUsers ${USERS[*]}
AuthorizedKeysFile /etc/ssh/authorized_keys/%u

LoginGraceTime 20
MaxAuthTries 3
MaxSessions 2
MaxStartups 3:30:10
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive no
Compression no

X11Forwarding no
AllowAgentForwarding no
EOF

if [[ "${#PERMIT_OPENS[@]}" -gt 0 ]]; then
  {
    echo
    echo "# Allow local SSH tunnels only for explicitly approved loopback services."
    echo "AllowTcpForwarding local"
    printf "PermitOpen"
    for target in "${PERMIT_OPENS[@]}"; do
      printf " %s" "$target"
    done
    printf "\n"
    echo "DisableForwarding no"
  } >> /etc/ssh/sshd_config.d/00-hardening.conf
else
  {
    echo
    echo "AllowTcpForwarding no"
    echo "DisableForwarding yes"
  } >> /etc/ssh/sshd_config.d/00-hardening.conf
fi

cat >> /etc/ssh/sshd_config.d/00-hardening.conf <<'EOF'

PermitTunnel no
PermitUserEnvironment no
GatewayPorts no

Subsystem sftp internal-sftp

LogLevel VERBOSE
EOF

# Comment duplicate SFTP subsystem in main config if present.
if grep -qE '^[[:space:]]*Subsystem[[:space:]]+sftp' /etc/ssh/sshd_config; then
  cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.backup.$(date +%F-%H%M%S)"
  sed -i 's/^[[:space:]]*Subsystem[[:space:]]\+sftp/# &/' /etc/ssh/sshd_config
fi

sshd -t

echo
echo "Effective SSH config:"
sshd -T | grep -E '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|authenticationmethods|allowusers|authorizedkeysfile|disableforwarding|allowtcpforwarding|permitopen|allowagentforwarding|x11forwarding|loglevel)' || true

echo
echo "============================================================================"
echo "4. systemd ssh.socket override"
echo "============================================================================"

mkdir -p /etc/systemd/system/ssh.socket.d

cat > /etc/systemd/system/ssh.socket.d/override.conf <<EOF
[Socket]
ListenStream=
ListenStream=0.0.0.0:$SSH_PORT
ListenStream=[::]:$SSH_PORT
EOF

systemctl daemon-reload
systemctl restart ssh.socket
systemctl restart ssh

systemctl status ssh.socket --no-pager || true
ss -tulpen | grep ssh || true

echo
echo "============================================================================"
echo "5. UFW firewall"
echo "============================================================================"

ufw --force reset
ufw default deny incoming
ufw default allow outgoing

if [[ "$SSH_ACCESS_MODE" == "restricted" ]]; then
  for ip in "${ADMIN_IPS[@]}"; do
    ufw allow from "$ip" to any port "$SSH_PORT" proto tcp comment "Admin SSH $ip"
  done
else
  ufw allow "$SSH_PORT/tcp" comment "Public SSH"
fi

ufw --force enable
ufw status verbose

echo
echo "IMPORTANT: Configure your VPS provider firewall too:"
if [[ "$SSH_ACCESS_MODE" == "restricted" ]]; then
  echo "ALLOW TCP $SSH_PORT from:"
  for ip in "${ADMIN_IPS[@]}"; do
    echo "- $ip/32"
  done
else
  echo "ALLOW TCP $SSH_PORT from anywhere:"
  echo "- 0.0.0.0/0"
  echo "- ::/0 if using IPv6"
fi
echo "Remove public rules for 22, 80, 443, 8443, 8447 unless needed."
pause

echo
echo "============================================================================"
echo "6. Fail2ban"
echo "============================================================================"

apt-get install -y fail2ban

cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 3
backend = systemd
banaction = ufw

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = %(sshd_log)s
mode = aggressive
EOF

systemctl enable --now fail2ban
systemctl restart fail2ban
systemctl status fail2ban --no-pager || true
fail2ban-client status || true
fail2ban-client status sshd || true

echo
echo "============================================================================"
echo "7. Unattended security updates"
echo "============================================================================"

apt-get install -y unattended-upgrades apt-listchanges

cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

cat > /etc/apt/apt.conf.d/52unattended-upgrades-local <<'EOF'
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
Unattended-Upgrade::Automatic-Reboot-Time "23:00";
EOF

unattended-upgrade --dry-run --debug || true
systemctl status unattended-upgrades --no-pager || true
systemctl list-timers | grep -E 'apt|unattended' || true

echo
echo "============================================================================"
echo "8. Sudo hardening"
echo "============================================================================"

cat > /etc/sudoers.d/99-hardening <<'EOF'
Defaults        use_pty
Defaults        passwd_timeout=1
Defaults        timestamp_timeout=5
EOF

chmod 440 /etc/sudoers.d/99-hardening
visudo -c

echo
echo "Root password is intentionally NOT locked for provider console recovery."
echo "Root SSH remains disabled."

echo
echo "============================================================================"
echo "9. AppArmor"
echo "============================================================================"

apt-get install -y apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra
systemctl enable --now apparmor
aa-status || true

echo
echo "============================================================================"
echo "10. sysctl hardening"
echo "============================================================================"

cat > /etc/sysctl.d/99-hardening.conf <<'EOF'
# ============================================================================
# Kernel and network hardening
# ============================================================================

net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

net.ipv4.tcp_syncookies = 1

kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1

fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

kernel.yama.ptrace_scope = 1

kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

kernel.unprivileged_userns_clone = 0
EOF

sysctl --system

sysctl kernel.dmesg_restrict kernel.kptr_restrict kernel.yama.ptrace_scope kernel.unprivileged_bpf_disabled kernel.unprivileged_userns_clone
sysctl net.core.bpf_jit_harden

echo
echo "============================================================================"
echo "11. Kernel module blocklists"
echo "============================================================================"

cat > /etc/modprobe.d/99-disable-rare-filesystems.conf <<'EOF'
# Rare filesystem modules not needed on this VPS.

install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install udf /bin/false
EOF

cat > /etc/modprobe.d/99-disable-usb-storage.conf <<'EOF'
# USB storage should not be needed on a VPS.

install usb-storage /bin/false
EOF

cat > /etc/modprobe.d/99-disable-algif-aead.conf <<'EOF'
# Conservative hardening: block algif_aead unless a legitimate workload needs it.

install algif_aead /bin/false
EOF

update-initramfs -u

lsmod | grep -E 'cramfs|freevxfs|jffs2|hfs|hfsplus|udf|usb_storage|algif_aead' || true

echo
echo "============================================================================"
echo "12. auditd"
echo "============================================================================"

apt-get install -y auditd audispd-plugins
systemctl enable --now auditd

cat > /etc/audit/rules.d/99-hardening.rules <<'EOF'
# ============================================================================
# auditd hardening rules
# ============================================================================

-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity

-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /etc/ssh/authorized_keys/ -p wa -k sshkeys

-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k privileged
-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k privileged

-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
EOF

augenrules --load
auditctl -l
systemctl status auditd --no-pager || true

echo
echo "============================================================================"
echo "13. Service/package cleanup before AIDE baseline"
echo "============================================================================"

apt-get purge -y avahi-daemon cups rpcbind nfs-common samba* telnet inetutils-telnet rsh-client talk || true
apt-get autoremove --purge -y

systemctl disable --now ModemManager.service 2>/dev/null || true
systemctl disable --now udisks2.service 2>/dev/null || true
systemctl disable --now multipathd.service 2>/dev/null || true
systemctl disable --now open-iscsi.service 2>/dev/null || true

if command -v snap >/dev/null 2>&1; then
  if ask_yes_no "Remove snapd if unused?" "y"; then
    systemctl disable --now snapd.service snapd.socket snapd.seeded.service 2>/dev/null || true
    apt-get purge -y snapd || true
    rm -rf /root/snap /home/*/snap /snap /var/snap /var/lib/snapd /var/cache/snapd
    apt-get autoremove --purge -y
  fi
fi

if dpkg -l packagekit >/dev/null 2>&1; then
  echo
  echo "PackageKit simulated removal:"
  apt-get -s purge packagekit || true
  if ask_yes_no "Purge packagekit if simulation looks acceptable?" "y"; then
    apt-get purge -y packagekit || true
    apt-get autoremove --purge -y
  fi
fi

echo
echo "============================================================================"
echo "14. Docker install/hardening"
echo "============================================================================"

if ! command -v docker >/dev/null 2>&1; then
  apt-get update
  apt-get install -y ca-certificates curl gnupg
  install -m 0755 -d /etc/apt/keyrings

  if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
  fi

  . /etc/os-release

  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list

  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
fi

mkdir -p /etc/docker

cat > /etc/docker/daemon.json <<EOF
{
  "live-restore": true,
  "icc": false,
  "no-new-privileges": true,
  "userland-proxy": false,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "5"
  },
  "default-address-pools": [
    {
      "base": "$DOCKER_POOL_BASE",
      "size": $DOCKER_POOL_SIZE
    }
  ]
}
EOF

python3 -m json.tool /etc/docker/daemon.json >/dev/null
systemctl restart docker
systemctl enable docker

echo "Docker users/groups:"
getent group docker || true
for user in "${USERS[@]}"; do
  groups "$user" || true
done

docker info | sed -n '/Security Options:/,/Kernel Version:/p'
docker info | sed -n '/Default Address Pools:/,/CDI spec directories:/p'
docker info | grep -E 'Live Restore Enabled|Logging Driver'
ss -tulpen | grep -E '2375|2376|docker' || true

echo
echo "============================================================================"
echo "15. Docker published-port firewall guard"
echo "============================================================================"

cat > /usr/local/sbin/docker-user-firewall-apply <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail

LOG_FILE="/var/log/harden-vps/docker-user-firewall-apply.log"
mkdir -p /var/log/harden-vps
touch "\$LOG_FILE"
chmod 600 "\$LOG_FILE" 2>/dev/null || true
exec > >(tee -a "\$LOG_FILE") 2>&1

on_error() {
  local exit_code="\$?"
  local line_no="\${1:-unknown}"
  local command="\${2:-unknown}"

  echo
  echo "ERROR applying DOCKER-USER firewall"
  echo "Exit code: \$exit_code"
  echo "Line:      \$line_no"
  echo "Command:   \$command"
  echo "Log file:  \$LOG_FILE"
  exit "\$exit_code"
}

trap 'on_error "\$LINENO" "\$BASH_COMMAND"' ERR

iptables -N DOCKER-USER 2>/dev/null || true
iptables -F DOCKER-USER

iptables -A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
EOF

if [[ "${#ADMIN_IPS[@]}" -gt 0 ]]; then
  for ip in "${ADMIN_IPS[@]}"; do
    echo "iptables -A DOCKER-USER -i $PUBLIC_IFACE -s $ip -j RETURN" >> /usr/local/sbin/docker-user-firewall-apply
  done
else
  {
    echo
    echo "# SSH is public because no trusted admin IPs were provided."
    echo "# No admin IP bypass rules are added here."
    echo "# Result: inbound Docker-published ports on $PUBLIC_IFACE are dropped by default."
  } >> /usr/local/sbin/docker-user-firewall-apply
fi

cat >> /usr/local/sbin/docker-user-firewall-apply <<EOF
iptables -A DOCKER-USER -i $PUBLIC_IFACE -j DROP
iptables -A DOCKER-USER -j RETURN

echo "Applied DOCKER-USER firewall:"
iptables -S DOCKER-USER
EOF

chmod 755 /usr/local/sbin/docker-user-firewall-apply

cat > /etc/systemd/system/docker-user-firewall.service <<'EOF'
[Unit]
Description=Restrict inbound Docker-published ports
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/docker-user-firewall-apply
ExecReload=/usr/local/sbin/docker-user-firewall-apply

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now docker-user-firewall.service
systemctl status docker-user-firewall.service --no-pager || true
iptables -S DOCKER-USER

echo
echo "============================================================================"
echo "16. AIDE baseline"
echo "============================================================================"

# Preseed local-only postfix for AIDE/mail tooling.
echo "postfix postfix/mailname string localhost" | debconf-set-selections
echo "postfix postfix/main_mailer_type string Local only" | debconf-set-selections

apt-get install -y aide aide-common

cat > /etc/aide/aide.conf.d/99_local_noise <<'EOF'
# Local noise exclusions for volatile runtime files and AIDE staging DB.

!/run/systemd/journal/streams/.*
!/run/sudo-rs/ts/.*
!/var/lib/aide/aide\.db\.new
!/var/log/audit/audit\.log.*
!/var/log/sysstat/sa.*
!/run/docker.*
!/run/containerd/.*
EOF

aide --config /etc/aide/aide.conf --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
chown _aide:_aide /var/lib/aide/aide.db
chmod 600 /var/lib/aide/aide.db
aide --config /etc/aide/aide.conf --check || true

systemctl list-timers | grep aide || true

echo
echo "============================================================================"
echo "17. Final validation"
echo "============================================================================"

sshd -t
systemctl status ssh.socket --no-pager || true
ss -tulpen
ufw status verbose
fail2ban-client status sshd || true
aa-status || true
auditctl -l
iptables -S DOCKER-USER

echo
echo "============================================================================"
echo "Done"
echo "============================================================================"
echo "Completed: $(date --iso-8601=seconds)"
echo "Log file:  $LOG_FILE"
echo "============================================================================"
echo
echo "Next manual steps:"
echo "1. Configure provider firewall:"
if [[ "$SSH_ACCESS_MODE" == "restricted" ]]; then
  echo "   - ALLOW TCP $SSH_PORT from trusted admin IPs only:"
  for ip in "${ADMIN_IPS[@]}"; do
    echo "     - $ip/32"
  done
else
  echo "   - ALLOW TCP $SSH_PORT from anywhere:"
  echo "     - 0.0.0.0/0"
  echo "     - ::/0 if using IPv6"
fi
echo "   - Remove public allow rules for 22, 80, 443, 8443, 8447 unless needed."
echo
echo "2. Test SSH for each user/device:"
echo "   ssh -p $SSH_PORT USER@SERVER_IP"
echo
echo "3. Reboot after confirming SSH works:"
echo "   reboot"
echo
echo "4. After future legitimate changes, refresh AIDE:"
echo "   aide --config /etc/aide/aide.conf --update"
echo "   mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db"
echo "   chown _aide:_aide /var/lib/aide/aide.db"
echo "   chmod 600 /var/lib/aide/aide.db"
echo "   aide --config /etc/aide/aide.conf --check"