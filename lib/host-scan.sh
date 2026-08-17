#!/usr/bin/env bash
set -Eeuo pipefail

OUT="${1:-/tmp/vps-zinspection.txt}"
START_TS="$(date -Is)"
section(){ printf '
===== %s =====
' "$*"; }
run_sh(){ local label="$1"; local cmd="$2"; printf '
--- %s
' "$label"; bash -lc "$cmd" 2>&1 || true; }

{
section "SCAN META"
echo "Started: $START_TS"
echo "Report: $OUT"
echo "Effective user: $(id -un 2>/dev/null || true)"
echo "Effective uid: $(id -u 2>/dev/null || true)"

section "IDENTITY / OS"
run_sh "identity" 'whoami; id; hostname; hostnamectl 2>/dev/null || true; date -Is'
run_sh "os release" 'cat /etc/os-release 2>/dev/null || true; uname -a'
run_sh "virtualization" 'systemd-detect-virt 2>/dev/null || true; virt-what 2>/dev/null || true'

section "BOOT / KERNEL / REBOOT NEED"
run_sh "kernel packages" 'uname -r; dpkg -l "linux-image*" 2>/dev/null | awk "/^ii/{print \$2,\$3}" | tail -20'
run_sh "needrestart" 'needrestart -b 2>/dev/null || true'
run_sh "reboot required marker" 'ls -l /var/run/reboot-required /run/reboot-required 2>/dev/null || true; cat /var/run/reboot-required.pkgs 2>/dev/null || true'

section "APT / PATCH STATUS - READ ONLY"
run_sh "sources" 'grep -RhsE "^[[:space:]]*deb|^[[:space:]]*Types:" /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null | sed -n "1,160p"'
run_sh "held packages" 'apt-mark showhold 2>/dev/null || true'
run_sh "upgradable packages" 'apt list --upgradable 2>/dev/null | sed -n "1,220p"'
run_sh "release upgrade check" 'do-release-upgrade -c 2>/dev/null || true'
run_sh "ubuntu pro/security status" 'pro security-status 2>/dev/null || ubuntu-security-status 2>/dev/null || true'

section "USERS / AUTH / SUDO"
run_sh "interactive users uid >=1000" 'getent passwd | while IFS=: read -r name _ uid gid gecos home shell; do if [ "$uid" -ge 1000 ] && [ "$uid" -lt 65534 ]; then printf "%s:%s:%s:%s:%s:%s\n" "$name" "$uid" "$gid" "$gecos" "$home" "$shell"; fi; done'
run_sh "important groups" 'getent group sudo admin docker www-data nginx caddy 2>/dev/null || true'
run_sh "sudoers files" 'ls -la /etc/sudoers /etc/sudoers.d 2>/dev/null || true; for f in /etc/sudoers.d/*; do [ -f "$f" ] && echo "--- $f" && sed -n "1,160p" "$f"; done 2>/dev/null'
run_sh "root password state" 'passwd -S root 2>/dev/null || true'
run_sh "authorized keys inventory" 'find /root /home -maxdepth 3 -name authorized_keys -type f -print -exec ls -l {} \; -exec ssh-keygen -lf {} \; 2>/dev/null'
run_sh "recent logins and authentication failures" 'last -aiw 2>/dev/null | head -80; lastb -aiw 2>/dev/null | head -80 || true; journalctl _SYSTEMD_UNIT=ssh.service -n 120 --no-pager 2>/dev/null | grep -Ei "failed|invalid|authentication failure|accepted" | tail -100 || true'

section "SSH CONFIG"
run_sh "sshd effective config" 'sshd -T 2>/dev/null | grep -Ei "^(port|listenaddress|permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|authenticationmethods|allowusers|allowgroups|authorizedkeysfile|x11forwarding|allowagentforwarding|allowtcpforwarding|disableforwarding|permitopen|permitlisten|gatewayports|permituserenvironment|maxauthtries|maxsessions|maxstartups|clientaliveinterval|clientalivecountmax|loglevel|usepam|subsystem)" || true'
run_sh "sshd source config" 'grep -RniE "^[[:space:]]*(Port|ListenAddress|PermitRootLogin|PasswordAuthentication|KbdInteractiveAuthentication|PubkeyAuthentication|AuthenticationMethods|AllowUsers|AllowGroups|AuthorizedKeysFile|X11Forwarding|AllowAgentForwarding|AllowTcpForwarding|DisableForwarding|PermitOpen|PermitListen|GatewayPorts|PermitUserEnvironment|MaxAuthTries|MaxSessions|MaxStartups|ClientAliveInterval|ClientAliveCountMax|LogLevel|UsePAM|Subsystem)" /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null || true'
run_sh "sshd config test" 'sshd -t 2>&1 || true'

section "FIREWALL / PACKET FILTER"
run_sh "ufw status" 'ufw status verbose 2>/dev/null || true'
run_sh "nft ruleset head" 'nft list ruleset 2>/dev/null | sed -n "1,260p" || true'
run_sh "iptables rules" 'iptables -S 2>/dev/null | sed -n "1,240p" || true'
run_sh "iptables nat" 'iptables -t nat -S 2>/dev/null | sed -n "1,220p" || true'
run_sh "docker-user chain" 'iptables -S DOCKER-USER 2>/dev/null || true'

section "NETWORK / LISTENING PORTS"
run_sh "ip addresses" 'ip -brief addr 2>/dev/null || true'
run_sh "routes" 'ip route 2>/dev/null || true; ip -6 route 2>/dev/null || true'
run_sh "listening sockets" 'ss -tulpen 2>/dev/null || true'
run_sh "WireGuard posture" 'wg show 2>/dev/null || true; ip -brief addr show type wireguard 2>/dev/null || true; systemctl is-enabled wg-quick@wg0 2>/dev/null || true; stat -c "%a %U:%G %n" /etc/wireguard /etc/wireguard/*.conf 2>/dev/null || true'

section "WEB LOCAL BEHAVIOR / HEADERS"
run_sh "http localhost headers" 'curl -kIL --max-time 10 http://127.0.0.1 2>/dev/null | sed -n "1,120p" || true'
run_sh "https localhost headers" 'curl -kIL --max-time 10 https://127.0.0.1 2>/dev/null | sed -n "1,160p" || true'
run_sh "http localhost body first lines" 'curl -ksS --max-time 10 http://127.0.0.1 2>/dev/null | sed -n "1,40p" || true'

section "WEB SERVER CONFIG DETECTION"
run_sh "running web-ish services" 'systemctl --no-pager --type=service --state=running 2>/dev/null | grep -Ei "nginx|apache|httpd|caddy|traefik|certbot|php|mariadb|mysql|docker|containerd|ssh|ufw|fail2ban" || true'
run_sh "nginx summary" 'nginx -T 2>/dev/null | grep -Ei "server_name|listen|return[[:space:]]+30|rewrite|ssl_certificate|strict-transport-security|add_header|proxy_pass|root |index " | sed -n "1,260p" || true'
run_sh "caddy config" 'caddy validate --config /etc/caddy/Caddyfile 2>/dev/null || true; sed -n "1,260p" /etc/caddy/Caddyfile 2>/dev/null || true'
run_sh "apache summary" 'apache2ctl -S 2>/dev/null || httpd -S 2>/dev/null || true'
run_sh "certbot certs" 'certbot certificates 2>/dev/null | sed -n "1,220p" || true'

section "DOCKER / CONTAINERS"
run_sh "docker ps" 'docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}" 2>/dev/null || true'
run_sh "docker networks" 'docker network ls 2>/dev/null || true'
run_sh "docker info security" 'docker info 2>/dev/null | sed -n "/Security Options:/,/Kernel Version:/p" || true'
run_sh "compose files nearby" 'find /opt /srv /var/www /home -maxdepth 5 \( -name docker-compose.yml -o -name docker-compose.yaml -o -name compose.yml -o -name compose.yaml \) -print 2>/dev/null | sed -n "1,120p"'
run_sh "container privilege and published-port posture" 'docker ps -q 2>/dev/null | while read -r c; do docker inspect --format "{{.Name}} privileged={{.HostConfig.Privileged}} network={{.HostConfig.NetworkMode}} readonly_rootfs={{.HostConfig.ReadonlyRootfs}} ports={{json .NetworkSettings.Ports}}" "$c"; done 2>/dev/null || true'

section "PERSISTENCE / PRIVILEGE / KERNEL POSTURE"
run_sh "cron and systemd timers" 'systemctl list-timers --all --no-pager 2>/dev/null || true; crontab -l 2>/dev/null || true; for f in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/*; do [ -f "$f" ] && echo "--- $f" && sed -n "1,160p" "$f"; done 2>/dev/null'
run_sh "SUID SGID and file capabilities" 'find /usr /bin /sbin /opt -xdev -type f \( -perm -4000 -o -perm -2000 \) -printf "%m %u:%g %p\\n" 2>/dev/null | sort | sed -n "1,260p"; getcap -r /usr /bin /sbin /opt 2>/dev/null | sed -n "1,260p" || true'
run_sh "kernel hardening controls" 'sysctl kernel.kptr_restrict kernel.dmesg_restrict kernel.yama.ptrace_scope fs.protected_hardlinks fs.protected_symlinks fs.protected_fifos fs.protected_regular fs.suid_dumpable net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter net.ipv4.tcp_syncookies net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects net.ipv4.conf.all.send_redirects net.ipv4.conf.default.send_redirects net.ipv4.conf.all.accept_source_route net.ipv4.conf.default.accept_source_route net.ipv4.conf.all.log_martians net.ipv4.conf.default.log_martians net.ipv6.conf.all.accept_redirects net.ipv6.conf.default.accept_redirects net.ipv6.conf.all.accept_source_route net.ipv6.conf.default.accept_source_route 2>/dev/null || true'

section "SYSTEM HEALTH"
run_sh "uptime/memory/disk" 'uptime; free -h; df -hT; lsblk -f'
run_sh "failed systemd units" 'systemctl --failed --no-pager 2>/dev/null || true'
run_sh "enabled security services" 'for unit in ufw fail2ban unattended-upgrades apparmor auditd; do printf "%s: " "$unit"; systemctl is-enabled "$unit" 2>/dev/null || echo not-found; done'
run_sh "service status summary" 'systemctl status ufw fail2ban unattended-upgrades apparmor auditd ssh nginx apache2 caddy docker containerd --no-pager 2>/dev/null | sed -n "1,320p" || true'
run_sh "fail2ban" 'fail2ban-client status 2>/dev/null || true; fail2ban-client status 2>/dev/null | sed -n "s/.*Jail list:[[:space:]]*//p" | tr "," "\n" | while read -r jail; do jail="$(echo "$jail" | xargs)"; [ -n "$jail" ] || continue; echo "--- $jail"; fail2ban-client status "$jail" 2>/dev/null || true; done'
run_sh "apparmor" 'aa-status 2>/dev/null || true'
run_sh "auditd storage and rotation posture" 'grep -nE "^(log_file|max_log_file|max_log_file_action|num_logs|space_left|admin_space_left|disk_full_action|disk_error_action|flush|freq)[[:space:]]*=" /etc/audit/auditd.conf 2>/dev/null || true; du -sh /var/log/audit 2>/dev/null || true; ls -lh /var/log/audit 2>/dev/null || true; auditctl -s 2>/dev/null || true; auditctl -l 2>/dev/null || true; journalctl -u auditd -b -n 120 --no-pager 2>/dev/null || true'
run_sh "active PAM module references and resolution" 'grep -RnsE "^[[:space:]]*[^#[:space:]].*pam_lastlog\\.so" /etc/pam.d 2>/dev/null || true; find /usr/lib -type f -name pam_lastlog.so -print 2>/dev/null; dpkg -l libpam-modules libpam-runtime 2>/dev/null || true'

section "RECENT WARNINGS / ERRORS"
run_sh "journal warnings" 'journalctl -p warning..alert -n 160 --no-pager 2>/dev/null || true'

if [[ "${ZVPS_APPEND_PROFILE_SCAN:-0}" != "1" ]]; then
  section "DONE"
  echo "Started:  $START_TS"
  echo "Finished: $(date -Is)"
  echo "Report:   $OUT"
fi
} | tee "$OUT"
