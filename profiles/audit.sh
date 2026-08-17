#!/usr/bin/env bash
# Full, read-only machine scan: the original host scan plus profile evidence.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/lib/select-profile.sh"
PROFILE="$(select_profile "${1:-}")"
OUT="${2:-/tmp/zvps-${PROFILE}-audit-$(date +%F-%H%M%S).txt}"

# This retains the original detailed output and formatting: patching, users,
# SSH, UFW/nft/iptables, sockets, web headers, Docker, services and journals.
ZVPS_APPEND_PROFILE_SCAN=1 "$ROOT/lib/host-scan.sh" "$OUT"

section(){ printf '\n===== %s =====\n' "$*"; }
run_sh(){ local label="$1" cmd="$2"; printf '\n--- %s\n' "$label"; bash -lc "$cmd" 2>&1 || true; }
wp_roots(){ find /var/www -xdev -type f -name wp-config.php -printf '%h\n' 2>/dev/null | sort -u; }

{
  case "$PROFILE" in
    openclaw)
      section "OPENCLAW PRIVATE PROFILE"
      run_sh "port 80/443 policy" 'ss -tulpen 2>/dev/null | grep -E "(:80|:443)[[:space:]]" || echo "PASS: no listeners on 80/443"'
      run_sh "OpenClaw security and update state" 'openclaw security audit --deep 2>/dev/null || true; openclaw update status 2>/dev/null || true'
      run_sh "WireGuard-only SSH evidence" 'wg show wg0 2>/dev/null || true; ufw status numbered 2>/dev/null || true; ss -tulpen 2>/dev/null | grep -E "(:22|:2222|:51820)[[:space:]]" || true'
      run_sh "source-repo safety posture" 'find /opt /srv -maxdepth 4 -type d -name .git -print 2>/dev/null | while read -r d; do r="${d%/.git}"; echo "--- $r"; git -C "$r" remote -v 2>/dev/null || true; git -C "$r" status --short 2>/dev/null | sed -n "1,80p" || true; find "$r" -maxdepth 3 -type f -name ".env*" -printf "ENV %m %u:%g %p\\n" 2>/dev/null; grep -RIlE "pull_request_target|workflow_run|permissions:[[:space:]]*write-all" "$r/.github/workflows" 2>/dev/null || true; done'
      ;;
    apps)
      section "APPS / ZHUB PROFILE"
      run_sh "app runtime inventory" 'systemctl --type=service --state=running --no-pager 2>/dev/null | grep -Ei "nginx|caddy|apache|node|pm2|docker|postgres|mysql|redis" || true; docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}" 2>/dev/null || true'
      run_sh "app reverse proxy and TLS" 'nginx -T 2>/dev/null | grep -Ei "server_name|listen|proxy_pass|root |ssl_certificate|strict-transport-security" | sed -n "1,400p" || true; caddy validate --config /etc/caddy/Caddyfile 2>/dev/null || true; apache2ctl -S 2>/dev/null || httpd -S 2>/dev/null || true; certbot certificates 2>/dev/null || true'
      run_sh "app compose inventory" 'find /opt /srv /var/www /home -maxdepth 5 \( -name docker-compose.yml -o -name docker-compose.yaml -o -name compose.yml -o -name compose.yaml \) -print 2>/dev/null | sed -n "1,160p"'
      run_sh "application secrets and permissions posture" 'find /opt /srv /var/www -xdev -type f \( -name ".env" -o -name ".env.*" \) -printf "%m %u:%g %p\\n" 2>/dev/null | sed -n "1,200p"; find /opt /srv /var/www -xdev -type f -perm -0002 -printf "WORLD_WRITABLE %m %u:%g %p\\n" 2>/dev/null | sed -n "1,200p"'
      ;;
    websites)
      section "WEBSITES / WORDPRESS PROFILE"
      run_sh "web services, vhosts, TLS and PHP" 'systemctl --type=service --state=running --no-pager 2>/dev/null | grep -Ei "nginx|apache|httpd|php.*fpm|mariadb|mysql|certbot|redis" || true; nginx -T 2>/dev/null | grep -Ei "server_name|listen|root |index|ssl_certificate|fastcgi_pass|proxy_pass|add_header" | sed -n "1,500p" || true; apache2ctl -S 2>/dev/null || httpd -S 2>/dev/null || true; certbot certificates 2>/dev/null || true; php -v 2>/dev/null || true; systemctl status mariadb mysql --no-pager 2>/dev/null | sed -n "1,220p" || true'
      mapfile -t SITES < <(wp_roots)
      echo "WordPress roots found: ${#SITES[@]}"
      ((${#SITES[@]})) || echo "WARN: no wp-config.php found below /var/www"
      for site in "${SITES[@]}"; do
        section "WORDPRESS SITE: $site"
        run_sh "ownership and permissions" "stat -c '%n %U:%G %a' '$site' '$site/wp-config.php' '$site/wp-content' 2>/dev/null || true; find '$site' -xdev \( -type d -o -type f \) -perm -0002 -printf 'WORLD_WRITABLE %m %u:%g %p\\n' 2>/dev/null | sed -n '1,200p'"
        run_sh "executable files in PHP-writable content areas" "for rel in uploads ai1wm-backups cache config-* ewww languages litespeed upgrade upgrade-temp-backup w3tc-config; do for dir in '$site/wp-content'/\$rel; do [ -d \"\$dir\" ] || continue; find \"\$dir\" -xdev -type f \( -iname '*.php' -o -iname '*.php[0-9]' -o -iname '*.phtml' -o -iname '*.pht' -o -iname '*.phar' -o -iname '*.phps' -o -iname '*.cgi' -o -iname '*.pl' -o -iname '*.py' -o -iname '*.sh' \) -printf '%m %u:%g %TY-%Tm-%Td %TT %s %p\\n' 2>/dev/null; done; done | sort | sed -n '1,400p'"
        run_sh "recent PHP changes" "find '$site' -xdev -type f \( -iname '*.php' -o -iname '*.phtml' \) -mtime -30 -printf '%TY-%Tm-%Td %TT %s %p\\n' 2>/dev/null | sort -r | sed -n '1,200p'"
        run_sh "WordPress hardening flags (values redacted)" "grep -nE \"^[[:space:]]*define[[:space:]]*\\([[:space:]]*['\\\"](DISALLOW_FILE_EDIT|DISALLOW_FILE_MODS|FORCE_SSL_ADMIN|WP_DEBUG|WP_DEBUG_LOG|AUTOMATIC_UPDATER_DISABLED|WP_AUTO_UPDATE_CORE|DISABLE_WP_CRON)['\\\"]\" '$site/wp-config.php' 2>/dev/null | sed -E 's/,[[:space:]]*.*/,...);/' || true"
        run_sh "WordPress runtime modification policy" "if command -v wp >/dev/null 2>&1; then wp --path='$site' eval 'foreach ([\"DISALLOW_FILE_MODS\",\"DISALLOW_FILE_EDIT\",\"AUTOMATIC_UPDATER_DISABLED\",\"WP_AUTO_UPDATE_CORE\",\"DISABLE_WP_CRON\"] as \$c) { echo \$c.\"=\".(defined(\$c) ? var_export(constant(\$c), true) : \"UNDEFINED\").PHP_EOL; }' --allow-root 2>&1 || true; else echo 'WP-CLI not installed'; fi"
        run_sh "WordPress core, plugins, themes, checksums and cron" "if command -v wp >/dev/null 2>&1; then wp --path='$site' core version --allow-root 2>&1 || true; wp --path='$site' config get MULTISITE --type=constant --allow-root 2>&1 || true; wp --path='$site' plugin list --fields=name,status,version,update,update_version --format=table --allow-root 2>&1 || true; wp --path='$site' theme list --fields=name,status,version,update,update_version --format=table --allow-root 2>&1 || true; wp --path='$site' core verify-checksums --allow-root 2>&1 || true; wp --path='$site' plugin verify-checksums --all --strict --allow-root 2>&1 || true; wp --path='$site' config get DISABLE_WP_CRON --type=constant --allow-root 2>&1 || true; wp --path='$site' cron event list --fields=hook,next_run_relative --format=table --allow-root 2>&1 | sed -n '1,220p' || true; else echo 'WP-CLI not installed'; fi"
        run_sh "account, registration and application-password posture" "if command -v wp >/dev/null 2>&1; then wp --path='$site' option get users_can_register --allow-root 2>&1 || true; wp --path='$site' option get default_role --allow-root 2>&1 || true; wp --path='$site' user list --role=administrator --fields=ID,user_login,user_registered,roles --format=table --allow-root 2>&1 || true; wp --path='$site' plugin list --status=must-use --fields=name,status,version --format=table --allow-root 2>&1 || true; wp --path='$site' user list --role=administrator --field=ID --format=ids --allow-root 2>/dev/null | tr ' ' '\\n' | while read -r id; do [ -n \"\$id\" ] || continue; echo \"--- application passwords for admin id=\$id\"; wp --path='$site' user application-password list \"\$id\" --fields=name,created,last_used,last_ip --format=table --allow-root 2>&1 || true; done; else echo 'WP-CLI not installed'; fi"
        run_sh "public WordPress exposure" "if command -v wp >/dev/null 2>&1; then home=\$(wp --path='$site' option get home --allow-root 2>/dev/null || true); echo \"home=\$home\"; if [ -n \"\$home\" ]; then curl -ksS -o /dev/null -w 'REST users status=%{http_code}\\n' --max-time 15 \"\$home/wp-json/wp/v2/users\"; curl -ksS -o /dev/null -w 'XML-RPC status=%{http_code}\\n' --max-time 15 \"\$home/xmlrpc.php\"; curl -ksS -o /dev/null -w 'WP-Cron status=%{http_code}\\n' --max-time 15 \"\$home/wp-cron.php\"; curl -ksS -o /dev/null -w 'wp-config-sample status=%{http_code}\\n' --max-time 15 \"\$home/wp-config-sample.php\"; curl -ksS -o /dev/null -w 'readme status=%{http_code}\\n' --max-time 15 \"\$home/readme.html\"; curl -ksS -o /dev/null -w 'WP login PATH_INFO status=%{http_code}\\n' --max-time 15 \"\$home/wp-login.php/xmlrpc.php\"; backup=\$(find '$site/wp-content/ai1wm-backups' -maxdepth 1 -type f -name '*.wpress' -printf '%T@ %f\\n' 2>/dev/null | sort -nr | head -1 | cut -d' ' -f2-); [ -z \"\$backup\" ] || curl -kIsS -o /dev/null -w 'latest AI1WM backup status=%{http_code}\\n' --max-time 15 \"\$home/wp-content/ai1wm-backups/\$backup\"; fi; else echo 'WP-CLI not installed'; fi"
        run_sh "WordPress scheduler service" "systemctl status \"\$(basename '$site')-wp-cron.timer\" \"\$(basename '$site')-wp-cron.service\" --no-pager 2>/dev/null || systemctl list-timers --all --no-pager 2>/dev/null | grep -Ei 'wp.?cron|wordpress' || true"
        run_sh "PHP-FPM security posture" "fpm=\$(command -v php-fpm8.3 || command -v php-fpm || true); [ -n \"\$fpm\" ] || { echo 'PHP-FPM binary not found'; exit 0; }; \"\$fpm\" -i 2>/dev/null | grep -E '^(expose_php|display_errors|display_startup_errors|log_errors|allow_url_fopen|allow_url_include|cgi.fix_pathinfo|session.use_strict_mode|session.use_only_cookies|session.cookie_secure|session.cookie_httponly|session.cookie_samesite|disable_functions|open_basedir) =>'; \"\$fpm\" -tt 2>&1 | grep -E 'listen.mode|clear_env|security.limit_extensions' || true"
        run_sh "MariaDB security posture" "if command -v mariadb >/dev/null 2>&1; then mariadb --batch --skip-column-names -e \"SELECT User,Host,plugin,IF(authentication_string='','EMPTY','SET') FROM mysql.user ORDER BY User,Host; SHOW VARIABLES WHERE Variable_name IN ('bind_address','local_infile','skip_name_resolve','require_secure_transport'); SELECT User,Host FROM mysql.user WHERE User=''; SHOW DATABASES LIKE 'test';\" 2>&1 || true; else echo 'MariaDB client not installed'; fi"
      done
      run_sh "WordPress auth-abuse fail2ban posture" 'for jail in nginx-wp-login nginx-wp-lostpassword; do echo "--- $jail"; fail2ban-client status "$jail" 2>/dev/null || true; fail2ban-client get "$jail" maxretry 2>/dev/null || true; fail2ban-client get "$jail" findtime 2>/dev/null || true; fail2ban-client get "$jail" bantime 2>/dev/null || true; done; grep -RniE "^\[nginx-wp-(login|lostpassword)\]|^[[:space:]]*(enabled|bantime|findtime|maxretry|logpath)[[:space:]]*=" /etc/fail2ban/jail.local /etc/fail2ban/jail.d 2>/dev/null || true'
      run_sh "web exploit and error log signals" 'for f in /var/log/nginx/access.log /var/log/apache2/access.log /var/log/httpd/access_log; do [ -r "$f" ] || continue; echo "--- $f"; grep -Ei "(wp-login\.php|xmlrpc\.php|wp-admin|\.env|\.git|phpmyadmin|adminer|/vendor/phpunit|eval-stdin\.php)" "$f" | tail -n 250; done; for f in /var/log/nginx/error.log /var/log/apache2/error.log /var/log/httpd/error_log; do [ -r "$f" ] || continue; echo "--- $f"; tail -n 200 "$f"; done'
      run_sh "password-reset and user-enumeration log counts" 'for f in /var/log/nginx/access.log /var/log/apache2/access.log /var/log/httpd/access_log; do [ -r "$f" ] || continue; echo "--- $f"; grep -E "wp-json/wp/v2/users|wp-login\.php\?action=lostpassword|wp-login\.php\?action=register|wp-comments-post\.php" "$f" | tail -n 500; done'
      ;;
  esac
  section "DONE"
  echo "Finished: $(date -Is)"
  echo "Report:   $OUT"
} | tee -a "$OUT"
