# zvps

Role-based VPS bootstrap, health snapshots, and deep audits.

## Profiles

| Profile | Target | Expected exposure |
| --- | --- | --- |
| `openclaw` | Private agent gateway | No domains or public 80/443; SSH and explicitly approved private/tunnel access only. |
| `apps` | Custom applications | Explicit domains, reverse proxy, app runtime, and database inventory. |
| `websites` | Institutional and WordPress sites | Explicit domains, TLS, PHP/database, WordPress and staging inventory. |

The four general entrypoints prompt for the profile when run without an argument:

```text
profiles/init.sh    # destructive bootstrap; requires --apply
profiles/health.sh  # one read-only report containing the whole current state
profiles/audit.sh   # complete read-only audit
profiles/cleanup.sh # read-only cleanup candidate inventory; never deletes
```

Examples:

```bash
sudo ./profiles/health.sh
sudo ./profiles/audit.sh
sudo ./profiles/cleanup.sh

# Optional explicit profile for automation
sudo ./profiles/health.sh websites /tmp/zvps-health.txt
```

`health.sh` is the first command for every maintenance operation. It runs the complete role-specific read-only collector and writes one report file: host identity, patches, users/SSH, firewall/listeners, services, and the relevant OpenClaw, app-runtime, or WordPress/site inventory. It does not install packages, update software, restart services, or alter configuration.

`audit.sh` is the same complete collector exposed for teams that call it an audit. There is deliberately one implementation so the health report and audit report cannot silently diverge. The website profile discovers WordPress roots under `/var/www`, inventories core/plugins/themes/updates/checksums, checks permissions and executable files in writable content areas, tests sensitive endpoints and backup exposure, verifies the local WP-Cron scheduler, reviews PHP/MariaDB hardening, and avoids printing `wp-config.php` secrets or application-password hashes.

`init.sh` is intentionally guarded with `--apply`. Its shared bootstrap lives in `lib/bootstrap.sh`; profile entrypoints enforce the role policy before it runs. Never run it blindly against an existing production host.

For the `openclaw` profile, `init.sh` refuses to run unless `wg0` is already up. Its firewall path preserves only the existing WireGuard UDP listener publicly and allows SSH via `wg0`; it never falls back to public SSH.

The bootstrap is profile-aware: `apps` and `websites` open only public HTTP/HTTPS in addition to the approved SSH path, while `openclaw` leaves 80/443 closed. Docker defaults on for `openclaw` and `apps`, off for `websites`, and always requires confirmation. Automatic security updates remain enabled, but automatic reboot is disabled so production restarts stay controlled. Cloud-safe loose reverse-path filtering is used to avoid breaking `/32` or asymmetric provider routing. Root SSH remains disabled, while locking the root password defaults off so hosting-panel remote-console recovery still works.

The bootstrap explicitly asks whether VS Code Remote SSH forwarding is required. When enabled it uses `AllowTcpForwarding local` with `GatewayPorts no`, agent forwarding disabled, and `PermitOpen any` because VS Code's dynamic SOCKS tunnel connects to a random remote server port. Only enable it for trusted key-only admin users.

## Operating sequence

1. Run the relevant `health.sh` and review the single report.
2. Run `audit.sh` only when the health snapshot identifies a reason to go deeper.
3. Preserve the current SSH session and use a second login to test any access/firewall change. Confirm the provider firewall path before touching SSH ports.
4. Write a remediation plan, preserve access, and confirm a backup/snapshot.
5. Patch the current OS and verify services/config syntax before considering a release upgrade.
6. Apply changes only with explicit approval, then take a provider snapshot after clean verification.
7. Re-run `health.sh` and attach both reports to the task thread.
