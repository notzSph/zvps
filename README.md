# zvps

<!--
Replace notzSph/zvps in the badges below with your GitHub path, for example:
  sed -i 's#notzSph/zvps#your-user/zvps#g' README.md
-->

[![Ubuntu](https://img.shields.io/badge/Ubuntu-26.04-E95420?logo=ubuntu&logoColor=white)](https://ubuntu.com/)
[![Shell](https://img.shields.io/badge/Shell-Bash-4EAA25?logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/)
[![Docker](https://img.shields.io/badge/Docker-hardened-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![OpenSSH](https://img.shields.io/badge/OpenSSH-key--only-2A6DB0)](https://www.openssh.com/)
[![Firewall](https://img.shields.io/badge/firewall-UFW%20%2B%20DOCKER--USER-red)](#security-model)
[![Fail2ban](https://img.shields.io/badge/Fail2ban-enabled-orange)](#security-model)
[![License](https://img.shields.io/badge/license-TBD-lightgrey)](#license)
[![GitHub issues](https://img.shields.io/github/issues/notzSph/zvps)](https://github.com/notzSph/zvps/issues)
[![GitHub stars](https://img.shields.io/github/stars/notzSph/zvps?style=social)](https://github.com/notzSph/zvps/stargazers)

A tiny collection of Bash scripts for preparing a fresh Ubuntu VPS for OpenClaw-style Docker workloads.

The repository does **not** deploy OpenClaw itself. It prepares the host: SSH-only administration, baseline OS hardening, firewall policy, Docker hardening, audit tooling, and post-install validation.

## Contents

```text
.
├── vps_check.sh   # post-hardening validation script
└── vps_init.sh    # interactive VPS bootstrap and hardening script
```

## What this does

`vps_init.sh` is an interactive root-only bootstrap script for a fresh VPS. It performs the following high-level actions:

- sets hostname, timezone, NTP, and base packages
- creates SSH users and installs root-controlled authorized keys
- disables root SSH login and password-based SSH authentication
- moves SSH to a configurable port, defaulting to `2222`
- configures `ssh.socket` for the selected port
- enables UFW with either public SSH or trusted-admin-IP-only SSH
- installs and configures Fail2ban
- enables unattended security upgrades
- applies sudo, AppArmor, sysctl, kernel module, auditd, and AIDE hardening
- removes common unneeded services and packages
- installs Docker from Docker’s upstream apt repository
- hardens Docker daemon defaults
- installs a `DOCKER-USER` firewall guard to drop inbound Docker-published ports by default

`vps_check.sh` validates the resulting system state and prints a pass/warn/fail summary.

## Target environment

This repo is designed for:

- fresh Ubuntu VPS instances
- Ubuntu `26.04` target configuration
- root shell or provider console access
- SSH public-key-only administration
- Docker workloads exposed through explicit reverse proxy, tunnel, or firewall policy

Do **not** run this blindly on an existing production server. The init script modifies SSH, UFW, systemd units, sysctl values, package state, Docker daemon config, audit rules, and firewall behavior.

## Quick start

Clone the repository on a fresh VPS:

```bash
git clone https://github.com/notzSph/zvps.git zvps
cd zvps
chmod +x vps_init.sh vps_check.sh
```

Run the hardening bootstrap as root:

```bash
sudo ./vps_init.sh
```

After the script finishes, test SSH from a second terminal before rebooting:

```bash
ssh -p 2222 USER@SERVER_IP
```

Then run the validation script:

```bash
sudo ./vps_check.sh
```

If validation passes and SSH works, reboot:

```bash
sudo reboot
```

## Interactive configuration

`vps_init.sh` prompts for the following values:

| Prompt | Default | Purpose |
| --- | --- | --- |
| Hostname | `zMainX` | New VPS hostname |
| Timezone | `America/New_York` | System timezone |
| SSH port | `2222` | OpenSSH listening port |
| SSH users | `zsph` | Comma-separated Unix users to create or configure |
| Trusted admin public IPs | empty | If set, UFW allows SSH only from these IPs |
| Public network interface | auto-detected, fallback `ens6` | Interface used by the Docker firewall guard |
| Allowed SSH local tunnel targets | `127.0.0.1:18789,127.0.0.1:18790` | `PermitOpen` targets for local forwarding |
| Docker address pool base | `172.30.0.0/16` | Docker default address pool base |
| Docker address pool size | `24` | Docker default address pool subnet size |

SSH public keys are pasted interactively per user. The script stores them under:

```text
/etc/ssh/authorized_keys/USER
```

The directory is root-owned, and OpenSSH is configured with:

```text
AuthorizedKeysFile /etc/ssh/authorized_keys/%u
```

## Security model

The hardening profile assumes that administration should happen over SSH with public keys only.

Core SSH settings include:

```text
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
X11Forwarding no
AllowAgentForwarding no
LogLevel VERBOSE
```

System hardening includes:

- UFW default deny incoming / allow outgoing
- optional SSH allowlist by trusted admin public IP
- Fail2ban `sshd` jail
- unattended upgrades with automatic reboot window
- sudo pseudo-terminal enforcement and shorter credential caching
- AppArmor profiles
- network and kernel sysctl hardening
- rare filesystem and USB storage module blocklists
- auditd watch rules for identity, sudo, SSH, SSH keys, and module tooling
- AIDE baseline database

Docker hardening includes:

- `live-restore`
- `icc: false`
- `no-new-privileges: true`
- `userland-proxy: false`
- bounded JSON log rotation
- custom default address pool
- no Docker TCP API exposure on `2375` or `2376`
- `DOCKER-USER` chain guard that drops inbound Docker-published ports on the public interface unless explicitly allowed

## OpenClaw notes

This repository prepares the VPS for an OpenClaw deployment but does not clone or run OpenClaw.

By default, the SSH tunnel allowlist permits:

```text
127.0.0.1:18789
127.0.0.1:18790
```

Change these during `vps_init.sh` if your OpenClaw services use different local ports.

Published Docker ports are intentionally guarded. If an OpenClaw service needs public ingress, add an explicit allow rule at the provider firewall, UFW, reverse proxy, or `DOCKER-USER` layer instead of relying on Docker’s default port publishing behavior.

## Logs

`vps_init.sh` writes logs to:

```text
/var/log/harden-vps/vps_init-YYYY-MM-DD-HHMMSS.log
```

When run without root, it falls back to the current directory, but the init script exits unless run as root.

`vps_check.sh` writes logs to:

```text
/root/vps-postcheck-YYYY-MM-DD-HHMMSS.log
```

## Recovery checklist

Before running the init script:

- keep provider console access open
- have at least one valid SSH public key ready
- know your current trusted admin public IP if you plan to restrict SSH
- know your provider firewall rules and how to edit them

After running the init script:

1. configure the provider firewall for the selected SSH port
2. remove public provider-firewall rules for ports that are not needed
3. test a fresh SSH login before closing the existing session
4. run `sudo ./vps_check.sh`
5. reboot only after SSH and validation are acceptable

## Known caveats

- The script resets UFW. Existing firewall rules are not preserved.
- Docker-published ports can bypass naïve UFW setups; this repo addresses that with a `DOCKER-USER` guard, but you should still verify effective exposure.
- The Docker firewall guard uses `iptables`. If you expose Docker over IPv6, add equivalent `ip6tables` policy and validate it separately.
- `kernel.unprivileged_userns_clone = 0` may break rootless containers and some sandboxed applications.
- Removing `snapd` and `packagekit` is optional and may be undesirable on some VPS images.
- Blocking uncommon kernel modules is conservative. Remove a blocklist if a legitimate workload requires one of those modules.
- AIDE baselines should be refreshed after legitimate system changes.

## Validation

Run:

```bash
sudo ./vps_check.sh
```

The checker reports:

```text
PASS: <count>
WARN: <count>
FAIL: <count>
```

A zero-FAIL run exits with status `0`. Any FAIL item exits with status `1` and should be reviewed before rebooting or deploying workloads.

## Refreshing AIDE after legitimate changes

```bash
sudo aide --config /etc/aide/aide.conf --update
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
sudo chown _aide:_aide /var/lib/aide/aide.db
sudo chmod 600 /var/lib/aide/aide.db
sudo aide --config /etc/aide/aide.conf --check
```

## Suggested repository hygiene

For a slightly cleaner repo, consider adding:

```text
.editorconfig
.gitignore
LICENSE
.github/workflows/shellcheck.yml
```

A minimal ShellCheck workflow:

```yaml
name: ShellCheck

on:
  push:
  pull_request:

jobs:
  shellcheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run ShellCheck
        uses: ludeeus/action-shellcheck@master
```

After adding that workflow, you can add this badge near the top:

```markdown
[![ShellCheck](https://img.shields.io/github/actions/workflow/status/notzSph/zvps/shellcheck.yml?branch=main&label=shellcheck)](https://github.com/notzSph/zvps/actions/workflows/shellcheck.yml)
```

## License

No license file is included in the current tree. Add a `LICENSE` file before distributing or accepting contributions.

If you choose MIT, replace the license badge with:

```markdown
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
```

## Disclaimer

These scripts make security-sensitive system changes. Read them before running them. Keep an active recovery console, test SSH before rebooting, and validate network exposure from outside the VPS.
