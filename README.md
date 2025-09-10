# n8n Manager — Install • Upgrade • Backup • Restore • Monitor (Single or Queue Mode)

A production-ready way to **install**, **upgrade**, **back up**, and **restore**, and minitor a self-hosted [n8n](https://n8n.io) stack on Docker — with **Traefik** (HTTPS & reverse proxy), **PostgreSQL** (persistence), and optional **Queue Mode** (Redis + workers) and a turnkey observability stack **(Prometheus + Grafana)** you can enable with a flag.
Everything is driven by one script: `n8n_manager.sh`.

---

## Table of Contents

- [Highlights](#highlights)
- [Repository Layout](#repository-layout)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
  - [Get the Repository](#get-the-repository)
  - [CLI Overview](#cli-overview)
  - [Install (Single or Queue Mode)](#install-single-or-queue-mode)
  - [Upgrade](#upgrade)
  - [Backup](#backup)
  - [Restore](#restore)
  - [Cleanup](#cleanup)
- [Monitoring (Prometheus & Grafana)](#monitoring-prometheus--grafana)
- [Queue Mode basics](#queue-mode-basics)
- [Scheduling Daily Backups](#scheduling-daily-backups)
- [Logs & Health](#logs--health)
- [Troubleshooting & FAQs](#troubleshooting--faqs)
- [Security Notes](#security-notes)
- [Support](#support)
---

## Highlights

- **One script, all tasks** — install, upgrade, backup/restore, cleanup, and **monitoring** in a single CLI.
- **Mode-aware** — deploy **Single** or **Queue** mode; upgrades auto-detect the current mode.
- **Built-in observability** — enable **Prometheus + Grafana** with `--monitoring`, pre-provisioned dashboards & alert rules.
- **Secure by default** — Traefik + Let’s Encrypt (auto-renew), strong secrets, HTTPS everywhere; Traefik **Basic Auth** in front of Grafana/Prometheus.
- **Resilient data** — PostgreSQL + persistent volumes; deterministic restores preserve workflows & credentials.
- **Smart version picker** — lists latest stable (or newer-than-current when running) with image tag validation.
- **Change-aware backups** — skip when nothing changed (use `-f` to force).
- **Fast, verifiable archives** — `pigz` compression and SHA-256 checksums; built-in local + remote retention.
- **One-command restore** — from local file or any `rclone` remote; DB restore from dump or volume; post-restore health checks.
- **Off-site ready** — upload archives & checksums to Google Drive or any `rclone` remote, with remote pruning.
- **Email notifications** — Gmail SMTP via `msmtp`; attach logs on failure (optional on success).
- **Strong UX & logging** — per-run logs under `logs/`, `--log-level DEBUG` tracing, graceful error/interrupt traps, and a rolling `backups/backup_summary.md` dashboard.

---

## Repository Layout

```
.
├── n8n_manager.sh                      # Main script (install/upgrade/backup/restore/cleanup)
├── common.sh                           # Shared helpers used by the manager
├── monitoring                          # Monitoring configuration
│   ├── grafana
│   │   └── provisioning
│   │       ├── alerts
│   │       │   ├── n8n-alert-rules.yml
│   │       │   └── system-alert-rules.yml
│   │       ├── dashboards
│   │       │   ├── dashboards.yml
│   │       │   └── n8n.json
│   │       └── datasources
│   │           └── datasource.yml
│   └── prometheus.yml
├── single-mode/
│   ├── docker-compose.yml              # Compose template (single-container n8n)
│   └── .env                            # Template env for single mode
├── queue-mode/
│   ├── docker-compose.yml              # Compose template (main + redis + workers)
│   └── .env                            # Template env for queue mode
└── (created at runtime)
    ├── /home/n8n/logs/                 # All run logs (or your chosen --dir)
    │   ├── install_n8n_<ts>.log
    │   ├── upgrade_n8n_<ts>.log
    │   ├── backup_n8n_<ts>.log
    │   ├── restore_n8n_<ts>.log
    │   └── latest_<action>.log         # symlink per action (install/upgrade/backup/restore/cleanup)
    └── /home/n8n/backups/              # Backup archives, checksums, summary, snapshot
    └── /home/n8n/monitoring/           # copied when --monitoring is enabled
```

> **Templates:** Installation copies the selected template (`single-mode/` or `queue-mode/`) into your target directory and pins your chosen **n8n version**, **domain**, **SSL email**, and **secrets**, and (optionally) copies monitoring/ for Prometheus/Grafana.

---

## Prerequisites

1. **Linux Server** — Ubuntu 20.04+ or Debian with root (or sudo) access.  
2. **Domain/Subdomain** — e.g. `n8n.example.com`.  
3. **DNS A Record** — point your domain to the server’s public IP and let it propagate.  
4. **Open Ports** — allow **80** (HTTP) and **443** (HTTPS).  
5. **Email Address** — for Let’s Encrypt (e.g., `you@company.com`).  
6. **Recommended sizing & worker strategy**

| VPS (vCPU / RAM)   | Suggestion                         |
|--------------------|------------------------------------|
| **1 vCPU / 2 GB**  | 1 worker @ concurrency **3–5**     |
| **2 vCPU / 4 GB**  | 1–2 workers @ concurrency **5**    |
| **4 vCPU / 8 GB**  | 2 workers @ concurrency **8**      |
| **8+ vCPU / 16+ GB** | 3–4 workers @ concurrency **8–10** |

---

## Quick Start

### Get the Repository

You can set up this project in **two different ways**, depending on your experience:

#### Option 1 — For developers (using Git)
If you already have `git` installed and are comfortable with it:

```bash
git clone https://github.com/thenguyenvn90/n8n-toolkit.git
cd n8n-toolkit
chmod +x *.sh
```

#### Option 2 — For non-tech users (download as ZIP)
If you don’t use Git, you can just download the code directly:

```bash
# Install unzip if not available
sudo apt update && sudo apt install -y unzip

# Download and extract
curl -L -o n8n-toolkit.zip https://github.com/thenguyenvn90/n8n-toolkit/archive/refs/heads/main.zip
unzip n8n-toolkit.zip
cd n8n-toolkit-main
chmod +x *.sh
```

Note: After unzipping, GitHub appends -main to the folder name. Instead of n8n-toolkit/, the folder will be called n8n-toolkit-main/.

---

### CLI Overview

```text
Usage: ./n8n_manager.sh [ONE ACTION] [OPTIONS]

Actions (choose exactly one):
  -a, --available                     List available n8n versions
  -i, --install <DOMAIN>              Install n8n for <DOMAIN>
  -u, --upgrade                       Upgrade n8n in the chosen --dir (reads .env)
  -b, --backup                        Run backup (skip if unchanged unless -f)
  -r, --restore <FILE_OR_REMOTE>      Restore from local file or rclone remote
  -c, --cleanup <safe|all>            Stop stack & remove resources (preview; confirm in 'all')

Options:
  --mode <single|queue>               Install mode (default: single)   [install only]
  -v, --version <tag>                 n8n image tag (default: latest stable)
  -m, --ssl-email <email>             Email for Let’s Encrypt (install/upgrade)
  -d, --dir <path>                    Target directory (default: /home/n8n)
  -l, --log-level <LEVEL>             DEBUG | INFO (default) | WARN | ERROR
  -f, --force                         Force backup or downgrade/redeploy
  -e, --email-to <email>              Send notifications to this address
  -n, --notify-on-success             Also email on success (not just failures)
  -s, --remote-name <name|path>       rclone remote (e.g. gdrive or gdrive:/n8n-backups)

  # Monitoring-related (install-time):
  --monitoring                        Enable Prometheus/Grafana profile
  --expose-prometheus                 Expose Prometheus publicly (default private)
  --subdomain-n8n <sub>               Override n8n subdomain (default: n8n)
  --subdomain-grafana <sub>           Override Grafana subdomain (default: grafana)
  --subdomain-prometheus <sub>        Override Prometheus subdomain (default: prometheus)
  --basic-auth-user <user>            Traefik basic auth user for Grafana/Prometheus
  --basic-auth-pass <pass>            Traefik basic auth pass for Grafana/Prometheus
```

> **Two different emails:**  
> `--ssl-email` is for Let’s Encrypt. `--email-to` is for **notifications** (backup/upload).  
> Set `SMTP_USER` and `SMTP_PASS` environment variables for Gmail SMTP before running if you want emails.

---

### Install (Single or Queue Mode)

> Before you run install, make sure your domain’s A record points to this server.

**Latest stable, Single mode (default):**
```bash
sudo ./n8n_manager.sh --install n8n.example.com -m you@example.com
```

**Specific version:**
```bash
sudo ./n8n_manager.sh --install n8n.example.com -m you@example.com -v 1.107.2
```

**Queue mode:**
```bash
sudo ./n8n_manager.sh --install n8n.example.com -m you@example.com --mode queue
```

**Enable monitoring (Grafana + Prometheus):**
```bash
sudo ./n8n_manager.sh --install example.com -m you@example.com --mode queue --monitoring \
  --subdomain-n8n n8n --subdomain-grafana grafana \
  --basic-auth-user admin --basic-auth-pass 'StrongPass123'
```

**Custom target directory:**
```bash
sudo ./n8n_manager.sh --install n8n.example.com -m you@example.com --mode queue -d /opt/n8n
```

What happens:

- DNS check: confirms `DOMAIN` resolves to this host.  
- Installs Docker/Compose v2 if missing.  
- Copies the template (`single-mode/` or `queue-mode/`) into your target dir.  
- Pins **n8n version**, **domain**, **SSL email**; generates **STRONG_PASSWORD** and **N8N_ENCRYPTION_KEY**.  
- Create **volumes** and start the stack behind Traefik.
- Prints a full summary with paths and logs.

Example logs for single mode:

```
═════════════════════════════════════════════════════════════
N8N has been successfully installed!
Installation Mode:       single
Domain (n8n):            https://n8n.example.com
Grafana:                 https://grafana.example.com
Prometheus:              (internal only)
Installed Version:       1.111.0
Install Timestamp:       2025-09-09_23-41-53
Installed By:            root
Target Directory:        /home/n8n
SSL Email:               you@example.com
Execution log:           /home/n8n/logs/install_n8n_2025-09-09_23-41-53.log
═════════════════════════════════════════════════════════════
```

Example logs for queue mode:

```
═════════════════════════════════════════════════════════════
N8N has been successfully installed!
Installation Mode:       queue
Domain (n8n):            https://n8n.example.com
Grafana:                 https://grafana.example.com
Prometheus:              (internal only)
Installed Version:       1.111.0
Install Timestamp:       2025-09-09_15-22-05
Installed By:            root
Target Directory:        /home/n8n
SSL Email:               you@example.com
Execution log:           /home/n8n/logs/install_n8n_2025-09-09_15-22-05.log
═════════════════════════════════════════════════════════════
```
---

### Upgrade

**See newer versions:**
```bash
sudo ./n8n_manager.sh -a
```

**Upgrade to latest stable:**
```bash
sudo ./n8n_manager.sh --upgrade
```

**Upgrade to a specific version:**
```bash
sudo ./n8n_manager.sh --upgrade -v 1.110.1
```

**Downgrade or force redeploy of the same version:**
```bash
sudo ./n8n_manager.sh --upgrade -v 1.110.1 -f
```

**Notes:**
- No domain argument for upgrade; it reads existing config from `.env`.
- Upgrades **auto-detect** whether your stack is single or queue mode (no flag needed).  
- If you **omit `-v`** (or pass `latest`), the script resolves the latest stable tag and updates `.env` to that version.
- If you **pass `-v <version>`**, the script validates the tag, pins it in `.env`, and deploys that exact version.
- A later `-u` **without `-v`** will switch you back to the latest stable.
- Use `-d /path/to/n8n` to upgrade an existing n8n installation in the specified directory.

---
Example logs for upgrade:

```
═════════════════════════════════════════════════════════════
N8N has been successfully upgraded!
Detected Mode:           queue
Domain:                  https://n8n.example.com
Upgraded Version:        1.110.1
Upgraded Timestamp:      2025-09-04_15-26-26
Upgraded By:             root
Target Directory:        /home/n8n
Execution log:           /home/n8n/logs/upgrade_n8n_2025-09-04_15-26-26.log
═════════════════════════════════════════════════════════════
```
### Backup

Backups include:

- Backs up Docker **volumes**: `n8n-data`, `postgres-data`, `letsencrypt` (+ monitoring volumes if enabled)
- Creates a **PostgreSQL dump** (from the `postgres` container, DB `n8n`)
- Copies of `.env` and `docker-compose.yml`
- Change detection to skip redundant backups (use -f to force)
- Keeps a rolling **30‑day summary** in `backups/backup_summary.md`
- Optionally **uploads** backups to **Google Drive** via `rclone`
- Sends **email alerts** through Gmail SMTP (**msmtp**) — with the log file attached on failures (and optionally on success)

**Local backup, no upload, no emails:**
```bash
sudo ./n8n_manager.sh -b
```

**Upload to Google Drive (or any rclone remote):**
```bash
# First, configure rclone once: rclone config
sudo ./n8n_manager.sh -b -s gdrive:/n8n-backups
```

**Email on failure (Gmail via msmtp):**
```bash
export SMTP_USER="youraddress@gmail.com"
export SMTP_PASS="your_gmail_app_password"
sudo ./n8n_manager.sh -b -s gdrive:/n8n-backups -e ops@example.com
```

**Always email (success or failure):**
```bash
sudo ./n8n_manager.sh -b -s gdrive:/n8n-backups -e ops@example.com -n
```

What to expect after a backup:

- Backup files: in `backups/`, named like\
  `n8n_backup_<N8N_VERSION>_<YYYY-MM-DD_HH-MM-SS>.tar.gz` 
- Matching `.sha256` checksum  
- Summary file: `backups/backup_summary.md` tracks daily history (last 30 days kept)
- Snapshot for change detection: `backups/snapshot/`  
- Local retention: **7 days** (archives + checksums)  
- Remote retention: **7 days** (pattern-based prune)

> Optional TLS gate: set `BACKUP_REQUIRE_TLS=true` in your environment to require a valid Traefik certificate before a backup proceeds.

Example logs for backup:

```
═════════════════════════════════════════════════════════════
Backup completed!
Detected Mode:           queue
Domain (n8n):            https://n8n.example.com
Backup Action:           Backup (forced)
Backup Status:           SUCCESS
Backup Timestamp:        2025-09-09_15-31-56
Backup file:             /home/n8n/backups/n8n_backup_1.111.0_2025-09-09_15-31-56.tar.gz
N8N Version:             1.111.0
N8N Directory:           /home/n8n
Log File:                /home/n8n/logs/backup_n8n_2025-09-09_15-31-56.log
Daily tracking:          /home/n8n/backups/backup_summary.md
Remote upload:           SKIPPED
Email notification:      SKIPPED (not requested)
═════════════════════════════════════════════════════════════
```
---

### Restore

**From a local archive:**
```bash
sudo ./n8n_manager.sh -r /home/n8n/backups/n8n_backup_1.107.2_2025-08-18_01-10-30.tar.gz
```

**From an rclone remote (the script will fetch, verify checksum if present, and restore):**
```bash
sudo ./n8n_manager.sh -r gdrive:/n8n-backups/n8n_backup_1.107.2_2025-08-18_01-10-30.tar.gz
```

What restore does:

1. (If remote) downloads the archive to `backups/_restore_tmp/` and verifies the `.sha256` when available.  
2. Extracts `.env.bak` and `docker-compose.yml.bak`; **requires** `N8N_ENCRYPTION_KEY` to be present.  
3. Brings the stack down; restores volumes (skips `postgres-data` if an SQL dump was found).  
4. Starts Postgres; restores DB from `.dump` or `.sql` when present; otherwise assumes DB came from volume.  
5. Starts the full stack; waits for health.  
6. Prints a final, human-friendly summary.

> ⚠️ The **same** `N8N_ENCRYPTION_KEY` must be present during restore, otherwise stored credentials cannot be decrypted.

Example logs for restore:
```
═════════════════════════════════════════════════════════════
Restore completed successfully.
Detected Mode:           queue
Domain (n8n):            https://n8n.example.com
Restore from file:       /home/n8n/backups/n8n_backup_1.111.0_2025-09-09_15-31-56.tar.gz
Local archive used:      /home/n8n/backups/n8n_backup_1.111.0_2025-09-09_15-31-56.tar.gz
Restore Timestamp:       2025-09-09_15-32-47
N8N Version:             1.111.0
N8N Directory:           /home/n8n
Log File:                /home/n8n/logs/restore_n8n_2025-09-09_15-32-47.log
Volumes restored:        grafana-data, letsencrypt, n8n-data, prometheus-data, redis-data
PostgreSQL:              Restored from SQL file (.sql)
═════════════════════════════════════════════════════════════
```
---

### Cleanup

```bash
# Safe: keep TLS certs, keep base images, keep target dir (default /home/n8n)
sudo ./n8n_manager.sh --cleanup safe

# All: remove EVERYTHING (including letsencrypt, images, and wipe target dir)
sudo ./n8n_manager.sh --cleanup all
```

Interactive plan to:

- `docker compose down --remove-orphans` (and -v in all to drop anonymous volumes)  
- safe: removes named project volumes except letsencrypt; removes project network; prunes dangling images
- all: removes all named volumes (including letsencrypt), removes network(s), prunes dangling images, removes base images (n8n & postgres families), and wipes the target directory

> ⚠️ Rate limits: deleting `letsencrypt` may hit Let’s Encrypt issuance limits when you re-install soon after..

---

## Monitoring (Prometheus & Grafana)

Turnkey observability for your n8n stack. When enabled, the manager deploys:

- **Prometheus** (scrapes metrics from n8n & exporters)
- **Grafana** (pre-provisioned datasource, dashboard, alert rules)
- **Exporters**: cAdvisor, Node Exporter, Redis Exporter, Postgres Exporter
- **Traefik** routes with **Basic Auth** in front of Grafana (and optionally Prometheus)

### Enable at install

```bash
sudo ./n8n_manager.sh --install example.com -m you@example.com --monitoring
```

Optional flags:

- `--expose-prometheus` – also make Prometheus reachable at `https://prometheus.<domain>`  
  (default: **internal only**, not exposed)
- `--subdomain-grafana <sub>` – default `grafana` → `https://grafana.<domain>`
- `--subdomain-prometheus <sub>` – default `prometheus` → `https://prometheus.<domain>`
- `--basic-auth-user <user> --basic-auth-pass <pass>` – set/rotate proxy auth for monitoring UIs

> The manager writes an `htpasswd` file at `/home/n8n/secrets/htpasswd` and points Traefik to it.

### Enable/disable after install

Monitoring is controlled by a Compose **profile**:

- **Enable:** set `COMPOSE_PROFILES=monitoring` in `/home/n8n/.env` and redeploy:
  ```bash
  docker compose -f /home/n8n/docker-compose.yml --profile monitoring up -d
  ```
- **Disable:** set `COMPOSE_PROFILES=` (empty) and redeploy:
  ```bash
  docker compose -f /home/n8n/docker-compose.yml up -d
  ```

To (un)expose Prometheus later, set `EXPOSE_PROMETHEUS=true|false` in `.env` and redeploy.

### URLs

- **Grafana**: `https://grafana.<domain>` → **protected by Traefik Basic Auth**  
- **Prometheus** (optional): `https://prometheus.<domain>` → **protected by Traefik Basic Auth** if exposed

> Grafana’s own login depends on your Compose config. If you didn’t set `GF_*` envs, configure credentials in Grafana or set them via Compose and redeploy. Traefik Basic Auth always gates access at the edge.

### What’s provisioned

- **Grafana**
  - Datasource bound to Prometheus
  - Dashboard: `monitoring/grafana/provisioning/dashboards/n8n.json`
  - Alert rules:  
    - `monitoring/grafana/provisioning/alerts/n8n-alert-rules.yml`  
    - `monitoring/grafana/provisioning/alerts/system-alert-rules.yml`  
  > Configure **Contact points** and **Notification policies** in Grafana UI to actually send alerts.
- **Prometheus**
  - Config: `monitoring/prometheus.yml` (scrapes n8n and exporters)
  - Adjust scrape intervals/targets by editing this file, then `docker compose up -d` to reload.

### Environment variables (monitoring)

| Variable | Purpose | Default |
|---|---|---|
| `COMPOSE_PROFILES` | Set to `monitoring` to enable the monitoring stack | *(empty)* |
| `SUBDOMAIN_GRAFANA` | Grafana subdomain | `grafana` |
| `SUBDOMAIN_PROMETHEUS` | Prometheus subdomain | `prometheus` |
| `GRAFANA_FQDN` | Derived FQDN (`sub.domain`) | auto |
| `PROMETHEUS_FQDN` | Derived FQDN | auto |
| `TRAEFIK_USERSFILE` | htpasswd file path in Traefik container | `/etc/traefik/htpasswd` |
| `MONITORING_BASIC_AUTH_USER` | Traefik Basic Auth user | `admin` |
| `MONITORING_BASIC_AUTH_PASS` | Traefik Basic Auth password | generated/your value |
| `EXPOSE_PROMETHEUS` | Whether Prometheus is public | `false` |

### Backups & monitoring data

When monitoring is enabled, `grafana-data` and `prometheus-data` volumes are **included** in backups and restored automatically.

👉 For deeper context on n8n monitoring, see the guide: **[n8n-observability](https://github.com/thenguyenvn90/n8n-observability)**
---

## Queue Mode basics

👉 For deeper context on queue mode, see the guide: **[n8n-queue-mode](https://github.com/thenguyenvn90/n8n-queue-mode/blob/main/README.md)**

⚠️ Set `N8N_WORKER_SCALE` in `.env` to change worker replicas (default 1).

---

## Scheduling Daily Backups

Here are two easy ways to run your backup every day automatically.

1. Use cron (example: **2:00 AM** daily):

- Create a tiny wrapper script so cron has everything it needs:

```bash
sudo mkdir -p /opt/n8n-toolkit/logs
sudo tee /opt/n8n-toolkit/run_backup.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# Gmail for notifications (optional)
export SMTP_USER="you@YourDomain.com"
export SMTP_PASS="your_app_password"   # Gmail App Password
# Run backup for the deployed n8n dir
/opt/n8n-toolkit/n8n_manager.sh -b -d /home/n8n -s gdrive:/n8n-backups -e you@YourDomain.com --notify-on-success "$@" >> /opt/n8n-toolkit/logs/cron.log 2>&1
EOF
sudo chmod +x /opt/n8n-toolkit/run_backup.sh

EOF
sudo chmod +x /opt/n8n-toolkit/run_backup.sh
```

- Schedule it daily at 02:00 (server’s local time)

Use **cron**
```bash
crontab -e
```

Add:
```cron
0 2 * * * /opt/n8n-toolkit/run_backup.sh
```

- Want a weekly forced backup as well? Add this extra line to force on Sundays:

```cron
15 2 * * 0 /opt/n8n-toolkit/run_backup.sh -f
```
---

- Check if the crontab was set up correctly:
```cron
crontab -l
```

2. Use systemd timer (resilient & survives reboots)

- Create Service unit (/etc/systemd/system/n8n-backup.service)

```bash
sudo tee /etc/systemd/system/n8n-backup.service >/dev/null <<'EOF'
[Unit]
Description=n8n daily backup

[Service]
Type=oneshot
WorkingDirectory=/opt/n8n-toolkit
Environment=SMTP_USER=you@YourDomain.com
Environment=SMTP_PASS=your_app_password
ExecStart=/opt/n8n-toolkit/n8n_manager.sh -b -d /home/n8n -s gdrive:/n8n-backups -e you@YourDomain.com --notify-on-success
StandardOutput=append:/opt/n8n-toolkit/logs/systemd-backup.log
StandardError=append:/opt/n8n-toolkit/logs/systemd-backup.log
EOF
```
- Create the timer (runs 02:05 daily and catches missed runs after reboot):

```bash
sudo tee /etc/systemd/system/n8n-backup.timer >/dev/null <<'EOF'
[Unit]
Description=Run n8n backup daily

[Timer]
OnCalendar=*-*-* 02:05:00
Persistent=true
Unit=n8n-backup.service

[Install]
WantedBy=timers.target
EOF
```

- Enable & start the timer:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now n8n-backup.timer
systemctl list-timers | grep n8n-backup
```
- Check status & logs

```bash
systemctl list-timers | grep n8n-backup
journalctl -u n8n-backup.service --no-pager -n 200
tail -n 200 /opt/n8n-toolkit/logs/systemd-backup.log
```

**Remote cleanup:** files older than **7 days** are deleted from the target folder:

```bash
rclone delete --min-age 7d gdrive-user:n8n-backups
```

(The script runs automatically after each upload.)

---

## Logs & Health

Run logs: under logs/ in your target dir (default /home/n8n/logs/):

- Install: logs/install_n8n_<YYYY-MM-DD_HH-MM-SS>.log
- Upgrade: logs/upgrade_n8n_<YYYY-MM-DD_HH-MM-SS>.log
- Backup: logs/backup_n8n_<YYYY-MM-DD_HH-MM-SS>.log
- Restore: logs/restore_n8n_<YYYY-MM-DD_HH-MM-SS>.log
- Symlink: logs/latest_<action>.log (e.g., latest_backup.log)

- **Containers:**
  ```bash
  docker compose -f /home/n8n/docker-compose.yml ps
  docker compose logs -f traefik
  docker compose logs -f n8n-main
  docker compose logs -f n8n-worker
  docker compose logs -f postgres
  docker compose logs -f redis
  ```
- **TLS check:**
  ```bash
  curl -I https://$DOMAIN
  ```

---

## Troubleshooting & FAQs

**Install fails on Docker setup**  
The script tries Docker’s official APT repo when supported; otherwise uses Docker’s convenience script. Check logs in `logs/`, then:
```bash
docker --version
docker compose version
```

**“Email didn’t send.”**  
Use Gmail **App Passwords** and export creds in the same environment:
```bash
export SMTP_USER="your@gmail.com"
export SMTP_PASS="your_app_password"
```
Then include `-e you@example.com` (and `-n` for success emails).

**“Upload went to the wrong folder.”**  
Pass `-s` as either a **remote name** or **remote:path**, e.g.:
- `-s gdrive` → uploads to the remote’s **root**
- `-s gdrive:/n8n-backups` → uploads into `/n8n-backups`

**Backups always run (no change detection).**  
First run bootstraps the snapshot. After a successful backup, the snapshot is refreshed.  
We already exclude noisy Postgres dirs (`pg_wal`, `pg_stat_tmp`, `pg_logical`), but any real file changes will trigger a backup.

**Restore complains about missing `N8N_ENCRYPTION_KEY`.**  
The backup’s `.env.bak` must contain `N8N_ENCRYPTION_KEY`. If it’s missing or different, encrypted credentials from old backups cannot be decrypted.

**Queue Mode jobs stuck in “Waiting”.**  
- Check Redis health: `docker compose exec n8n-redis-1 redis-cli ping` → `PONG`  
- Ensure workers are running: `docker compose ps` and `docker compose logs -f n8n-worker-1`  
- If Redis auth is enabled in compose, ensure `.env` contains the same password.

**Grafana asks for credentials.**  
That’s Traefik Basic Auth. Change `MONITORING_BASIC_AUTH_USER/PASS` in `.env` or rotate them via `--basic-auth-user/--basic-auth-pass` and redeploy.

**Can’t open Prometheus UI.**  
It’s internal by default. Set `EXPOSE_PROMETHEUS=true` (or pass `--expose-prometheus` on install/upgrade) and redeploy.

---

## Security Notes

- **Protect `.env`** — it contains **`N8N_ENCRYPTION_KEY`** and other secrets.
- Treat backup archives as **sensitive** (DB dumps, configs).
- Use strong passwords and rotate tokens regularly.
- Restrict SSH access and keep your system updated.
- Leave `EXPOSE_PROMETHEUS=false` unless you need its UI; it’s always behind Basic Auth if exposed.

---

## Support

- Open an issue in the repository, or  
- Email **thenguyen.ai.automation@gmail.com**