# n8n Manager — Install • Upgrade • Backup/Restore (Single or Queue Mode)

A production-ready way to **install**, **upgrade**, **back up**, and **restore** a self-hosted [n8n](https://n8n.io) stack on Docker — with **Traefik** (HTTPS & reverse proxy), **PostgreSQL** (persistence), and optional **Queue Mode** (Redis + workers).  
Everything is driven by one script: `n8n_manager.sh`.

---

## Table of Contents

- [Highlights](#highlights)
- [Repository Layout](#repository-layout)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
  - [Get the Code](#get-the-code)
  - [CLI Overview](#cli-overview)
  - [Install (Single or Queue Mode)](#install-single-or-queue-mode)
  - [Upgrade](#upgrade)
  - [Back up](#back-up)
  - [Restore](#restore)
  - [Cleanup](#cleanup)
- [Queue Mode Basics](#queue-mode-basics)
- [Scheduling Daily Backups](#scheduling-daily-backups)
- [Logs & Health](#logs--health)
- [Troubleshooting & FAQs](#troubleshooting--faqs)
- [Security Notes](#security-notes)
- [Support](#support)

---

## Highlights

- **One script, all tasks** — install, upgrade, backup/restore, cleanup.
- **Mode-aware** — deploy either **Single** or **Queue** mode; upgrades auto-detect the current mode.
- **Secure by default** — Traefik + Let’s Encrypt, strong secrets, HTTPS everywhere.
- **Resilient data** — PostgreSQL database, persistent volumes, deterministic restores.
- **Change detection** — backups skip when nothing changed (use `-f` to force).
- **Optional cloud uploads** — send archives to Google Drive (or any `rclone` remote).
- **Email notifications** — Gmail SMTP via `msmtp` (attach logs on failure; optional on success).
- **Self-healing checks** — health checks for services, TLS verification (optional).

---

## Repository Layout

```
.
├── n8n_manager.sh                 # Main script (install/upgrade/backup/restore/cleanup)
├── common.sh                      # Shared helpers used by the manager
├── single-mode/
│   ├── docker-compose.yml         # Compose template (single-container n8n)
│   └── .env                       # Template env for single mode
├── queue-mode/
│   ├── docker-compose.yml         # Compose template (main + redis + workers)
│   └── .env                       # Template env for queue mode
└── (created at runtime)
    ├── /home/n8n/logs/            # All run logs (or your chosen --dir)
    └── /home/n8n/backups/         # Backup archives, checksums, summary, snapshot
```

> **Templates:** Installation copies the selected template (`single-mode/` or `queue-mode/`) into your target directory and pins your chosen **n8n version**, **domain**, **SSL email**, and **secrets**.

---

## Prerequisites

- **Ubuntu/Debian** server (root or sudo).
- **Domain/subdomain** pointing to this server’s **public IP**.
- **Open ports**: **80** and **443**.
- **Recommended resources**: min **1 vCPU / 2 GB RAM** (Single); **2 vCPU / 4 GB RAM**+ for Queue.
- **Email for SSL** (Let’s Encrypt) — e.g., `you@example.com`.

> The script auto-installs Docker Engine & Compose v2 (APT repo when possible; otherwise Docker’s convenience script). It also installs `jq`, `rsync`, `tar`, `msmtp-mta`, `dnsutils`, `openssl`, `pigz`, and `vim` on apt-based systems.

---

## Quick Start

### Get the Code

**Option A — Git**
```bash
git clone https://github.com/<your-org-or-user>/<your-repo>.git
cd <your-repo>
chmod +x *.sh
```

**Option B — ZIP (no git)**
```bash
sudo apt-get update && sudo apt-get install -y unzip
curl -L -o n8n.zip https://github.com/<your-org-or-user>/<your-repo>/archive/refs/heads/main.zip
unzip n8n.zip
cd <your-repo>-main
chmod +x *.sh
```
> GitHub ZIPs append `-main` to the folder name.

---

### CLI Overview

```text
Usage: ./n8n_manager.sh [ONE ACTION] [OPTIONS]

Actions (choose exactly one):
  -a, --available                 List available n8n versions
  -i, --install <DOMAIN>          Install n8n for <DOMAIN>
  -u, --upgrade <DOMAIN>          Upgrade n8n for <DOMAIN>
  -b, --backup                    Run backup (skip if unchanged unless -f)
  -r, --restore <FILE_OR_REMOTE>  Restore from local file or rclone remote
  -c, --cleanup                   Stop stack and remove resources (interactive)

Options:
  --mode <single|queue>           Install mode (default: single)   [install only]
  -v, --version <tag>             n8n image tag (default: latest stable)
  -m, --ssl-email <email>         Email for Let's Encrypt
  -d, --dir <path>                Target directory (default: /home/n8n)
  -l, --log-level <LEVEL>         DEBUG | INFO (default) | WARN | ERROR
  -f, --force                     Force backup or downgrade/redeploy
  -e, --email-to <email>          Send notifications to this address
  -n, --notify-on-success         Also email on success (not just failures)
  -s, --remote-name <name|path>   rclone remote (e.g. gdrive or gdrive:/n8n-backups)
  -h, --help                      Show help
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

**Custom target directory:**
```bash
sudo ./n8n_manager.sh --install n8n.example.com -m you@example.com --mode queue -d /opt/n8n
```

What happens:

1. DNS check: confirms `DOMAIN` resolves to this host.  
2. Installs Docker/Compose v2 if missing.  
3. Copies the template (`single-mode/` or `queue-mode/`) into your target dir.  
4. Pins **n8n version**, **domain**, **SSL email**; generates **STRONG_PASSWORD** and **N8N_ENCRYPTION_KEY** if needed.  
5. Brings the stack up; waits for health and TLS.  
6. Prints a full summary with paths and logs.

---

### Upgrade

**See newer versions:**
```bash
sudo ./n8n_manager.sh -a
```

**Upgrade to latest stable:**
```bash
sudo ./n8n_manager.sh --upgrade n8n.example.com
```

**Upgrade to a specific version:**
```bash
sudo ./n8n_manager.sh --upgrade n8n.example.com -v 1.107.3
```

**Downgrade or force redeploy of the same version:**
```bash
sudo ./n8n_manager.sh --upgrade n8n.example.com -v 1.105.3 -f
```

Notes:

- Upgrades **auto-detect** whether your stack is single or queue mode (no flag needed).  
- `-v` pins the `.env` `N8N_IMAGE_TAG` and redeploys.  
- Without `-v`, upgrades to **latest stable**.

---

### Back up

Backups include:

- Volumes: `n8n-data`, `postgres-data`, `letsencrypt`  
- PostgreSQL dump (DB and user discovered from `.env`)  
- Copies of `.env` and `docker-compose.yml`  
- Change detection via a snapshot to skip identical runs (use `-f` to force)

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

Artifacts:

- `backups/n8n_backup_<VERSION>_<YYYY-MM-DD_HH-MM-SS>.tar.gz`  
- Matching `.sha256` checksum  
- Rolling 30-day log: `backups/backup_summary.md`  
- Snapshot for change detection: `backups/snapshot/`  
- Local retention: **7 days** (archives + checksums)  
- Remote retention: **7 days** (pattern-based prune)

> Optional TLS gate: set `BACKUP_REQUIRE_TLS=true` in your environment to require a valid Traefik certificate before a backup proceeds.

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

---

### Cleanup

```bash
sudo ./n8n_manager.sh -c
```

Interactive plan to:

- `docker compose down --remove-orphans -v`  
- Remove named volumes (keeps `letsencrypt` by default; set `KEEP_CERTS=false` to delete)  
- Remove the stack network  
- Prune dangling images (optionally remove base images if `REMOVE_IMAGES=true`)

---

## Queue Mode Basics

**Why:** Separate UI/API/webhooks from execution to keep the editor responsive and scale executions horizontally.

**Architecture (Queue Mode):**

- `n8n-main` — UI, API, webhooks, schedules, queues jobs  
- `redis` — BullMQ queue backend  
- `n8n-worker`(s) — run workflow executions (scale horizontally)  
- `postgres` — workflows, credentials, executions  
- `traefik` — TLS & reverse proxy

**Common ops:**
```bash
# See queue mode is active
docker exec -it n8n-main printenv | grep EXECUTIONS_MODE  # => EXECUTIONS_MODE=queue

# Scale workers
docker compose up -d --scale n8n-worker=2

# Check health quickly
docker compose ps --format "table {{.Name}}\t{{.Status}}"
docker compose logs -f n8n-worker
```

**Sizing guidelines (starting points):**

| VPS (vCPU/RAM) | Workers x Concurrency |
|---|---|
| 1 / 2 GB | 1 × 3–5 |
| 2 / 4 GB | 1–2 × 5 |
| 4 / 8 GB | 2 × 8 |
| 8+ / 16+ GB | 3–4 × 8–10 |

> Prefer **more workers** before making a single worker’s concurrency too high.

---

## Scheduling Daily Backups

### Cron (02:00 every day)

Create a small wrapper:

```bash
sudo tee /usr/local/bin/n8n-daily-backup <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
cd /home/n8n
export SMTP_USER="you@example.com"
export SMTP_PASS="your_gmail_app_password"
# Upload to Drive and email on failure; also email on success (optional)
 /home/n8n/n8n_manager.sh -b -s gdrive:/n8n-backups -e you@example.com --notify-on-success \
  >> /home/n8n/logs/cron-backup.log 2>&1
EOF
sudo chmod +x /usr/local/bin/n8n-daily-backup
```

Add to root’s crontab:
```cron
0 2 * * * /usr/local/bin/n8n-daily-backup
```

### systemd timer (02:05 daily)

Service:
```bash
sudo tee /etc/systemd/system/n8n-backup.service >/dev/null <<'EOF'
[Unit]
Description=n8n daily backup

[Service]
Type=oneshot
WorkingDirectory=/home/n8n
Environment=SMTP_USER=you@example.com
Environment=SMTP_PASS=your_gmail_app_password
ExecStart=/home/n8n/n8n_manager.sh -b -s gdrive:/n8n-backups -e you@example.com --notify-on-success
StandardOutput=append:/home/n8n/logs/systemd-backup.log
StandardError=append:/home/n8n/logs/systemd-backup.log
EOF
```

Timer:
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

sudo systemctl daemon-reload
sudo systemctl enable --now n8n-backup.timer
```

---

## Logs & Health

- **Run logs** (manager): `logs/` under your target dir (default `/home/n8n/logs/`)  
  - `manager_n8n_<timestamp>.log`, `backup_n8n_<timestamp>.log`, `restore_n8n_<timestamp>.log`  
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
- Check Redis health: `docker compose exec redis redis-cli ping` → `PONG`  
- Ensure workers are running: `docker compose ps` and `docker compose logs -f n8n-worker`  
- If Redis auth is enabled in compose, ensure `.env` contains the same password.

---

## Security Notes

- **Keep `.env` safe** — it contains **`N8N_ENCRYPTION_KEY`** and other secrets.
- Treat backup archives as **sensitive**. They include your DB dump and configs.
- Use strong passwords and rotate tokens regularly.
- Restrict SSH access and keep your system updated.

---

## Support

- Open an issue in the repository, or  
- Email **thenguyen.ai.automation@gmail.com**

Happy automating! 🚀
