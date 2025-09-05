# n8n Manager — Install • Upgrade • Backup • Restore (Single or Queue Mode)

A production-ready way to **install**, **upgrade**, **back up**, and **restore** a self-hosted [n8n](https://n8n.io) stack on Docker — with **Traefik** (HTTPS & reverse proxy), **PostgreSQL** (persistence), and optional **Queue Mode** (Redis + workers).  
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
- [Queue Mode knowledge](#queue-mode-knowledge)
- [Scheduling Daily Backups](#scheduling-daily-backups)
- [Where to check logs](#where-to-check-logs)
- [Logs & Health](#logs--health)
- [Troubleshooting & FAQs](#troubleshooting--faqs)
- [Security Notes](#security-notes)
- [Support](#support)

---

## Highlights

- **One script, all tasks** — install, upgrade, backup/restore, and cleanup in a single CLI.
- **Mode-aware** — deploy **Single** or **Queue** mode; upgrades auto-detect the current mode.
- **Secure by default** — Traefik + Let’s Encrypt (auto-renew), strong secrets, HTTPS everywhere.
- **Resilient data** — PostgreSQL + persistent volumes; deterministic restores preserve workflows & credentials.
- **Smart version picker** — lists latest stable (or newer-than-current when running) with image tag validation.
- **Change-aware backups** — skip when nothing changed (use `-f` to force).
- **Fast, verifiable archives** — compression with `pigz` when available and SHA-256 checksums; retention pruning built-in.
- **One-command restore** — from local file or any `rclone` remote; deterministic DB rebuild (SQL dump or volume) and post-restore health checks.
- **Off-site ready** — upload archives & checksums to Google Drive or any `rclone` remote, with remote pruning.
- **Email notifications** — Gmail SMTP via `msmtp`; attach logs on failure (optional on success).
- **Strong UX & logging** — per-run logs under `logs/`, `--log-level DEBUG` tracing, graceful error/interrupt traps, and a rolling `backups/backup_summary.md` dashboard.

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
    │   ├── install_n8n_<ts>.log
    │   ├── upgrade_n8n_<ts>.log
    │   ├── backup_n8n_<ts>.log
    │   ├── restore_n8n_<ts>.log
    │   └── latest_<action>.log    # symlink per action (install/upgrade/backup/restore/cleanup)
    └── /home/n8n/backups/         # Backup archives, checksums, summary, snapshot
```

> **Templates:** Installation copies the selected template (`single-mode/` or `queue-mode/`) into your target directory and pins your chosen **n8n version**, **domain**, **SSL email**, and **secrets**.

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
Domain:                  https://n8n.example.com
Installed Version:       1.110.1
Install Timestamp:       2025-09-04_14-35-55
Installed By:            root
Target Directory:        /home/n8n
SSL Email:               thenguyen.ai.automation@gmail.com
Execution log:           /home/n8n/logs/install_n8n_2025-09-04_14-35-55.log
═════════════════════════════════════════════════════════════
```

Example logs for queue mode:

```
═════════════════════════════════════════════════════════════
N8N has been successfully installed!
Installation Mode:       queue
Domain:                  https://n8n.example.com
Installed Version:       1.110.1
Install Timestamp:       2025-09-04_15-23-17
Installed By:            root
Target Directory:        /home/n8n
SSL Email:               thenguyen.au.automation@gmail.com
Execution log:           /home/n8n/logs/install_n8n_2025-09-04_15-23-17.log
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
sudo ./n8n_manager.sh --upgrade n8n.example.com
```

**Upgrade to a specific version:**
```bash
sudo ./n8n_manager.sh --upgrade n8n.example.com -v 1.107.3
```

**Downgrade or force redeploy of the same version:**
```bash
sudo ./n8n_manager.sh --upgrade n8n.example.com -v 1.107.2 -f
```

**Notes:**

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

- Backs up Docker **volumes**: `n8n-data`, `postgres-data`, `letsencrypt`
- Creates a **PostgreSQL dump** (from the `postgres` container, DB `n8n`)
- Copies of `.env` and `docker-compose.yml`  
- **Skips** backup automatically if nothing has changed (unless you force it)
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
Detected Mode:           single
Domain:                  https://n8n.example.com
Backup Action:           Backup (forced)
Backup Status:           SUCCESS
Backup Timestamp:        2025-09-04_15-20-02
Backup file:             /home/n8n/backups/n8n_backup_1.110.1_2025-09-04_15-20-02.tar.gz
N8N Version:             1.110.1
N8N Directory:           /home/n8n
Log File:                /home/n8n/logs/backup_n8n_2025-09-04_15-20-02.log
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
Detected Mode:           single
Domain:                  https://n8n.example.com
Restore from file:       /home/n8n/backups/n8n_backup_1.110.1_2025-09-04_14-50-40.tar.gz
Local archive used:      /home/n8n/backups/n8n_backup_1.110.1_2025-09-04_14-50-40.tar.gz
Restore Timestamp:       2025-09-04_15-20-51
N8N Version:             1.110.1
N8N Directory:           /home/n8n
Log File:                /home/n8n/logs/restore_n8n_2025-09-04_15-20-51.log
Volumes restored:        letsencrypt, n8n-data
PostgreSQL:              Restored from SQL dump
═════════════════════════════════════════════════════════════
```
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

## Queue Mode knowledge

👉 For details about queue mode, see the full guide: [**n8n-queue-mode**](https://github.com/thenguyenvn90/n8n-queue-mode/blob/main/README.md)

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
/opt/n8n-toolkit/n8n_manager.sh -b -d /home/n8n -s gdrive:/n8n-backups -e you@YourDomain.com --notify-on-success >> /opt/n8n-toolkit/logs/cron.log 2>&1
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
15 2 * * 0 /opt/n8n-toolkit/run_backup.sh
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

- **Run logs** (manager): `logs/` under your target dir (default `/home/n8n/logs/`)  
  - `install_n8n_<timestamp>.log`, `upgrade_n8n_<timestamp>.log`, `backup_n8n_<timestamp>.log`, `restore_n8n_<timestamp>.log`, `cleanup_n8n_<timestamp>.log`, symlink `latest_<mode>.log`.

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