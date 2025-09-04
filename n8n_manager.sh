#!/bin/bash
set -euo pipefail
set -o errtrace
IFS=$'\n\t'

#############################################################################################
# N8N Installation, Upgrade, Backup & Restore Manager (Mode-aware: Single or Queue)
# Author:      TheNguyen
# Email:       thenguyen.ai.automation@gmail.com
# Version:     2.0.0
# Date:        2025-09-04
#
# Description:
#   A unified management tool for installing, upgrading, backing up, and restoring the
#   n8n automation stack running on Docker Compose with Traefik + Let's Encrypt, supporting
#   BOTH "single" mode and "queue" mode. For install, --mode defaults to "single". For other
#   actions, the current mode is auto-detected from compose and containers.
#
# Key features:
#   - Install:
#       * --mode {single|queue} (default: single) chooses template folder (single-mode/ or queue-mode/)
#       * Validates DNS, installs Docker/Compose if missing, pins version, generates secrets
#       * Brings stack up, waits for health, prints a summary
#   - Upgrade:
#       * No mode needed; auto-detects from current compose
#       * Pulls/validates target version, redeploys safely (downgrade with -f)
#   - Backup / Restore:
#       * No mode needed; discovers services, volumes, and containers dynamically
#       * Full local backup of Docker volumes, PostgreSQL dump, and configs
#       * Change detection snapshot to skip redundant backups (use -f to force)
#       * Optional email notifications via Gmail SMTP (msmtp)
#       * Optional upload to Google Drive (or any rclone remote)
#       * Restore from local archive or rclone remote path (remote:folder/file.tar.gz)
#############################################################################################

# ------------------------------------- Globals --------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load shared helpers
COMMON_FILE="$SCRIPT_DIR/common.sh"
if [[ -f "$COMMON_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$COMMON_FILE"
else
    echo "[ERROR] Missing common library: $COMMON_FILE" >&2
    exit 1
fi

TEMPLATE_SINGLE="$SCRIPT_DIR/single-mode"
TEMPLATE_QUEUE="$SCRIPT_DIR/queue-mode"

DEFAULT_N8N_DIR="/home/n8n"
N8N_DIR="$DEFAULT_N8N_DIR"
ENV_FILE=""
COMPOSE_FILE=""

# Actions
DO_INSTALL=false
DO_UPGRADE=false
DO_BACKUP=false
DO_RESTORE=false
DO_CLEANUP=false
DO_AVAILABLE=false

# Install-only
INSTALL_MODE="single"
DOMAIN=""
SSL_EMAIL=""

# Upgrade/Install shared
N8N_VERSION="latest"
FORCE_FLAG=false

# Backup/Restore
TARGET_RESTORE_FILE=""
DAYS_TO_KEEP=7
POSTGRES_SERVICE="${POSTGRES_SERVICE:-postgres}"

# Email (msmtp) - notification recipient (separate from SSL_EMAIL)
EMAIL_TO=""
EMAIL_EXPLICIT=false
NOTIFY_ON_SUCCESS=false
SMTP_USER="${SMTP_USER:-}"
SMTP_PASS="${SMTP_PASS:-}"
EMAIL_SENT=false

# rclone remote path (e.g. gdrive:/n8n-backups)
RCLONE_REMOTE=""
RCLONE_FLAGS=(--transfers=4 --checkers=8 --retries=5 --low-level-retries=10 --contimeout=30s --timeout=5m --retries-sleep=10s)
# Run apt-get update only once across calls (used by require_cmd in common)
APT_UPDATED=false

# Logs & run context
LOG_LEVEL="${LOG_LEVEL:-INFO}"
DATE="$(date +%F_%H-%M-%S)"
LOG_FILE=""
BACKUP_DIR=""
LOG_DIR=""
ACTION=""
BACKUP_STATUS=""
UPLOAD_STATUS=""
BACKUP_FILE=""
DRIVE_LINK=""

# Auto-discovery caches (shadowed locally to avoid collisions)
declare -a DISCOVERED_SERVICES=()
declare -a DISCOVERED_VOLUMES=()
declare -a DISCOVERED_VOLUME_EXTERNAL=()
declare -a DISCOVERED_CONTAINER_NAMES=()

DISCOVERED_MODE="unknown"

declare -a RUNNING_CONTAINER_NAMES=()
declare -A __SERVICE_TO_CONTAINER_HINT=()

# ---------- Compose discovery cache ----------
_DISCOVERY_SIG=""
DISCOVERY_VALID=false

# Defer detailed reporting to common on_error; also handle interrupts
trap on_error ERR
trap on_interrupt INT TERM HUP

################################################################################
# usage()
# Description:
#   Print CLI help and exit.
#
# Behaviors:
#   - Shows mode flag only (optional) for install path (default single).
#   - Shows dynamic behavior for other actions.
#
# Returns:
#   Exits 1.
################################################################################
usage() {
    cat <<EOF
Usage: $0 [ONE ACTION] [OPTIONS]

Actions (choose exactly one):
  -a, --available
        List available n8n versions

  -i, --install <DOMAIN>
        Install n8n with the given domain
        Optional: --mode single|queue  (default: single)
        Optional: -v|--version <tag>

  -u, --upgrade <DOMAIN>
        Upgrade n8n to target version (or latest)

  -b, --backup
        Run backup (skip if no changes unless -f)

  -r, --restore <FILE_OR_REMOTE>
        Restore from local file or rclone remote (e.g. gdrive:folder/file.tar.gz)

  -c, --cleanup
        Stop stack, remove volumes/images (interactive confirm)

Options:
  --mode <single|queue>     (install only; default: single)
  -v, --version <tag>       Target n8n version (default: latest stable)
  -m, --ssl-email <email>   LE certificate email (install/upgrade)
  -d, --dir <path>          Target n8n directory (default: /home/n8n)
  -l, --log-level <LEVEL>   DEBUG | INFO (default) | WARN | ERROR
  -f, --force               Upgrade: allow downgrade or redeploy; Backup: force even if unchanged
  -e, --email-to <email>    Send notifications to this address (requires SMTP_USER/SMTP_PASS env)
  -n, --notify-on-success   Also email on success (not just failures)
  -s, --remote-name <name>  rclone remote root (e.g. gdrive-user or gdrive-user:/n8n-backups)
  -h, --help                Show this help

Examples:
  $0 -a
      # List available versions

  $0 --install n8n.example.com -m you@example.com
      # Install the latest n8n version with single mode

  $0 --install n8n.example.com -m you@example.com -v 1.105.3 --mode queue
      # Install a specific n8n version with queue mode

  $0 --install n8n.example.com -m you@example.com -d /path/to/n8n --mode queue
      # Install the latest n8n version (queue mode) to a specific target directory

  $0 --upgrade n8n.example.com
      # Upgrade to the latest n8n version

  $0 --upgrade n8n.example.com -f -v 1.107.2
      # Upgrade to a specific n8n version

  $0 --backup --remote-name gdrive-user --email-to ops@example.com --notify-on-success
      # Backup and upload to Google Drive, notify via email

  $0 --restore backups/your_backup_file.tar.gz
      # Restore with the tar.gz file at local
EOF
    exit 1
}

################################################################################
# set_paths()
# Description:
#   Compute important paths for the chosen/target directory.
#
# Behaviors:
#   - Sets ENV_FILE, COMPOSE_FILE, BACKUP_DIR, LOG_DIR, LOG_FILE.
#   - Creates logs/ and backups/ if missing.
#
# Returns:
#   0 always.
################################################################################
set_paths() {
    ENV_FILE="$N8N_DIR/.env"
    COMPOSE_FILE="$N8N_DIR/docker-compose.yml"
    mkdir -p "$N8N_DIR/logs" "$N8N_DIR/backups"
    BACKUP_DIR="$N8N_DIR/backups"
    LOG_DIR="$N8N_DIR/logs"

    local mode="manager"
    $DO_BACKUP  && mode="backup"
    $DO_RESTORE && mode="restore"
    LOG_FILE="$N8N_DIR/logs/${mode}_n8n_${DATE}.log"

    exec > >(tee -a "$LOG_FILE") 2>&1
    log INFO "Working directory: $N8N_DIR"
    log INFO "Logging to: $LOG_FILE"
}

################################################################################
# install_prereqs()
# Description:
#   Install Docker Engine and Compose v2 on Ubuntu with safe fallbacks.
#
# Behaviors:
#   - If Docker present → skip install.
#   - Else add Docker apt repo & key, install engine + compose plugin.
#   - Fallback to get.docker.com script if apt install fails.
#   - Installs common dependencies (jq, rsync, tar, msmtp, dnsutils, openssl, pigz).
#   - Enables & starts docker via systemd if available.
#   - Adds invoking user to docker group.
#
# Returns:
#   0 on success (best-effort with fallbacks).
################################################################################
install_prereqs() {
    if command -v docker >/dev/null 2>&1 && docker version >/dev/null 2>&1; then
        log INFO "Docker already installed. Skipping Docker install."
    else
        log INFO "Installing prerequisites (curl, ca-certificates, gpg, lsb-release)…"
        DEBIAN_FRONTEND=noninteractive apt-get update -y
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl gnupg lsb-release

        log INFO "Adding Docker GPG key (non-interactive)…"
        mkdir -p /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
            | gpg --dearmor | tee /etc/apt/keyrings/docker.gpg > /dev/null
        chmod a+r /etc/apt/keyrings/docker.gpg

        log INFO "Adding Docker repository…"
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
            https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
            | tee /etc/apt/sources.list.d/docker.list > /dev/null
        DEBIAN_FRONTEND=noninteractive apt-get update -y

        log INFO "Installing Docker Engine and Docker Compose v2…"
        if ! DEBIAN_FRONTEND=noninteractive apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
            log WARN "APT install from Docker repo failed. Falling back to official convenience script…"
            curl -fsSL https://get.docker.com | sh
        fi
    fi

    log INFO "Installing required dependencies…"
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        jq vim rsync tar msmtp dnsutils openssl pigz

    # Make sure the daemon is running/enabled
    if command -v systemctl >/dev/null 2>&1; then
        systemctl enable --now docker || true
    fi

    local CURRENT_USER=${SUDO_USER:-$(whoami)}
    if [[ "$CURRENT_USER" != "root" ]]; then
        log INFO "Adding user '$CURRENT_USER' to the docker group…"
        usermod -aG docker "$CURRENT_USER" || true
    fi

    log INFO "Docker and dependencies installed."
}

################################################################################
# prompt_ssl_email()
# Description:
#   Prompt operator for Let's Encrypt email if not given.
#
# Behaviors:
#   - Simple regex validation; loops until ok.
#
# Returns:
#   0 after exporting SSL_EMAIL.
################################################################################
prompt_ssl_email() {
    while true; do
        read -e -p "Enter your email address (used for SSL cert): " SSL_EMAIL
        if [[ "$SSL_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            export SSL_EMAIL
            break
        else
            log ERROR "Invalid email. Please try again."
        fi
    done
}

################################################################################
# copy_templates_for_mode()
# Description:
#   Copy docker-compose.yml and .env from the selected template (single|queue).
#
# Behaviors:
#   - Backs up existing files with timestamp.
#   - Updates DOMAIN, SSL_EMAIL, N8N_IMAGE_TAG in .env.
#   - Generates STRONG_PASSWORD and N8N_ENCRYPTION_KEY if placeholders found.
#
# Returns:
#   0 on success; exits non-zero on missing templates.
################################################################################
copy_templates_for_mode() {
    local src_dir=""
    case "$INSTALL_MODE" in
        single) src_dir="$TEMPLATE_SINGLE" ;;
        queue)  src_dir="$TEMPLATE_QUEUE" ;;
        *) log ERROR "--mode must be 'single' or 'queue'"; exit 2 ;;
    esac

    if [[ ! -f "$src_dir/docker-compose.yml" ]]; then
        log ERROR "docker-compose.yml not found at $src_dir"
        exit 1
    fi

    if [[ ! -f "$src_dir/.env" ]]; then
        log ERROR ".env file not found at $src_dir"
        exit 1
    fi

    for f in docker-compose.yml .env; do
        [[ -f "$N8N_DIR/$f" ]] && cp -a "$N8N_DIR/$f" "$N8N_DIR/${f}.bak.$(date +%F_%H-%M-%S)"
        cp -a "$src_dir/$f" "$N8N_DIR/$f"
    done

    # Update .env
    log INFO "Updating .env with DOMAIN, SSL_EMAIL and N8N_IMAGE_TAG…"
    upsert_env_var "DOMAIN" "$DOMAIN" "$ENV_FILE"
    [[ -n "${SSL_EMAIL:-}" ]] && upsert_env_var "SSL_EMAIL" "$SSL_EMAIL" "$ENV_FILE"

    # Resolve target version: explicit -v wins; else latest stable
    local target_version="${N8N_VERSION}"
    if [[ -z "$target_version" || "$target_version" == "latest" ]]; then
        target_version="$(get_latest_n8n_version)"
        [[ -z "$target_version" ]] && { log ERROR "Could not determine latest n8n tag."; exit 1; }
    fi

    validate_image_tag "$target_version" || {
        log ERROR "Image tag not found on docker.n8n.io or docker.io: $target_version"
        exit 1
    }

    # Pin the tag into .env (insert or update)
    log INFO "Installing n8n version: $target_version"
    log INFO "Updating .env with N8N_IMAGE_TAG=$target_version"
    upsert_env_var "N8N_IMAGE_TAG" "$target_version" "$ENV_FILE"

    # Rotate STRONG_PASSWORD if missing/default
    local password_line
    password_line=$(awk -F= '/^STRONG_PASSWORD=/{print $2; found=1} END{if(!found) print ""}' "$ENV_FILE")
    if [[ "$password_line" == "CHANGE_ME_BASE64_16_BYTES" || -z "$password_line" ]]; then
        local new_password
        new_password="$(openssl rand -base64 16)"
        log INFO "Setting STRONG_PASSWORD in .env"
        upsert_env_var "STRONG_PASSWORD" "${new_password}" "$ENV_FILE"
    else
        log INFO "Existing STRONG_PASSWORD found. Not modifying it."
    fi

    # Rotate N8N_ENCRYPTION_KEY if missing/default
    local enc_key_line
    enc_key_line=$(awk -F= '/^N8N_ENCRYPTION_KEY=/{print $2; found=1} END{if(!found) print ""}' "$ENV_FILE")
    if [[ -z "$enc_key_line" || "$enc_key_line" == "CHANGE_ME_BASE64_32_BYTES" ]]; then
        local new_key
        new_key="$(openssl rand -base64 32)"
        log INFO "Setting N8N_ENCRYPTION_KEY in .env"
        upsert_env_var "N8N_ENCRYPTION_KEY" "${new_key}" "$ENV_FILE"
    else
        log INFO "Existing N8N_ENCRYPTION_KEY found. Not modifying it."
    fi

    # Secure secrets file
    chmod 600 "$ENV_FILE" || true
    chmod 640 "$COMPOSE_FILE" || true
}

################################################################################
# print_summary_message()
# Description:
#   Print a human-friendly final summary after install/upgrade.
#
# Behaviors:
#   - Loads .env for current context.
#   - Prints domain URL, detected n8n version, timestamp, user, target dir,
#     SSL email (if set), and log file path.
#
# Returns:
#   0 always.
################################################################################
print_summary_message() {
    echo "═════════════════════════════════════════════════════════════"
    if $DO_INSTALL; then
        echo "N8N has been successfully installed!"
    elif $DO_UPGRADE; then
        echo "N8N has been successfully upgraded!"
    fi
    box_line "Mode:"               "$INSTALL_MODE"
    box_line "Domain:"             "https://${DOMAIN}"
    box_line "Installed Version:"  "$(get_current_n8n_version)"
    box_line "Install Timestamp:"  "$(date "+%Y-%m-%d %H:%M:%S")"
    box_line "Installed By:"       "${SUDO_USER:-$USER}"
    box_line "Target Directory:"   "$N8N_DIR"
    box_line "SSL Email:"          "${SSL_EMAIL:-N/A}"
    box_line "Execution log:"      "${LOG_FILE}"
    echo "═════════════════════════════════════════════════════════════"
}

################################################################################
# install_stack()
# Description:
#   Orchestrate a fresh installation of the n8n stack behind Traefik/LE.
#
# Behaviors:
#   - --mode is optional; defaults to 'single'.
#   - Prompts for SSL_EMAIL if missing.
#   - Verifies DOMAIN DNS points to this host (check_domain()).
#   - Installs Docker/Compose and dependencies (install_prereqs()).
#   - Prepares compose + .env with pinned version and secrets (copy_templates_for_mode()).
#   - Validates compose/env (validate_compose_and_env()).
#   - Creates volumes as needed and starts stack (docker_up_check()).
#   - Waits for containers and TLS to be healthy (check_services_up_running()).
#   - Prints a summary on success.
#
# Returns:
#   0 on success; exits non-zero if any step fails.
################################################################################
install_stack() {
    [[ -n "$DOMAIN" ]] || { log ERROR "Install requires a domain."; exit 2; }
    log INFO "Starting N8N installation for domain: $DOMAIN"
    [[ -z "${SSL_EMAIL:-}" ]] && prompt_ssl_email
    check_domain
    install_prereqs
    copy_templates_for_mode
    validate_compose_and_env
    load_env_file
    discover_from_compose
    ensure_external_volumes
    docker_up_check || { log ERROR "Stack unhealthy after install."; exit 1; }
    print_summary_message
}

################################################################################
# upgrade_stack()
# Description:
#   Upgrade (or force re-deploy/downgrade with -f) the running n8n stack.
#
# Behaviors:
#   - Detects current n8n version; resolves target:
#       * explicit -v, else latest stable via get_latest_n8n_version()
#   - Prevents downgrades unless --force; prevents no-op redeploy unless --force.
#   - Validates target tag with validate_image_tag().
#   - Writes N8N_IMAGE_TAG to .env; brings stack down (compose down).
#   - Re-validates compose/env; brings stack up; waits for health & TLS.
#   - Prints a summary on success.
#
# Returns:
#   0 on success; exits non-zero on validation/health failures.
################################################################################
upgrade_stack() {
    [[ -f "$ENV_FILE" && -f "$COMPOSE_FILE" ]] || { log ERROR "Compose/.env not found in $N8N_DIR"; exit 1; }
    load_env_file
    log INFO "Checking current and latest n8n versions..."
    cd "$N8N_DIR"

    local current_version target_version
    current_version=$(get_current_n8n_version || echo "0.0.0")
    # Decide target version
    target_version="$N8N_VERSION"
    if [[ -z "$target_version" || "$target_version" == "latest" ]]; then
        target_version=$(get_latest_n8n_version)
        [[ -z "$target_version" ]] && { log ERROR "Could not determine latest n8n tag."; exit 1; }
    fi

    log INFO "Current version: $current_version  ->  Target version: $target_version"

    # Refuse to downgrade unless -f
    if [[ "$(printf "%s\n%s" "$target_version" "$current_version" | sort -V | head -n1)" == "$target_version" \
          && "$target_version" != "$current_version" \
          && "$FORCE_FLAG" != true ]]; then
        log INFO "Target ($target_version) <= current ($current_version). Use -f to force downgrade."
        exit 0
    fi

    # If same version, allow redeploy only with -f
    if [[ "$target_version" == "$current_version" && "$FORCE_FLAG" != true ]]; then
        log INFO "Already on $current_version. Use -f to force redeploy."
        exit 0
    fi

    # Validate tag exists (either registry)
    validate_image_tag "$target_version" || { log ERROR "Image tag not found: $target_version"; exit 1; }

    # Pin the tag into .env (insert or update)
    upsert_env_var "N8N_IMAGE_TAG" "$target_version" "$ENV_FILE"

    log INFO "Stopping and removing existing containers..."
    compose down --remove-orphans || true

    validate_compose_and_env
    discover_from_compose
    docker_up_check || { log ERROR "Stack unhealthy after upgrade."; exit 1; }
    print_summary_message
}

################################################################################
# snapshot_bootstrap()
# Description:
#   Create the initial snapshot tree for change detection.
#
# Behaviors:
#   - Creates snapshot directories for each volume and for config.
#   - Rsyncs current data of volumes and config (.env, docker-compose.yml).
#   - Skips if snapshot already exists.
#
# Returns:
#   0 on success; non-zero on failure.
################################################################################
snapshot_bootstrap() {
    local snap="$BACKUP_DIR/snapshot"
    [[ -d "$snap" ]] || mkdir -p "$snap/volumes" "$snap/config"

    local vol
    for vol in "${DISCOVERED_VOLUMES[@]}"; do
        mkdir -p "$snap/volumes/$vol"
        rsync -a "/var/lib/docker/volumes/${vol}/_data/" "$snap/volumes/$vol/" || true
    done
    [[ -f "$ENV_FILE" ]] && rsync -a "$ENV_FILE" "$snap/config/" || true
    [[ -f "$COMPOSE_FILE" ]] && rsync -a "$COMPOSE_FILE" "$snap/config/" || true
}

################################################################################
# snapshot_refresh()
# Description:
#   Refresh snapshot after successful backup.
#
# Behaviors:
#   - Rsync with --delete for each discovered volume and config.
#
# Returns:
#   0 on success.
################################################################################
snapshot_refresh() {
    local snap="$BACKUP_DIR/snapshot"
    mkdir -p "$snap/volumes" "$snap/config"
    local vol
    for vol in "${DISCOVERED_VOLUMES[@]}"; do
        rsync -a --delete \
            --exclude='pg_wal/**' --exclude='pg_stat_tmp/**' --exclude='pg_logical/**' \
            "/var/lib/docker/volumes/${vol}/_data/" "$snap/volumes/$vol/" || true
    done
    [[ -f "$ENV_FILE" ]] && rsync -a --delete "$ENV_FILE" "$snap/config/" || true
    [[ -f "$COMPOSE_FILE" ]] && rsync -a --delete "$COMPOSE_FILE" "$snap/config/" || true
}

################################################################################
# is_changed_since_snapshot()
# Description:
#   Determine if live data differs from the snapshot (to decide backup).
#
# Behaviors:
#   - For each volume: rsync dry-run with excludes (pg_wal, pg_stat_tmp, pg_logical).
#   - For configs: rsync dry-run on .env and docker-compose.yml (only if they exist).
#   - Creates snapshot target dirs if missing.
#   - If any file changes detected → considered "changed".
#
# Returns:
#   0 if changed; 1 if no differences.
################################################################################
is_changed_since_snapshot() {
    local snap="$BACKUP_DIR/snapshot"
    mkdir -p "$snap/volumes" "$snap/config"
    local vol diffs

    for vol in "${DISCOVERED_VOLUMES[@]}"; do
        diffs="$(rsync -rtun \
            --exclude='pg_wal/**' --exclude='pg_stat_tmp/**' --exclude='pg_logical/**' \
            "/var/lib/docker/volumes/${vol}/_data/" "$snap/volumes/$vol/" | grep -v '/$' || true)"
        if [[ -n "$diffs" ]]; then
            log INFO "Change detected in volume: $vol"
            log DEBUG "  $diffs"
            return 0
        fi
    done

    local f
    for f in "$ENV_FILE" "$COMPOSE_FILE"; do
        [[ -f "$f" ]] || continue
        diffs="$(rsync -rtun --out-format="%n" "$f" "$snap/config/" | grep -v '/$' || true)"
        if [[ -n "$diffs" ]]; then
            log INFO "Change detected in config: $f"
            log DEBUG "  $diffs"
            return 0
        fi
    done

    # No differences found
    return 1
}

################################################################################
# do_local_backup()
# Description:
#   Execute local backup: volumes, Postgres dump, config copy, compress, checksum.
#
# Behaviors:
#   - Verifies N8N_ENCRYPTION_KEY exists in .env.
#   - Archives each Docker volume to BACKUP_PATH as tar.gz chunks.
#   - Dumps Postgres DB from container "postgres" to SQL file.
#   - Copies .env and docker-compose.yml as *.bak.
#   - Compresses BACKUP_PATH into BACKUP_DIR/n8n_backup_<ver>_<ts>.tar.gz
#       * Uses `tar | pigz` if pigz exists; else `tar -czf`.
#   - Generates SHA-256 checksum for the archive.
#   - Prunes old archives/checksums older than DAYS_TO_KEEP.
#
# Returns:
#   0 on success; non-zero on any failure.
################################################################################
do_local_backup() {
    ensure_encryption_key || return 1

    local BACKUP_PATH="$BACKUP_DIR/backup_$DATE"
    mkdir -p "$BACKUP_PATH"

    log INFO "Starting backup at $DATE..."
    log INFO "Backing up ./local-files directory..."
    if [[ -d "$N8N_DIR/local-files" ]]; then
        tar -czf "$BACKUP_PATH/local-files_$DATE.tar.gz" -C "$N8N_DIR" local-files \
            || { log ERROR "Failed to backup local-files directory"; return 1; }
        log INFO "local-files directory backed up"
    else
        log INFO "No local-files directory found, skipping..."
    fi

    log INFO "Backing up Docker volumes..."
    local vol
    for vol in "${DISCOVERED_VOLUMES[@]}"; do
        if ! docker volume inspect "$vol" &>/dev/null; then
            log ERROR "Volume $vol not found"
            return 1
        fi
        local vol_backup="volume_${vol}_$DATE.tar.gz"
        docker run --rm \
            -v "${vol}:/data" \
            -v "$BACKUP_PATH:/backup" \
            alpine \
            sh -c "tar czf /backup/$vol_backup -C /data ." \
            || { log ERROR "Failed to archive volume $vol"; return 1; }
        log INFO "Volume '$vol' backed up: $vol_backup"
    done

    log INFO "Dumping PostgreSQL database..."
    local DB_USER="${DB_POSTGRESDB_USER:-${POSTGRES_USER:-n8n}}"
    local DB_NAME="${DB_POSTGRESDB_DATABASE:-${POSTGRES_DB:-n8n}}"
    local pgcid; pgcid="$(container_id_for_service "$POSTGRES_SERVICE")"

    if [[ -z "$pgcid" ]]; then
        log ERROR "Postgres service '$POSTGRES_SERVICE' is not running"
        return 1
    fi

    if docker exec "$pgcid" pg_isready &>/dev/null; then
        docker exec "$pgcid" pg_dump -U "$DB_USER" -d "$DB_NAME" > "$BACKUP_PATH/n8n_postgres_dump_$DATE.sql" \
            || { log ERROR "Postgres dump failed"; return 1; }
        log INFO "Database dump saved to $BACKUP_PATH/n8n_postgres_dump_$DATE.sql"
    else
        log ERROR "Postgres not ready ($POSTGRES_SERVICE)"
        return 1
    fi

    log INFO "Backing up .env and docker-compose.yml..."
    cp "$ENV_FILE" "$BACKUP_PATH/.env.bak"
    cp "$COMPOSE_FILE" "$BACKUP_PATH/docker-compose.yml.bak"

    log INFO "Compressing backup folder..."
    BACKUP_FILE="n8n_backup_${N8N_VERSION}_${DATE}.tar.gz"

    if command -v pigz >/dev/null 2>&1; then
        tar -C "$BACKUP_PATH" -cf - . | pigz > "$BACKUP_DIR/$BACKUP_FILE" \
            || { log ERROR "Failed to compress backup with pigz"; return 1; }
    else
        tar -czf "$BACKUP_DIR/$BACKUP_FILE" -C "$BACKUP_PATH" . \
            || { log ERROR "Failed to compress backup with gzip"; return 1; }
    fi
    log INFO "Created archive -> $BACKUP_DIR/$BACKUP_FILE"

    # sha256 checksum
    if [[ -f "$BACKUP_DIR/$BACKUP_FILE" ]]; then
        sha256sum "$BACKUP_DIR/$BACKUP_FILE" > "$BACKUP_DIR/$BACKUP_FILE.sha256" \
            || { log ERROR "Failed to write checksum"; return 1; }
    else
        log ERROR "Archive not found after compression: $BACKUP_DIR/$BACKUP_FILE"
        return 1
    fi
    log INFO "Created checksum -> $BACKUP_DIR/$BACKUP_FILE.sha256"

    log INFO "Cleaning up local backups older than $DAYS_TO_KEEP days..."
    rm -rf "$BACKUP_PATH"
    find "$BACKUP_DIR" -type f -name "*.tar.gz" -mtime +$DAYS_TO_KEEP -exec rm -f {} \;
    find "$BACKUP_DIR" -type f -name "*.sha256" -mtime +$DAYS_TO_KEEP -exec rm -f {} \;
    find "$BACKUP_DIR" -maxdepth 1 -type d -name 'backup_*' -empty -exec rmdir {} \;
    log INFO "Removed any empty backup_<timestamp> folders"
    return 0
}

################################################################################
# upload_backup_rclone()
# Description:
#   Upload the archive, its checksum, and backup_summary.md to rclone remote,
#   then prune remote old files.
#
# Behaviors:
#   - If RCLONE_REMOTE is empty → sets UPLOAD_STATUS=SKIPPED and returns 0.
#   - Uploads files via `rclone copyto` to remote root.
#   - Sets UPLOAD_STATUS=SUCCESS on success; FAIL on any upload error.
#   - Prunes remote files older than DAYS_TO_KEEP by filter (keeps recent ones).
#
# Returns:
#   0 on full success; non-zero if upload failed (prune still attempted).
################################################################################
upload_backup_rclone() {
    if [[ -z "$RCLONE_REMOTE" ]]; then
        UPLOAD_STATUS="SKIPPED"; return 0
    fi
    require_cmd rclone || { UPLOAD_STATUS="FAIL"; return 1; }

    # Normalize remote (force one colon)
    local REMOTE="${RCLONE_REMOTE%:}:"
    log INFO "Uploading backup files directly to remote root ($REMOTE)"

    if  rclone copyto "$BACKUP_DIR/$BACKUP_FILE" "$REMOTE/$BACKUP_FILE" "${RCLONE_FLAGS[@]}" \
        && rclone copyto "$BACKUP_DIR/$BACKUP_FILE.sha256" "$REMOTE/$BACKUP_FILE.sha256" "${RCLONE_FLAGS[@]}" \
        && rclone copyto "$BACKUP_DIR/backup_summary.md" "$REMOTE/backup_summary.md" "${RCLONE_FLAGS[@]}"; then
        UPLOAD_STATUS="SUCCESS"
        log INFO "Uploaded '$BACKUP_FILE', checksum and 'backup_summary.md' successfully."
    else
        UPLOAD_STATUS="FAIL"
        log ERROR "One or more uploads failed"
    fi

    # Safer remote prune
    log INFO "Pruning remote archives older than ${DAYS_TO_KEEP:-7} days (pattern: n8n_backup_*.tar.gz)"
    local tmpfilter; tmpfilter="$(mktemp)"
    printf "%s\n" "+ n8n_backup_*.tar.gz" "+ n8n_backup_*.tar.gz.sha256" "- *" > "$tmpfilter"
    rclone delete "$REMOTE" --min-age "${DAYS_TO_KEEP:-7}d" --filter-from "$tmpfilter" --rmdirs \
        || log WARN "Remote prune returned non-zero (continuing)."
    rm -f "$tmpfilter"

    [[ "$UPLOAD_STATUS" == "SUCCESS" ]]
}

################################################################################
# write_summary_row()
# Description:
#   Append action/status to backup_summary.md and prune entries >30 days old.
#
# Behaviors:
#   - Creates header if file is missing.
#   - Appends a table row: DATE | ACTION | N8N_VERSION | STATUS.
#   - Keeps only rows with DATE >= cutoff (30 days ago), preserving header.
#
# Returns:
#   0 on success; non-zero on failure.
################################################################################
write_summary_row() {
    local action="$1" status="$2"
    local version="$N8N_VERSION"
    local file="$BACKUP_DIR/backup_summary.md"
    local now; now="$DATE"
    local cutoff; cutoff=$(date -d '30 days ago' '+%F')

    # If the file doesn't exist, write the markdown table header
    if [[ ! -f "$file" ]]; then
        cat >> "$file" <<'EOF'
| DATE               | ACTION         | N8N_VERSION | STATUS   |
|--------------------|----------------|-------------|----------|
EOF
    fi

    # Append a new row
    printf "| %s | %s | %s | %s |\n" "$now" "$action" "$version" "$status" >> "$file"

    # Prune rows older than 30 days (match YYYY-MM-DD at start of each row)
    # We'll keep the header plus any rows whose DATE ≥ cutoff
    {
        # print header
        head -n2 "$file"
        # filter data rows
        tail -n +3 "$file" \
            | awk -v cut="$cutoff" -F'[| ]+' '$2 >= cut'
    } > "${file}.tmp" && mv "${file}.tmp" "$file"
}

################################################################################
# can_send_email()
# Description:
#   Check whether SMTP config is sufficient to send email.
#
# Behaviors:
#   - Verifies EMAIL_TO, SMTP_USER, SMTP_PASS are all non-empty.
#
# Returns:
#   0 if all present; 1 otherwise.
################################################################################
can_send_email() {
    [[ "$EMAIL_EXPLICIT" == true && -n "$SMTP_USER" && -n "$SMTP_PASS" && -n "$EMAIL_TO" ]]
}

################################################################################
# send_email()
# Description:
#   Send a multipart email via Gmail SMTP (msmtp), optional attachment.
#
# Behaviors:
#   - No-op if EMAIL_EXPLICIT=false.
#   - Validates SMTP creds; logs error and returns non-zero if missing.
#   - Builds multipart MIME with text body and optional base64 attachment.
#   - Pipes message to msmtp with STARTTLS (smtp.gmail.com:587).
#   - Sets EMAIL_SENT=true on success.
#
# Returns:
#   0 on success; non-zero if send fails.
################################################################################
send_email() {
    local subject="$1"
    local body="$2"
    local attachment="${3:-}"

    if ! $EMAIL_EXPLICIT; then
        # user never asked → silently skip
        return 0
    fi

    if ! can_send_email; then
        log ERROR "Email requested (-e) but SMTP_USER/SMTP_PASS not set → cannot send email."
        return 1
    fi

    log INFO "Sending email to: $EMAIL_TO"

    # Prepare password securely for passwordeval
    local pass_tmp
    pass_tmp="$(mktemp)"
    printf '%s' "$SMTP_PASS" > "$pass_tmp"
    chmod 600 "$pass_tmp"

    local boundary="=====n8n_backup_$(date +%s)_$$====="
    {
        echo "From: $SMTP_USER"
        echo "To: $EMAIL_TO"
        echo "Subject: $subject"
        echo "MIME-Version: 1.0"
        echo "Content-Type: multipart/mixed; boundary=\"$boundary\""
        echo
        echo "--$boundary"
        echo "Content-Type: text/plain; charset=UTF-8"
        echo "Content-Transfer-Encoding: 7bit"
        echo
        echo "$body"
        echo

        if [[ -n "$attachment" && -f "$attachment" ]]; then
            local filename
            filename="$(basename "$attachment")"
            echo "--$boundary"
            echo "Content-Type: application/octet-stream; name=\"$filename\""
            echo "Content-Transfer-Encoding: base64"
            echo "Content-Disposition: attachment; filename=\"$filename\""
            echo
            base64 "$attachment"
            echo
        fi

        echo "--$boundary--"
    } | msmtp \
        --host=smtp.gmail.com \
        --port=587 \
        --auth=on \
        --tls=on \
        --from="$SMTP_USER" \
        --user="$SMTP_USER" \
        --passwordeval="cat $pass_tmp" \
        "$EMAIL_TO"

    local rc=$?
    rm -f "$pass_tmp"
    if [[ $rc -eq 0 ]]; then
        log INFO "Email sent with subject: $subject"
        EMAIL_SENT=true
    else
        log WARN "Failed to send email with subject: $subject"
    fi
}

################################################################################
# send_mail_on_action()
# Description:
#   Decide whether and what to email based on BACKUP_STATUS/UPLOAD_STATUS.
#
# Behaviors:
#   - Composes subject/body per cases:
#       * Local FAIL → always email (attach LOG_FILE).
#       * Upload FAIL → always email.
#       * SUCCESS/SKIPPED → email only if NOTIFY_ON_SUCCESS=true.
#   - Calls send_email accordingly.
#
# Returns:
#   0 if email not needed or sent successfully; non-zero if send fails.
################################################################################
send_mail_on_action() {
    local subject body

    # Determine subject/body based on statuses:
    if [[ "$BACKUP_STATUS" == "FAIL" ]]; then
        subject="$DATE: n8n Backup FAILED locally"
        body="An error occurred during the local backup step. See attached log.

Log File: $LOG_FILE"

    elif [[ "$BACKUP_STATUS" == "SKIPPED" ]]; then
        subject="$DATE: n8n Backup SKIPPED: no changes"
        body="No changes detected since the last backup; nothing to do."

    elif [[ "$BACKUP_STATUS" == "SUCCESS" && "$UPLOAD_STATUS" == "FAIL" ]]; then
        subject="$DATE: n8n Backup Succeeded; upload FAILED"
        body="Local backup succeeded as:

File: $BACKUP_FILE

But the upload to $RCLONE_REMOTE failed.
See log for details:

Log File: $LOG_FILE"

    elif [[ "$BACKUP_STATUS" == "SUCCESS" && "$UPLOAD_STATUS" == "SUCCESS" ]]; then
        subject="$DATE: n8n Backup SUCCESS"
        body="Backup and upload completed successfully.

  File: $BACKUP_FILE
  Remote: $RCLONE_REMOTE
  Drive Link: ${DRIVE_LINK:-N/A}"

    elif [[ "$BACKUP_STATUS" == "SUCCESS" && "$UPLOAD_STATUS" == "SKIPPED" ]]; then
        subject="$DATE: n8n Backup SUCCESS (upload skipped)"
        body="Local backup completed successfully.

  File: $BACKUP_FILE
  Remote upload: SKIPPED (no rclone remote/target configured)

  Log File: $LOG_FILE"

    else
        subject="$DATE: n8n Backup status unknown"
        body="Backup reported an unexpected status:
  BACKUP_STATUS=$BACKUP_STATUS
  UPLOAD_STATUS=$UPLOAD_STATUS
  Log File: $LOG_FILE"
    fi

    # Decide whether to send email:
    if [[ "$BACKUP_STATUS" == "FAIL" ]] || [[ "$UPLOAD_STATUS" == "FAIL" ]]; then
        # failures: attach the log
        send_email "$subject" "$body" "$LOG_FILE"

    elif [[ "$BACKUP_STATUS" == "SKIPPED" ]]; then
        # skipped: only notify if explicitly requested
        if [[ "$NOTIFY_ON_SUCCESS" == true ]]; then
            send_email "$subject" "$body"
        fi

    else
        # success & upload success: only if notify-on-success
        if [[ "$NOTIFY_ON_SUCCESS" == true ]]; then
            send_email "$subject" "$body" "$LOG_FILE"
        fi
    fi
}

################################################################################
# summarize_backup()
# Description:
#   Print a human-readable, aligned one-shot summary of the latest action
#   (backup/restore) to the console.
#
# Behaviors:
#   - Derives the email outcome line:
#       * EMAIL_EXPLICIT=false  → "SKIPPED (not requested)"
#       * EMAIL_SENT=true       → "SUCCESS"
#       * Missing SMTP config   → "ERROR (missing SMTP config)"
#       * Otherwise             → "FAILED (send failed)"
#   - Renders a status box via box_line() for:
#       Action, Status, Timestamp, Domain, Backup file (if any),
#       N8N Version, Log File, Daily tracking (backup_summary.md),
#       Google Drive upload (SUCCESS/SKIPPED/FAILED) and Folder link (if SUCCESS),
#       Email notification (derived as above).
#
# Returns:
#   0 always.
################################################################################
summarize_backup() {
    local env_domain; env_domain="$(awk -F= '/^DOMAIN=/{print $2}' "$ENV_FILE" 2>/dev/null || echo "")"
    local summary_file="$BACKUP_DIR/backup_summary.md"
    local email_status email_reason
    log INFO "Print a summary of what happened..."

    # Determine whether an email was sent
    if ! $EMAIL_EXPLICIT; then
        email_status="SKIPPED"
        email_reason="(not requested)"
    elif $EMAIL_SENT; then
        email_status="SUCCESS"
        email_reason=""
    else
        if [[ -z "$SMTP_USER" || -z "$SMTP_PASS" || -z "$EMAIL_TO" ]]; then
            email_status="ERROR"
            email_reason="(missing SMTP config)"
        else
            email_status="FAILED"
            email_reason="(send failed)"
        fi
    fi

    echo "═════════════════════════════════════════════════════════════"
    box_line "Action:"          "$ACTION"
    box_line "Status:"          "$BACKUP_STATUS"
    box_line "Timestamp:"       "$DATE"
    box_line "Domain:"          "https://${DOMAIN:-$env_domain}"
    [[ -n "${BACKUP_FILE:-}" ]] && box_line "Backup file:" "$BACKUP_DIR/$BACKUP_FILE"
    box_line "N8N Version:"     "$N8N_VERSION"
    box_line "Log File:"        "$LOG_FILE"
    box_line "Daily tracking:"  "$summary_file"
    case "$UPLOAD_STATUS" in
        "SUCCESS")
            box_line "Google Drive upload:" "SUCCESS"
            box_line "Folder link:"         "$DRIVE_LINK"
            ;;
        "SKIPPED")
            box_line "Google Drive upload:" "SKIPPED"
            ;;
        *)
            box_line "Google Drive upload:" "FAILED"
            ;;
    esac
    if [[ -n "$email_reason" ]]; then
        box_line "Email notification:" "$email_status $email_reason"
    else
        box_line "Email notification:" "$email_status"
    fi
    echo "═════════════════════════════════════════════════════════════"
}

################################################################################
# backup_stack()
# Description:
#   Orchestrate a full backup: change check → local backup → upload → notify/print.
#
# Behaviors:
#   - If no changes and not forced → marks SKIPPED, writes summary, optional email.
#   - Runs do_local_backup(); on success refreshes snapshot and writes summary.
#   - If remote configured, uploads and prunes; captures DRIVE_LINK.
#   - Sends final email per policy and prints the summary box.
#
# Returns:
#   0 on success (including SKIPPED); 1 if local backup failed.
################################################################################
backup_stack() {
    N8N_VERSION="$(get_current_n8n_version)"
    BACKUP_STATUS=""
    UPLOAD_STATUS=""
    BACKUP_FILE=""
    DRIVE_LINK=""
    load_env_file
    discover_from_compose 
    snapshot_bootstrap

    if is_changed_since_snapshot; then
        ACTION="Backup (normal)"
    elif [[ "$FORCE_FLAG" == true ]]; then
        ACTION="Backup (forced)"
    else
        ACTION="Skipped"; BACKUP_STATUS="SKIPPED"
        log INFO "No changes detected; skipping backup. Use -f to force backup."
        write_summary_row "$ACTION" "$BACKUP_STATUS"
        send_mail_on_action
        summarize_backup
        return 0
    fi

    wait_for_containers_healthy 180 10 || return 1

    verify_traefik_certificate "$DOMAIN" || return 1

    if do_local_backup; then
        BACKUP_STATUS="SUCCESS"
        log INFO "Local backup succeeded: $BACKUP_FILE"
        # Refresh our snapshot so next run sees “no changes”
        snapshot_refresh
    else
        BACKUP_STATUS="FAIL"
        log ERROR "Local backup failed."
        write_summary_row "$ACTION" "$BACKUP_STATUS"
        send_mail_on_action
        summarize_backup
        return 1
    fi

    # upload if requested
    if [[ -n "$RCLONE_REMOTE" ]]; then
        upload_backup_rclone || true
    else
        UPLOAD_STATUS="SKIPPED"
    fi

    # Record in rolling summary
    write_summary_row "$ACTION" "$BACKUP_STATUS"

    # cache the Google Drive link exactly once
    DRIVE_LINK="$(get_google_drive_link)"

    # Final email notification
    send_mail_on_action

    # Console summary
    summarize_backup
}

################################################################################
# fetch_remote_if_needed()
# Description:
#   If TARGET_RESTORE_FILE points to an rclone remote, download it locally
#   and verify checksum when available.
#
# Behaviors:
#   - No-op if TARGET_RESTORE_FILE already exists locally.
#   - For "remote:path/file": downloads to BACKUP_DIR/_restore_tmp/<sanitized_name>.
#   - Attempts to fetch .sha256 and verify via sha256sum -c.
#   - Rewrites TARGET_RESTORE_FILE to the local path on success.
#
# Returns:
#   0 on success; non-zero on download/verification failure.
################################################################################
fetch_remote_if_needed() {
    # Already a real local file? nothing to do.
    if [[ -f "$TARGET_RESTORE_FILE" ]]; then
        return 0
    fi

    # Heuristic: looks like "remote:path/..." (and not an absolute local path)
    if [[ "$TARGET_RESTORE_FILE" == *:* && "$TARGET_RESTORE_FILE" != /* ]]; then
        require_cmd rclone || { log ERROR "rclone required to fetch remote backup."; return 1; }

        local tmp_dir="$BACKUP_DIR/_restore_tmp"
        mkdir -p "$tmp_dir"

        # Derive a local filename (keep the basename of the remote object)
        # Sanitize basename: replace ':' with '_'
        local base
        base="$(basename "$TARGET_RESTORE_FILE" | tr ':' '_')"
        local local_path="$tmp_dir/$base"

        log INFO "Fetching backup from remote: $TARGET_RESTORE_FILE"
        if rclone copyto "$TARGET_RESTORE_FILE" "$local_path" "${RCLONE_FLAGS[@]}"; then
            log INFO "Downloaded to: $local_path"
            # try to fetch checksum and verify if available
            log INFO "Verifying checksum..."
            if rclone copyto "${TARGET_RESTORE_FILE}.sha256" "${local_path}.sha256" "${RCLONE_FLAGS[@]}"; then
                (cd "$tmp_dir" && sha256sum -c "$(basename "${local_path}.sha256")") \
                    || { log ERROR "Checksum verification failed for $local_path"; return 1; }
                log INFO "Checksum verified."
            else
                log WARN "Checksum file not found remotely. Skipping verification."
            fi
            TARGET_RESTORE_FILE="$local_path"
            echo "$TARGET_RESTORE_FILE" > "$tmp_dir/.last_fetched"
        else
            log ERROR "Failed to fetch remote backup: $TARGET_RESTORE_FILE"
            return 1
        fi
    fi
}

################################################################################
# restore_stack()
# Description:
#   Restore the n8n stack from a backup archive (configs, volumes, database).
#
# Behaviors:
#   - Fetches remote archive if needed; extracts to temp dir.
#   - Validates .env.bak (with N8N_ENCRYPTION_KEY) and docker-compose.yml.bak,
#     then restores them to N8N_DIR and reloads env.
#   - Stops stack (compose down --volumes --remove-orphans).
#   - If DB dump (*.dump or *.sql) present → skip postgres-data volume restore.
#   - Recreates and restores non-DB volumes from their tarballs.
#   - Starts postgres, waits healthy, then:
#       * For .dump → drop/create DB and pg_restore -c -v.
#       * For .sql  → drop/create DB and psql < file.
#       * If none   → assume DB came from restored volume.
#   - Starts remaining services (compose up -d), health-checks stack.
#   - Cleans temp files and prints aligned summary.
#
# Returns:
#   0 on success; non-zero on any failure.
################################################################################
restore_stack() {
    local requested_spec="$TARGET_RESTORE_FILE"

    # If it's a remote like "gdrive-user:n8n-backups/xxx.tar.gz", fetch it locally
    fetch_remote_if_needed || { log ERROR "Failed to fetch remote restore archive."; return 1; }

    # After fetch, TARGET_RESTORE_FILE should be a local path
    if [[ ! -f "$TARGET_RESTORE_FILE" ]]; then
        log ERROR "Restore file not found: $TARGET_RESTORE_FILE (requested: $requested_spec)"
        return 1
    fi

    log INFO "Starting restore at $DATE..."
    local restore_dir="$N8N_DIR/n8n_restore_$(date +%s)"
    mkdir -p "$restore_dir" || { log ERROR "Cannot create $restore_dir"; return 1; }

    log INFO "Extracting backup archive to $restore_dir"
    tar -xzf "$TARGET_RESTORE_FILE" -C "$restore_dir" \
        || { log ERROR "Failed to extract $TARGET_RESTORE_FILE"; return 1; }

    local backup_env_path="$restore_dir/.env.bak"
    local backup_compose_path="$restore_dir/docker-compose.yml.bak"

    if [[ ! -f "$backup_env_path" ]]; then
        log ERROR "Not found $backup_env_path. Aborting restore."
        return 1
    fi

    if [[ ! -f "$backup_compose_path" ]]; then
        log ERROR "Not found $backup_compose_path. Aborting restore."
        return 1
    fi

    # Verify N8N_ENCRYPTION_KEY is present in backup .env
    local n8n_encryption_key
    n8n_encryption_key="$(read_env_var "$backup_env_path" N8N_ENCRYPTION_KEY || true)"
    if [[ -z "$n8n_encryption_key" ]]; then
        log ERROR "$backup_env_path has no N8N_ENCRYPTION_KEY. Aborting restore."
        return 1
    fi

    if ! looks_like_b64 "$n8n_encryption_key"; then
        log WARN "N8N_ENCRYPTION_KEY in $backup_env_path doesn't look base64. Decryption may fail."
    fi
    log INFO "N8N_ENCRYPTION_KEY (masked): $(mask_secret "$n8n_encryption_key")"

    log INFO "Restoring local-files directory..."
    shopt -s nullglob
    local lf_archives=("$restore_dir"/local-files_*.tar.gz)
    if (( ${#lf_archives[@]} > 0 )); then
        tar -xzf "${lf_archives[0]}" -C "$N8N_DIR" \
            || { log ERROR "Failed to restore local-files"; return 1; }
        log INFO "local-files directory restored"
    else
        log INFO "No local-files archive found, skipping..."
    fi
    shopt -u nullglob

    # Restore .env and docker-compose.yml
    cp -f "$backup_env_path" "$ENV_FILE"
    log INFO "Restored $backup_env_path to $ENV_FILE"
    cp -f "$backup_compose_path" "$COMPOSE_FILE"
    log INFO "Restored $backup_compose_path to $COMPOSE_FILE"

    # Reload restored .env so later steps (DOMAIN, etc.) reflect the restored config
    load_env_file
    discover_from_compose

    # Stop and remove the current containers before cleaning volumes
    log INFO "Stopping and removing containers before restore..."
    compose down --volumes --remove-orphans \
        || { log ERROR "docker compose down failed"; return 1; }

    # Check if we have a SQL database
    local dump_file=""
    local sql_file=""
    dump_file="$(find "$restore_dir" -name "n8n_postgres_dump_*.dump" -print -quit || true)"
    sql_file="$(find "$restore_dir" -name "n8n_postgres_dump_*.sql" -print -quit || true)"

    # List volumes to restore
    local RESTORE_VOLUMES=("${DISCOVERED_VOLUMES[@]}")
    if [[ -n "$dump_file" || -n "$sql_file" ]]; then
        log INFO "SQL dump present. Skipping postgres-data volume restore..."
        local filtered=()
        local v
        for v in "${RESTORE_VOLUMES[@]}"; do
            [[ "$v" == "postgres-data" ]] || filtered+=("$v")
        done
        RESTORE_VOLUMES=("${filtered[@]}")
    fi

    # Cleanup volumes to avoid DB conflict
    log INFO "Cleaning existing Docker volumes before restore..."
    local vol
    for vol in "${RESTORE_VOLUMES[@]}"; do
        if docker volume inspect "$vol" >/dev/null 2>&1; then
            docker volume rm "$vol" && log INFO "Removed volume: $vol"
        else
            log INFO "Volume '$vol' not found, skipping..."
        fi
    done

    # Restore Docker volumes
    log INFO "Restoring volumes from archive..."
    for vol in "${RESTORE_VOLUMES[@]}"; do
        local vol_file
        vol_file="$(find "$restore_dir" -name "*${vol}_*.tar.gz" -print -quit || true)"
        if [[ -z "${vol_file:-}" ]]; then
            log ERROR "No backup found for volume $vol"
            return 1
        fi
        docker volume create "$vol" >/dev/null

        docker run --rm -v "${vol}:/data" -v "$restore_dir:/backup" alpine \
            sh -c "find /data -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + \
            && tar xzf /backup/$(basename "$vol_file") -C /data" \
            || { log ERROR "Failed to restore $vol"; return 1; }

        log INFO "Volume $vol restored"
    done

    log INFO "Start working on $N8N_DIR ..."
    cd "$N8N_DIR" || { log ERROR "Failed to change directory to $N8N_DIR"; return 1; }

    log INFO "Starting PostgreSQL first..."
    compose up -d "$POSTGRES_SERVICE" \
        || { log ERROR "Failed to start postgres"; return 1; }

    log INFO "Waiting for postgres to be healthy..."
    check_container_healthy "$POSTGRES_SERVICE" || return 1

    # Database
    local PG_CID
    PG_CID="$(container_id_for_service "$POSTGRES_SERVICE")"
    if [[ -z "$PG_CID" ]]; then
        log ERROR "Could not resolve container ID for service '$POSTGRES_SERVICE'"
        return 1
    fi

    # Database variables
    local DB_USER="${DB_POSTGRESDB_USER:-${POSTGRES_USER:-n8n}}"
    local DB_NAME="${DB_POSTGRESDB_DATABASE:-${POSTGRES_DB:-n8n}}"
    local POSTGRES_RESTORE_MODE=""

    if [[ -n "$dump_file" ]]; then
        POSTGRES_RESTORE_MODE="dump"
        log INFO "Custom dump found: $(basename "$dump_file"). Restoring via pg_restore..."
        log INFO "Recreate database ${DB_NAME}..."
        docker exec -i "$PG_CID" psql -U "$DB_USER" -d postgres -v ON_ERROR_STOP=1 -c \
          "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='${DB_NAME}' AND pid <> pg_backend_pid();" || true
        docker exec -i "$PG_CID" psql -U "$DB_USER" -d postgres -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS ${DB_NAME};"
        docker exec -i "$PG_CID" psql -U "$DB_USER" -d postgres -v ON_ERROR_STOP=1 -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};"
        docker exec -i "$PG_CID" pg_restore -U "$DB_USER" -d "${DB_NAME}" -c -v < "$dump_file"

    elif [[ -n "$sql_file" ]]; then
        POSTGRES_RESTORE_MODE="dump"
        log INFO "SQL dump found: $(basename "$sql_file"). Restoring via psql..."
        log INFO "Recreate database ${DB_NAME}..."
        docker exec -i "$PG_CID" psql -U "$DB_USER" -d postgres -v ON_ERROR_STOP=1 -c \
          "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='${DB_NAME}' AND pid <> pg_backend_pid();" || true
        docker exec -i "$PG_CID" psql -U "$DB_USER" -d postgres -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS ${DB_NAME};"
        docker exec -i "$PG_CID" psql -U "$DB_USER" -d postgres -v ON_ERROR_STOP=1 -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};"
        docker exec -i "$PG_CID" psql -U "$DB_USER" -d "${DB_NAME}" -v ON_ERROR_STOP=1 < "$sql_file"

    else
        POSTGRES_RESTORE_MODE="volume"
        log INFO "No SQL dump found. Assuming the postgres-data volume already contains the DB. Skipping SQL import."
    fi

    # When the PostgreSQL DB is ready, start other containers
    log INFO "Starting the rest of the stack..."
    compose up -d || { log ERROR "docker compose up failed"; return 1; }

    log INFO "Checking services running and healthy after restoring backup..."
    if ! check_services_up_running; then
        log ERROR "Some services and Traefik are not running or unhealthy after restoring the backup"
        log ERROR "Restore the backup failed."
        log INFO "Log File: $LOG_FILE"
        return 1
    else
        log INFO "Services running and healthy"
    fi

    detect_mode_runtime || true

    log INFO "Cleaning up..."
    rm -rf "$restore_dir"
    # Optional: clean up any fetched temp archive
    if [[ -d "$BACKUP_DIR/_restore_tmp" ]]; then
        # Only remove files we created; ignore user local archives
        find "$BACKUP_DIR/_restore_tmp" -type f -name '*n8n_backup_*.tar.gz' -delete || true
        rmdir "$BACKUP_DIR/_restore_tmp" 2>/dev/null || true
    fi

    N8N_VERSION="$(get_current_n8n_version)"
    local restored_list=""
    if ((${#RESTORE_VOLUMES[@]})); then
        restored_list=$(printf '%s, ' "${RESTORE_VOLUMES[@]}")
        restored_list=${restored_list%, }
    else
        restored_list="(none)"
    fi
    echo "═════════════════════════════════════════════════════════════"
    echo "Restore completed successfully."
    box_line "Detected Mode:"           "${DISCOVERED_MODE:-unknown}"
    box_line "Domain:"                  "https://$DOMAIN"
    box_line "Restore from file:"       "$requested_spec"
    box_line "Local archive used:"      "$TARGET_RESTORE_FILE"
    box_line "N8N Version:"             "$N8N_VERSION"
    box_line "N8N Directory:"           "$N8N_DIR"
    box_line "Log File:"                "$LOG_FILE"
    box_line "Timestamp:"               "$DATE"
    box_line "Volumes restored:"        "${restored_list}"
    if [[ "$POSTGRES_RESTORE_MODE" == "dump" ]]; then
        box_line "PostgreSQL:"           "Restored from SQL dump"
    else
        box_line "PostgreSQL:"           "Restored from volume"
    fi
    echo "═════════════════════════════════════════════════════════════"
}

################################################################################
# cleanup_stack()
# Description:
#   Interactively tear down the stack and remove named resources.
#
# Behaviors:
#   - Prints a plan and asks for confirmation.
#   - Runs `compose down --remove-orphans`.
#   - Removes named volumes in VOLUMES; respects KEEP_CERTS=true for letsencrypt.
#   - Prunes dangling images; optionally removes base images if REMOVE_IMAGES=true.
#   - Logs completion and whether certs were preserved.
#
# Returns:
#   0 on completion; 0 if user cancels; non-zero only on unexpected errors.
################################################################################
cleanup_stack() {
    discover_from_compose
    # Settings (can be overridden via env)
    local NETWORK_NAME="${NETWORK_NAME:-n8n-network}"
    local KEEP_CERTS="${KEEP_CERTS:-true}"
    local REMOVE_IMAGES="${REMOVE_IMAGES:-false}"

    log WARN "This will stop containers, remove the compose stack, and delete named resources."
    echo "Planned actions:"
    echo "  - docker compose down --remove-orphans -v"
    echo "  - Remove volumes: ${DISCOVERED_VOLUMES[*]}  (letsencrypt kept: ${KEEP_CERTS})"
    echo "  - Remove docker network: ${NETWORK_NAME}"
    echo "  - Remove dangling images (docker image prune -f)"
    echo "  - Remove base images (n8nio/n8n, postgres) : ${REMOVE_IMAGES}"
    echo

    read -e -p "Continue? [y/N] " ans
    [[ "${ans,,}" == "y" ]] || { log INFO "Cleanup cancelled."; return 0; }

    log INFO "Shutting down stack and removing orphans + anonymous volumes..."
    if [[ -f "$N8N_DIR/docker-compose.yml" ]]; then
        compose down --remove-orphans || true
    else
        log WARN "docker-compose.yml not found at \$N8N_DIR; attempting plain 'docker compose down' in $PWD."
        docker compose down --remove-orphans || true
    fi

    log INFO "Removing related volumes..."
    local vol
    for vol in "${DISCOVERED_VOLUMES[@]}"; do
        if [[ "$KEEP_CERTS" == "true" && "$vol" == "letsencrypt" ]]; then
            log INFO "Skipping volume '$vol' (KEEP_CERTS=true)"
            continue
        fi
        if docker volume inspect "$vol" >/dev/null 2>&1; then
            if docker volume rm "$vol" >/dev/null 2>&1; then
                log INFO "Removed volume: $vol"
            else
                log WARN "Could not remove volume '$vol' (in use?)."
            fi
        else
            log INFO "Volume '$vol' not found; skipping."
        fi
    done

    log INFO "Removing docker network (if exists): ${NETWORK_NAME}"
    docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || true

    log INFO "Pruning dangling images…"
    docker image prune -f >/dev/null 2>&1 || true
    if [[ "$REMOVE_IMAGES" == "true" ]]; then
        log WARN "Removing base images: n8nio/n8n and postgres (explicit request)"
        docker images --format '{{.Repository}}:{{.Tag}} {{.ID}}' \
          | grep -E '^(n8nio/n8n|docker\.n8n\.io/n8nio/n8n|postgres):' \
          | awk '{print $2}' \
          | xargs -r docker rmi -f || true
    fi

    log INFO "Cleanup completed."
    [[ "$KEEP_CERTS" == "true" ]] && log INFO "Note: kept 'letsencrypt' volume (certs preserved). Set KEEP_CERTS=false to reset TLS."
}

################################################################################
# parse_args()
# Description:
#   Parse CLI arguments and set global flags/vars.
#
# Behaviors:
#   - Enforces single action selection.
#   - Uses distinct flags for SSL email vs. notification email.
#
# Returns:
#   0 on success; exits 1 on invalid usage.
################################################################################
parse_args() {
    # Define short/long specs
    SHORT="i:u:v:m:cbad:l:r:e:ns:fh"
    LONG="install:,upgrade:,version:,ssl-email:,cleanup,backup,available,dir:,log-level:,restore:,email-to:,notify-on-success,remote-name:,force,help,mode:"

    # Parse
    PARSED=$(getopt --options="$SHORT" --longoptions="$LONG" --name "$0" -- "$@") || usage
    eval set -- "$PARSED"

    while true; do
        case "$1" in
            -i|--install)
                DO_INSTALL=true
                DOMAIN="$(parse_domain_arg "$2")"
                shift 2
                ;;
            -u|--upgrade)
                DO_UPGRADE=true
                DOMAIN="$(parse_domain_arg "$2")"
                shift 2
                ;;
            -v|--version)
                N8N_VERSION="$2"
                shift 2
                ;;
            -m|--ssl-email)
                SSL_EMAIL="$2"
                shift 2
                ;;
            -c|--cleanup)
                DO_CLEANUP=true
                shift
                ;;
            -b|--backup)
                DO_BACKUP=true
                shift
                ;;
            -a|--available)
                DO_AVAILABLE=true
                shift
                ;;
            -d|--dir)
                N8N_DIR="$2"
                shift 2
                ;;
            -l|--log-level)
                LOG_LEVEL="${2^^}"
                shift 2
                ;;
            -r|--restore)
                DO_RESTORE=true
                TARGET_RESTORE_FILE="$2"
                shift 2
                ;;
            -e|--email-to)
                EMAIL_TO="$2"; EMAIL_EXPLICIT=true
                shift 2
                ;;
            -n|--notify-on-success)
                NOTIFY_ON_SUCCESS=true
                shift
                ;;
            -s|--remote-name)
                RCLONE_REMOTE="$2"
                shift 2
                ;;
            --mode)
                INSTALL_MODE="$2"
                shift 2
                ;;
            -f|--force)
                FORCE_FLAG=true
                shift
                ;;
            -h|--help)
                usage
                ;;
            --)
                shift
                break
                ;;
            *)
                usage
                ;;
        esac
    done

    # Enforce single action
    local count=0
    $DO_INSTALL   && ((count+=1))
    $DO_UPGRADE   && ((count+=1))
    $DO_BACKUP    && ((count+=1))
    $DO_RESTORE   && ((count+=1))
    $DO_CLEANUP   && ((count+=1))
    $DO_AVAILABLE && ((count+=1))
    (( count == 1 )) || { log ERROR "Choose exactly one action."; usage; }

    # Normalize mode default for install
    if $DO_INSTALL; then
        case "$INSTALL_MODE" in
            single|queue) ;;
            *) log ERROR "Invalid --mode '$INSTALL_MODE' (use single|queue)"; exit 2 ;;
        esac
    fi
}

################################################################################
# main()
# Description:
#   Entry point; routes to the chosen action.
#
# Behaviors:
#   - Sets paths, logging, and runs the selected flow.
#
# Returns:
#   Exit code from the selected subroutine.
################################################################################
main() {
    check_root
    parse_args "$@"
    mkdir -p "$N8N_DIR"
    set_paths

    # Debug tracing
    if [[ "$LOG_LEVEL" == "DEBUG" ]]; then
        export PS4='+ $(date "+%H:%M:%S") ${BASH_SOURCE##*/}:${LINENO}:${FUNCNAME[0]:-main}: '
        set -x
    fi

    if $DO_INSTALL; then
        install_stack
    elif $DO_UPGRADE; then
        install_prereqs
        upgrade_stack
    elif $DO_BACKUP; then
        install_prereqs
        backup_stack
    elif $DO_RESTORE; then
        install_prereqs
        restore_stack
    elif $DO_CLEANUP; then
        cleanup_stack
    elif $DO_AVAILABLE; then
        list_available_versions
    fi

    # post-run housekeeping
    find "$LOG_DIR" -type f -mtime +$DAYS_TO_KEEP -delete || true
}

main "$@"
