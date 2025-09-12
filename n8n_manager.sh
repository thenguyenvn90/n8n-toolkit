#!/bin/bash
set -euo pipefail
set -o errtrace
IFS=$'\n\t'

#############################################################################################
# N8N Installation, Upgrade, Backup & Restore Manager (Mode-aware: Single or Queue)
# Author:      TheNguyen
# Email:       thenguyen.ai.automation@gmail.com
# Version:     2.1.0
# Date:        2025-09-06
#
# Description:
#   A unified management tool for installing, upgrading, backing up, and restoring the
#   n8n automation stack running on Docker Compose with Traefik + Let's Encrypt, supporting
#   BOTH "single" mode and "queue" mode. For install, --mode defaults to "single".
#
#   This version adds:
#     • Monitoring toggle via --monitoring (Prometheus, Grafana, exporters via Compose profiles)
#     • Optional public Prometheus via --expose-prometheus (default private)
#     • Base domain input (example.com), with subdomain defaults:
#         - n8n.<domain>       for n8n
#         - grafana.<domain>   for Grafana
#         - prometheus.<domain> for Prometheus (if exposed)
#       Overridable with:
#         --subdomain-n8n, --subdomain-grafana, --subdomain-prometheus
#
# Key features:
#   - Install:
#       * --mode {single|queue} (default: single) chooses template folder (single-mode/ or queue-mode/)
#       * Validates DNS, installs Docker/Compose if missing, pins version, generates secrets
#       * Optional monitoring profile & subdomains persisted into .env
#       * Brings stack up, waits for health, prints a summary
#   - Upgrade:
#       * Auto-detects mode from compose
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
# Cleanup mode: safe (default) | all
CLEANUP_MODE="safe"

# Install-only
INSTALL_MODE="single"
DOMAIN=""
SSL_EMAIL=""

# Upgrade/Install shared
N8N_VERSION="latest"
FORCE_FLAG=false
BACKUP_REQUIRE_TLS="${BACKUP_REQUIRE_TLS:-false}"

# Monitoring & subdomain CLI overrides (defaults live in .env templates)
MONITORING=false
EXPOSE_PROMETHEUS=false
SUBDOMAIN_N8N=""
SUBDOMAIN_GRAFANA=""
SUBDOMAIN_PROMETHEUS=""
N8N_FQDN=""
GRAFANA_FQDN=""
PROMETHEUS_FQDN=""
BASIC_AUTH_USER=""
BASIC_AUTH_PASS=""

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
EMAIL_ATTEMPTED=false

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
        Install n8n with the given base domain (e.g., example.com)
        Optional: --mode single|queue  (default: single)
        Optional: -v|--version <tag>

  -u, --upgrade
        Upgrade n8n to target version (or latest). Domain/FQDNs are read from .env.

  -b, --backup
        Run backup (skip if no changes unless -f)

  -r, --restore <FILE_OR_REMOTE>
        Restore from local file or rclone remote (e.g. gdrive:folder/file.tar.gz)

  -c, --cleanup [safe|all]  Stop stack & remove resources (preview; confirm in 'all')

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

# Monitoring-related (install-time):
  --monitoring                        Enable Prometheus/Grafana profile
  --expose-prometheus                 Expose Prometheus publicly (default: private)
  --subdomain-n8n <sub>               Override n8n subdomain (default: n8n)
  --subdomain-grafana <sub>           Override Grafana subdomain (default: grafana)
  --subdomain-prometheus <sub>        Override Prometheus subdomain (default: prometheus)
  --basic-auth-user <user>            Traefik basic auth user for Grafana/Prometheus
  --basic-auth-pass <pass>            Traefik basic auth pass for Grafana/Prometheus

Examples:
  $0 -a
      # List available versions

  $0 --install example.com -m you@example.com
      # Install the latest n8n version with single mode

  $0 --install example.com -m you@example.com -v 1.105.3 --mode queue
      # Install a specific n8n version with queue mode

  $0 --install example.com -m you@example.com -d /path/to/n8n --mode queue
      # Install the latest n8n version (queue mode) to a specific target directory

  $0 --install example.com -m you@example.com --mode queue --monitoring --basic-auth-user admin --basic-auth-pass 'StrongPass123'
      # Install the latest n8n version (queue mode) with monitoring (Grafana + Prometheus)

  $0 --upgrade
      # Upgrade to the latest n8n version (domain/FQDNs read from .env)

  $0 --upgrade -f -v 1.107.2
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
    if   $DO_INSTALL;   then mode="install"
    elif $DO_UPGRADE;   then mode="upgrade"
    elif $DO_BACKUP;    then mode="backup"
    elif $DO_RESTORE;   then mode="restore"
    elif $DO_CLEANUP;   then mode="cleanup"
    elif $DO_AVAILABLE; then mode="available"
    fi

    LOG_FILE="$N8N_DIR/logs/${mode}_n8n_${DATE}.log"
    umask 0077
    exec > >(tee -a "$LOG_FILE") 2>&1
    ln -sf "$LOG_FILE" "$LOG_DIR/latest_${mode}.log"
    log INFO "Working directory: $N8N_DIR"
    log INFO "Logging to: $LOG_FILE"
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
        queue)  src_dir="$TEMPLATE_QUEUE"  ;;
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
    log INFO "Updating DOMAIN=$DOMAIN in $ENV_FILE"
    upsert_env_var "DOMAIN" "$DOMAIN" "$ENV_FILE"

    log INFO "Updating SSL_EMAIL=$SSL_EMAIL in $ENV_FILE"
    [[ -n "${SSL_EMAIL:-}" ]] && upsert_env_var "SSL_EMAIL" "$SSL_EMAIL" "$ENV_FILE"

    # Resolve target version: explicit -v wins; else latest stable
    local target_version
    target_version="$(resolve_n8n_target_version "$N8N_VERSION")" || exit 1
    log INFO "Updating N8N_IMAGE_TAG=$target_version in $ENV_FILE"
    upsert_env_var "N8N_IMAGE_TAG" "$target_version" "$ENV_FILE"

    # Rotate SECRETS in env if missing/default
    rotate_or_generate_secret "$ENV_FILE" POSTGRES_PASSWORD        16 "CHANGE_ME_BASE64_16_BYTES"
    rotate_or_generate_secret "$ENV_FILE" N8N_BASIC_AUTH_PASSWORD  16 "CHANGE_ME_BASE64_16_BYTES"
    rotate_or_generate_secret "$ENV_FILE" N8N_ENCRYPTION_KEY       32 "CHANGE_ME_BASE64_32_BYTES"

    # Queue mode only
    if [[ "${INSTALL_MODE:-single}" == "queue" ]] || [[ "${DISCOVERED_MODE:-}" == "queue" ]]; then
        rotate_or_generate_secret "$ENV_FILE" REDIS_PASSWORD        16 "CHANGE_ME_BASE64_16_BYTES"
    fi

    # Subdomains & monitoring flags persisted in .env
    [[ -n "$SUBDOMAIN_N8N" ]]        && upsert_env_var "SUBDOMAIN_N8N" "$SUBDOMAIN_N8N" "$ENV_FILE"
    [[ -n "$SUBDOMAIN_GRAFANA" ]]    && upsert_env_var "SUBDOMAIN_GRAFANA" "$SUBDOMAIN_GRAFANA" "$ENV_FILE"
    [[ -n "$SUBDOMAIN_PROMETHEUS" ]] && upsert_env_var "SUBDOMAIN_PROMETHEUS" "$SUBDOMAIN_PROMETHEUS" "$ENV_FILE"

    if $MONITORING; then
        upsert_env_var "COMPOSE_PROFILES" "monitoring" "$ENV_FILE"
        local mon_src="$SCRIPT_DIR/monitoring"
        local mon_dst="$N8N_DIR/monitoring"
        if [[ -d "$mon_src" ]]; then
            mkdir -p "$mon_dst"
            cp -a "$mon_src/." "$mon_dst/"
            log INFO "Copied monitoring assets into $mon_dst"
            if [[ ! -f "$mon_dst/prometheus.yml" ]]; then
                log ERROR "Expected file not found: $mon_dst/prometheus.yml (is it missing or a directory?)"
                exit 1
            fi
        else
            log WARN "Monitoring enabled but $mon_src not found; Prometheus/Grafana may fail to start."
        fi
    else
        upsert_env_var "COMPOSE_PROFILES" "" "$ENV_FILE"
    fi

    # Ensure Traefik basic auth variables are consistent (always run)
    ensure_monitoring_auth

    if $EXPOSE_PROMETHEUS; then
        upsert_env_var "EXPOSE_PROMETHEUS" "true" "$ENV_FILE"
    else
        upsert_env_var "EXPOSE_PROMETHEUS" "false" "$ENV_FILE"
    fi

    # persist explicit FQDNs
    local base_dom sub_n8n sub_graf sub_prom
    base_dom="$(read_env_var "$ENV_FILE" DOMAIN)"
    sub_n8n="$(read_env_var "$ENV_FILE" SUBDOMAIN_N8N)"
    sub_graf="$(read_env_var "$ENV_FILE" SUBDOMAIN_GRAFANA)"
    sub_prom="$(read_env_var "$ENV_FILE" SUBDOMAIN_PROMETHEUS)"

    sub_n8n="${sub_n8n:-n8n}"
    sub_graf="${sub_graf:-grafana}"
    sub_prom="${sub_prom:-prometheus}"

    N8N_FQDN="${sub_n8n:+$sub_n8n.}${base_dom}"
    GRAFANA_FQDN="${sub_graf:+$sub_graf.}${base_dom}"
    PROMETHEUS_FQDN="${sub_prom:+$sub_prom.}${base_dom}"

    upsert_env_var "N8N_FQDN" "$N8N_FQDN" "$ENV_FILE"
    upsert_env_var "GRAFANA_FQDN" "$GRAFANA_FQDN" "$ENV_FILE"
    upsert_env_var "PROMETHEUS_FQDN" "$PROMETHEUS_FQDN" "$ENV_FILE"

    # Secure secrets file
    chmod 600 "$ENV_FILE" || true
    chmod 640 "$COMPOSE_FILE" || true
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
#   - Installs Docker/Compose and dependencies (ensure_prereqs()).
#   - Prepares compose + .env with pinned version and secrets (copy_templates_for_mode()).
#   - Validates compose/env (validate_compose_and_env()).
#   - Creates volumes as needed and starts stack (docker_up_check()).
#   - Waits for containers and TLS to be healthy.
#   - Prints a summary on success.
#
# Returns:
#   0 on success; exits non-zero if any step fails.
################################################################################
install_stack() {
    [[ -n "$DOMAIN" ]] || { log ERROR "Install requires a base domain."; exit 2; }

    log INFO "Starting N8N installation for base domain: $DOMAIN"
    ensure_prereqs
    copy_templates_for_mode
    load_env_file
    preflight_dns_checks
    validate_compose_and_env
    discover_from_compose
    ensure_external_volumes
    [[ "$INSTALL_MODE" == "queue" ]] && DISCOVERED_MODE="queue"

    docker_up_check || { log ERROR "Stack unhealthy after install."; exit 1; }
    post_up_tls_checks || true

    # Summary
    local graf_fqdn prom_fqdn expose_prom compose_profiles
    graf_fqdn="$(read_env_var "$ENV_FILE" GRAFANA_FQDN || true)"
    prom_fqdn="$(read_env_var "$ENV_FILE" PROMETHEUS_FQDN || true)"
    expose_prom="$(read_env_var "$ENV_FILE" EXPOSE_PROMETHEUS || echo false)"
    compose_profiles="$(read_env_var "$ENV_FILE" COMPOSE_PROFILES || true)"

    echo "═════════════════════════════════════════════════════════════"
    echo "N8N has been successfully installed!"
    box_line "Installation Mode:"       "$INSTALL_MODE"
    box_line "Domain (n8n):"           "https://${N8N_FQDN}"
    if [[ "$compose_profiles" == *monitoring* ]]; then
        box_line "Grafana:"             "https://${graf_fqdn}"
        if [[ "${expose_prom,,}" == "true" ]]; then
            box_line "Prometheus:"      "https://${prom_fqdn}"
        else
            box_line "Prometheus:"      "(internal only)"
        fi
    fi
    box_line "Installed Version:"       "$(get_current_n8n_version)"
    box_line "Install Timestamp:"       "${DATE}"
    box_line "Installed By:"            "${SUDO_USER:-$USER}"
    box_line "Target Directory:"        "${N8N_DIR}"
    box_line "SSL Email:"               "${SSL_EMAIL:-N/A}"
    box_line "Execution log:"           "${LOG_FILE}"
    echo "═════════════════════════════════════════════════════════════"
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
    ensure_monitoring_auth
    N8N_FQDN="$(read_env_var "$ENV_FILE" N8N_FQDN || true)"

    log INFO "Checking current and target n8n versions..."
    cd "$N8N_DIR" || { log ERROR "Failed to change directory to $N8N_DIR"; return 1; }

    local current_version target_version
    current_version=$(get_current_n8n_version || echo "0.0.0")
    target_version="$(resolve_n8n_target_version "$N8N_VERSION")" || exit 1
    log INFO "Current version: $current_version  ->  Target version: $target_version"

    if [[ "$(printf "%s\n%s" "$target_version" "$current_version" | sort -V | head -n1)" == "$target_version" \
          && "$target_version" != "$current_version" \
          && "$FORCE_FLAG" != true ]]; then
        log INFO "Target ($target_version) <= current ($current_version). Use -f to force downgrade."
        exit 0
    fi

    if [[ "$target_version" == "$current_version" && "$FORCE_FLAG" != true ]]; then
        log INFO "Already on $current_version. Use -f to force redeploy."
        exit 0
    fi

    log INFO "Updating .env with N8N_IMAGE_TAG=$target_version"
    upsert_env_var "N8N_IMAGE_TAG" "$target_version" "$ENV_FILE"

    log INFO "Stopping and removing existing containers..."
    compose down --remove-orphans || true

    validate_compose_and_env
    discover_from_compose

    docker_up_check || { log ERROR "Stack unhealthy after upgrade."; exit 1; }
    post_up_tls_checks || true

    echo "═════════════════════════════════════════════════════════════"
    echo "N8N has been successfully upgraded!"
    box_line "Detected Mode:"           "${DISCOVERED_MODE:-unknown}"
    box_line "Domain (n8n):"            "https://${N8N_FQDN}"
    box_line "Upgraded Version:"        "$(get_current_n8n_version)"
    box_line "Upgraded Timestamp:"      "${DATE}"
    box_line "Upgraded By:"             "${SUDO_USER:-$USER}"
    box_line "Target Directory:"        "${N8N_DIR}"
    box_line "Execution log:"           "${LOG_FILE}"
    echo "═════════════════════════════════════════════════════════════"
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
        real="$(resolve_volume_name "$vol" || true)"
        if [[ -z "$real" ]]; then
            log INFO "Skipping volume '$vol' (not present on host)."
            continue
        fi
        local vol_backup="volume_${vol}_$DATE.tar.gz"
        docker run --rm \
            -v "${real}:/data" \
            -v "$BACKUP_PATH:/backup" \
            alpine \
            sh -c "tar czf /backup/$vol_backup -C /data ." \
            || { log ERROR "Failed to archive volume $vol"; return 1; }
        log INFO "Volume '$vol' backed up: $vol_backup"
    done

    log INFO "Dumping PostgreSQL database..."
    local DB_USER="${DB_POSTGRESDB_USER:-${POSTGRES_USER:-n8n}}"
    local DB_NAME="${DB_POSTGRESDB_DATABASE:-${POSTGRES_DB:-n8n}}"
    local ADMIN_USER="${POSTGRES_USER:-postgres}"
    local pgcid; pgcid="$(container_id_for_service "$POSTGRES_SERVICE")"
    local ADMIN_PASS="$(_read_env_var_from_container "$pgcid" POSTGRES_PASSWORD)"

    if [[ -z "$pgcid" ]]; then
        log ERROR "Postgres service '$POSTGRES_SERVICE' is not running"
        return 1
    fi

    [[ -z "$ADMIN_PASS" ]] && log WARN "POSTGRES_PASSWORD not found in container env; proceeding (trust/peer auth assumed)."

    if docker exec "$pgcid" pg_isready &>/dev/null; then
        docker exec -e PGPASSWORD="$ADMIN_PASS" "$pgcid" \
            pg_dump -U "$ADMIN_USER" -d "$DB_NAME" > "$BACKUP_PATH/n8n_postgres_dump_$DATE.sql" \
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
        # Write checksum relative to BACKUP_DIR so verification after download works
        ( cd "$BACKUP_DIR" \
          && sha256sum "$BACKUP_FILE" > "$BACKUP_FILE.sha256" ) \
          || { log ERROR "Failed to write checksum"; return 1; }
    else
        log ERROR "Archive not found after compression: $BACKUP_DIR/$BACKUP_FILE"
        return 1
    fi
    log INFO "Created checksum -> $BACKUP_DIR/$BACKUP_FILE.sha256"

    chmod 600 "$BACKUP_DIR/"*.tar.gz 2>/dev/null || true
    chmod 600 "$BACKUP_DIR/"*.sha256 2>/dev/null || true

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
    local REMOTE
    if [[ "$RCLONE_REMOTE" == *:* ]]; then
        REMOTE="$RCLONE_REMOTE"
    else
        REMOTE="${RCLONE_REMOTE}:"
    fi

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
    {
        head -n2 "$file"
        tail -n +3 "$file" \
        | awk -F'|' -v cut="$(date -d '30 days ago' '+%F')" '
            {
                date=$2; gsub(/^[[:space:]]+|[[:space:]]+$/,"",date)
                split(date, dt, "_"); if (dt[1] >= cut) print
            }'
    } > "${file}.tmp" && mv "${file}.tmp" "$file"

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

    # Decide whether to send email (policy lives here; common.sh only sends)
    EMAIL_SENT=false
    if ! $EMAIL_EXPLICIT; then
        return 0
    fi

    if [[ "$BACKUP_STATUS" == "FAIL" || "$UPLOAD_STATUS" == "FAIL" ]]; then
        EMAIL_ATTEMPTED=true
        send_email "$subject" "$body" "$LOG_FILE" && EMAIL_SENT=true
    elif [[ "$BACKUP_STATUS" == "SKIPPED" ]]; then
        if [[ "$NOTIFY_ON_SUCCESS" == true ]]; then
            EMAIL_ATTEMPTED=true
            send_email "$subject" "$body" && EMAIL_SENT=true
        fi
    else
        if [[ "$NOTIFY_ON_SUCCESS" == true ]]; then
            EMAIL_ATTEMPTED=true
            send_email "$subject" "$body" && EMAIL_SENT=true
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
    local summary_file="$BACKUP_DIR/backup_summary.md"
    local email_status email_reason
    log INFO "Print a summary of what happened..."

    if ! $EMAIL_EXPLICIT; then
        email_status="SKIPPED"; email_reason="(not requested)"
    elif $EMAIL_ATTEMPTED; then
        if $EMAIL_SENT; then
            email_status="SUCCESS"; email_reason=""
        else
            if [[ -z "$SMTP_USER" || -z "$SMTP_PASS" || -z "$EMAIL_TO" ]]; then
                email_status="ERROR";  email_reason="(missing SMTP config)"
            else
                email_status="FAILED"; email_reason="(send failed)"
            fi
        fi
    else
        email_status="SKIPPED"; email_reason="(policy: not required)"
    fi

    local n8n_fqdn
    n8n_fqdn="$(read_env_var "$ENV_FILE" N8N_FQDN)"
    echo "═════════════════════════════════════════════════════════════"
    echo "Backup completed!"
    box_line "Detected Mode:"           "${DISCOVERED_MODE:-unknown}"
    box_line "Domain (n8n):"            "https://${n8n_fqdn}"
    box_line "Backup Action:"           "$ACTION"
    box_line "Backup Status:"           "$BACKUP_STATUS"
    box_line "Backup Timestamp:"        "$DATE"
    [[ -n "${BACKUP_FILE:-}" ]] && box_line "Backup file:" "$BACKUP_DIR/$BACKUP_FILE"
    box_line "N8N Version:"             "$N8N_VERSION"
    box_line "N8N Directory:"           "$N8N_DIR"
    box_line "Log File:"                "$LOG_FILE"
    box_line "Daily tracking:"          "$summary_file"
    case "$UPLOAD_STATUS" in
        "SUCCESS") box_line "Remote upload:" "SUCCESS"; box_line "Remote folder link:" "$DRIVE_LINK" ;;
        "SKIPPED") box_line "Remote upload:" "SKIPPED" ;;
        *)         box_line "Remote upload:" "FAILED"  ;;
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
    detect_mode_runtime || true

    N8N_FQDN="$(read_env_var "$ENV_FILE" N8N_FQDN || true)"

    # Initialize snapshot baseline only if missing
    if [[ ! -d "$BACKUP_DIR/snapshot/config" ]]; then
        snapshot_sync boot
    fi

    # Change detection (skip unless forced)
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

    wait_for_containers_healthy || return 1

    if [[ "$BACKUP_REQUIRE_TLS" == "true" ]]; then
        verify_traefik_certificate "$N8N_FQDN" || return 1
    fi

    if do_local_backup; then
        BACKUP_STATUS="SUCCESS"
        log INFO "Local backup succeeded: $BACKUP_FILE"
        # Refresh snapshot so next run sees “no changes”
        snapshot_sync refresh
        write_summary_row "$ACTION" "$BACKUP_STATUS"
    else
        BACKUP_STATUS="FAIL"
        log ERROR "Local backup failed."
        write_summary_row "$ACTION" "$BACKUP_STATUS"
        send_mail_on_action
        summarize_backup
        return 1
    fi

    # Remote upload (optional)
    if [[ -n "$RCLONE_REMOTE" ]]; then
        upload_backup_rclone || true
    else
        UPLOAD_STATUS="SKIPPED"
    fi

    # Cache Google Drive folder link (if rclone remote is Google Drive)
    DRIVE_LINK="$(get_google_drive_link)"

    # Final email + console summary
    send_mail_on_action
    summarize_backup
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
#   - Stops stack (compose down --remove-orphans), then explicitly removes/recreates volumes.
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
    N8N_FQDN="$(read_env_var "$ENV_FILE" N8N_FQDN || true)"

    # Stop and remove the current containers before cleaning volumes
    log INFO "Stopping and removing containers before restore..."
    compose down --remove-orphans \
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
    if [[ "$vol" == "letsencrypt" ]]; then
        log INFO "Skipping volume '$vol' (TLS certs) during restore."
        continue
    fi
    real="$(resolve_volume_name "$vol" || expected_volume_name "$vol")"
    if docker volume inspect "$real" >/dev/null 2>&1; then
        docker volume rm "$real" && log INFO "Removed volume: $vol"
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

    real="$(expected_volume_name "$vol")"
    docker volume create "$real" >/dev/null

    docker run --rm -v "${real}:/data" -v "$restore_dir:/backup" alpine \
        sh -c "find /data -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + \
        && tar xzf /backup/$(basename "$vol_file") -C /data" \
        || { log ERROR "Failed to restore $vol"; return 1; }

    log INFO "Volume $vol restored"
    done

    log INFO "Start working on $N8N_DIR ..."
    cd "$N8N_DIR" || { log ERROR "Failed to change directory to $N8N_DIR"; return 1; }

    log INFO "Starting PostgreSQL first..."
    # Recreate any external volumes the compose expects
    ensure_external_volumes
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
    local ADMIN_USER="${POSTGRES_USER:-postgres}"
    local ADMIN_PASS="$(_read_env_var_from_container "$PG_CID" POSTGRES_PASSWORD)"

    local POSTGRES_RESTORE_MODE=""
    log INFO "Recreating database ${DB_NAME}..."

    if [[ -n "$dump_file" ]]; then
        POSTGRES_RESTORE_MODE="dump"
        log INFO "Custom dump found: $(basename "$dump_file"). Restoring via pg_restore..."
        postgres_recreate_db "$PG_CID" "$ADMIN_USER" "$ADMIN_PASS" "$DB_NAME" "$DB_USER"
        docker exec -e PGPASSWORD="$ADMIN_PASS" -i "$PG_CID" pg_restore -U "$ADMIN_USER" -d "${DB_NAME}" -c -v < "$dump_file"
    elif [[ -n "$sql_file" ]]; then
        POSTGRES_RESTORE_MODE="sql"
        log INFO "SQL dump found: $(basename "$sql_file"). Restoring via psql..."
        postgres_recreate_db "$PG_CID" "$ADMIN_USER" "$ADMIN_PASS" "$DB_NAME" "$DB_USER"
        docker exec -e PGPASSWORD="$ADMIN_PASS" -i "$PG_CID" psql -U "$ADMIN_USER" -d "${DB_NAME}" -v ON_ERROR_STOP=1 < "$sql_file"
    else
        POSTGRES_RESTORE_MODE="volume"
        log INFO "No SQL dump found. Assuming the postgres-data volume already contains the DB. Skipping SQL import."
    fi

    # When the PostgreSQL DB is ready, start other containers
    log INFO "Starting the rest of the stack..."
    ensure_external_volumes

    docker_up_check || { log ERROR "Stack unhealthy after restore."; return 1; }
    post_up_tls_checks || true

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
    box_line "Domain (n8n):"            "https://${N8N_FQDN}"
    box_line "Restore from file:"       "$requested_spec"
    box_line "Local archive used:"      "$TARGET_RESTORE_FILE"
    box_line "Restore Timestamp:"       "$DATE"
    box_line "N8N Version:"             "$N8N_VERSION"
    box_line "N8N Directory:"           "$N8N_DIR"
    box_line "Log File:"                "$LOG_FILE"
    box_line "Volumes restored:"        "${restored_list}"
    case "$POSTGRES_RESTORE_MODE" in
        dump) box_line "PostgreSQL:" "Restored from custom dump (.dump)";;
        sql)  box_line "PostgreSQL:" "Restored from SQL file (.sql)";;
        *)    box_line "PostgreSQL:" "Restored from volume";;
    esac
    echo "═════════════════════════════════════════════════════════════"
}

################################################################################
# cleanup_stack()
#
# Purpose
#   Tear down the n8n Docker stack and remove project resources with two
#   levels of aggressiveness, while clearly previewing what will be deleted.
#
# Modes
#   safe (default via CLEANUP_MODE=safe)
#     - Runs `docker compose down --remove-orphans`
#     - Deletes named project volumes EXCEPT `letsencrypt`
#       (preserves TLS certs to avoid Let's Encrypt rate limits)
#     - Removes discovered project Docker networks
#     - Prunes dangling images (`docker image prune -f`)
#     - Keeps base images (n8nio/n8n, docker.n8n.io/n8nio/n8n, postgres)
#     - Does NOT wipe files in $N8N_DIR
#
#   all  (CLEANUP_MODE=all)
#     - Runs `docker compose down --remove-orphans -v` (also drops anonymous vols)
#     - Deletes ALL named project volumes, including `letsencrypt`
#     - Removes discovered project Docker networks
#     - Prunes dangling images AND removes base images (n8n + postgres)
#     - Wipes the project directory $N8N_DIR (via safe_wipe_target_dir)
#     - Prompts for a yes/no confirmation before executing
#
# What it does (high level)
#   1) Discovers compose-defined volumes and networks
#   2) Builds the exact deletion sets (volumes, networks, images, dir entries)
#   3) Prints a PREVIEW block showing every item that will be removed
#   4) If mode = all, asks for interactive confirmation (yes/no)
#   5) Executes the plan:
#        - docker compose down (with flags per mode)
#        - docker volume rm <named volumes>
#        - docker network rm <project networks>
#        - docker image prune -f
#        - (all) docker rmi -f <base images by ID>
#        - (all) safe_wipe_target_dir
################################################################################
cleanup_stack() {
    discover_from_compose
    discover_compose_networks || true

    local MODE="${CLEANUP_MODE:-safe}"
    local NUKE_ALL=false
    case "$MODE" in
        safe) NUKE_ALL=false ;;
        all)  NUKE_ALL=true  ;;
        *)    log ERROR "cleanup mode must be 'safe' or 'all', got '$MODE'"; exit 2 ;;
    esac

    # Flags for compose down
    local -a DOWN_FLAGS=(--remove-orphans)
    $NUKE_ALL && DOWN_FLAGS+=(-v)   # in ALL, also remove anonymous volumes

    # ---------- Determine resources to delete (preview) ----------

    # Volumes (named)
    local -a VOLS_TO_REMOVE=()      # logical names from compose
    local -a VOLS_EXISTING=()       # "logical|real" only if they currently exist
    if $NUKE_ALL; then
        VOLS_TO_REMOVE=("${DISCOVERED_VOLUMES[@]}")
    else
        local v
        for v in "${DISCOVERED_VOLUMES[@]}"; do
            [[ "$v" == "letsencrypt" ]] && continue
            VOLS_TO_REMOVE+=("$v")
        done
    fi
    # Map to real docker volume names and keep only those that exist
    if ((${#VOLS_TO_REMOVE[@]})); then
        local vname real
        for vname in "${VOLS_TO_REMOVE[@]}"; do
            real="$(resolve_volume_name "$vname" || expected_volume_name "$vname")"
            if docker volume inspect "$real" >/dev/null 2>&1; then
                VOLS_EXISTING+=("$vname|$real")
            fi
        done
    fi

    # Networks
    local -a NETS_TO_REMOVE=()
    if ((${#DISCOVERED_NETWORKS[@]})); then
        NETS_TO_REMOVE=("${DISCOVERED_NETWORKS[@]}")
    else
        local defnet
        defnet="$(project_default_network_name)"
        if [[ -n "$defnet" ]] && docker network inspect "$defnet" >/dev/null 2>&1; then
            NETS_TO_REMOVE+=("$defnet")
        fi
    fi

    # Images (ALL only): remove every image defined in docker-compose.yml (resolved by compose config)
    local -a IMAGES_TO_REMOVE=()   # pretty list for preview: "<repo[:tag|@digest]> (<id>|not present locally)"
    local -a IMAGE_IDS=()          # bare IDs to rmi -f
    if $NUKE_ALL; then
        local json
        if json="$(compose config --format json 2>/dev/null)"; then
            # 1) Collect images referenced by services (already env-resolved)
            local -a compose_images=()
            mapfile -t compose_images < <(
                printf '%s' "$json" | jq -r '.services[]?.image? // empty' | awk 'NF' | sort -u
            )

            # 2) Build maps of local images by "<repo:tag>" and "<repo@digest>" -> ID
            declare -A map_tag_to_id=()
            declare -A map_digest_to_id=()

            # repo:tag map
            while IFS= read -r line; do
                # "<repo>:<tag> <id>"
                local key="${line% *}"
                local val="${line##* }"
                [[ -n "$key" && -n "$val" ]] && map_tag_to_id["$key"]="$val"
            done < <(docker images --format '{{.Repository}}:{{.Tag}} {{.ID}}' 2>/dev/null || true)

            # repo@digest map
            while IFS= read -r line; do
                # "<repo>@<digest> <id>"
                local key="${line% *}"
                local val="${line##* }"
                # Skip entries where the digest part is literally "<none>"
                if [[ "${key#*@}" == "<none>" ]]; then
                    continue
                fi
                [[ -n "$key" && -n "$val" ]] && map_digest_to_id["$key"]="$val"
            done < <(docker images --digests --format '{{.Repository}}@{{.Digest}} {{.ID}}' 2>/dev/null || true)

            # 3) Resolve each compose image to an ID if present locally
            local img id
            for img in "${compose_images[@]}"; do
                if [[ "$img" == *"@"* ]]; then
                    id="${map_digest_to_id[$img]:-}"
                else
                    id="${map_tag_to_id[$img]:-}"
                fi
                if [[ -n "$id" ]]; then
                    IMAGES_TO_REMOVE+=("${img} (${id})")
                    IMAGE_IDS+=("$id")
                else
                    IMAGES_TO_REMOVE+=("${img} (not present locally)")
                fi
            done

            # 4) De-dupe IDs
            if ((${#IMAGE_IDS[@]})); then
                mapfile -t IMAGE_IDS < <(printf '%s\n' "${IMAGE_IDS[@]}" | awk 'NF' | sort -u)
            fi
        else
            log WARN "Could not parse 'compose config' JSON; skipping compose-defined image list."
        fi
    fi

    # Directory contents to wipe (only ALL)
    local -a DIR_ENTRIES=()
    if $NUKE_ALL; then
        shopt -s dotglob nullglob
        local p
        for p in "$N8N_DIR"/*; do
            DIR_ENTRIES+=("$(basename "$p")")
        done
        shopt -u dotglob nullglob
    fi

    # ---------- Preview ----------
    echo "════════════════ CLEANUP PREVIEW (mode: ${MODE^^}) ════════════════"
    {
        local IFS=' '
        printf 'Will run: docker compose down %s\n\n' "${DOWN_FLAGS[*]}"
    }
    echo "Named volumes to be DELETED:"
    if ((${#VOLS_EXISTING[@]})); then
        local pair lv rv
        for pair in "${VOLS_EXISTING[@]}"; do
            IFS='|' read -r lv rv <<< "$pair"
            echo "  - ${lv}  ->  ${rv}"
        done
    else
        echo "  - <none>"
    fi
    echo

    echo "Docker networks to be DELETED:"
    if ((${#NETS_TO_REMOVE[@]})); then
        local n
        for n in "${NETS_TO_REMOVE[@]}"; do
            echo "  - ${n}"
        done
    else
        echo "  - <none detected>"
    fi
    echo

    echo "Dangling images to be PRUNED:"
    echo "  - (dynamic: docker image prune -f)"

    if $NUKE_ALL; then
        echo
        echo "Compose-defined images to DELETE:"
        if ((${#IMAGES_TO_REMOVE[@]})); then
            local i
            for i in "${IMAGES_TO_REMOVE[@]}"; do
                echo "  - ${i}"
            done
        else
            echo "  - <none discovered>"
        fi
        echo
        echo "Target directory to be WIPED: $N8N_DIR"
        if ((${#DIR_ENTRIES[@]})); then
            echo "  Contents to be removed:"
            local d
            for d in "${DIR_ENTRIES[@]}"; do
                echo "    - $d"
            done
        else
            echo "  (directory is empty)"
        fi
        echo
        echo "NOTE: letsencrypt volume WILL be removed (Let's Encrypt rate limits may apply)."
    else
        echo
        echo "NOTES (SAFE):"
        echo "  - Preserving 'letsencrypt' volume (keeps TLS certs)."
        echo "  - No directory wipe."
        echo "  - Base images are kept."
    fi
    echo "══════════════════════════════════════════════════════════════"

    # ---------- Confirmation (ALL only) ----------
    if $NUKE_ALL; then
        local ans
        read -r -p "Proceed with FULL cleanup (all)? (yes/no) [no]: " ans
        case "${ans,,}" in
            y|yes) ;;
            *) log INFO "Cleanup (all) cancelled by user."; return 0 ;;
        esac
    fi

    # ---------- Execute ----------
    log INFO "Shutting down stack…"
    if [[ -f "$N8N_DIR/docker-compose.yml" ]]; then
        compose down "${DOWN_FLAGS[@]}" || true
    else
        log WARN "docker-compose.yml not found at \$N8N_DIR; attempting plain 'docker compose down' in $PWD."
        docker compose down "${DOWN_FLAGS[@]}" || true
    fi

    if ((${#VOLS_EXISTING[@]})); then
        log INFO "Removing named volumes…"
        local pair lv rv
        for pair in "${VOLS_EXISTING[@]}"; do
            IFS='|' read -r lv rv <<< "$pair"
            if docker volume inspect "$rv" >/dev/null 2>&1; then
                if docker volume rm "$rv" >/dev/null 2>&1; then
                    log INFO "Removed volume: $lv ($rv)"
                else
                    log WARN "Could not remove volume '$lv' ($rv) — maybe still in use?"
                fi
            else
                log INFO "Already gone: $lv ($rv) (removed by compose)"
            fi
        done
    fi

    log INFO "Removing docker networks…"
    remove_compose_networks
    if $NUKE_ALL; then
        purge_project_volumes_by_label
        purge_project_networks_by_label
    fi

    log INFO "Pruning dangling images…"
    docker image prune -f >/dev/null 2>&1 || true
    if $NUKE_ALL && ((${#IMAGE_IDS[@]})); then
        log WARN "Removing compose-defined images…"
        docker rmi -f "${IMAGE_IDS[@]}" >/dev/null 2>&1 || true
    fi

    if $NUKE_ALL; then
        safe_wipe_target_dir
    fi

    log INFO "Cleanup completed (mode=${MODE^^})."
    if [[ "$MODE" == "safe" ]]; then
        log INFO "Preserved 'letsencrypt' volume. Use '--cleanup all' to remove everything."
    fi
}

################################################################################
# parse_args()
# Description:
#   Parse CLI arguments and set global flags/vars.
#   - Enforces exactly one primary action.
################################################################################
parse_args() {
    # NOTE: keep short/long specs in sync with usage()
    SHORT="i:uv:m:c:bad:l:r:e:ns:fh"
    LONG="install:,upgrade,version:,ssl-email:,cleanup:,backup,available,dir:,log-level:,restore:,email-to:,notify-on-success,remote-name:,force,help,mode:,monitoring,expose-prometheus,subdomain-n8n:,subdomain-grafana:,subdomain-prometheus:,basic-auth-user:,basic-auth-pass:"

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
                shift
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
                CLEANUP_MODE="$2"
                shift 2
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
                EMAIL_TO="$2"
                EMAIL_EXPLICIT=true
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
            --monitoring)
                MONITORING=true
                shift
                ;;
            --expose-prometheus)
                EXPOSE_PROMETHEUS=true
                shift
                ;;
            --subdomain-n8n)
                SUBDOMAIN_N8N="$2"
                shift 2
                ;;
            --subdomain-grafana)
                SUBDOMAIN_GRAFANA="$2"
                shift 2
                ;;
            --subdomain-prometheus)
                SUBDOMAIN_PROMETHEUS="$2"
                shift 2
                ;;
            --basic-auth-user)
                BASIC_AUTH_USER="$2"
                shift 2
                ;;
            --basic-auth-pass)
                BASIC_AUTH_PASS="$2"
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

    # Enforce exactly one primary action
    local count=0
    $DO_INSTALL   && ((count+=1))
    $DO_UPGRADE   && ((count+=1))
    $DO_BACKUP    && ((count+=1))
    $DO_RESTORE   && ((count+=1))
    $DO_CLEANUP   && ((count+=1))
    $DO_AVAILABLE && ((count+=1))
    if (( count != 1 )); then
        log ERROR "Choose exactly one action."
        usage
    fi

    # Validate install mode if used
    if $DO_INSTALL; then
        case "${INSTALL_MODE}" in
            single|queue) ;;
            *) log ERROR "Invalid --mode '${INSTALL_MODE}' (use single|queue)"; exit 2 ;;
        esac
    fi

    if $DO_CLEANUP; then
        case "${CLEANUP_MODE}" in
            safe|all) ;;
            *) log ERROR "cleanup expects with option 'safe' or 'all'"; exit 2 ;;
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
        ensure_prereqs
        upgrade_stack
    elif $DO_BACKUP; then
        ensure_prereqs
        backup_stack
    elif $DO_RESTORE; then
        ensure_prereqs
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
