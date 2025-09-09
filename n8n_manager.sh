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
#     • DNS/TLS checks performed against the n8n FQDN only (subdomain-n8n.domain).
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

  -u, --upgrade <DOMAIN>
        Upgrade n8n to target version (or latest). Domain/FQDNs are read from .env.

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

  $0 --install example.com -m you@example.com
      # Install the latest n8n version with single mode

  $0 --install example.com -m you@example.com -v 1.105.3 --mode queue
      # Install a specific n8n version with queue mode

  $0 --install example.com -m you@example.com -d /path/to/n8n --mode queue
      # Install the latest n8n version (queue mode) to a specific target directory

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
# install_prereqs()
# Description:
#   Install Docker Engine and Compose v2 with safe fallbacks, then common tools.
#
# Behaviors:
#   - If Docker already works → skip engine install but still ensure deps.
#   - Debian/Ubuntu family: use official Docker APT repo when codename supported.
#   - Non-Debian/Ubuntu or unsupported codename: use convenience script.
#   - Installs ancillary packages (jq, rsync, tar, msmtp-mta, dnsutils, openssl, pigz, vim).
#   - Enables/starts docker via systemd when available.
#   - Adds invoking user to the "docker" group (effective after re-login).
#
# Returns:
#   0 on success; 1 if Docker not available after all attempts.
################################################################################
install_prereqs() {
    # Fast path: Docker already installed and responding?
    if command -v docker >/dev/null 2>&1 && docker version >/dev/null 2>&1; then
        log INFO "Docker already installed. Skipping engine install."
    else
        # Try to use APT repo on Debian/Ubuntu; otherwise fall back to script
        . /etc/os-release 2>/dev/null || true
        local DISTRO_ID="${ID:-}"
        local DISTRO_LIKE="${ID_LIKE:-}"
        local DISTRO_CODENAME="${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}"
        if [[ -z "$DISTRO_CODENAME" ]] && command -v lsb_release >/dev/null 2>&1; then
            DISTRO_CODENAME="$(lsb_release -cs 2>/dev/null || true)"
        fi

        local is_deb_like=false
        if [[ "$DISTRO_ID" =~ ^(debian|ubuntu)$ ]] || [[ "$DISTRO_LIKE" == *debian* ]] || [[ "$DISTRO_LIKE" == *ubuntu* ]]; then
            is_deb_like=true
        fi

        if $is_deb_like && command -v apt-get >/dev/null 2>&1; then
            log INFO "Detected Debian/Ubuntu family (ID=${DISTRO_ID:-?}, CODENAME=${DISTRO_CODENAME:-?})."
            DEBIAN_FRONTEND=noninteractive apt-get update -y || true
            DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl gnupg lsb-release || true

            local repo_base="debian"
            [[ "$DISTRO_ID" == "ubuntu" || "$DISTRO_LIKE" == *ubuntu* ]] && repo_base="ubuntu"

            if [[ -z "$DISTRO_CODENAME" ]]; then
                log WARN "Could not determine distro codename; using Docker convenience script."
                curl -fsSL https://get.docker.com | sh
            else
                local REPO_CHECK_URL="https://download.docker.com/linux/${repo_base}/dists/${DISTRO_CODENAME}/Release"
                if curl -fsS --connect-timeout 5 --max-time 10 "$REPO_CHECK_URL" >/dev/null 2>&1; then
                    log INFO "Configuring Docker APT repo for ${repo_base} ${DISTRO_CODENAME}…"
                    install -d -m 0755 /etc/apt/keyrings
                    if [[ ! -s /etc/apt/keyrings/docker.gpg ]]; then
                        curl -fsSL "https://download.docker.com/linux/${repo_base}/gpg" \
                          | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
                        chmod a+r /etc/apt/keyrings/docker.gpg
                    else
                        log INFO "Docker GPG key already present."
                    fi

                    local arch; arch="$(dpkg --print-architecture)"
                    echo "deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${repo_base} ${DISTRO_CODENAME} stable" \
                      > /etc/apt/sources.list.d/docker.list

                    DEBIAN_FRONTEND=noninteractive apt-get update -y || true
                    log INFO "Installing Docker Engine and Compose v2 from Docker APT repo…"
                    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y \
                        docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
                        log WARN "APT install failed; falling back to Docker convenience script."
                        curl -fsSL https://get.docker.com | sh
                    fi
                else
                    log WARN "Docker repo does not publish '${repo_base}/${DISTRO_CODENAME}'; using convenience script."
                    curl -fsSL https://get.docker.com | sh
                fi
            fi
        else
            log INFO "Non–Debian/Ubuntu or no apt-get detected (ID=${DISTRO_ID:-?}); using Docker convenience script."
            curl -fsSL https://get.docker.com | sh
        fi
    fi

    # Verify Docker availability
    if ! command -v docker >/dev/null 2>&1 || ! docker version >/dev/null 2>&1; then
        log ERROR "Docker installation did not complete successfully."
        return 1
    fi

    # Ensure ancillary tools (best effort; only on apt-based systems)
    if command -v apt-get >/dev/null 2>&1; then
        log INFO "Installing common dependencies (jq, rsync, tar, msmtp-mta, dnsutils, openssl, pigz, vim)…"
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
            jq rsync tar msmtp-mta dnsutils openssl pigz vim apache2-utils || true
    else
        log WARN "apt-get not found; skipping ancillary package installation."
    fi

    # Enable/start docker via systemd when present
    if command -v systemctl >/dev/null 2>&1; then
        systemctl enable --now docker || true
    fi

    # Add invoking user to docker group (effective after re-login)
    local CURRENT_USER="${SUDO_USER:-$(id -un)}"
    if ! getent group docker >/dev/null 2>&1; then
        log INFO "Creating 'docker' group…"
        groupadd docker || true
    fi
    if [[ "$CURRENT_USER" != "root" ]]; then
        log INFO "Adding user '$CURRENT_USER' to the 'docker' group (you may need to log out/in)…"
        usermod -aG docker "$CURRENT_USER" || true
        log INFO "Tip: run 'newgrp docker' to activate group membership in the current shell."
    fi

    # Quick version notes
    log INFO "Docker version: $(docker --version 2>/dev/null || echo 'unknown')"
    if docker compose version >/dev/null 2>&1; then
        log INFO "Docker Compose v2: $(docker compose version 2>/dev/null | head -n1)"
    else
        log WARN "Docker Compose v2 not detected via 'docker compose'."
    fi

    log INFO "Docker and dependencies are ready."
    return 0
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
    if [[ ! -t 0 ]]; then
        log ERROR "No TTY to prompt for --ssl-email. Please pass -m <email>."
        exit 2
    fi
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

    # --- NEW: persist explicit FQDNs---
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
#   - Installs Docker/Compose and dependencies (install_prereqs()).
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

    [[ -z "${SSL_EMAIL:-}" ]] && prompt_ssl_email
    install_prereqs
    copy_templates_for_mode
    load_env_file
    preflight_dns_checks
    validate_compose_and_env
    discover_from_compose
    ensure_external_volumes

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

    log INFO "Checking current and target n8n versions..."
    cd "$N8N_DIR" || { log ERROR "Failed to change directory to $N8N_DIR"; return 1; }

    local current_version target_version
    current_version=$(get_current_n8n_version || echo "0.0.0")

    target_version="$N8N_VERSION"
    if [[ -z "$target_version" || "$target_version" == "latest" ]]; then
        target_version=$(get_latest_n8n_version)
        [[ -z "$target_version" ]] && { log ERROR "Could not determine latest n8n tag."; exit 1; }
    fi
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

    validate_image_tag "$target_version" || { log ERROR "Image tag not found: $target_version"; exit 1; }
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
# snapshot_bootstrap()
# Description:
#   Create (or refresh if missing) the initial snapshot tree for change detection.
#
# Behaviors:
#   - Creates snapshot directories for each volume and for config if absent.
#   - Rsyncs current data of volumes and config (.env, docker-compose.yml).
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

    require_cmd msmtp || { log ERROR "msmtp not available; cannot send email."; return 1; }
    if ! $EMAIL_EXPLICIT; then return 0; fi
    if [[ -z "$SMTP_USER" || -z "$SMTP_PASS" || -z "$EMAIL_TO" ]]; then
        log ERROR "Email requested (-e) but SMTP_USER/SMTP_PASS/EMAIL_TO not set → cannot send email."
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

    wait_for_containers_healthy || return 1

    if [[ "$BACKUP_REQUIRE_TLS" == "true" ]]; then
        verify_traefik_certificate "$N8N_FQDN" || return 1
    fi

    if do_local_backup; then
        BACKUP_STATUS="SUCCESS"
        log INFO "Local backup succeeded: $BACKUP_FILE"
        # Refresh our snapshot so next run sees “no changes”
        snapshot_refresh
        write_summary_row "$ACTION" "$BACKUP_STATUS"
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
                ( cd "$tmp_dir" \
                    && sha256sum -c "$(basename "${local_path}.sha256")" ) \
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
# ensure_db_role_exists()
# Description:
#   Ensure a Postgres role exists (LOGIN); no password is set here.
#   Avoids failures when recreating a DB with OWNER=<role> that doesn't exist.
#
# Args:
#   $1 -> PG_CID     : postgres container id/name
#   $2 -> ADMIN_USER : superuser to run DDL (e.g., "postgres")
#   $3 -> ADMIN_PASS : password for ADMIN_USER (may be empty for peer/trust)
#   $4 -> ROLE_NAME  : role to ensure exists
#
# Returns:
#   0 on success.
################################################################################
ensure_db_role_exists() {
    local pgcid="$1" admin="$2" pass="$3" role="$4"
    docker exec -e PGPASSWORD="$pass" -i "$pgcid" psql -U "$admin" -d postgres -v ON_ERROR_STOP=1 -c \
"DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='${role}') THEN
    EXECUTE format('CREATE ROLE %I LOGIN', '${role}');
  END IF;
END
\$\$;"
}

################################################################################
# drop_and_create_db()
# Description:
#   Drop the target database (terminating active sessions) and create it again
#   owned by DB_OWNER inside the running Postgres container.
#
# Args:
#   $1 -> PG_CID     : postgres container id/name (from docker compose)
#   $2 -> ADMIN_USER : superuser to run DDL (e.g., "postgres")
#   $3 -> ADMIN_PASS : password for ADMIN_USER (may be empty for peer/trust)
#   $4 -> DB_NAME    : database to (re)create
#   $5 -> DB_OWNER   : role to own the new database (must already exist)
#
# Behaviors:
#   - Best-effort terminates active backends before DROP (errors ignored).
#   - Executes: DROP DATABASE IF EXISTS <db>; CREATE DATABASE <db> OWNER <owner>.
#   - Uses ON_ERROR_STOP=1 so DROP/CREATE failures propagate non-zero.
#   - Does not create DB_OWNER; assumes the role exists.
#   - Uses cluster defaults for encoding/locale/template.
#
# Returns:
#   0 on success; non-zero if DROP or CREATE fails.
################################################################################
drop_and_create_db() {
    local pgcid="$1" admin="$2" pass="$3" db="$4" owner="$5"
    docker exec -e PGPASSWORD="$pass" -i "$pgcid" psql -U "$admin" -d postgres -v ON_ERROR_STOP=1 -c \
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='${db}' AND pid <> pg_backend_pid();" || true
    docker exec -e PGPASSWORD="$pass" -i "$pgcid" psql -U "$admin" -d postgres -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS ${db};"
    docker exec -e PGPASSWORD="$pass" -i "$pgcid" psql -U "$admin" -d postgres -v ON_ERROR_STOP=1 -c "CREATE DATABASE ${db} OWNER ${owner};"
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
    # Ensure owner role exists to avoid CREATE DATABASE OWNER failures
    ensure_db_role_exists "$PG_CID" "$ADMIN_USER" "$ADMIN_PASS" "$DB_USER"

    if [[ -n "$dump_file" ]]; then
        POSTGRES_RESTORE_MODE="dump"
        log INFO "Custom dump found: $(basename "$dump_file"). Restoring via pg_restore..."
        log INFO "Recreate database ${DB_NAME}..."
        drop_and_create_db "$PG_CID" "$ADMIN_USER" "$ADMIN_PASS" "$DB_NAME" "$DB_USER"
        docker exec -e PGPASSWORD="$ADMIN_PASS" -i "$PG_CID" pg_restore -U "$ADMIN_USER" -d "${DB_NAME}" -c -v < "$dump_file"
    elif [[ -n "$sql_file" ]]; then
        POSTGRES_RESTORE_MODE="sql"
        log INFO "SQL dump found: $(basename "$sql_file"). Restoring via psql..."
        log INFO "Recreate database ${DB_NAME}..."
        drop_and_create_db "$PG_CID" "$ADMIN_USER" "$ADMIN_PASS" "$DB_NAME" "$DB_USER"
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

    log INFO "Shutting down stack (respect KEEP_CERTS=${KEEP_CERTS})..."
    local -a down_flags=(--remove-orphans)
    [[ "$KEEP_CERTS" == "false" ]] && down_flags+=(-v)

    if [[ -f "$N8N_DIR/docker-compose.yml" ]]; then
        compose down "${down_flags[@]}" || true
    else
        log WARN "docker-compose.yml not found at \$N8N_DIR; attempting plain 'docker compose down' in $PWD."
        docker compose down "${down_flags[@]}" || true
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
    SHORT="i:u::v:m:cbad:l:r:e:ns:fh"
    LONG="install:,upgrade::,version:,ssl-email:,cleanup,backup,available,dir:,log-level:,restore:,email-to:,notify-on-success,remote-name:,force,help,mode:,monitoring,expose-prometheus,subdomain-n8n:,subdomain-grafana:,subdomain-prometheus:,basic-auth-user:,basic-auth-pass:"

    PARSED=$(getopt --options="$SHORT" --longoptions="$LONG" --name "$0" -- "$@") || usage
    eval set -- "$PARSED"

    while true; do
        case "$1" in
            -i|--install)
                DO_INSTALL=true
                DOMAIN="$(parse_domain_arg "$2")"
                shift 2 ;;
            -u|--upgrade)
                DO_UPGRADE=true
                # optional domain parameter ignored; we read from .env
                if [[ "$2" != "--" && "$2" != "-"* ]]; then shift 2; else shift; fi ;;
            -v|--version)
                N8N_VERSION="$2"; shift 2 ;;
            -m|--ssl-email)
                SSL_EMAIL="$2"; shift 2 ;;
            -c|--cleanup)
                DO_CLEANUP=true; shift ;;
            -b|--backup)
                DO_BACKUP=true; shift ;;
            -a|--available)
                DO_AVAILABLE=true; shift ;;
            -d|--dir)
                N8N_DIR="$2"; shift 2 ;;
            -l|--log-level)
                LOG_LEVEL="${2^^}"; shift 2 ;;
            -r|--restore)
                DO_RESTORE=true; TARGET_RESTORE_FILE="$2"; shift 2 ;;
            -e|--email-to)
                EMAIL_TO="$2"; EMAIL_EXPLICIT=true; shift 2 ;;
            -n|--notify-on-success)
                NOTIFY_ON_SUCCESS=true; shift ;;
            -s|--remote-name)
                RCLONE_REMOTE="$2"; shift 2 ;;
            --mode)
                INSTALL_MODE="$2"; shift 2 ;;
            --monitoring)
                MONITORING=true; shift ;;
            --expose-prometheus)
                EXPOSE_PROMETHEUS=true; shift ;;
            --subdomain-n8n)
                SUBDOMAIN_N8N="$2"; shift 2 ;;
            --subdomain-grafana)
                SUBDOMAIN_GRAFANA="$2"; shift 2 ;;
            --subdomain-prometheus)
                SUBDOMAIN_PROMETHEUS="$2"; shift 2 ;;
            --basic-auth-user)
                BASIC_AUTH_USER="$2"; shift 2 ;;
            --basic-auth-pass)
                BASIC_AUTH_PASS="$2"; shift 2 ;;
            -f|--force)
                FORCE_FLAG=true; shift ;;
            -h|--help)
                usage ;;
            --)
                shift; break ;;
            *)
                usage ;;
        esac
    done

    local count=0
    $DO_INSTALL   && ((count+=1))
    $DO_UPGRADE   && ((count+=1))
    $DO_BACKUP    && ((count+=1))
    $DO_RESTORE   && ((count+=1))
    $DO_CLEANUP   && ((count+=1))
    $DO_AVAILABLE && ((count+=1))
    (( count == 1 )) || { log ERROR "Choose exactly one action."; usage; }

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
