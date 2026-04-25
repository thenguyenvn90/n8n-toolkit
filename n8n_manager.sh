#!/bin/bash
set -euo pipefail
set -o errtrace
IFS=$'\n\t'

#############################################################################################
# N8N Installation, Upgrade, Backup & Restore Manager (Mode-aware: Single or Queue)
# Author:      TheNguyen
# Email:       thenguyen.ai.automation@gmail.com
# Version:     3.0.0
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
LIB_DIR="$SCRIPT_DIR/lib"
# Source order is load-bearing: common.sh must come first (all other libs depend on its functions and globals)
for _lib in common.sh install.sh upgrade.sh backup.sh cleanup.sh; do
    _path="$LIB_DIR/$_lib"
    if [[ -f "$_path" ]]; then
        # shellcheck disable=SC1090
        source "$_path"
    else
        echo "[ERROR] Missing library: $_path" >&2
        exit 1
    fi
done
unset _lib _path

TEMPLATE_SINGLE="$SCRIPT_DIR/deploy/single-mode"
TEMPLATE_QUEUE="$SCRIPT_DIR/deploy/queue-mode"

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
