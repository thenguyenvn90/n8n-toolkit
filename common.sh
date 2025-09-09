#!/bin/bash
# common.sh — Common helpers reused by n8n_manager.sh & others
set -euo pipefail
IFS=$'\n\t'

#############################################################################################
# n8n_common.sh - Shared functions for install/upgrade/backup/restore tooling
# Provides:
#   • Logging with levels & timestamps
#   • Error/interrupt handling (exposed; caller sets traps)
#   • Root privilege check
#   • .env load / read / upsert helpers
#   • Docker Compose wrapper
#   • Compose discovery (services, volumes, external volumes, expected container names)
#   • Health checks + log dumps
#   • “up + wait healthy” helper (with external volume ensure)
#   • Version & image utilities
#   • Domain DNS sanity check and optional TLS verification
#   • ensure_monitoring_auth(): generate htpasswd usersfile once
#############################################################################################

# ------------------------------ Globals used by discovery ------------------------------
# (Arrays are global so caller can inspect the results)
declare -a DISCOVERED_SERVICES=()
declare -a DISCOVERED_VOLUMES=()
declare -a DISCOVERED_VOLUME_EXTERNAL=()
declare -a DISCOVERED_CONTAINER_NAMES=()
declare -a RUNNING_CONTAINER_NAMES=()
DISCOVERED_MODE="unknown"

# Logging level
LOG_LEVEL="${LOG_LEVEL:-INFO}"
LOG_LEVEL="${LOG_LEVEL^^}"

################################################################################
# log()
# Description:
#     Structured logger with levels (DEBUG, INFO, WARN, ERROR).
#
# Behaviors:
#     - Respects global LOG_LEVEL (defaults to INFO).
#     - Sends WARN/ERROR to stderr; DEBUG/INFO to stdout.
#     - Format: [YYYY-MM-DD HH:MM:SS] [LEVEL] message
#
# Returns:
#     0 always.
################################################################################
log() {
    local level="$1"
    shift || true
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"

    case "$LOG_LEVEL" in
        DEBUG) : ;;
        INFO)  [[ "$level" == "DEBUG" ]] && return 0 ;;
        WARN)  [[ "$level" == "DEBUG" || "$level" == "INFO" ]] && return 0 ;;
        ERROR) [[ "$level" != "ERROR" ]] && return 0 ;;
        *)     : ;;
    esac

    if [[ "$level" == "WARN" || "$level" == "ERROR" ]]; then
        echo "[$ts] [$level] $*" >&2
    else
        echo "[$ts] [$level] $*"
    fi
}

################################################################################
# print_stacktrace()
# Description:
#     Print a compact stack trace (most recent call first) for diagnostics.
#
# Returns:
#     0 always.
################################################################################
print_stacktrace() {
    local depth=$(( ${#FUNCNAME[@]} - 1 ))
    [[ $depth -lt 1 ]] && return 0
    log ERROR "Stack trace (most recent call first):"
    for ((i=0; i<depth; i++)); do
        local func="${FUNCNAME[$i]:-main}"
        local src="${BASH_SOURCE[$i+1]:-${BASH_SOURCE[0]}}"
        local line="${BASH_LINENO[$i]:-0}"
        log ERROR "  at ${func}()  ${src}:${line}"
    done
}

################################################################################
# on_error()
# Description:
#     Trap handler for ERR: log failing command/location, show stack & compose ps.
#
# Returns:
#     Never returns (exits with prior exit code).
################################################################################
on_error() {
    local exit_code=$?
    local cmd="$BASH_COMMAND"
    local where_file="${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}"
    local where_line="${BASH_LINENO[0]:-0}"
    local where_func="${FUNCNAME[1]:-main}"
    log ERROR "Command failed (exit $exit_code): $cmd"
    log ERROR "Location: ${where_file}:${where_line} in ${where_func}()"
    print_stacktrace
    if [[ -n "${N8N_DIR:-}" && -f "$N8N_DIR/docker-compose.yml" ]]; then
        (cd "$N8N_DIR" && docker compose -f "$N8N_DIR/docker-compose.yml" ps) || true
    fi
    exit "$exit_code"
}

################################################################################
# on_interrupt()
# Description:
#     Trap handler for INT/TERM/HUP: stop stack cleanly and exit.
#
# Returns:
#     Never returns (exits 130).
################################################################################
on_interrupt() {
    log ERROR "Interrupted (SIGINT/SIGTERM). Stopping compose (if present) and exiting..."
    if [[ -n "${N8N_DIR:-}" && -f "$N8N_DIR/docker-compose.yml" ]]; then
        (cd "$N8N_DIR" && docker compose -f "$N8N_DIR/docker-compose.yml" down) || true
    fi
    exit 130
}

################################################################################
# check_root()
# Description:
#     Ensure the script is running as root (EUID = 0).
#
# Returns:
#     0 if root; 1 otherwise.
################################################################################
check_root() {
    if [[ ${EUID:-$(id -u)}"x" != "0x" ]]; then
        log ERROR "This script must be run as root."
        return 1
    fi
}

################################################################################
# require_cmd()
# Description:
#     Ensure a required executable is available; if missing, auto-install via APT
#     on Debian/Ubuntu where possible (except Docker).
#
# Returns:
#     0 on success; 1 on failure.
################################################################################
require_cmd() {
    local cmd="$1"

    if command -v "$cmd" >/dev/null 2>&1; then
        return 0
    fi

    if [[ "$cmd" == "docker" ]]; then
        log ERROR "Docker is missing. Please run the Docker installer step (install_prereqs) first."
        return 1
    fi

    if ! command -v apt-get >/dev/null 2>&1; then
        log ERROR "Command '$cmd' not found and no supported package manager (apt-get) available."
        return 1
    fi

    local pkg="$cmd"
    case "$cmd" in
        msmtp)  pkg="msmtp-mta" ;;
        dig)    pkg="dnsutils"  ;;
        getent) pkg="libc-bin"  ;;
        gpg)    pkg="gnupg"     ;;
    esac

    if [[ "${APT_UPDATED:-false}" != true ]]; then
        log INFO "Updating package index (apt-get update)…"
        apt-get update -y || true
        APT_UPDATED=true
    fi

    log INFO "Installing missing command '$cmd' (package: $pkg)…"
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$pkg" || true

    if command -v "$cmd" >/dev/null 2>&1; then
        return 0
    fi

    log ERROR "Failed to install dependency '$cmd' (tried package: $pkg). Please install it manually."
    return 1
}

################################################################################
# parse_domain_arg()
# Description:
#     Normalize and validate a domain/hostname string.
#
# Output:
#     Prints normalized domain to stdout on success.
#
# Returns:
#     0 on success; exits 2 on invalid input.
################################################################################
parse_domain_arg() {
    local raw="$1"
    local d

    d="${raw,,}"
    d="${d#"${d%%[![:space:]]*}"}"
    d="${d%"${d##*[![:space:]]}"}"
    d="${d#http://}"; d="${d#https://}"
    d="${d%%/*}"
    d="${d%%\?*}"
    d="${d%%\#*}"
    d="${d%%:*}"
    d="${d%.}"

    [[ "$d" == www.* ]] && d="${d#www.}"

    local re='^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'
    if [[ -z "$d" || ${#d} -gt 253 || ! "$d" =~ $re ]]; then
        log ERROR "Invalid domain: '$raw' → '$d'. Expected a hostname like n8n.example.com"
        exit 2
    fi

    printf '%s\n' "$d"
}

################################################################################
# mask_secret()
# Description:
#     Mask a secret by showing only the first and last 4 characters.
#
# Output:
#     Prints masked secret.
#
# Returns:
#     0 always.
################################################################################
mask_secret() {
    local s="$1"
    local n=${#s}
    (( n<=8 )) && { printf '%s\n' "$s"; return; }
    printf '%s\n' "${s:0:4}***${s: -4}"
}

################################################################################
# looks_like_b64()
# Description:
#     Heuristic check whether a string looks like base64 (proper padding).
#
# Returns:
#     0 if matches; 1 otherwise.
################################################################################
looks_like_b64() {
    [[ "$1" =~ ^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$ ]]
}

################################################################################
# upsert_env_var()
# Description:
#     Insert or update KEY=VALUE in a .env file idempotently.
#
# Behaviors:
#     - Creates the file if missing.
#     - Escapes backslashes and '&' for sed safety.
#
# Returns:
#     0 on success.
################################################################################
upsert_env_var() {
    local key="$1" val="$2" file="$3"
    [[ -f "$file" ]] || : > "$file"

    local esc="${val//\\/\\\\}"; esc="${esc//&/\\&}"; esc="${esc//|/\\|}"
    if grep -qE "^${key}=" "$file"; then
        sed -i "s|^${key}=.*$|${key}=${esc}|" "$file"
    else
        printf '%s=%s\n' "$key" "$val" >> "$file"
    fi
}

################################################################################
# load_env_file()
# Description:
#     Load environment variables from a .env file into the current shell.
#
# Returns:
#     0 on success or when file missing (no-op).
################################################################################
load_env_file() {
    local f="${1:-${ENV_FILE:-}}"
    [[ -z "$f" ]] && f="${N8N_DIR:-$PWD}/.env"
    [[ -f "$f" ]] || { log INFO "No .env to load at: $f (skip)"; return 0; }
    set -o allexport
    # shellcheck disable=SC1090
    source "$f"
    set +o allexport
}

################################################################################
# read_env_var()
# Description:
#     Read and print the value of KEY from a .env-style file.
#
# Output:
#     Prints value to stdout.
#
# Returns:
#     0 if key found; 1 if file missing or key not found.
################################################################################
read_env_var() {
    local file="$1" key="$2" line val
    [[ -f "$file" ]] || return 1
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%$'\r'}"
        [[ "$line" =~ ^[[:space:]]*$ ]] && continue
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        if [[ "$line" =~ ^[[:space:]]*${key}[[:space:]]*=(.*)$ ]]; then
            val="${BASH_REMATCH[1]}"
            val="${val#"${val%%[![:space:]]*}"}"
            if [[ "$val" =~ ^\"(.*)\"[[:space:]]*$ ]]; then
                val="${BASH_REMATCH[1]}"; val="${val//\\\"/\"}"
            elif [[ "$val" =~ ^\'(.*)\'[[:space:]]*$ ]]; then
                val="${BASH_REMATCH[1]}"
            else
                val="${val%%#*}"; val="${val%"${val##*[![:space:]]}"}"
            fi
            printf '%s\n' "$val"; return 0
        fi
    done < "$file"
    return 1
}

################################################################################
# ensure_encryption_key()
# Description:
#     Verify N8N_ENCRYPTION_KEY exists in ENV_FILE and looks reasonable.
#
# Returns:
#     0 if present; 1 if missing.
################################################################################
ensure_encryption_key() {
    local key
    key="$(read_env_var "$ENV_FILE" N8N_ENCRYPTION_KEY || true)"
    if [[ -z "$key" ]]; then
        log ERROR "N8N_ENCRYPTION_KEY is missing in $ENV_FILE. Aborting to avoid an unrecoverable restore."
        return 1
    fi
    if ! looks_like_b64 "$key"; then
        log WARN "N8N_ENCRYPTION_KEY in $ENV_FILE does not look like base64. Continue at your own risk."
    fi
    log INFO "N8N_ENCRYPTION_KEY present (masked): $(mask_secret "$key")"
}

################################################################################
# compose()
# Description:
#     Wrapper around `docker compose` that targets the project directory,
#     compose file, and .env (and COMPOSE_PROJECT_NAME if set).
#
# Returns:
#     Exit code from `docker compose`; 1 on missing config.
################################################################################
compose() {
    if [[ -z "${N8N_DIR:-}" || -z "${COMPOSE_FILE:-}" || -z "${ENV_FILE:-}" ]]; then
        log ERROR "compose(): N8N_DIR/COMPOSE_FILE/ENV_FILE must be set"
        return 1
    fi

    [[ -f "$COMPOSE_FILE" ]] || { log ERROR "compose(): compose file not found: $COMPOSE_FILE"; return 1; }
    [[ -f "$ENV_FILE"    ]] || { log ERROR "compose(): env file not found: $ENV_FILE";       return 1; }

    local -a flags=( --project-directory "$N8N_DIR" -f "$COMPOSE_FILE" --env-file "$ENV_FILE" )

    local compose_project_name
    compose_project_name="$(read_env_var "$ENV_FILE" COMPOSE_PROJECT_NAME || true)"
    if [[ -n "$compose_project_name" ]]; then
        flags+=( -p "$compose_project_name" )
    fi

    docker compose "${flags[@]}" "$@"
    return $?
}

################################################################################
# container_id_for_service()
# Description:
#     Resolve a docker-compose SERVICE name to the ID of its running container
#     within the current compose project.
#
# Behaviors:
#     - Uses `compose ps -q <service>` (project-aware).
#     - If the service is scaled, prints only the FIRST ID.
#     - Prints nothing if no running container is found.
#
# Args:
#     $1 -> Service name (e.g., "postgres").
#
# Output:
#     Container ID (SHA) to stdout on success; nothing if not found.
#
# Returns:
#     0 always (even if not found), to keep call sites simple.
################################################################################
container_id_for_service() {
    compose ps -q "$1" 2>/dev/null | awk 'NF{print; exit}'
}

################################################################################
# container_name_for_service()
# Description:
#     Resolve a docker-compose SERVICE name to the Docker container NAME of its
#     running instance within the current compose project.
#
# Behaviors:
#     - Calls container_id_for_service(); inspects the container `.Name`
#       and strips the leading slash.
#     - If no running container exists, prints nothing.
#
# Args:
#     $1 -> Service name (e.g., "postgres").
#
# Output:
#     Docker container name (e.g., "n8n-postgres-1") to stdout; nothing if absent.
#
# Returns:
#     0 always.
################################################################################
container_name_for_service() {
    local cid
    cid="$(container_id_for_service "$1")" || true
    [[ -n "$cid" ]] && docker inspect --format '{{.Name}}' "$cid" 2>/dev/null | sed 's#^/##'
}

################################################################################
# discover_from_compose()
# Description:
#     Parse docker compose to discover services, volumes, external volumes, and
#     expected container names (explicit container_name or service fallback).
#
# Returns:
#     0 on success; non-zero on failure to parse services.
################################################################################
discover_from_compose() {
    DISCOVERED_SERVICES=()
    DISCOVERED_VOLUMES=()
    DISCOVERED_VOLUME_EXTERNAL=()
    DISCOVERED_CONTAINER_NAMES=()

    if command -v jq >/dev/null 2>&1; then
        local json
        if json="$(compose config --format json 2>/dev/null)"; then
            mapfile -t DISCOVERED_SERVICES < <(printf '%s' "$json" | jq -r '.services | keys[]')
            mapfile -t DISCOVERED_VOLUMES  < <(printf '%s' "$json" | jq -r '(.volumes // {}) | keys[]?')
            if ((${#DISCOVERED_VOLUMES[@]})); then
                local vol is_ext
                for vol in "${DISCOVERED_VOLUMES[@]}"; do
                    is_ext="$(printf '%s' "$json" | jq -r --arg v "$vol" '((.volumes[$v].external // false) | tostring)')"
                    [[ "$is_ext" == "true" ]] && DISCOVERED_VOLUME_EXTERNAL+=( "$vol" )
                done
            fi
            local svc cname
            for svc in "${DISCOVERED_SERVICES[@]}"; do
                cname="$(printf '%s' "$json" | jq -r --arg s "$svc" '.services[$s].container_name // ""')"
                if [[ -n "$cname" ]]; then
                    DISCOVERED_CONTAINER_NAMES+=( "$cname" )
                else
                    DISCOVERED_CONTAINER_NAMES+=( "$svc" )
                fi
            done
        fi
    fi

    if ((${#DISCOVERED_SERVICES[@]}==0)); then
        local svcs vols
        svcs="$(compose config --services 2>/dev/null || true)"
        vols="$(compose config --volumes  2>/dev/null || true)"
        mapfile -t DISCOVERED_SERVICES <<<"$svcs"
        mapfile -t DISCOVERED_VOLUMES  <<<"$vols"
        DISCOVERED_CONTAINER_NAMES=( "${DISCOVERED_SERVICES[@]}" )
        DISCOVERED_VOLUME_EXTERNAL=()
    fi

    [[ -n "${DISCOVERED_SERVICES[*]:-}" ]] || { log ERROR "discover_from_compose: cannot parse services."; return 1; }

    # De-dup & tidy
    ((${#DISCOVERED_CONTAINER_NAMES[@]}>0)) && mapfile -t DISCOVERED_CONTAINER_NAMES < <(printf "%s\n" "${DISCOVERED_CONTAINER_NAMES[@]}" | awk 'NF' | sort -u)
    ((${#DISCOVERED_VOLUME_EXTERNAL[@]}>0)) && mapfile -t DISCOVERED_VOLUME_EXTERNAL < <(printf "%s\n" "${DISCOVERED_VOLUME_EXTERNAL[@]}" | awk 'NF' | sort -u)

    log DEBUG "Services: ${DISCOVERED_SERVICES[*]}"
    log DEBUG "Expected container names: ${DISCOVERED_CONTAINER_NAMES[*]}"
    log DEBUG "Volumes: ${DISCOVERED_VOLUMES[*]:-<none>} (external: ${DISCOVERED_VOLUME_EXTERNAL[*]:-<none>})"
    return 0
}

################################################################################
# ensure_external_volumes()
# Description:
#     Pre-create any compose volumes that are marked external.
#
# Returns:
#     0 always (warns on create failures but continues).
################################################################################
ensure_external_volumes() {
    ((${#DISCOVERED_VOLUME_EXTERNAL[@]})) || { log INFO "No external volumes to create."; return 0; }
    local vol
    for vol in "${DISCOVERED_VOLUME_EXTERNAL[@]}"; do
        if ! docker volume inspect "$vol" >/dev/null 2>&1; then
            log INFO "Creating external volume: $vol"
            docker volume create "$vol" >/dev/null 2>&1 || log WARN "Failed to create volume: $vol"
        else
            log INFO "External volume exists: $vol"
        fi
    done
}

################################################################################
# project_name()
# Description:
#   Resolve the effective Compose project name used for containers/volumes.
#   - Returns COMPOSE_PROJECT_NAME from .env when set
#   - Otherwise falls back to basename of $N8N_DIR
# Output:
#   Prints the project name to stdout.
################################################################################
project_name() {
    read_env_var "$ENV_FILE" COMPOSE_PROJECT_NAME || basename "$N8N_DIR"
}

################################################################################
# is_external_volume(<logical_name>)
# Description:
#   Tell whether the logical volume in compose is marked "external: true".
#   Requires discover_from_compose() has populated DISCOVERED_VOLUME_EXTERNAL[].
# Exit status:
#   0 if external; 1 otherwise.
################################################################################
is_external_volume() {
    local v="$1" x
    for x in "${DISCOVERED_VOLUME_EXTERNAL[@]}"; do
        [[ "$x" == "$v" ]] && return 0
    done
    return 1
}

################################################################################
# expected_volume_name(<logical_name>)
# Description:
#   Given a logical volume name from compose (e.g., "postgres-data"),
#   return the actual Docker volume name Compose will use:
#     - If external → keep the logical name as-is
#     - Else        → "<project>_<logical>"
# Output:
#   Prints the expected real volume name.
################################################################################
expected_volume_name() {
    local logical="$1"
    if is_external_volume "$logical"; then
        printf '%s\n' "$logical"
    else
        printf '%s_%s\n' "$(project_name)" "$logical"
    fi
}

################################################################################
# resolve_volume_name(<logical_name>)
# Description:
#   Best-effort lookup of the real Docker volume name that currently exists
#   for a given logical name. Tries:
#     1) <logical>
#     2) <project>_<logical>
#     3) <project>-<logical>    (rare legacy form)
# Output:
#   Prints the first existing match; empty if none found.
# Exit status:
#   0 if a match is printed; 1 if none found.
################################################################################
resolve_volume_name() {
    local logical="$1" pn; pn="$(project_name)"
    local cand
    for cand in "$logical" "${pn}_${logical}" "${pn}-${logical}"; do
        docker volume inspect "$cand" >/dev/null 2>&1 && { printf '%s\n' "$cand"; return 0; }
    done
    return 1
}

################################################################################
# volume_mountpoint(<real_volume_name>)
# Description:
#   Return the local filesystem mountpoint path of a Docker volume
#   (usually /var/lib/docker/volumes/<id>/_data).
# Output:
#   Prints the path to stdout; empty if inspect fails.
################################################################################
volume_mountpoint() {
    docker volume inspect -f '{{.Mountpoint}}' "$1" 2>/dev/null
}

################################################################################
# discover_running_containers()
# Description:
#     Populate RUNNING_CONTAINER_NAMES with running container names in this project.
#
# Returns:
#     0 always.
################################################################################
discover_running_containers() {
    RUNNING_CONTAINER_NAMES=()
    local names
    names="$(compose ps --format '{{.Name}}' || true)"
    if [[ -n "$names" ]]; then
        mapfile -t RUNNING_CONTAINER_NAMES < <(printf '%s\n' "$names" | awk 'NF' | sort -u)
    fi
    log DEBUG "Running containers: ${RUNNING_CONTAINER_NAMES[*]:-<none>}"
    return 0
}

################################################################################
# find_missing_expected_containers()
# Description:
#     Compare expected containers (from compose) against actually running ones.
#
# Output:
#     Prints newline-separated list of missing expected entries (if any).
#
# Returns:
#     0 always.
################################################################################
find_missing_expected_containers() {
    declare -A svc_has=()
    local line svc name
    while read -r line; do
        svc="$(awk '{print $1}' <<<"$line")"
        name="$(awk '{print $2}' <<<"$line")"
        [[ -n "$svc" && -n "$name" ]] && svc_has["$svc"]=1
    done < <(compose ps --format '{{.Service}} {{.Name}}' 2>/dev/null || true)

    declare -A running_set=()
    local r
    for r in "${RUNNING_CONTAINER_NAMES[@]}"; do running_set["$r"]=1; done

    local exp missing=()
    for exp in "${DISCOVERED_CONTAINER_NAMES[@]}"; do
        if printf '%s\0' "${DISCOVERED_SERVICES[@]}" | grep -Fzxq -- "$exp"; then
            [[ -z "${svc_has[$exp]:-}" ]] && missing+=( "$exp" )
        else
            [[ -z "${running_set[$exp]:-}" ]] && missing+=( "$exp" )
        fi
    done
    ((${#missing[@]})) && printf "%s\n" "${missing[@]}"
}

################################################################################
# dump_service_logs()
# Description:
#     Dump logs for a single container by service.
#
# Returns:
#     0 always.
################################################################################
dump_service_logs() {
    local service="$1"
    local tail="${2:-200}"
    local cid

    cid="$(container_id_for_service "$service")"
    if [[ -n "$cid" ]]; then
        docker logs --tail "$tail" "$cid" || true
    else
        log WARN "Service '$service' has no running container for log dump."
    fi
}

################################################################################
# dump_unhealthy_container_logs()
# Description:
#     For all containers in the compose project, print logs for non-running/unhealthy ones.
#
# Returns:
#     0 always.
################################################################################
dump_unhealthy_container_logs() {
    local tail="${1:-200}"
    local ids
    ids="$(compose ps -q || true)"
    [[ -n "$ids" ]] || { log WARN "No containers to dump."; return 0; }
    for id in $ids; do
        local name status health
        name="$(docker inspect --format='{{.Name}}' "$id" | sed 's#^/##')"
        status="$(docker inspect --format='{{.State.Status}}' "$id" || echo unknown)"
        health="$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$id" || echo none)"
        if [[ "$status" != "running" || ( "$health" != "none" && "$health" != "healthy" ) ]]; then
            log INFO "----- Logs: ${name} (status=$status health=$health) -----"
            docker logs --tail "$tail" "$id" || true
            log INFO "----- End logs: ${name} -----"
        fi
    done
}

################################################################################
# check_container_healthy()
# Description:
#     Wait until a specific container/service is running and healthy (or timeout).
#
# Args:
#     $1 -> service name (preferred) or explicit container name/ID
#     $2 -> timeout seconds (default 60)
#     $3 -> interval seconds (default 5)
#
# Returns:
#     0 if healthy; 1 on timeout or not found.
################################################################################
check_container_healthy() {
    local target="$1"
    local timeout="${2:-60}"
    local interval="${3:-5}"
    local elapsed=0

    log INFO "Checking health for: $target"

    _resolve_cids() {
        local t="$1" cids project
        cids="$(compose ps -q "$t" 2>/dev/null | awk 'NF')" || true
        [[ -n "$cids" ]] && { echo "$cids"; return 0; }

        project="$(read_env_var "$ENV_FILE" COMPOSE_PROJECT_NAME || basename "$N8N_DIR")"
        cids="$(docker ps -q \
                -f "label=com.docker.compose.project=${project}" \
                -f "label=com.docker.compose.service=${t}" \
                2>/dev/null | awk 'NF')" || true
        [[ -n "$cids" ]] && { echo "$cids"; return 0; }

        cids="$(docker ps -q -f "name=^${t}$" 2>/dev/null | awk 'NF')" || true
        [[ -n "$cids" ]] && { echo "$cids"; return 0; }

        cids="$(docker ps -q -f "name=${project}-${t}-" 2>/dev/null | awk 'NF')" || true
        [[ -n "$cids" ]] && { echo "$cids"; return 0; }
        cids="$(docker ps -q -f "name=${project}_${t}_" 2>/dev/null | awk 'NF')" || true
        [[ -n "$cids" ]] && { echo "$cids"; return 0; }

        return 1
    }

    local cids=""
    while (( elapsed < timeout )); do
        local status_ok=true
        cids="$(_resolve_cids "$target" || true)"

        if [[ -z "$cids" ]]; then
            log WARN "'$target' not found or not running yet."
            status_ok=false
        else
            while IFS='|' read -r cid name st hl; do
                name="${name#/}"
                if [[ "$st" == "running" && ( "$hl" == "none" || "$hl" == "healthy" ) ]]; then
                    log INFO "$name is running (${hl})"
                else
                    log WARN "$name not healthy yet (status=$st, health=$hl)"
                    status_ok=false
                fi
            done < <(docker inspect --format \
                '{{.Id}}|{{.Name}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \
                $cids 2>/dev/null || true)
        fi

        $status_ok && return 0

        log INFO "Waiting ${interval}s for next check"
        for ((i=0; i<interval; i++)); do printf "."; sleep 1; done
        echo ""
        elapsed=$((elapsed + interval))
    done

    log ERROR "Timeout after ${timeout}s. '$target' is not healthy."
    if [[ -n "$cids" ]]; then
        log INFO "Recent logs from $target:"
        docker logs --tail 200 $(echo "$cids") || true
    fi
    return 1
}

################################################################################
# wait_for_containers_healthy()
# Description:
#     Wait until all compose containers are running and healthy (or timeout).
#
# Args:
#     $1 -> timeout seconds (default 180)
#     $2 -> interval seconds (default 10)
#
# Returns:
#     0 if all healthy before timeout; 1 on timeout.
################################################################################
wait_for_containers_healthy() {
    local timeout="${1:-180}"
    local interval="${2:-20}"
    local elapsed=0

    discover_from_compose || true
    log INFO "Waiting for containers to be running & healthy (timeout=${timeout}s)…"

    while (( elapsed < timeout )); do
        local all_ok=true
        local ids missing

        discover_running_containers
        missing="$(find_missing_expected_containers || true)"
        [[ -n "$missing" ]] && all_ok=false

        ids="$(compose ps -q 2>/dev/null || true)"
        if [[ -n "$ids" ]]; then
            while IFS='|' read -r id name status health; do
                [[ -z "$id" ]] && continue
                name="${name#/}"
                if [[ "$status" != "running" ]]; then
                    all_ok=false
                elif [[ "$health" != "none" && "$health" != "healthy" ]]; then
                    all_ok=false
                fi
            done < <(
                docker inspect \
                    --format '{{.Id}}|{{.Name}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \
                    $ids 2>/dev/null || true
            )
        fi

        log INFO "Container status:"
        compose ps --format "table {{.Name}}\t{{.Status}}" 2>/dev/null || true

        if $all_ok; then
            log INFO "All expected containers are running and healthy."
            compose ps || true
            return 0
        fi

        local remaining=$(( timeout - elapsed ))
        (( remaining < 0 )) && remaining=0
        log INFO "Waiting ${interval}s for next check (remaining ~${remaining}s)"
        for ((j=0; j<interval; j++)); do
            printf "."
            sleep 1
        done
        echo ""
        elapsed=$((elapsed + interval))
    done

    log ERROR "Timeout after ${timeout}s: containers missing or unhealthy."

    local -a offenders=()
    local missing_now
    missing_now="$(find_missing_expected_containers || true)"
    if [[ -n "$missing_now" ]]; then
        while IFS= read -r miss; do
            [[ -n "$miss" ]] && offenders+=( "${miss}|missing|n/a" )
        done <<< "$missing_now"
    fi

    local ids_now
    ids_now="$(compose ps -q 2>/dev/null || true)"
    if [[ -n "$ids_now" ]]; then
        while IFS='|' read -r id name status health; do
            [[ -z "$id" ]] && continue
            name="${name#/}"
            if [[ "$status" != "running" ]] || [[ "$health" != "none" && "$health" != "healthy" ]]; then
                offenders+=( "${name}|${status}|${health}" )
            fi
        done < <(
            docker inspect \
                --format '{{.Id}}|{{.Name}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \
                $ids_now 2>/dev/null || true
        )
    fi

    if ((${#offenders[@]} > 0)); then
        log WARN "Offending containers:"
        printf "  %-24s %-14s %-10s\n" "NAME" "STATUS" "HEALTH"
        printf "  %-24s %-14s %-10s\n" "----" "------" "------"
        local row nm st hl
        for row in "${offenders[@]}"; do
            IFS="|" read -r nm st hl <<<"$row"
            printf "  %-24s %-14s %-10s\n" "$nm" "$st" "$hl"
        done
    fi

    log INFO "Container status:"
    compose ps || true
    dump_unhealthy_container_logs 200
    return 1
}

################################################################################
# verify_traefik_certificate()
# Description:
#     Lightweight post-deploy TLS check: confirm HTTPS reaches Traefik (valid TLS)
#     and (best-effort) log issuer/subject/dates via openssl.
#
# Args:
#     $1 -> domain (falls back to $DOMAIN)
#     $2 -> max retries (default 12)
#     $3 -> sleep between retries (default 10)
#
# Returns:
#     0 on HTTPS success; 1 only if HTTPS cannot be reached after retries.
################################################################################
verify_traefik_certificate() {
    local domain="${1:-${DOMAIN:-}}"
    local MAX_RETRIES="${2:-6}"
    local SLEEP_INTERVAL="${3:-10}"

    local domain_url success=false
    # Accept 2xx/3xx and also 401/403/404 (auth-guarded apps) — TLS must still be valid.
    local ok_re='^(2[0-9]{2}|3[0-9]{2}|401|403|404)$'

    if [[ -z "$domain" ]]; then
        log ERROR "verify_traefik_certificate: domain is empty"
        return 1
    fi
    domain_url="https://${domain}"

    if command -v dig >/dev/null 2>&1; then
        log INFO "DNS A records for ${domain}:"
        dig +short A "$domain" | sed 's/^/  - /' || true
        log INFO "DNS AAAA records for ${domain}:"
        dig +short AAAA "$domain" | sed 's/^/  - /' || true
    else
        log WARN "'dig' not found; skipping DNS details."
    fi

    # Quick probe (do NOT use --fail so 401 doesn't look like "down")
    if curl -ks -o /dev/null --connect-timeout 3 --max-time 5 "${domain_url}"; then
        log INFO "TLS endpoint is reachable (insecure probe). Waiting for a valid certificate..."
    else
        log INFO "TLS endpoint not yet reachable. Proceeding with normal retries..."
    fi

    log INFO "Checking HTTPS reachability (valid chain required by curl)…"
    for ((i=1; i<=MAX_RETRIES; i++)); do
        # No --fail: we want status on 401/403/404 too. Require ssl_verify_result==0.
        local out rc http ssl
        out="$(curl -sSI \
                --connect-timeout 5 --max-time 15 \
                --proto =https --tlsv1.2 \
                --write-out 'http=%{http_code} ssl=%{ssl_verify_result}' \
                --output /dev/null "${domain_url}")"
        rc=$?
        http="$(sed -n 's/.*http=\([0-9]\+\).*/\1/p' <<<"$out")"
        ssl="$(sed -n 's/.*ssl=\([0-9]\+\).*/\1/p' <<<"$out")"

        if (( rc == 0 )); then
            if [[ "$ssl" == "0" && "$http" =~ $ok_re ]]; then
                log INFO "HTTPS reachable for ${domain} (status=${http}, tls=ok) [attempt ${i}/${MAX_RETRIES}]"
                success=true
                break
            else
                log WARN "HTTPS up but not acceptable yet (http=${http:-N/A}, ssl=${ssl:-N/A}) [attempt ${i}/${MAX_RETRIES}]"
            fi
        else
            if (( rc == 60 )); then
                # TLS chain not valid yet
                if curl -ks -o /dev/null --connect-timeout 3 --max-time 5 "${domain_url}"; then
                    log WARN "TLS reachable but certificate not valid yet (curl_exit=60) [attempt ${i}/${MAX_RETRIES}]"
                else
                    log WARN "HTTPS not ready (curl_exit=60) [attempt ${i}/${MAX_RETRIES}]"
                fi
            else
                log WARN "HTTPS not ready (curl_exit=${rc}, http=${http:-N/A}) [attempt ${i}/${MAX_RETRIES}]"
            fi
        fi

        [[ $i -lt $MAX_RETRIES ]] && { log INFO "Retrying in ${SLEEP_INTERVAL}s..."; sleep "$SLEEP_INTERVAL"; }
    done

    if ! $success; then
        log ERROR "${domain} is not reachable via HTTPS after ${MAX_RETRIES} attempts."
        dump_service_logs traefik 200
        local tname; tname="$(container_name_for_service traefik || echo traefik)"
        log INFO "Tip: follow live Traefik logs with: docker logs -f ${tname}"
        return 1
    fi

    if command -v openssl >/dev/null 2>&1; then
        log INFO "Fetching certificate details (best-effort)…"
        local cert_info issuer subject not_before not_after
        cert_info=$(echo | openssl s_client -connect "${domain}:443" -servername "${domain}" 2>/dev/null \
                    | openssl x509 -noout -issuer -subject -dates 2>/dev/null || true)
        if [[ -n "$cert_info" ]]; then
            issuer=$(echo "$cert_info"  | grep '^issuer='   || true)
            subject=$(echo "$cert_info" | grep '^subject='  || true)
            not_before=$(echo "$cert_info"| grep '^notBefore=' || true)
            not_after=$(echo "$cert_info" | grep '^notAfter='  || true)
            [[ -n "$issuer"     ]] && log INFO "Issuer: $issuer"
            [[ -n "$subject"    ]] && log INFO "Subject: $subject"
            [[ -n "$not_before" ]] && log INFO "Valid from: ${not_before#notBefore=}"
            [[ -n "$not_after"  ]] && log INFO "Valid till:  ${not_after#notAfter=}"
        else
            log WARN "Could not parse certificate via openssl (continuing)."
        fi
    else
        log WARN "'openssl' not found; skipping certificate inspection."
    fi
    return 0
}

################################################################################
# list_exposed_fqdns()
# Description:
#   Return the list of FQDNs that should be reachable (DNS/TLS) based on the
#   current .env and profiles. Output: one FQDN per line.
################################################################################
list_exposed_fqdns() {
    [[ -f "$ENV_FILE" ]] || { return 0; }

    local n8n graf prom profiles expose
    n8n="$(read_env_var "$ENV_FILE" N8N_FQDN || true)"
    graf="$(read_env_var "$ENV_FILE" GRAFANA_FQDN || true)"
    prom="$(read_env_var "$ENV_FILE" PROMETHEUS_FQDN || true)"
    profiles="$(read_env_var "$ENV_FILE" COMPOSE_PROFILES || true)"
    expose="$(read_env_var "$ENV_FILE" EXPOSE_PROMETHEUS || echo false)"

    [[ -n "$n8n" ]] && printf '%s\n' "$n8n"
    if [[ "$profiles" == *monitoring* ]]; then
        [[ -n "$graf" ]] && printf '%s\n' "$graf"
        if [[ "${expose,,}" == "true" ]]; then
            [[ -n "$prom" ]] && printf '%s\n' "$prom"
        fi
    fi
}

################################################################################
# check_domain()
# Description:
#     Verify the provided DOMAIN’s A record points to this server’s public IP.
#
# Returns:
#     0 on success/skip (no resolver); exits 1 on mismatch.
################################################################################
check_domain() {
    local server_ip domain_ips resolver=""
    server_ip=$(curl -fsS --connect-timeout 5 --max-time 10 https://api.ipify.org || echo "Unavailable")

    if command -v dig >/dev/null 2>&1; then
        resolver="dig"
        domain_ips=$(dig +short A "$DOMAIN" | tr '\n' ' ')
    elif command -v getent >/dev/null 2>&1; then
        resolver="getent"
        domain_ips=$(getent ahostsv4 "$DOMAIN" | awk '{print $1}' | sort -u | tr '\n' ' ')
    else
        log WARN "Neither 'dig' nor 'getent' found; DNS check will be skipped."
    fi

    log INFO "Your server's public IP is: $server_ip"
    [[ -n "$resolver" ]] && log INFO "Domain $DOMAIN resolves (via $resolver): $domain_ips"

    if [[ -z "$resolver" || "$server_ip" == "Unavailable" ]]; then
        log WARN "Cannot verify DNS → continuing; Let's Encrypt may fail if DNS is wrong."
        return 0
    fi

    if echo "$domain_ips" | tr ' ' '\n' | grep -Fxq "$server_ip"; then
        log INFO "Domain $DOMAIN is correctly pointing to this server."
        return 0
    else
        log ERROR "Domain $DOMAIN is NOT pointing to this server. Update your A record to: $server_ip"
        return 1
    fi
}

################################################################################
# gen_bcrypt_hash()
# Description:
#   Return a bcrypt hash for a given user+password (cost 12).
#   Prefers `htpasswd`; falls back to Docker httpd:2.4-alpine.
# Returns:
#   Prints hash to stdout (no username), or empty string on failure.
################################################################################
# --- bcrypt helper for Traefik usersFile ---
# Usage: gen_bcrypt_hash <user> <pass>  -> prints only the bcrypt hash
gen_bcrypt_hash() {
    local user="$1" pass="$2" out

    if command -v htpasswd >/dev/null 2>&1; then
        # apache2-utils
        out="$(htpasswd -nbBC 12 "$user" "$pass" 2>/dev/null)" || return 1
        printf '%s\n' "${out#*:}"
        return 0
    fi

    # Fallback: use a tiny httpd container just to run htpasswd
    if command -v docker >/dev/null 2>&1; then
        out="$(docker run --rm httpd:2.4-alpine htpasswd -nbBC 12 "$user" "$pass" 2>/dev/null)" || return 1
        printf '%s\n' "${out#*:}"
        return 0
    fi

    echo "[ERROR] No bcrypt tool available (need apache2-utils 'htpasswd' or Docker)." >&2
    return 127
}

################################################################################
# ensure_monitoring_auth()
# Create secrets/htpasswd from MONITORING_BASIC_AUTH_USER/PASS (or CLI overrides).
################################################################################
ensure_monitoring_auth() {
    [[ -f "$ENV_FILE" ]] || return 0
    [[ -n "$BASIC_AUTH_USER" ]] && upsert_env_var "MONITORING_BASIC_AUTH_USER" "$BASIC_AUTH_USER" "$ENV_FILE"
    [[ -n "$BASIC_AUTH_PASS" ]] && upsert_env_var "MONITORING_BASIC_AUTH_PASS" "$BASIC_AUTH_PASS" "$ENV_FILE"

    local user pass
    user="$(read_env_var "$ENV_FILE" MONITORING_BASIC_AUTH_USER || true)"
    pass="$(read_env_var "$ENV_FILE" MONITORING_BASIC_AUTH_PASS || true)"
    if [[ -z "$user" || -z "$pass" ]]; then
        log WARN "MONITORING_BASIC_AUTH_USER/PASS not set; skipping usersFile creation."
        return 0
    fi

    local hash
    hash="$(gen_bcrypt_hash "$user" "$pass")"
    if [[ -z "$hash" ]]; then
        log ERROR "Failed to bcrypt MONITORING_BASIC_AUTH_PASS."
        return 1
    fi

    local secdir="$N8N_DIR/secrets"
    local file="$secdir/htpasswd"
    mkdir -p "$secdir"
    printf '%s:%s\n' "$user" "$hash" > "$file"
    chmod 640 "$file" || true
    log INFO "Wrote Traefik usersFile: $file"

    # Record the container path used in labels
    upsert_env_var "TRAEFIK_USERSFILE" "/etc/traefik/htpasswd" "$ENV_FILE"
}

################################################################################
# _read_env_var_from_container()
# Description:
#     Print the value of ENV variable VAR from the given container (CID or name),
#     without a TTY. Reads from .Config.Env via `docker inspect`.
#
# Args:
#     $1 -> container id or name
#     $2 -> ENV var key to read
#
# Output:
#     Prints the value to stdout (nothing if not set).
#
# Returns:
#     0 always (even if the var is unset).
################################################################################
_read_env_var_from_container() {
    local cid="$1" var="$2"
    docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$cid" 2>/dev/null \
        | awk -F= -v k="$var" '$1==k{print $2; exit}'
}

################################################################################
# detect_mode_runtime()
# Description:
#     Determine n8n runtime mode (single|queue) from EXECUTIONS_MODE inside
#     the compose service named `main`.
#
# Returns:
#     0 on success; 1 if the `main` container is not found.
################################################################################
detect_mode_runtime() {
    DISCOVERED_MODE="unknown"

    local cid
    cid="$(compose ps -q main 2>/dev/null | awk 'NF' | head -n1)"
    if [[ -z "$cid" ]]; then
        log ERROR "detect_mode_runtime: no container for service 'main' (is the stack up?)"
        return 1
    fi

    local exec_mode
    exec_mode="$(_read_env_var_from_container "$cid" EXECUTIONS_MODE | tr '[:upper:]' '[:lower:]' | xargs)"

    if [[ "$exec_mode" == "queue" ]]; then
        DISCOVERED_MODE="queue"
    else
        [[ -z "$exec_mode" ]] && log DEBUG "detect_mode_runtime: EXECUTIONS_MODE is not set; assuming single mode."
        DISCOVERED_MODE="single"
    fi

    local cname
    cname="$(docker inspect --format '{{.Name}}' "$cid" 2>/dev/null | sed 's#^/##')"
    log INFO "Runtime mode: ${DISCOVERED_MODE} (service=main, container=${cname:-$cid})"
    return 0
}

################################################################################
# docker_up_check()
# Description:
#   Bring the stack up and verify readiness.
#
# Behaviors:
#   - Best-effort `compose pull` to prefetch images.
#   - If DISCOVERED_MODE=queue → scales worker replicas to $N8N_WORKER_SCALE (default 1).
#   - Starts services with `docker compose up -d`.
#   - Detects runtime mode via `detect_mode_runtime` (for logging/summary).
#   - Waits for all containers to be running & healthy (timeout 180s, interval 10s).
#   - Verifies Traefik HTTPS is reachable for $DOMAIN (valid certificate).
#
# Returns:
#   0 on success; 1 if compose up, health checks, or TLS verification fail.
################################################################################
docker_up_check() {
    log INFO "Starting Docker Compose…"
    compose pull -q || true
    local up_args=(-d)
    if [[ "${DISCOVERED_MODE:-unknown}" == "queue" ]]; then
        local replicas="${N8N_WORKER_SCALE:-1}"
        if printf '%s\n' "${DISCOVERED_SERVICES[@]}" | grep -qx "worker"; then
            up_args+=( --scale "worker=${replicas}" )
        else
            log WARN "Queue mode detected but no 'worker' service in compose; skip scaling."
        fi
    fi
    compose up "${up_args[@]}" || return 1
    detect_mode_runtime || true
    wait_for_containers_healthy || return 1
}

################################################################################
# preflight_dns_checks()
# Description:
#   Hard-fail DNS preflight for all exposed hostnames *before* bringing the
#   stack up. The set of hostnames is provided by `list_exposed_fqdns`, which
#   should echo one FQDN per line (and is expected to include at least
#   N8N_FQDN).
#
# Behaviors:
#   - Iterates over the FQDNs emitted by `list_exposed_fqdns`.
#   - For each FQDN, runs `check_domain` (via a temporary DOMAIN=<fqdn>)
#     to validate public A/AAAA records (typically also matching this host’s
#     public IP).
#   - Aggregates failures; returns non-zero if any FQDN fails validation.
#   - This function does not itself enforce that N8N_FQDN is set; that contract
#     belongs to `list_exposed_fqdns` (which should error if required inputs
#     are missing).
#
# Returns:
#   0 if all FQDNs pass `check_domain`; 1 if any fail.
################################################################################
preflight_dns_checks() {
    local errs=0 fq
    while IFS= read -r fq; do
        [[ -z "$fq" ]] && continue
        ( DOMAIN="$fq"; check_domain ) || ((errs++))
    done < <(list_exposed_fqdns)
    (( errs == 0 )) || { log ERROR "DNS preflight failed for one or more FQDNs."; return 1; }
    return 0
}

################################################################################
# post_up_tls_checks()
# Description:
#   Post-deploy TLS verification for all exposed hostnames. Treats failures as
#   warnings by default (to tolerate Let’s Encrypt issuance/propagation lag),
#   but becomes strict if STRICT_TLS_ALL=true.
#
# Behaviors:
#   - Iterates over the FQDNs emitted by `list_exposed_fqdns`.
#   - For each FQDN, calls `verify_traefik_certificate <fqdn>` to confirm that
#     HTTPS is reachable with a valid certificate.
#   - Aggregates failures.
#   - If any verification fails:
#       * STRICT_TLS_ALL=true  → log ERROR and return 1.
#       * otherwise            → log WARN and return 0.
#
# Returns:
#   0 if all verifications succeed, or if failures are allowed (STRICT_TLS_ALL
#   not true). Returns 1 only when STRICT_TLS_ALL=true and at least one FQDN
#   fails verification.
################################################################################
post_up_tls_checks() {
    local strict="${STRICT_TLS_ALL:-false}" errs=0 fq
    while IFS= read -r fq; do
        [[ -z "$fq" ]] && continue
        verify_traefik_certificate "$fq" || ((errs++))
    done < <(list_exposed_fqdns)
    if (( errs > 0 )); then
        if [[ "${strict,,}" == "true" ]]; then
            log ERROR "TLS verification failed for one or more FQDNs (STRICT_TLS_ALL=true)."; return 1
        else
            log WARN "TLS verification failed for one or more FQDNs (continuing; set STRICT_TLS_ALL=true to enforce)."
        fi
    fi
    return 0
}

################################################################################
# strict_env_check()
# Description:
#     Validate that all ${VARS} used in compose file exist in the .env file.
#
# Returns:
#     0 if all present; 1 if any are missing or .env is missing.
################################################################################
strict_env_check() {
    local compose_file="$1" env_file="$2"
    [[ -f "$env_file" ]] || { log ERROR ".env file not found at $env_file"; return 1; }

    log INFO "Checking for unset environment variables in $compose_file..."
    local vars_in_compose
    if vars_in_compose=$(grep -oP '\$\{\K[A-Za-z_][A-Za-z0-9_]*(?=[^}]*)' "$compose_file" 2>/dev/null | sort -u); then
        :
    else
        vars_in_compose=$(grep -oE '\$\{[A-Za-z_][A-Za-z0-9_]*' "$compose_file" | sed 's/^\${//' | sort -u)
    fi

    declare -A envmap
    while IFS='=' read -r k v; do
        [[ -z "$k" || "$k" =~ ^\s*# ]] && continue
        k="${k%% *}"; k="${k%%    *}"
        envmap["$k"]=1
    done < "$env_file"

    local missing_vars=()
    for var in $vars_in_compose; do
        [[ -n "${envmap[$var]:-}" ]] || missing_vars+=("$var")
    done

    if (( ${#missing_vars[@]} )); then
        log ERROR "Missing required environment variables:"
        printf ' - %s\n' "${missing_vars[@]}"
        return 1
    fi

    log INFO "All required environment variables are set."
    return 0
}

################################################################################
# validate_compose_and_env()
# Description:
#     Run strict_env_check and `compose config` to catch unset vars/syntax errors.
#
# Returns:
#     0 if valid; 1 on any validation error.
################################################################################
validate_compose_and_env() {
    [[ -f "${COMPOSE_FILE:-}" ]] || { log ERROR "Missing COMPOSE_FILE"; return 1; }
    [[ -f "${ENV_FILE:-}"     ]] || { log ERROR "Missing ENV_FILE"; return 1; }
    strict_env_check "$COMPOSE_FILE" "$ENV_FILE" || return 1

    local config_output
    config_output=$(compose config 2>&1) || true

    if grep -q 'variable is not set' <<<"$config_output"; then
        log ERROR "Compose config found unset variables:"
        echo "$config_output" | grep 'variable is not set'
        return 1
    elif grep -qi 'error' <<<"$config_output"; then
        log ERROR "Compose config error:"
        echo "$config_output"
        return 1
    fi
    log INFO "docker-compose.yml and .env validated successfully."
}

################################################################################
# get_current_n8n_version()
# Description:
#     Print the running n8n version by exec'ing into the main container.
#
# Output:
#     Version (x.y.z) or "0.0.0" if unknown.
#
# Returns:
#     0 always.
################################################################################
get_current_n8n_version() {
    local cid ver
    cid="$(container_id_for_service main)"
    if [[ -n "$cid" ]]; then
        ver="$(docker exec "$cid" n8n --version 2>/dev/null | awk '{print $NF}' | tr -d '\r')"
        [[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] && { echo "$ver"; return 0; }
    fi
    echo "0.0.0"
}

################################################################################
# get_latest_n8n_version()
# Description:
#     Fetch the latest stable semver tag (x.y.z) of n8n from Docker Hub.
#
# Output:
#     Tag string on success (may be empty on API issues).
#
# Returns:
#     0 on success; 1 if jq/curl missing.
################################################################################
get_latest_n8n_version() {
    require_cmd jq || return 1
    require_cmd curl || return 1
    local response
    response="$(curl -fsS --connect-timeout 5 --retry 3 --retry-delay 2 \
        'https://hub.docker.com/v2/repositories/n8nio/n8n/tags?page_size=100' \
        | jq -r '.results[].name' \
        | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' \
        | sort -Vr | head -n 1 || true)"
    [[ -z "$response" ]] && log ERROR "Could not fetch latest n8n tag from Docker Hub"
    echo "$response"
}

################################################################################
# list_available_versions()
# Description:
#     Retrieve and print recent stable semver tags (x.y.z) from Docker Hub.
#
# Output:
#     Prints the latest 5 tags (newest first).
#
# Returns:
#     0 on success (even if none found); 1 if jq/curl missing.
################################################################################
list_available_versions() {
    require_cmd jq || return 1
    require_cmd curl || return 1

    local url="https://registry.hub.docker.com/v2/repositories/n8nio/n8n/tags?page_size=100"
    local page_json

    page_json=$(curl -fsS --retry 3 --retry-delay 2 "$url" 2>/dev/null || true)
    [[ -z "$page_json" ]] && { log WARN "Failed to fetch tags page"; return 1; }

    mapfile -t all < <(jq -r '.results[].name' <<<"$page_json" \
                        | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' \
                        | sort -Vr | head -n 5)

    if ((${#all[@]}==0)); then
        log WARN "No n8n stable version found from Docker Hub"
        return 0
    fi

    echo "Latest 5 n8n versions (newest first):"
    printf "%s\n" "${all[@]}"
}

################################################################################
# validate_image_tag()
# Description:
#     Check whether an n8n image tag exists on docker.n8n.io or docker.io.
#
# Returns:
#     0 if found; 1 otherwise.
################################################################################
validate_image_tag() {
    local tag="$1"
    docker manifest inspect "docker.n8n.io/n8nio/n8n:${tag}" >/dev/null 2>&1 && return 0
    docker manifest inspect "docker.io/n8nio/n8n:${tag}" >/dev/null 2>&1 && return 0
    return 1
}

################################################################################
# get_google_drive_link()
# Description:
#     Produce Google Drive folder URL for the configured rclone remote.
#
# Output:
#     Prints folder URL or empty string.
#
# Returns:
#     0 always.
################################################################################
get_google_drive_link() {
    if [[ -z "$RCLONE_REMOTE" ]]; then
        echo ""
        return
    fi

    local remote_name="${RCLONE_REMOTE%%:*}"
    [[ -n "$remote_name" ]] || { echo ""; return; }

    local folder_id
    folder_id=$(rclone config show "$remote_name" 2>/dev/null \
            | awk -F '=' '$1 ~ /root_folder_id/ { gsub(/[[:space:]]/, "", $2); print $2 }')

    if [[ -n "$folder_id" ]]; then
        echo "https://drive.google.com/drive/folders/$folder_id"
    else
        log WARN "Could not find root_folder_id for remote '$remote_name'"
        echo ""
    fi
}

################################################################################
# box_line()
# Description:
#     Pretty print a left-justified label and value for summary boxes.
#
# Returns:
#     0 always.
################################################################################
box_line() {
    local label="$1"
    local value="$2"
    printf '%-24s %s\n' "$label" "$value"
}