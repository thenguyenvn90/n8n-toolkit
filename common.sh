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
#   • Health checks + log dumps
#   • Compose discovery (services, volumes, external volumes, expected container names)
#   • “up + wait healthy” helper (with external volume ensure)
#   • Version & image utilities
#   • Domain DNS sanity check and optional TLS verification
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
#   Structured logger with levels (DEBUG, INFO, WARN, ERROR).
#
# Behaviors:
#   - Respects global LOG_LEVEL (defaults to INFO).
#   - Sends WARN/ERROR to stderr; DEBUG/INFO to stdout.
#   - Format: [YYYY-MM-DD HH:MM:SS] [LEVEL] message
#
# Returns:
#   0 always.
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
#   Print a compact stack trace (most recent call first) for diagnostics.
#
# Behaviors:
#   - Skips the trap frame.
#   - Logs function name, source file, and line for each frame.
#
# Returns:
#   0 always.
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
# on_interrupt()
# Description:
#   Trap handler for INT/TERM/HUP: stop stack cleanly and exit.
#
# Behaviors:
#   - Logs interrupt location.
#   - Runs `docker compose down` for current N8N_DIR if compose file exists.
#   - Exits with code 130.
#
# Returns:
#   Never returns (exits 130).
################################################################################
on_interrupt() {
    log ERROR "Interrupted (SIGINT/SIGTERM). Stopping compose (if present) and exiting..."
    if [[ -n "${N8N_DIR:-}" && -f "$N8N_DIR/docker-compose.yml" ]]; then
        (cd "$N8N_DIR" && docker compose -f "$N8N_DIR/docker-compose.yml" down) || true
    fi
    exit 130
}

################################################################################
# on_error()
# Description:
#   Trap handler for ERR: log failing command/location, show stack & compose ps.
#
# Behaviors:
#   - Logs failed command, file, line, and function.
#   - Calls print_stacktrace().
#   - Runs `docker compose ps` (if compose file present).
#   - Exits with the original failing command’s exit code.
#
# Returns:
#   Never returns (exits with prior exit code).
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
# require_cmd()
# Description:
#   Ensure a required executable is available; if missing, attempt to install it
#   automatically using APT on Debian/Ubuntu systems.
#
# Behaviors:
#   - If the command already exists in PATH → returns success immediately.
#   - Special-case: for "docker", do NOT auto-install here; logs a clear error
#     and expects the caller to run install_prereqs() (which handles Docker).
#   - Verifies an APT-based system is available (apt-get); if not, logs an error.
#   - Runs `apt-get update` only once per script run (uses APT_UPDATED flag).
#   - Maps common command→package name differences on Debian/Ubuntu:
#       * msmtp   → msmtp-mta
#       * dig     → dnsutils
#       * getent  → libc-bin   (usually present)
#       * gpg     → gnupg
#     (Otherwise, assumes package name equals the command.)
#   - Installs with: `apt-get install -y --no-install-recommends <package>`
#     in noninteractive mode, then re-checks the command is available.
#   - Logs informative messages on update/install steps and failures.
#
# Returns:
#   0  if the command is present or is installed successfully.
#   1  if installation fails or a supported package manager is not available.
#
# Side effects:
#   - May run `apt-get update` and install system packages.
#   - Sets global APT_UPDATED=true after the first `apt-get update`.
################################################################################
require_cmd() {
    local cmd="$1"

    # Already present?
    if command -v "$cmd" >/dev/null 2>&1; then
        return 0
    fi

    # Special case: don't try to apt-get docker via this helper
    if [[ "$cmd" == "docker" ]]; then
        log ERROR "Docker is missing. Please run the Docker installer step (install_prereqs) first."
        return 1
    fi

    # We only support apt-get here (Ubuntu/Debian). Extend if needed.
    if ! command -v apt-get >/dev/null 2>&1; then
        log ERROR "Command '$cmd' not found and no supported package manager (apt-get) available."
        return 1
    fi

    # Map command -> package name (when they differ)
    local pkg="$cmd"
    case "$cmd" in
        msmtp)   pkg="msmtp-mta" ;;   # provides 'msmtp' binary on Debian/Ubuntu
        dig)     pkg="dnsutils"  ;;
        getent)  pkg="libc-bin"  ;;   # usually already installed
        gpg)     pkg="gnupg"     ;;
        # most others keep pkg="$cmd"
    esac

    # Update package index once
    if [[ "$APT_UPDATED" != true ]]; then
        log INFO "Updating package index (apt-get update)…"
        apt-get update -y || true
        APT_UPDATED=true
    fi

    log INFO "Installing missing command '$cmd' (package: $pkg)…"
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$pkg" || true

    # Verify installation
    if command -v "$cmd" >/dev/null 2>&1; then
        return 0
    fi

    log ERROR "Failed to install dependency '$cmd' (tried package: $pkg). Please install it manually."
    return 1
}

################################################################################
# check_root()
# Description:
#   Ensure the script is running as root (EUID = 0).
#
# Behaviors:
#   - Logs ERROR and returns non-zero if not root.
#
# Returns:
#   0 if root; 1 otherwise.
################################################################################
check_root() {
    if [[ ${EUID:-$(id -u)}"x" != "0x" ]]; then
        log ERROR "This script must be run as root."
        return 1
    fi
}

################################################################################
# upsert_env_var()
# Description:
#   Insert or update KEY=VALUE in a .env file idempotently.
#
# Behaviors:
#   - Replaces existing line matching ^KEY=... or appends a new line.
#
# Returns:
#   0 on success; non-zero on failure.
################################################################################
upsert_env_var() {
    local key="$1" val="$2" file="$3"
    if grep -qE "^${key}=" "$file"; then
        sed -i "s|^${key}=.*|${key}=${val}|" "$file"
    else
        printf "%s=%s\n" "$key" "$val" >> "$file"
    fi
}

################################################################################
# mask_secret()
# Description:
#   Mask a secret by showing only the first and last 4 characters.
#
# Behaviors:
#   - If length ≤ 8, prints the string unchanged.
#   - Else prints: XXXX***YYYY
#
# Returns:
#   0 always (prints masked value to stdout).
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
#   Heuristic check whether a string looks like base64.
#
# Behaviors:
#   - Tests against regex: ^[A-Za-z0-9+/=]+$
#
# Returns:
#   0 if matches; 1 otherwise.
################################################################################
looks_like_b64() {
    [[ "$1" =~ ^[A-Za-z0-9+/=]+$ ]]
}

################################################################################
# load_env_file()
# Description:
#   Load environment variables from a .env file into the current shell.
#
# Behaviors:
#   - Uses provided path or falls back to ENV_FILE or $N8N_DIR/.env.
#   - Warns and no-ops if file does not exist.
#
# Returns:
#   0 on success or when file missing (no-op); non-zero on source errors.
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
#   Read and print the value of KEY from a .env-style file.
#
# Behaviors:
#   - Ignores blank lines and full-line comments.
#   - Supports unquoted, single-quoted, and double-quoted values.
#   - Trims inline comments for unquoted values.
#   - Only the first '=' is treated as the separator.
#
# Returns:
#   0 if key found (prints value); 1 if file missing or key not found.
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
# ensure_encryption_key_exists()
# Description:
#   Verify N8N_ENCRYPTION_KEY exists in the given .env and looks reasonable.
#
# Behaviors:
#   - Reads N8N_ENCRYPTION_KEY via read_env_var().
#   - ERROR if missing; WARN if not base64-like.
#   - Logs masked key on success.
#
# Returns:
#   0 if present; 1 if missing.
################################################################################
ensure_encryption_key_exists() {
    local env_file="$1"
    local key
    key="$(read_env_var "$env_file" N8N_ENCRYPTION_KEY || true)"
    if [[ -z "$key" ]]; then
        log ERROR "N8N_ENCRYPTION_KEY is missing in $env_file. Aborting to avoid an unrecoverable restore."
        return 1
    fi
    if ! looks_like_b64 "$key"; then
        log WARN "N8N_ENCRYPTION_KEY in $env_file does not look like base64. Continue at your own risk."
    fi
    log INFO "N8N_ENCRYPTION_KEY present (masked): $(mask_secret "$key")"
}

################################################################################
# parse_domain_arg()
# Description:
#   Normalize and validate a domain/hostname string.
#
# Behaviors:
#   - Lowercases; strips scheme, path, query, fragment, port, trailing dot, and www.
#   - Validates against strict hostname regex and overall length.
#   - Prints normalized domain on success.
#
# Returns:
#   0 on success (prints domain); exits 2 on invalid input.
################################################################################
parse_domain_arg() {
    local raw="$1"
    local d

    # Normalize
    d="${raw,,}"                              # lowercase
    d="${d#"${d%%[![:space:]]*}"}"            # trim leading space
    d="${d%"${d##*[![:space:]]}"}"            # trim trailing space
    d="${d#http://}"; d="${d#https://}"       # strip scheme
    d="${d%%/*}"                              # strip path (/...), if any
    d="${d%%\?*}"                             # strip query
    d="${d%%\#*}"                             # strip fragment
    d="${d%%:*}"                              # strip :port
    d="${d%.}"                                # strip trailing dot

    # Strip "www."
    [[ "$d" == www.* ]] && d="${d#www.}"

    # Validate
    # Hostname labels: a-z, 0-9, hyphen (no leading/trailing '-'), 1–63 chars per label
    # At least one dot; TLD 2–63 letters; total length <= 253
    local re='^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'
    if [[ -z "$d" || ${#d} -gt 253 || ! "$d" =~ $re ]]; then
        log ERROR "Invalid domain: '$raw' → '$d'. Expected a hostname like n8n.example.com"
        exit 2
    fi

    printf '%s\n' "$d"
}

################################################################################
# compose()
# Description:
#   Wrapper around `docker compose` that always supplies --env-file and -f.
#
# Behaviors:
#   - Requires ENV_FILE and COMPOSE_FILE to be set.
#   - Forwards all additional arguments to `docker compose`.
#
# Returns:
#   Exit code from `docker compose`; 1 if ENV_FILE/COMPOSE_FILE unset.
################################################################################
# Expect: ENV_FILE, COMPOSE_FILE set by caller scripts.
compose() {
    if [[ -z "${COMPOSE_FILE:-}" || -z "${ENV_FILE:-}" ]]; then
        log ERROR "compose(): COMPOSE_FILE/ENV_FILE not set"; return 1
    fi
    docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"
}

################################################################################
# strict_env_check()
# Description:
#   Validate that all ${VARS} used in compose file exist in the .env file.
#
# Behaviors:
#   - Extracts ${VAR} tokens from compose file.
#   - Builds a set of keys present in .env (ignores comments/blank).
#   - Logs missing variables, if any.
#
# Returns:
#   0 if all present; 1 if any are missing or .env is missing.
################################################################################
strict_env_check() {
    local compose_file="$1" env_file="$2"
    [[ -f "$env_file" ]] || { log ERROR ".env file not found at $env_file"; return 1; }

    log INFO "Checking for unset environment variables in $compose_file..."
    local vars_in_compose missing_vars=()
	# Extract VAR from ${VAR}, ${VAR:-...}, ${VAR?err}, etc.
	vars_in_compose=$(grep -oP '\$\{\K[A-Za-z_][A-Za-z0-9_]*(?=[^}]*)' "$compose_file" | sort -u)

    # Build KEY set from .env (ignore comments/blank). Accept: KEY=..., no "export".
	
    declare -A envmap
    while IFS='=' read -r k v; do
        [[ -z "$k" || "$k" =~ ^\s*# ]] && continue
        k="${k%% *}"; k="${k%%	*}"
        envmap["$k"]=1
    done < "$env_file"

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
#   Run strict_env_check and `compose config` to catch unset Vars/syntax errors.
#
# Behaviors:
#   - Verifies COMPOSE_FILE and ENV_FILE exist.
#   - Fails if strict_env_check reports missing keys.
#   - Runs `compose config` and checks for "variable is not set" or errors.
#
# Returns:
#   0 if valid; 1 on any validation error.
################################################################################
validate_compose_and_env() {
    [[ -f "${COMPOSE_FILE:-}" ]] || { log ERROR "Missing COMPOSE_FILE"; return 1; }
    [[ -f "${ENV_FILE:-}" ]]     || { log ERROR "Missing ENV_FILE"; return 1; }
    strict_env_check "$COMPOSE_FILE" "$ENV_FILE" || return 1

    # Validate docker-compose config syntax
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
# dump_unhealthy_container_logs()
# Description:
#   For all containers in the compose project, print logs for non-running/unhealthy ones.
#
# Behaviors:
#   - Iterates `compose ps -q` containers.
#   - Inspects state and health; prints last logs for offenders.
#
# Returns:
#   0 always.
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
# wait_for_containers_healthy()
# Description:
#   Wait until all compose containers are running and healthy (or timeout).
#
# Behaviors:
#   - Polls every <interval> seconds (default 10) up to <timeout> (default 180).
#   - Validates that each expected service has at least one running container.
#   - Logs per-cycle status and offenders; dumps logs on timeout.
#
# Returns:
#   0 if all healthy before timeout; 1 on timeout.
################################################################################
wait_for_containers_healthy() {
    local timeout="${1:-180}"
    local interval="${2:-10}"
    local elapsed=0
    discover_from_compose || true
    log INFO "Waiting for containers to be running & healthy (timeout=${timeout}s)…"
    while (( elapsed < timeout )); do
        local all_ok=true
        discover_running_containers
        local missing
        missing="$(find_missing_expected_containers || true)"
        if [[ -n "$missing" ]]; then
            all_ok=false
            log WARN "Expected but not (yet) running: $(echo "$missing" | tr '\n' ' ')"
        fi
        local offenders=() id name status health
        local ids
        ids="$(compose ps -q 2>/dev/null || true)"
        for id in $ids; do
            name="$(docker inspect --format='{{.Name}}' "$id" | sed 's#^/##')"
            status="$(docker inspect --format='{{.State.Status}}' "$id" || echo unknown)"
            health="$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$id" || echo none)"
            if [[ "$status" != "running" ]]; then
                all_ok=false; offenders+=( "$name(status=$status)" )
            elif [[ "$health" != "none" && "$health" != "healthy" ]]; then
                all_ok=false; offenders+=( "$name(health=$health)" )
            fi
        done
        if $all_ok; then
            log INFO "All expected containers are running and healthy."
            return 0
        fi
        log INFO "Waiting ${interval}s for next check"
        for ((i = 0; i < interval; i++)); do
            echo -n "."
            sleep 1
        done
        echo ""
        elapsed=$((elapsed + interval))
    done
    log ERROR "Timeout after ${timeout}s: containers missing or unhealthy."
    dump_unhealthy_container_logs 200
    return 1
}

################################################################################
# check_container_healthy()
# Description:
#   Wait until a specific container is running and healthy (or timeout).
#
# Behaviors:
#   - Resolves container by compose service name, falling back to docker ps by name.
#   - Accepts health "none" or "healthy" as OK when status is "running".
#   - Polls every <interval> seconds until <timeout>.
#
# Returns:
#   0 if healthy; 1 on timeout or not found.
################################################################################
check_container_healthy() {
    local container_name="$1"
    local timeout="${2:-60}"
    local interval="${3:-5}"
    local elapsed=0

    log INFO "Checking health for container: $container_name"

    while [ $elapsed -lt $timeout ]; do
        local container_id
		compose ps || true
		container_id="$(compose ps -q "$container_name" 2>/dev/null || true)"
		if [[ -z "$container_id" ]]; then
            container_id=$(docker ps -q -f "name=${container_name}" || true)
        fi

        if [[ -z "$container_id" ]]; then
            log WARN "Container '$container_name' not found or not running."
        else
            local status health
            status=$(docker inspect --format='{{.State.Status}}' "$container_id")
            health=$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$container_id")

            if [[ "$status" == "running" && ( "$health" == "none" || "$health" == "healthy" ) ]]; then
                log INFO "$container_name is running and ${health:-no-health-check}"
                return 0
            else
                log WARN "$container_name is running but not healthy (status: $status, health: $health)"
            fi
        fi

        log INFO "Waiting ${interval}s for next check"
        for ((i = 0; i < interval; i++)); do
            echo -n "."
            sleep 1
        done
        echo ""
        elapsed=$((elapsed + interval))
    done

    log ERROR "Timeout after ${timeout}s. Container '$container_name' is not healthy."
    return 1
}

################################################################################
# discover_from_compose()
# Description:
#   Parse docker compose to discover services, volumes, external volumes,
#   expected container names (container_name or service fallback), and mode.
#
# Behaviors:
#   - Uses `docker compose config --format json` if jq is present; falls back to
#     `--services` / `--volumes`.
#   - Fills DISCOVERED_SERVICES, DISCOVERED_VOLUMES, DISCOVERED_VOLUME_EXTERNAL,
#     DISCOVERED_CONTAINER_NAMES, and DISCOVERED_MODE.
#
# Returns:
#   0 on success; non-zero on failure to parse services.
################################################################################
discover_from_compose() {
    DISCOVERED_SERVICES=()
    DISCOVERED_VOLUMES=()
    DISCOVERED_VOLUME_EXTERNAL=()
    DISCOVERED_CONTAINER_NAMES=()
    DISCOVERED_MODE="unknown"

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

    local found_worker=false found_runner=false found_main=false s
    for s in "${DISCOVERED_SERVICES[@]}"; do
        case "${s,,}" in
            n8n-worker* ) found_worker=true ;;
            n8n-runner* ) found_runner=true ;;
            n8n|n8n-main ) found_main=true ;;
        esac
    done
    if $found_worker || $found_runner; then
        DISCOVERED_MODE="queue"
    elif $found_main; then
        DISCOVERED_MODE="single"
    fi

    ((${#DISCOVERED_CONTAINER_NAMES[@]}>0)) && mapfile -t DISCOVERED_CONTAINER_NAMES < <(printf "%s\n" "${DISCOVERED_CONTAINER_NAMES[@]}" | awk 'NF' | sort -u)
    ((${#DISCOVERED_VOLUME_EXTERNAL[@]}>0)) && mapfile -t DISCOVERED_VOLUME_EXTERNAL < <(printf "%s\n" "${DISCOVERED_VOLUME_EXTERNAL[@]}" | awk 'NF' | sort -u)

    log DEBUG "Services: ${DISCOVERED_SERVICES[*]}"
    log DEBUG "Expected container names: ${DISCOVERED_CONTAINER_NAMES[*]}"
    log DEBUG "Volumes: ${DISCOVERED_VOLUMES[*]:-<none>} (external: ${DISCOVERED_VOLUME_EXTERNAL[*]:-<none>})"
    log INFO  "Detected mode from compose: ${DISCOVERED_MODE}"
    return 0
}

################################################################################
# ensure_external_volumes()
# Description:
#   Pre-create any compose volumes that are marked external.
#
# Behaviors:
#   - Uses DISCOVERED_VOLUME_EXTERNAL list.
#   - Creates any missing external volume via `docker volume create`.
#
# Returns:
#   0 always (warns on create failures but continues).
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
# discover_running_containers()
# Description:
#   Populate RUNNING_CONTAINER_NAMES with running container names in this project.
#
# Behaviors:
#   - Uses `docker compose ps --format '{{.Name}}'`.
#   - De-duplicates and sorts the result.
#
# Returns:
#   0 always.
################################################################################
discover_running_containers() {
    RUNNING_CONTAINER_NAMES=()
    local names
    names="$(compose ps --format '{{.Name}}' 2>/dev/null || true)"
    if [[ -n "$names" ]]; then
        mapfile -t RUNNING_CONTAINER_NAMES < <(printf '%s\n' "$names" | awk 'NF' | sort -u)
    fi
    log INFO "Running containers: ${RUNNING_CONTAINER_NAMES[*]:-<none>}"
    return 0
}

################################################################################
# find_missing_expected_containers()
# Description:
#   Compare expected containers (from compose) against actually running ones.
#
# Behaviors:
#   - Expected set: DISCOVERED_CONTAINER_NAMES.
#   - Service name is satisfied by any running container for that service.
#   - Explicit container_name must appear as a running container.
#   - Prints a newline-separated list of missing expected entries (empty if none).
#
# Returns:
#   0 always (output is the list to consume by caller).
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
# docker_up_check()
# Description:
#   Ensure external volumes, bring up the stack, and wait for health.
#
# Behaviors:
#   - Runs discover_from_compose, ensure_external_volumes, compose up -d.
#   - Waits for containers to be healthy via wait_for_containers_healthy().
#
# Returns:
#   0 on success; 1 on health failures.
################################################################################
docker_up_check() {
    discover_from_compose || true
    ensure_external_volumes
    log INFO "Starting Docker Compose…"
    compose up -d
    wait_for_containers_healthy 180 10
}

################################################################################
# verify_traefik_certificate()
#   Lightweight post-deploy TLS check: confirm HTTPS reaches Traefik (valid TLS)
#   and (best-effort) log issuer/subject/dates via openssl.
#
# Behavior:
#   - DNS hint (A/AAAA) if `dig` is available.
#   - Treats HTTPS status 200/301/302/308/404 as success (TLS OK even if 404).
#   - Retries HTTPS up to 6 times with short delays.
#   - Tries to read and log certificate issuer/subject/notBefore/notAfter.
#   - Cert introspection is best-effort; failure to parse does NOT fail the check.
#
# Returns:
#   0 on HTTPS success (TLS established), regardless of cert introspection result.
#   1 only if HTTPS cannot be reached after retries.
################################################################################
verify_traefik_certificate() {
    local domain="${1:-${DOMAIN:-}}"
    local MAX_RETRIES="${2:-6}"
    local SLEEP_INTERVAL="${3:-10}"
    local domain_url curl_rc http_code success=false

    if [[ -z "$domain" ]]; then
        log ERROR "verify_traefik_certificate: domain is empty"
        return 1
    fi
    domain_url="https://${domain}"

    # DNS A/AAAA (optional)
    if command -v dig >/dev/null 2>&1; then
        log INFO "DNS A records for ${domain}:"
        dig +short A "$domain" | sed 's/^/  - /' || true
        log INFO "DNS AAAA records for ${domain}:"
        dig +short AAAA "$domain" | sed 's/^/  - /' || true
    else
        log WARN "'dig' not found; skipping DNS details."
    fi

    log INFO "Checking HTTPS reachability (valid chain required by curl)…"
    for ((i=1; i<=MAX_RETRIES; i++)); do
        # --fail makes curl exit non-zero on HTTP >= 400 and TLS/conn errors
        if http_code="$(curl -fsS -o /dev/null -w '%{http_code}' \
                         --connect-timeout 5 --max-time 15 \
                         "${domain_url}")"; then
            # Consider TLS OK if HTTP is up: 200/301/302/308/404
            if [[ "$http_code" =~ ^(200|301|302|308|404)$ ]]; then
                log INFO "HTTPS reachable (HTTP ${http_code}) [attempt ${i}/${MAX_RETRIES}]"
                success=true
                break
            else
                log WARN "HTTPS up but app not ready yet (HTTP ${http_code}) [attempt ${i}/${MAX_RETRIES}]"
            fi
        else
            curl_rc=$?
            # When curl fails, http_code will usually be empty or "000"
            log WARN "HTTPS not ready (curl_exit=${curl_rc}, http=${http_code:-N/A}) [attempt ${i}/${MAX_RETRIES}]"
        fi
        [[ $i -lt $MAX_RETRIES ]] && { log INFO "Retrying in ${SLEEP_INTERVAL}s..."; sleep "$SLEEP_INTERVAL"; }
    done

    if ! $success; then
        log ERROR "${domain} is not reachable via HTTPS after ${MAX_RETRIES} attempts."
        dump_service_logs traefik 200
        log INFO "Tip: follow live Traefik logs with: docker logs -f traefik"
        return 1
    fi

    # Best-effort cert details (non-fatal)
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
# check_domain_points_here()
# Description:
#   Verify the provided domain’s A record points to this server’s public IP.
#
# Behaviors:
#   - Detects server IP via api.ipify.org.
#   - Resolves DOMAIN with `dig` (preferred) or `getent`; logs resolved IPs.
#   - Warns and continues if resolver tools are missing.
#
# Returns:
#   0 on success/skip (no resolver); 1 on mismatch.
################################################################################
check_domain_points_here() {
    local domain="$1"
    require_cmd curl || { log WARN "curl missing; cannot verify DNS."; return 0; }
    local server_ip domain_ips resolver=""
    server_ip="$(curl -s https://api.ipify.org || echo "Unavailable")"
    if command -v dig >/dev/null 2>&1; then
        resolver="dig"
        domain_ips="$(dig +short A "$domain" | tr '\n' ' ')"
    elif command -v getent >/dev/null 2>&1; then
        resolver="getent"
        domain_ips="$(getent ahostsv4 "$domain" | awk '{print $1}' | sort -u | tr '\n' ' ')"
    else
        log WARN "No 'dig' nor 'getent'; DNS check skipped."
        return 0
    fi
    log INFO "Server public IP: $server_ip"
    log INFO "Domain ${domain} resolves (${resolver}): $domain_ips"
    if [[ "$server_ip" == "Unavailable" ]]; then
        log WARN "Could not determine server IP; continuing."
        return 0
    fi
    if echo "$domain_ips" | tr ' ' '\n' | grep -Fxq "$server_ip"; then
        log INFO "Domain points to this server."
    else
        log ERROR "Domain does NOT point here. Update A record to: $server_ip"
        return 1
    fi
}

################################################################################
# get_current_n8n_version()
# Description:
#   Print the running n8n version by exec'ing into the n8n container.
#
# Behaviors:
#   - Tries `compose ps -q n8n`; falls back to `docker exec n8n`.
#   - Prints "unknown" if not available.
#
# Returns:
#   0 always (prints version or "unknown").
################################################################################
get_current_n8n_version() {
    local cid
    cid="$(compose ps -q n8n 2>/dev/null || true)"
    if [[ -n "$cid" ]]; then
        docker exec "$cid" n8n --version 2>/dev/null && return 0
    fi
    docker exec n8n n8n --version 2>/dev/null || echo "unknown"
}

################################################################################
# get_latest_n8n_version()
# Description:
#   Fetch the latest stable semver tag (x.y.z) of n8n from Docker Hub.
#
# Behaviors:
#   - Requests tags page and filters stable semver names.
#   - Prints the newest version (sort -Vr | head -n1).
#
# Returns:
#   0 on success (may print empty on API issues); 1 if jq missing.
################################################################################
get_latest_n8n_version() {
    require_cmd jq || return 1
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
# fetch_all_stable_versions()
# Description:
#   Retrieve and print all stable semver tags (x.y.z) from Docker Hub.
#
# Behaviors:
#   - Requires jq.
#   - Follows pagination; aggregates results.
#   - Prints unique ascending-sorted list.
#
# Returns:
#   0 on success (even if none found); 1 if jq missing.
################################################################################
fetch_all_stable_versions() {
    if ! command -v jq >/dev/null 2>&1; then
        log ERROR "'jq' is required to fetch tags from Docker Hub."
        return 1
    fi

    local url="https://registry.hub.docker.com/v2/repositories/n8nio/n8n/tags?page_size=100"
    local next page_json
    local -a all=()

    while [[ -n "$url" ]]; do
        page_json=$(curl -fsS --retry 3 --retry-delay 2 "$url" 2>/dev/null || true)
        [[ -z "$page_json" ]] && { log WARN "Failed to fetch tags page"; break; }
        mapfile -t page_tags < <(jq -r '.results[].name' <<<"$page_json" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' || true)
        all+=("${page_tags[@]}")
        next=$(jq -r '.next // empty' <<<"$page_json" 2>/dev/null || true)
        url="$next"
    done

    if ((${#all[@]}==0)); then
        log WARN "No n8n stable version found from Docker Hub"
        return 0
    fi

    # print unique, sorted ascending (natural/semantic)
    printf "%s\n" "${all[@]}" | sort -Vu
}

################################################################################
# validate_image_tag()
# Description:
#   Check whether an n8n image tag exists.
#
# Behaviors:
#   - Tries docker.n8n.io then docker.io registries via `docker manifest inspect`.
#
# Returns:
#   0 if found; 1 otherwise.
################################################################################
validate_image_tag() {
    local tag="$1"
    docker manifest inspect "docker.n8n.io/n8nio/n8n:${tag}" >/dev/null 2>&1 && return 0
    docker manifest inspect "docker.io/n8nio/n8n:${tag}" >/dev/null 2>&1 && return 0
    return 1
}
