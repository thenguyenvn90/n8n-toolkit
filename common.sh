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
declare -a DISCOVERED_NETWORKS=()
declare -a DISCOVERED_NETWORK_EXTERNAL=()
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
check_root() { (( EUID == 0 )) || { log ERROR "This script must be run as root."; return 1; }; }

################################################################################
# ensure_prereqs()
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
ensure_prereqs() {
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
        log ERROR "Docker is missing. Please run the Docker installer step (ensure_prereqs) first."
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
    (( n<=8 )) && { printf '***\n'; return; }
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
# upsert_env_var()
# Description:
#     Insert or update KEY=VALUE in a .env file idempotently.
#
# Behaviors:
#   upsert_env_var KEY VALUE FILE
#   Idempotently set KEY=VALUE in FILE.
#       - If KEY exists (line begins with "^KEY="), replace the whole line.
#       - If KEY is missing, append "KEY=VALUE" and ensure there's a newline before it.
#       - Handles special chars in VALUE (/, &, backslashes) for sed.
#
# Returns:
#     0 on success.
################################################################################
upsert_env_var() {
    local key="$1"
    local value="$2"
    local file="$3"

    [[ -n "$key" && -n "$file" ]] || { echo "[ERROR] upsert_env_var: missing key or file" >&2; return 1; }
    [[ -f "$file" ]] || touch "$file"

    # Escape VALUE for sed replacement (slashes, ampersands, and backslashes)
    local esc
    esc="$(printf '%s' "$value" | sed -e 's/[\/&]/\\&/g' -e 's/\\/\\\\/g')"

    if grep -qE "^${key}=" "$file"; then
        # Replace entire line
        sed -i -E "s|^${key}=.*$|${key}=${esc}|g" "$file"
    else
        # Ensure file ends with a newline before appending
        if [[ -s "$file" ]]; then
            # If last char is not a newline, add one
            local last_char
            last_char="$(tail -c1 -- "$file" 2>/dev/null || true)"
            [[ "$last_char" == $'\n' ]] || printf '\n' >> "$file"
        fi
        printf '%s=%s\n\n' "$key" "$value" >> "$file"
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
# rotate_or_generate_secret()
# Description:
#   Ensures a secret variable in the .env file is properly set.
#   If missing or still a placeholder, generates a secure value using openssl.
#
# Behaviors:
#   - Reads the value of the specified variable from the provided .env file.
#   - If the value is empty or matches the placeholder, generates a new secret.
#   - Updates the .env file with the new value.
#
# Returns:
#   None. Prints info message on rotation.
################################################################################
rotate_or_generate_secret() {
    local envfile="$1"     # path to .env
    local key="$2"         # VAR name
    local bytes="$3"       # number of random bytes before base64
    local placeholder="$4" # placeholder to detect

    [[ -n "$envfile" && -n "$key" && -n "$bytes" ]] || { log ERROR "rotate_or_generate_secret: missing args"; return 1; }
    [[ -f "$envfile" ]] || : > "$envfile"

    # Read current value (prefer your read_env_var if present)
    local current=""
    if declare -F read_env_var >/dev/null 2>&1; then
        current="$(read_env_var "$envfile" "$key" || true)"
    else
        # simple fallback (won’t handle quotes/comments as robustly as read_env_var)
        current="$(awk -F= -v v="$key" '$1==v{print substr($0, index($0,$2)); exit}' "$envfile" | tr -d '\r')"
    fi

    if [[ -z "$current" || "$current" == "$placeholder" ]]; then
        local new_secret
        new_secret="$(openssl rand -base64 "$bytes" | tr -d '\n')"
        upsert_env_var "$key" "$new_secret" "$envfile"
        log INFO "Rotated ${key} in ${envfile}"
    else
        log INFO "Existing ${key} found. Not rotating."
    fi
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
# project_default_network_name()
# Description:
#   Return the implicit default Compose network name for this project.
################################################################################
project_default_network_name() {
    printf '%s_default\n' "$(project_name)"
}


################################################################################
# discover_compose_networks()
# Description:
#   Populate DISCOVERED_NETWORKS (real Docker network names) and
#   DISCOVERED_NETWORK_EXTERNAL (logical names marked external in config).
#   Sources:
#     1) `compose config --format json` (.networks + name/external logic)
#     2) Docker networks labeled with this compose project
#        (catches implicit "<project>_default" and any unnamed ones)
################################################################################
discover_compose_networks() {
    DISCOVERED_NETWORKS=()
    DISCOVERED_NETWORK_EXTERNAL=()

    local pn; pn="$(project_name)"

    # 1) Parse from compose config (names + external flags)
    if command -v jq >/dev/null 2>&1; then
        local json
        if json="$(compose config --format json 2>/dev/null)"; then
            local -a logicals=()
            mapfile -t logicals < <(printf '%s' "$json" | jq -r '(.networks // {}) | keys[]?')

            local n ext_flag ext_name explicit_name realname
            for n in "${logicals[@]}"; do
                ext_flag="$(printf '%s' "$json" | jq -r --arg n "$n" \
                    '(.networks[$n].external // false) | (if type=="boolean" then . else (has("name")) end)')"
                if [[ "$ext_flag" == "true" ]]; then
                    # external network → don't delete it; record real name for info
                    ext_name="$(printf '%s' "$json" | jq -r --arg n "$n" '(.networks[$n].external.name // "")')"
                    DISCOVERED_NETWORK_EXTERNAL+=( "$n" )
                    DISCOVERED_NETWORKS+=( "${ext_name:-$n}" )
                else
                    # compose-managed network: may have an explicit 'name', else <project>_<logical>
                    explicit_name="$(printf '%s' "$json" | jq -r --arg n "$n" '(.networks[$n].name // "")')"
                    realname="${explicit_name:-${pn}_${n}}"
                    DISCOVERED_NETWORKS+=( "$realname" )
                fi
            done
        fi
    fi

    # 2) Union with networks actually created for this project (labeled)
    local -a labeled=()
    mapfile -t labeled < <(
        docker network ls \
          --filter "label=com.docker.compose.project=${pn}" \
          --format '{{.Name}}' 2>/dev/null | awk 'NF' | sort -u
    )

    if ((${#labeled[@]})); then
        DISCOVERED_NETWORKS+=( "${labeled[@]}" )
    else
        # Fallback: implicit "<project>_default" if it exists
        local def; def="$(project_default_network_name)"
        docker network inspect "$def" >/dev/null 2>&1 && DISCOVERED_NETWORKS+=( "$def" )
    fi

    # De-dup
    if ((${#DISCOVERED_NETWORKS[@]})); then
        mapfile -t DISCOVERED_NETWORKS < <(printf '%s\n' "${DISCOVERED_NETWORKS[@]}" | awk 'NF' | sort -u)
    fi

    log DEBUG "Networks: ${DISCOVERED_NETWORKS[*]:-<none>} (external logicals: ${DISCOVERED_NETWORK_EXTERNAL[*]:-<none>})"
    return 0
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
    discover_compose_networks || true
    return 0
}

################################################################################
# _discover_running_containers()
# Description:
#     Populate RUNNING_CONTAINER_NAMES with running container names in this project.
#
# Returns:
#     0 always.
################################################################################
_discover_running_containers() {
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
# _find_missing_expected_containers()
# Description:
#     Compare expected containers (from compose) against actually running ones.
#
# Output:
#     Prints newline-separated list of missing expected entries (if any).
#
# Returns:
#     0 always.
################################################################################
_find_missing_expected_containers() {
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
# remove_compose_networks()
# Description:
#   Remove all Docker networks created by this Compose project.
#   - Only removes networks labeled with this project (safe for externals).
#   - Falls back to removing "<project>_default" if present.
################################################################################
remove_compose_networks() {
    command -v docker >/dev/null 2>&1 || { log WARN "docker not found; skipping network removal."; return 0; }
    local pn; pn="$(project_name)"

    local -a nets=()
    mapfile -t nets < <(
        docker network ls \
          --filter "label=com.docker.compose.project=${pn}" \
          --format '{{.Name}}' 2>/dev/null | awk 'NF' | sort -u
    )

    if ((${#nets[@]} == 0)); then
        local def; def="$(project_default_network_name)"
        docker network inspect "$def" >/dev/null 2>&1 && nets=( "$def" )
    fi

    if ((${#nets[@]} == 0)); then
        log INFO "No Compose-managed networks found to remove."
        return 0
    fi

    log INFO "Removing Compose networks: ${nets[*]}"
    local n
    for n in "${nets[@]}"; do
        if docker network rm "$n" >/dev/null 2>&1; then
            log INFO "Removed network: $n"
        else
            log WARN "Could not remove network '$n' (in use or already gone)."
        fi
    done
}

################################################################################
# purge_project_volumes_by_label()
# Description:
#   Remove all Docker volumes that belong to the current Compose project,
#   identified by the standard Compose v2 label:
#       com.docker.compose.project = $(project_name)
#
#   This is stronger and more reliable than name-based matching because it
#   correctly handles custom COMPOSE_PROJECT_NAME, variations like "_" vs "-",
#   and any volumes created by Compose for this project.
#
# Args:
#   (none) — uses project_name() derived from .env or $N8N_DIR basename.
#
# Returns:
#   0 always (best-effort purge; ignores individual rm failures).
#
# Behavior/Notes:
#   - Does nothing if no labeled volumes are found.
#   - Forces removal (-f) to avoid “in use” prompts.
################################################################################
purge_project_volumes_by_label() {
    local pn; pn="$(project_name)"
    local -a vols=()
    mapfile -t vols < <(docker volume ls -q --filter "label=com.docker.compose.project=${pn}" 2>/dev/null | awk 'NF')
    ((${#vols[@]})) || { log INFO "No project-labeled volumes to purge."; return 0; }
    log INFO "Purging project-labeled volumes: ${#vols[@]}"
    printf '%s\n' "${vols[@]}" | xargs -r docker volume rm -f >/dev/null 2>&1 || true
}

################################################################################
# purge_project_networks_by_label()
# Description:
#   Remove all Docker networks that belong to the current Compose project,
#   identified by the Compose v2 label:
#       com.docker.compose.project = $(project_name)
#
# Args:
#   (none) — uses project_name() derived from .env or $N8N_DIR basename.
#
# Returns:
#   0 always (best-effort purge; ignores individual rm failures).
#
# Behavior/Notes:
#   - Complements remove_compose_networks() which targets discovered networks.
#   - This label-based purge catches any leftover/renamed networks for the project.
################################################################################
purge_project_networks_by_label() {
    local pn; pn="$(project_name)"
    local -a nets=()
    mapfile -t nets < <(docker network ls -q --filter "label=com.docker.compose.project=${pn}" 2>/dev/null | awk 'NF')
    ((${#nets[@]})) || { log INFO "No project-labeled networks to purge."; return 0; }
    log INFO "Purging project-labeled networks: ${#nets[@]}"
    printf '%s\n' "${nets[@]}" | xargs -r docker network rm >/dev/null 2>&1 || true
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

        _discover_running_containers
        missing="$(_find_missing_expected_containers || true)"
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
    missing_now="$(_find_missing_expected_containers || true)"
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
#     $2 -> max retries (default 6)
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
# preflight_dns_checks()
# Description:
#   Hard-fail DNS preflight for all exposed hostnames *before* bringing the
#   stack up. The set of hostnames is provided by `list_exposed_fqdns`, which
#   should echo one FQDN per line.
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
    local latest
    latest="$(_fetch_stable_tags 100 | head -n 1 || true)"
    [[ -z "$latest" ]] && log ERROR "Could not fetch latest n8n tag from Docker Hub"
    echo "$latest"
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
    mapfile -t all < <(_fetch_stable_tags 100 | head -n 5)
    if ((${#all[@]}==0)); then
        log WARN "No n8n stable version found from Docker Hub"
        return 0
    fi

    echo "Latest 5 n8n versions (newest first):"
    printf "%s\n" "${all[@]}"
}

################################################################################
# _fetch_stable_tags()
# Description:
#     Internal helper to fetch and output all stable semver tags (x.y.z) for
#     n8n from Docker Hub, sorted newest-first (version-aware).
#
# Args:
#     $1 -> page size to request (default: 100)
#
# Output:
#     Prints one tag per line, e.g.:
#         1.107.2
#         1.107.1
#         ...
#
# Returns:
#     0 on success (even if empty); non-zero if curl/jq missing or fetch fails.
################################################################################
_fetch_stable_tags() {
    local page_size="${1:-100}"
    require_cmd jq || return 1
    require_cmd curl || return 1

    local url="https://registry.hub.docker.com/v2/repositories/n8nio/n8n/tags?page_size=${page_size}"
    local page_json
    page_json=$(curl -fsS --retry 3 --retry-delay 2 "$url" 2>/dev/null || true)
    [[ -z "$page_json" ]] && { log WARN "Failed to fetch tags page"; return 1; }

    jq -r '.results[].name' <<<"$page_json" \
        | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' \
        | sort -Vr
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
# resolve_n8n_target_version()
# Description:
#     Determine a concrete n8n Docker image tag to deploy.
#     - If the input tag is empty or "latest", it queries Docker Hub for the
#       latest stable semver (via get_latest_n8n_version).
#     - It then validates the candidate tag exists on docker.n8n.io or docker.io
#       (via validate_image_tag).
#
# Args:
#     $1 -> desired tag (e.g., "1.108.0" or "latest"; defaults to "latest" when unset)
#
# Output:
#     Prints the resolved tag (e.g., "1.108.0") to stdout on success.
#
# Returns:
#     0 on success.
#     1 if the tag cannot be determined or does not exist in registries.
#
# Dependencies:
#     get_latest_n8n_version, validate_image_tag, log
#
# Example:
#     TAG="$(resolve_n8n_target_version "${N8N_VERSION:-latest}")" || exit 1
################################################################################
resolve_n8n_target_version() {
    local desired="${1:-latest}"
    if [[ -z "$desired" || "$desired" == "latest" ]]; then
        desired="$(get_latest_n8n_version)"
        [[ -z "$desired" ]] && { log ERROR "Could not determine latest n8n tag."; return 1; }
    fi
    validate_image_tag "$desired" || { log ERROR "Image tag not found: $desired"; return 1; }
    printf '%s\n' "$desired"
}

################################################################################
# send_email()
# Description:
#   Low-level sender: send a multipart email via Gmail SMTP (msmtp), optional
#   attachment. Caller (manager) decides *whether* to send and interprets result.
#
# Env consumed (must be set by caller):
#   SMTP_USER, SMTP_PASS, EMAIL_TO
#
# Args:
#   $1 -> subject
#   $2 -> body (text/plain UTF-8)
#   $3 -> optional attachment path
#
# Returns:
#   0 on success; non-zero on failure.
################################################################################
send_email() {
    local subject="$1"
    local body="$2"
    local attachment="${3:-}"

    require_cmd msmtp || { log ERROR "msmtp not available; cannot send email."; return 1; }
    if [[ -z "${SMTP_USER:-}" || -z "${SMTP_PASS:-}" || -z "${EMAIL_TO:-}" ]]; then
        log ERROR "SMTP_USER/SMTP_PASS/EMAIL_TO not set; cannot send email."
        return 1
    fi

    log INFO "Sending email to: $EMAIL_TO"

    # Protect password for passwordeval
    local pass_tmp; pass_tmp="$(mktemp)"; printf '%s' "$SMTP_PASS" > "$pass_tmp"; chmod 600 "$pass_tmp"
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
            local filename; filename="$(basename "$attachment")"
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
    [[ $rc -eq 0 ]] && log INFO "Email sent: $subject" || log WARN "Email failed: $subject"
    return $rc
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
    if [[ -z "$RCLONE_REMOTE" ]]; then echo ""; return; fi
    command -v rclone >/dev/null 2>&1 || { log WARN "rclone not installed; cannot derive Drive link."; echo ""; return; }
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
# snapshot_sync()
# Description:
#   Synchronize the on-disk snapshot used for change detection.
#   Modes:
#     - boot    : initialize snapshot dirs (create if missing) and copy current data
#     - refresh : update snapshot after a successful backup (uses --delete)
# Notes:
#   - Uses BACKUP_DIR, DISCOVERED_VOLUMES, ENV_FILE, COMPOSE_FILE.
#   - Excludes transient Postgres paths on refresh for smaller, stable diffs.
# Returns:
#   0 always (best-effort; logs warnings on missing volumes/mounts).
################################################################################
snapshot_sync() {
    local mode="${1:-boot}"
    local snap="${BACKUP_DIR:-$PWD}/snapshot"
    mkdir -p "$snap/volumes" "$snap/config"

    local vol real mp
    for vol in "${DISCOVERED_VOLUMES[@]}"; do
        real="$(resolve_volume_name "$vol" || true)"
        if [[ -z "$real" ]]; then
            log INFO "Snapshot: volume '$vol' not present; skipping."
            continue
        fi
        mp="$(volume_mountpoint "$real")"
        if [[ -z "$mp" || ! -d "$mp" ]]; then
            log WARN "Snapshot: no mountpoint for '$real'; skipping."
            continue
        fi
        if [[ "$mode" == "refresh" ]]; then
            rsync -a --delete \
              --exclude='pg_wal/**' --exclude='pg_stat_tmp/**' --exclude='pg_logical/**' \
              "$mp/" "$snap/volumes/$vol/" || true
        else
            rsync -a "$mp/" "$snap/volumes/$vol/" || true
        fi
    done

    # Configs
    if [[ "$mode" == "refresh" ]]; then
        [[ -f "$ENV_FILE"     ]] && rsync -a --delete "$ENV_FILE"     "$snap/config/" || true
        [[ -f "$COMPOSE_FILE" ]] && rsync -a --delete "$COMPOSE_FILE" "$snap/config/" || true
    else
        [[ -f "$ENV_FILE"     ]] && rsync -a "$ENV_FILE"     "$snap/config/" || true
        [[ -f "$COMPOSE_FILE" ]] && rsync -a "$COMPOSE_FILE" "$snap/config/" || true
    fi
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
    local vol diffs real mp

    for vol in "${DISCOVERED_VOLUMES[@]}"; do
    real="$(resolve_volume_name "$vol" || true)"; [[ -z "$real" ]] && continue
    mp="$(volume_mountpoint "$real")"; [[ -z "$mp" || ! -d "$mp" ]] && continue
    diffs="$(rsync -rtun \
        --exclude='pg_wal/**' --exclude='pg_stat_tmp/**' --exclude='pg_logical/**' \
        "$mp/" "$snap/volumes/$vol/" | grep -v '/$' || true)"
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
# postgres_recreate_db()
# Description:
#     In a running PostgreSQL container, ensure a role exists, then drop and
#     recreate a target database owned by that role.
#
#     Steps (in order):
#       1) CREATE ROLE <owner> LOGIN if it does not already exist.
#       2) Terminate active sessions connected to <db> (best-effort).
#       3) DROP DATABASE IF EXISTS <db>.
#       4) CREATE DATABASE <db> OWNER <owner>.
#
# Args:
#     $1 -> pgcid  : Postgres container id/name (as seen by `docker ps` / compose)
#     $2 -> admin  : superuser to run DDL (e.g., "postgres")
#     $3 -> pass   : password for the admin role (can be empty if trust/peer auth)
#     $4 -> db     : database name to recreate
#     $5 -> owner  : role that will own the recreated database
#
# Returns:
#     0 on success.
#     Non-zero if DROP/CREATE or role creation fails.
#     (Session termination is best-effort and ignored on failure.)
#
# Behavior/Notes:
#     - All commands are executed inside the container via `docker exec` with
#       `ON_ERROR_STOP=1` so SQL errors propagate as non-zero exit codes.
#     - The owner role is created with LOGIN and no password.
#     - Requires `psql` inside the container and Docker CLI on the host.
#
# Example:
#     postgres_recreate_db "$PG_CID" "postgres" "$ADMIN_PASS" "n8n" "n8n"
################################################################################
postgres_recreate_db() {
    local pgcid="$1" admin="$2" pass="$3" db="$4" owner="$5"

    # ensure role exists
    docker exec -e PGPASSWORD="$pass" -i "$pgcid" psql -U "$admin" -d postgres -v ON_ERROR_STOP=1 -c \
"DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='${owner}') THEN
    EXECUTE format('CREATE ROLE %I LOGIN', '${owner}');
  END IF;
END
\$\$;"

    # terminate sessions, drop+create db
    docker exec -e PGPASSWORD="$pass" -i "$pgcid" psql -U "$admin" -d postgres -v ON_ERROR_STOP=1 -c \
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='${db}' AND pid <> pg_backend_pid();" || true
    docker exec -e PGPASSWORD="$pass" -i "$pgcid" psql -U "$admin" -d postgres -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS ${db};"
    docker exec -e PGPASSWORD="$pass" -i "$pgcid" psql -U "$admin" -d postgres -v ON_ERROR_STOP=1 -c "CREATE DATABASE ${db} OWNER ${owner};"
}

################################################################################
# safe_wipe_target_dir()
# Description:
#   Delete the *contents* of $N8N_DIR (files and dotfiles), but NOT the directory
#   itself. Includes safeguards to avoid deleting the script’s own location if
#   $SCRIPT_DIR is inside $N8N_DIR.
#
# Args:
#   (none) — uses global $N8N_DIR and $SCRIPT_DIR.
#
# Returns:
#   0 always (best-effort removal).
#
# Behavior/Notes:
#   - Skips if $N8N_DIR does not exist.
#   - Skips if $SCRIPT_DIR resides under $N8N_DIR to prevent self-deletion.
#   - Uses dotglob to include dotfiles and nullglob to ignore empty globs.
################################################################################
safe_wipe_target_dir() {
    local tgt="$N8N_DIR"
    [[ -d "$tgt" ]] || { log INFO "Target dir not found: $tgt (skip)"; return 0; }

    local abs_tgt abs_script
    abs_tgt="$(readlink -f "$tgt" 2>/dev/null || echo "$tgt")"
    abs_script="$(readlink -f "$SCRIPT_DIR" 2>/dev/null || echo "$SCRIPT_DIR")"

    if [[ "$abs_script" == "$abs_tgt" || "$abs_script" == "$abs_tgt"/* ]]; then
        log WARN "Script directory is inside target dir; skipping directory wipe to avoid self-deletion."
        return 0
    fi

    log WARN "Wiping contents of $abs_tgt …"
    shopt -s dotglob nullglob
    rm -rf -- "${abs_tgt}/"* "${abs_tgt}"/.[!.]* "${abs_tgt}"/..?* 2>/dev/null || true
    shopt -u dotglob nullglob
    log INFO "Target directory contents removed."
}
