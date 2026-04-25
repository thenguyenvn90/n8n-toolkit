#!/usr/bin/env bash
# tests/test_helper/common.bash — Shared setup helpers for all bats test files.
# Loaded via: load '../test_helper/common'

# Repository root: two levels up from test_helper/
TOOLKIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# ---------------------------------------------------------------------------
# source_common()
# Source lib/common.sh safely in test context, suppressing trap conflicts.
# ---------------------------------------------------------------------------
source_common() {
    # Prevent ERR/INT/TERM traps in common.sh from killing the bats harness
    trap '' ERR INT TERM HUP 2>/dev/null || true
    # shellcheck disable=SC1090
    source "$TOOLKIT_DIR/lib/common.sh" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# source_all_libs()
# Source all lib files in load-order, exactly as n8n_manager.sh does.
# ---------------------------------------------------------------------------
source_all_libs() {
    trap '' ERR INT TERM HUP 2>/dev/null || true
    for _lib in common.sh install.sh upgrade.sh backup.sh cleanup.sh; do
        # shellcheck disable=SC1090
        source "$TOOLKIT_DIR/lib/$_lib" 2>/dev/null || true
    done
    unset _lib
}

# ---------------------------------------------------------------------------
# create_test_env()
# Write a minimal valid .env file to the given path.
# ---------------------------------------------------------------------------
create_test_env() {
    local env_file="$1"
    cat > "$env_file" <<'EOF'
DOMAIN=example.com
SUBDOMAIN_N8N=n8n
SSL_EMAIL=test@example.com
GENERIC_TIMEZONE=UTC
N8N_IMAGE_TAG=2.17.7
POSTGRES_PASSWORD=testpassword123
N8N_ENCRYPTION_KEY=dGVzdGtleWJhc2U2NGVuY3J5cHRpb25rZXk=
N8N_BASIC_AUTH_PASSWORD=testauth123
REDIS_PASSWORD=testredis123
N8N_RUNNERS_AUTH_TOKEN=testtoken123
MONITORING_BASIC_AUTH_PASS=testmon123
DB_TYPE=postgresdb
DB_POSTGRESDB_HOST=postgres
DB_POSTGRESDB_PORT=5432
DB_POSTGRESDB_DATABASE=n8n
DB_POSTGRESDB_USER=n8n
DB_POSTGRESDB_PASSWORD=testpassword123
POSTGRES_USER=n8n
POSTGRES_DB=n8n
EXECUTIONS_MODE=regular
N8N_RUNNERS_ENABLED=true
N8N_RUNNERS_MODE=internal
COMPOSE_PROFILES=
EXPOSE_PROMETHEUS=false
N8N_FQDN=n8n.example.com
GRAFANA_FQDN=grafana.example.com
PROMETHEUS_FQDN=prometheus.example.com
COMPOSE_PROJECT_NAME=n8n
EOF
}

# ---------------------------------------------------------------------------
# mock_docker()
# Export a docker() shell function that handles common stub cases.
# ---------------------------------------------------------------------------
mock_docker() {
    docker() {
        case "$1" in
            version)
                if [[ "${*}" == *"--format"* ]]; then
                    echo "27"
                else
                    echo "Docker version 27.0.0, build abc1234"
                fi
                ;;
            compose)
                case "${*}" in
                    *"config --format json"*)
                        echo '{"services":{"main":{"container_name":"n8n-main"}},"volumes":{},"networks":{}}'
                        ;;
                    *"config --services"*) echo "main" ;;
                    *"config --volumes"*)  echo "" ;;
                    *"ps -q"*)             echo "abc123def456" ;;
                    *"ps --format"*)       echo "n8n-main Up" ;;
                    *"ps"*)                printf 'NAME\tSTATUS\nn8n-main\tUp\n' ;;
                    *"down"*)              return 0 ;;
                    *"up"*)                return 0 ;;
                    *)                     return 0 ;;
                esac
                ;;
            inspect)
                if [[ "${*}" == *"--format"*"Name"* ]]; then
                    echo "/n8n-main"
                elif [[ "${*}" == *"--format"*"Mountpoint"* ]]; then
                    echo "/var/lib/docker/volumes/n8n_data/_data"
                else
                    echo '[]'
                fi
                ;;
            volume)
                case "$2" in
                    inspect) return 0 ;;
                    create)  return 0 ;;
                    ls)      echo "" ;;
                    *)       return 0 ;;
                esac
                ;;
            network)
                case "$2" in
                    ls)      echo "" ;;
                    inspect) return 1 ;;
                    rm)      return 0 ;;
                    *)       return 0 ;;
                esac
                ;;
            image)
                case "$2" in
                    prune) return 0 ;;
                    *)     return 0 ;;
                esac
                ;;
            manifest)
                case "$2" in
                    inspect) return 0 ;;
                    *)       return 0 ;;
                esac
                ;;
            exec)  return 0 ;;
            run)   return 0 ;;
            logs)  echo "[fake-log] container started" ;;
            --version) echo "Docker version 27.0.0, build abc1234" ;;
            *)     return 0 ;;
        esac
        return 0
    }
    export -f docker
}

# ---------------------------------------------------------------------------
# mock_compose()
# A lighter mock that only intercepts "docker compose" sub-commands.
# Delegates everything else to mock_docker.
# ---------------------------------------------------------------------------
mock_compose() {
    mock_docker
}

# ---------------------------------------------------------------------------
# setup_stub_bin()
# Create a $STUB_BIN directory on PATH with stub executables for external
# commands. This is the PATH-injection alternative to export -f for subshells.
# ---------------------------------------------------------------------------
setup_stub_bin() {
    export STUB_BIN="$BATS_TEST_TMPDIR/bin"
    mkdir -p "$STUB_BIN"
    export PATH="$STUB_BIN:$PATH"

    # docker stub
    cat > "$STUB_BIN/docker" <<'DOCKEREOF'
#!/bin/bash
args="$*"
case "$args" in
    *"version --format"*) echo "27" ;;
    *"manifest inspect"*) exit 0 ;;
    *"compose"*"config --format json"*)
        echo '{"services":{"main":{"container_name":"n8n-main"}},"volumes":{},"networks":{}}'
        ;;
    *"compose"*"config --services"*) echo "main" ;;
    *"compose"*"config --volumes"*)  echo "" ;;
    *"compose"*"ps -q"*)             echo "abc123def456" ;;
    *"compose"*"ps --format"*)       echo "n8n-main Up" ;;
    *"compose"*"ps"*)                printf 'NAME\tSTATUS\nn8n-main\tUp\n' ;;
    *"compose"*)                     exit 0 ;;
    *"inspect"*"--format"*"Name"*)   echo "/n8n-main" ;;
    *"inspect"*"--format"*"Mountpoint"*) echo "/var/lib/docker/volumes/n8n_data/_data" ;;
    *"inspect"*)                     echo '[]' ;;
    *"volume inspect"*)              exit 0 ;;
    *"volume create"*)               exit 0 ;;
    *"volume ls"*)                   echo "" ;;
    *"network ls"*)                  echo "" ;;
    *"network inspect"*)             exit 1 ;;
    *"network rm"*)                  exit 0 ;;
    *"exec"*"n8n --version"*)        echo "1.108.0" ;;
    *"exec"*)                        exit 0 ;;
    *"run"*"--rm"*)                  exit 0 ;;
    *"image prune"*)                 exit 0 ;;
    *"--version"*)                   echo "Docker version 27.0.0, build abc1234" ;;
    *)                               exit 0 ;;
esac
DOCKEREOF
    chmod +x "$STUB_BIN/docker"

    # openssl stub
    cat > "$STUB_BIN/openssl" <<'EOF'
#!/bin/bash
case "$*" in
    *"rand"*"-base64"*"32"*) echo "dGVzdFNlY3JldEtleUZvcjMyQnl0ZXNMT05HRU5PVUdI" ;;
    *"rand"*"-base64"*"16"*) echo "dGVzdHNlY3JldDEyMzQ1Ng==" ;;
    *"rand"*"-base64"*)      echo "dGVzdHNlY3JldA==" ;;
    *)                       exit 0 ;;
esac
EOF
    chmod +x "$STUB_BIN/openssl"

    # curl stub
    cat > "$STUB_BIN/curl" <<'EOF'
#!/bin/bash
case "$*" in
    *"api.ipify.org"*)           echo "1.2.3.4" ;;
    *"registry.hub.docker.com"*) printf '{"results":[{"name":"1.108.0"},{"name":"1.107.2"},{"name":"latest"}]}\n' ;;
    *)                           echo "1.2.3.4" ;;
esac
EOF
    chmod +x "$STUB_BIN/curl"

    # dig stub
    cat > "$STUB_BIN/dig" <<'EOF'
#!/bin/bash
echo "1.2.3.4"
EOF
    chmod +x "$STUB_BIN/dig"

    # htpasswd stub
    cat > "$STUB_BIN/htpasswd" <<'EOF'
#!/bin/bash
echo "admin:\$2y\$12\$FakeHashForTestingOnlyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
exit 0
EOF
    chmod +x "$STUB_BIN/htpasswd"

    # rsync stub (respects RSYNC_STUB_CHANGED env var)
    # Detects dry-run via --dry-run OR any short-flag group containing 'n'
    # (e.g. -n, -rtun, -rtn) — is_changed_since_snapshot uses -rtun.
    cat > "$STUB_BIN/rsync" <<'EOF'
#!/bin/bash
is_dry=false
for a in "$@"; do
    case "$a" in
        --dry-run) is_dry=true; break ;;
        -[a-zA-Z]*) [[ "$a" =~ ^-[a-zA-Z]*n[a-zA-Z]*$ ]] && is_dry=true && break ;;
    esac
done
if $is_dry; then
    if [[ "${RSYNC_STUB_CHANGED:-0}" == "1" ]]; then
        echo ">f...... changed_file.dat"
    fi
    exit 0
fi
exit 0
EOF
    chmod +x "$STUB_BIN/rsync"

    # jq stub — minimal subset used by n8n-toolkit
    cat > "$STUB_BIN/jq" <<'JQEOF'
#!/usr/bin/env bash
filter=""; raw_output=false; arg_key=""; arg_val=""
args=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -r)    raw_output=true; shift ;;
        --arg) arg_key="$2"; arg_val="$3"; shift 3 ;;
        -*)    shift ;;
        *)     args+=("$1"); shift ;;
    esac
done
filter="${args[0]:-}"
input="$(cat)"

if [[ "$filter" == ".results[].name" ]]; then
    echo "$input" | sed 's/},{/}\n{/g' | while IFS= read -r seg; do
        [[ "$seg" =~ \"name\":\"([^\"]+)\" ]] && echo "${BASH_REMATCH[1]}"
    done
    exit 0
fi
[[ "$filter" == *"services"*"keys"* ]]     && { echo "main"; exit 0; }
[[ "$filter" == *"volumes"*"keys"* ]]      && exit 0
[[ "$filter" == *"networks"*"keys"* ]]     && exit 0
[[ "$filter" == *"container_name"* ]]      && { echo ""; exit 0; }
[[ "$filter" == *"external"* ]]            && { echo "false"; exit 0; }
[[ "$filter" == *"services"*"image"* ]]    && { echo "n8nio/n8n:1.108.0"; exit 0; }
[[ "$filter" == '.' ]]                     && { echo "$input"; exit 0; }
exit 0
JQEOF
    chmod +x "$STUB_BIN/jq"

    # getent stub
    cat > "$STUB_BIN/getent" <<'EOF'
#!/bin/bash
case "$*" in
    *"group docker"*) echo "docker:x:999:"; exit 0 ;;
    *"ahostsv4"*)     echo "1.2.3.4   STREAM example.com" ;;
    *)                exit 0 ;;
esac
EOF
    chmod +x "$STUB_BIN/getent"

    # sha256sum stub (for environments that lack it)
    if ! command -v sha256sum &>/dev/null 2>&1; then
        cat > "$STUB_BIN/sha256sum" <<'EOF'
#!/bin/bash
for f in "$@"; do
    echo "fakehash1234567890abcdef1234567890abcdef1234567890abcdef1234567890  $f"
done
EOF
        chmod +x "$STUB_BIN/sha256sum"
    fi
}
