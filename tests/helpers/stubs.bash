#!/usr/bin/env bash
# tests/helpers/stubs.bash — Reusable command stubs for bats tests
# Provides setup_stubs() which overrides PATH to use stub binaries.

setup_stubs() {
    export STUB_BIN="$BATS_TEST_TMPDIR/bin"
    mkdir -p "$STUB_BIN"
    export PATH="$STUB_BIN:$PATH"

    # ---- docker stub ----
    cat > "$STUB_BIN/docker" <<'EOF'
#!/bin/bash
# Minimal docker stub — matches by substring of the full argument string

args="$*"

case "$args" in
    *"version --format"*)
        echo "27"
        ;;
    *"manifest inspect"*)
        # Always succeed — tag exists
        exit 0
        ;;
    *"compose"*"config --format json"*)
        # Return minimal compose JSON so discover_from_compose can parse it
        echo '{"services":{"main":{"container_name":"n8n-main"}},"volumes":{},"networks":{}}'
        ;;
    *"compose"*"config --services"*)
        echo "main"
        ;;
    *"compose"*"config --volumes"*)
        echo ""
        ;;
    *"compose"*"config"*)
        exit 0
        ;;
    *"compose"*"up"*)
        exit 0
        ;;
    *"compose"*"down"*)
        exit 0
        ;;
    *"compose"*"pull"*)
        exit 0
        ;;
    *"compose"*"ps -q"*)
        # Return a fake container ID
        echo "abc123def456"
        ;;
    *"compose"*"ps --format"*)
        echo "n8n-main   Up"
        ;;
    *"compose"*"ps"*)
        printf 'NAME\t\tIMAGE\t\tSTATUS\n'
        printf 'n8n-main\tn8nio/n8n\tUp\n'
        ;;
    *"ps -q"*)
        echo "abc123def456"
        ;;
    *"ps"*)
        echo "CONTAINER ID   NAME"
        ;;
    *"inspect"*"--format"*"State"*)
        # Health check inspection
        echo "abc123def456|/n8n-main|running|none"
        ;;
    *"inspect"*"--format"*"Name"*)
        echo "/n8n-main"
        ;;
    *"inspect"*"--format"*"Env"*)
        echo "EXECUTIONS_MODE=regular"
        ;;
    *"inspect"*"--format"*"Mountpoint"*)
        echo "/var/lib/docker/volumes/n8n_data/_data"
        ;;
    *"inspect"*)
        echo '[]'
        ;;
    *"volume inspect"*)
        exit 0
        ;;
    *"volume create"*)
        exit 0
        ;;
    *"volume ls"*)
        echo ""
        ;;
    *"network ls"*)
        echo ""
        ;;
    *"network inspect"*)
        exit 1
        ;;
    *"network rm"*)
        exit 0
        ;;
    *"exec"*"n8n --version"*)
        echo "1.108.0"
        ;;
    *"exec"*"pg_isready"*)
        exit 0
        ;;
    *"exec"*"pg_dump"*)
        echo "-- PostgreSQL dump"
        exit 0
        ;;
    *"exec"*)
        exit 0
        ;;
    *"run"*"--rm"*"alpine"*)
        exit 0
        ;;
    *"run"*"--rm"*)
        exit 0
        ;;
    *"logs"*)
        echo "[fake-log] container started"
        ;;
    *"--version"*)
        echo "Docker version 27.0.0, build abc1234"
        ;;
    *)
        exit 0
        ;;
esac
EOF
    chmod +x "$STUB_BIN/docker"

    # ---- openssl stub ----
    cat > "$STUB_BIN/openssl" <<'EOF'
#!/bin/bash
args="$*"
case "$args" in
    *"rand"*"-base64"*"32"*)
        echo "dGVzdFNlY3JldEtleUZvcjMyQnl0ZXNMT05HRU5PVUdI"
        ;;
    *"rand"*"-base64"*"16"*)
        echo "dGVzdHNlY3JldDEyMzQ1Ng=="
        ;;
    *"rand"*"-base64"*)
        echo "dGVzdHNlY3JldA=="
        ;;
    *"s_client"*)
        printf 'subject=CN=test.example.com\n'
        printf 'issuer=CN=Let'"'"'s Encrypt Authority X3\n'
        printf 'notBefore=Jan  1 00:00:00 2025 GMT\n'
        printf 'notAfter=Apr  1 00:00:00 2025 GMT\n'
        exit 0
        ;;
    *"x509"*)
        printf 'subject=CN=test.example.com\n'
        printf 'issuer=CN=Let'"'"'s Encrypt Authority X3\n'
        printf 'notBefore=Jan  1 00:00:00 2025 GMT\n'
        printf 'notAfter=Apr  1 00:00:00 2025 GMT\n'
        exit 0
        ;;
    *)
        exit 0
        ;;
esac
EOF
    chmod +x "$STUB_BIN/openssl"

    # ---- curl stub ----
    cat > "$STUB_BIN/curl" <<'EOF'
#!/bin/bash
# Return fake public IP by default; also simulate Docker Hub API response
args="$*"
case "$args" in
    *"api.ipify.org"*)
        echo "1.2.3.4"
        ;;
    *"registry.hub.docker.com"*)
        # Return JSON with one stable tag
        printf '{"results":[{"name":"1.108.0"},{"name":"1.107.2"},{"name":"latest"}]}\n'
        ;;
    *"-sSI"*"https://"*)
        # TLS probe — return success headers with http/ssl info
        printf 'HTTP/2 200 \r\nContent-Type: text/html\r\n\r\n'
        printf 'http=200 ssl=0'
        ;;
    *"-ks"*)
        exit 0
        ;;
    *)
        echo "1.2.3.4"
        ;;
esac
EOF
    chmod +x "$STUB_BIN/curl"

    # ---- dig stub ----
    cat > "$STUB_BIN/dig" <<'EOF'
#!/bin/bash
echo "1.2.3.4"
EOF
    chmod +x "$STUB_BIN/dig"

    # ---- wget stub ----
    cat > "$STUB_BIN/wget" <<'EOF'
#!/bin/bash
exit 0
EOF
    chmod +x "$STUB_BIN/wget"

    # ---- pg_dump stub ----
    cat > "$STUB_BIN/pg_dump" <<'EOF'
#!/bin/bash
echo "-- PostgreSQL dump"
exit 0
EOF
    chmod +x "$STUB_BIN/pg_dump"

    # ---- htpasswd stub ----
    cat > "$STUB_BIN/htpasswd" <<'EOF'
#!/bin/bash
# apache2-utils htpasswd stub
USER="${@: -2:1}"
echo "${USER}:\$2y\$12\$abcdefghijklmnopqrstuuFakeHashValueForTestingOnlyXXXXXX"
exit 0
EOF
    chmod +x "$STUB_BIN/htpasswd"

    # ---- rsync stub ----
    cat > "$STUB_BIN/rsync" <<'EOF'
#!/bin/bash
# rsync stub — dry-run returns empty (no changes) by default
# Tests that need "changed" behavior override RSYNC_STUB_CHANGED
args="$*"
case "$args" in
    *"--dry-run"*|*"-n"*)
        if [[ "${RSYNC_STUB_CHANGED:-0}" == "1" ]]; then
            echo ">f...... somefile.dat"
        fi
        exit 0
        ;;
    *)
        exit 0
        ;;
esac
EOF
    chmod +x "$STUB_BIN/rsync"

    # ---- jq stub ----
    # Always install to ensure consistent behavior in test environments where jq may not be available.
    # Implements the subset of jq operations used by this codebase.
    cat > "$STUB_BIN/jq" <<'JQEOF'
#!/usr/bin/env bash
# Minimal jq stub — handles the specific jq operations used by n8n-toolkit.
# Reads stdin and simulates jq output for known patterns.

filter=""
raw_output=false
arg_key=""
arg_val=""

# Parse flags
args=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -r)   raw_output=true; shift ;;
        --arg) arg_key="$2"; arg_val="$3"; shift 3 ;;
        -*)   shift ;;   # ignore unknown flags
        *)    args+=("$1"); shift ;;
    esac
done

filter="${args[0]:-}"

# Read stdin
input="$(cat)"

# Pattern: .results[].name  → extract Docker Hub tag names
if [[ "$filter" == ".results[].name" ]]; then
    # Use sed to extract all "name":"value" pairs from the JSON (handles single-line JSON)
    echo "$input" | sed 's/},{/}\n{/g' | while IFS= read -r segment; do
        if [[ "$segment" =~ \"name\":\"([^\"]+)\" ]]; then
            echo "${BASH_REMATCH[1]}"
        fi
    done
    exit 0
fi

# Pattern: .services | keys[]  and  .volumes | ... → for discover_from_compose
if [[ "$filter" == *"services"*"keys"* ]]; then
    echo "main"
    exit 0
fi

if [[ "$filter" == *"volumes"*"keys"* ]]; then
    exit 0
fi

if [[ "$filter" == *"networks"*"keys"* ]]; then
    exit 0
fi

# Pattern: .services[$s].container_name  → for container name discovery
if [[ "$filter" == *"container_name"* ]]; then
    echo ""
    exit 0
fi

# Pattern: .volumes[$v].external  → external volume check
if [[ "$filter" == *"external"* ]]; then
    echo "false"
    exit 0
fi

# Pattern: .networks[$n].external  → external network check
if [[ "$filter" == *"networks"* && "$filter" == *"external"* ]]; then
    echo "false"
    exit 0
fi

# Pattern: .networks[$n].name  → network name
if [[ "$filter" == *"networks"* && "$filter" == *"name"* ]]; then
    echo ""
    exit 0
fi

# Pattern used in discover_from_compose for full JSON parse — return empty
# This covers: 'compose config --format json' parsing
if [[ "$filter" == '.' ]]; then
    echo "$input"
    exit 0
fi

# Default: exit 0 silently (non-fatal stub for unknown patterns)
exit 0
JQEOF
    chmod +x "$STUB_BIN/jq"

    # ---- getent stub ----
    cat > "$STUB_BIN/getent" <<'EOF'
#!/bin/bash
args="$*"
case "$args" in
    *"group docker"*)
        echo "docker:x:999:"
        exit 0
        ;;
    *"ahostsv4"*)
        echo "1.2.3.4   STREAM example.com"
        ;;
    *)
        exit 0
        ;;
esac
EOF
    chmod +x "$STUB_BIN/getent"

    # ---- rclone stub ----
    cat > "$STUB_BIN/rclone" <<'EOF'
#!/bin/bash
exit 0
EOF
    chmod +x "$STUB_BIN/rclone"

    # ---- tar stub ----
    # Only stub if real tar might not handle our test paths well
    # We do NOT override tar — it must work for fixture creation.
    # Integration tests that need tar for backup use a real tempdir.

    # ---- sha256sum stub (for Windows git-bash environments) ----
    if ! command -v sha256sum &>/dev/null 2>&1; then
        cat > "$STUB_BIN/sha256sum" <<'EOF'
#!/bin/bash
for f in "$@"; do
    echo "fakehashvalue1234567890abcdef1234567890abcdef1234567890abcdef  $f"
done
EOF
        chmod +x "$STUB_BIN/sha256sum"
    fi
}

# Helper: inject a fake /proc/meminfo with given KB value for testing wizard_check_prereqs
setup_mock_meminfo() {
    local mem_kb="${1:-4096000}"
    export MOCK_PROC_MEMINFO_KB="$mem_kb"
}
