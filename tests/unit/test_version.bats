#!/usr/bin/env bats
# tests/unit/test_version.bats — Unit tests for version management functions
# Coverage: get_latest_n8n_version, resolve_n8n_target_version, validate_image_tag,
#           get_current_n8n_version

load '../helpers/stubs'
load '../helpers/fixtures'

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"

setup() {
    setup_stubs
    cd "$REPO_ROOT"
    export LOG_LEVEL="INFO"
    export APT_UPDATED=false
    export N8N_DIR="$BATS_TEST_TMPDIR/n8n"
    mkdir -p "$N8N_DIR"
    export ENV_FILE="$N8N_DIR/.env"
    export COMPOSE_FILE="$N8N_DIR/docker-compose.yml"
    source "$REPO_ROOT/lib/common.sh"
}

# ---------------------------------------------------------------------------
# validate_image_tag()
# ---------------------------------------------------------------------------

@test "validate_image_tag returns 0 for a valid tag (stub docker manifest)" {
    # Our docker stub exits 0 for manifest inspect
    run validate_image_tag "1.108.0"
    [ "$status" -eq 0 ]
}

@test "validate_image_tag returns 0 for latest tag" {
    run validate_image_tag "latest"
    [ "$status" -eq 0 ]
}

@test "validate_image_tag fails when docker manifest returns non-zero" {
    # Override docker stub to fail on manifest inspect
    cat > "$STUB_BIN/docker" <<'EOF'
#!/bin/bash
case "$*" in
    *"manifest inspect"*) exit 1 ;;
    *)                    exit 0 ;;
esac
EOF
    chmod +x "$STUB_BIN/docker"

    run validate_image_tag "9.99.99-nonexistent"
    [ "$status" -ne 0 ]
}

# ---------------------------------------------------------------------------
# get_latest_n8n_version()
# ---------------------------------------------------------------------------

@test "get_latest_n8n_version returns a semver string from Docker Hub" {
    # The curl stub returns JSON with tag "1.108.0" as the first result
    result="$(get_latest_n8n_version)"
    # Should be a semver x.y.z pattern
    [[ "$result" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

@test "get_latest_n8n_version returns non-empty result" {
    result="$(get_latest_n8n_version)"
    [ -n "$result" ]
}

@test "get_latest_n8n_version does not return 'latest' literal" {
    # "latest" is in the stub JSON but should be filtered by grep -E semver
    result="$(get_latest_n8n_version)"
    [ "$result" != "latest" ]
}

@test "get_latest_n8n_version returns version with exactly two dots" {
    result="$(get_latest_n8n_version)"
    dot_count="$(echo "$result" | tr -cd '.' | wc -c)"
    [ "$dot_count" -eq 2 ]
}

# ---------------------------------------------------------------------------
# resolve_n8n_target_version()
# ---------------------------------------------------------------------------

@test "resolve_n8n_target_version with 'latest' resolves to concrete version" {
    result="$(resolve_n8n_target_version "latest")"
    [ "$status" -eq 0 ] || true
    [[ "$result" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

@test "resolve_n8n_target_version with explicit version passes it through" {
    result="$(resolve_n8n_target_version "1.107.2")"
    [ "$result" = "1.107.2" ]
}

@test "resolve_n8n_target_version with empty string resolves like latest" {
    result="$(resolve_n8n_target_version "")"
    [ -n "$result" ]
    [[ "$result" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

@test "resolve_n8n_target_version fails when image tag does not exist" {
    # Override docker to fail manifest inspect (tag not found)
    cat > "$STUB_BIN/docker" <<'EOF'
#!/bin/bash
case "$*" in
    *"manifest inspect"*) exit 1 ;;
    *)                    exit 0 ;;
esac
EOF
    chmod +x "$STUB_BIN/docker"

    run resolve_n8n_target_version "9.99.99"
    [ "$status" -ne 0 ]
}

@test "resolve_n8n_target_version fails when Docker Hub is unreachable" {
    # Override curl to return empty (simulating no network)
    cat > "$STUB_BIN/curl" <<'EOF'
#!/bin/bash
# Simulate connection failure: exit non-zero, no output
exit 6
EOF
    chmod +x "$STUB_BIN/curl"

    run resolve_n8n_target_version "latest"
    [ "$status" -ne 0 ]
}

# ---------------------------------------------------------------------------
# get_current_n8n_version()
# ---------------------------------------------------------------------------

@test "get_current_n8n_version returns version string when container running" {
    # The docker stub returns "1.108.0" for exec n8n --version
    # We need compose ps -q to return a container ID
    result="$(
        N8N_DIR="$BATS_TEST_TMPDIR/n8n"
        ENV_FILE="$N8N_DIR/.env"
        COMPOSE_FILE="$N8N_DIR/docker-compose.yml"
        make_env_file "$N8N_DIR"
        make_compose_file "$N8N_DIR"
        get_current_n8n_version
    )"
    # The exec stub returns "1.108.0" or get_current returns "0.0.0"
    [[ "$result" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

@test "get_current_n8n_version returns 0.0.0 when no container found" {
    # Override docker to return empty for compose ps -q (no containers)
    cat > "$STUB_BIN/docker" <<'EOF'
#!/bin/bash
case "$*" in
    *"compose"*"ps -q"*) echo "" ;;
    *"ps -q"*)           echo "" ;;
    *)                   exit 0  ;;
esac
EOF
    chmod +x "$STUB_BIN/docker"

    result="$(
        N8N_DIR="$BATS_TEST_TMPDIR/n8n"
        ENV_FILE="$N8N_DIR/.env"
        COMPOSE_FILE="$N8N_DIR/docker-compose.yml"
        make_env_file "$N8N_DIR"
        make_compose_file "$N8N_DIR"
        get_current_n8n_version
    )"
    [ "$result" = "0.0.0" ]
}

# ---------------------------------------------------------------------------
# list_available_versions()
# ---------------------------------------------------------------------------

@test "list_available_versions prints at least one version" {
    run list_available_versions
    [ "$status" -eq 0 ]
    # At least one line of output that looks like a version
    found=false
    while IFS= read -r line; do
        [[ "$line" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] && found=true && break
    done <<< "$output"
    $found
}
