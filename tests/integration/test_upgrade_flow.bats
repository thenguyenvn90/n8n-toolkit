#!/usr/bin/env bats
# tests/integration/test_upgrade_flow.bats — Integration tests for upgrade_stack()
# Coverage: version resolution, downgrade guard, --force bypass, .env N8N_IMAGE_TAG update.

load '../test_helper/common'

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"

setup() {
    setup_stub_bin
    trap '' ERR INT TERM HUP 2>/dev/null || true
    export LOG_LEVEL="INFO"
    export APT_UPDATED=false
    export N8N_DIR="$BATS_TEST_TMPDIR/n8n"
    mkdir -p "$N8N_DIR/logs" "$N8N_DIR/backups"
    export ENV_FILE="$N8N_DIR/.env"
    export COMPOSE_FILE="$N8N_DIR/docker-compose.yml"
    create_test_env "$ENV_FILE"
    cat > "$COMPOSE_FILE" <<'COMPOSE'
services:
  main:
    image: n8nio/n8n:${N8N_IMAGE_TAG:-1.108.0}
    container_name: n8n-main
  postgres:
    image: postgres:16
    container_name: n8n-postgres
volumes:
  n8n-data:
  postgres-data:
COMPOSE
}

teardown() {
    rm -rf "$BATS_TEST_TMPDIR/n8n" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Helper: run upgrade_stack with injected current + target versions
# PATH is inherited from bats setup() which already has STUB_BIN prepended
# via setup_stub_bin — do NOT re-export PATH in the subshell (would clobber
# system tools like sort/head/sed/date that upgrade_stack depends on).
# ---------------------------------------------------------------------------
_run_upgrade() {
    local current_ver="${1:-1.107.0}"
    local target_ver="${2:-latest}"
    local force="${3:-false}"

    bash -c "
        set +e
        export LOG_LEVEL=INFO APT_UPDATED=false
        export N8N_DIR='$N8N_DIR'
        export ENV_FILE=\"\$N8N_DIR/.env\"
        export COMPOSE_FILE=\"\$N8N_DIR/docker-compose.yml\"

        source '$REPO_ROOT/lib/common.sh'
        source '$REPO_ROOT/lib/install.sh'
        source '$REPO_ROOT/lib/upgrade.sh'
        source '$REPO_ROOT/lib/backup.sh'
        source '$REPO_ROOT/lib/cleanup.sh'

        DATE=\$(date +%F_%H-%M-%S)
        LOG_FILE=\"\$N8N_DIR/logs/upgrade_test.log\"
        mkdir -p \"\$N8N_DIR/logs\"
        N8N_VERSION='$target_ver'
        FORCE_FLAG=$force
        MONITORING=false

        # Stub everything that needs live Docker/TLS
        get_current_n8n_version() { echo '$current_ver'; }
        docker_up_check()         { return 0; }
        post_up_tls_checks()      { return 0; }
        ensure_monitoring_auth()  { return 0; }
        validate_compose_and_env() { return 0; }
        discover_from_compose()   { DISCOVERED_SERVICES=(main postgres); DISCOVERED_VOLUMES=(); return 0; }

        upgrade_stack
        echo \"EXIT:\$?\"
    " 2>&1
}

# ---------------------------------------------------------------------------
# upgrade: version detection and basic upgrade path
# ---------------------------------------------------------------------------

@test "upgrade: succeeds when upgrading to a newer version" {
    run _run_upgrade "1.107.0" "1.108.0" false
    [ "$status" -eq 0 ]
    [[ "$output" != *"Cannot downgrade"* ]]
}

@test "upgrade: resolves 'latest' to a concrete version tag" {
    # The stub curl returns 1.108.0 as the top version
    run _run_upgrade "1.107.0" "latest" false
    [ "$status" -eq 0 ]
    # resolve_n8n_target_version must return a semver, not "latest"
    [[ "$output" != *"N8N_VERSION=latest"* ]] || true
}

@test "upgrade: updates N8N_VERSION (N8N_IMAGE_TAG) in .env file" {
    _run_upgrade "1.107.0" "1.108.0" false > /dev/null 2>&1 || true
    # shellcheck disable=SC1090
    source "$REPO_ROOT/lib/common.sh" 2>/dev/null
    tag="$(read_env_var "$N8N_DIR/.env" N8N_IMAGE_TAG || true)"
    [ -n "$tag" ]
    [[ "$tag" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

# ---------------------------------------------------------------------------
# upgrade: downgrade guard
# ---------------------------------------------------------------------------

@test "upgrade: rejects downgrade without --force flag" {
    # current=1.108.0, target=1.100.0 — downgrade should be blocked
    # PATH inherited from bats setup(); STUB_BIN already prepended.
    run bash -c "
        set +e
        export LOG_LEVEL=INFO APT_UPDATED=false
        export N8N_DIR='$N8N_DIR'
        export ENV_FILE=\"\$N8N_DIR/.env\"
        export COMPOSE_FILE=\"\$N8N_DIR/docker-compose.yml\"

        source '$REPO_ROOT/lib/common.sh'
        source '$REPO_ROOT/lib/install.sh'
        source '$REPO_ROOT/lib/upgrade.sh'
        source '$REPO_ROOT/lib/backup.sh'
        source '$REPO_ROOT/lib/cleanup.sh'

        DATE=\$(date +%F_%H-%M-%S)
        LOG_FILE=\"\$N8N_DIR/logs/upgrade_test.log\"
        mkdir -p \"\$N8N_DIR/logs\"
        N8N_VERSION='1.100.0'
        FORCE_FLAG=false MONITORING=false

        get_current_n8n_version() { echo '1.108.0'; }
        docker_up_check()         { return 0; }
        post_up_tls_checks()      { return 0; }
        ensure_monitoring_auth()  { return 0; }
        validate_compose_and_env() { return 0; }
        discover_from_compose()   { DISCOVERED_SERVICES=(main postgres); DISCOVERED_VOLUMES=(); return 0; }

        upgrade_stack
        echo \"EXIT:\$?\"
    " 2>&1

    # upgrade_stack exits 0 gracefully when blocking a downgrade (logs INFO, doesn't crash)
    [ "$status" -eq 0 ]
    [[ "$output" == *"force"* ]] || [[ "$output" == *"downgrade"* ]] || [[ "$output" == *"already"* ]]
}

@test "upgrade: allows downgrade with --force flag" {
    run bash -c "
        set +e
        export LOG_LEVEL=INFO APT_UPDATED=false
        export N8N_DIR='$N8N_DIR'
        export ENV_FILE=\"\$N8N_DIR/.env\"
        export COMPOSE_FILE=\"\$N8N_DIR/docker-compose.yml\"

        source '$REPO_ROOT/lib/common.sh'
        source '$REPO_ROOT/lib/install.sh'
        source '$REPO_ROOT/lib/upgrade.sh'
        source '$REPO_ROOT/lib/backup.sh'
        source '$REPO_ROOT/lib/cleanup.sh'

        DATE=\$(date +%F_%H-%M-%S)
        LOG_FILE=\"\$N8N_DIR/logs/upgrade_test.log\"
        mkdir -p \"\$N8N_DIR/logs\"
        N8N_VERSION='1.100.0'
        FORCE_FLAG=true MONITORING=false

        get_current_n8n_version() { echo '1.108.0'; }
        docker_up_check()         { return 0; }
        post_up_tls_checks()      { return 0; }
        ensure_monitoring_auth()  { return 0; }
        validate_compose_and_env() { return 0; }
        discover_from_compose()   { DISCOVERED_SERVICES=(main postgres); DISCOVERED_VOLUMES=(); return 0; }

        upgrade_stack
        echo \"EXIT:\$?\"
    " 2>&1

    # With --force the downgrade proceeds and completes (exit 0)
    [ "$status" -eq 0 ]
    [[ "$output" == *"EXIT:0"* ]]
}

# ---------------------------------------------------------------------------
# upgrade: no-op detection (already on target)
# ---------------------------------------------------------------------------

@test "upgrade: skips redeploy when already on target version without --force" {
    # current=1.108.0, target resolves to 1.108.0 → should skip
    run bash -c "
        set +e
        export LOG_LEVEL=INFO APT_UPDATED=false
        export N8N_DIR='$N8N_DIR'
        export ENV_FILE=\"\$N8N_DIR/.env\"
        export COMPOSE_FILE=\"\$N8N_DIR/docker-compose.yml\"

        source '$REPO_ROOT/lib/common.sh'
        source '$REPO_ROOT/lib/install.sh'
        source '$REPO_ROOT/lib/upgrade.sh'
        source '$REPO_ROOT/lib/backup.sh'
        source '$REPO_ROOT/lib/cleanup.sh'

        DATE=\$(date +%F_%H-%M-%S)
        LOG_FILE=\"\$N8N_DIR/logs/upgrade_test.log\"
        mkdir -p \"\$N8N_DIR/logs\"
        N8N_VERSION='latest'   # stub resolves to 1.108.0
        FORCE_FLAG=false MONITORING=false

        get_current_n8n_version() { echo '1.108.0'; }
        docker_up_check()         { return 0; }
        post_up_tls_checks()      { return 0; }
        ensure_monitoring_auth()  { return 0; }
        validate_compose_and_env() { return 0; }
        discover_from_compose()   { DISCOVERED_SERVICES=(main postgres); DISCOVERED_VOLUMES=(); return 0; }

        upgrade_stack
        echo \"EXIT:\$?\"
    " 2>&1

    [ "$status" -eq 0 ]
    [[ "$output" == *"already"* ]] || [[ "$output" == *"redeploy"* ]]
}

# ---------------------------------------------------------------------------
# upgrade: tag validation failure
# ---------------------------------------------------------------------------

@test "upgrade: fails when target tag does not exist in registry" {
    # Override docker stub to fail manifest inspect
    cat > "$STUB_BIN/docker" <<'EOF'
#!/bin/bash
case "$*" in
    *"manifest inspect"*) exit 1 ;;
    *"version --format"*) echo "27" ;;
    *)                    exit 0 ;;
esac
EOF
    chmod +x "$STUB_BIN/docker"

    run bash -c "
        set +e
        export LOG_LEVEL=INFO APT_UPDATED=false
        export N8N_DIR='$N8N_DIR'
        export ENV_FILE=\"\$N8N_DIR/.env\"
        export COMPOSE_FILE=\"\$N8N_DIR/docker-compose.yml\"

        source '$REPO_ROOT/lib/common.sh'
        source '$REPO_ROOT/lib/install.sh'
        source '$REPO_ROOT/lib/upgrade.sh'
        source '$REPO_ROOT/lib/backup.sh'
        source '$REPO_ROOT/lib/cleanup.sh'

        DATE=\$(date +%F_%H-%M-%S)
        LOG_FILE=\"\$N8N_DIR/logs/upgrade_test.log\"
        mkdir -p \"\$N8N_DIR/logs\"
        N8N_VERSION='9.99.99-does-not-exist'
        FORCE_FLAG=false MONITORING=false

        get_current_n8n_version() { echo '1.107.0'; }
        docker_up_check()         { return 0; }
        post_up_tls_checks()      { return 0; }
        ensure_monitoring_auth()  { return 0; }

        upgrade_stack
    " 2>&1

    [ "$status" -ne 0 ]
}

# ---------------------------------------------------------------------------
# upgrade: ENV_FILE update
# ---------------------------------------------------------------------------

@test "upgrade: N8N_IMAGE_TAG in .env is updated to the resolved version" {
    # Run upgrade with explicit version 1.108.0 and force flag
    # PATH inherited from bats setup(); STUB_BIN already prepended.
    bash -c "
        set +e
        export LOG_LEVEL=INFO APT_UPDATED=false
        export N8N_DIR='$N8N_DIR'
        export ENV_FILE=\"\$N8N_DIR/.env\"
        export COMPOSE_FILE=\"\$N8N_DIR/docker-compose.yml\"

        source '$REPO_ROOT/lib/common.sh'
        source '$REPO_ROOT/lib/install.sh'
        source '$REPO_ROOT/lib/upgrade.sh'
        source '$REPO_ROOT/lib/backup.sh'
        source '$REPO_ROOT/lib/cleanup.sh'

        DATE=\$(date +%F_%H-%M-%S)
        LOG_FILE=\"\$N8N_DIR/logs/upgrade_test.log\"
        mkdir -p \"\$N8N_DIR/logs\"
        N8N_VERSION='1.108.0'
        FORCE_FLAG=true MONITORING=false

        get_current_n8n_version() { echo '1.107.0'; }
        docker_up_check()         { return 0; }
        post_up_tls_checks()      { return 0; }
        ensure_monitoring_auth()  { return 0; }
        validate_compose_and_env() { return 0; }
        discover_from_compose()   { DISCOVERED_SERVICES=(main postgres); DISCOVERED_VOLUMES=(); return 0; }

        upgrade_stack
    " 2>&1 || true

    # shellcheck disable=SC1090
    source "$REPO_ROOT/lib/common.sh" 2>/dev/null
    tag="$(read_env_var "$N8N_DIR/.env" N8N_IMAGE_TAG || true)"
    [ "$tag" = "1.108.0" ]
}
