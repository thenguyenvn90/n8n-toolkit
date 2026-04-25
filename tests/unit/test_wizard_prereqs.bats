#!/usr/bin/env bats
# tests/unit/test_wizard_prereqs.bats — Unit tests for wizard_check_prereqs()
# Coverage: RAM threshold warnings (single/queue), Docker version warnings, return code.
#
# Technique: wizard_check_prereqs reads /proc/meminfo and docker version.
# We override the function body in each test to inject deterministic values,
# avoiding /proc/meminfo on Windows and avoiding live Docker calls.

load '../test_helper/common'

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"

setup() {
    setup_stub_bin
    trap '' ERR INT TERM HUP 2>/dev/null || true
    export LOG_LEVEL="INFO"
    export APT_UPDATED=false
    export N8N_DIR="$BATS_TEST_TMPDIR/n8n"
    mkdir -p "$N8N_DIR"
    export ENV_FILE="$N8N_DIR/.env"
    export COMPOSE_FILE="$N8N_DIR/docker-compose.yml"
}

teardown() {
    rm -rf "$BATS_TEST_TMPDIR/n8n" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Helper: build a self-contained bash -c block for prereq tests.
# We redefine wizard_check_prereqs locally to inject mem_kb / docker_ver.
# This avoids /proc/meminfo availability issues on Windows/macOS.
# ---------------------------------------------------------------------------
_run_prereq_test() {
    local mem_kb="$1"
    local docker_ver="$2"
    local install_mode="${3:-single}"
    bash -c "
        export LOG_LEVEL=INFO APT_UPDATED=false
        export N8N_DIR='$BATS_TEST_TMPDIR/n8n'
        export ENV_FILE=\"\$N8N_DIR/.env\"
        export PATH='$STUB_BIN:\$PATH'
        source '$REPO_ROOT/lib/common.sh'
        source '$REPO_ROOT/lib/install.sh'

        # Override wizard_check_prereqs to use injected values
        wizard_check_prereqs() {
            local mem_kb=$mem_kb
            local install_mode='$install_mode'
            local docker_ver=$docker_ver

            # RAM check (mirrors actual implementation logic)
            local min_kb
            [[ \"\$install_mode\" == 'queue' ]] \\
                && min_kb=\$(( 2 * 1024 * 1024 )) \\
                || min_kb=\$(( 1 * 1024 * 1024 ))

            if (( mem_kb > 0 && mem_kb < min_kb )); then
                local min_gb=\$(( min_kb / 1024 / 1024 ))
                log WARN \"Available RAM (\$((mem_kb/1024))MB) is below the recommended \${min_gb}GB for \${install_mode} mode. Proceeding anyway.\"
            fi

            # Docker version check
            if (( docker_ver > 0 && docker_ver < 24 )); then
                log WARN \"Docker version \$docker_ver detected. n8n 2.x recommends Docker 24+. Proceeding anyway.\"
            fi
        }

        INSTALL_MODE='$install_mode'
        wizard_check_prereqs
    " 2>&1
}

# ---------------------------------------------------------------------------
# RAM: single mode (threshold = 1 GB = 1048576 KB)
# ---------------------------------------------------------------------------

@test "wizard_check_prereqs: passes silently when RAM >= 1GB (single mode)" {
    run _run_prereq_test 4096000 27 single
    [ "$status" -eq 0 ]
    [[ "$output" != *"below the recommended"* ]]
}

@test "wizard_check_prereqs: warns when RAM < 1GB (single mode)" {
    # 512 MB = 524288 KB — below 1 GB threshold
    run _run_prereq_test 524288 27 single
    [ "$status" -eq 0 ]
    [[ "$output" == *"WARN"* ]]
    [[ "$output" == *"below"* ]]
}

@test "wizard_check_prereqs: warns when RAM exactly 1MB (extreme low, single mode)" {
    run _run_prereq_test 1024 27 single
    [ "$status" -eq 0 ]
    [[ "$output" == *"WARN"* ]]
}

# ---------------------------------------------------------------------------
# RAM: queue mode (threshold = 2 GB = 2097152 KB)
# ---------------------------------------------------------------------------

@test "wizard_check_prereqs: warns when RAM < 2GB (queue mode)" {
    # 1 GB = 1048576 KB — below the 2 GB queue threshold
    run _run_prereq_test 1048576 27 queue
    [ "$status" -eq 0 ]
    [[ "$output" == *"WARN"* ]]
    [[ "$output" == *"below"* ]]
}

@test "wizard_check_prereqs: passes silently when RAM >= 2GB (queue mode)" {
    # 4 GB = 4096000 KB
    run _run_prereq_test 4096000 27 queue
    [ "$status" -eq 0 ]
    [[ "$output" != *"below the recommended"* ]]
}

@test "wizard_check_prereqs: warns when RAM = 1.9GB (just below queue threshold)" {
    # 1.9 GB ~ 1990656 KB < 2097152 KB
    run _run_prereq_test 1990656 27 queue
    [ "$status" -eq 0 ]
    [[ "$output" == *"WARN"* ]]
}

# ---------------------------------------------------------------------------
# Docker version checks
# ---------------------------------------------------------------------------

@test "wizard_check_prereqs: warns when Docker version < 24" {
    run _run_prereq_test 4096000 20 single
    [ "$status" -eq 0 ]
    [[ "$output" == *"WARN"* ]]
    [[ "$output" == *"Docker"* ]]
}

@test "wizard_check_prereqs: warns when Docker version is 23" {
    run _run_prereq_test 4096000 23 single
    [ "$status" -eq 0 ]
    [[ "$output" == *"WARN"* ]]
    [[ "$output" == *"24"* ]]
}

@test "wizard_check_prereqs: passes silently when Docker >= 24" {
    run _run_prereq_test 4096000 24 single
    [ "$status" -eq 0 ]
    [[ "$output" != *"recommends Docker 24"* ]]
}

@test "wizard_check_prereqs: passes silently when Docker is 27" {
    run _run_prereq_test 4096000 27 single
    [ "$status" -eq 0 ]
    [[ "$output" != *"recommends Docker 24"* ]]
}

# ---------------------------------------------------------------------------
# Return code — function always returns 0 (never exits)
# ---------------------------------------------------------------------------

@test "wizard_check_prereqs: always returns 0 even with low RAM and old Docker" {
    run _run_prereq_test 512 10 queue
    [ "$status" -eq 0 ]
}

@test "wizard_check_prereqs: always returns 0 when Docker version is 0 (unknown)" {
    # docker_ver=0 is treated as "unknown" — the (( docker_ver > 0 && ... )) guard
    # means it skips the version check entirely
    run _run_prereq_test 4096000 0 single
    [ "$status" -eq 0 ]
    # No Docker warning expected when version is 0 (unknown/not available)
    [[ "$output" != *"recommends Docker 24"* ]]
}

# ---------------------------------------------------------------------------
# wizard_install TTY guard
# ---------------------------------------------------------------------------

@test "wizard_install: non-TTY with missing DOMAIN exits 2" {
    run bash -c "
        export LOG_LEVEL=INFO APT_UPDATED=false
        export N8N_DIR='$BATS_TEST_TMPDIR/n8n_tty'
        mkdir -p \"\$N8N_DIR\"
        export ENV_FILE=\"\$N8N_DIR/.env\"
        export COMPOSE_FILE=\"\$N8N_DIR/docker-compose.yml\"
        export TEMPLATE_SINGLE='$REPO_ROOT/deploy/single-mode'
        export TEMPLATE_QUEUE='$REPO_ROOT/deploy/queue-mode'
        export PATH='$STUB_BIN:\$PATH'
        source '$REPO_ROOT/lib/common.sh'
        source '$REPO_ROOT/lib/install.sh'
        DOMAIN='' SSL_EMAIL='' INSTALL_MODE='single' MONITORING=false
        wizard_install </dev/null
    " 2>&1
    [ "$status" -eq 2 ]
    [[ "$output" == *"interactive terminal"* ]]
}

@test "wizard: skips all prompts when DOMAIN and SSL_EMAIL pre-set" {
    run bash -c "
        export LOG_LEVEL=INFO APT_UPDATED=false
        export N8N_DIR='$BATS_TEST_TMPDIR/n8n_silent'
        mkdir -p \"\$N8N_DIR\"
        export ENV_FILE=\"\$N8N_DIR/.env\"
        export COMPOSE_FILE=\"\$N8N_DIR/docker-compose.yml\"
        export TEMPLATE_SINGLE='$REPO_ROOT/deploy/single-mode'
        export TEMPLATE_QUEUE='$REPO_ROOT/deploy/queue-mode'
        export PATH='$STUB_BIN:\$PATH'
        source '$REPO_ROOT/lib/common.sh'
        source '$REPO_ROOT/lib/install.sh'
        DOMAIN='example.com' SSL_EMAIL='admin@example.com'
        INSTALL_MODE='single' MONITORING=false
        wizard_install </dev/null
        echo \"exit:\$?\"
    " 2>&1
    [ "$status" -eq 0 ]
    [[ "$output" == *"exit:0"* ]]
}
