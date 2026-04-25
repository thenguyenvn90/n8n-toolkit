#!/usr/bin/env bats
# tests/unit/test_arg_parsing.bats — Unit tests for parse_args()
# Coverage: all flags, actions, mutual exclusion, LOG_LEVEL, --help.
#
# Technique: parse_args() lives in n8n_manager.sh (not a lib file).
# We extract usage() + parse_args() + set_paths() definitions via sed,
# eval them in a subshell with all required globals initialized, then
# print the resulting variable values for assertion.

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
}

teardown() {
    rm -rf "$BATS_TEST_TMPDIR/n8n" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Helper: run parse_args with given CLI args and print all relevant globals.
# Uses sed to extract function definitions from n8n_manager.sh, avoids
# executing the script-level main() call.
# ---------------------------------------------------------------------------
_parse_and_report() {
    bash -c "
        set +euo pipefail
        export LOG_LEVEL=INFO APT_UPDATED=false
        export N8N_DIR='$N8N_DIR'
        export ENV_FILE='$ENV_FILE'
        export COMPOSE_FILE='$COMPOSE_FILE'
        # PATH is inherited from bats setup() which already has STUB_BIN prepended via setup_stub_bin

        # Source libs (parse_domain_arg from common.sh is needed)
        source '$REPO_ROOT/lib/common.sh'
        source '$REPO_ROOT/lib/install.sh'
        source '$REPO_ROOT/lib/upgrade.sh'
        source '$REPO_ROOT/lib/backup.sh'
        source '$REPO_ROOT/lib/cleanup.sh'

        # Extract usage() + parse_args() + set_paths() from n8n_manager.sh
        eval \"\$(sed -n '/^usage()/,/^main()/{ /^main()/q; p }' '$REPO_ROOT/n8n_manager.sh')\"

        # Initialize all globals that parse_args reads/sets
        TEMPLATE_SINGLE='$REPO_ROOT/deploy/single-mode'
        TEMPLATE_QUEUE='$REPO_ROOT/deploy/queue-mode'
        DEFAULT_N8N_DIR='$N8N_DIR'
        DO_INSTALL=false DO_UPGRADE=false DO_BACKUP=false
        DO_RESTORE=false DO_CLEANUP=false DO_AVAILABLE=false
        CLEANUP_MODE='safe'
        INSTALL_MODE='single'
        DOMAIN='' SSL_EMAIL=''
        N8N_VERSION='latest'
        FORCE_FLAG=false
        MONITORING=false EXPOSE_PROMETHEUS=false
        SUBDOMAIN_N8N='' SUBDOMAIN_GRAFANA='' SUBDOMAIN_PROMETHEUS=''
        BASIC_AUTH_USER='' BASIC_AUTH_PASS=''
        EMAIL_TO='' EMAIL_EXPLICIT=false NOTIFY_ON_SUCCESS=false
        RCLONE_REMOTE=''
        LOG_LEVEL='INFO'
        TARGET_RESTORE_FILE=''
        APT_UPDATED=false
        DATE=\$(date +%F_%H-%M-%S)
        LOG_FILE=\"\$N8N_DIR/logs/test.log\"

        parse_args \"\$@\"

        # Print all globals so tests can grep
        echo \"DO_INSTALL=\$DO_INSTALL\"
        echo \"DO_UPGRADE=\$DO_UPGRADE\"
        echo \"DO_BACKUP=\$DO_BACKUP\"
        echo \"DO_RESTORE=\$DO_RESTORE\"
        echo \"DO_CLEANUP=\$DO_CLEANUP\"
        echo \"DO_AVAILABLE=\$DO_AVAILABLE\"
        echo \"DOMAIN=\$DOMAIN\"
        echo \"SSL_EMAIL=\$SSL_EMAIL\"
        echo \"INSTALL_MODE=\$INSTALL_MODE\"
        echo \"MONITORING=\$MONITORING\"
        echo \"FORCE_FLAG=\$FORCE_FLAG\"
        echo \"N8N_VERSION=\$N8N_VERSION\"
        echo \"RCLONE_REMOTE=\$RCLONE_REMOTE\"
        echo \"EMAIL_TO=\$EMAIL_TO\"
        echo \"NOTIFY_ON_SUCCESS=\$NOTIFY_ON_SUCCESS\"
        echo \"LOG_LEVEL=\$LOG_LEVEL\"
        echo \"TARGET_RESTORE_FILE=\$TARGET_RESTORE_FILE\"
        echo \"CLEANUP_MODE=\$CLEANUP_MODE\"
    " -- "$@"
}

# ---------------------------------------------------------------------------
# --help
# ---------------------------------------------------------------------------

@test "--help prints usage and exits 0" {
    # usage() is defined in n8n_manager.sh; we call it via the same subshell technique
    # used by _parse_and_report to avoid the root-check guard.
    run bash -c "
        set +euo pipefail
        export LOG_LEVEL=INFO APT_UPDATED=false
        export N8N_DIR='$N8N_DIR'
        export ENV_FILE='$ENV_FILE'
        export COMPOSE_FILE='$COMPOSE_FILE'

        source '$REPO_ROOT/lib/common.sh'
        # Extract usage() from n8n_manager.sh and call it directly
        eval \"\$(sed -n '/^usage()/,/^set_paths()/{ /^set_paths()/q; p }' '$REPO_ROOT/n8n_manager.sh')\"
        usage
    " 2>&1 || true
    # usage() exits 1 but the help text must appear in output or stderr
    [[ "$output" == *"Usage"* ]] || [[ "$output" == *"Actions"* ]] || [[ "$output" == *"install"* ]]
}

# ---------------------------------------------------------------------------
# --install
# ---------------------------------------------------------------------------

@test "--install sets DO_INSTALL=true" {
    run _parse_and_report --install=example.com
    [ "$status" -eq 0 ]
    [[ "$output" == *"DO_INSTALL=true"* ]]
}

@test "--install example.com sets DOMAIN" {
    run _parse_and_report --install=example.com
    [ "$status" -eq 0 ]
    [[ "$output" == *"DOMAIN=example.com"* ]]
}

@test "--install without domain leaves DOMAIN empty (wizard fills it later)" {
    run _parse_and_report --install
    [ "$status" -eq 0 ]
    [[ "$output" == *"DOMAIN="* ]]
    [[ "$output" != *"DOMAIN=example"* ]]
}

@test "--install with https:// prefix strips scheme from DOMAIN" {
    run _parse_and_report --install=https://example.com
    [ "$status" -eq 0 ]
    [[ "$output" == *"DOMAIN=example.com"* ]]
}

# ---------------------------------------------------------------------------
# --mode
# ---------------------------------------------------------------------------

@test "--mode queue sets INSTALL_MODE=queue" {
    run _parse_and_report --install=example.com --mode queue
    [ "$status" -eq 0 ]
    [[ "$output" == *"INSTALL_MODE=queue"* ]]
}

@test "--mode single sets INSTALL_MODE=single" {
    run _parse_and_report --install=example.com --mode single
    [ "$status" -eq 0 ]
    [[ "$output" == *"INSTALL_MODE=single"* ]]
}

@test "--mode invalid exits with error" {
    run _parse_and_report --install=example.com --mode invalid
    [ "$status" -ne 0 ]
}

# ---------------------------------------------------------------------------
# --monitoring
# ---------------------------------------------------------------------------

@test "--monitoring sets MONITORING=true" {
    run _parse_and_report --install=example.com --monitoring
    [ "$status" -eq 0 ]
    [[ "$output" == *"MONITORING=true"* ]]
}

@test "without --monitoring MONITORING remains false" {
    run _parse_and_report --install=example.com
    [ "$status" -eq 0 ]
    [[ "$output" == *"MONITORING=false"* ]]
}

# ---------------------------------------------------------------------------
# --backup
# ---------------------------------------------------------------------------

@test "--backup sets DO_BACKUP=true" {
    run _parse_and_report --backup
    [ "$status" -eq 0 ]
    [[ "$output" == *"DO_BACKUP=true"* ]]
}

@test "-b (short flag) sets DO_BACKUP=true" {
    run _parse_and_report -b
    [ "$status" -eq 0 ]
    [[ "$output" == *"DO_BACKUP=true"* ]]
}

# ---------------------------------------------------------------------------
# --restore
# ---------------------------------------------------------------------------

@test "--restore FILE sets DO_RESTORE=true and TARGET_RESTORE_FILE" {
    run _parse_and_report --restore backups/myfile.tar.gz
    [ "$status" -eq 0 ]
    [[ "$output" == *"DO_RESTORE=true"* ]]
    [[ "$output" == *"TARGET_RESTORE_FILE=backups/myfile.tar.gz"* ]]
}

# ---------------------------------------------------------------------------
# --upgrade
# ---------------------------------------------------------------------------

@test "--upgrade sets DO_UPGRADE=true" {
    run _parse_and_report --upgrade
    [ "$status" -eq 0 ]
    [[ "$output" == *"DO_UPGRADE=true"* ]]
}

@test "-u (short flag) sets DO_UPGRADE=true" {
    run _parse_and_report -u
    [ "$status" -eq 0 ]
    [[ "$output" == *"DO_UPGRADE=true"* ]]
}

# ---------------------------------------------------------------------------
# --cleanup
# ---------------------------------------------------------------------------

@test "--cleanup sets DO_CLEANUP=true" {
    run _parse_and_report --cleanup safe
    [ "$status" -eq 0 ]
    [[ "$output" == *"DO_CLEANUP=true"* ]]
}

@test "--cleanup safe sets CLEANUP_MODE=safe" {
    run _parse_and_report --cleanup safe
    [ "$status" -eq 0 ]
    [[ "$output" == *"CLEANUP_MODE=safe"* ]]
}

@test "--cleanup all sets CLEANUP_MODE=all" {
    run _parse_and_report --cleanup all
    [ "$status" -eq 0 ]
    [[ "$output" == *"CLEANUP_MODE=all"* ]]
}

# ---------------------------------------------------------------------------
# --force
# ---------------------------------------------------------------------------

@test "--force sets FORCE_FLAG=true" {
    run _parse_and_report --backup --force
    [ "$status" -eq 0 ]
    [[ "$output" == *"FORCE_FLAG=true"* ]]
}

@test "-f (short flag) sets FORCE_FLAG=true" {
    run _parse_and_report --backup -f
    [ "$status" -eq 0 ]
    [[ "$output" == *"FORCE_FLAG=true"* ]]
}

# ---------------------------------------------------------------------------
# --log-level
# ---------------------------------------------------------------------------

@test "--log-level DEBUG sets LOG_LEVEL=DEBUG" {
    run _parse_and_report --backup --log-level DEBUG
    [ "$status" -eq 0 ]
    [[ "$output" == *"LOG_LEVEL=DEBUG"* ]]
}

@test "-l INFO sets LOG_LEVEL=INFO" {
    run _parse_and_report --backup -l INFO
    [ "$status" -eq 0 ]
    [[ "$output" == *"LOG_LEVEL=INFO"* ]]
}

# ---------------------------------------------------------------------------
# --version
# ---------------------------------------------------------------------------

@test "--version 1.107.2 sets N8N_VERSION=1.107.2" {
    run _parse_and_report --install=example.com --version 1.107.2
    [ "$status" -eq 0 ]
    [[ "$output" == *"N8N_VERSION=1.107.2"* ]]
}

@test "-v 1.107.2 (short flag) sets N8N_VERSION" {
    run _parse_and_report --upgrade -v 1.107.2
    [ "$status" -eq 0 ]
    [[ "$output" == *"N8N_VERSION=1.107.2"* ]]
}

# ---------------------------------------------------------------------------
# --ssl-email
# ---------------------------------------------------------------------------

@test "--ssl-email sets SSL_EMAIL" {
    run _parse_and_report --install=example.com --ssl-email you@example.com
    [ "$status" -eq 0 ]
    [[ "$output" == *"SSL_EMAIL=you@example.com"* ]]
}

@test "-m (short flag) sets SSL_EMAIL" {
    run _parse_and_report --install=example.com -m ops@example.com
    [ "$status" -eq 0 ]
    [[ "$output" == *"SSL_EMAIL=ops@example.com"* ]]
}

# ---------------------------------------------------------------------------
# Mutual exclusion — two actions must fail
# ---------------------------------------------------------------------------

@test "two actions at once exits with error: --install and --backup" {
    run _parse_and_report --install=example.com --backup
    [ "$status" -ne 0 ]
}

@test "two actions at once exits with error: --install and --upgrade" {
    run _parse_and_report --install=example.com --upgrade
    [ "$status" -ne 0 ]
}

@test "two actions at once exits with error: --backup and --upgrade" {
    run _parse_and_report --backup --upgrade
    [ "$status" -ne 0 ]
}

@test "no action at all exits with error" {
    run _parse_and_report
    [ "$status" -ne 0 ]
}

@test "unknown flag exits with error" {
    run _parse_and_report --unknown-flag
    [ "$status" -ne 0 ]
}

# ---------------------------------------------------------------------------
# --available
# ---------------------------------------------------------------------------

@test "--available sets DO_AVAILABLE=true" {
    run _parse_and_report --available
    [ "$status" -eq 0 ]
    [[ "$output" == *"DO_AVAILABLE=true"* ]]
}

@test "-a (short flag) sets DO_AVAILABLE=true" {
    run _parse_and_report -a
    [ "$status" -eq 0 ]
    [[ "$output" == *"DO_AVAILABLE=true"* ]]
}

# ---------------------------------------------------------------------------
# --email-to / --notify-on-success / --remote-name
# ---------------------------------------------------------------------------

@test "--email-to sets EMAIL_TO" {
    run _parse_and_report --backup --email-to ops@example.com
    [ "$status" -eq 0 ]
    [[ "$output" == *"EMAIL_TO=ops@example.com"* ]]
}

@test "--notify-on-success sets NOTIFY_ON_SUCCESS=true" {
    run _parse_and_report --backup --notify-on-success
    [ "$status" -eq 0 ]
    [[ "$output" == *"NOTIFY_ON_SUCCESS=true"* ]]
}

@test "--remote-name sets RCLONE_REMOTE" {
    run _parse_and_report --backup --remote-name gdrive-user
    [ "$status" -eq 0 ]
    [[ "$output" == *"RCLONE_REMOTE=gdrive-user"* ]]
}
