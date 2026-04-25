#!/usr/bin/env bats
# tests/integration/test_install_cli.bats — CLI argument parsing scenarios
# Tests parse_args() behavior: flags, mutual exclusion, domain parsing.

load '../helpers/stubs'
load '../helpers/fixtures'

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"

setup() {
    setup_stubs
    cd "$REPO_ROOT"
    export LOG_LEVEL="INFO"
    export APT_UPDATED=false
    export N8N_DIR="$BATS_TEST_TMPDIR/n8n"
    mkdir -p "$N8N_DIR/logs" "$N8N_DIR/backups"
    export ENV_FILE="$N8N_DIR/.env"
    export COMPOSE_FILE="$N8N_DIR/docker-compose.yml"
}

# Helper to run parse_args in isolation and print resulting globals.
# parse_args() is defined in n8n_manager.sh (not in any lib/ file).
# Strategy: extract parse_args + usage + set_paths definitions by sourcing
# libs first, then loading ONLY the function definitions from n8n_manager.sh
# using a sed-extract approach — avoiding executing the script-level code.
_parse_and_report() {
    bash -c "
        set +euo
        export LOG_LEVEL=INFO APT_UPDATED=false
        export N8N_DIR='$N8N_DIR'
        export ENV_FILE='$ENV_FILE'
        export COMPOSE_FILE='$COMPOSE_FILE'
        # PATH is inherited from bats setup() which already has STUB_BIN prepended

        # Source lib files (parse_args depends on parse_domain_arg from common.sh)
        source '$REPO_ROOT/lib/common.sh'
        source '$REPO_ROOT/lib/install.sh'
        source '$REPO_ROOT/lib/upgrade.sh'
        source '$REPO_ROOT/lib/backup.sh'
        source '$REPO_ROOT/lib/cleanup.sh'

        # Extract function definitions from n8n_manager.sh using sed:
        # Grab lines from 'usage()' through end of 'parse_args()' block,
        # stopping before 'main()'.
        # We eval the extracted functions to define them in this shell.
        eval \"\$(sed -n '/^usage()/,/^main()/{ /^main()/q; p }' '$REPO_ROOT/n8n_manager.sh')\"

        # Initialize all required globals
        TEMPLATE_SINGLE='$REPO_ROOT/deploy/single-mode'
        TEMPLATE_QUEUE='$REPO_ROOT/deploy/queue-mode'
        DEFAULT_N8N_DIR='$N8N_DIR'
        DO_INSTALL=false DO_UPGRADE=false DO_BACKUP=false
        DO_RESTORE=false DO_CLEANUP=false DO_AVAILABLE=false
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
        CLEANUP_MODE='safe'
        TARGET_RESTORE_FILE=''
        APT_UPDATED=false

        parse_args \"\$@\"

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
    " -- "$@"
}

# ---------------------------------------------------------------------------
# --install with domain
# ---------------------------------------------------------------------------

@test "parse_args --install=example.com sets DOMAIN=example.com" {
    # getopt with optional-arg (::) requires = syntax: --install=DOMAIN
    run _parse_and_report --install=example.com
    [ "$status" -eq 0 ]
    [[ "$output" == *"DOMAIN=example.com"* ]]
}

@test "parse_args --install=example.com sets DO_INSTALL=true" {
    run _parse_and_report --install=example.com
    [ "$status" -eq 0 ]
    [[ "$output" == *"DO_INSTALL=true"* ]]
}

@test "parse_args -iexample.com (short flag) sets DOMAIN=example.com" {
    # Short optional arg also requires no space: -iDOMAIN
    run _parse_and_report -iexample.com
    [ "$status" -eq 0 ]
    [[ "$output" == *"DOMAIN=example.com"* ]]
}

# ---------------------------------------------------------------------------
# --install without domain (wizard fills later)
# ---------------------------------------------------------------------------

@test "parse_args --install without domain leaves DOMAIN empty" {
    run _parse_and_report --install
    [ "$status" -eq 0 ]
    [[ "$output" == *"DOMAIN="* ]]
    # Ensure DOMAIN is truly empty (not "example.com" or any filler)
    [[ "$output" != *"DOMAIN=example"* ]]
}

# ---------------------------------------------------------------------------
# --mode
# ---------------------------------------------------------------------------

@test "parse_args --install=example.com --mode queue sets INSTALL_MODE=queue" {
    run _parse_and_report --install=example.com --mode queue
    [ "$status" -eq 0 ]
    [[ "$output" == *"INSTALL_MODE=queue"* ]]
}

@test "parse_args --install=example.com --mode single sets INSTALL_MODE=single" {
    run _parse_and_report --install=example.com --mode single
    [ "$status" -eq 0 ]
    [[ "$output" == *"INSTALL_MODE=single"* ]]
}

@test "parse_args --install with invalid mode exits non-zero" {
    run _parse_and_report --install=example.com --mode invalid
    [ "$status" -ne 0 ]
}

# ---------------------------------------------------------------------------
# --monitoring
# ---------------------------------------------------------------------------

@test "parse_args --monitoring sets MONITORING=true" {
    run _parse_and_report --install=example.com --monitoring
    [ "$status" -eq 0 ]
    [[ "$output" == *"MONITORING=true"* ]]
}

@test "parse_args without --monitoring leaves MONITORING=false" {
    run _parse_and_report --install=example.com
    [ "$status" -eq 0 ]
    [[ "$output" == *"MONITORING=false"* ]]
}

# ---------------------------------------------------------------------------
# --upgrade
# ---------------------------------------------------------------------------

@test "parse_args --upgrade sets DO_UPGRADE=true" {
    run _parse_and_report --upgrade
    [ "$status" -eq 0 ]
    [[ "$output" == *"DO_UPGRADE=true"* ]]
}

@test "parse_args -u sets DO_UPGRADE=true (short flag)" {
    run _parse_and_report -u
    [ "$status" -eq 0 ]
    [[ "$output" == *"DO_UPGRADE=true"* ]]
}

# ---------------------------------------------------------------------------
# --backup
# ---------------------------------------------------------------------------

@test "parse_args --backup sets DO_BACKUP=true" {
    run _parse_and_report --backup
    [ "$status" -eq 0 ]
    [[ "$output" == *"DO_BACKUP=true"* ]]
}

@test "parse_args -b sets DO_BACKUP=true (short flag)" {
    run _parse_and_report -b
    [ "$status" -eq 0 ]
    [[ "$output" == *"DO_BACKUP=true"* ]]
}

# ---------------------------------------------------------------------------
# --force
# ---------------------------------------------------------------------------

@test "parse_args --force sets FORCE_FLAG=true" {
    run _parse_and_report --backup --force
    [ "$status" -eq 0 ]
    [[ "$output" == *"FORCE_FLAG=true"* ]]
}

@test "parse_args -f sets FORCE_FLAG=true (short flag)" {
    run _parse_and_report --backup -f
    [ "$status" -eq 0 ]
    [[ "$output" == *"FORCE_FLAG=true"* ]]
}

# ---------------------------------------------------------------------------
# --version
# ---------------------------------------------------------------------------

@test "parse_args --version 1.107.2 sets N8N_VERSION=1.107.2" {
    run _parse_and_report --install=example.com --version 1.107.2
    [ "$status" -eq 0 ]
    [[ "$output" == *"N8N_VERSION=1.107.2"* ]]
}

@test "parse_args -v sets N8N_VERSION (short flag)" {
    run _parse_and_report --upgrade -v 1.107.2
    [ "$status" -eq 0 ]
    [[ "$output" == *"N8N_VERSION=1.107.2"* ]]
}

# ---------------------------------------------------------------------------
# --available
# ---------------------------------------------------------------------------

@test "parse_args --available sets DO_AVAILABLE=true" {
    run _parse_and_report --available
    [ "$status" -eq 0 ]
    [[ "$output" == *"DO_AVAILABLE=true"* ]]
}

# ---------------------------------------------------------------------------
# --email-to / --notify-on-success / --remote-name
# ---------------------------------------------------------------------------

@test "parse_args --email-to sets EMAIL_TO" {
    run _parse_and_report --backup --email-to ops@example.com
    [ "$status" -eq 0 ]
    [[ "$output" == *"EMAIL_TO=ops@example.com"* ]]
}

@test "parse_args --notify-on-success sets NOTIFY_ON_SUCCESS=true" {
    run _parse_and_report --backup --notify-on-success
    [ "$status" -eq 0 ]
    [[ "$output" == *"NOTIFY_ON_SUCCESS=true"* ]]
}

@test "parse_args --remote-name sets RCLONE_REMOTE" {
    run _parse_and_report --backup --remote-name gdrive-user
    [ "$status" -eq 0 ]
    [[ "$output" == *"RCLONE_REMOTE=gdrive-user"* ]]
}

# ---------------------------------------------------------------------------
# Mutual exclusion — two actions must fail
# ---------------------------------------------------------------------------

@test "parse_args --install and --backup together exits non-zero" {
    run _parse_and_report --install=example.com --backup
    [ "$status" -ne 0 ]
}

@test "parse_args --install and --upgrade together exits non-zero" {
    run _parse_and_report --install=example.com --upgrade
    [ "$status" -ne 0 ]
}

@test "parse_args --backup and --upgrade together exits non-zero" {
    run _parse_and_report --backup --upgrade
    [ "$status" -ne 0 ]
}

@test "parse_args no action at all exits non-zero" {
    run _parse_and_report
    [ "$status" -ne 0 ]
}

# ---------------------------------------------------------------------------
# Unknown flag
# ---------------------------------------------------------------------------

@test "parse_args --unknown-flag exits non-zero" {
    run _parse_and_report --unknown-flag
    [ "$status" -ne 0 ]
}

# ---------------------------------------------------------------------------
# --restore
# ---------------------------------------------------------------------------

@test "parse_args --restore file.tar.gz sets DO_RESTORE=true" {
    run _parse_and_report --restore backups/myfile.tar.gz
    [ "$status" -eq 0 ]
    [[ "$output" == *"DO_RESTORE=true"* ]]
}

# ---------------------------------------------------------------------------
# --ssl-email
# ---------------------------------------------------------------------------

@test "parse_args --ssl-email sets SSL_EMAIL" {
    run _parse_and_report --install=example.com --ssl-email you@example.com
    [ "$status" -eq 0 ]
    [[ "$output" == *"SSL_EMAIL=you@example.com"* ]]
}
