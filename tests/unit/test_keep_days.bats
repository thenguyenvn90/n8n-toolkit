#!/usr/bin/env bats
# tests/unit/test_keep_days.bats — backup retention.
#
# DAYS_TO_KEEP=7 was hardcoded with no flag, and it governed three different
# lifetimes at once: log files, local backups and remote backups. Seven days is
# reasonable for logs and short for backups, and the operator could change
# neither.

load '../test_helper/common'

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"

setup() {
    trap '' ERR INT TERM HUP 2>/dev/null || true
    export LOG_LEVEL="INFO"
    export N8N_DIR="$BATS_TEST_TMPDIR/n8n"
    export BACKUP_DIR="$N8N_DIR/backups"
    mkdir -p "$BACKUP_DIR"
}

_parse_keep_days() {
    bash -c "
        set +euo pipefail
        export LOG_LEVEL=INFO
        source '$REPO_ROOT/lib/common.sh'
        eval \"\$(sed -n '/^usage()/,/^main()/{ /^main()/q; p }' '$REPO_ROOT/n8n_manager.sh')\"
        TEMPLATE_SINGLE='$REPO_ROOT/deploy/single-mode'
        TEMPLATE_QUEUE='$REPO_ROOT/deploy/queue-mode'
        DO_INSTALL=false DO_UPGRADE=false DO_BACKUP=false
        DO_RESTORE=false DO_CLEANUP=false DO_AVAILABLE=false
        CLEANUP_MODE='safe' INSTALL_MODE='single'
        DOMAIN='' SSL_EMAIL='' N8N_VERSION='latest' FORCE_FLAG=false
        LOCAL_MODE=false MONITORING=false EXPOSE_PROMETHEUS=false
        SUBDOMAIN_N8N='' SUBDOMAIN_GRAFANA='' SUBDOMAIN_PROMETHEUS=''
        BASIC_AUTH_USER='' BASIC_AUTH_PASS='' OWNER_EMAIL='' OWNER_PASSWORD=''
        EMAIL_TO='' EMAIL_EXPLICIT=false NOTIFY_ON_SUCCESS=false
        RCLONE_REMOTE='' TARGET_RESTORE_FILE='' N8N_DIR='$N8N_DIR'
        DAYS_TO_KEEP=7 LOG_KEEP_DAYS=7
        parse_args \"\$@\"
        echo \"DAYS_TO_KEEP=\$DAYS_TO_KEEP\"
        echo \"LOG_KEEP_DAYS=\$LOG_KEEP_DAYS\"
    " _ "$@" 2>&1
}

# ---------------------------------------------------------------------------
# The flag
# ---------------------------------------------------------------------------

@test "--keep-days sets the backup retention" {
    run _parse_keep_days --backup --keep-days 30
    [[ "$output" == *"DAYS_TO_KEEP=30"* ]]
}

@test "--keep-days leaves log retention alone" {
    run _parse_keep_days --backup --keep-days 30
    [[ "$output" == *"LOG_KEEP_DAYS=7"* ]]
}

@test "backup retention defaults to 7 when the flag is absent" {
    run _parse_keep_days --backup
    [[ "$output" == *"DAYS_TO_KEEP=7"* ]]
}

@test "--keep-days rejects a non-numeric value" {
    run _parse_keep_days --backup --keep-days abc
    [[ "$output" == *"must be a positive integer"* ]]
}

@test "--keep-days rejects zero" {
    # `find -mtime +0` would prune everything from today onward, which is not
    # what anyone means by "keep zero days".
    run _parse_keep_days --backup --keep-days 0
    [[ "$output" == *"must be a positive integer"* ]]
}

@test "--keep-days is documented in --help" {
    run bash "$REPO_ROOT/n8n_manager.sh" --help
    [[ "$output" == *"--keep-days"* ]]
    [[ "$output" == *"Logs are pruned after 7 days regardless"* ]]
}

# ---------------------------------------------------------------------------
# The two retentions are genuinely separate now
# ---------------------------------------------------------------------------

@test "the log prune uses LOG_KEEP_DAYS, not the backup retention" {
    grep -q 'find "\$LOG_DIR" -type f -mtime +\$LOG_KEEP_DAYS' "$REPO_ROOT/n8n_manager.sh"
    run grep -c 'find "\$LOG_DIR" -type f -mtime +\$DAYS_TO_KEEP' "$REPO_ROOT/n8n_manager.sh"
    [ "$output" -eq 0 ]
}

@test "--keep-days 30 keeps a 20-day-old archive that the default would prune" {
    : > "$BACKUP_DIR/n8n_backup_2.17.7_old.tar.gz"
    touch -d '20 days ago' "$BACKUP_DIR/n8n_backup_2.17.7_old.tar.gz"

    # Default retention would take it
    find "$BACKUP_DIR" -maxdepth 1 -type f -name "*.tar.gz" -mtime +30 -exec rm -f {} \;
    [ -f "$BACKUP_DIR/n8n_backup_2.17.7_old.tar.gz" ]

    find "$BACKUP_DIR" -maxdepth 1 -type f -name "*.tar.gz" -mtime +7 -exec rm -f {} \;
    [ ! -f "$BACKUP_DIR/n8n_backup_2.17.7_old.tar.gz" ]
}
