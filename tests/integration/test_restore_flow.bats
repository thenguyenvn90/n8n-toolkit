#!/usr/bin/env bats
# tests/integration/test_restore_flow.bats — Restore safety gates.
#
# Coverage: preview_restore_archive, snapshot_current_state, snapshot_keep_last,
#           recent_backup_exists, prune scoping, safe_wipe_target_dir guards.
#
# These exist because restore_stack() used to overwrite the live .env and
# docker-compose.yml BEFORE validating anything and without taking a copy. A
# mistyped archive path replaced the running N8N_ENCRYPTION_KEY, and every
# credential in the database became permanently undecryptable.

load '../test_helper/common'

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"

setup() {
    trap '' ERR INT TERM HUP 2>/dev/null || true
    export LOG_LEVEL="INFO"
    export DATE="2026-08-25_10-00-00"
    export FORCE_FLAG=false
    export POSTGRES_SERVICE="postgres"

    export N8N_DIR="$BATS_TEST_TMPDIR/n8n"
    export BACKUP_DIR="$N8N_DIR/backups"
    export ENV_FILE="$N8N_DIR/.env"
    export COMPOSE_FILE="$N8N_DIR/docker-compose.yml"
    mkdir -p "$BACKUP_DIR"

    create_test_env "$ENV_FILE"
    printf 'services:\n  main:\n    image: n8nio/n8n:${N8N_IMAGE_TAG:-2.17.7}\n' > "$COMPOSE_FILE"

    # Archive staging dir, as restore_stack would have extracted it
    export ARCHIVE_DIR="$BATS_TEST_TMPDIR/archive"
    mkdir -p "$ARCHIVE_DIR"
    cp "$ENV_FILE" "$ARCHIVE_DIR/.env.bak"
    cp "$COMPOSE_FILE" "$ARCHIVE_DIR/docker-compose.yml.bak"
    export TARGET_RESTORE_FILE="$BATS_TEST_TMPDIR/n8n_backup_2.17.7_2026-08-25_09-00-00.tar.gz"
    : > "$TARGET_RESTORE_FILE"

    # No PostgreSQL container in these tests -> snapshots stay config-only.
    container_id_for_service() { return 1; }

    source_all_libs
    export -f container_id_for_service 2>/dev/null || true
    container_id_for_service() { return 1; }
}

# ---------------------------------------------------------------------------
# preview_restore_archive() — the gate
# ---------------------------------------------------------------------------

@test "restore aborts when the archive encryption key differs and -f is absent" {
    # Archive from a different instance
    sed -i 's|^N8N_ENCRYPTION_KEY=.*|N8N_ENCRYPTION_KEY=b3RoZXJpbnN0YW5jZWtleXZhbHVlMTIzNDU2|' "$ARCHIVE_DIR/.env.bak"
    FORCE_FLAG=false
    # stdin is not a TTY under bats, which is the unattended case: refuse.
    run preview_restore_archive "$ARCHIVE_DIR" "$TARGET_RESTORE_FILE"
    [ "$status" -eq 1 ]
    [[ "$output" == *"DIFFERENT"* ]]
    [[ "$output" == *"unrecoverable"* ]]
}

@test "restore preview reports MATCH when the archive is from the same instance" {
    FORCE_FLAG=true
    run preview_restore_archive "$ARCHIVE_DIR" "$TARGET_RESTORE_FILE"
    [ "$status" -eq 0 ]
    [[ "$output" == *"MATCH"* ]]
}

@test "restore preview reports no existing instance when there is no live .env" {
    rm -f "$ENV_FILE"
    FORCE_FLAG=true
    run preview_restore_archive "$ARCHIVE_DIR" "$TARGET_RESTORE_FILE"
    [ "$status" -eq 0 ]
    [[ "$output" == *"NO EXISTING INSTANCE"* ]]
}

@test "restore proceeds without a prompt when -f is given" {
    sed -i 's|^N8N_ENCRYPTION_KEY=.*|N8N_ENCRYPTION_KEY=b3RoZXJpbnN0YW5jZWtleXZhbHVlMTIzNDU2|' "$ARCHIVE_DIR/.env.bak"
    FORCE_FLAG=true
    run preview_restore_archive "$ARCHIVE_DIR" "$TARGET_RESTORE_FILE"
    [ "$status" -eq 0 ]
    [[ "$output" == *"skipping the restore confirmation"* ]]
}

@test "restore leaves the live .env untouched when the gate refuses" {
    local before
    before="$(cat "$ENV_FILE")"
    sed -i 's|^N8N_ENCRYPTION_KEY=.*|N8N_ENCRYPTION_KEY=b3RoZXJpbnN0YW5jZWtleXZhbHVlMTIzNDU2|' "$ARCHIVE_DIR/.env.bak"
    FORCE_FLAG=false
    run preview_restore_archive "$ARCHIVE_DIR" "$TARGET_RESTORE_FILE"
    [ "$status" -eq 1 ]
    [ "$(cat "$ENV_FILE")" = "$before" ]
    [ -f "$COMPOSE_FILE" ]
}

# ---------------------------------------------------------------------------
# snapshot_current_state() — the rescue copy
# ---------------------------------------------------------------------------

@test "restore writes a pre-restore snapshot before touching .env" {
    run snapshot_current_state pre-restore
    [ "$status" -eq 0 ]
    local snap="$BACKUP_DIR/pre-restore/$DATE"
    [ -d "$snap" ]
    [ -f "$snap/.env.bak" ]
    [ -f "$snap/docker-compose.yml.bak" ]
    # The snapshot must hold the LIVE key, not the archive's
    grep -q "dGVzdGtleWJhc2U2NGVuY3J5cHRpb25rZXk=" "$snap/.env.bak"
}

@test "snapshot_current_state works on a fresh target with no live config" {
    rm -f "$ENV_FILE" "$COMPOSE_FILE"
    run snapshot_current_state pre-restore
    [ "$status" -eq 0 ]
    [ -d "$BACKUP_DIR/pre-restore/$DATE" ]
}

@test "upgrade takes its snapshot under pre-upgrade" {
    run snapshot_current_state pre-upgrade
    [ "$status" -eq 0 ]
    [ -f "$BACKUP_DIR/pre-upgrade/$DATE/.env.bak" ]
}

@test "snapshot_keep_last keeps only the newest 3 snapshots" {
    local root="$BACKUP_DIR/pre-restore"
    mkdir -p "$root"/2026-08-2{1,2,3,4,5}_10-00-00
    snapshot_keep_last "$root" 3
    local n
    n="$(find "$root" -mindepth 1 -maxdepth 1 -type d | wc -l)"
    [ "$n" -eq 3 ]
    [ -d "$root/2026-08-25_10-00-00" ]
    [ -d "$root/2026-08-23_10-00-00" ]
    [ ! -d "$root/2026-08-21_10-00-00" ]
}

@test "recent_backup_exists sees a fresh archive and ignores an old one" {
    run recent_backup_exists 60
    [ "$status" -eq 1 ]

    : > "$BACKUP_DIR/n8n_backup_2.17.7_now.tar.gz"
    run recent_backup_exists 60
    [ "$status" -eq 0 ]

    touch -d '3 hours ago' "$BACKUP_DIR/n8n_backup_2.17.7_now.tar.gz"
    run recent_backup_exists 60
    [ "$status" -eq 1 ]
}

# ---------------------------------------------------------------------------
# prune scoping — a rescue copy that expires on a timer is not a rescue copy
# ---------------------------------------------------------------------------

@test "pre-restore snapshots survive the backup prune" {
    export DAYS_TO_KEEP=7
    mkdir -p "$BACKUP_DIR/pre-restore/old"
    : > "$BACKUP_DIR/pre-restore/old/n8n_postgres_dump_old.tar.gz"
    : > "$BACKUP_DIR/n8n_backup_top_level.tar.gz"
    touch -d '30 days ago' "$BACKUP_DIR/pre-restore/old/n8n_postgres_dump_old.tar.gz" \
                            "$BACKUP_DIR/n8n_backup_top_level.tar.gz"

    # Same prune expression backup_stack() uses
    find "$BACKUP_DIR" -maxdepth 1 -type f -name "*.tar.gz" -mtime +$DAYS_TO_KEEP -exec rm -f {} \;

    [ ! -f "$BACKUP_DIR/n8n_backup_top_level.tar.gz" ]
    [ -f "$BACKUP_DIR/pre-restore/old/n8n_postgres_dump_old.tar.gz" ]
}

@test "backup_stack prunes with -maxdepth 1" {
    grep -q 'find "$BACKUP_DIR" -maxdepth 1 -type f -name "\*.tar.gz" -mtime' "$REPO_ROOT/lib/backup.sh"
}

# ---------------------------------------------------------------------------
# safe_wipe_target_dir() — SC2115, surfaced by the new shellcheck job
# ---------------------------------------------------------------------------

@test "safe_wipe_target_dir refuses the filesystem root" {
    N8N_DIR="/" SCRIPT_DIR="$BATS_TEST_TMPDIR/elsewhere" run safe_wipe_target_dir
    [ "$status" -eq 1 ]
    [[ "$output" == *"Refusing to wipe filesystem root"* ]]
}

@test "safe_wipe_target_dir refuses a top-level directory" {
    mkdir -p "$BATS_TEST_TMPDIR/elsewhere"
    N8N_DIR="/n8n" SCRIPT_DIR="$BATS_TEST_TMPDIR/elsewhere" run safe_wipe_target_dir
    [ "$status" -ne 0 ]
    [[ "$output" == *"Refusing to wipe"* ]]
}

@test "safe_wipe_target_dir still wipes a normal nested target" {
    local tgt="$BATS_TEST_TMPDIR/deep/nested/n8n"
    mkdir -p "$tgt"
    : > "$tgt/somefile"
    : > "$tgt/.dotfile"
    N8N_DIR="$tgt" SCRIPT_DIR="$BATS_TEST_TMPDIR/elsewhere" run safe_wipe_target_dir
    [ "$status" -eq 0 ]
    [ ! -f "$tgt/somefile" ]
    [ ! -f "$tgt/.dotfile" ]
    [ -d "$tgt" ]
}
