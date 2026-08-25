#!/usr/bin/env bats
# tests/unit/test_backup_encryption.bats — backup archive encryption.
#
# The archive holds .env — N8N_ENCRYPTION_KEY, the Postgres password, the Redis
# password — alongside a full database dump, and upload_backup_rclone() sent it
# to Google Drive as-is. One compromised cloud account yielded every credential
# the instance holds.
#
# v3.3.0 makes encryption available and warns loudly on a plaintext upload;
# v3.5.0 makes it mandatory. Two releases of notice, because a cron job that
# starts failing at 3am is its own kind of incident.

load '../test_helper/common'

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"

setup() {
    trap '' ERR INT TERM HUP 2>/dev/null || true
    export LOG_LEVEL="INFO"
    export N8N_DIR="$BATS_TEST_TMPDIR/n8n"
    export BACKUP_DIR="$N8N_DIR/backups"
    export ENV_FILE="$N8N_DIR/.env"
    mkdir -p "$BACKUP_DIR"
    create_test_env "$ENV_FILE"

    source_common
    # shellcheck disable=SC1090
    source "$REPO_ROOT/lib/backup.sh"

    export BACKUP_FILE="n8n_backup_test.tar.gz"
    printf 'N8N_ENCRYPTION_KEY=super-secret-value\n' > "$BACKUP_DIR/$BACKUP_FILE"
    ( cd "$BACKUP_DIR" && sha256sum "$BACKUP_FILE" > "$BACKUP_FILE.sha256" )

    unset BACKUP_PASSPHRASE
}

_need_gpg() {
    command -v gpg >/dev/null 2>&1 || skip "needs gpg"
}

# ---------------------------------------------------------------------------
# Passphrase resolution
# ---------------------------------------------------------------------------

@test "the passphrase is taken from the environment" {
    BACKUP_PASSPHRASE="from-env" run backup_passphrase
    [ "$status" -eq 0 ]
    [ "$output" = "from-env" ]
}

@test "a passphrase in .env works but says what it does not protect against" {
    upsert_env_var BACKUP_PASSPHRASE "from-dotenv" "$ENV_FILE"
    run backup_passphrase
    [ "$status" -eq 0 ]
    [[ "$output" == *"from-dotenv"* ]]
    [[ "$output" == *"same machine as the data it protects"* ]]
}

@test "no passphrase anywhere is a failure, never a generated one" {
    # A backup encrypted with a key the operator does not hold is not a backup.
    run backup_passphrase
    [ "$status" -eq 1 ]
}

# ---------------------------------------------------------------------------
# Encrypt / decrypt round trip
# ---------------------------------------------------------------------------

@test "encrypting replaces the plaintext archive and re-points BACKUP_FILE" {
    _need_gpg
    BACKUP_PASSPHRASE="correct horse battery staple"
    export BACKUP_PASSPHRASE
    run encrypt_backup_archive
    [ "$status" -eq 0 ]

    [ ! -f "$BACKUP_DIR/n8n_backup_test.tar.gz" ]
    [ -f "$BACKUP_DIR/n8n_backup_test.tar.gz.gpg" ]
    [ -f "$BACKUP_DIR/n8n_backup_test.tar.gz.gpg.sha256" ]
}

@test "the encrypted archive does not contain the plaintext secret" {
    _need_gpg
    export BACKUP_PASSPHRASE="correct horse battery staple"
    encrypt_backup_archive
    run grep -c "super-secret-value" "$BACKUP_DIR/n8n_backup_test.tar.gz.gpg"
    [ "$output" -eq 0 ]
}

@test "a round trip returns the original bytes" {
    _need_gpg
    export BACKUP_PASSPHRASE="correct horse battery staple"
    local before
    before="$(sha256sum "$BACKUP_DIR/$BACKUP_FILE" | cut -d' ' -f1)"

    encrypt_backup_archive
    export TARGET_RESTORE_FILE="$BACKUP_DIR/n8n_backup_test.tar.gz.gpg"
    run decrypt_backup_archive
    [ "$status" -eq 0 ]

    local after
    after="$(sha256sum "$BACKUP_DIR/n8n_backup_test.tar.gz" | cut -d' ' -f1)"
    [ "$before" = "$after" ]
}

@test "decryption with the wrong passphrase fails and leaves no partial file" {
    _need_gpg
    export BACKUP_PASSPHRASE="the right one"
    encrypt_backup_archive

    export TARGET_RESTORE_FILE="$BACKUP_DIR/n8n_backup_test.tar.gz.gpg"
    export BACKUP_PASSPHRASE="the wrong one"
    run decrypt_backup_archive
    [ "$status" -eq 1 ]
    [[ "$output" == *"Wrong passphrase"* ]]
    [ ! -f "$BACKUP_DIR/n8n_backup_test.tar.gz" ]
}

@test "a plain archive passes through decrypt untouched" {
    export TARGET_RESTORE_FILE="$BACKUP_DIR/$BACKUP_FILE"
    run decrypt_backup_archive
    [ "$status" -eq 0 ]
    [ -f "$BACKUP_DIR/$BACKUP_FILE" ]
}

@test "encryption without a passphrase refuses rather than writing plaintext" {
    run encrypt_backup_archive
    [ "$status" -eq 1 ]
    [[ "$output" == *"no passphrase found"* ]]
    # the plaintext archive is still there, untouched, not silently "encrypted"
    [ -f "$BACKUP_DIR/$BACKUP_FILE" ]
}

# ---------------------------------------------------------------------------
# The warning, and the notice period
# ---------------------------------------------------------------------------

@test "the unencrypted-upload warning names what is at risk and when it stops" {
    run warn_unencrypted_upload
    [[ "$output" == *"N8N_ENCRYPTION_KEY"* ]]
    [[ "$output" == *"full PostgreSQL dump"* ]]
    [[ "$output" == *"v3.5.0"* ]]
    [[ "$output" == *"--no-encrypt"* ]]
}

@test "the grace release is stated once, not scattered" {
    [ "$ENCRYPTION_GRACE_RELEASE" = "v3.5.0" ]
}

# ---------------------------------------------------------------------------
# Housekeeping
# ---------------------------------------------------------------------------

@test "the prune covers encrypted archives too" {
    # Without this, encrypted backups accumulate forever while plain ones expire.
    grep -q 'name "\*.tar.gz.gpg" -mtime' "$REPO_ROOT/lib/backup.sh"
}

@test "restore decrypts before it previews" {
    # The preview compares encryption keys inside the archive, so decryption has
    # to happen first or the archive looks unreadable.
    run awk '/^restore_stack\(\)/,/preview_restore_archive/' "$REPO_ROOT/lib/backup.sh"
    [[ "$output" == *"decrypt_backup_archive"* ]]
    dec_line="$(grep -n 'decrypt_backup_archive || return 1' "$REPO_ROOT/lib/backup.sh" | cut -d: -f1)"
    prev_line="$(grep -n 'preview_restore_archive "\$restore_dir"' "$REPO_ROOT/lib/backup.sh" | cut -d: -f1)"
    [ "$dec_line" -lt "$prev_line" ]
}

@test "--encrypt and --no-encrypt are documented" {
    run bash "$REPO_ROOT/n8n_manager.sh" --help
    [[ "$output" == *"--encrypt"* ]]
    [[ "$output" == *"--no-encrypt"* ]]
    [[ "$output" == *"BACKUP_PASSPHRASE"* ]]
}
