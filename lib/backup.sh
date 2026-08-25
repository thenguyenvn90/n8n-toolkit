#!/usr/bin/env bash
# lib/backup.sh — Backup and restore stack functions
# Sourced by n8n_manager.sh — do not execute directly.
# shellcheck disable=SC2154  # Variables set by n8n_manager.sh globals

################################################################################
# do_local_backup()
# Description:
#   Execute local backup: volumes, Postgres dump, config copy, compress, checksum.
#
# Behaviors:
#   - Verifies N8N_ENCRYPTION_KEY exists in .env.
#   - Archives each Docker volume to BACKUP_PATH as tar.gz chunks.
#   - Dumps Postgres DB from container "postgres" to SQL file.
#   - Copies .env and docker-compose.yml as *.bak.
#   - Compresses BACKUP_PATH into BACKUP_DIR/n8n_backup_<ver>_<ts>.tar.gz
#       * Uses `tar | pigz` if pigz exists; else `tar -czf`.
#   - Generates SHA-256 checksum for the archive.
#   - Prunes old archives/checksums older than DAYS_TO_KEEP.
#
# Returns:
#   0 on success; non-zero on any failure.
################################################################################
do_local_backup() {
    ensure_encryption_key || return 1

    local BACKUP_PATH="$BACKUP_DIR/backup_$DATE"
    mkdir -p "$BACKUP_PATH"

    log INFO "Starting backup at $DATE..."
    log INFO "Backing up ./local-files directory..."
    if [[ -d "$N8N_DIR/local-files" ]]; then
        tar -czf "$BACKUP_PATH/local-files_$DATE.tar.gz" -C "$N8N_DIR" local-files \
            || { log ERROR "Failed to backup local-files directory"; return 1; }
        log INFO "local-files directory backed up"
    else
        log INFO "No local-files directory found, skipping..."
    fi

    log INFO "Backing up Docker volumes..."
    local vol
    for vol in "${DISCOVERED_VOLUMES[@]}"; do
        local real
        real="$(resolve_volume_name "$vol" || true)"
        if [[ -z "$real" ]]; then
            log INFO "Skipping volume '$vol' (not present on host)."
            continue
        fi
        local vol_backup="volume_${vol}_$DATE.tar.gz"
        docker run --rm \
            -v "${real}:/data" \
            -v "$BACKUP_PATH:/backup" \
            alpine \
            sh -c "tar czf /backup/$vol_backup -C /data ." \
            || { log ERROR "Failed to archive volume $vol"; return 1; }
        log INFO "Volume '$vol' backed up: $vol_backup"
    done

    log INFO "Dumping PostgreSQL database..."
    local DB_USER="${DB_POSTGRESDB_USER:-${POSTGRES_USER:-n8n}}"
    local DB_NAME="${DB_POSTGRESDB_DATABASE:-${POSTGRES_DB:-n8n}}"
    local ADMIN_USER="${POSTGRES_USER:-postgres}"
    local pgcid; pgcid="$(container_id_for_service "$POSTGRES_SERVICE")"
    local ADMIN_PASS="$(_read_env_var_from_container "$pgcid" POSTGRES_PASSWORD)"

    if [[ -z "$pgcid" ]]; then
        log ERROR "Postgres service '$POSTGRES_SERVICE' is not running"
        return 1
    fi

    [[ -z "$ADMIN_PASS" ]] && log WARN "POSTGRES_PASSWORD not found in container env; proceeding (trust/peer auth assumed)."

    if docker exec "$pgcid" pg_isready &>/dev/null; then
        docker exec -e PGPASSWORD="$ADMIN_PASS" "$pgcid" \
            pg_dump -U "$ADMIN_USER" -d "$DB_NAME" > "$BACKUP_PATH/n8n_postgres_dump_$DATE.sql" \
                || { log ERROR "Postgres dump failed"; return 1; }
        log INFO "Database dump saved to $BACKUP_PATH/n8n_postgres_dump_$DATE.sql"
    else
        log ERROR "Postgres not ready ($POSTGRES_SERVICE)"
        return 1
    fi

    log INFO "Backing up .env and docker-compose.yml..."
    cp "$ENV_FILE" "$BACKUP_PATH/.env.bak"
    cp "$COMPOSE_FILE" "$BACKUP_PATH/docker-compose.yml.bak"

    log INFO "Compressing backup folder..."
    BACKUP_FILE="n8n_backup_${N8N_VERSION}_${DATE}.tar.gz"

    if command -v pigz >/dev/null 2>&1; then
        tar -C "$BACKUP_PATH" -cf - . | pigz > "$BACKUP_DIR/$BACKUP_FILE" \
            || { log ERROR "Failed to compress backup with pigz"; return 1; }
    else
        tar -czf "$BACKUP_DIR/$BACKUP_FILE" -C "$BACKUP_PATH" . \
            || { log ERROR "Failed to compress backup with gzip"; return 1; }
    fi
    log INFO "Created archive -> $BACKUP_DIR/$BACKUP_FILE"

    # sha256 checksum
    if [[ -f "$BACKUP_DIR/$BACKUP_FILE" ]]; then
        # Write checksum relative to BACKUP_DIR so verification after download works
        ( cd "$BACKUP_DIR" \
          && sha256sum "$BACKUP_FILE" > "$BACKUP_FILE.sha256" ) \
          || { log ERROR "Failed to write checksum"; return 1; }
    else
        log ERROR "Archive not found after compression: $BACKUP_DIR/$BACKUP_FILE"
        return 1
    fi
    log INFO "Created checksum -> $BACKUP_DIR/$BACKUP_FILE.sha256"

    chmod 600 "$BACKUP_DIR/"*.tar.gz 2>/dev/null || true
    chmod 600 "$BACKUP_DIR/"*.sha256 2>/dev/null || true

    log INFO "Cleaning up local backups older than $DAYS_TO_KEEP days (--keep-days)..."
    rm -rf "$BACKUP_PATH"
    # -maxdepth 1 keeps the prune out of backups/pre-restore/ and backups/pre-upgrade/.
    # Those are rescue copies kept by count, not by age — a prune that eats them
    # defeats the point of taking them.
    find "$BACKUP_DIR" -maxdepth 1 -type f -name "*.tar.gz" -mtime +$DAYS_TO_KEEP -exec rm -f {} \;
    find "$BACKUP_DIR" -maxdepth 1 -type f -name "*.sha256" -mtime +$DAYS_TO_KEEP -exec rm -f {} \;
    find "$BACKUP_DIR" -maxdepth 1 -type d -name 'backup_*' -empty -exec rmdir {} \;
    log INFO "Removed any empty backup_<timestamp> folders"
    return 0
}

################################################################################
# upload_backup_rclone()
# Description:
#   Upload the archive, its checksum, and backup_summary.md to rclone remote,
#   then prune remote old files.
#
# Behaviors:
#   - If RCLONE_REMOTE is empty → sets UPLOAD_STATUS=SKIPPED and returns 0.
#   - Uploads files via `rclone copyto` to remote root.
#   - Sets UPLOAD_STATUS=SUCCESS on success; FAIL on any upload error.
#   - Prunes remote files older than DAYS_TO_KEEP by filter (keeps recent ones).
#
# Returns:
#   0 on full success; non-zero if upload failed (prune still attempted).
################################################################################
upload_backup_rclone() {
    if [[ -z "$RCLONE_REMOTE" ]]; then
        UPLOAD_STATUS="SKIPPED"; return 0
    fi
    require_cmd rclone || { UPLOAD_STATUS="FAIL"; return 1; }

    # Normalize remote (force one colon)
    local REMOTE
    if [[ "$RCLONE_REMOTE" == *:* ]]; then
        REMOTE="$RCLONE_REMOTE"
    else
        REMOTE="${RCLONE_REMOTE}:"
    fi

    log INFO "Uploading backup files directly to remote root ($REMOTE)"

    if  rclone copyto "$BACKUP_DIR/$BACKUP_FILE" "$REMOTE/$BACKUP_FILE" "${RCLONE_FLAGS[@]}" \
        && rclone copyto "$BACKUP_DIR/$BACKUP_FILE.sha256" "$REMOTE/$BACKUP_FILE.sha256" "${RCLONE_FLAGS[@]}" \
        && rclone copyto "$BACKUP_DIR/backup_summary.md" "$REMOTE/backup_summary.md" "${RCLONE_FLAGS[@]}"; then
        UPLOAD_STATUS="SUCCESS"
        log INFO "Uploaded '$BACKUP_FILE', checksum and 'backup_summary.md' successfully."
    else
        UPLOAD_STATUS="FAIL"
        log ERROR "One or more uploads failed"
    fi

    # Safer remote prune
    log INFO "Pruning remote archives older than ${DAYS_TO_KEEP:-7} days (pattern: n8n_backup_*.tar.gz)"
    local tmpfilter; tmpfilter="$(mktemp)"
    printf "%s\n" "+ n8n_backup_*.tar.gz" "+ n8n_backup_*.tar.gz.sha256" "- *" > "$tmpfilter"
    rclone delete "$REMOTE" --min-age "${DAYS_TO_KEEP:-7}d" --filter-from "$tmpfilter" --rmdirs \
        || log WARN "Remote prune returned non-zero (continuing)."
    rm -f "$tmpfilter"

    [[ "$UPLOAD_STATUS" == "SUCCESS" ]]
}

################################################################################
# write_summary_row()
# Description:
#   Append action/status to backup_summary.md and prune entries >30 days old.
#
# Behaviors:
#   - Creates header if file is missing.
#   - Appends a table row: DATE | ACTION | N8N_VERSION | STATUS.
#   - Keeps only rows with DATE >= cutoff (30 days ago), preserving header.
#
# Returns:
#   0 on success; non-zero on failure.
################################################################################
write_summary_row() {
    local action="$1" status="$2"
    local version="$N8N_VERSION"
    local file="$BACKUP_DIR/backup_summary.md"
    local now; now="$DATE"

    # If the file doesn't exist, write the markdown table header
    if [[ ! -f "$file" ]]; then
        cat >> "$file" <<'EOF'
| DATE               | ACTION         | N8N_VERSION | STATUS   |
|--------------------|----------------|-------------|----------|
EOF
    fi

    # Append a new row
    printf "| %s | %s | %s | %s |\n" "$now" "$action" "$version" "$status" >> "$file"

    # Prune rows older than 30 days (match YYYY-MM-DD at start of each row)
    {
        head -n2 "$file"
        tail -n +3 "$file" \
        | awk -F'|' -v cut="$(date -d '30 days ago' '+%F')" '
            {
                date=$2; gsub(/^[[:space:]]+|[[:space:]]+$/,"",date)
                split(date, dt, "_"); if (dt[1] >= cut) print
            }'
    } > "${file}.tmp" && mv "${file}.tmp" "$file"

}

################################################################################
# send_mail_on_action()
# Description:
#   Decide whether and what to email based on BACKUP_STATUS/UPLOAD_STATUS.
#
# Behaviors:
#   - Composes subject/body per cases:
#       * Local FAIL → always email (attach LOG_FILE).
#       * Upload FAIL → always email.
#       * SUCCESS/SKIPPED → email only if NOTIFY_ON_SUCCESS=true.
#   - Calls send_email accordingly.
#
# Returns:
#   0 if email not needed or sent successfully; non-zero if send fails.
################################################################################
send_mail_on_action() {
    local subject body

    if [[ "$BACKUP_STATUS" == "FAIL" ]]; then
        subject="$DATE: n8n Backup FAILED locally"
        body="An error occurred during the local backup step. See attached log.

Log File: $LOG_FILE"

    elif [[ "$BACKUP_STATUS" == "SKIPPED" ]]; then
        subject="$DATE: n8n Backup SKIPPED: no changes"
        body="No changes detected since the last backup; nothing to do."

    elif [[ "$BACKUP_STATUS" == "SUCCESS" && "$UPLOAD_STATUS" == "FAIL" ]]; then
        subject="$DATE: n8n Backup Succeeded; upload FAILED"
        body="Local backup succeeded as:

File: $BACKUP_FILE

But the upload to $RCLONE_REMOTE failed.
See log for details:

Log File: $LOG_FILE"

    elif [[ "$BACKUP_STATUS" == "SUCCESS" && "$UPLOAD_STATUS" == "SUCCESS" ]]; then
        subject="$DATE: n8n Backup SUCCESS"
        body="Backup and upload completed successfully.

  File: $BACKUP_FILE
  Remote: $RCLONE_REMOTE
  Drive Link: ${DRIVE_LINK:-N/A}"

    elif [[ "$BACKUP_STATUS" == "SUCCESS" && "$UPLOAD_STATUS" == "SKIPPED" ]]; then
        subject="$DATE: n8n Backup SUCCESS (upload skipped)"
        body="Local backup completed successfully.

  File: $BACKUP_FILE
  Remote upload: SKIPPED (no rclone remote/target configured)

  Log File: $LOG_FILE"

    else
        subject="$DATE: n8n Backup status unknown"
        body="Backup reported an unexpected status:
  BACKUP_STATUS=$BACKUP_STATUS
  UPLOAD_STATUS=$UPLOAD_STATUS
  Log File: $LOG_FILE"
    fi

    # Decide whether to send email (policy lives here; common.sh only sends)
    EMAIL_SENT=false
    if ! $EMAIL_EXPLICIT; then
        return 0
    fi

    if [[ "$BACKUP_STATUS" == "FAIL" || "$UPLOAD_STATUS" == "FAIL" ]]; then
        EMAIL_ATTEMPTED=true
        send_email "$subject" "$body" "$LOG_FILE" && EMAIL_SENT=true
    elif [[ "$BACKUP_STATUS" == "SKIPPED" ]]; then
        if [[ "$NOTIFY_ON_SUCCESS" == true ]]; then
            EMAIL_ATTEMPTED=true
            send_email "$subject" "$body" && EMAIL_SENT=true
        fi
    else
        if [[ "$NOTIFY_ON_SUCCESS" == true ]]; then
            EMAIL_ATTEMPTED=true
            send_email "$subject" "$body" && EMAIL_SENT=true
        fi
    fi
}

################################################################################
# summarize_backup()
# Description:
#   Print a human-readable, aligned one-shot summary of the latest action
#   (backup/restore) to the console.
#
# Behaviors:
#   - Derives the email outcome line:
#       * EMAIL_EXPLICIT=false  → "SKIPPED (not requested)"
#       * EMAIL_SENT=true       → "SUCCESS"
#       * Missing SMTP config   → "ERROR (missing SMTP config)"
#       * Otherwise             → "FAILED (send failed)"
#   - Renders a status box via box_line() for:
#       Action, Status, Timestamp, Domain, Backup file (if any),
#       N8N Version, Log File, Daily tracking (backup_summary.md),
#       Google Drive upload (SUCCESS/SKIPPED/FAILED) and Folder link (if SUCCESS),
#       Email notification (derived as above).
#
# Returns:
#   0 always.
################################################################################
summarize_backup() {
    local summary_file="$BACKUP_DIR/backup_summary.md"
    local email_status email_reason
    log INFO "Print a summary of what happened..."

    if ! $EMAIL_EXPLICIT; then
        email_status="SKIPPED"; email_reason="(not requested)"
    elif $EMAIL_ATTEMPTED; then
        if $EMAIL_SENT; then
            email_status="SUCCESS"; email_reason=""
        else
            if [[ -z "$SMTP_USER" || -z "$SMTP_PASS" || -z "$EMAIL_TO" ]]; then
                email_status="ERROR";  email_reason="(missing SMTP config)"
            else
                email_status="FAILED"; email_reason="(send failed)"
            fi
        fi
    else
        email_status="SKIPPED"; email_reason="(policy: not required)"
    fi

    local n8n_fqdn
    n8n_fqdn="$(read_env_var "$ENV_FILE" N8N_FQDN)"
    echo "═════════════════════════════════════════════════════════════"
    echo "Backup completed!"
    box_line "Detected Mode:"           "${DISCOVERED_MODE:-unknown}"
    box_line "Domain (n8n):"            "https://${n8n_fqdn}"
    box_line "Backup Action:"           "$ACTION"
    box_line "Backup Status:"           "$BACKUP_STATUS"
    box_line "Backup Timestamp:"        "$DATE"
    [[ -n "${BACKUP_FILE:-}" ]] && box_line "Backup file:" "$BACKUP_DIR/$BACKUP_FILE"
    box_line "N8N Version:"             "$N8N_VERSION"
    box_line "N8N Directory:"           "$N8N_DIR"
    box_line "Log File:"                "$LOG_FILE"
    box_line "Daily tracking:"          "$summary_file"
    case "$UPLOAD_STATUS" in
        "SUCCESS") box_line "Remote upload:" "SUCCESS"; box_line "Remote folder link:" "$DRIVE_LINK" ;;
        "SKIPPED") box_line "Remote upload:" "SKIPPED" ;;
        *)         box_line "Remote upload:" "FAILED"  ;;
    esac
    if [[ -n "$email_reason" ]]; then
        box_line "Email notification:" "$email_status $email_reason"
    else
        box_line "Email notification:" "$email_status"
    fi
    echo "═════════════════════════════════════════════════════════════"
}

################################################################################
# backup_stack()
# Description:
#   Orchestrate a full backup: change check → local backup → upload → notify/print.
#
# Behaviors:
#   - If no changes and not forced → marks SKIPPED, writes summary, optional email.
#   - Runs do_local_backup(); on success refreshes snapshot and writes summary.
#   - If remote configured, uploads and prunes; captures DRIVE_LINK.
#   - Sends final email per policy and prints the summary box.
#
# Returns:
#   0 on success (including SKIPPED); 1 if local backup failed.
################################################################################
backup_stack() {
    BACKUP_STATUS=""
    UPLOAD_STATUS=""
    BACKUP_FILE=""
    DRIVE_LINK=""

    load_env_file
    # After load_env_file: it sources .env with allexport, so a legacy .env
    # carrying N8N_VERSION= would otherwise mislabel the archive.
    N8N_VERSION="$(get_current_n8n_version)"
    discover_from_compose
    detect_mode_runtime || true

    N8N_FQDN="$(read_env_var "$ENV_FILE" N8N_FQDN || true)"

    # Initialize snapshot baseline only if missing
    if [[ ! -d "$BACKUP_DIR/snapshot/config" ]]; then
        snapshot_sync boot
    fi

    # Change detection (skip unless forced)
    if is_changed_since_snapshot; then
        ACTION="Backup (normal)"
    elif [[ "$FORCE_FLAG" == true ]]; then
        ACTION="Backup (forced)"
    else
        ACTION="Skipped"; BACKUP_STATUS="SKIPPED"
        log INFO "No changes detected; skipping backup. Use -f to force backup."
        write_summary_row "$ACTION" "$BACKUP_STATUS"
        send_mail_on_action
        summarize_backup
        return 0
    fi

    wait_for_containers_healthy || return 1

    if [[ "$BACKUP_REQUIRE_TLS" == "true" ]]; then
        verify_traefik_certificate "$N8N_FQDN" || return 1
    fi

    if do_local_backup; then
        BACKUP_STATUS="SUCCESS"
        log INFO "Local backup succeeded: $BACKUP_FILE"
        # Refresh snapshot so next run sees "no changes"
        snapshot_sync refresh
        write_summary_row "$ACTION" "$BACKUP_STATUS"
    else
        BACKUP_STATUS="FAIL"
        log ERROR "Local backup failed."
        write_summary_row "$ACTION" "$BACKUP_STATUS"
        send_mail_on_action
        summarize_backup
        return 1
    fi

    # Remote upload (optional)
    if [[ -n "$RCLONE_REMOTE" ]]; then
        upload_backup_rclone || true
    else
        UPLOAD_STATUS="SKIPPED"
    fi

    # Cache Google Drive folder link (if rclone remote is Google Drive)
    DRIVE_LINK="$(get_google_drive_link)"

    # Final email + console summary
    send_mail_on_action
    summarize_backup
}

################################################################################
# snapshot_keep_last()
# Description:
#   Keep only the newest N timestamped snapshot directories under a snapshot
#   root, deleting the rest.
#
# Args:
#   $1 -> snapshot root (e.g. "$BACKUP_DIR/pre-restore")
#   $2 -> how many to keep (default: 3)
#
# Returns:
#   0 always.
#
# Notes:
#   Snapshot dirs are named with the DATE stamp (YYYY-MM-DD_HH-MM-SS), so a
#   reverse lexicographic sort is a chronological sort. Kept by COUNT, not age —
#   a rescue copy that expires on a timer is not a rescue copy.
################################################################################
snapshot_keep_last() {
    local root="$1"
    local keep="${2:-3}"
    [[ -d "$root" ]] || return 0

    local -a dirs=()
    local d
    while IFS= read -r d; do
        [[ -n "$d" ]] && dirs+=("$d")
    done < <(find "$root" -mindepth 1 -maxdepth 1 -type d | sort -r)

    local i
    for (( i = keep; i < ${#dirs[@]}; i++ )); do
        rm -rf -- "${dirs[$i]}"
        log INFO "Pruned old snapshot: $(basename "${dirs[$i]}")"
    done
    return 0
}

################################################################################
# recent_backup_exists()
# Description:
#   Report whether a full backup archive was written in the last N minutes.
#
# Args:
#   $1 -> age in minutes (default: 60)
#
# Returns:
#   0 if a recent archive exists; 1 otherwise.
################################################################################
recent_backup_exists() {
    local minutes="${1:-60}"
    [[ -d "$BACKUP_DIR" ]] || return 1
    local hit
    hit="$(find "$BACKUP_DIR" -maxdepth 1 -type f -name 'n8n_backup_*.tar.gz' \
             -mmin "-${minutes}" -print -quit 2>/dev/null || true)"
    [[ -n "$hit" ]]
}

################################################################################
# snapshot_current_state()
# Description:
#   Take a rescue copy of the CURRENT instance before a destructive operation.
#
# Args:
#   $1 -> kind: "pre-restore" | "pre-upgrade"
#
# Behaviors:
#   - Always copies .env and docker-compose.yml. These are cheap and they are
#     exactly what is lost in the worst case: overwrite the live
#     N8N_ENCRYPTION_KEY and every credential in the database becomes
#     permanently undecryptable.
#   - Dumps PostgreSQL too, UNLESS a full backup was taken in the last hour
#     (that archive already holds the same data).
#   - Keeps the last 3 snapshots per kind, by count.
#
# Output:
#   Prints the snapshot directory path to stdout on success.
#
# Returns:
#   0 on success (including the degraded config-only case); 1 if the snapshot
#   directory could not be created.
################################################################################
snapshot_current_state() {
    local kind="${1:-pre-restore}"
    local root="$BACKUP_DIR/$kind"
    local dir="$root/$DATE"

    mkdir -p "$dir" || { log ERROR "Cannot create snapshot dir: $dir"; return 1; }
    chmod 700 "$root" "$dir" 2>/dev/null || true

    local copied=0
    if [[ -f "$ENV_FILE" ]]; then
        cp -a "$ENV_FILE" "$dir/.env.bak" && copied=1
    fi
    if [[ -f "$COMPOSE_FILE" ]]; then
        cp -a "$COMPOSE_FILE" "$dir/docker-compose.yml.bak" && copied=1
    fi
    chmod 600 "$dir"/* 2>/dev/null || true

    if (( copied == 0 )); then
        log INFO "No live .env/compose to snapshot (fresh target) — nothing to rescue."
    fi

    if recent_backup_exists 60; then
        log INFO "A full backup exists from the last hour; skipping the snapshot DB dump."
        printf '%s\n' "$dir"
        snapshot_keep_last "$root" 3
        return 0
    fi

    local pg_cid
    pg_cid="$(container_id_for_service "$POSTGRES_SERVICE" 2>/dev/null || true)"
    if [[ -z "$pg_cid" ]]; then
        log INFO "PostgreSQL not running; snapshot is config-only."
        printf '%s\n' "$dir"
        snapshot_keep_last "$root" 3
        return 0
    fi

    local db_user db_name admin_pass
    db_user="$(read_env_var "$ENV_FILE" DB_POSTGRESDB_USER || echo n8n)"
    db_name="$(read_env_var "$ENV_FILE" DB_POSTGRESDB_DATABASE || echo n8n)"
    admin_pass="$(_read_env_var_from_container "$pg_cid" POSTGRES_PASSWORD 2>/dev/null || true)"

    log INFO "Dumping ${db_name} into the ${kind} snapshot..."
    if docker exec -e PGPASSWORD="$admin_pass" "$pg_cid" \
         pg_dump -U "$db_user" -d "$db_name" -F c > "$dir/n8n_postgres_dump_${DATE}.dump" 2>/dev/null; then
        chmod 600 "$dir/n8n_postgres_dump_${DATE}.dump" 2>/dev/null || true
        log INFO "Snapshot DB dump written."
    else
        rm -f "$dir/n8n_postgres_dump_${DATE}.dump"
        log WARN "Snapshot DB dump failed; snapshot is config-only."
    fi

    printf '%s\n' "$dir"
    snapshot_keep_last "$root" 3
    return 0
}

################################################################################
# preview_restore_archive()
# Description:
#   Print what a restore is about to do, and gate it behind a confirmation.
#
# Args:
#   $1 -> extracted archive dir (contains .env.bak / docker-compose.yml.bak)
#   $2 -> the archive path or remote spec the user asked for (for display)
#
# Behaviors:
#   - Compares the archive's N8N_ENCRYPTION_KEY with the one currently live.
#     Three outcomes: same instance / DIFFERENT instance / no existing instance.
#     "Different" is the case that silently destroys every stored credential,
#     so it gets the loudest treatment.
#   - Prompts [y/N]. $FORCE_FLAG (-f) skips the prompt.
#   - With no TTY and no -f, refuses rather than assuming yes. A cron job must
#     opt in explicitly.
#
# Returns:
#   0 to proceed; 1 to abort.
################################################################################
preview_restore_archive() {
    local restore_dir="$1"
    local requested_spec="$2"

    local archive_key live_key archive_fqdn live_fqdn key_verdict
    archive_key="$(read_env_var "$restore_dir/.env.bak" N8N_ENCRYPTION_KEY || true)"
    archive_fqdn="$(read_env_var "$restore_dir/.env.bak" N8N_FQDN || true)"

    if [[ -f "$ENV_FILE" ]]; then
        live_key="$(read_env_var "$ENV_FILE" N8N_ENCRYPTION_KEY || true)"
        live_fqdn="$(read_env_var "$ENV_FILE" N8N_FQDN || true)"
    fi

    if [[ -z "${live_key:-}" ]]; then
        key_verdict="NO EXISTING INSTANCE (nothing to overwrite)"
    elif [[ "$archive_key" == "$live_key" ]]; then
        key_verdict="MATCH (same instance)"
    else
        key_verdict="DIFFERENT — credentials encrypted with the live key will NOT decrypt"
    fi

    echo "═════════════════════════════════════════════════════════════"
    echo "RESTORE PREVIEW — this replaces the live instance"
    box_line "Requested:"            "$requested_spec"
    box_line "Local archive:"        "$TARGET_RESTORE_FILE"
    box_line "Archive date:"         "$(date -r "$TARGET_RESTORE_FILE" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo unknown)"
    box_line "Archive domain:"       "${archive_fqdn:-unknown}"
    box_line "Live domain:"          "${live_fqdn:-none}"
    box_line "Encryption key:"       "$key_verdict"
    echo "═════════════════════════════════════════════════════════════"

    if [[ -n "${live_key:-}" && "$archive_key" != "$live_key" ]]; then
        log WARN "The archive was taken from a DIFFERENT instance."
        log WARN "Restoring it overwrites the live N8N_ENCRYPTION_KEY. Any credential"
        log WARN "still encrypted with the current key becomes unrecoverable."
    fi

    if [[ "${FORCE_FLAG:-false}" == true ]]; then
        log WARN "-f given; skipping the restore confirmation."
        return 0
    fi

    if [[ ! -t 0 ]]; then
        log ERROR "Restore needs confirmation but there is no terminal to ask on."
        log ERROR "Re-run with -f if you intend this to run unattended."
        return 1
    fi

    local reply=""
    read -r -p "Proceed with restore? [y/N]: " reply
    case "$reply" in
        y|Y|yes|YES) return 0 ;;
        *) log INFO "Restore cancelled. Nothing was changed."; return 1 ;;
    esac
}

################################################################################
# restore_stack()
# Description:
#   Restore the n8n stack from a backup archive (configs, volumes, database).
#
# Behaviors:
#   - Fetches remote archive if needed; extracts to temp dir.
#   - Validates .env.bak (with N8N_ENCRYPTION_KEY) and docker-compose.yml.bak,
#     then restores them to N8N_DIR and reloads env.
#   - Stops stack (compose down --remove-orphans), then explicitly removes/recreates volumes.
#   - If DB dump (*.dump or *.sql) present → skip postgres-data volume restore.
#   - Recreates and restores non-DB volumes from their tarballs.
#   - Starts postgres, waits healthy, then:
#       * For .dump → drop/create DB and pg_restore -c -v.
#       * For .sql  → drop/create DB and psql < file.
#       * If none   → assume DB came from restored volume.
#   - Starts remaining services (compose up -d), health-checks stack.
#   - Cleans temp files and prints aligned summary.
#
# Returns:
#   0 on success; non-zero on any failure.
################################################################################
restore_stack() {
    local requested_spec="$TARGET_RESTORE_FILE"

    # If it's a remote like "gdrive-user:n8n-backups/xxx.tar.gz", fetch it locally
    fetch_remote_if_needed || { log ERROR "Failed to fetch remote restore archive."; return 1; }

    # After fetch, TARGET_RESTORE_FILE should be a local path
    if [[ ! -f "$TARGET_RESTORE_FILE" ]]; then
        log ERROR "Restore file not found: $TARGET_RESTORE_FILE (requested: $requested_spec)"
        return 1
    fi

    log INFO "Starting restore at $DATE..."
    local restore_dir="$N8N_DIR/n8n_restore_$(date +%s)"
    mkdir -p "$restore_dir" || { log ERROR "Cannot create $restore_dir"; return 1; }

    log INFO "Extracting backup archive to $restore_dir"
    tar -xzf "$TARGET_RESTORE_FILE" -C "$restore_dir" \
        || { log ERROR "Failed to extract $TARGET_RESTORE_FILE"; return 1; }

    local backup_env_path="$restore_dir/.env.bak"
    local backup_compose_path="$restore_dir/docker-compose.yml.bak"

    if [[ ! -f "$backup_env_path" ]]; then
        log ERROR "Not found $backup_env_path. Aborting restore."
        return 1
    fi

    if [[ ! -f "$backup_compose_path" ]]; then
        log ERROR "Not found $backup_compose_path. Aborting restore."
        return 1
    fi

    # Verify N8N_ENCRYPTION_KEY is present in backup .env
    local n8n_encryption_key
    n8n_encryption_key="$(read_env_var "$backup_env_path" N8N_ENCRYPTION_KEY || true)"
    if [[ -z "$n8n_encryption_key" ]]; then
        log ERROR "$backup_env_path has no N8N_ENCRYPTION_KEY. Aborting restore."
        return 1
    fi

    if ! looks_like_b64 "$n8n_encryption_key"; then
        log WARN "N8N_ENCRYPTION_KEY in $backup_env_path doesn't look base64. Decryption may fail."
    fi
    log INFO "N8N_ENCRYPTION_KEY (masked): $(mask_secret "$n8n_encryption_key")"

    # ---- POINT OF NO RETURN -------------------------------------------------
    # Everything above this line only reads. Show the operator what is about to
    # happen, get a yes, and take a rescue copy - THEN start mutating. Doing the
    # .env overwrite first (as this function used to) meant a mistyped archive
    # path destroyed the live encryption key before anything had been checked.
    if ! preview_restore_archive "$restore_dir" "$requested_spec"; then
        rm -rf "$restore_dir"
        return 1
    fi

    local snap_dir
    if ! snap_dir="$(snapshot_current_state pre-restore)"; then
        log ERROR "Could not snapshot the current state; refusing to restore."
        rm -rf "$restore_dir"
        return 1
    fi
    log INFO "Pre-restore snapshot: $snap_dir"
    log INFO "If this restore goes wrong, the previous .env and compose are in that directory."

    log INFO "Restoring local-files directory..."
    shopt -s nullglob
    local lf_archives=("$restore_dir"/local-files_*.tar.gz)
    if (( ${#lf_archives[@]} > 0 )); then
        tar -xzf "${lf_archives[0]}" -C "$N8N_DIR" \
            || { log ERROR "Failed to restore local-files"; return 1; }
        log INFO "local-files directory restored"
    else
        log INFO "No local-files archive found, skipping..."
    fi
    shopt -u nullglob

    # Restore .env and docker-compose.yml
    cp -f "$backup_env_path" "$ENV_FILE"
    log INFO "Restored $backup_env_path to $ENV_FILE"
    cp -f "$backup_compose_path" "$COMPOSE_FILE"
    log INFO "Restored $backup_compose_path to $COMPOSE_FILE"

    # Reload restored .env so later steps (DOMAIN, etc.) reflect the restored config
    load_env_file
    discover_from_compose
    N8N_FQDN="$(read_env_var "$ENV_FILE" N8N_FQDN || true)"

    # Stop and remove the current containers before cleaning volumes
    log INFO "Stopping and removing containers before restore..."
    compose down --remove-orphans \
        || { log ERROR "docker compose down failed"; return 1; }

    # Check if we have a SQL database
    local dump_file=""
    local sql_file=""
    dump_file="$(find "$restore_dir" -name "n8n_postgres_dump_*.dump" -print -quit || true)"
    sql_file="$(find "$restore_dir" -name "n8n_postgres_dump_*.sql" -print -quit || true)"

    # List volumes to restore
    local RESTORE_VOLUMES=("${DISCOVERED_VOLUMES[@]}")
    if [[ -n "$dump_file" || -n "$sql_file" ]]; then
        log INFO "SQL dump present. Skipping postgres-data volume restore..."
        local filtered=()
        local v
        for v in "${RESTORE_VOLUMES[@]}"; do
            [[ "$v" == "postgres-data" ]] || filtered+=("$v")
        done
        RESTORE_VOLUMES=("${filtered[@]}")
    fi

    # Cleanup volumes to avoid DB conflict
    log INFO "Cleaning existing Docker volumes before restore..."
    local vol
    for vol in "${RESTORE_VOLUMES[@]}"; do
    if [[ "$vol" == "letsencrypt" ]]; then
        log INFO "Skipping volume '$vol' (TLS certs) during restore."
        continue
    fi
    local real
    real="$(resolve_volume_name "$vol" || expected_volume_name "$vol")"
    if docker volume inspect "$real" >/dev/null 2>&1; then
        docker volume rm "$real" && log INFO "Removed volume: $vol"
    else
        log INFO "Volume '$vol' not found, skipping..."
    fi
    done

    # Restore Docker volumes
    log INFO "Restoring volumes from archive..."
    for vol in "${RESTORE_VOLUMES[@]}"; do
    local vol_file
    vol_file="$(find "$restore_dir" -name "*${vol}_*.tar.gz" -print -quit || true)"
    if [[ -z "${vol_file:-}" ]]; then
        log ERROR "No backup found for volume $vol"
        return 1
    fi

    local real
    real="$(expected_volume_name "$vol")"
    docker volume create "$real" >/dev/null

    docker run --rm -v "${real}:/data" -v "$restore_dir:/backup" alpine \
        sh -c "find /data -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + \
        && tar xzf /backup/$(basename "$vol_file") -C /data" \
        || { log ERROR "Failed to restore $vol"; return 1; }

    log INFO "Volume $vol restored"
    done

    # Fix ownership for n8n data after restore (UID 1000 = node)
    if docker volume inspect "$(expected_volume_name n8n-data)" >/dev/null 2>&1; then
        log INFO "Fixing ownership on n8n-data volume (UID 1000)"
        docker run --rm -v "$(expected_volume_name n8n-data):/data" alpine \
          sh -c 'chown -R 1000:1000 /data || true'
    fi

    log INFO "Start working on $N8N_DIR ..."
    cd "$N8N_DIR" || { log ERROR "Failed to change directory to $N8N_DIR"; return 1; }

    log INFO "Starting PostgreSQL first..."
    # Recreate any external volumes the compose expects
    ensure_external_volumes
    compose up -d "$POSTGRES_SERVICE" \
        || { log ERROR "Failed to start postgres"; return 1; }

    log INFO "Waiting for postgres to be healthy..."
    check_container_healthy "$POSTGRES_SERVICE" || return 1

    # Database
    local PG_CID
    PG_CID="$(container_id_for_service "$POSTGRES_SERVICE")"
    if [[ -z "$PG_CID" ]]; then
        log ERROR "Could not resolve container ID for service '$POSTGRES_SERVICE'"
        return 1
    fi

    # Database variables
    local DB_USER="${DB_POSTGRESDB_USER:-${POSTGRES_USER:-n8n}}"
    local DB_NAME="${DB_POSTGRESDB_DATABASE:-${POSTGRES_DB:-n8n}}"
    local ADMIN_USER="${POSTGRES_USER:-postgres}"
    local ADMIN_PASS="$(_read_env_var_from_container "$PG_CID" POSTGRES_PASSWORD)"

    local POSTGRES_RESTORE_MODE=""
    log INFO "Recreating database ${DB_NAME}..."

    if [[ -n "$dump_file" ]]; then
        POSTGRES_RESTORE_MODE="dump"
        log INFO "Custom dump found: $(basename "$dump_file"). Restoring via pg_restore..."
        postgres_recreate_db "$PG_CID" "$ADMIN_USER" "$ADMIN_PASS" "$DB_NAME" "$DB_USER"
        docker exec -e PGPASSWORD="$ADMIN_PASS" -i "$PG_CID" pg_restore -U "$ADMIN_USER" -d "${DB_NAME}" -c -v < "$dump_file"
    elif [[ -n "$sql_file" ]]; then
        POSTGRES_RESTORE_MODE="sql"
        log INFO "SQL dump found: $(basename "$sql_file"). Restoring via psql..."
        postgres_recreate_db "$PG_CID" "$ADMIN_USER" "$ADMIN_PASS" "$DB_NAME" "$DB_USER"
        docker exec -e PGPASSWORD="$ADMIN_PASS" -i "$PG_CID" psql -U "$ADMIN_USER" -d "${DB_NAME}" -v ON_ERROR_STOP=1 < "$sql_file"
    else
        POSTGRES_RESTORE_MODE="volume"
        log INFO "No SQL dump found. Assuming the postgres-data volume already contains the DB. Skipping SQL import."
    fi

    # When the PostgreSQL DB is ready, start other containers
    log INFO "Starting the rest of the stack..."
    ensure_external_volumes  # called again after DB restore — volumes may have been re-created

    docker_up_check || { log ERROR "Stack unhealthy after restore."; exit 1; }
    post_up_tls_checks || true

    log INFO "Cleaning up..."
    rm -rf "$restore_dir"
    # Optional: clean up any fetched temp archive
    if [[ -d "$BACKUP_DIR/_restore_tmp" ]]; then
        # Only remove files we created; ignore user local archives
        find "$BACKUP_DIR/_restore_tmp" -type f -name '*n8n_backup_*.tar.gz' -delete || true
        rmdir "$BACKUP_DIR/_restore_tmp" 2>/dev/null || true
    fi

    N8N_VERSION="$(get_current_n8n_version)"
    local restored_list=""
    if ((${#RESTORE_VOLUMES[@]})); then
        restored_list=$(printf '%s, ' "${RESTORE_VOLUMES[@]}")
        restored_list=${restored_list%, }
    else
        restored_list="(none)"
    fi

    echo "═════════════════════════════════════════════════════════════"
    echo "Restore completed successfully."
    box_line "Detected Mode:"           "${DISCOVERED_MODE:-unknown}"
    box_line "Domain (n8n):"            "https://${N8N_FQDN}"
    box_line "Restore from file:"       "$requested_spec"
    box_line "Local archive used:"      "$TARGET_RESTORE_FILE"
    box_line "Restore Timestamp:"       "$DATE"
    box_line "N8N Version:"             "$N8N_VERSION"
    box_line "N8N Directory:"           "$N8N_DIR"
    box_line "Log File:"                "$LOG_FILE"
    box_line "Volumes restored:"        "${restored_list}"
    case "$POSTGRES_RESTORE_MODE" in
        dump) box_line "PostgreSQL:" "Restored from custom dump (.dump)";;
        sql)  box_line "PostgreSQL:" "Restored from SQL file (.sql)";;
        *)    box_line "PostgreSQL:" "Restored from volume";;
    esac
    echo "═════════════════════════════════════════════════════════════"
}
