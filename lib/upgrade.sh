#!/usr/bin/env bash
# lib/upgrade.sh — Upgrade stack functions
# Sourced by n8n_manager.sh — do not execute directly.
# shellcheck disable=SC2154  # Variables set by n8n_manager.sh globals

################################################################################
# upgrade_stack()
# Description:
#   Upgrade (or force re-deploy/downgrade with -f) the running n8n stack.
#
# Behaviors:
#   - Detects current n8n version; resolves target:
#       * explicit -v, else latest stable via get_latest_n8n_version()
#   - Prevents downgrades unless --force; prevents no-op redeploy unless --force.
#   - Validates target tag with validate_image_tag().
#   - Writes the image tag to .env under the name the deployed compose reads
#     (N8N_IMAGE_TAG, or N8N_VERSION for pre-v3.1 compose copies); compose down.
#   - Re-validates compose/env; brings stack up; waits for health & TLS.
#   - Prints a summary on success.
#
# Returns:
#   0 on success; exits non-zero on validation/health failures.
################################################################################
upgrade_stack() {
    [[ -f "$ENV_FILE" && -f "$COMPOSE_FILE" ]] || { log ERROR "Compose/.env not found in $N8N_DIR"; exit 1; }

    # Snapshot the requested tag BEFORE load_env_file: that call sources .env with
    # allexport, so a legacy .env carrying N8N_VERSION= would silently overwrite -v.
    local requested_version="${N8N_VERSION:-latest}"
    load_env_file
    ensure_monitoring_auth
    N8N_FQDN="$(read_env_var "$ENV_FILE" N8N_FQDN || true)"

    log INFO "Checking current and target n8n versions..."
    local current_version target_version
    current_version=$(get_current_n8n_version || echo "0.0.0")
    target_version="$(resolve_n8n_target_version "$requested_version")" || exit 1
    log INFO "Current version: $current_version  ->  Target version: $target_version"

    if [[ "$(printf "%s\n%s" "$target_version" "$current_version" | sort -V | head -n1)" == "$target_version" \
          && "$target_version" != "$current_version" \
          && "$FORCE_FLAG" != true ]]; then
        log INFO "Target ($target_version) <= current ($current_version). Use -f to force downgrade."
        exit 0
    fi

    if [[ "$target_version" == "$current_version" && "$FORCE_FLAG" != true ]]; then
        log INFO "Already on $current_version. Use -f to force redeploy."
        exit 0
    fi

    local tag_var; tag_var="$(compose_image_tag_var "$COMPOSE_FILE")"
    log INFO "Updating .env with ${tag_var}=$target_version"
    upsert_env_var "$tag_var" "$target_version" "$ENV_FILE"

    # Writing the file is not enough. load_env_file() above sourced .env with
    # allexport, so the OLD tag is still exported in this process - and Docker
    # Compose resolves shell environment variables ahead of --env-file. Without
    # this the stack comes back up on the version it was already running, while
    # .env and the summary both claim the new one.
    export "${tag_var}=${target_version}"

    if snapshot_current_state pre-upgrade; then
        log INFO "Pre-upgrade snapshot: $SNAPSHOT_DIR"
        log INFO "Roll back with: n8n_manager.sh -r <archive>  (config copy is in that directory)"
    else
        log WARN "Pre-upgrade snapshot failed; continuing without a rescue copy."
    fi

    log INFO "Stopping and removing existing containers..."
    compose down --remove-orphans || true

    validate_compose_and_env
    discover_from_compose

    docker_up_check || { log ERROR "Stack unhealthy after upgrade."; exit 1; }
    post_up_tls_checks || true

    local running_version
    running_version="$(get_current_n8n_version)"
    if [[ "$running_version" != "$target_version" ]]; then
        log ERROR "Upgrade did not take: asked for $target_version, running $running_version."
        log ERROR "The stack is up but on the wrong version. Roll back with the pre-upgrade snapshot if needed."
        return 1
    fi

    echo "═════════════════════════════════════════════════════════════"
    echo "N8N has been successfully upgraded!"
    box_line "Detected Mode:"           "${DISCOVERED_MODE:-unknown}"
    box_line "Domain (n8n):"            "https://${N8N_FQDN}"
    box_line "Upgraded Version:"        "$running_version"
    box_line "Upgraded Timestamp:"      "${DATE}"
    box_line "Upgraded By:"             "${SUDO_USER:-$USER}"
    box_line "Target Directory:"        "${N8N_DIR}"
    box_line "Execution log:"           "${LOG_FILE}"
    echo "═════════════════════════════════════════════════════════════"
}
