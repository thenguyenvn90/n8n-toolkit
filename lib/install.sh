#!/usr/bin/env bash
# lib/install.sh — Install stack functions
# Sourced by n8n_manager.sh — do not execute directly.
# shellcheck disable=SC2154  # Variables set by n8n_manager.sh globals

################################################################################
# copy_templates_for_mode()
# Description:
#   Copy docker-compose.yml and .env from the selected template (single|queue).
#
# Behaviors:
#   - Backs up existing files with timestamp.
#   - Updates DOMAIN, SSL_EMAIL, N8N_IMAGE_TAG in .env.
#   - Generates STRONG_PASSWORD and N8N_ENCRYPTION_KEY if placeholders found.
#
# Returns:
#   0 on success; exits non-zero on missing templates.
################################################################################
copy_templates_for_mode() {
    local src_dir=""
    case "$INSTALL_MODE" in
        single) src_dir="$TEMPLATE_SINGLE" ;;
        queue)  src_dir="$TEMPLATE_QUEUE"  ;;
        *) log ERROR "--mode must be 'single' or 'queue'"; exit 2 ;;
    esac

    if [[ ! -f "$src_dir/docker-compose.yml" ]]; then
        log ERROR "docker-compose.yml not found at $src_dir"
        exit 1
    fi

    if [[ ! -f "$src_dir/.env" ]]; then
        log ERROR ".env file not found at $src_dir"
        exit 1
    fi

    for f in docker-compose.yml .env; do
        [[ -f "$N8N_DIR/$f" ]] && cp -a "$N8N_DIR/$f" "$N8N_DIR/${f}.bak.$(date +%F_%H-%M-%S)"
        cp -a "$src_dir/$f" "$N8N_DIR/$f"
    done

    # Update .env
    log INFO "Updating DOMAIN=$DOMAIN in $ENV_FILE"
    upsert_env_var "DOMAIN" "$DOMAIN" "$ENV_FILE"

    log INFO "Updating SSL_EMAIL=$SSL_EMAIL in $ENV_FILE"
    [[ -n "${SSL_EMAIL:-}" ]] && upsert_env_var "SSL_EMAIL" "$SSL_EMAIL" "$ENV_FILE"

    # Resolve target version: explicit -v wins; else latest stable
    local target_version
    target_version="$(resolve_n8n_target_version "$N8N_VERSION")" || exit 1
    log INFO "Updating N8N_IMAGE_TAG=$target_version in $ENV_FILE"
    upsert_env_var "N8N_IMAGE_TAG" "$target_version" "$ENV_FILE"

    # Rotate SECRETS in env if missing/default
    rotate_or_generate_secret "$ENV_FILE" POSTGRES_PASSWORD        16 "CHANGE_ME_BASE64_16_BYTES"
    rotate_or_generate_secret "$ENV_FILE" N8N_BASIC_AUTH_PASSWORD  16 "CHANGE_ME_BASE64_16_BYTES"
    rotate_or_generate_secret "$ENV_FILE" N8N_RUNNERS_AUTH_TOKEN   16 "CHANGE_ME_BASE64_16_BYTES"
    rotate_or_generate_secret "$ENV_FILE" N8N_ENCRYPTION_KEY       32 "CHANGE_ME_BASE64_32_BYTES"

    # Queue mode only
    if [[ "${INSTALL_MODE:-single}" == "queue" ]]; then
        rotate_or_generate_secret "$ENV_FILE" REDIS_PASSWORD        16 "CHANGE_ME_BASE64_16_BYTES"
    fi

    # Subdomains & monitoring flags persisted in .env
    [[ -n "$SUBDOMAIN_N8N" ]]        && upsert_env_var "SUBDOMAIN_N8N" "$SUBDOMAIN_N8N" "$ENV_FILE"
    [[ -n "$SUBDOMAIN_GRAFANA" ]]    && upsert_env_var "SUBDOMAIN_GRAFANA" "$SUBDOMAIN_GRAFANA" "$ENV_FILE"
    [[ -n "$SUBDOMAIN_PROMETHEUS" ]] && upsert_env_var "SUBDOMAIN_PROMETHEUS" "$SUBDOMAIN_PROMETHEUS" "$ENV_FILE"

    if $MONITORING; then
        upsert_env_var "COMPOSE_PROFILES" "monitoring" "$ENV_FILE"
        local mon_src="$SCRIPT_DIR/monitoring"
        local mon_dst="$N8N_DIR/monitoring"
        if [[ -d "$mon_src" ]]; then
            mkdir -p "$mon_dst"
            cp -a "$mon_src/." "$mon_dst/"
            log INFO "Copied monitoring assets into $mon_dst"
            if [[ ! -f "$mon_dst/prometheus.yml" ]]; then
                log ERROR "Expected file not found: $mon_dst/prometheus.yml (is it missing or a directory?)"
                exit 1
            fi
        else
            log WARN "Monitoring enabled but $mon_src not found; Prometheus/Grafana may fail to start."
        fi
    else
        upsert_env_var "COMPOSE_PROFILES" "" "$ENV_FILE"
    fi

    # Ensure Traefik basic auth variables are consistent (always run)
    ensure_monitoring_auth

    if $EXPOSE_PROMETHEUS; then
        upsert_env_var "EXPOSE_PROMETHEUS" "true" "$ENV_FILE"
    else
        upsert_env_var "EXPOSE_PROMETHEUS" "false" "$ENV_FILE"
    fi

    # persist explicit FQDNs
    local base_dom sub_n8n sub_graf sub_prom
    base_dom="$(read_env_var "$ENV_FILE" DOMAIN)"
    sub_n8n="$(read_env_var "$ENV_FILE" SUBDOMAIN_N8N)"
    sub_graf="$(read_env_var "$ENV_FILE" SUBDOMAIN_GRAFANA)"
    sub_prom="$(read_env_var "$ENV_FILE" SUBDOMAIN_PROMETHEUS)"

    sub_n8n="${sub_n8n:-n8n}"
    sub_graf="${sub_graf:-grafana}"
    sub_prom="${sub_prom:-prometheus}"

    N8N_FQDN="${sub_n8n:+$sub_n8n.}${base_dom}"
    GRAFANA_FQDN="${sub_graf:+$sub_graf.}${base_dom}"
    PROMETHEUS_FQDN="${sub_prom:+$sub_prom.}${base_dom}"

    upsert_env_var "N8N_FQDN" "$N8N_FQDN" "$ENV_FILE"
    upsert_env_var "GRAFANA_FQDN" "$GRAFANA_FQDN" "$ENV_FILE"
    upsert_env_var "PROMETHEUS_FQDN" "$PROMETHEUS_FQDN" "$ENV_FILE"

    # Secure secrets file
    chmod 600 "$ENV_FILE" || true
    chmod 640 "$COMPOSE_FILE" || true
}

################################################################################
# install_stack()
# Description:
#   Orchestrate a fresh installation of the n8n stack behind Traefik/LE.
#
# Behaviors:
#   - --mode is optional; defaults to 'single'.
#   - Prompts for SSL_EMAIL if missing.
#   - Verifies DOMAIN DNS points to this host (check_domain()).
#   - Installs Docker/Compose and dependencies (ensure_prereqs()).
#   - Prepares compose + .env with pinned version and secrets (copy_templates_for_mode()).
#   - Validates compose/env (validate_compose_and_env()).
#   - Creates volumes as needed and starts stack (docker_up_check()).
#   - Waits for containers and TLS to be healthy.
#   - Prints a summary on success.
#
# Returns:
#   0 on success; exits non-zero if any step fails.
################################################################################
install_stack() {
    [[ -n "$DOMAIN" ]] || { log ERROR "Install requires a base domain."; exit 2; }

    log INFO "Starting N8N installation for base domain: $DOMAIN"
    ensure_prereqs
    copy_templates_for_mode
    load_env_file
    preflight_dns_checks
    validate_compose_and_env
    discover_from_compose
    ensure_external_volumes
    [[ "$INSTALL_MODE" == "queue" ]] && DISCOVERED_MODE="queue"

    docker_up_check || { log ERROR "Stack unhealthy after install."; exit 1; }
    post_up_tls_checks || true

    # Summary
    local graf_fqdn prom_fqdn expose_prom compose_profiles
    graf_fqdn="$(read_env_var "$ENV_FILE" GRAFANA_FQDN || true)"
    prom_fqdn="$(read_env_var "$ENV_FILE" PROMETHEUS_FQDN || true)"
    expose_prom="$(read_env_var "$ENV_FILE" EXPOSE_PROMETHEUS || echo false)"
    compose_profiles="$(read_env_var "$ENV_FILE" COMPOSE_PROFILES || true)"

    echo "═════════════════════════════════════════════════════════════"
    echo "N8N has been successfully installed!"
    box_line "Installation Mode:"       "$INSTALL_MODE"
    box_line "Domain (n8n):"           "https://${N8N_FQDN}"
    if [[ "$compose_profiles" == *monitoring* ]]; then
        box_line "Grafana:"             "https://${graf_fqdn}"
        if [[ "${expose_prom,,}" == "true" ]]; then
            box_line "Prometheus:"      "https://${prom_fqdn}"
        else
            box_line "Prometheus:"      "(internal only)"
        fi
    fi
    box_line "Installed Version:"       "$(get_current_n8n_version)"
    box_line "Install Timestamp:"       "${DATE}"
    box_line "Installed By:"            "${SUDO_USER:-$USER}"
    box_line "Target Directory:"        "${N8N_DIR}"
    box_line "SSL Email:"               "${SSL_EMAIL:-N/A}"
    box_line "Execution log:"           "${LOG_FILE}"
    echo "═════════════════════════════════════════════════════════════"
}
