#!/usr/bin/env bash
# lib/doctor.sh — One-command diagnosis: health, security, legacy config.
# Sourced by n8n_manager.sh — do not execute directly.
# shellcheck disable=SC2154  # Variables set by n8n_manager.sh globals

################################################################################
# Why one command and not two
#
# People do not open an issue saying "the toolkit is broken". They open one
# saying "the container will not start" (see issue #2). They paste ONE output,
# not two, so health and security live together with a verdict on top.
#
# Every finding is recorded, then the summary is printed first, so the reader
# sees FAIL/WARN/PASS counts before scrolling.
################################################################################

# Collected findings: "STATUS|SECTION|TITLE|DETAIL"
declare -a DOCTOR_FINDINGS=()
DOCTOR_FAIL=0
DOCTOR_WARN=0
DOCTOR_PASS=0

################################################################################
# CVE floors, taken from the NVD records rather than press coverage.
# versionEndExcluding is the first fixed release.
#
#   CVE-2026-21858  CVSS 10.0  fixed in 1.121.0
#   CVE-2026-25049  CVSS  9.9  fixed in 1.123.17 / 2.5.2
#   CVE-2026-27493  CVSS  9.0  fixed in 1.123.22 / 2.9.3 / 2.10.1
#
# The highest floor per release line is what matters. Retrieved 2026-08-26 from
# services.nvd.nist.gov. Getting this wrong reports a vulnerable instance as
# safe, so it is pinned here with its source and nowhere else.
################################################################################
readonly DOCTOR_CVE_FLOOR_1X="1.123.22"
readonly DOCTOR_CVE_FLOOR_2X="2.10.1"

################################################################################
# doctor_record()
# Args: $1 status (PASS|WARN|FAIL) · $2 section · $3 title · $4 detail
################################################################################
doctor_record() {
    local status="$1" section="$2" title="$3" detail="${4:-}"
    DOCTOR_FINDINGS+=("${status}|${section}|${title}|${detail}")
    case "$status" in
        # x=$((x+1)), not ((x++)): post-increment returns the OLD value, so
        # ((x++)) exits 1 when x is 0 and takes the caller down under set -e.
        FAIL) DOCTOR_FAIL=$((DOCTOR_FAIL + 1)) ;;
        WARN) DOCTOR_WARN=$((DOCTOR_WARN + 1)) ;;
        *)    DOCTOR_PASS=$((DOCTOR_PASS + 1)) ;;
    esac
}

################################################################################
# version_lt()
# Description:
#     True when $1 is an earlier version than $2, by version-sort.
# Returns:
#     0 if $1 < $2; 1 otherwise (including equal).
################################################################################
version_lt() {
    [[ "$1" == "$2" ]] && return 1
    [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$1" ]]
}

################################################################################
# doctor_check_health()
################################################################################
doctor_check_health() {
    local sec="Health"

    if [[ -f "$COMPOSE_FILE" && -f "$ENV_FILE" ]]; then
        doctor_record PASS "$sec" "Stack files present" "$N8N_DIR"
    else
        doctor_record FAIL "$sec" "Stack files missing" \
            "Expected docker-compose.yml and .env in $N8N_DIR"
        return 0
    fi

    doctor_record PASS "$sec" "Deployment mode" "${DISCOVERED_MODE:-unknown}"

    local ver
    ver="$(get_current_n8n_version)"
    if [[ "$ver" == "0.0.0" ]]; then
        doctor_record FAIL "$sec" "n8n is not answering" \
            "Could not read a version from the main container. Is the stack up?"
    else
        doctor_record PASS "$sec" "n8n version" "$ver"
    fi

    # Container health, per discovered service.
    local svc cid state health unhealthy=0 missing=0
    for svc in "${DISCOVERED_SERVICES[@]}"; do
        cid="$(container_id_for_service "$svc" 2>/dev/null || true)"
        if [[ -z "$cid" ]]; then
            missing=$((missing + 1))
            continue
        fi
        state="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo unknown)"
        health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$cid" 2>/dev/null || echo none)"
        if [[ "$state" != "running" ]] || [[ "$health" == "unhealthy" ]]; then
            unhealthy=$((unhealthy + 1))
            doctor_record FAIL "$sec" "Service '$svc' is $state/$health" \
                "docker logs $(container_name_for_service "$svc" 2>/dev/null || echo "$cid")"
        fi
    done
    (( missing == 0 )) || doctor_record WARN "$sec" "$missing service(s) not running" \
        "Compose defines them but no container exists"
    if (( unhealthy == 0 )); then doctor_record PASS "$sec" "All running services healthy" ""; fi

    # Disk. A backup that runs out of space mid-archive is a bad way to find out.
    local avail_kb avail_h
    avail_kb="$(df -Pk "$N8N_DIR" 2>/dev/null | awk 'NR==2{print $4}')"
    avail_h="$(df -Ph "$N8N_DIR" 2>/dev/null | awk 'NR==2{print $4}')"
    if [[ -n "$avail_kb" ]] && (( avail_kb < 2097152 )); then
        doctor_record WARN "$sec" "Low disk space" "$avail_h free on $N8N_DIR; a backup may not fit"
    elif [[ -n "$avail_kb" ]]; then
        doctor_record PASS "$sec" "Disk space" "$avail_h free"
    fi
}

################################################################################
# doctor_check_security()
################################################################################
doctor_check_security() {
    local sec="Security"
    [[ -f "$ENV_FILE" ]] || return 0

    # Encryption key. If this is still a placeholder, every credential in the
    # database is protected by a value published in this repository.
    local key
    key="$(read_env_var "$ENV_FILE" N8N_ENCRYPTION_KEY || true)"
    if [[ -z "$key" ]]; then
        doctor_record FAIL "$sec" "N8N_ENCRYPTION_KEY is not set" "Credentials cannot be decrypted without it"
    elif [[ "$key" == CHANGE_ME* ]]; then
        doctor_record FAIL "$sec" "N8N_ENCRYPTION_KEY is still the shipped placeholder" \
            "Anyone with this repository can decrypt your credentials"
    else
        doctor_record PASS "$sec" "N8N_ENCRYPTION_KEY is set" "$(mask_secret "$key")"
    fi

    # .env holds every secret the instance has.
    local perms
    perms="$(stat -c '%a' "$ENV_FILE" 2>/dev/null || echo unknown)"
    if [[ "$perms" =~ ^[0-9]+$ ]] && (( perms > 600 )); then
        doctor_record WARN "$sec" ".env is world- or group-readable" "mode $perms; chmod 600 $ENV_FILE"
    elif [[ "$perms" != unknown ]]; then
        doctor_record PASS "$sec" ".env permissions" "mode $perms"
    fi

    # Known-vulnerable n8n. Floors come from NVD, see the header.
    local ver floor
    ver="$(get_current_n8n_version)"
    if [[ "$ver" == "0.0.0" ]]; then
        doctor_record WARN "$sec" "Cannot check the n8n version against known CVEs" "n8n is not answering"
    else
        case "$ver" in
            2.*) floor="$DOCTOR_CVE_FLOOR_2X" ;;
            1.*) floor="$DOCTOR_CVE_FLOOR_1X" ;;
            *)   floor="" ;;
        esac
        if [[ -z "$floor" ]]; then
            doctor_record FAIL "$sec" "n8n $ver predates the 1.x line" "Upgrade; it is years behind security fixes"
        elif version_lt "$ver" "$floor"; then
            doctor_record FAIL "$sec" "n8n $ver is below the CVE patch floor ($floor)" \
                "CVE-2026-21858 (10.0), CVE-2026-25049 (9.9), CVE-2026-27493 (9.0). Run: n8n_manager.sh -u"
        else
            doctor_record PASS "$sec" "n8n $ver is at or above the CVE patch floor" "floor $floor"
        fi
    fi

    # n8n published straight to the host bypasses Traefik, its TLS and its
    # rate limit. This is how instances end up on Shodan.
    local published
    published="$(docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null | grep -E '0\.0\.0\.0:[0-9]+->5678' || true)"
    if [[ -n "$published" ]]; then
        doctor_record FAIL "$sec" "n8n's port is published on all interfaces" \
            "$published — this bypasses Traefik, its TLS and its rate limit"
    else
        doctor_record PASS "$sec" "n8n is reachable only through Traefik" ""
    fi

    # GitGuardian found 321 live instances via tokens leaked in public commits.
    if [[ -d "$N8N_DIR/.git" ]]; then
        if git -C "$N8N_DIR" ls-files --error-unmatch .env >/dev/null 2>&1; then
            doctor_record FAIL "$sec" ".env is tracked by git" \
                "Every secret in it is in your history. Untrack it and rotate."
        else
            doctor_record PASS "$sec" ".env is not tracked by git" ""
        fi
    fi

    # Backups carry .env and a full database dump.
    local remote enc_archives
    remote="$(read_env_var "$ENV_FILE" RCLONE_REMOTE || true)"
    if [[ -n "${RCLONE_REMOTE:-}${remote:-}" ]]; then
        enc_archives="$(find "$BACKUP_DIR" -maxdepth 1 -name '*.tar.gz.gpg' -print -quit 2>/dev/null || true)"
        if [[ -n "$enc_archives" ]]; then
            doctor_record PASS "$sec" "Backups are encrypted before upload" ""
        else
            doctor_record WARN "$sec" "Backups are uploaded unencrypted" \
                "The archive holds .env and a full DB dump. Use --encrypt with BACKUP_PASSPHRASE; required from v3.5.0."
        fi
    fi

    # Alert rules with nowhere to fire are decoration.
    if [[ -d "$N8N_DIR/monitoring/grafana/provisioning/alerts" ]]; then
        if [[ -f "$N8N_DIR/monitoring/grafana/provisioning/alerting/contactpoints.yaml" ]]; then
            doctor_record PASS "$sec" "Grafana alerts have a delivery channel" ""
        else
            doctor_record WARN "$sec" "Grafana alert rules have no contact point" \
                "They evaluate and notify nobody. Set one with --alerts telegram --alert-target ..."
        fi
    fi
}

################################################################################
# doctor_check_legacy()
################################################################################
doctor_check_legacy() {
    local sec="Legacy"
    [[ -f "$ENV_FILE" ]] || return 0

    if grep -q "^N8N_BASIC_AUTH_" "$ENV_FILE" 2>/dev/null; then
        doctor_record WARN "$sec" "N8N_BASIC_AUTH_* is present in .env" \
            "n8n removed basic auth in 1.0 and ignores these. They protect nothing."
    else
        doctor_record PASS "$sec" "No dead basic-auth keys" ""
    fi

    if [[ -f "$COMPOSE_FILE" ]] && [[ "$(compose_image_tag_var "$COMPOSE_FILE")" == "N8N_VERSION" ]]; then
        doctor_record WARN "$sec" "compose still reads \${N8N_VERSION}" \
            "Pre-v3.1 template. Upgrades work, but refresh it to match the current one."
    fi

    if [[ -f "$N8N_DIR/docker-compose.local.yml" ]]; then
        doctor_record WARN "$sec" "This instance is running in --local mode" \
            "Self-signed TLS, no Let's Encrypt. Fine locally, not for a public server."
    fi
}

################################################################################
# doctor_check_webhooks()
# Description:
#     For every active workflow, is there a matching row in webhook_entity?
#
#     This is the diagnostic for issue #1 (production form URLs returning 404).
#     An active workflow whose webhook never registered answers 404 on /form/
#     and /webhook/ while the UI shows it live, and nothing else surfaces that.
################################################################################
doctor_check_webhooks() {
    local sec="Webhooks"
    local cid
    cid="$(container_id_for_service "$POSTGRES_SERVICE" 2>/dev/null || true)"
    [[ -n "$cid" ]] || { doctor_record WARN "$sec" "Skipped" "PostgreSQL is not running"; return 0; }

    local db_user db_name pass
    db_user="$(read_env_var "$ENV_FILE" DB_POSTGRESDB_USER || echo n8n)"
    db_name="$(read_env_var "$ENV_FILE" DB_POSTGRESDB_DATABASE || echo n8n)"
    pass="$(_read_env_var_from_container "$cid" POSTGRES_PASSWORD 2>/dev/null || true)"

    local active hooks
    active="$(docker exec -e PGPASSWORD="$pass" "$cid" psql -tAq -U "$db_user" -d "$db_name" \
        -c 'select count(*) from workflow_entity where active = true;' 2>/dev/null | tr -d '[:space:]')"
    hooks="$(docker exec -e PGPASSWORD="$pass" "$cid" psql -tAq -U "$db_user" -d "$db_name" \
        -c 'select count(distinct "workflowId") from webhook_entity;' 2>/dev/null | tr -d '[:space:]')"

    if [[ ! "$active" =~ ^[0-9]+$ || ! "$hooks" =~ ^[0-9]+$ ]]; then
        doctor_record WARN "$sec" "Could not query the workflow tables" "psql did not return counts"
        return 0
    fi

    if (( active == 0 )); then
        doctor_record PASS "$sec" "No active workflows" ""
    elif (( hooks == 0 )); then
        doctor_record WARN "$sec" "$active active workflow(s), none with a registered webhook" \
            "Normal if none of them are webhook- or form-triggered. Otherwise production URLs will 404."
    else
        doctor_record PASS "$sec" "$hooks of $active active workflow(s) have registered webhooks" \
            "A trigger-based workflow missing here answers 404 on its production URL"
    fi
}

################################################################################
# doctor_report()
# Description:
#     Print the verdict first, then the detail, then a paste-ready block.
################################################################################
doctor_report() {
    local verdict="PASS"
    (( DOCTOR_WARN > 0 )) && verdict="WARN"
    (( DOCTOR_FAIL > 0 )) && verdict="FAIL"

    echo "═════════════════════════════════════════════════════════════"
    echo "n8n-toolkit doctor — ${verdict}   (${DOCTOR_FAIL} fail · ${DOCTOR_WARN} warn · ${DOCTOR_PASS} pass)"
    echo "═════════════════════════════════════════════════════════════"

    local current_section="" line status section title detail
    for line in "${DOCTOR_FINDINGS[@]}"; do
        IFS='|' read -r status section title detail <<< "$line"
        if [[ "$section" != "$current_section" ]]; then
            echo
            echo "── $section ──"
            current_section="$section"
        fi
        printf '  [%-4s] %s\n' "$status" "$title"
        [[ -n "$detail" ]] && printf '         %s\n' "$detail"
    done

    echo
    echo "--- paste this into your issue ---"
    echo "toolkit:  ${TOOLKIT_VERSION:-unknown}"
    echo "n8n:      $(get_current_n8n_version)"
    echo "mode:     ${DISCOVERED_MODE:-unknown}"
    echo "docker:   $(docker --version 2>/dev/null || echo unavailable)"
    echo "compose:  $(docker compose version --short 2>/dev/null || echo unavailable)"
    echo "os:       $(uname -srm 2>/dev/null || echo unknown)"
    echo "verdict:  ${verdict} (${DOCTOR_FAIL} fail, ${DOCTOR_WARN} warn, ${DOCTOR_PASS} pass)"
    for line in "${DOCTOR_FINDINGS[@]}"; do
        IFS='|' read -r status section title detail <<< "$line"
        [[ "$status" == "PASS" ]] && continue
        echo "  ${status} ${section}: ${title}"
    done
    echo "--- end ---"
    echo
    echo "No secret values are printed above; keys are masked."
}

################################################################################
# doctor_stack()
# Description:
#     Entry point for --doctor. Read-only: it inspects and reports, and changes
#     nothing. A user's .env is theirs; this names the problem and the fix.
#
# Returns:
#     0 when nothing failed; 1 when at least one check failed.
################################################################################
doctor_stack() {
    DOCTOR_FINDINGS=(); DOCTOR_FAIL=0; DOCTOR_WARN=0; DOCTOR_PASS=0

    load_env_file
    discover_from_compose 2>/dev/null || true
    detect_mode_runtime 2>/dev/null || true

    doctor_check_health
    doctor_check_security
    doctor_check_legacy
    doctor_check_webhooks

    doctor_report
    (( DOCTOR_FAIL == 0 ))
}
