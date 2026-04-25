#!/usr/bin/env bash
# lib/cleanup.sh — Cleanup stack functions
# Sourced by n8n_manager.sh — do not execute directly.
# shellcheck disable=SC2154  # Variables set by n8n_manager.sh globals

################################################################################
# cleanup_stack()
#
# Purpose
#   Tear down the n8n Docker stack and remove project resources with two
#   levels of aggressiveness, while clearly previewing what will be deleted.
#
# Modes
#   safe (default via CLEANUP_MODE=safe)
#     - Runs `docker compose down --remove-orphans`
#     - Deletes named project volumes EXCEPT `letsencrypt`
#       (preserves TLS certs to avoid Let's Encrypt rate limits)
#     - Removes discovered project Docker networks
#     - Prunes dangling images (`docker image prune -f`)
#     - Keeps base images (n8nio/n8n, docker.n8n.io/n8nio/n8n, postgres)
#     - Does NOT wipe files in $N8N_DIR
#
#   all  (CLEANUP_MODE=all)
#     - Runs `docker compose down --remove-orphans -v` (also drops anonymous vols)
#     - Deletes ALL named project volumes, including `letsencrypt`
#     - Removes discovered project Docker networks
#     - Prunes dangling images AND removes base images (n8n + postgres)
#     - Wipes the project directory $N8N_DIR (via safe_wipe_target_dir)
#     - Prompts for a yes/no confirmation before executing
#
# What it does (high level)
#   1) Discovers compose-defined volumes and networks
#   2) Builds the exact deletion sets (volumes, networks, images, dir entries)
#   3) Prints a PREVIEW block showing every item that will be removed
#   4) If mode = all, asks for interactive confirmation (yes/no)
#   5) Executes the plan:
#        - docker compose down (with flags per mode)
#        - docker volume rm <named volumes>
#        - docker network rm <project networks>
#        - docker image prune -f
#        - (all) docker rmi -f <base images by ID>
#        - (all) safe_wipe_target_dir
################################################################################
cleanup_stack() {
    discover_from_compose
    discover_compose_networks || true

    local MODE="${CLEANUP_MODE:-safe}"
    local NUKE_ALL=false
    case "$MODE" in
        safe) NUKE_ALL=false ;;
        all)  NUKE_ALL=true  ;;
        *)    log ERROR "cleanup mode must be 'safe' or 'all', got '$MODE'"; exit 2 ;;
    esac

    # Flags for compose down
    local -a DOWN_FLAGS=(--remove-orphans)
    $NUKE_ALL && DOWN_FLAGS+=(-v)   # in ALL, also remove anonymous volumes

    # ---------- Determine resources to delete (preview) ----------

    # Volumes (named)
    local -a VOLS_TO_REMOVE=()      # logical names from compose
    local -a VOLS_EXISTING=()       # "logical|real" only if they currently exist
    if $NUKE_ALL; then
        VOLS_TO_REMOVE=("${DISCOVERED_VOLUMES[@]}")
    else
        local v
        for v in "${DISCOVERED_VOLUMES[@]}"; do
            [[ "$v" == "letsencrypt" ]] && continue
            VOLS_TO_REMOVE+=("$v")
        done
    fi
    # Map to real docker volume names and keep only those that exist
    if ((${#VOLS_TO_REMOVE[@]})); then
        local vname real
        for vname in "${VOLS_TO_REMOVE[@]}"; do
            real="$(resolve_volume_name "$vname" || expected_volume_name "$vname")"
            if docker volume inspect "$real" >/dev/null 2>&1; then
                VOLS_EXISTING+=("$vname|$real")
            fi
        done
    fi

    # Networks
    local -a NETS_TO_REMOVE=()
    if ((${#DISCOVERED_NETWORKS[@]})); then
        NETS_TO_REMOVE=("${DISCOVERED_NETWORKS[@]}")
    else
        local defnet
        defnet="$(project_default_network_name)"
        if [[ -n "$defnet" ]] && docker network inspect "$defnet" >/dev/null 2>&1; then
            NETS_TO_REMOVE+=("$defnet")
        fi
    fi

    # Images (ALL only): remove every image defined in docker-compose.yml (resolved by compose config)
    local -a IMAGES_TO_REMOVE=()   # pretty list for preview: "<repo[:tag|@digest]> (<id>|not present locally)"
    local -a IMAGE_IDS=()          # bare IDs to rmi -f
    if $NUKE_ALL; then
        local json
        if json="$(compose config --format json 2>/dev/null)"; then
            # 1) Collect images referenced by services (already env-resolved)
            local -a compose_images=()
            mapfile -t compose_images < <(
                printf '%s' "$json" | jq -r '.services[]?.image? // empty' | awk 'NF' | sort -u
            )

            # 2) Build maps of local images by "<repo:tag>" and "<repo@digest>" -> ID
            declare -A map_tag_to_id=()
            declare -A map_digest_to_id=()

            # repo:tag map
            while IFS= read -r line; do
                # "<repo>:<tag> <id>"
                local key="${line% *}"
                local val="${line##* }"
                [[ -n "$key" && -n "$val" ]] && map_tag_to_id["$key"]="$val"
            done < <(docker images --format '{{.Repository}}:{{.Tag}} {{.ID}}' 2>/dev/null || true)

            # repo@digest map
            while IFS= read -r line; do
                # "<repo>@<digest> <id>"
                local key="${line% *}"
                local val="${line##* }"
                # Skip entries where the digest part is literally "<none>"
                if [[ "${key#*@}" == "<none>" ]]; then
                    continue
                fi
                [[ -n "$key" && -n "$val" ]] && map_digest_to_id["$key"]="$val"
            done < <(docker images --digests --format '{{.Repository}}@{{.Digest}} {{.ID}}' 2>/dev/null || true)

            # 3) Resolve each compose image to an ID if present locally
            local img id
            for img in "${compose_images[@]}"; do
                if [[ "$img" == *"@"* ]]; then
                    id="${map_digest_to_id[$img]:-}"
                else
                    id="${map_tag_to_id[$img]:-}"
                fi
                if [[ -n "$id" ]]; then
                    IMAGES_TO_REMOVE+=("${img} (${id})")
                    IMAGE_IDS+=("$id")
                else
                    IMAGES_TO_REMOVE+=("${img} (not present locally)")
                fi
            done

            # 4) De-dupe IDs
            if ((${#IMAGE_IDS[@]})); then
                mapfile -t IMAGE_IDS < <(printf '%s\n' "${IMAGE_IDS[@]}" | awk 'NF' | sort -u)
            fi
        else
            log WARN "Could not parse 'compose config' JSON; skipping compose-defined image list."
        fi
    fi

    # Directory contents to wipe (only ALL)
    local -a DIR_ENTRIES=()
    if $NUKE_ALL; then
        shopt -s dotglob nullglob
        local p
        for p in "$N8N_DIR"/*; do
            DIR_ENTRIES+=("$(basename "$p")")
        done
        shopt -u dotglob nullglob
    fi

    # ---------- Preview ----------
    echo "════════════════ CLEANUP PREVIEW (mode: ${MODE^^}) ════════════════"
    {
        local IFS=' '
        printf 'Will run: docker compose down %s\n\n' "${DOWN_FLAGS[*]}"
    }
    echo "Named volumes to be DELETED:"
    if ((${#VOLS_EXISTING[@]})); then
        local pair lv rv
        for pair in "${VOLS_EXISTING[@]}"; do
            IFS='|' read -r lv rv <<< "$pair"
            echo "  - ${lv}  ->  ${rv}"
        done
    else
        echo "  - <none>"
    fi
    echo

    echo "Docker networks to be DELETED:"
    if ((${#NETS_TO_REMOVE[@]})); then
        local n
        for n in "${NETS_TO_REMOVE[@]}"; do
            echo "  - ${n}"
        done
    else
        echo "  - <none detected>"
    fi
    echo

    echo "Dangling images to be PRUNED:"
    echo "  - (dynamic: docker image prune -f)"

    if $NUKE_ALL; then
        echo
        echo "Compose-defined images to DELETE:"
        if ((${#IMAGES_TO_REMOVE[@]})); then
            local i
            for i in "${IMAGES_TO_REMOVE[@]}"; do
                echo "  - ${i}"
            done
        else
            echo "  - <none discovered>"
        fi
        echo
        echo "Target directory to be WIPED: $N8N_DIR"
        if ((${#DIR_ENTRIES[@]})); then
            echo "  Contents to be removed:"
            local d
            for d in "${DIR_ENTRIES[@]}"; do
                echo "    - $d"
            done
        else
            echo "  (directory is empty)"
        fi
        echo
        echo "NOTE: 'letsencrypt' volume WILL be removed."
        echo "      WARNING: You may hit Let's Encrypt rate limits on next start."
    else
        echo
        echo "NOTES (SAFE):"
        echo "  - Preserving 'letsencrypt' volume (keeps TLS certs)."
        echo "  - No directory wipe."
        echo "  - Base images are kept."
    fi
    echo "══════════════════════════════════════════════════════════════"

    # ---------- Confirmation (ALL only) ----------
    if $NUKE_ALL; then
        local ans
        read -r -p "Proceed with FULL cleanup (all)? (yes/no) [no]: " ans
        case "${ans,,}" in
            y|yes) ;;
            *) log INFO "Cleanup (all) cancelled by user."; return 0 ;;
        esac
    fi

    # ---------- Execute ----------
    log INFO "Shutting down stack…"
    if [[ -f "$N8N_DIR/docker-compose.yml" ]]; then
        compose down "${DOWN_FLAGS[@]}" || true
    else
        log WARN "docker-compose.yml not found at \$N8N_DIR; attempting plain 'docker compose down' in $PWD."
        docker compose down "${DOWN_FLAGS[@]}" || true
    fi

    if ((${#VOLS_EXISTING[@]})); then
        log INFO "Removing named volumes…"
        local pair lv rv
        for pair in "${VOLS_EXISTING[@]}"; do
            IFS='|' read -r lv rv <<< "$pair"
            if docker volume inspect "$rv" >/dev/null 2>&1; then
                if docker volume rm "$rv" >/dev/null 2>&1; then
                    log INFO "Removed volume: $lv ($rv)"
                else
                    log WARN "Could not remove volume '$lv' ($rv) — maybe still in use?"
                fi
            else
                log INFO "Already gone: $lv ($rv) (removed by compose)"
            fi
        done
    fi

    log INFO "Removing docker networks…"
    remove_compose_networks
    if $NUKE_ALL; then
        purge_project_volumes_by_label
        purge_project_networks_by_label
    fi

    log INFO "Pruning dangling images…"
    docker image prune -f >/dev/null 2>&1 || true
    if $NUKE_ALL && ((${#IMAGE_IDS[@]})); then
        log WARN "Removing compose-defined images…"
        docker rmi -f "${IMAGE_IDS[@]}" >/dev/null 2>&1 || true
    fi

    if $NUKE_ALL; then
        safe_wipe_target_dir
    fi

    log INFO "Cleanup completed (mode=${MODE^^})."
    if [[ "$MODE" == "safe" ]]; then
        log INFO "Preserved 'letsencrypt' volume. Use '--cleanup all' to remove everything."
    fi
}
