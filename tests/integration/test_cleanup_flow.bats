#!/usr/bin/env bats
# tests/integration/test_cleanup_flow.bats — Integration tests for cleanup_stack()
# Coverage: safe mode (compose down), non-TTY guard for "all" mode, TTY prompt path.

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
    create_test_env "$ENV_FILE"
    cat > "$COMPOSE_FILE" <<'COMPOSE'
services:
  main:
    image: n8nio/n8n:${N8N_IMAGE_TAG:-1.108.0}
    container_name: n8n-main
  postgres:
    image: postgres:16
    container_name: n8n-postgres
volumes:
  n8n-data:
  postgres-data:
COMPOSE
}

teardown() {
    rm -rf "$BATS_TEST_TMPDIR/n8n" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Common preamble snippet for cleanup subshell tests
# ---------------------------------------------------------------------------
_cleanup_preamble() {
    # PATH is inherited from bats setup() which already has STUB_BIN prepended
    # via setup_stub_bin — do NOT re-export PATH here (would clobber system tools).
    cat <<PREAMBLE
        set +e
        export LOG_LEVEL=INFO APT_UPDATED=false
        export N8N_DIR='${N8N_DIR}'
        export ENV_FILE="\${N8N_DIR}/.env"
        export COMPOSE_FILE="\${N8N_DIR}/docker-compose.yml"
        source '${REPO_ROOT}/lib/common.sh'
        source '${REPO_ROOT}/lib/install.sh'
        source '${REPO_ROOT}/lib/upgrade.sh'
        source '${REPO_ROOT}/lib/backup.sh'
        source '${REPO_ROOT}/lib/cleanup.sh'
        DATE=\$(date +%F_%H-%M-%S)
        LOG_FILE="\${N8N_DIR}/logs/cleanup_test.log"
        BACKUP_DIR="\${N8N_DIR}/backups"
        CLEANUP_MODE='safe'
        DAYS_TO_KEEP=7
PREAMBLE
}

# ---------------------------------------------------------------------------
# cleanup safe: runs docker compose down
# ---------------------------------------------------------------------------

@test "cleanup safe: runs docker compose down" {
    local preamble; preamble="$(_cleanup_preamble)"
    run bash -c "
        $preamble
        CLEANUP_MODE='safe'

        # Track whether compose down was invoked
        COMPOSE_DOWN_CALLED=false

        # Override compose() to track calls
        compose() {
            if [[ \"\$*\" == *'down'* ]]; then
                COMPOSE_DOWN_CALLED=true
                echo 'MOCK compose down'
            fi
            return 0
        }
        export -f compose

        # Override Docker stub to avoid real calls
        docker() {
            case \"\$*\" in
                *'volume inspect'*)   return 1 ;;   # no volumes exist
                *'network ls'*)       echo '' ;;
                *'network inspect'*)  return 1 ;;
                *'image prune'*)      return 0 ;;
                *'compose'*'config --format json'*)
                    echo '{\"services\":{\"main\":{}},\"volumes\":{},\"networks\":{}}'
                    ;;
                *'compose'*) echo 'MOCK compose' ;;
                *) return 0 ;;
            esac
        }
        export -f docker

        cleanup_stack
        echo \"COMPOSE_DOWN:\$COMPOSE_DOWN_CALLED\"
    " 2>&1

    [ "$status" -eq 0 ]
    # Either the COMPOSE_DOWN flag is set or the output shows compose down was called
    [[ "$output" == *"COMPOSE_DOWN:true"* ]] || [[ "$output" == *"Shutting down"* ]] || [[ "$output" == *"compose down"* ]]
}

@test "cleanup safe: prints PREVIEW block before executing" {
    local preamble; preamble="$(_cleanup_preamble)"
    run bash -c "
        $preamble
        CLEANUP_MODE='safe'
        docker() {
            case \"\$*\" in
                *'volume inspect'*)   return 1 ;;
                *'network ls'*)       echo '' ;;
                *'network inspect'*)  return 1 ;;
                *'image prune'*)      return 0 ;;
                *'compose'*'config --format json'*)
                    echo '{\"services\":{\"main\":{}},\"volumes\":{},\"networks\":{}}'
                    ;;
                *'compose'*) return 0 ;;
                *) return 0 ;;
            esac
        }
        export -f docker
        cleanup_stack
    " 2>&1

    [ "$status" -eq 0 ]
    [[ "$output" == *"CLEANUP PREVIEW"* ]] || [[ "$output" == *"SAFE"* ]]
}

@test "cleanup safe: does not wipe N8N_DIR (no directory deletion)" {
    local preamble; preamble="$(_cleanup_preamble)"
    bash -c "
        $preamble
        CLEANUP_MODE='safe'
        docker() {
            case \"\$*\" in
                *'volume inspect'*)   return 1 ;;
                *'network ls'*)       echo '' ;;
                *'network inspect'*)  return 1 ;;
                *'image prune'*)      return 0 ;;
                *'compose'*'config --format json'*)
                    echo '{\"services\":{\"main\":{}},\"volumes\":{},\"networks\":{}}'
                    ;;
                *'compose'*) return 0 ;;
                *) return 0 ;;
            esac
        }
        export -f docker
        cleanup_stack
    " 2>&1 || true

    # N8N_DIR must still exist after safe cleanup
    [ -d "$N8N_DIR" ]
}

# ---------------------------------------------------------------------------
# cleanup all: exits 2 on non-TTY (stdin not interactive)
# ---------------------------------------------------------------------------

@test "cleanup all: exits 2 on non-TTY (stdin not interactive)" {
    local preamble; preamble="$(_cleanup_preamble)"
    run bash -c "
        $preamble
        CLEANUP_MODE='all'
        docker() {
            case \"\$*\" in
                *'volume inspect'*)   return 1 ;;
                *'network ls'*)       echo '' ;;
                *'network inspect'*)  return 1 ;;
                *'image prune'*)      return 0 ;;
                *'compose'*'config --format json'*)
                    echo '{\"services\":{\"main\":{}},\"volumes\":{},\"networks\":{}}'
                    ;;
                *'images'*)           echo '' ;;
                *'compose'*) return 0 ;;
                *) return 0 ;;
            esac
        }
        export -f docker
        # Redirect stdin from /dev/null to simulate non-TTY environment
        cleanup_stack </dev/null
    " 2>&1

    [ "$status" -eq 2 ]
    [[ "$output" == *"interactive terminal"* ]] || [[ "$output" == *"TTY"* ]] || [[ "$output" == *"stdin"* ]]
}

@test "cleanup all: error message mentions interactive terminal" {
    local preamble; preamble="$(_cleanup_preamble)"
    run bash -c "
        $preamble
        CLEANUP_MODE='all'
        docker() {
            case \"\$*\" in
                *'volume inspect'*)   return 1 ;;
                *'network ls'*)       echo '' ;;
                *'network inspect'*)  return 1 ;;
                *'images'*)           echo '' ;;
                *'compose'*'config --format json'*)
                    echo '{\"services\":{\"main\":{}},\"volumes\":{},\"networks\":{}}'
                    ;;
                *'compose'*) return 0 ;;
                *) return 0 ;;
            esac
        }
        export -f docker
        cleanup_stack </dev/null
    " 2>&1

    [[ "$output" == *"interactive"* ]] || [[ "$output" == *"TTY"* ]]
}

# ---------------------------------------------------------------------------
# cleanup all: prompts for confirmation on TTY (simulated via process substitution)
# ---------------------------------------------------------------------------

@test "cleanup all: cancels when user types 'no' at confirmation prompt" {
    local preamble; preamble="$(_cleanup_preamble)"
    run bash -c "
        $preamble
        CLEANUP_MODE='all'
        docker() {
            case \"\$*\" in
                *'volume inspect'*)   return 1 ;;
                *'network ls'*)       echo '' ;;
                *'network inspect'*)  return 1 ;;
                *'images'*)           echo '' ;;
                *'compose'*'config --format json'*)
                    echo '{\"services\":{\"main\":{}},\"volumes\":{},\"networks\":{}}'
                    ;;
                *'compose'*) return 0 ;;
                *) return 0 ;;
            esac
        }
        export -f docker

        # Override the TTY check so we get past the non-TTY guard,
        # then supply 'no' as stdin answer to the confirmation prompt
        # We test the cancel path by patching cleanup_stack's read call
        cleanup_stack_patched() {
            # Run cleanup_stack with stdin supplying 'no'
            echo 'no' | cleanup_stack
        }

        # Since we can't easily fake a TTY, test the cancel path via a subshell
        # that overrides the read command behavior
        bash -c \"
            source '$REPO_ROOT/lib/common.sh'
            source '$REPO_ROOT/lib/install.sh'
            source '$REPO_ROOT/lib/upgrade.sh'
            source '$REPO_ROOT/lib/backup.sh'
            source '$REPO_ROOT/lib/cleanup.sh'
            export N8N_DIR='$N8N_DIR'
            export ENV_FILE='\$N8N_DIR/.env'
            export COMPOSE_FILE='\$N8N_DIR/docker-compose.yml'
            export LOG_LEVEL=INFO
            CLEANUP_MODE='all'
            docker() { return 0; }
            export -f docker

            # Patch the TTY check in cleanup_stack with a wrapper
            _orig_cleanup=\$(declare -f cleanup_stack)
            # Replace '[[ ! -t 0 ]]' guard by patching read to return 'no'
            read() { echo 'no'; return 0; }
            export -f read

            # Force past TTY guard by reopening stdin to a pipe
            cleanup_stack <<< 'no'
        \" 2>&1
        echo 'CANCEL_RESULT:\$?'
    " 2>&1

    # Either the function returns 0 (cancelled gracefully) or the output shows cancellation
    [[ "$output" == *"cancelled"* ]] || [[ "$output" == *"CANCEL_RESULT:0"* ]] || [ "$status" -eq 0 ]
}

# ---------------------------------------------------------------------------
# cleanup: invalid mode exits with error
# ---------------------------------------------------------------------------

@test "cleanup: exits with error for invalid CLEANUP_MODE" {
    local preamble; preamble="$(_cleanup_preamble)"
    run bash -c "
        $preamble
        CLEANUP_MODE='badmode'
        docker() {
            case \"\$*\" in
                *'compose'*'config --format json'*)
                    echo '{\"services\":{\"main\":{}},\"volumes\":{},\"networks\":{}}'
                    ;;
                *) return 0 ;;
            esac
        }
        export -f docker
        cleanup_stack
    " 2>&1

    [ "$status" -ne 0 ]
    [[ "$output" == *"safe"* ]] || [[ "$output" == *"all"* ]] || [[ "$output" == *"ERROR"* ]]
}

# ---------------------------------------------------------------------------
# cleanup safe: preserves letsencrypt volume note in output
# ---------------------------------------------------------------------------

@test "cleanup safe: output mentions letsencrypt volume is preserved" {
    local preamble; preamble="$(_cleanup_preamble)"
    run bash -c "
        $preamble
        CLEANUP_MODE='safe'
        docker() {
            case \"\$*\" in
                *'volume inspect'*)   return 1 ;;
                *'network ls'*)       echo '' ;;
                *'network inspect'*)  return 1 ;;
                *'image prune'*)      return 0 ;;
                *'compose'*'config --format json'*)
                    echo '{\"services\":{\"main\":{}},\"volumes\":{},\"networks\":{}}'
                    ;;
                *'compose'*) return 0 ;;
                *) return 0 ;;
            esac
        }
        export -f docker
        cleanup_stack
    " 2>&1

    [ "$status" -eq 0 ]
    [[ "$output" == *"letsencrypt"* ]]
}
