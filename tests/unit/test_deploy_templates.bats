#!/usr/bin/env bats
# tests/unit/test_deploy_templates.bats — Contract tests for the shipped deploy/ templates.
#
# These guard the wiring between what the scripts WRITE into .env and what the
# compose templates READ. A mismatch there is invisible to the flow tests (their
# fixtures ship their own compose) but pins every real deployment to the compose
# default tag — see issue #4, "-upgrade will not advance past version 2.17.7".

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"

setup() {
    export LOG_LEVEL="INFO"
    export N8N_DIR="$BATS_TEST_TMPDIR/n8n"
    mkdir -p "$N8N_DIR"
    export ENV_FILE="$N8N_DIR/.env"
    export COMPOSE_FILE="$N8N_DIR/docker-compose.yml"
    source "$REPO_ROOT/lib/common.sh"
}

# ---------------------------------------------------------------------------
# compose template <-> installer env-var contract
# ---------------------------------------------------------------------------

@test "every shipped compose pins the n8n image to \${N8N_IMAGE_TAG}" {
    for mode in single-mode queue-mode; do
        local file="$REPO_ROOT/deploy/$mode/docker-compose.yml"
        [ -f "$file" ]
        run grep -E 'image:[[:space:]]*.*n8nio/n8n:' "$file"
        [ "$status" -eq 0 ]
        # Every n8n image line must interpolate N8N_IMAGE_TAG, the var install.sh
        # and upgrade.sh write. Any other name silently pins the default tag.
        while IFS= read -r line; do
            [[ "$line" == *'${N8N_IMAGE_TAG'* ]]
        done <<< "$output"
    done
}

@test "every shipped .env.example defines N8N_IMAGE_TAG and not N8N_VERSION" {
    for mode in single-mode queue-mode; do
        local file="$REPO_ROOT/deploy/$mode/.env.example"
        [ -f "$file" ]
        grep -qE '^N8N_IMAGE_TAG=' "$file"
        # N8N_VERSION is a script global (the -v flag). load_env_file sources .env
        # with allexport, so shipping that key in .env overwrites the user's -v.
        run grep -qE '^N8N_VERSION=' "$file"
        [ "$status" -ne 0 ]
    done
}

@test "install templates provide an env source install.sh can copy" {
    for mode in single-mode queue-mode; do
        local dir="$REPO_ROOT/deploy/$mode"
        [ -f "$dir/.env" ] || [ -f "$dir/.env.example" ]
    done
}

# ---------------------------------------------------------------------------
# compose_image_tag_var()
# ---------------------------------------------------------------------------

@test "compose_image_tag_var returns N8N_IMAGE_TAG for current templates" {
    cp "$REPO_ROOT/deploy/queue-mode/docker-compose.yml" "$COMPOSE_FILE"
    run compose_image_tag_var "$COMPOSE_FILE"
    [ "$status" -eq 0 ]
    [ "$output" = "N8N_IMAGE_TAG" ]
}

@test "compose_image_tag_var returns N8N_VERSION for a legacy compose copy" {
    printf 'services:\n  main:\n    image: n8nio/n8n:${N8N_VERSION:-2.17.7}\n' > "$COMPOSE_FILE"
    run compose_image_tag_var "$COMPOSE_FILE"
    [ "$status" -eq 0 ]
    [ "$output" = "N8N_VERSION" ]
}

@test "compose_image_tag_var defaults to N8N_IMAGE_TAG when compose is missing" {
    run compose_image_tag_var "$BATS_TEST_TMPDIR/nope.yml"
    [ "$status" -eq 0 ]
    [ "$output" = "N8N_IMAGE_TAG" ]
}

# ---------------------------------------------------------------------------
# -v must survive load_env_file
# ---------------------------------------------------------------------------

@test "load_env_file does not clobber the -v version from a legacy .env" {
    # Legacy deployments still carry N8N_VERSION= in .env. upgrade_stack snapshots
    # the CLI value before sourcing, so the requested tag must survive.
    printf 'N8N_VERSION=2.17.7\nN8N_IMAGE_TAG=2.17.7\n' > "$ENV_FILE"
    N8N_VERSION="2.23.2"
    local requested_version="${N8N_VERSION:-latest}"
    load_env_file "$ENV_FILE"
    [ "$requested_version" = "2.23.2" ]
}
