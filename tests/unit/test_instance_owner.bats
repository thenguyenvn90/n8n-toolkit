#!/usr/bin/env bats
# tests/unit/test_instance_owner.bats — Instance-owner provisioning.
#
# n8n removed basic auth in 1.0 and replaced it with user management, but the
# shipped .env.example still declared N8N_BASIC_AUTH_ACTIVE=true and install
# generated a random password for it. The setting was inert: it cost a secret
# and told the operator their instance was protected by something that no
# longer exists. These tests keep it gone and keep its replacement honest.

load '../test_helper/common'

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"

# The shape n8n itself enforces, from
# packages/cli/src/instance-settings-loader/loaders/owner.instance-settings-loader.ts
#   /^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/
BCRYPT_RE='^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$'

setup() {
    trap '' ERR INT TERM HUP 2>/dev/null || true
    export LOG_LEVEL="INFO"
    source_common
}

# ---------------------------------------------------------------------------
# The dead config stays dead
# ---------------------------------------------------------------------------

@test "no shipped .env.example contains N8N_BASIC_AUTH_" {
    run grep -rl "N8N_BASIC_AUTH_" "$REPO_ROOT/deploy"
    [ -z "$output" ]
}

@test "install.sh does not generate a basic-auth password" {
    run grep -c "N8N_BASIC_AUTH_PASSWORD" "$REPO_ROOT/lib/install.sh"
    [ "$output" -eq 0 ]
}

@test "the Traefik basic-auth flags are untouched" {
    # These are a different thing and are correct: they guard Grafana and
    # Prometheus via ensure_monitoring_auth(). Only the n8n-side keys were dead.
    grep -q -- "--basic-auth-user" "$REPO_ROOT/n8n_manager.sh"
    grep -q "MONITORING_BASIC_AUTH_USER" "$REPO_ROOT/lib/common.sh"
}

# ---------------------------------------------------------------------------
# The replacement
# ---------------------------------------------------------------------------

@test "both .env.example files document the instance-owner variables" {
    local f
    for f in "$REPO_ROOT/deploy/single-mode/.env.example" "$REPO_ROOT/deploy/queue-mode/.env.example"; do
        grep -q "N8N_INSTANCE_OWNER_MANAGED_BY_ENV" "$f"
        grep -q "N8N_INSTANCE_OWNER_EMAIL" "$f"
        grep -q "N8N_INSTANCE_OWNER_PASSWORD_HASH" "$f"
    done
}

# parse_args() lives in n8n_manager.sh and main() calls check_root before it, so
# the validation is unreachable through the CLI as a non-root user. Same
# extraction technique as test_arg_parsing.bats: pull the function definitions
# out and call parse_args directly.
_parse_owner_args() {
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
        MONITORING=false EXPOSE_PROMETHEUS=false
        SUBDOMAIN_N8N='' SUBDOMAIN_GRAFANA='' SUBDOMAIN_PROMETHEUS=''
        BASIC_AUTH_USER='' BASIC_AUTH_PASS=''
        OWNER_EMAIL='' OWNER_PASSWORD=''
        EMAIL_TO='' EMAIL_EXPLICIT=false NOTIFY_ON_SUCCESS=false
        RCLONE_REMOTE='' TARGET_RESTORE_FILE='' N8N_DIR='$BATS_TEST_TMPDIR/n8n'
        parse_args \"\$@\"
        echo \"OWNER_EMAIL=\$OWNER_EMAIL\"
        echo \"OWNER_PASSWORD_SET=\$([[ -n \$OWNER_PASSWORD ]] && echo yes || echo no)\"
    " _ "$@" 2>&1
}

@test "--owner-email without --owner-password is refused" {
    run _parse_owner_args --install example.com --owner-email a@b.c
    [[ "$output" == *"must be given together"* ]]
}

@test "--owner-password without --owner-email is refused" {
    run _parse_owner_args --install example.com --owner-password hunter2
    [[ "$output" == *"must be given together"* ]]
}

@test "--owner-email with --owner-password parses cleanly" {
    run _parse_owner_args --install example.com --owner-email a@b.c --owner-password hunter2
    [[ "$output" == *"OWNER_EMAIL=a@b.c"* ]]
    [[ "$output" == *"OWNER_PASSWORD_SET=yes"* ]]
    [[ "$output" != *"must be given together"* ]]
}

@test "the owner password never reaches the parsed output" {
    run _parse_owner_args --install example.com --owner-email a@b.c --owner-password hunter2
    [[ "$output" != *"hunter2"* ]]
}

@test "--help documents the owner flags" {
    run bash "$REPO_ROOT/n8n_manager.sh" --help
    [[ "$output" == *"--owner-email"* ]]
    [[ "$output" == *"--owner-password"* ]]
}

# ---------------------------------------------------------------------------
# The hash must be one n8n will actually accept
# ---------------------------------------------------------------------------

@test "gen_bcrypt_hash produces a hash matching n8n's bcrypt regex" {
    if ! command -v htpasswd >/dev/null 2>&1 && ! command -v docker >/dev/null 2>&1; then
        skip "needs htpasswd or docker"
    fi
    run gen_bcrypt_hash "owner@example.com" "correct horse battery staple"
    [ "$status" -eq 0 ]
    [[ "$output" =~ $BCRYPT_RE ]]
    # 60 characters, per n8n's own comment on the regex
    [ "${#output}" -eq 60 ]
}

@test "gen_bcrypt_hash never emits the plaintext password" {
    if ! command -v htpasswd >/dev/null 2>&1 && ! command -v docker >/dev/null 2>&1; then
        skip "needs htpasswd or docker"
    fi
    run gen_bcrypt_hash "owner@example.com" "hunter2"
    [[ "$output" != *"hunter2"* ]]
}

@test "install.sh validates the hash shape before writing it" {
    # n8n refuses to boot on a malformed hash, so a crash-looping container is a
    # worse error message than a check here.
    grep -qE 'owner_hash.*=~.*2\[aby\]' "$REPO_ROOT/lib/install.sh"
}

@test "install.sh writes the hash, never the plaintext password" {
    grep -q 'N8N_INSTANCE_OWNER_PASSWORD_HASH" *"\$owner_hash"' "$REPO_ROOT/lib/install.sh"
    run grep -c 'upsert_env_var.*OWNER_PASSWORD"' "$REPO_ROOT/lib/install.sh"
    [ "$output" -eq 0 ]
}
