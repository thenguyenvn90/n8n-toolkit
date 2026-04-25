#!/usr/bin/env bats
# tests/unit/test_env_helpers.bats — Unit tests for .env file helpers
# Coverage: upsert_env_var, read_env_var, rotate_or_generate_secret, looks_like_b64

load '../test_helper/common'

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"

setup() {
    setup_stub_bin
    trap '' ERR INT TERM HUP 2>/dev/null || true
    export LOG_LEVEL="INFO"
    export APT_UPDATED=false
    export N8N_DIR="$BATS_TEST_TMPDIR/n8n"
    mkdir -p "$N8N_DIR"
    export ENV_FILE="$N8N_DIR/.env"
    export COMPOSE_FILE="$N8N_DIR/docker-compose.yml"
    # shellcheck disable=SC1090
    source "$REPO_ROOT/lib/common.sh"
}

teardown() {
    rm -rf "$BATS_TEST_TMPDIR/n8n" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# upsert_env_var
# ---------------------------------------------------------------------------

@test "upsert_env_var: adds new variable to empty file" {
    local f="$BATS_TEST_TMPDIR/empty.env"
    touch "$f"
    upsert_env_var "MY_KEY" "my_value" "$f"
    run grep "^MY_KEY=my_value$" "$f"
    [ "$status" -eq 0 ]
}

@test "upsert_env_var: updates existing variable in file" {
    local f="$BATS_TEST_TMPDIR/update.env"
    echo "MY_KEY=old_value" > "$f"
    upsert_env_var "MY_KEY" "new_value" "$f"
    run grep "^MY_KEY=new_value$" "$f"
    [ "$status" -eq 0 ]
}

@test "upsert_env_var: does not duplicate variable" {
    local f="$BATS_TEST_TMPDIR/dup.env"
    echo "MY_KEY=first" > "$f"
    upsert_env_var "MY_KEY" "second" "$f"
    count="$(grep -c "^MY_KEY=" "$f")"
    [ "$count" -eq 1 ]
}

@test "upsert_env_var: preserves other keys when updating" {
    local f="$BATS_TEST_TMPDIR/other.env"
    printf 'DOMAIN=old.com\nSSL_EMAIL=admin@test.com\n' > "$f"
    upsert_env_var "DOMAIN" "new.com" "$f"
    run grep "^SSL_EMAIL=admin@test.com$" "$f"
    [ "$status" -eq 0 ]
}

@test "upsert_env_var: creates file when it does not exist" {
    local f="$BATS_TEST_TMPDIR/nonexistent_$(date +%s).env"
    [ ! -f "$f" ]
    upsert_env_var "NEW_KEY" "hello" "$f"
    [ -f "$f" ]
    run grep "NEW_KEY=hello" "$f"
    [ "$status" -eq 0 ]
}

@test "upsert_env_var: stores empty value correctly" {
    local f="$BATS_TEST_TMPDIR/empty_val.env"
    echo "COMPOSE_PROFILES=monitoring" > "$f"
    upsert_env_var "COMPOSE_PROFILES" "" "$f"
    run grep "^COMPOSE_PROFILES=$" "$f"
    [ "$status" -eq 0 ]
}

@test "upsert_env_var: stores value with forward slashes" {
    local f="$BATS_TEST_TMPDIR/slash.env"
    touch "$f"
    upsert_env_var "PATH_VAR" "/home/user/n8n" "$f"
    run grep "PATH_VAR=/home/user/n8n" "$f"
    [ "$status" -eq 0 ]
}

@test "upsert_env_var: stores value with ampersand" {
    local f="$BATS_TEST_TMPDIR/amp.env"
    touch "$f"
    upsert_env_var "NAME" "Tom&Jerry" "$f"
    run grep "NAME=Tom&Jerry" "$f"
    [ "$status" -eq 0 ]
}

@test "upsert_env_var: rejects value containing newline" {
    local f="$BATS_TEST_TMPDIR/newline.env"
    touch "$f"
    run upsert_env_var "BAD_KEY" $'line1\nline2' "$f"
    [ "$status" -ne 0 ]
}

@test "upsert_env_var: fails when key argument is empty" {
    local f="$BATS_TEST_TMPDIR/nokey.env"
    touch "$f"
    run upsert_env_var "" "value" "$f"
    [ "$status" -ne 0 ]
}

# ---------------------------------------------------------------------------
# read_env_var
# ---------------------------------------------------------------------------

@test "read_env_var: reads existing variable" {
    local f="$BATS_TEST_TMPDIR/read.env"
    echo "MY_KEY=hello_world" > "$f"
    result="$(read_env_var "$f" "MY_KEY")"
    [ "$result" = "hello_world" ]
}

@test "read_env_var: returns non-zero for missing variable" {
    local f="$BATS_TEST_TMPDIR/miss.env"
    echo "OTHER=val" > "$f"
    run read_env_var "$f" "MISSING_KEY"
    [ "$status" -eq 1 ]
}

@test "read_env_var: returns exit 1 for missing file" {
    run read_env_var "/tmp/nonexistent_$(date +%s)_bats.env" "ANY"
    [ "$status" -eq 1 ]
}

@test "read_env_var: ignores comment lines" {
    local f="$BATS_TEST_TMPDIR/comment.env"
    printf '# MY_KEY=not_this\nMY_KEY=real_value\n' > "$f"
    result="$(read_env_var "$f" "MY_KEY")"
    [ "$result" = "real_value" ]
}

@test "read_env_var: strips inline comments from value" {
    local f="$BATS_TEST_TMPDIR/inline.env"
    echo 'MY_KEY=value # this is a comment' > "$f"
    result="$(read_env_var "$f" "MY_KEY")"
    [ "$result" = "value" ]
}

@test "read_env_var: handles double-quoted value" {
    local f="$BATS_TEST_TMPDIR/quoted.env"
    echo 'MY_KEY="quoted value"' > "$f"
    result="$(read_env_var "$f" "MY_KEY")"
    [ "$result" = "quoted value" ]
}

@test "read_env_var: handles single-quoted value" {
    local f="$BATS_TEST_TMPDIR/singleq.env"
    echo "MY_KEY='single quoted'" > "$f"
    result="$(read_env_var "$f" "MY_KEY")"
    [ "$result" = "single quoted" ]
}

@test "read_env_var: ignores blank lines" {
    local f="$BATS_TEST_TMPDIR/blank.env"
    printf '\n\nFOO=baz\n\n' > "$f"
    result="$(read_env_var "$f" "FOO")"
    [ "$result" = "baz" ]
}

# ---------------------------------------------------------------------------
# rotate_or_generate_secret
# ---------------------------------------------------------------------------

@test "rotate_or_generate_secret: generates secret when value is CHANGE_ME placeholder" {
    local f="$BATS_TEST_TMPDIR/secret_placeholder.env"
    echo "MY_SECRET=CHANGE_ME_BASE64_16_BYTES" > "$f"
    rotate_or_generate_secret "$f" "MY_SECRET" "16" "CHANGE_ME_BASE64_16_BYTES"
    val="$(read_env_var "$f" "MY_SECRET")"
    [[ "$val" != "CHANGE_ME_BASE64_16_BYTES" ]]
    [[ -n "$val" ]]
}

@test "rotate_or_generate_secret: skips when value already looks like base64" {
    local f="$BATS_TEST_TMPDIR/secret_existing.env"
    echo "MY_SECRET=alreadySetValue" > "$f"
    rotate_or_generate_secret "$f" "MY_SECRET" "16" "CHANGE_ME_BASE64_16_BYTES"
    val="$(read_env_var "$f" "MY_SECRET")"
    [ "$val" = "alreadySetValue" ]
}

@test "rotate_or_generate_secret: generates secret when entry is missing entirely" {
    local f="$BATS_TEST_TMPDIR/secret_missing.env"
    touch "$f"
    rotate_or_generate_secret "$f" "FRESH_SECRET" "16" "PLACEHOLDER"
    run grep "^FRESH_SECRET=" "$f"
    [ "$status" -eq 0 ]
    val="$(read_env_var "$f" "FRESH_SECRET")"
    [[ -n "$val" ]]
}

@test "rotate_or_generate_secret: generates secret when value is empty" {
    local f="$BATS_TEST_TMPDIR/secret_empty.env"
    echo "MY_SECRET=" > "$f"
    rotate_or_generate_secret "$f" "MY_SECRET" "16" "CHANGE_ME"
    val="$(read_env_var "$f" "MY_SECRET")"
    # An empty value matches the "missing" case → should be rotated
    # The stub openssl outputs a base64 string; result should be non-empty
    [[ -n "$val" ]]
}

# ---------------------------------------------------------------------------
# looks_like_b64
# ---------------------------------------------------------------------------

@test "looks_like_b64: returns 0 for valid base64 string" {
    run looks_like_b64 "dGVzdHNlY3JldA=="
    [ "$status" -eq 0 ]
}

@test "looks_like_b64: returns 0 for valid base64 without padding" {
    run looks_like_b64 "dGVzdFNlY3JldEtleUZvcjMyQnl0ZXNMT05HRU5PVUdI"
    [ "$status" -eq 0 ]
}

@test "looks_like_b64: returns 1 for plain text placeholder" {
    run looks_like_b64 "CHANGE_ME_BASE64_32_BYTES"
    [ "$status" -ne 0 ]
}

@test "looks_like_b64: returns 1 for string with spaces" {
    run looks_like_b64 "not a b64 string"
    [ "$status" -ne 0 ]
}

@test "looks_like_b64: returns 0 for empty string" {
    run looks_like_b64 ""
    [ "$status" -eq 0 ]
}

@test "looks_like_b64: returns 1 for string with invalid base64 chars" {
    run looks_like_b64 "invalid!@#\$%base64"
    [ "$status" -ne 0 ]
}

# ---------------------------------------------------------------------------
# Round-trip: upsert → read
# ---------------------------------------------------------------------------

@test "upsert then read: returns same base64 value" {
    local f="$BATS_TEST_TMPDIR/b64_roundtrip.env"
    touch "$f"
    local secret="dGVzdEVuY3J5cHRpb25LZXkzMkJ5dGVzTE9ORw=="
    upsert_env_var "N8N_ENCRYPTION_KEY" "$secret" "$f"
    result="$(read_env_var "$f" "N8N_ENCRYPTION_KEY")"
    [ "$result" = "$secret" ]
}

@test "upsert twice: read returns second value" {
    local f="$BATS_TEST_TMPDIR/double.env"
    touch "$f"
    upsert_env_var "MY_KEY" "first" "$f"
    upsert_env_var "MY_KEY" "second" "$f"
    result="$(read_env_var "$f" "MY_KEY")"
    [ "$result" = "second" ]
}
