#!/usr/bin/env bats
# tests/unit/test_common.bats — Unit tests for lib/common.sh helper functions
# Coverage: log, mask_secret, looks_like_b64, parse_domain_arg, box_line, upsert_env_var,
#           read_env_var, load_env_file, rotate_or_generate_secret

load '../helpers/stubs'
load '../helpers/fixtures'

# Repository root (one level above tests/)
REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"

setup() {
    setup_stubs
    cd "$REPO_ROOT"

    # Minimal globals that common.sh reads (sourced without n8n_manager.sh)
    export LOG_LEVEL="INFO"
    export APT_UPDATED=false
    export N8N_DIR="$BATS_TEST_TMPDIR/n8n"
    mkdir -p "$N8N_DIR"
    export ENV_FILE="$N8N_DIR/.env"
    export COMPOSE_FILE="$N8N_DIR/docker-compose.yml"

    # Source only common.sh (it must be standalone-sourceable)
    # shellcheck disable=SC1090
    source "$REPO_ROOT/lib/common.sh"
}

# ---------------------------------------------------------------------------
# log()
# ---------------------------------------------------------------------------

@test "log INFO prints to stdout" {
    run bash -c "
        LOG_LEVEL=INFO
        source '$REPO_ROOT/lib/common.sh'
        log INFO 'hello world'
    "
    [ "$status" -eq 0 ]
    [[ "$output" == *"[INFO]"* ]]
    [[ "$output" == *"hello world"* ]]
}

@test "log DEBUG is suppressed at INFO level" {
    run bash -c "
        LOG_LEVEL=INFO
        source '$REPO_ROOT/lib/common.sh'
        log DEBUG 'should not appear'
    "
    [ "$status" -eq 0 ]
    [[ "$output" != *"should not appear"* ]]
}

@test "log WARN goes to stderr" {
    run bash -c "
        LOG_LEVEL=INFO
        source '$REPO_ROOT/lib/common.sh'
        log WARN 'warning message' 2>&1
    "
    [ "$status" -eq 0 ]
    [[ "$output" == *"[WARN]"* ]]
    [[ "$output" == *"warning message"* ]]
}

@test "log ERROR goes to stderr" {
    run bash -c "
        LOG_LEVEL=INFO
        source '$REPO_ROOT/lib/common.sh'
        log ERROR 'error message' 2>&1
    "
    [ "$status" -eq 0 ]
    [[ "$output" == *"[ERROR]"* ]]
    [[ "$output" == *"error message"* ]]
}

@test "log INFO suppressed at WARN level" {
    run bash -c "
        LOG_LEVEL=WARN
        source '$REPO_ROOT/lib/common.sh'
        log INFO 'should be hidden'
    "
    [ "$status" -eq 0 ]
    [[ "$output" != *"should be hidden"* ]]
}

# ---------------------------------------------------------------------------
# mask_secret()
# ---------------------------------------------------------------------------

@test "mask_secret masks a long string" {
    result="$(mask_secret "abcdefghijklmnop")"
    [[ "$result" == "abcd***mnop" ]]
}

@test "mask_secret shows *** for short strings" {
    result="$(mask_secret "abc")"
    [[ "$result" == "***" ]]
}

@test "mask_secret exactly 8 chars shows ***" {
    result="$(mask_secret "abcdefgh")"
    [[ "$result" == "***" ]]
}

# ---------------------------------------------------------------------------
# looks_like_b64()
# ---------------------------------------------------------------------------

@test "looks_like_b64 accepts valid base64" {
    run looks_like_b64 "dGVzdHNlY3JldA=="
    [ "$status" -eq 0 ]
}

@test "looks_like_b64 rejects non-base64 string" {
    run looks_like_b64 "CHANGE_ME_BASE64_32_BYTES"
    [ "$status" -ne 0 ]
}

@test "looks_like_b64 accepts empty string" {
    run looks_like_b64 ""
    [ "$status" -eq 0 ]
}

# ---------------------------------------------------------------------------
# parse_domain_arg()
# ---------------------------------------------------------------------------

@test "parse_domain_arg strips https:// prefix" {
    result="$(parse_domain_arg "https://example.com")"
    [ "$result" = "example.com" ]
}

@test "parse_domain_arg strips http:// prefix" {
    result="$(parse_domain_arg "http://example.com")"
    [ "$result" = "example.com" ]
}

@test "parse_domain_arg strips www. prefix" {
    result="$(parse_domain_arg "www.example.com")"
    [ "$result" = "example.com" ]
}

@test "parse_domain_arg strips trailing slash" {
    result="$(parse_domain_arg "example.com/")"
    [ "$result" = "example.com" ]
}

@test "parse_domain_arg normalizes to lowercase" {
    result="$(parse_domain_arg "EXAMPLE.COM")"
    [ "$result" = "example.com" ]
}

@test "parse_domain_arg accepts valid subdomain" {
    result="$(parse_domain_arg "n8n.example.com")"
    [ "$result" = "n8n.example.com" ]
}

@test "parse_domain_arg exits 2 on invalid domain" {
    run parse_domain_arg "not_a_domain"
    [ "$status" -eq 2 ]
}

@test "parse_domain_arg exits 2 on empty string" {
    run parse_domain_arg ""
    [ "$status" -eq 2 ]
}

# ---------------------------------------------------------------------------
# box_line()
# ---------------------------------------------------------------------------

@test "box_line formats label and value" {
    result="$(box_line "Label:" "Value")"
    [[ "$result" == *"Label:"* ]]
    [[ "$result" == *"Value"* ]]
}

# ---------------------------------------------------------------------------
# upsert_env_var() and read_env_var()
# ---------------------------------------------------------------------------

@test "upsert_env_var adds new key to empty file" {
    local envfile="$BATS_TEST_TMPDIR/test.env"
    touch "$envfile"
    upsert_env_var "MY_KEY" "my_value" "$envfile"
    run grep "MY_KEY=my_value" "$envfile"
    [ "$status" -eq 0 ]
}

@test "upsert_env_var updates existing key in place" {
    local envfile="$BATS_TEST_TMPDIR/test.env"
    echo "MY_KEY=old_value" > "$envfile"
    echo "OTHER=unchanged" >> "$envfile"
    upsert_env_var "MY_KEY" "new_value" "$envfile"
    run grep "MY_KEY=new_value" "$envfile"
    [ "$status" -eq 0 ]
    run grep "OTHER=unchanged" "$envfile"
    [ "$status" -eq 0 ]
}

@test "upsert_env_var does not duplicate key" {
    local envfile="$BATS_TEST_TMPDIR/test.env"
    echo "MY_KEY=value1" > "$envfile"
    upsert_env_var "MY_KEY" "value2" "$envfile"
    count=$(grep -c "^MY_KEY=" "$envfile")
    [ "$count" -eq 1 ]
}

@test "upsert_env_var creates file if missing" {
    local envfile="$BATS_TEST_TMPDIR/nonexistent.env"
    [ ! -f "$envfile" ]
    upsert_env_var "NEW_KEY" "hello" "$envfile"
    [ -f "$envfile" ]
    run grep "NEW_KEY=hello" "$envfile"
    [ "$status" -eq 0 ]
}

@test "upsert_env_var preserves value with dollar sign" {
    local envfile="$BATS_TEST_TMPDIR/test.env"
    touch "$envfile"
    upsert_env_var "DB_PASS" 'pa$$w0rd' "$envfile"
    val="$(read_env_var "$envfile" "DB_PASS")"
    [ "$val" = 'pa$$w0rd' ]
}

@test "upsert_env_var rejects value with newline" {
    local envfile="$BATS_TEST_TMPDIR/test.env"
    touch "$envfile"
    run upsert_env_var "BAD_KEY" $'line1\nline2' "$envfile"
    [ "$status" -ne 0 ]
}

@test "upsert_env_var fails with missing key argument" {
    local envfile="$BATS_TEST_TMPDIR/test.env"
    touch "$envfile"
    run upsert_env_var "" "value" "$envfile"
    [ "$status" -ne 0 ]
}

# ---------------------------------------------------------------------------
# read_env_var()
# ---------------------------------------------------------------------------

@test "read_env_var returns value for existing key" {
    local envfile="$BATS_TEST_TMPDIR/test.env"
    echo "MY_KEY=hello_world" > "$envfile"
    result="$(read_env_var "$envfile" "MY_KEY")"
    [ "$result" = "hello_world" ]
}

@test "read_env_var returns exit 1 for missing key" {
    local envfile="$BATS_TEST_TMPDIR/test.env"
    echo "OTHER=value" > "$envfile"
    run read_env_var "$envfile" "MISSING_KEY"
    [ "$status" -eq 1 ]
}

@test "read_env_var returns exit 1 for missing file" {
    run read_env_var "/tmp/nonexistent_$(date +%s).env" "ANY_KEY"
    [ "$status" -eq 1 ]
}

@test "read_env_var ignores comment lines" {
    local envfile="$BATS_TEST_TMPDIR/test.env"
    printf '# MY_KEY=not_this\nMY_KEY=real_value\n' > "$envfile"
    result="$(read_env_var "$envfile" "MY_KEY")"
    [ "$result" = "real_value" ]
}

@test "read_env_var strips inline comments" {
    local envfile="$BATS_TEST_TMPDIR/test.env"
    echo 'MY_KEY=value # this is a comment' > "$envfile"
    result="$(read_env_var "$envfile" "MY_KEY")"
    [ "$result" = "value" ]
}

@test "read_env_var handles quoted values" {
    local envfile="$BATS_TEST_TMPDIR/test.env"
    echo 'MY_KEY="quoted value"' > "$envfile"
    result="$(read_env_var "$envfile" "MY_KEY")"
    [ "$result" = "quoted value" ]
}

# ---------------------------------------------------------------------------
# load_env_file()
# ---------------------------------------------------------------------------

@test "load_env_file exports variables into current shell" {
    local envfile="$BATS_TEST_TMPDIR/load_test.env"
    echo "LOAD_TEST_VAR=exported_value" > "$envfile"
    ENV_FILE="$envfile"
    load_env_file "$envfile"
    [ "${LOAD_TEST_VAR:-}" = "exported_value" ]
}

@test "load_env_file is a no-op for missing file" {
    run load_env_file "/tmp/definitely_missing_$(date +%s).env"
    [ "$status" -eq 0 ]
}

# ---------------------------------------------------------------------------
# rotate_or_generate_secret()
# ---------------------------------------------------------------------------

@test "rotate_or_generate_secret replaces placeholder with openssl output" {
    local envfile="$BATS_TEST_TMPDIR/secret.env"
    echo "MY_SECRET=CHANGE_ME_BASE64_16_BYTES" > "$envfile"
    rotate_or_generate_secret "$envfile" "MY_SECRET" "16" "CHANGE_ME_BASE64_16_BYTES"
    val="$(read_env_var "$envfile" "MY_SECRET")"
    # After rotation the value should be the stub output (not the placeholder)
    [[ "$val" != "CHANGE_ME_BASE64_16_BYTES" ]]
    [[ -n "$val" ]]
}

@test "rotate_or_generate_secret does not replace existing real secret" {
    local envfile="$BATS_TEST_TMPDIR/secret.env"
    echo "MY_SECRET=alreadySetValue" > "$envfile"
    rotate_or_generate_secret "$envfile" "MY_SECRET" "16" "CHANGE_ME_BASE64_16_BYTES"
    val="$(read_env_var "$envfile" "MY_SECRET")"
    [ "$val" = "alreadySetValue" ]
}

@test "rotate_or_generate_secret generates key when entry is missing" {
    local envfile="$BATS_TEST_TMPDIR/secret.env"
    touch "$envfile"
    rotate_or_generate_secret "$envfile" "FRESH_SECRET" "16" "PLACEHOLDER"
    run grep "^FRESH_SECRET=" "$envfile"
    [ "$status" -eq 0 ]
    val="$(read_env_var "$envfile" "FRESH_SECRET")"
    [[ -n "$val" ]]
}
