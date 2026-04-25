#!/usr/bin/env bats
# tests/unit/test_env_handling.bats — Unit tests for env file functions
# Coverage: upsert_env_var, read_env_var, load_env_file

load '../helpers/stubs'
load '../helpers/fixtures'

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"

setup() {
    setup_stubs
    cd "$REPO_ROOT"
    export LOG_LEVEL="INFO"
    export APT_UPDATED=false
    export N8N_DIR="$BATS_TEST_TMPDIR/n8n"
    mkdir -p "$N8N_DIR"
    export ENV_FILE="$N8N_DIR/.env"
    export COMPOSE_FILE="$N8N_DIR/docker-compose.yml"
    source "$REPO_ROOT/lib/common.sh"
}

# ---------------------------------------------------------------------------
# upsert_env_var — add new key
# ---------------------------------------------------------------------------

@test "upsert_env_var adds new key when file is empty" {
    local f="$BATS_TEST_TMPDIR/empty.env"
    touch "$f"
    upsert_env_var "KEY1" "value1" "$f"
    run grep "^KEY1=value1$" "$f"
    [ "$status" -eq 0 ]
}

@test "upsert_env_var adds key at end of multi-line file" {
    local f="$BATS_TEST_TMPDIR/multi.env"
    printf 'A=1\nB=2\n' > "$f"
    upsert_env_var "C" "3" "$f"
    result="$(tail -n1 "$f")"
    [[ "$result" == *"C=3"* ]]
}

@test "upsert_env_var does not add duplicate when key already exists" {
    local f="$BATS_TEST_TMPDIR/dup.env"
    echo "MYKEY=old" > "$f"
    upsert_env_var "MYKEY" "new" "$f"
    count="$(grep -c "^MYKEY=" "$f")"
    [ "$count" -eq 1 ]
}

# ---------------------------------------------------------------------------
# upsert_env_var — update existing key
# ---------------------------------------------------------------------------

@test "upsert_env_var updates existing key value" {
    local f="$BATS_TEST_TMPDIR/update.env"
    echo "DOMAIN=old.com" > "$f"
    upsert_env_var "DOMAIN" "new.com" "$f"
    run grep "^DOMAIN=new.com$" "$f"
    [ "$status" -eq 0 ]
}

@test "upsert_env_var does not touch other keys when updating" {
    local f="$BATS_TEST_TMPDIR/update2.env"
    printf 'DOMAIN=old.com\nSSL_EMAIL=admin@test.com\n' > "$f"
    upsert_env_var "DOMAIN" "new.com" "$f"
    run grep "^SSL_EMAIL=admin@test.com$" "$f"
    [ "$status" -eq 0 ]
}

# ---------------------------------------------------------------------------
# upsert_env_var — special characters
# ---------------------------------------------------------------------------

@test "upsert_env_var stores value with hash character" {
    local f="$BATS_TEST_TMPDIR/hash.env"
    touch "$f"
    upsert_env_var "COLOR" "#FF7F00" "$f"
    val="$(read_env_var "$f" "COLOR")"
    # Note: read_env_var strips inline comments, so bare # values need quoting in real .env
    # The function itself stores the literal value; reading back may strip # suffix
    run grep "COLOR=#FF7F00" "$f"
    [ "$status" -eq 0 ]
}

@test "upsert_env_var stores value with ampersand" {
    local f="$BATS_TEST_TMPDIR/amp.env"
    touch "$f"
    upsert_env_var "NAME" "Tom&Jerry" "$f"
    run grep "NAME=Tom&Jerry" "$f"
    [ "$status" -eq 0 ]
}

@test "upsert_env_var stores value with forward slashes" {
    local f="$BATS_TEST_TMPDIR/slash.env"
    touch "$f"
    upsert_env_var "PATH_VAR" "/home/user/n8n" "$f"
    run grep "PATH_VAR=/home/user/n8n" "$f"
    [ "$status" -eq 0 ]
}

@test "upsert_env_var stores empty value" {
    local f="$BATS_TEST_TMPDIR/empty_val.env"
    echo "COMPOSE_PROFILES=monitoring" > "$f"
    upsert_env_var "COMPOSE_PROFILES" "" "$f"
    run grep "^COMPOSE_PROFILES=$" "$f"
    [ "$status" -eq 0 ]
}

@test "upsert_env_var rejects multiline value" {
    local f="$BATS_TEST_TMPDIR/multi_val.env"
    touch "$f"
    run upsert_env_var "BAD" $'line1\nline2' "$f"
    [ "$status" -ne 0 ]
}

# ---------------------------------------------------------------------------
# read_env_var — correct value
# ---------------------------------------------------------------------------

@test "read_env_var returns correct value for simple key" {
    local f="$BATS_TEST_TMPDIR/read_simple.env"
    echo "FOO=bar" > "$f"
    result="$(read_env_var "$f" "FOO")"
    [ "$result" = "bar" ]
}

@test "read_env_var handles KEY=value with spaces around equals" {
    local f="$BATS_TEST_TMPDIR/read_spaces.env"
    echo "FOO = bar" > "$f"
    result="$(read_env_var "$f" "FOO")"
    [ "$result" = "bar" ]
}

@test "read_env_var ignores blank lines" {
    local f="$BATS_TEST_TMPDIR/read_blank.env"
    printf '\n\nFOO=baz\n\n' > "$f"
    result="$(read_env_var "$f" "FOO")"
    [ "$result" = "baz" ]
}

@test "read_env_var ignores lines starting with #" {
    local f="$BATS_TEST_TMPDIR/read_comment.env"
    printf '# FOO=wrong\nFOO=correct\n' > "$f"
    result="$(read_env_var "$f" "FOO")"
    [ "$result" = "correct" ]
}

@test "read_env_var returns first match when key appears once" {
    local f="$BATS_TEST_TMPDIR/read_once.env"
    printf 'FOO=first\nBAR=other\n' > "$f"
    result="$(read_env_var "$f" "FOO")"
    [ "$result" = "first" ]
}

# ---------------------------------------------------------------------------
# read_env_var — missing key or missing file
# ---------------------------------------------------------------------------

@test "read_env_var exits 1 for missing key" {
    local f="$BATS_TEST_TMPDIR/read_miss.env"
    echo "OTHER=val" > "$f"
    run read_env_var "$f" "NOTHERE"
    [ "$status" -eq 1 ]
}

@test "read_env_var exits 1 for missing file" {
    run read_env_var "/nonexistent/path/$(date +%s).env" "ANY"
    [ "$status" -eq 1 ]
}

@test "read_env_var output is empty for missing key" {
    local f="$BATS_TEST_TMPDIR/read_empty.env"
    echo "OTHER=val" > "$f"
    result="$(read_env_var "$f" "NOTHERE" 2>/dev/null || true)"
    [ -z "$result" ]
}

# ---------------------------------------------------------------------------
# load_env_file — exports variables
# ---------------------------------------------------------------------------

@test "load_env_file exports variable to current shell environment" {
    local f="$BATS_TEST_TMPDIR/loadme.env"
    echo "LOAD_TEST_123=exported" > "$f"
    ENV_FILE="$f"
    load_env_file "$f"
    [ "${LOAD_TEST_123:-}" = "exported" ]
}

@test "load_env_file exports multiple variables" {
    local f="$BATS_TEST_TMPDIR/load_multi.env"
    printf 'VAR_A=alpha\nVAR_B=beta\n' > "$f"
    load_env_file "$f"
    [ "${VAR_A:-}" = "alpha" ]
    [ "${VAR_B:-}" = "beta" ]
}

@test "load_env_file returns 0 when file does not exist" {
    run load_env_file "/nonexistent/$(date +%s).env"
    [ "$status" -eq 0 ]
}

@test "load_env_file uses ENV_FILE when no argument given" {
    local f="$BATS_TEST_TMPDIR/default_load.env"
    echo "DEFAULT_LOAD_VAR=yes" > "$f"
    ENV_FILE="$f"
    load_env_file
    [ "${DEFAULT_LOAD_VAR:-}" = "yes" ]
}

# ---------------------------------------------------------------------------
# round-trip: upsert → read
# ---------------------------------------------------------------------------

@test "upsert then read returns correct value for base64-like string" {
    local f="$BATS_TEST_TMPDIR/b64_roundtrip.env"
    touch "$f"
    local secret="dGVzdEVuY3J5cHRpb25LZXkzMkJ5dGVzTE9ORw=="
    upsert_env_var "N8N_ENCRYPTION_KEY" "$secret" "$f"
    result="$(read_env_var "$f" "N8N_ENCRYPTION_KEY")"
    [ "$result" = "$secret" ]
}

@test "upsert twice then read returns second value" {
    local f="$BATS_TEST_TMPDIR/double_upsert.env"
    touch "$f"
    upsert_env_var "MY_KEY" "first" "$f"
    upsert_env_var "MY_KEY" "second" "$f"
    result="$(read_env_var "$f" "MY_KEY")"
    [ "$result" = "second" ]
}

@test "fixtures make_env_file creates readable env file" {
    local dir="$BATS_TEST_TMPDIR/fixture_test"
    mkdir -p "$dir"
    make_env_file "$dir" "mytest.com" "ops@mytest.com"
    result="$(read_env_var "$dir/.env" "DOMAIN")"
    [ "$result" = "mytest.com" ]
    result_email="$(read_env_var "$dir/.env" "SSL_EMAIL")"
    [ "$result_email" = "ops@mytest.com" ]
}
