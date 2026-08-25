#!/usr/bin/env bats
# tests/unit/test_doctor.bats — --doctor.
#
# People do not open an issue saying "the toolkit is broken"; they open one
# saying "the container will not start" (#2). --doctor exists so that becomes a
# paste instead of a conversation, and so the security posture is checkable
# rather than assumed.

load '../test_helper/common'

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"

setup() {
    trap '' ERR INT TERM HUP 2>/dev/null || true
    export LOG_LEVEL="INFO"
    export N8N_DIR="$BATS_TEST_TMPDIR/n8n"
    export ENV_FILE="$N8N_DIR/.env"
    export COMPOSE_FILE="$N8N_DIR/docker-compose.yml"
    export POSTGRES_SERVICE="postgres"
    export TOOLKIT_VERSION="test"
    mkdir -p "$N8N_DIR"
    create_test_env "$ENV_FILE"
    printf 'services:\n  main:\n    image: n8nio/n8n:${N8N_IMAGE_TAG:-2.17.7}\n' > "$COMPOSE_FILE"

    source_common
    # shellcheck disable=SC1090
    source "$REPO_ROOT/lib/doctor.sh"

    DISCOVERED_SERVICES=()
    DISCOVERED_MODE="single"
    container_id_for_service() { return 1; }
    docker() { return 1; }
}

# ---------------------------------------------------------------------------
# version_lt() — the CVE comparison rests on it
# ---------------------------------------------------------------------------

@test "version_lt orders versions numerically, not lexically" {
    run version_lt "2.9.3" "2.10.1";  [ "$status" -eq 0 ]   # 9 < 10 despite the string
    run version_lt "2.10.1" "2.9.3";  [ "$status" -eq 1 ]
    run version_lt "2.10.1" "2.10.1"; [ "$status" -eq 1 ]   # equal is not less
    run version_lt "1.123.22" "2.0.0"; [ "$status" -eq 0 ]
}

# ---------------------------------------------------------------------------
# CVE floors — wrong values here report a vulnerable instance as safe
# ---------------------------------------------------------------------------

@test "the CVE floors match the NVD records" {
    # versionEndExcluding from services.nvd.nist.gov, retrieved 2026-08-26:
    #   CVE-2026-21858  fixed 1.121.0
    #   CVE-2026-25049  fixed 1.123.17 / 2.5.2
    #   CVE-2026-27493  fixed 1.123.22 / 2.9.3 / 2.10.1
    # The highest floor per line is what --doctor must enforce.
    [ "$DOCTOR_CVE_FLOOR_1X" = "1.123.22" ]
    [ "$DOCTOR_CVE_FLOOR_2X" = "2.10.1" ]
}

@test "a 2.x version below the floor fails the security section" {
    get_current_n8n_version() { echo "2.9.3"; }
    doctor_check_security
    run bash -c "printf '%s\n' \"\${DOCTOR_FINDINGS[@]}\""
    [[ "${DOCTOR_FINDINGS[*]}" == *"below the CVE patch floor"* ]]
    [ "$DOCTOR_FAIL" -gt 0 ]
}

@test "a 2.x version at the floor passes" {
    get_current_n8n_version() { echo "2.10.1"; }
    doctor_check_security
    [[ "${DOCTOR_FINDINGS[*]}" == *"at or above the CVE patch floor"* ]]
}

@test "a pre-1.x version fails outright" {
    get_current_n8n_version() { echo "0.236.3"; }
    doctor_check_security
    [[ "${DOCTOR_FINDINGS[*]}" == *"predates the 1.x line"* ]]
    [ "$DOCTOR_FAIL" -gt 0 ]
}

# ---------------------------------------------------------------------------
# Security checks
# ---------------------------------------------------------------------------

@test "a placeholder encryption key is a FAIL, not a warning" {
    # It means every credential is protected by a value published in this repo.
    upsert_env_var N8N_ENCRYPTION_KEY "CHANGE_ME_BASE64_32_BYTES" "$ENV_FILE"
    get_current_n8n_version() { echo "2.37.1"; }
    doctor_check_security
    [[ "${DOCTOR_FINDINGS[*]}" == *"still the shipped placeholder"* ]]
    [[ "${DOCTOR_FINDINGS[*]}" == *"FAIL|Security|N8N_ENCRYPTION_KEY is still"* ]]
}

@test "a real encryption key is reported masked, never in full" {
    local secret="dGVzdGtleWJhc2U2NGVuY3J5cHRpb25rZXk="
    get_current_n8n_version() { echo "2.37.1"; }
    doctor_check_security
    [[ "${DOCTOR_FINDINGS[*]}" != *"$secret"* ]]
}

@test "a tracked .env is a FAIL" {
    # This is the GitGuardian failure mode: 321 live instances found through
    # tokens committed to public repositories.
    git -C "$N8N_DIR" init -q 2>/dev/null || skip "git unavailable"
    git -C "$N8N_DIR" add -f .env 2>/dev/null
    get_current_n8n_version() { echo "2.37.1"; }
    doctor_check_security
    [[ "${DOCTOR_FINDINGS[*]}" == *".env is tracked by git"* ]]
}

# ---------------------------------------------------------------------------
# Legacy checks
# ---------------------------------------------------------------------------

@test "dead basic-auth keys are reported" {
    printf 'N8N_BASIC_AUTH_ACTIVE=true\n' >> "$ENV_FILE"
    doctor_check_legacy
    [[ "${DOCTOR_FINDINGS[*]}" == *"N8N_BASIC_AUTH_* is present"* ]]
}

@test "a clean .env reports no dead basic-auth keys" {
    doctor_check_legacy
    [[ "${DOCTOR_FINDINGS[*]}" == *"No dead basic-auth keys"* ]]
}

@test "a pre-v3.1 compose reading \${N8N_VERSION} is reported" {
    printf 'services:\n  main:\n    image: n8nio/n8n:${N8N_VERSION:-2.17.7}\n' > "$COMPOSE_FILE"
    doctor_check_legacy
    [[ "${DOCTOR_FINDINGS[*]}" == *'compose still reads ${N8N_VERSION}'* ]]
}

@test "a --local instance is flagged as not for a public server" {
    : > "$N8N_DIR/docker-compose.local.yml"
    doctor_check_legacy
    [[ "${DOCTOR_FINDINGS[*]}" == *"--local mode"* ]]
}

# ---------------------------------------------------------------------------
# The report
# ---------------------------------------------------------------------------

@test "the verdict is the worst status, and it comes first" {
    doctor_record PASS Health "fine" ""
    doctor_record WARN Legacy "meh" ""
    doctor_record FAIL Security "bad" ""
    get_current_n8n_version() { echo "2.37.1"; }
    run doctor_report
    [[ "${lines[1]}" == *"FAIL"* ]]
    [[ "${lines[1]}" == *"1 fail"* ]]
}

@test "the report ends with a paste-ready block that omits PASS noise" {
    doctor_record PASS Health "a passing check nobody needs in an issue" ""
    doctor_record FAIL Security "the thing that is broken" ""
    get_current_n8n_version() { echo "2.37.1"; }
    run doctor_report
    [[ "$output" == *"--- paste this into your issue ---"* ]]
    [[ "$output" == *"FAIL Security: the thing that is broken"* ]]
    # PASS lines appear in the detail but not in the paste block
    paste_block="${output#*--- paste this into your issue ---}"
    paste_block="${paste_block%%--- end ---*}"
    [[ "$paste_block" != *"a passing check nobody needs"* ]]
}

@test "--doctor is a standalone action and is documented" {
    run bash "$REPO_ROOT/n8n_manager.sh" --help
    [[ "$output" == *"--doctor"* ]]
    [[ "$output" == *"Read-only"* ]]
}

@test "--doctor cannot be combined with another action" {
    run bash "$REPO_ROOT/n8n_manager.sh" --doctor --backup
    [ "$status" -ne 0 ]
}

# ---------------------------------------------------------------------------
# Exit-code plumbing
#
# The first attempt wrapped the entrypoint as `main "$@" || exit $?` to keep the
# ERR trap quiet on a FAIL verdict. That suspends errexit INSIDE main, so a real
# failure in restore or upgrade stopped aborting and the script exited 0 - the
# smoke test caught it when an unattended restore refused correctly and the
# script still reported success.
# ---------------------------------------------------------------------------

@test "the entrypoint is a bare call, so errexit still applies inside main" {
    run tail -n 3 "$REPO_ROOT/n8n_manager.sh"
    [[ "$output" == *'main "$@"'* ]]
    [[ "$output" != *'main "$@" || exit'* ]]
}

@test "main exits with the doctor verdict rather than returning it" {
    grep -q 'exit "\${DOCTOR_EXIT_CODE:-0}"' "$REPO_ROOT/n8n_manager.sh"
    run grep -c 'return "\${DOCTOR_EXIT_CODE:-0}"' "$REPO_ROOT/n8n_manager.sh"
    [ "$output" -eq 0 ]
}

@test "doctor_stack is collected with || so the ERR trap stays quiet" {
    grep -q 'doctor_stack || DOCTOR_EXIT_CODE=1' "$REPO_ROOT/n8n_manager.sh"
}
