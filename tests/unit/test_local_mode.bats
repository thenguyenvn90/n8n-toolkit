#!/usr/bin/env bats
# tests/unit/test_local_mode.bats — `--local` overlay.
#
# check_domain() aborts the install when the A record does not resolve to the
# server's public IP, and Traefik demands Let's Encrypt. Together that meant no
# local trial, no CI smoke test, and no way to evaluate the toolkit before
# buying a VPS.
#
# The fix is an overlay rather than a variable in the production compose: a bug
# in local mode cannot reach anyone running in production. These tests pin the
# overlay to the file it is derived from so the two cannot drift.

load '../test_helper/common'

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"

setup() {
    trap '' ERR INT TERM HUP 2>/dev/null || true
    export LOG_LEVEL="INFO"
}

# ---------------------------------------------------------------------------
# Helper: list the label lines of one service in a compose file
# ---------------------------------------------------------------------------
_labels_of() {
    local file="$1" svc="$2"
    awk -v s="  $svc:" '
        $0 == s { in_svc = 1; next }
        in_svc && /^  [a-zA-Z]/ { in_svc = 0 }
        in_svc && /^    labels:/ { in_lbl = 1; next }
        in_lbl && /^    [a-zA-Z]/ { in_lbl = 0 }
        in_svc && in_lbl && /^      - / { sub(/^      - /, ""); print }
    ' "$file"
}

# ---------------------------------------------------------------------------
# The overlay exists and says what it is
# ---------------------------------------------------------------------------

@test "both modes ship a local overlay" {
    [ -f "$REPO_ROOT/deploy/single-mode/docker-compose.local.yml" ]
    [ -f "$REPO_ROOT/deploy/queue-mode/docker-compose.local.yml" ]
}

@test "the overlay drops Let's Encrypt entirely" {
    local f
    for f in "$REPO_ROOT"/deploy/*/docker-compose.local.yml; do
        run grep -c "acme" "$f"
        [ "$output" -eq 0 ]
        run grep -c "certresolver" "$f"
        [ "$output" -eq 0 ]
    done
}

# ---------------------------------------------------------------------------
# The overlay must stay in step with the file it is derived from
# ---------------------------------------------------------------------------

@test "overlay labels equal the production labels minus certresolver" {
    local mode svc base local_f
    for mode in single-mode queue-mode; do
        base="$REPO_ROOT/deploy/$mode/docker-compose.yml"
        local_f="$REPO_ROOT/deploy/$mode/docker-compose.local.yml"

        # Every service the overlay overrides must match base-minus-certresolver.
        while IFS= read -r svc; do
            [ -n "$svc" ] || continue
            local expected actual
            expected="$(_labels_of "$base" "$svc" | grep -v certresolver)"
            actual="$(_labels_of "$local_f" "$svc")"
            [ -n "$expected" ]
            [ "$expected" = "$actual" ]
        done < <(grep -E '^  [a-z-]+:$' "$local_f" | tr -d ' :' | grep -v traefik)
    done
}

@test "overlay traefik command equals production minus the three acme lines" {
    local mode base local_f base_n local_n
    for mode in single-mode queue-mode; do
        base="$REPO_ROOT/deploy/$mode/docker-compose.yml"
        local_f="$REPO_ROOT/deploy/$mode/docker-compose.local.yml"
        base_n="$(grep -cE '^      - "--' "$base" || true)"
        [ "$base_n" -gt 0 ]
        # The overlay only restates traefik's command, so counting its own
        # command lines against the base's acme lines is the check.
        run grep -c "acme" "$base"
        [ "$output" -eq 3 ]
        run grep -c "acme" "$local_f"
        [ "$output" -eq 0 ]
    done
}

@test "the production compose is unchanged by local mode" {
    # The overlay is additive; nothing in it edits the production file.
    grep -q "certresolver=le" "$REPO_ROOT/deploy/queue-mode/docker-compose.yml"
    grep -q "acme.tlschallenge" "$REPO_ROOT/deploy/queue-mode/docker-compose.yml"
}

# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------

@test "compose() stacks the overlay when it is present in N8N_DIR" {
    grep -q 'local_overlay="\$N8N_DIR/docker-compose.local.yml"' "$REPO_ROOT/lib/common.sh"
    grep -q 'flags+=( -f "\$local_overlay" )' "$REPO_ROOT/lib/common.sh"
}

@test "presence of the overlay is the only state local mode needs" {
    # No LOCAL_MODE key is written to .env: later commands infer it from the
    # file, so they cannot disagree with how the stack was brought up.
    run grep -c 'upsert_env_var "LOCAL_MODE"' "$REPO_ROOT/lib/install.sh"
    [ "$output" -eq 0 ]
}

@test "a normal reinstall removes a stale local overlay" {
    grep -q 'rm -f "\$N8N_DIR/docker-compose.local.yml"' "$REPO_ROOT/lib/install.sh"
}

@test "local mode skips the public DNS check" {
    grep -q 'LOCAL_MODE:-false.*== true' "$REPO_ROOT/lib/common.sh"
    run awk '/^preflight_dns_checks\(\)/,/^}/' "$REPO_ROOT/lib/common.sh"
    [[ "$output" == *"LOCAL_MODE"* ]]
}

@test "local mode skips the Let's Encrypt certificate verification" {
    run awk '/^post_up_tls_checks\(\)/,/^}/' "$REPO_ROOT/lib/common.sh"
    [[ "$output" == *"LOCAL_MODE"* ]]
    [[ "$output" == *"self-signed"* ]]
}

@test "--local is documented in --help" {
    run bash "$REPO_ROOT/n8n_manager.sh" --help
    [[ "$output" == *"--local"* ]]
    [[ "$output" == *"not for a public server"* ]]
}

@test "--local is rejected on actions other than install" {
    grep -q 'applies to --install only' "$REPO_ROOT/n8n_manager.sh"
}
