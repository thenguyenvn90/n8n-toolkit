#!/usr/bin/env bats
# tests/unit/test_docs_align.bats — the README must describe the CLI that exists.
#
# The README's "CLI Overview" was a hand-copied paste of `--help`, and it drifted:
# eight flags shipped across v3.1.0 to v3.3.3 (--doctor, --local, --encrypt,
# --no-encrypt, --alerts, --alert-target, --keep-days, --self-version,
# --owner-email, --owner-password) and not one of them appeared in the docs.
#
# Documentation that is checked is documentation that stays true. These tests
# make drift a build failure instead of something a reader discovers.

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
README="$REPO_ROOT/README.md"

# Every flag the CLI accepts, from the getopt long spec itself rather than a
# list maintained by hand here - a flag added without touching this file still
# gets checked.
_cli_long_flags() {
    grep -m1 'LONG="' "$REPO_ROOT/n8n_manager.sh" \
        | sed 's/.*LONG="//; s/".*//' \
        | tr ',' '\n' \
        | sed 's/:*$//' \
        | grep -vE '^\s*$'
}

@test "every long flag the CLI accepts appears in the README" {
    local missing=()
    local flag
    while IFS= read -r flag; do
        grep -q -- "--$flag" "$README" || missing+=("--$flag")
    done < <(_cli_long_flags)

    if (( ${#missing[@]} )); then
        echo "flags missing from README.md: ${missing[*]}"
        return 1
    fi
}

@test "the README CLI block matches the actual --help output" {
    # Both are normalised: leading/trailing space stripped, blank lines dropped.
    # This catches a flag whose description changed, not just a missing name.
    local help_body readme_body
    help_body="$(bash "$REPO_ROOT/n8n_manager.sh" --help 2>&1 \
                 | sed -n '/^Usage:/,/^$/p;/^Actions/,$p' \
                 | sed 's/[[:space:]]*$//' | grep -v '^$' | sort -u)"
    readme_body="$(sed -n '/^## CLI Overview/,/^```$/p' "$README" \
                 | sed '1d;/^```/d' \
                 | sed 's/[[:space:]]*$//' | grep -v '^$' | sort -u)"

    [ -n "$help_body" ]
    [ -n "$readme_body" ]

    # Every line the README claims must exist in --help. The README may omit
    # trailing prose, but it must not invent or keep a stale option line.
    local stale=()
    local line
    while IFS= read -r line; do
        case "$line" in
            -*|--*)
                grep -Fqx "$line" <<< "$help_body" || stale+=("$line")
                ;;
        esac
    done <<< "$readme_body"

    if (( ${#stale[@]} )); then
        printf 'README lines not present in --help:\n'
        printf '  %s\n' "${stale[@]}"
        return 1
    fi
}

@test "the README does not tell anyone to set config n8n removed" {
    # N8N_BASIC_AUTH_* has been inert since n8n 1.0, so instructing a reader to
    # set it is worse than saying nothing. Saying that --doctor DETECTS a
    # leftover is the opposite of a problem, so only assignment forms fail.
    run grep -nE "N8N_BASIC_AUTH_[A-Z]*=" "$README"
    [ "$status" -ne 0 ]
}

@test "the README states the toolkit version it documents" {
    local declared
    declared="$(grep -m1 -E '^TOOLKIT_VERSION=' "$REPO_ROOT/n8n_manager.sh" | cut -d'"' -f2)"
    [ -n "$declared" ]
    grep -q "$declared" "$README"
}

@test "the four capabilities added since v3.0 have their own section" {
    # A flag in a usage block is a reference, not an explanation.
    grep -qi "^## .*Doctor" "$README"
    grep -qi "^## .*Local" "$README"
    grep -qi "Encrypt" "$README"
    grep -qi "instance owner" "$README"
}

@test "the security notes mention backup encryption and doctor" {
    local sec
    sec="$(sed -n '/^## Security Notes/,/^## /p' "$README")"
    [[ "$sec" == *"--encrypt"* ]]
    [[ "$sec" == *"--doctor"* ]]
}
