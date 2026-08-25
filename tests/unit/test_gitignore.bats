#!/usr/bin/env bats
# tests/unit/test_gitignore.bats — the paths that must never be committed.
#
# This repository had no .gitignore at all. `queue-mode/.env` and
# `single-mode/.env` are already in the history (f05f72f, 735fcaa); those two
# only ever held placeholders, so nothing needs rotating — but they are proof of
# how a real .env gets committed.
#
# That is the failure mode GitGuardian found 321 live n8n instances through: no
# vulnerability, just secrets in a public repository. --doctor checks whether a
# user's .env is tracked; this checks that the toolkit's own repo makes it hard
# to happen in the first place.

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"

_ignored() {
    git -C "$REPO_ROOT" check-ignore -q "$1"
}

@test "the repository has a .gitignore" {
    [ -f "$REPO_ROOT/.gitignore" ]
}

# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------

@test ".env is ignored, at the root and under deploy/" {
    _ignored ".env"
    _ignored "deploy/queue-mode/.env"
    _ignored "deploy/single-mode/.env"
}

@test ".env.example is NOT ignored" {
    # It is the template the installer copies; ignoring it would break install.
    run _ignored "deploy/queue-mode/.env.example"
    [ "$status" -ne 0 ]
    run _ignored "deploy/single-mode/.env.example"
    [ "$status" -ne 0 ]
}

@test "the Traefik htpasswd and its directory are ignored" {
    _ignored "secrets/htpasswd"
    _ignored "deploy/queue-mode/secrets/htpasswd"
}

@test "the Grafana contact point is ignored" {
    # It carries a Telegram bot token in plain text.
    _ignored "monitoring/grafana/provisioning/alerting/contactpoints.yaml"
    _ignored "contactpoints.yaml"
}

# ---------------------------------------------------------------------------
# Backups
# ---------------------------------------------------------------------------

@test "backup archives are ignored, encrypted ones included" {
    # A .gpg in a public repo is a brute-force target with the passphrase as the
    # only thing between an attacker and every credential in the instance.
    _ignored "backups/n8n_backup_2.37.1_2026-08-26.tar.gz"
    _ignored "backups/n8n_backup_2.37.1_2026-08-26.tar.gz.gpg"
    _ignored "n8n_postgres_dump_2026-08-26.dump"
    _ignored "backups/"
}

@test "the .bak copies install writes are ignored" {
    _ignored ".env.bak"
    _ignored "docker-compose.yml.bak.2026-08-26_10-00-00"
}

# ---------------------------------------------------------------------------
# Runtime and tooling
# ---------------------------------------------------------------------------

@test "logs and restore scratch directories are ignored" {
    _ignored "logs/install_n8n_2026-08-26.log"
    _ignored "n8n_restore_1787684422/"
}

@test "a locally cloned bats is ignored" {
    # tests/run_tests.sh clones bats-core here when it is not on PATH.
    _ignored "tests/bats/"
}

# ---------------------------------------------------------------------------
# Nothing sensitive is tracked right now
# ---------------------------------------------------------------------------

@test "no .env, secret or archive is currently tracked" {
    run git -C "$REPO_ROOT" ls-files
    [ "$status" -eq 0 ]

    # Historical commits are not rewritten (those files held only placeholders),
    # but nothing sensitive may be tracked in the CURRENT tree.
    while IFS= read -r f; do
        case "$f" in
            *.env.example) continue ;;
            *.env|*/secrets/*|*.tar.gz|*.tar.gz.gpg|*.dump|*htpasswd*|*contactpoints.yaml)
                echo "sensitive file is tracked: $f"
                return 1
                ;;
        esac
    done <<< "$output"
}
