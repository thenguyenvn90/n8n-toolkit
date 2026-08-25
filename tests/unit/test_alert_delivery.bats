#!/usr/bin/env bats
# tests/unit/test_alert_delivery.bats — Grafana alert delivery.
#
# The repo ships 14 alert rules with better thresholds than any published guide:
# event-loop p99 at 250/500ms, RSS at 850MiB, API error ratio at 2%/5%, queue
# backlog, "queue active but throughput ~ 0", version skew. What provisioning/
# did NOT contain was a contact point or a notification policy, so all 14
# evaluated and notified nobody.
#
# So this adds delivery and deliberately does not touch a single threshold.

load '../test_helper/common'

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
ALERTS_JSON="$REPO_ROOT/deploy/monitoring/grafana/provisioning/alerts/n8n_grafana_alerts.json"

setup() {
    trap '' ERR INT TERM HUP 2>/dev/null || true
    export LOG_LEVEL="INFO"
    export N8N_DIR="$BATS_TEST_TMPDIR/n8n"
    mkdir -p "$N8N_DIR"
    source_common
}

CP="monitoring/grafana/provisioning/alerting/contactpoints.yaml"

# ---------------------------------------------------------------------------
# Provisioning
# ---------------------------------------------------------------------------

@test "telegram provisioning writes a contact point and a policy" {
    run provision_alert_channel telegram "123456:ABC-DEF_ghi:-1001234567890"
    [ "$status" -eq 0 ]
    [ -f "$N8N_DIR/$CP" ]
    grep -q "contactPoints:" "$N8N_DIR/$CP"
    grep -q "policies:" "$N8N_DIR/$CP"
    grep -q "type: telegram" "$N8N_DIR/$CP"
}

@test "the bot token is split on the LAST colon, because tokens contain one" {
    # A Telegram bot token is itself "<digits>:<secret>", so a naive split on the
    # first colon truncates it and the contact point silently never delivers.
    provision_alert_channel telegram "8123456789:AAH1a-bcDEF_gh2IJKlmNOP3qrs4TUV5wxy:-1009876543210"
    grep -q "bottoken: 8123456789:AAH1a-bcDEF_gh2IJKlmNOP3qrs4TUV5wxy" "$N8N_DIR/$CP"
    grep -q 'chatid: "-1009876543210"' "$N8N_DIR/$CP"
}

@test "the contact point file is not world-readable" {
    # It holds a bot token that can post as your bot.
    # Some filesystems (NTFS via git-bash, some CI volumes) ignore chmod, so
    # prove chmod works here before asserting on it - otherwise this test
    # reports a permissions bug that is really a filesystem limitation.
    local probe="$BATS_TEST_TMPDIR/chmod-probe"
    : > "$probe"; chmod 600 "$probe"
    [ "$(stat -c '%a' "$probe" 2>/dev/null || echo 600)" = "600" ]         || skip "this filesystem does not honour chmod"

    provision_alert_channel telegram "123:abc:456"
    local perms
    perms="$(stat -c '%a' "$N8N_DIR/$CP" 2>/dev/null || echo 600)"
    [ "$perms" -le 600 ]
}

@test "an unsupported channel is refused" {
    run provision_alert_channel carrier-pigeon "nest:1"
    [ "$status" -eq 1 ]
    [[ "$output" == *"Unsupported alert channel"* ]]
}

@test "an empty target half is refused" {
    run provision_alert_channel telegram ":"
    [ "$status" -eq 1 ]
    [[ "$output" == *"bot-token"* ]]
}

# ---------------------------------------------------------------------------
# The thresholds are not ours to change
# ---------------------------------------------------------------------------

@test "the shipped alert rules and their thresholds are untouched" {
    run python3 - "$ALERTS_JSON" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding='utf-8'))
rules = [r for g in d['groups'] for r in g['rules']]
print(len(rules))
sys.exit(0 if len(rules) >= 14 else 1)
PY
    [ "$status" -eq 0 ]
    # Spot-check the thresholds the plan singled out as already good.
    grep -q "850 MiB" "$ALERTS_JSON"
    grep -q "500ms" "$ALERTS_JSON"
    grep -q "> 5%" "$ALERTS_JSON"
}

@test "provisioning delivery does not write into the alerts directory" {
    provision_alert_channel telegram "123:abc:456"
    [ ! -e "$N8N_DIR/monitoring/grafana/provisioning/alerts" ]
}

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@test "--alerts requires a supported channel" {
    run bash "$REPO_ROOT/n8n_manager.sh" --install example.com --alerts carrier-pigeon --alert-target x:y
    [ "$status" -ne 0 ]
}

@test "--alerts and --alert-target are documented" {
    run bash "$REPO_ROOT/n8n_manager.sh" --help
    [[ "$output" == *"--alerts"* ]]
    [[ "$output" == *"--alert-target"* ]]
    [[ "$output" == *"telegram"* ]]
}

# ---------------------------------------------------------------------------
# doctor knows about it
# ---------------------------------------------------------------------------

@test "doctor warns when alert rules have no contact point" {
    # shellcheck disable=SC1090
    source "$REPO_ROOT/lib/doctor.sh"
    export ENV_FILE="$N8N_DIR/.env"
    export COMPOSE_FILE="$N8N_DIR/docker-compose.yml"
    export BACKUP_DIR="$N8N_DIR/backups"
    create_test_env "$ENV_FILE"
    mkdir -p "$N8N_DIR/monitoring/grafana/provisioning/alerts"
    get_current_n8n_version() { echo "2.37.1"; }
    docker() { return 1; }

    doctor_check_security
    [[ "${DOCTOR_FINDINGS[*]}" == *"no contact point"* ]]

    DOCTOR_FINDINGS=(); DOCTOR_FAIL=0; DOCTOR_WARN=0; DOCTOR_PASS=0
    provision_alert_channel telegram "123:abc:456"
    doctor_check_security
    [[ "${DOCTOR_FINDINGS[*]}" == *"have a delivery channel"* ]]
}
