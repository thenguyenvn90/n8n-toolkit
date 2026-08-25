#!/usr/bin/env bats
# tests/unit/test_monitoring_config.bats — Contract tests for the shipped
# monitoring config.
#
# In queue mode the worker is what executes workflows, so its CPU, RSS and
# event-loop numbers are the ones that matter — yet Prometheus scraped only
# `main`. Adding workers is easy to get wrong: every pre-existing alert rule is
# scoped to job="n8n", and `n8n Down` is min_over_time(up{job="n8n"}), so
# folding workers into that job would fire a critical alert on every scale-down.

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
PROM="$REPO_ROOT/deploy/monitoring/prometheus.yml"
ALERTS="$REPO_ROOT/deploy/monitoring/grafana/provisioning/alerts/n8n_grafana_alerts.json"
QUEUE_COMPOSE="$REPO_ROOT/deploy/queue-mode/docker-compose.yml"

# ---------------------------------------------------------------------------
# Worker metrics are actually enabled and scraped
# ---------------------------------------------------------------------------

@test "the worker service sets N8N_METRICS=true" {
    # Grab the worker service block: from `  worker:` to the next top-level
    # service key at the same indentation.
    run awk '/^  worker:/{f=1} f&&/^  [a-z]/&&!/^  worker:/{f=0} f' "$QUEUE_COMPOSE"
    [ "$status" -eq 0 ]
    [[ "$output" == *"N8N_METRICS=true"* ]]
}

@test "prometheus.yml scrapes workers under a job label other than n8n" {
    grep -q "job_name: n8n-worker" "$PROM"
    # and the worker job must not be named plain `n8n`
    run grep -c "job_name: n8n$" "$PROM"
    [ "$output" -eq 1 ]
}

@test "the worker scrape job uses DNS discovery so --scale worker=N is picked up" {
    run awk '/job_name: n8n-worker/{f=1} f&&/^  - job_name/&&!/n8n-worker/{f=0} f' "$PROM"
    [[ "$output" == *"dns_sd_configs"* ]]
    [[ "$output" == *"worker"* ]]
}

# ---------------------------------------------------------------------------
# The pre-existing alert rules must keep meaning what they meant
# ---------------------------------------------------------------------------

@test "every pre-existing alert rule still matches only job=\"n8n\"" {
    # No rule outside the Workers group may reference job="n8n-worker",
    # and no rule inside it may reference bare job="n8n".
    run python3 - "$ALERTS" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding='utf-8'))
bad = []
for g in d['groups']:
    is_worker = g['name'] == 'n8n - Workers'
    for r in g['rules']:
        exprs = [q['model'].get('expr', '') for q in r['data'] if 'model' in q]
        blob = ' '.join(exprs)
        if is_worker and 'job="n8n"' in blob:
            bad.append(f"worker rule {r['uid']} references job=\"n8n\"")
        if not is_worker and 'n8n-worker' in blob:
            bad.append(f"non-worker rule {r['uid']} references n8n-worker")
print('\n'.join(bad))
sys.exit(1 if bad else 0)
PY
    [ "$status" -eq 0 ]
}

@test "the worker-down rule tolerates zero replicas" {
    # With no workers running there are no DNS targets and therefore no data.
    # That is "scaled to zero", not an outage, so noDataState must not alert.
    run python3 - "$ALERTS" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding='utf-8'))
for g in d['groups']:
    for r in g['rules']:
        if r['uid'] == 'n8n-worker-down':
            print(r['noDataState'])
            sys.exit(0 if r['noDataState'] != 'Alerting' else 1)
print('rule not found'); sys.exit(1)
PY
    [ "$status" -eq 0 ]
}

@test "alert rule uids are unique across every group" {
    run python3 - "$ALERTS" <<'PY'
import json, sys, collections
d = json.load(open(sys.argv[1], encoding='utf-8'))
uids = [r['uid'] for g in d['groups'] for r in g['rules']]
dupes = [u for u, n in collections.Counter(uids).items() if n > 1]
print(' '.join(dupes))
sys.exit(1 if dupes else 0)
PY
    [ "$status" -eq 0 ]
}

# ---------------------------------------------------------------------------
# The worker health server does not listen on N8N_PORT
# ---------------------------------------------------------------------------

@test "the worker healthcheck probes QUEUE_HEALTH_CHECK_PORT, not N8N_PORT" {
    # n8n's WorkerServer binds globalConfig.queue.health.port
    # (QUEUE_HEALTH_CHECK_PORT, default 5678). Both default to 5678, so using
    # N8N_PORT only worked by coincidence — set N8N_PORT and the healthcheck
    # would probe a port nothing listens on.
    run awk '/^  worker:/{f=1} f&&/^  [a-z]/&&!/^  worker:/{f=0} f' "$QUEUE_COMPOSE"
    [[ "$output" == *"QUEUE_HEALTH_CHECK_PORT"* ]]
    [[ "$output" != *'localhost:${N8N_PORT'* ]]
}

@test "queue-mode .env.example documents QUEUE_HEALTH_CHECK_PORT" {
    grep -qE '^QUEUE_HEALTH_CHECK_PORT=' "$REPO_ROOT/deploy/queue-mode/.env.example"
}

# ---------------------------------------------------------------------------
# Dashboards
# ---------------------------------------------------------------------------

@test "no two provisioned dashboards share a normalized filename" {
    # A hyphen/en-dash pair provisions the same dashboard twice in Grafana.
    run python3 - "$REPO_ROOT/deploy/monitoring/grafana/provisioning/dashboards" <<'PY'
import os, sys, collections, unicodedata
d = sys.argv[1]
def norm(n):
    n = unicodedata.normalize('NFKD', n)
    for dash in ('–', '—', '−'):
        n = n.replace(dash, '-')
    return n.lower()
names = [norm(f) for f in os.listdir(d) if f.endswith('.json')]
dupes = [n for n, c in collections.Counter(names).items() if c > 1]
print(' '.join(dupes))
sys.exit(1 if dupes else 0)
PY
    [ "$status" -eq 0 ]
}
