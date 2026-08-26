# Monitoring

Prometheus + Grafana, enabled with `--monitoring` at install time (Compose
profile `monitoring`).

- Dashboards: `deploy/monitoring/grafana/provisioning/dashboards/`
- Alert rules: `deploy/monitoring/grafana/provisioning/alerts/`
- Scrape config: `deploy/monitoring/prometheus.yml`

In queue mode, workers are scraped under their own job label (`n8n-worker`), via
DNS discovery, so `--scale worker=N` needs no config change. They are deliberately
not folded into `job="n8n"`: every pre-existing rule is scoped to that label, and
`n8n Down` would fire on each scale-down.

The rules ship with thresholds but no contact point. Give them one with
`--alerts telegram --alert-target '<bot-token>:<chat-id>'`, or configure it in
Grafana. `--doctor` warns when rules exist with nowhere to deliver.

See the root `README.md` for full setup instructions.
