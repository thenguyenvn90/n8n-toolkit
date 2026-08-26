# Queue Mode

Main + workers + Redis, from `deploy/queue-mode/docker-compose.yml`.

```bash
sudo ./n8n_manager.sh --install example.com -m you@example.com --mode queue
```

Notes specific to this mode:

- The **worker** executes the workflows, so its CPU, RSS and event-loop numbers
  are the ones that matter. Workers expose `/metrics` on
  `QUEUE_HEALTH_CHECK_PORT` (default 5678) - not `N8N_PORT`, which is a different
  setting.
- Scale with `docker compose up -d --scale worker=N`; Prometheus discovers the
  new workers by DNS.
- The main instance serves production webhooks and Form Trigger URLs.

See the root `README.md` for full setup instructions.
