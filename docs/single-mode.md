# Single Mode

All-in-one, from `deploy/single-mode/docker-compose.yml`. The default.

```bash
sudo ./n8n_manager.sh --install example.com -m you@example.com
```

One n8n container runs the UI, the schedules and the executions, with its task
runner internal. Choose queue mode when executions start competing with the UI
for the same process - see `queue-mode.md`.

See the root `README.md` for full setup instructions.
