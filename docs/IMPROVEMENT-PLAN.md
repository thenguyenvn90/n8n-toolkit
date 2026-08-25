# n8n-toolkit — Improvement Plan

Status: **v3.1.0, v3.2.0 and v3.3.0 shipped** · Created 2026-08-25 · Baseline commit `b30b800`

| Release | State | PRs |
|---|---|---|
| v3.1.0 — Safety | shipped | #6 #7 #8 #9 |
| v3.2.0 — Remove the lies, remove the gate | shipped | #11 #12 #13 #14 |
| v3.3.0 — Hardening | shipped | #16 #17 |
| v3.5.0 — Encryption enforced | pending | — |

This plan came out of a code audit plus a 30-day survey of what self-hosters actually
struggle with. Every finding was verified in the source, not inferred from the README.
File and line references point at the current tree.

It has been through one adversarial review pass; where that pass changed a decision or
caught an error in an earlier draft, the correction is recorded inline rather than quietly
edited out.

---

## 1. Who this toolkit is for

**The solo self-hoster.** One VPS, one n8n instance, no ops team. Their two real fears are
losing data and getting owned. Every decision in this plan is weighted for that person.

This deliberately rules out competing on:

| Territory | Who already owns it |
|---|---|
| Worker autoscaling | [conor-is-my-name/n8n-autoscaling](https://github.com/conor-is-my-name/n8n-autoscaling) — 729★, active, 1 open issue |
| Kubernetes | [8gears/n8n-helm-chart](https://github.com/8gears/n8n-helm-chart) — 703★ |
| Bundled AI stack | [kossakovsky/selfhost-ai](https://github.com/kossakovsky/selfhost-ai) — 921★ |
| Reference compose examples | [n8n-io/n8n-hosting](https://github.com/n8n-io/n8n-hosting) — 1,722★, first-party |

The gap none of them fill is the operational lifecycle: safe upgrades with a rollback,
backups you can actually restore from, and a security posture you can check. That is the
lane, and `n8n_manager.sh` — a real operations CLI rather than a compose file — is the
asset the rest of this plan builds on.

### Why security, not scale

A 30-day survey of r/n8n, the n8n issue tracker, Hacker News, and the web put the pressure
somewhere other than throughput:

- GitGuardian found **321 live instances** accepting API tokens leaked in public GitHub
  commits — no vulnerability needed, just exposed secrets — against 100,000+ instances
  visible on Shodan and 50+ advisories since January 2026.
- Several critical RCEs disclosed in 2026, including
  [CVE-2026-21858](https://nvd.nist.gov/vuln/detail/CVE-2026-21858) ("Ni8mare", reported
  CVSS 10.0, unauthenticated RCE via content-type confusion in file upload — reads the
  credentials database and encryption key off disk) and
  [CVE-2026-27493](https://nvd.nist.gov/vuln/detail/CVE-2026-27493) (reported zero-click
  full server takeover). See the sourcing note below.
- The recurring cause of "n8n is unstable" reports is the Code node duplicating a large
  JSON payload — a single execution can reach 800 MB — on a 1–2 GB VPS.
- The n8n issue tracker in the same window reads like an upgrade-regression log: the JS
  task runner crashing on health-check connections since 2.33.4/2.34.1, mutating array
  methods on `$json` returning null in 2.35.3, sub-workflow data corruption after 2.28.6.

Nobody is asking for a bigger cluster. They are asking not to lose their credentials and
not to have an upgrade take the instance down.

> **Sourcing note — resolved.** The figures above came from secondary reporting (vendor
> blogs, security press) gathered on 2026-08-25, and were checked against NVD before the
> `--doctor` version check was written. The records say:
>
> | CVE | CVSS | First fixed |
> |---|---|---|
> | CVE-2026-21858 | 10.0 | 1.121.0 |
> | CVE-2026-25049 | 9.9 | 1.123.17 / 2.5.2 |
> | CVE-2026-27493 | **9.0** | 1.123.22 / 2.9.3 / 2.10.1 |
>
> So the enforced floors are **1.123.22** and **2.10.1**. Note the correction: CVE-2026-27493
> is **9.0**, not the 10.0 the press reporting claimed — exactly the kind of drift this note
> existed to catch. Retrieved from services.nvd.nist.gov on 2026-08-26.

---

## 2. Findings

Ordered by blast radius.

### F1 — `--restore` can destroy a working instance, with no undo · CRITICAL

`restore_stack()` ([lib/backup.sh:480](../lib/backup.sh#L480)) has no confirmation prompt and
takes no snapshot of the current state. It `cp -f`s the archive's `.env` and
`docker-compose.yml` over the live ones **before** `compose down`, then deletes and
recreates volumes.

A mistyped archive path overwrites the running `N8N_ENCRYPTION_KEY`. Every credential in
the database then becomes permanently undecryptable. There is no recovery path.

The asymmetry makes it worse: `--cleanup`, which is *less* destructive, prints a full
preview and demands confirmation.

### F2 — Backups ship unencrypted secrets to third-party cloud storage · HIGH

`backup_stack()` puts `.env.bak` into the archive ([lib/backup.sh:84](../lib/backup.sh#L84)) —
`N8N_ENCRYPTION_KEY`, `POSTGRES_PASSWORD`, `REDIS_PASSWORD` — alongside a full Postgres
dump. `upload_backup_rclone()` then sends that archive to Google Drive as-is. There is no
`gpg` call anywhere in the repo.

One compromised Google account yields every credential the n8n instance holds.

### F3 — `N8N_BASIC_AUTH_*` is security theatre · HIGH

Both `.env.example` files ship `N8N_BASIC_AUTH_ACTIVE=true`, and
[lib/install.sh:61](../lib/install.sh#L61) generates a random password into
`N8N_BASIC_AUTH_PASSWORD`.

Basic auth was **removed from n8n in 1.0** and replaced by user management. The setting is
inert. It costs a generated secret and, worse, tells the operator their instance is
protected by something that no longer exists.

> The `--basic-auth-user` / `--basic-auth-pass` CLI flags are a different thing and are
> correct — they feed `ensure_monitoring_auth()` for the Traefik htpasswd in front of
> Grafana and Prometheus. Leave them alone.

### F4 — Queue mode is monitored half-blind · HIGH

[deploy/monitoring/prometheus.yml](../deploy/monitoring/prometheus.yml) scrapes only
`main:5678`. The `worker` service sets no `N8N_METRICS=true` and appears in no scrape
target.

In queue mode the worker is what executes workflows. Its CPU, RSS, and event-loop metrics
are invisible, so the "Queue Mode Health" dashboards are missing the half that matters —
precisely the blind spot in the OOM-crash scenario that dominates the community reports.

> **Two constraints the fix must respect** (both missed in the first draft of this plan):
>
> 1. **Do not scrape workers under `job="n8n"`.** All 14 existing alert rules are scoped to
>    that label. `n8n Down` is `min_over_time(up{job="n8n"}[2m])`, so a worker disappearing
>    during a scale-down would fire it, and `Version skew detected` changes meaning. Workers
>    get their own `job="n8n-worker"` and their own down rule that tolerates N=0.
> 2. **Confirm the port before writing the scrape job.** n8n docs state that both `main` and
>    `worker` instances can expose metrics with `N8N_METRICS=true`
>    ([n8n-io/n8n#7146](https://github.com/n8n-io/n8n/issues/7146), closed 2023), but do not
>    document which port a worker serves them on, and the worker's HTTP server historically
>    existed only for the health check. Verify against a running worker; do not assume 5678.

### F5 — No CI · HIGH

No `.github/workflows/`. The 262-test bats suite runs only when somebody remembers.

The suite also has a known blind spot: its fixtures ship their own compose file, so a
mismatch between what the scripts write into `.env` and what the *shipped* templates read
is invisible to it. That is exactly how the `N8N_VERSION` / `N8N_IMAGE_TAG` regression
behind issue #4 shipped green.

### F6 — The toolkit cannot report its own version · MEDIUM

`-v` / `--version` means the *n8n* version. The toolkit's own version exists only as a
comment on line 10 of `n8n_manager.sh`. Git carries a single `v2.0.0` tag — there is no
`v3.0.0` tag and no GitHub release.

A bug reporter has no way to say which revision they are running, which is the root of
why issue #4 was hard to pin down.

### F7 — No way to run without a public domain · MEDIUM

`check_domain()` ([lib/common.sh:1443](../lib/common.sh#L1443)) returns 1 when the A record
does not resolve to the server's public IP, which aborts the install. Combined with Let's
Encrypt, that means: no local trial, no CI smoke test, and no way for a newcomer to
evaluate the toolkit before buying a VPS.

This is also a hard prerequisite for the CI smoke test in F5.

> **Cost correction.** The first draft described the fix as "self-signed TLS, skip
> `check_domain`". That understates it: `certresolver=le` is hardcoded across **9 label
> lines** in the two compose files, plus three `certificatesresolvers.le.acme.*` command
> lines each. A flag alone cannot switch it. See D17.

### F8 — Backup retention is hardcoded and overloaded · MEDIUM

`DAYS_TO_KEEP=7` ([n8n_manager.sh:107](../n8n_manager.sh#L107)) has no CLI flag and governs
three different lifetimes at once: log files, local backups, and remote backups. Seven days
is reasonable for logs and short for backups, and the operator cannot change either.

### F9 — Duplicate Grafana dashboards · LOW

`n8n-Queue-Mode-Health-Essentials.json` and `n8n–Queue-Mode-Health-Essentials.json` differ
only by hyphen versus en-dash. Same for the `Full` pair. Grafana provisions all four, so
the user sees every queue dashboard twice.

### F10 — Alert rules fire into nothing · MEDIUM

`deploy/monitoring/grafana/provisioning/` contains `alerts/`, `dashboards/`, and
`datasources/` — but no contact points and no notification policies. The 14 rules evaluate
and have nowhere to deliver.

### F11 — SMTP password can be left in `/tmp` · LOW

`send_email()` ([lib/common.sh:1897](../lib/common.sh#L1897)) writes `SMTP_PASS` to a
`mktemp` file for msmtp's `--passwordeval`, `chmod 600`s it, and removes it at line 1935 —
with **no trap**. An interrupt or an `errexit` between those two points leaves the SMTP
password on disk in plaintext.

Found during the review of this plan, not the original audit. One-line fix
(`trap 'rm -f "$pass_tmp"' RETURN`), recorded because a document that presents itself as a
security audit cannot drop a finding it produced itself.

### F12 — `safe_wipe_target_dir` could wipe the filesystem root · CRITICAL

Found by the shellcheck job from #6 on its first run (`SC2115`). The self-deletion guard
compares `$SCRIPT_DIR` against `"$abs_tgt"/*`, which cannot match when `abs_tgt` is `/` —
the glob becomes `//*`. So `-d /` expanded to `rm -rf /*` while running as root.

Fixed in #7: path guards run **before** the existence check, and reject the root and any
top-level directory.

### F13 — one page of Docker Hub tags yields ~4 usable versions · LOW

`_fetch_stable_tags 100` requests 100 tags, but the page is dominated by arch and sha
variants (`2.37.1-amd64`, `2.37.1-<sha>-pc`, …). Only **4** pure-semver names survive the
filter, so `list_available_versions` promises the latest 5 and can only ever return 4.

Not yet fixed. Surfaced while writing the smoke test, which had to take the oldest
available tag rather than a fixed offset.

### F14 — the upgrade wrote the new tag and came back on the old one · HIGH

Found by the lifecycle smoke test (#14) on its first real version change:

```
installed 2.36.6, asked for 2.37.1, .env says '2.37.1', running '2.36.6'
```

`upgrade_stack` calls `load_env_file`, which sources `.env` with `allexport`, so the **old**
tag stays exported in the process — and Docker Compose resolves shell environment variables
ahead of `--env-file`. The stack came back on the version it was already running while
`.env` and the summary both claimed the new one. Verified directly:

```
$ TAG=shellwins docker compose --env-file .env config    # .env has TAG=fromfile
image: alpine:shellwins
```

Same user-visible symptom as issue #4 — *upgrade will not advance past version X* — by a
different mechanism, and it **survived that fix**. The bats suite could never have caught
it: it stubs docker, so the env-precedence layer does not exist there.

Fixed in #14: the resolved tag is exported as well as written, and the upgrade verifies the
running version afterwards instead of printing "successfully upgraded" above the old number.

---

## 3. What is already good — do not rebuild it

Two things were on an earlier draft of this roadmap and were removed after reading the
code. Recording them so nobody re-proposes them:

**Alert thresholds are already done, and done well.**
[n8n_grafana_alerts.json](../deploy/monitoring/grafana/provisioning/alerts/n8n_grafana_alerts.json)
carries 14 rules with better thresholds than any published guide: event-loop p99 at
250 ms / 500 ms, RSS at 850 MiB, API error ratio at 2% / 5%, queue backlog at 0 / 100,
"queue active but throughput ≈ 0", n8n down for 2 m, FDs at 80% of limit, and version
skew across instances. The gap is delivery (F10), not thresholds.

**`--basic-auth-user` / `--basic-auth-pass` work correctly.** See the note under F3.

---

## 4. Decisions

Settled during the design review. Each records the alternative that was rejected, because
the reasoning is the part that gets lost.

| # | Decision | Rejected alternative |
|---|---|---|
| D1 | Target the solo self-hoster | Agency / multi-client — walks into autoscaling and Helm territory |
| D2 | Fix F1 and F2 before any new feature | Ship `--doctor` first for stars — a toolkit whose restore can wipe an instance has no credible feature on top |
| D3 | Force encryption on upload; leave local archives plain | Encrypt everything (friction, no threat model) or warn only (does not stop the leak) |
| D4 | Drop `N8N_BASIC_AUTH_*`; add `N8N_INSTANCE_OWNER_MANAGED_BY_ENV` + `--owner-email` / `--owner-password` | Delete only, or keep with a "deprecated" comment — neither gives back what the operator thought they had |
| D5 | CI in three stages: bats → shellcheck → smoke test | Jumping straight to the smoke test; it depends on F7 |
| D6 | `--keep-days N` for backups; logs stay fixed at 7 | Three separate retention flags — three knobs for one need |
| D7 | Passphrase from the environment at run time; accept it from `.env` but WARN | Auto-generating one (a backup encrypted with a key the user does not hold is not a backup) |
| D8 | Restore gates on a preview plus `[y/N]`, bypassed with the existing `-f` | A type-the-domain confirmation — needless friction in a 3 a.m. recovery |
| D9 | Always snapshot `.env` + compose; skip the DB dump if one was taken within the hour | Snapshot everything every time (slow) or config only (loses the DB) |
| D10 | One `--doctor` covering health *and* security audit | Separate `--doctor` and `--audit` — people paste one output into an issue, not two |
| D11 | Wire the alert contact point; do not touch thresholds | Writing new rules — the existing ones are already better than the published guides |
| D12 | `gpg --symmetric --cipher-algo AES256`; hard-fail if `gpg` is absent | `openssl enc` (weak default KDF, behaviour has shifted between releases). Never silently upload plaintext |
| D13 | Keep pre-flight snapshots in `backups/pre-restore/` and `backups/pre-upgrade/`, exempt from pruning, keep the last 3 by count | Leaving them in `backups/` — the `-mtime +7` prune would eat the rescue copy |
| D14 | Auto-rollback only on objective signals (health-check failure, restart loop); print the rollback command for anything else | Detecting logic regressions automatically — beyond what a shell script can know |
| D15 | `--doctor` emits flat text with a `--- paste this into your issue ---` block, secrets masked | JSON — nobody pastes JSON into an issue |
| D16 | Report legacy config in `--doctor`; never auto-migrate a user's `.env` | Rewriting their `.env` on upgrade — that file is theirs |
| D17 | `--local` ships as a `docker-compose.local.yml` overlay | Templating `${CERT_RESOLVER}` into the production labels — adds a variable at exactly the spot that produced issue #4, and lets a local-mode bug reach production users |
| D18 | Enforced encryption gets a two-release grace period: warn loudly with a countdown, enforce after | A straight `v4.0.0` (heavy for one feature) or opt-in only (leaves the insecure default in place) |
| D19 | Workers scrape under `job="n8n-worker"` with their own down rule | Reusing `job="n8n"` — would make `n8n Down` fire on every scale-down and change what version-skew means |
| D20 | Answer issue #1 as a `--doctor` check: does an active workflow have a row in `webhook_entity`? | Leaving it out of the plan — it turns an open question into a diagnostic anyone can run |
| D21 | Acceptance criteria are named bats tests, not prose | Prose criteria — everybody declares those satisfied |
| D22 | Ship the CI PR first, before the code PRs it protects | Merging CI last — the code changes would land with nothing proving they broke nothing |

---

## 5. Versioning

The plan's first draft was inconsistent with itself. Corrected scheme:

| Tag | Commit | Why |
|---|---|---|
| `v3.0.0` | `0d83837` | The v3.0 rewrite — n8n 2.x support, modular `lib/`, wizard, 255 tests |
| `v3.0.1` | `b30b800` | Pure bugfix (image-tag contract, install `.env.example` fallback, backup version label). No new surface, so patch, not minor |
| `v3.1.0` | next | The safety release below — it adds `--self-version`, restore gating and snapshots, so it is a minor |

---

## 6. Release plan

Each item carries **Done when**: the bats test that must pass. An item without a passing
named test is not done (D21).

### v3.1.0 — safety · SHIPPED

Everything here closes a way to lose data or lose sight of the system. Four PRs, in this
order:

**PR 1 — `ci`** (merge first, D22)

1. **CI, fast job.** GitHub Actions running bats plus shellcheck on every push. *(F5, D5)*
   Done when: the workflow runs green on a push and fails on a deliberately broken test.

**PR 2 — `restore-safety`** (F1 — guard and snapshot ship together; a guard with no
snapshot still leaves no way back)

2. **Restore guard.** Preview the archive (file, date, FQDN) and compare the archive's
   `N8N_ENCRYPTION_KEY` against the running one — reporting *match / different / no
   existing instance*. Then `[y/N]`, bypassed by `-f`. Move the `.env` and compose
   overwrite to **after** validation, not before. *(F1, D8)*
3. **Pre-flight snapshots.** Auto-snapshot into `backups/pre-restore/` and
   `backups/pre-upgrade/`, exempt from pruning, last 3 kept by count. Config always; DB
   dump skipped if one is under an hour old. *(F1, D9, D13)*

   Done when `tests/integration/test_restore_flow.bats` passes:
   - `restore aborts when the archive encryption key differs and -f is absent`
   - `restore leaves the live .env untouched when validation fails`
   - `restore writes a pre-restore snapshot before touching .env`
   - `pre-restore snapshots survive the backup prune`
   - `restore proceeds without a prompt when -f is given`

**PR 3 — `worker-metrics`**

4. **Worker metrics.** Add `N8N_METRICS=true` to the `worker` service and a Prometheus
   scrape job under `job="n8n-worker"` using DNS service discovery, plus a worker-down rule
   that tolerates zero replicas. Verify the worker's metrics port against a running
   container first. *(F4, D19)*
   Done when `tests/unit/test_monitoring_config.bats` passes:
   - `prometheus.yml scrapes workers under a job label other than n8n`
   - `every existing alert rule still matches only job="n8n"`
   - `the worker service sets N8N_METRICS=true`

**PR 4 — `version-reporting`**

5. **Toolkit version.** Promote `TOOLKIT_VERSION` to a real variable, print it in `--help`
   and at the top of every log file, add `--self-version`. Tag per section 5. *(F6)*
6. **Delete the two en-dash dashboard files.** *(F9)*
7. **Trap the SMTP password temp file.** *(F11)*

   Done when `tests/unit/test_version.bats` gains:
   - `--self-version prints a semver matching TOOLKIT_VERSION`
   - `no two provisioned dashboards share a normalized filename`

### v3.2.0 — remove the lies, remove the gate · SHIPPED

8. **Drop `N8N_BASIC_AUTH_*`** from both `.env.example` files and from
   `rotate_or_generate_secret`. Add `N8N_INSTANCE_OWNER_MANAGED_BY_ENV` with
   `--owner-email` / `--owner-password` so install provisions the instance owner directly.
   *(F3, D4)*
   Done when: `no shipped .env.example contains N8N_BASIC_AUTH_` and
   `install writes N8N_INSTANCE_OWNER_MANAGED_BY_ENV when --owner-email is given`.
9. **`--local` mode** as a `docker-compose.local.yml` overlay: self-signed TLS, no ACME
   resolver, `*.localhost` FQDNs, `check_domain` skipped. The `compose()` helper learns to
   stack `-f`. Unblocks local trials, CI, and pre-purchase evaluation. *(F7, D17)*
   Done when: `--local install brings the stack healthy with no public DNS` and
   `the production compose file is byte-identical with and without --local`.
10. **`--keep-days N`** for backup retention; logs stay at 7. *(F8, D6)*
    Done when: `--keep-days 30 keeps a 20-day-old archive that the default would prune`.
11. **CI, slow job.** On PRs into `main` and nightly: `--local` install → backup → restore
    → upgrade → doctor. This is the only thing that catches "compose reads variable A,
    script writes variable B". *(F5, D5)*

### v3.3.0 — hardening · SHIPPED

12. **`--doctor`.** One command, three sections — runtime health, security audit, legacy
    config — with a PASS/WARN/FAIL summary at the top and a masked copy-paste block at the
    bottom. *(F3, D10, D15, D16, D20)*
    - Security: `N8N_ENCRYPTION_KEY` still a placeholder · port 5678 exposed to the
      internet · n8n version below the CVE patch line (**pin thresholds from NVD first —
      see the sourcing note**) · secrets committed to git (the GitGuardian failure mode) ·
      `.n8n` file permissions · backups uploaded unencrypted.
    - Legacy: `N8N_BASIC_AUTH_*` present · compose still on `${N8N_VERSION}`.
    - Webhook registration: for each active workflow, is there a row in `webhook_entity`?
      This is the diagnostic for issue #1 (production forms 404), which stays open pending
      the reporter's logs.
13. **Encrypted upload, phase 1 (warn).** `--encrypt` using
    `gpg --symmetric --cipher-algo AES256`; `BACKUP_PASSPHRASE` from the environment,
    accepted from `.env` with a WARN that states the limit plainly: it defends against
    someone who can read your Google Drive, not against someone who can read your VPS.
    Uploading plaintext still works but prints a loud warning naming the release that will
    stop allowing it. `--doctor` flags it. *(F2, D3, D7, D12, D18)*
14. **Alert delivery.** Provision a Grafana contact point and notification policy via
    `--alerts telegram <webhook>`. Thresholds untouched. *(F10, D11)*

### v3.5.0 — encryption enforced · PENDING

15. **Encrypted upload, phase 2.** Encryption becomes mandatory whenever an rclone remote
    is set; `--no-encrypt` to opt out explicitly; hard-fail when `gpg` is missing rather
    than uploading plaintext. *(F2, D18)*

### Explicitly out of scope

Worker autoscaling · Kubernetes · a bundled AI stack · additional Grafana dashboards ·
additional alert rules.

---

## 7. What execution changed

The plan survived contact largely intact. Where it did not, here is what moved and why.

- **F9 (duplicate dashboards) shipped in the worker-metrics PR, not the version PR.** It is
  monitoring config, so it belongs with its test. The duplicates turned out to be
  byte-identical *and* to carry the same Grafana `uid`, so provisioning loaded the same
  dashboard twice.
- **Three findings were added during execution**: F12, F13, F14 above. Two of them were
  found by the CI this plan introduced, which is the argument for D22 (CI first) making
  itself.
- **`--owner-password` needed a hash, not a password.** The plan named the flag before
  anyone read the loader; `N8N_INSTANCE_OWNER_PASSWORD_HASH` takes a pre-hashed bcrypt
  string and n8n refuses to boot on anything else. The flag kept its name and hashes the
  value before writing it.
- **The `--local` cost estimate was wrong and the plan says so** (see F7). Correcting it in
  place, rather than quietly, is why D17 chose an overlay.
- **Two self-inflicted bugs are recorded in the history rather than squashed away**: the
  snapshot path returned on stdout while `log()` also writes there (#14), and wrapping the
  entrypoint in `|| exit $?` which suspended `errexit` inside `main` (#16). Both were caught
  by the smoke test, not by review.

---

## 8. Open, not forgotten

**Issue #1 — production forms 404.** Not reproducible against the current queue-mode
template, which sets neither `N8N_DISABLE_PRODUCTION_MAIN_PROCESS` nor dedicated webhook
processors, so `main` serves `/form/` by default. Waiting on the reporter's
activation-time logs. Item 12 turns the question into a check anyone can run.

---

## 9. Positioning

> n8n-autoscaling makes your instance **big**. This toolkit keeps it **alive** — backups
> that restore, upgrades with a rollback, hardening you can check, and one command that
> tells you what broke.
