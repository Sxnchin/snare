# Assumptions and defaults

Every default or decision that the spec did not fix is listed here with the
reason and where to change it. Keep this file current: add an entry in the
same commit that introduces the default.

## Pins

| What | Value | Why | Change in |
| --- | --- | --- | --- |
| ARTEX | `BaaRai/ARTEX` commit `d89cf781b790ec9a1d071bee7e79de489ed05252` (main as of 2026-11-18) | Spec. The local copy at `../ARTEX-main` was extracted from `ARTEX-main.zip`, has no `.git`, and is identical to that commit. | `deploy/compose/.env` `ARTEX_SRC`, image tag in `deploy/compose/compose.yaml` |
| ARTEX image tag | `snare-lab/artex:d89cf78` | Short form of the pin, so a rebuilt image from another checkout is visibly different. | `compose.yaml` |
| Juice Shop | `bkimminich/juice-shop:v20.4.0` | Latest stable tag on Docker Hub on 2026-11-18 (`latest` and `snapshot` excluded). | `compose.yaml` |
| Postgres (for ARTEX) | `postgres:16-alpine` | The image ARTEX's own compose file uses at the pin. | `compose.yaml` |
| Go | `go 1.26.10` in `go.mod`, `golang:1.26-bookworm` builder | Matches ARTEX's `go.mod` at the pin. Newer local toolchains build it fine. | `go.mod`, `Dockerfile` |
| Runtime image | `gcr.io/distroless/static-debian12:nonroot` | Static CGO-free binary; no shell or package manager in the image. | `Dockerfile` |

## Project

| Decision | Reason | Change in |
| --- | --- | --- |
| Go module path `github.com/snare-dev/snare` | Placeholder: the public repository location is not decided. Replace with the real path before the first public release (one `go mod edit -module` plus an import rewrite). | `go.mod` |
| YAML library `gopkg.in/yaml.v3` | Boring, widely used, MIT and Apache-2.0. Unknown fields are rejected so typos fail at startup. | `internal/config` |
| CLI uses the standard `flag` package | No CLI framework dependency needed for a handful of subcommands. | `cmd/snare` |
| Placeholder subcommands (`quickstart`, `verify`, `bench`, `rules`) exit 2 and name their milestone | Makes the planned surface visible without pretending it works. | `cmd/snare/main.go` |
| Allowed dependency licenses in CI: Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0 | All compatible with distributing Snare under Apache-2.0. MPL-2.0 is file-level copyleft; acceptable for unmodified dependencies. Current dependency set contains none. | `.github/workflows/ci.yml` |
| golangci-lint v2.6.2, govulncheck v1.1.4, go-licenses v2.0.1 | Pinned so CI results are reproducible. | `.github/workflows/ci.yml` |
| Code of conduct is a short original text, not the Contributor Covenant verbatim | Avoids reproducing a third-party text from memory. Maintainers may swap in Contributor Covenant 2.1. | `CODE_OF_CONDUCT.md` |

## Configuration defaults

| Setting | Default | Reason |
| --- | --- | --- |
| `server.listen` | `127.0.0.1:8780` | Spec: UI binds to loopback. A non-loopback address is rejected unless `server.allow_non_loopback: true`. Port 8780 avoids ARTEX's 8787/8788. |
| `server.api_token_file` | `data/api.token`, generated (32 random bytes, hex, mode 0600) on first start | API is authenticated from the first run without a setup step. |
| `store.path` | `data/snare.db` | Relative to the working directory. |
| `secrets.key_file` | `data/secret.key` | Used from M1 for encryption at rest. `SNARE_SECRET_KEY` takes precedence. |
| `gateway.listen` | `127.0.0.1:8000` | Loopback unless the operator puts Snare in front of real traffic. |
| `gateway.limits.max_request_body_bytes` | 10 MiB | Covers typical JSON and form posts; uploads larger than this should be routed past Snare or the cap raised. |
| `gateway.limits.max_header_bytes` | 64 KiB | Larger than Go's 1 MiB default is unnecessary; 64 KiB fits large cookies. |
| `gateway.limits.read_timeout` / `write_timeout` / `upstream_timeout` | 30s / 60s / 30s | Conservative values for a web app; long-poll or SSE routes need higher values. |
| `gateway.limits.max_concurrent` / `max_per_source` | 1024 / 64 | Bounds Snare's resource use; per-source cap keeps one client from taking all slots. |
| Route `path_prefix` / `mode` | `/` / `record` | A new route is pass-through and recording only until the operator changes it. |
| `artex.username` | `ARTEX` | ARTEX accepts only this user name (`server/auth.go`, `login`). |
| `artex.timeout` | 30s | Per HTTP call to ARTEX. |
| `active.enabled` | `false` | Spec: active mode is off by default. `active.allow_production` is rejected unless active mode is on. |
| Environment overrides | `SNARE_<SECTION>_<FIELD>`, for example `SNARE_GATEWAY_LIMITS_MAX_PER_SOURCE`. Lists (routes) are file-only. `snare config env` prints every name. | Derived from YAML tags so overrides cannot drift from the file format. |

## Store

| Decision | Reason |
| --- | --- |
| Migrations are `internal/store/migrations/NNNN_name.sql`, contiguous from 0001, each in its own transaction, recorded in `schema_migrations` | Same model ARTEX uses; easy to review. |
| A database with a newer schema than the binary is refused | Prevents an old binary from silently misreading data after a downgrade. |
| SQLite pragmas: WAL, `foreign_keys=1`, `busy_timeout=5000`, immediate transactions | WAL lets the UI read while the gateway writes; immediate transactions avoid upgrade deadlocks. |
| `action_log` is append-only, enforced by triggers; an undo is a new row with `reverses_id` | The autonomy rule needs a log nobody can rewrite. Enforced in the schema, not only in code. |
| `action_log.actor` is constrained to `policy` or `human` | Spec: a model may propose, a deterministic policy decides. |
| Secret files are never overwritten; an empty file is an error | Avoids silently rotating a key or token because a file was truncated. |

## Lab (`deploy/compose`)

| Decision | Reason | Change in |
| --- | --- | --- |
| `lab` and `artex-db` are Docker `internal` networks | Juice Shop and Postgres have no route to the internet; constraint 3. | `compose.yaml` |
| ARTEX also joins an ordinary bridge (`artex-out`) | It needs to reach the LLM provider. Targets are restricted by Snare (task scope, target gate, ownership) in M7, not by the network. Possible later hardening: force LLM egress through `ARTEX_LLM_PROXY` with an allowlist. | `compose.yaml` |
| Host ports bound to 127.0.0.1 only: 8000 (gateway), 8780 (Snare API), 8787 (ARTEX UI). ARTEX's MITM proxy 8788 is not published | Nothing in the lab is reachable from other machines. ARTEX's recording proxy is used only inside its own container. | `compose.yaml` |
| ARTEX listens on `:8787` inside its container | The image's `CMD` already does this; it is the in-container equivalent of `ARTEX_BIND_ADDR=0.0.0.0`, reachable only on the compose networks and on host loopback. | `compose.yaml` |
| Lab ARTEX brakes default on: `ARTEX_NOISE_PROFILE=quiet`, task budget 2,000,000 tokens / 400 turns, intent budget 200,000 tokens / 40 turns | A manual run in the lab is braked even before M7 forces brakes per task. The task budget is far above ARTEX's 70,000-token practical floor; the intent budget is four times ARTEX's 50,000-token worker estimate. Values are a guess to be tuned by the benchmark. | `deploy/compose/.env` |
| Secrets are generated by `lab.sh` into `deploy/compose/secrets/` (git-ignored): directory mode 0700, files 0644 | Containers run as non-root users with different UIDs than the host user; 0644 files inside a 0700 directory are readable by the containers through compose `secrets` but not by other host users. | `lab.sh` |
| The ARTEX admin password is 48 hex characters | ARTEX requires 12 to 72 bytes (`server/auth.go`, `validatePassword`). | `lab.sh` |
| First-run claim reads the setup token from `docker compose logs artex` by matching `Setup token for the /setup page: <hex>` | That is the exact log line at the pin (`server/auth.go`, `initSetupToken`). | `lab.sh` |
| The Playwright service is not in the M0 compose file | It has nothing to run until the M1 happy-path suite exists. It arrives in M1 under a compose profile. | M1 |
| Juice Shop healthcheck uses the image's own Node (`/nodejs/bin/node`) | The image is distroless, with no curl or shell. | `compose.yaml` |

## ARTEX interface notes

Facts verified against the pin that differ from, or refine, the spec. Each
names the file it was read from.

1. **Login** (`server/auth.go`): `POST /api/auth/login` takes
   `{"username":"ARTEX","password":...}` and returns `{"token":...}`, a 7-day
   HS256 JWT. 10 attempts per minute per client IP; Snare caches the token and
   logs in again only after a rejection.
2. **Health** (`server/server.go`, `health`): `GET /api/health` is
   unauthenticated and never returns 401. With a valid token it adds
   `"service":"artex"` and the version. Snare uses that field to check a
   session cheaply (`artex.Client.CheckSession`).
3. **Errors**: every ARTEX error body is `{"error":"..."}` (`writeErr`).
4. **Task creation** (`server/server.go`, `createTaskReq`): `target_gate` is a
   pointer field on the create request (omitted means off), alongside
   `intercept_rules`, `timeout_seconds`, `llm_profile_ids`, `coverage_enabled`
   and `credentials`. `PATCH /api/tasks/{id}` (`server/task_metadata.go`) can
   change `target_gate` mid-run. `TaskDTO.target_gate` in `server/dto.go`
   reports it, which is how M7 confirms the brake through the API.
5. **Webhook payload** (`notify/webhook.go`): the template context is not the
   raw `Snapshot` from `notify/event.go`. Each item exposes `FindingID`,
   `Name`, `VulnClass`, `Severity`, `SeverityLabel`, `Summary`, `Assets`
   (display names, not IDs), `DetailURL`, `FromStatus`, `ToStatus`,
   `StatusLabel`; `task_id` and `kind` are not exposed, and one delivery may
   carry several items (digest mode). Snare therefore treats a webhook only as
   a hint carrying finding IDs, always fetches the finding from the API for
   the authoritative record (including `task_id`), infers the event kind from
   whether `FromStatus`/`ToStatus` are set, and deduplicates on
   `(finding_id, to_status)`. Snare supplies its own `body_template` that
   emits exactly those fields. A patch to expose `TaskID` and `Kind` in the
   template context may be proposed under `docs/upstream/` in M3 if it proves
   useful; Snare does not depend on it.
6. **Webhook destination check** (`notify/dingtalk.go` `validateHTTPURL`,
   `notify/http.go` `isBlockedDialIP`): ARTEX refuses loopback, link-local,
   multicast and unspecified addresses unless `ARTEX_NOTIFY_ALLOW_LOCAL=1`.
   Private RFC 1918 addresses, such as compose network addresses, are allowed,
   so `http://snare:8780/...` works without that variable.
7. **Retest verdicts** (`server/finding_retests.go`,
   `record_finding_retest_result`): stored values are `reproduced`, `fixed`,
   `inconclusive`, shown in the UI as Still reproducible, Fixed, Cannot
   confirm. Snare maps `fixed` and `inconclusive` to a passing gate.
   `POST .../retests` returns 202 when a retest starts and 200 when one is
   already running for that finding; it returns 409 if the `retester` agent or
   its two tools are disabled.
8. **Finding traffic** (`server/finding_traffic.go`, `db/finding_traffic.go`):
   `GET .../traffic` returns `{finding_id, version, report_version, bindings}`;
   binding and finding IDs are JSON strings. Each binding carries a stored
   evidence snapshot, so the proving exchange survives later traffic pruning.
9. **Noise profile**: once set through `PUT /api/settings`, the runtime
   setting takes precedence over `ARTEX_NOISE_PROFILE` (README, Configuration).
   M7 sets it through the API and reads it back from `GET /api/settings/noise`.
10. **Agent internals the tarpit relies on** (confirmed at the pin): large tool
    output spills to disk with a 30,000-character head (`agent/worker.go`);
    stagnation needs `stagnationMinRepeats = 3` repeats (`agent/tools.go`);
    `DefaultWorkerEstimateTokens = 50_000` (`agent/budget.go`); the worker
    prompt says to try every bypass after a filtered payload
    (`agent/worker.go`).
