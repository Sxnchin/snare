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
| Project name "Snare" is a working name. **TODO(rename):** it collides with existing security products and may still change. The repository is public at `github.com/Sxnchin/snare`; no image or package has been published. | Review item 5. | everywhere; search for `TODO(rename)` |
| Go module path `github.com/Sxnchin/snare` | Matches the public repository. **TODO(rename):** if the project name changes, the path changes with it. Changing it is one `go mod edit -module` plus an import rewrite. | `go.mod` |
| YAML library `gopkg.in/yaml.v3` | Boring, widely used, MIT and Apache-2.0. Unknown fields are rejected so typos fail at startup. | `internal/config` |
| CLI uses the standard `flag` package | No CLI framework dependency needed for a handful of subcommands. | `cmd/snare` |
| Placeholder subcommands (`quickstart`, `verify`, `bench`, `rules`) exit 2 and name their milestone | Makes the planned surface visible without pretending it works. | `cmd/snare/main.go` |
| Allowed dependency licenses in CI: Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0 | All compatible with distributing Snare under Apache-2.0. MPL-2.0 is file-level copyleft; acceptable for unmodified dependencies. Current dependency set contains none. | `.github/workflows/ci.yml` |
| golangci-lint v2.6.2, govulncheck v1.1.4, go-licenses v2.0.1 | Pinned so CI results are reproducible. | `.github/workflows/ci.yml` |
| The CI lint job is pinned to Go 1.26.10 | golangci-lint v2.6.2 fails under Go 1.27 with `could not load export data ... export data version 5 is greater than maximum supported version 2`: its bundled analysis code cannot read Go 1.27's standard library. Under 1.26.10 it reports 0 issues. Locally, run `GOTOOLCHAIN=go1.26.10 go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.6.2 run ./...`. Lift the pin when a golangci-lint release supports Go 1.27. | `.github/workflows/ci.yml` |
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

## Gateway and recording (M1)

| Decision | Reason | Change in |
| --- | --- | --- |
| Routes match exact host first (any host when the route has none), then longest path prefix on segment boundaries (`/api` matches `/api/x`, not `/apix`) | Predictable and easy to explain; no regex routing to misconfigure. | `internal/gateway` |
| Order of checks per request: global concurrency cap (503 + `Retry-After: 1`), per-source cap (429 + `Retry-After: 1`), route match (404), declared body length over cap (413), then streaming body cap (413 when it trips mid-stream) | Cheapest rejections first; nothing reaches the upstream once a cap is hit. | `internal/gateway` |
| Header cap is Go's `http.Server.MaxHeaderBytes` (431 on overflow) | Standard library behaviour, no custom parser. | `gateway.limits.max_header_bytes` |
| The source is the TCP peer address; `X-Forwarded-For` is used only when the peer is in `gateway.trusted_proxies`, taking the right-most address that is not a trusted proxy; a malformed entry stops the walk | The same rule ARTEX uses for its login limiter. Untrusted peers cannot spoof their source. | `gateway.trusted_proxies` |
| The gateway adds no `Via` or `Server` header and passes `Accept-Encoding` through unchanged (`DisableCompression`); the upstream transport never uses `HTTP_PROXY` from the environment | An identifying header tells an agent Snare is in the path. Pass-through encoding keeps responses byte-identical. | `internal/gateway` |
| The upstream `Host` header is the upstream's own host (Go's `SetURL` default), plus `X-Forwarded-For`, `-Host` and `-Proto` | Works for Juice Shop and most apps. A `preserve_host` option can be added if a vhost-based app needs the client's `Host`. | `internal/gateway` |
| `detect` and `enforce` modes are pass-through until rules exist (M4) and do not record | Only `record` mode feeds the benign corpus (spec 7.2). | M4 |
| Coraza is not wired in yet | It has nothing to evaluate until the compiler produces rules (M4). The overhead number will be measured again with Coraza in the path. | M4 |
| Recording never blocks traffic: exchanges go to a bounded queue (`recorder.queue_size`, default 4096) and a single writer stores them in batches of up to 100 per transaction; a full queue drops and counts (`/api/status` `corpus.dropped`) | A slow disk must not slow users down. Losing a few benign samples is harmless; the corpus only needs coverage. | `recorder.queue_size` |
| Body capture keeps the first `recorder.max_body_bytes` (default 256 KiB) of each side and records the full length | Enough for API JSON and HTML pages; bounded memory per request. Truncated JSON falls back to text redaction. | `recorder.max_body_bytes` |
| Not recorded: requests rejected by a cap, aborted requests, routes past their learning period, routes not in `record` mode, scanner traffic (next rows), and sources the detector flags as agent-like (hook in place; detector in M2) | The corpus must contain only completed, legitimate exchanges. | `internal/gateway` |
| Scanner sources: `recorder.exclude_sources` lists IPs, CIDRs or hostnames whose requests are never recorded. Hostnames are resolved at start and every 5 seconds. While any listed hostname does not resolve, nothing is recorded on any route (counted as `excluded_unresolved_source`), and a single warning is logged | ARTEX scanning through the gateway before the detector exists (M2) would otherwise become "benign" corpus, and every rule validated against it would be validated against attack traffic. Failing closed costs a few seconds of benign samples while the scanner restarts; failing open would poison the corpus. Remaining gap: if the scanner gets a new address, up to 5 seconds of its traffic can be recorded before the next refresh. Docker usually keeps the address across a restart. | `recorder.exclude_sources`; lab: `[10.203.0.10]`, ARTEX's fixed address, so the lab has no window |
| Scanner User-Agents: a built-in list of case-insensitive substrings (`sqlmap/`, `nuclei`, `fuzz faster u fool`, `nikto`, `gobuster/`, `feroxbuster/`, `wfuzz/`, `nmap scripting engine`, `masscan/`, `zgrab/`, `dirbuster`, `wpscan`, `commix`, `acunetix`, `netsparker`, `openvas`, `burpcollaborator`) plus `recorder.exclude_user_agents` | A second line for scanners not listed by address. User-Agents are trivially changed, so this is not relied on. Generic client libraries (`curl`, `python-httpx`, `Go-http-client`) are not on the list: real API clients use them. | `gateway.DefaultScannerAgents` |
| Exclusion only affects recording. Excluded requests are proxied normally and counted in `/api/status` (`excluded_scanner_source`, `excluded_scanner_agent`) | Detection and blocking are separate decisions (M2, M4). | `internal/gateway` |
| The learning period (default 72h) starts at the first stored live exchange on a route and is stored in `route_learning`; HAR imports never start it | Restarts do not reset it; importing old traffic does not end live learning early. If the learning-period check fails to read the database, the route does not record (fail closed). | `recorder.learning_period` |
| gzip and deflate response bodies are decoded before redaction; other encodings (br, zstd) are stored as `[REDACTED:binary]`, never as raw bytes | Compressed bytes would hide secrets from the redactor. Juice Shop uses gzip. Adding brotli needs a dependency; not worth it yet. **M4 note:** the gate replays the benign corpus and compares status classes, and response-body rules need a body to test against. For a route whose upstream answers in br or zstd, the stored response bodies are placeholders, so (a) count how many corpus records on each route have an undecodable body and show it in coverage, (b) a response-body rule on such a route cannot pass the gate on corpus evidence and stays `detect_only`, and (c) decide then between adding `github.com/andybalholm/brotli` (MIT) and `github.com/klauspost/compress/zstd` (BSD-3-Clause), or having the gateway narrow `Accept-Encoding` to gzip on recording routes. Request bodies are rarely compressed and are not affected. | M4 |
| Binary bodies (images, fonts) are stored as `[REDACTED:binary]` with their length | Nothing in them helps rule validation; their presence and size still help the detector's browser-presence signal. | `internal/recorder` |
| No client address is stored in the corpus | The corpus is for replaying benign requests against rules; who sent them is not needed and is personal data. | `internal/recorder` |
| Corpus layout: the full redacted exchange is sealed (AES-256-GCM, random 96-bit nonce, associated data `snare:corpus:v1:<route>`); plaintext columns hold only redacted method, path template, status, sizes, timing and parameter names | Coverage queries run without decrypting; a record cannot be moved to another route undetected. | `0002_corpus.sql` |
| Key handling: `SNARE_SECRET_KEY` (32 bytes, hex or base64) beats `secrets.key_file`; a key file is generated (mode 0600, base64) only when no encrypted data exists; a sealed check value in `meta` detects a wrong key at startup | Spec 7.2: refuse to start if encrypted data exists and no key is available. A wrong key fails at startup rather than on first read. | `internal/recorder/crypto.go` |
| The default key file lives next to the database (`data/secret.key`; in the lab, the same `snare-data` volume) | Works out of the box. It means a copy of the data directory includes the key, so encryption at rest only protects a database file copied without it. Production should set `SNARE_SECRET_KEY` from a secret store or point `secrets.key_file` at a separate mount. | `secrets.key_file` |
| Path templates replace all-digit segments with `{n}`, UUIDs, hex strings of 16 or more characters, dash-separated hex of 12 or more characters that contains a digit (Juice Shop order ids) and long tokens with `{id}`, and redacted segments with `{redacted}` | Groups `/api/Products/1` and `/api/Products/2` into one endpoint for coverage. | `recorder.PathTemplate` |
| `lab.sh test` includes `test-exclusion`: 3 requests through ARTEX's capture proxy (identified by header), 3 direct requests from ARTEX (identified by its fixed address) and 1 with a sqlmap User-Agent go through the gateway and the corpus must not grow; a browser-like request and one with a wrong header value must be recorded, without the header; none of ARTEX's own recorded exchanges may contain the header or its secret | Proves each identification path against the real containers, not only in unit tests. | `deploy/compose/lab.sh` |
| **Scanner identity header (primary).** ARTEX's capture proxy adds `X-Snare-Scanner: <secret>` to every request to host `snare`, through an ARTEX traffic rewrite rule (`set_header`, marked sensitive) that `lab.sh bootstrap` installs from `secrets/snare_scanner_secret`. The gateway removes the header from every request before proxying or recording, whatever its value; a single header with the right value (constant-time compare) marks the request as Snare's scanner, any other value counts as `scanner_header_mismatch` and the request is treated as normal traffic | The fixed address only works where Snare can see ARTEX's real address; a header works through NAT and load balancers, which M7 needs. Checked in ARTEX's code (`traffic/rewrite`, `traffic/rewrite_flow.go`) and in the lab: a sensitive value is kept out of ARTEX's API, traces and rule snapshots, and ARTEX's recorded exchanges store the request as the tool sent it, before the rewrite, so finding evidence never carries the secret. The rule is limited to host `snare` so the secret is never sent anywhere else. | `scanner.header`, `scanner.secret_file`; lab: `lab.sh install_scanner_rule` |
| The fixed address stays as the backup | ARTEX's proxy is opt-in per tool: workers get `HTTP_PROXY`/`HTTPS_PROXY`, but a tool that ignores them (raw-socket scanners, tools with their own proxy flag) sends no header. ARTEX's rewrite rules also fail open (the snapshot table is full, a body over 5 MiB streams past the hooks), and then the request goes out without the header. | `recorder.exclude_sources` |
| **M7 requirement:** in production, every ARTEX request to a protected target must be identifiable | Either route all ARTEX traffic through its capture proxy (so the header is always present), or give Snare a stable ARTEX source address it can see. Active mode must refuse to start when neither holds, and count requests that arrive from ARTEX's address without the header, since each one means a tool bypassed the proxy. | M7 |
| The scanner header only keeps traffic out of the corpus and turns on the lab capture. It is never an allowlist: the detector (M2) still scores the traffic, and nothing in M4 or M5 may exempt a request from rules, the tarpit or blocking because it carries the header | Anyone who learns the secret could otherwise walk past Snare. Learning it today only lets an attacker keep their own requests out of the benign corpus, which makes the corpus smaller, not wrong. | M2, M4, M5 |
| **Scanner capture (lab only):** with `scanner.capture_file` set (`SNARE_SCANNER_CAPTURE_FILE`, which only `lab.sh capture-run` sets), the gateway writes every exchange of the identified scanner (header or excluded address, not the User-Agent list) to a JSON Lines file: arrival time with nanoseconds, duration, source, how it was identified, method, path, query, headers (scanner header removed), the first 1 MiB of each body verbatim (base64 when not UTF-8), status and response headers. Mode 0600, bounded queue, 2 GiB file cap, drops are counted | The detector, compiler and gate need real attack traffic with its timing, and replaying a recording costs nothing where a live ARTEX run costs money. It is unredacted because redaction would destroy the payloads; that is acceptable only because it is the lab's own scanner against a lab app with fake data. Users' requests are never written to it (tested). Never set it where ARTEX tests a system with real data. | `scanner.capture_file` |
| `lab.sh latency` measures against a throwaway gateway with its store in its own `/tmp`, not the lab's Snare | The first measurement ran through the lab Snare in record mode and put 2203 copies of the logo request into the corpus. Benchmark traffic is not legitimate traffic and must not enter the corpus. | `deploy/compose/lab.sh` |
| Coverage is available as `GET /api/corpus/coverage` and `snare corpus coverage`; the HTML view comes with the UI (M8) | The UI framework lands in M8; the data and the CLI view are usable now. | M8 |
| Playwright import is done by running the suite through the gateway in record mode (`lab.sh traffic`). A HAR file saved by Playwright (`recordHar`) or a browser can be imported with `snare corpus import-har -route NAME -host HOST FILE` | One recording path for live and scripted traffic; HAR covers paths users have not hit yet. The `-host` filter keeps third-party requests from a browser HAR out of the corpus. | `cmd/snare/corpus.go` |

### Redaction defaults

| Rule | Default | Reason |
| --- | --- | --- |
| Header values dropped | `Authorization`, `Proxy-Authorization`, `Cookie` and `Set-Cookie` values (names kept), `X-Api-Key`, `X-Auth-Token`, `X-Csrf-Token`, `X-Xsrf-Token`, plus `recorder.redact.headers` | Spec list plus common token headers. Cookie names are kept because cookie continuity is a detector signal (M2). |
| Field values dropped in JSON, form and query | passwords, secrets, tokens, keys, session ids, CSRF tokens, OTP and TOTP, security answers, card fields, IBAN, SSN, and personal data (`fullName`, first and last name, phone and mobile, address, street, zip and postal codes, date of birth), plus `recorder.redact.json_fields`. Names are compared case-insensitively ignoring `_` and `-`. A sensitive key with an object value loses the whole object. | Generic names such as `name`, `city` and `country` are deliberately not on the list: they would also wipe product names and other content the corpus needs. Add them per deployment if your app uses them for people. |
| Text detectors (paths, query values, bodies, other headers) | email addresses; JWTs; `Bearer`/`Basic`/`Token` credentials; card-like numbers (13 to 19 digits, spaces or dashes allowed, Luhn-valid over whole digit groups); known key formats (OpenAI, Stripe, GitHub, Slack, Google, AWS access key IDs, GitLab); and generic tokens of 32 or more characters that mix upper case, lower case and digits | Plain hex hashes, UUIDs and all-lower-case strings are not treated as keys: they are common identifiers and rarely secret. |
| Where the generic long-token detector is skipped | `ETag`, `If-None-Match` and `If-Match` headers, and CSS and JavaScript bodies. Known key formats, JWTs, emails and cards are still detected there. | The first lab run flagged 228 values, all ETags and minified `main.js`/`styles.css` content. Over-redaction would make replayed benign requests differ from real ones (M4 gate). |
| Fuzzing | `FuzzText` (never panics, idempotent, planted secrets never survive) and `FuzzJSON`; CI runs each for 30 seconds | The first fuzz run found a real bug (a card followed by a stray digit group escaped the Luhn check); the case is kept under `testdata/fuzz` as a regression. |

## Repository hygiene

| Decision | Reason | Change in |
| --- | --- | --- |
| CI runs `gitleaks git` (v8.30.1, release tarball pinned by SHA-256) over the full history; an optional pre-commit hook in `.githooks/` scans staged changes | Catches committed secrets in CI and, for contributors who opt in, before they commit. A pinned binary avoids depending on a third-party action. | `.github/workflows/ci.yml`, `.githooks/pre-commit` |
| Fixtures that look like secrets are obviously fake and allowlisted: a trailing `gitleaks:allow` comment where the file format allows comments, otherwise a fingerprint in `.gitleaksignore`. The 7 findings in the history (4 in `bench/samples/juice-shop-sample.har`, 3 in `internal/recorder/redact_test.go`) are all fixtures and are listed | Keeps the scan at zero findings so a real hit stands out. Fingerprints carry line numbers, so editing those lines needs the entry updated. | `.gitleaksignore`, CONTRIBUTING.md |
| `.gitignore` ignores `data/`, `secret.key` and `api.token` anywhere in the tree, not only at the root | Snare's default paths are relative to the working directory; a Go test once wrote `cmd/snare/data/secret.key` into the tree. | `.gitignore` |

## Lab (`deploy/compose`)

| Decision | Reason | Change in |
| --- | --- | --- |
| **The network, not task scope, is the boundary that keeps ARTEX on lab targets.** ARTEX is attached only to Docker `internal` networks (`lab`, `artex-db`, `llm-egress`, `artex-admin`), which have no route and no DNS to the internet. Task scope, the target gate, and ownership verification (M7) are additional layers, not the boundary. | Review item 1. A prompt-injected or misconfigured agent cannot reach an internet host whatever its task says. | `compose.yaml` |
| ARTEX's only way out is the `egress` container, an allowlisting HTTP CONNECT proxy (`labnet egress`, `internal/labnet`), set as `ARTEX_LLM_PROXY=http://egress:3128` | It permits exactly the `host:port` pairs in `LLM_EGRESS_ALLOW` and refuses everything else, including plain HTTP forwarding, wildcards, other ports, and allowlisted names that resolve to private, loopback, link-local or CGNAT addresses. Every decision is logged; the container healthcheck uses an origin-form `GET /healthz` that is not a proxy path and is not logged. Written in Go (about 250 lines, standard library) rather than configuring Squid, so the whole policy is small enough to review and is covered by unit tests, and it reuses the Snare image instead of adding another one. | `internal/labnet`, `compose.yaml` |
| `LLM_EGRESS_ALLOW` defaults to `api.deepseek.com:443`, the one provider in use | Narrowed for M2. `lab.sh test-egress` checks that `api.openai.com`, `api.anthropic.com`, `generativelanguage.googleapis.com` and `openrouter.ai` are refused (CONNECT 403) unless listed, and that `api.deepseek.com` is reachable. No API key is configured by Snare or `lab.sh`; the operator pastes it into `deploy/compose/.env`. | `deploy/compose/.env` |
| **LLM: DeepSeek `deepseek-flash` through the OpenAI-compatible endpoint** (`ARTEX_LLM_PROVIDER=openai`, `ARTEX_LLM_BASE_URL=https://api.deepseek.com`, key in `OPENAI_API_KEY`), not the Anthropic-format endpoint (`/anthropic`) | Read in ARTEX's LLM library (Norma v0.4.11, `llm/openai.go`): the OpenAI path has explicit DeepSeek handling, passing `reasoning_content` back on assistant turns that carry tool calls (DeepSeek's thinking mode rejects a tool-call history without it) and asking for usage on streamed responses (`stream_options.include_usage`), which ARTEX's budget and outcome counts need. ARTEX's own sample DeepSeek profile uses the OpenAI format. The Anthropic path filters thinking blocks and relies on Anthropic-specific behaviour that DeepSeek's compatibility layer is not known to match, and ARTEX documents DeepSeek's Anthropic endpoint only for its server-side web search, which is off here. Not yet verified with a live call: the model id is checked with `GET /models` (no tokens) before the first run, and ARTEX's own sample data names the model `deepseek-v4-flash`, so the id may need changing. | `.env`, `compose.yaml` |
| LLM cost control | Every run is braked by ARTEX's task budget (`ARTEX_TASK_BUDGET_TOKENS`, input plus output, 2M by default), a wall-clock limit, and a hard stop in `lab.sh capture-run` that pauses the task past 2.4M tokens. ARTEX keeps dispatching workers until the remaining budget is below one worker's estimate, so a run can overshoot by what in-flight workers use. Runs refuse to start at DeepSeek peak hours unless `--allow-peak` is given. Each run's tokens, tool calls, wall time and cost go to `bench/results/llm-spend.md`. | `lab.sh`, `bench/results/llm-spend.md` |
| Record once, replay many: one capture run supplies the test data for M2 (detector), M3 (connector, against a fake ARTEX serving the captured findings) and M4 (compiler and gate) | Live runs are expensive. Live runs happen only where a done condition needs one: the M3 live sync check, the M4 retest, M5 tarpit behaviour and the final benchmark, each approved beforehand with its expected cost. | `bench/fixtures/` |
| An LLM profile saved in ARTEX's UI with no proxy, or a different base URL, simply fails to connect | `ARTEX_LLM_PROXY` applies to the environment-configured provider only (`agent/provider.go`, `FromEnv`); a UI profile has its own proxy field. The network makes this safe either way: set the profile's proxy to `http://egress:3128` and add its host to the allowlist. | ARTEX UI, `.env` |
| ARTEX web search is forced off at bootstrap (`PUT /api/settings {"web_search_enabled": false}`, then read back) | It is off by default at the pin (`server/manager.go`); setting it explicitly means a UI change is undone by the next `lab.sh bootstrap`. With search on, the request would fail at the network anyway. | `lab.sh` `harden_artex` |
| The lab's ARTEX image is an overlay (`deploy/compose/artex-offline/Dockerfile`) on the unmodified ARTEX image | Adds what the tools need to run offline without changing ARTEX's source or its own Dockerfile. The base image `snare-lab/artex:d89cf78` is still built from the pinned checkout by the `artex-base` service (scale 0, `network_mode: none`, never started) and passed to the overlay as a `service:` build context, which needs a recent Compose v2 or later (tested on Compose v5.7.0). | `artex-offline/Dockerfile` |
| nuclei-templates `v10.5.2`, sha256 `016b7abb...ec574`, baked into `/root/nuclei-templates` | Latest release on 2026-11-18. The ARTEX image ships no templates, so nuclei would otherwise download them at first use. The checksum was computed when pinned (GitHub archive tarballs are stable in practice but not guaranteed; a mismatch fails the build, which is the safe outcome). The image build checks that nuclei lists more than 1,000 templates without fetching. | `artex-offline/Dockerfile` |
| Self-updates off: `disable-update-check: true` in the config files of nuclei, httpx, subfinder and katana; `DISABLE_NUCLEI_TEMPLATES_*_DOWNLOAD=true` and `DISABLE_CLOUD_UPLOAD=true`; bbot `deps.behavior: disable` | The ProjectDiscovery tools have no environment switch for the update check, but their config files accept any CLI flag (`-duc`). bbot's dependencies were installed when ARTEX's image was built; runtime installs are disabled. | `artex-offline/Dockerfile` |
| Tools that still fetch at runtime fail closed | Some bbot modules download wordlists during setup, and `pip`, `npm`/`npx` and `sqlmap --update` need the internet. Inside ARTEX these requests fail at the network and the module or command errors out. That is acceptable: nothing can reach the internet, and a failed fetch never weakens isolation. Not enumerated module by module. | network |
| ARTEX's recording proxy (8788) is inside ARTEX's network namespace and has no published port | Its upstream connections go out on the same internal networks, so it can reach lab targets but not the internet. `lab.sh test-egress` checks this. | `compose.yaml` |
| `artex-ui` is a fixed-destination TCP forwarder (`labnet forward -to artex:8787`) on `artex-admin` and `front`, publishing ARTEX's UI on `127.0.0.1:8787` | Docker does not publish ports of containers that are only on internal networks. The forwarder dials only `artex:8787`, so ARTEX cannot use it to get out. | `compose.yaml` |
| `lab.sh test-egress` is the automated isolation test | Two positive controls first (ARTEX reaches Juice Shop through Snare's gateway, directly and through its own recording proxy), then a check that ARTEX cannot reach Juice Shop directly, so the negative checks cannot pass merely because something is down. Then, from inside the ARTEX container: direct HTTPS to `example.com` fails, DNS for it fails, the egress proxy refuses it (CONNECT 403) and refuses an allowlisted host on another port, ARTEX's recording proxy cannot reach it, every allowlisted LLM host is reachable through the proxy (any HTTP status, since no key is set), and nuclei lists its baked templates offline. Needs the host to have internet access for the allowlisted-host check; it is a lab test, not part of `go test`. | `lab.sh` |
| **Containment rule: any container reachable from ARTEX is part of the containment boundary.** ARTEX and every container it can reach, directly or through another reachable container (today postgres, snare, the playwright runner, and juice-shop through snare), must be on internal networks only, with no route to the internet. The only exceptions are `egress` (allowlisted LLM hosts), `artex-ui` (dials only `artex:8787`) and `snare-ports` (dials only `snare:8000` and `snare:8780`). | A reachable container with internet access is a pivot: Juice Shop's deliberate SSRF (`POST /profile/image/url` fetches any URL server-side) would let ARTEX reach the internet through it, and so would any proxying service. `lab.sh test-egress` enforces the rule structurally (walks the networks breadth-first from ARTEX, through every reachable container except the declared exceptions, so new services are covered automatically), probes each reachable container with an internet fetch, and runs the SSRF pivot itself from inside ARTEX with a lab-internal control. | `compose.yaml`, `lab.sh` `CONTAINMENT_EXCEPTIONS` |
| Snare is on internal networks only (`lab`, `snare-admin`); `snare-ports`, a fixed-destination forwarder on `snare-admin` and `front`, publishes 8000 and 8780 on host loopback | Snare is reachable from ARTEX, so under the containment rule it cannot have internet access. ARTEX is not on `snare-admin`, so it cannot reach `snare-ports` at all. The M0 layout had Snare on `front`; the audit caught it (Snare could fetch `https://example.com`) before the fix. | `compose.yaml` |
| ARTEX has a fixed address, `10.203.0.10`, on the `lab` network (`10.203.0.0/24`). Other containers get addresses only from `10.203.0.128/25` | Snare excludes ARTEX from recording by address with no DNS window, and no other container can ever be handed ARTEX's address. If the subnet collides with a local network, change it in `compose.yaml` (subnet, `ip_range`, `ipv4_address`) and `snare.lab.yaml`. | `compose.yaml`, `snare.lab.yaml` |
| Juice Shop is on its own internal `target` network with Snare only; ARTEX and the Playwright runner reach it only through `http://snare:8000` | The capture must hold every request ARTEX sends to the app, and the detector and gate are only meaningful when the attacker's path goes through Snare. The pivot test drives Juice Shop's SSRF through the gateway for the same reason. | `compose.yaml` |
| **Plan for M6:** Snare will need to reach AWS IAM for credential rotation | Snare must not get a direct route out. M6 adds a second allowlisting egress proxy for Snare, on a network ARTEX is not attached to, allowing only the IAM endpoint(s) configured; it becomes a third declared exception and the audit must still pass. Rotation calls from Snare must never be relayable by ARTEX (Snare exposes no fetch-a-URL feature, and the M6 review checks that). The optional LocalStack test runs inside the lab and needs no internet. | M6 |
| Host ports bound to 127.0.0.1 only: 8000 (gateway) and 8780 (Snare API) through `snare-ports`, 8787 (ARTEX UI) through `artex-ui`. ARTEX's MITM proxy 8788 is not published | Nothing in the lab is reachable from other machines. | `compose.yaml` |
| ARTEX listens on `:8787` inside its container | The image's `CMD` already does this; it is the in-container equivalent of `ARTEX_BIND_ADDR=0.0.0.0`, reachable only on the internal compose networks. | `compose.yaml` |
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
