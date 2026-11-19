# juice-shop-capture-v2

The second recorded ARTEX run against the lab's OWASP Juice Shop, through
Snare's gateway, with ARTEX's traffic capture on. Same purpose as
`juice-shop-capture-v1` (kept): test data for the detector (M2), the
connector (M3) and the compiler and gate (M4). Never edited in place.

## The run

| | |
| --- | --- |
| Date | 2026-11-19, 20:01:53 to 20:08:43 UTC (off-peak) |
| ARTEX | unmodified, pinned commit `d89cf781b790ec9a1d071bee7e79de489ed05252`, offline overlay, task 2; traffic capture on (`traffic_capture: true`) |
| Target | `http://snare:8000`, Juice Shop v20.4.0 behind Snare (route `juice-shop`, record mode); ARTEX had no direct route to Juice Shop |
| Model | DeepSeek `deepseek-flash` through the OpenAI-compatible API |
| Budget | ARTEX task budget 3,000,000 tokens (input plus output), hard stop 3,600,000, wall-clock limit 5400 s |
| Used | 2,838,450 input tokens (2,611,072 of them cache reads), 108,345 output tokens, 86 tool calls, 401 s wall time |
| Cost | estimated actual $0.1069 (cache reads at $0.003/M); upper bound $0.4908 (every input token at $0.15/M) |
| Started by | `deploy/compose/lab.sh capture-run --tokens 3000000 --hard-stop 3600000 --yes` |
| Exported by | `snare fixture export -task 2 -capture ... -artex-traffic-host snare -forbid <each lab secret>` |

## Files

| File | Contents |
| --- | --- |
| `task.json` | the task (`GET /api/tasks/2`) |
| `outcome.json` | `GET /api/tasks/2/outcome` |
| `findings.json` | 11 findings, each `{finding, lineage}`, with ARTEX's report text and verification fields |
| `evidence/<id>.json` | per finding: `artex_bound` (empty: ARTEX bound nothing, see below) and `snare_matched` (capture lines whose method and path appear in the finding's evidence text; a heuristic) |
| `artex_traffic.json` | ARTEX's own recorded exchanges to `snare` during the task, 114, each with its id, timestamp and full request and response as `GET /api/traffic/exchange` returns them. Requests are as the tools sent them, so none carries the scanner header |
| `scanner.jsonl.gz` | Snare's scanner capture of the same 114 requests, in arrival order, unredacted, with nanosecond timing |

## Findings

All 11 are `pending` with `verification_status: unverified` and
`poe_level` 3. ARTEX's report writer ran once per finding and saved a full
report (about 10,000 to 14,000 characters each), but ARTEX's verification
note on every one is `no proof traffic bound`: ARTEX verifies a finding only
when proof exchanges are bound to it and the report quotes them.

| id | severity | class | name | captured requests matched |
| --- | --- | --- | --- | --- |
| 12 | critical | sqli | UNION-based SQL injection in /rest/products/search?q= | 12 |
| 13 | critical | auth-bypass | SQL injection authentication bypass in POST /rest/user/login | 17 |
| 14 | high | idor | (no name) | 11 |
| 15 | high | idor | (no name) | 3 |
| 16 | high | broken access control | (no name) | 17 |
| 17 | medium | broken access control | (no name) | 1 |
| 18 | medium | broken access control | (no name) | 1 |
| 19 | high | sensitive_data_exposure | Unauthenticated user PII exposure via GET /rest/memories | 2 |
| 20 | medium | sensitive_file_exposure | Unauthenticated download of confidential documents and a KeePass database from /ftp | 5 |
| 21 | medium | broken-access-control | /ftp extension-allowlist bypass via double-encoded null byte | 10 |
| 22 | critical | JWT bypass | JWT algorithm confusion and `alg: none` forgery using the leaked jwt.pub | 13 |

## Why nothing was bound

ARTEX's capture was on, so the traffic exists: ARTEX recorded the same 114
exchanges Snare captured. The report writer had the tools to bind it
(`traffic_search`, `traffic_get`, `bind_finding_traffic`) and ARTEX's
instruction to do so before reporting. In every run it called
`get_finding_traffic` once (empty), read the worker traces, and saved the
report without searching or binding traffic. The workers also registered
findings without traffic references. That is the model's behaviour
(deepseek-flash), not the lab's setup.

## The capture

114 requests from 20:02:18 to 20:07:07 UTC, every one identified by the
`X-Snare-Scanner` header (none by address only): 100 GET, 10 POST, 4 PUT.
Statuses: 88 × 200, 11 × 401, 7 × 403, 5 × 500, 1 × 404, 1 × 400, 1 × 201.
User-Agents: `curl/7.88.1` (91), `Python-urllib/3.12` (23). Some requests are
the report writer re-testing live, not the workers. None of them is in the
benign corpus.

## Secret-looking values (reviewed 2026-11-19)

gitleaks flags 28 distinct values here, under two rules only, `jwt` and
`generic-api-key`, all lab data and allowed by the path-scoped allowlist in
`.gitleaks.toml`:

- JWTs the lab Juice Shop issued to lab users (RS256; Juice Shop's signing
  key is public in its source);
- JWTs ARTEX forged as exploit payloads (HS256 algorithm confusion,
  `alg: none`);
- 32-hex MD5 password hashes of Juice Shop's built-in demo users, leaked by
  the lab app.

The exporter refused to write anything containing the lab's own secrets (the
scanner header secret, the ARTEX admin password, Snare's API token and the
webhook secret); none appears.
