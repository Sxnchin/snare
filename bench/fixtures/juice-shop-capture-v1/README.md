# juice-shop-capture-v1

One recorded ARTEX run against the lab's OWASP Juice Shop, through Snare's
gateway. Test data for the detector (M2), the connector (M3, served by a fake
ARTEX) and the compiler and gate (M4). Never edited in place; a new capture
is `v2`.

## The run

| | |
| --- | --- |
| Date | 2026-11-19, 19:37:25 to about 19:42:20 UTC (off-peak) |
| ARTEX | unmodified, pinned commit `d89cf781b790ec9a1d071bee7e79de489ed05252`, offline overlay, task 1 |
| Target | `http://snare:8000`, Juice Shop v20.4.0 behind Snare (route `juice-shop`, record mode); ARTEX had no direct route to Juice Shop |
| Model | DeepSeek `deepseek-flash` through the OpenAI-compatible API |
| Budget | ARTEX task budget 2,000,000 tokens (input plus output), hard stop 2,400,000, wall-clock limit 5400 s |
| Used | 2,225,160 input tokens (2,035,328 of them cache reads), 78,621 output tokens, 49 tool calls, 296 s wall time |
| Cost | estimated actual $0.0818 (cache reads at the $0.003/M cache-hit rate); upper bound $0.3809 (every input token at $0.15/M) |
| Started by | `deploy/compose/lab.sh capture-run --yes` |
| Exported by | `snare fixture export -task 1 -capture ... -forbid <each lab secret>` |

## Files

| File | Contents |
| --- | --- |
| `task.json` | the task as ARTEX reports it (`GET /api/tasks/1`) |
| `outcome.json` | `GET /api/tasks/1/outcome` |
| `findings.json` | 11 findings, each `{finding, lineage}` from `GET /api/exploration/findings/{id}` and `.../lineage`, in finding id order |
| `evidence/<id>.json` | per finding: `artex_bound` (exchanges ARTEX bound to it; empty in this run, see below) and `snare_matched` (lines of the capture whose method and path appear in the finding's evidence text) |
| `scanner.jsonl.gz` | Snare's scanner capture: all 219 requests ARTEX sent through the gateway, in arrival order, unredacted, with nanosecond arrival time, duration, headers, the first 1 MiB of each body, status and response |

## Findings

All 11 are `pending`: ARTEX registered them but had not verified any when
the budget ran out (outcome: 11 open, 0 confirmed).

| id | severity | class | name | captured requests matched |
| --- | --- | --- | --- | --- |
| 1 | critical | sql_injection | SQL injection in POST /rest/user/login (authentication bypass to admin) | 10 |
| 2 | high | sqli | (no name) | 13 |
| 3 | high | jwt_authentication_bypass | JWT signature bypass via alg=none / HS256 algorithm confusion | 16 |
| 4 | medium | information_disclosure | Unauthenticated directory listing on /ftp | 1 |
| 5 | high | sensitive-file-exposure | Directory listing and extension-filter bypass under /ftp | 4 |
| 6 | low | verbose-error-disclosure | Verbose stack traces and internal paths in error responses | 11 |
| 7 | high | IDOR | Any customer can read any user's basket via GET /rest/basket/{id} | 18 |
| 8 | high | IDOR | GET /api/BasketItems lists every user's basket items | 1 |
| 9 | high | IDOR (write) | PUT /api/BasketItems/{id} modifies another user's basket | 13 |
| 10 | medium | business logic | Basket item quantity accepts negative values | 13 |
| 11 | medium | broken_access_control | Any registered customer can list all users | 29 |

## The capture

219 requests from 19:37:42 to 19:41:26 UTC: 186 GET, 27 POST, 5 PUT,
1 OPTIONS. Statuses: 142 × 200, 39 × 500, 17 × 401, 10 × 201, 5 × 403,
2 × 400, 2 × 301, 1 × 404, 1 × 204. User-Agents: `curl/7.88.1` (140),
`artex-authz-check/1.0` (69), `Python-urllib/3.12` (10).

## Limits of this capture

- **No ARTEX-bound evidence.** ARTEX's traffic capture (`traffic_capture`)
  is off by default, and while it is off ARTEX gives its tools no proxy. So
  no finding has bound exchanges (`traffic_count` 0), and `artex_bound` is
  empty everywhere. `snare_matched` is a heuristic made by the exporter: a
  captured request is listed when its method and path appear as a request
  line in the finding's evidence, summary or name. It can include requests
  to the same endpoint that were not the proof, and miss proofs the evidence
  text describes differently. `lab.sh bootstrap` now turns ARTEX's capture
  on, so the next capture will have bound evidence.
- **No scanner header.** For the same reason every request was identified by
  ARTEX's fixed address (`identified: "source"`), none by the
  `X-Snare-Scanner` header. The exclusion still held: none of these
  requests is in the benign corpus.
- **Unverified findings.** None was confirmed by ARTEX. Treat severities and
  classes as ARTEX's claims; the M4 gate checks them by replay.
- **Short run.** About four minutes of traffic. The budget went mostly to
  input tokens (the agents re-read long context), not to requests.

## Secret-looking values (reviewed 2026-11-19)

Every value gitleaks flags here is lab data, allowed by the path-scoped
allowlist in `.gitleaks.toml` (rules `jwt` and `generic-api-key` only):

- JWTs the lab Juice Shop issued to lab users (Juice Shop's signing key is
  public in its source);
- JWTs ARTEX forged as exploit payloads (HS256 algorithm confusion,
  `alg: none`);
- 32-hex MD5 password hashes of Juice Shop's built-in demo users, leaked by
  the lab app's `/api/Users` (the vulnerability in finding 11).

The exporter refused to write anything containing the lab's own secrets (the
scanner header secret, the ARTEX admin password, Snare's API token and the
webhook secret); none appears.
