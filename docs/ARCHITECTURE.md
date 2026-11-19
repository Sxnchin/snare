# Architecture

Snare sits in front of an application as a reverse proxy, and next to an
unmodified ARTEX instance as an API client. It turns what ARTEX proves about the
application into protections, and it watches production traffic for the
behavior of autonomous attack agents.

This document describes the target design and marks what exists today. The
milestone plan is in the README.

## Components

```mermaid
flowchart LR
  U[Real users] --> GW
  A[Attacking agent] --> GW
  subgraph SNARE[Snare: one Go binary, SQLite]
    GW[gateway: reverse proxy + Coraza]
    REC[recorder: redacted, encrypted benign corpus]
    DET[detect: agent-likelihood score]
    TP[tarpit + decoy + honeytokens]
    CMP[compiler: finding to rule]
    GATE[gate: validation and promotion]
    ROT[rotate: credential rotation]
    OWN[ownership: target verification]
    ACT[actions: log, undo, approvals]
    CON[artex: connector]
    UI[ui: API, htmx UI, CLI]
  end
  GW --> APP[Protected app]
  GW --> REC
  GW --> DET
  DET --> TP
  GW --> TP
  CON <--> ARTEX[ARTEX, unmodified]
  ARTEX -->|attacks only verified staging or lab| GW
  CON --> CMP --> GATE --> GW
  DET --> ROT
  TP --> ROT
  OWN --> CON
  GATE --> ACT
  ROT --> ACT
```

| Package | Responsibility | Status |
| --- | --- | --- |
| `internal/config` | Load `snare.yaml`, apply `SNARE_*` overrides, validate with all problems listed at once | M0, done |
| `internal/store` | SQLite (`modernc.org/sqlite`, no CGO), embedded numbered migrations, secret files | M0, done |
| `internal/ui` | Authenticated API (`/api/status`), unauthenticated `/healthz`; htmx UI later | M0 partial, M8 |
| `internal/artex` | ARTEX client. M0: health, auth status, login, session check | M0 partial, M3 |
| `internal/gateway` | Reverse proxy, per-route modes, Coraza, hard limits | M1 |
| `internal/recorder` | Redaction, AES-256-GCM at rest, HAR and Playwright import, coverage | M1 |
| `internal/detect` | Deterministic, explainable agent-likelihood score | M2 |
| `internal/compiler` | Finding plus proving exchange to a narrow SecLang rule, or a ticket | M4 |
| `internal/gate` | Promotion state machine, replay, soak, rollback | M4 |
| `internal/tarpit` | Lead-generating tarpit for certain-agent sources | M5 |
| `internal/decoy` | Decoy paths and honeytokens | M5 |
| `internal/rotate` | AWS IAM key deactivation, generic rotation webhook | M6 |
| `internal/ownership` | DNS TXT and well-known file verification, active-mode brakes | M7 |
| `internal/actions` | Append-only action log, undo handles, approvals queue | schema in M0, logic from M4 |

## Process model

`snare serve` runs everything in one process:

- the API and UI listener (`server.listen`, loopback by default, bearer token);
- the gateway listener (`gateway.listen`), from M1;
- background loops (webhook processing, soak timers, re-verification,
  regression replay), from M3 onward.

All state is in one SQLite file. Passive mode needs no other service. Active
mode needs an ARTEX instance reachable over HTTP.

## Data flow for a finding

1. ARTEX proves a hole in a verified target and posts a webhook to Snare.
2. The connector verifies the shared secret, deduplicates by finding ID and
   status, and fetches the finding, its lineage, and its bound proving
   exchanges from the ARTEX API.
3. The compiler turns the finding into a candidate rule scoped to method,
   path, parameter and payload class, or into a human ticket for classes a WAF
   cannot fix honestly (IDOR, business logic, broken auth).
4. The gate moves the rule through
   `candidate -> detect_only -> soaking -> enforced -> rolled_back | retired`,
   replaying the stored exploit and the benign corpus, soaking on live traffic,
   and finally asking ARTEX to retest through Snare.
5. Every transition is an action log row with evidence and an undo handle.

## Trust boundaries

- Protected-app traffic, attacker traffic, and ARTEX output are untrusted data.
  No component interprets them as instructions. When an optional model is
  used (off by default), untrusted text is framed as data and the output is
  only ever a candidate that must pass the deterministic gate.
- The action log is enforced append-only in the schema (SQLite triggers reject
  UPDATE and DELETE), and its `actor` column accepts only `policy` or `human`.
  A model can never be the actor of an action.
- Snare's API requires a bearer token. The API binds to loopback unless
  `server.allow_non_loopback` is set.

## The lab

`deploy/compose` defines the development lab. The network is the boundary
that keeps ARTEX on lab targets: ARTEX is attached only to Docker `internal`
networks, which have no route or DNS to the internet.

```
 host 127.0.0.1:   8000, 8780                    8787
                       |                           |
 front (bridge)    [ snare ]                  [ artex-ui ]  fixed forwarder to artex:8787
                       |                           |
 lab (internal)   -----+---- juice-shop ----+      | artex-admin (internal)
                                            |      |
                                         [ artex ]-+
                                            |  |
 artex-db (internal)       postgres --------+  +-------- [ egress ] -- outbound (bridge) --> LLM host only
                                              llm-egress (internal)
```

- Juice Shop is attached only to `lab`; the host reaches it only through
  Snare's gateway.
- ARTEX reaches the internet only through `egress`, an allowlisting CONNECT
  proxy (`internal/labnet`) set as `ARTEX_LLM_PROXY`. It allows exactly the
  hosts in `LLM_EGRESS_ALLOW` and refuses everything else.
- ARTEX runs as an offline overlay of the unmodified image: nuclei templates
  are baked in at a pinned release and tool self-updates are off
  (`deploy/compose/artex-offline`).
- `lab.sh up` generates secrets, builds everything, waits for health, performs
  ARTEX's first-run claim (it reads the one-time setup token from the ARTEX log
  and calls `POST /api/auth/init`), forces ARTEX web search off, and checks
  that Snare can log in to ARTEX. `lab.sh test` runs the isolation test from
  inside the ARTEX container and the Go client's integration test against the
  real container.

## ARTEX interface

Snare uses only ARTEX's HTTP API and its generic webhook notification channel.
The endpoints and the facts Snare depends on, with the file each was verified
in, are listed in [ASSUMPTIONS.md](ASSUMPTIONS.md#artex-interface-notes).
Changes Snare would like from ARTEX are written as patches with proposed pull
request descriptions under [upstream/](upstream/).
