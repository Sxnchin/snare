# Snare

> **TODO(rename):** "Snare" is a working name. It collides with existing
> security products and will change before any public release. Nothing has
> been published under this name.

Snare is an open-source defense against autonomous attack agents. It runs an
unmodified [ARTEX](https://github.com/BaaRai/ARTEX) against systems you have
proven you own, and turns every verified finding into four defensive
artifacts:

- a reversible mitigation (a narrow virtual patch, live in minutes),
- a detection rule,
- a decoy or token tarpit where the hole used to be,
- a regression replay that re-tests the hole after every deploy.

In front of production it runs a passive layer: traffic recording, agent
detection, honeytokens, decoys, and credential rotation.

**Status: early development (milestone M1 of M8).** Working today: the
compose lab with a contained ARTEX and OWASP Juice Shop, and the gateway in
front of Juice Shop recording a redacted, encrypted benign corpus. The
detector, compiler, validation gate, tarpit and the rest are not built yet.
Do not deploy Snare in front of anything real.

## What Snare is not

- Not a scanner or exploit framework. Snare adds no offensive capability.
  Active testing happens only through ARTEX, and only against targets that
  passed ownership verification.
- Not a general WAF. Its rules are narrow and specific to holes ARTEX proved.
  OWASP CRS support is optional and off by default.
- Not a replacement for fixing the code. A virtual patch buys time; the
  regression replay tells you when the real fix landed.

## Lab quickstart (development)

Requirements: Docker with Compose v2, curl, Go 1.26 or newer, and the pinned
ARTEX checkout next to this repository (`../ARTEX`, or `../ARTEX-main`
extracted from the release zip). See `docs/ASSUMPTIONS.md` for the pinned
commit.

```sh
cd deploy/compose
./lab.sh up        # builds Snare and ARTEX, starts the lab, sets up ARTEX
./lab.sh status
./lab.sh down      # add -v to delete volumes
```

`lab.sh up` generates local secrets under `deploy/compose/secrets/`, performs
ARTEX's first-run setup, and checks that Snare can log in to ARTEX. The first
build of the ARTEX image takes a long time (it installs its scanner
toolchain and a browser). Everything binds to 127.0.0.1:

| Port | Service |
| --- | --- |
| 8000 | Snare gateway (Juice Shop behind it, from M1) |
| 8780 | Snare API (`Authorization: Bearer $(cat deploy/compose/secrets/snare_api_token)`) |
| 8787 | ARTEX UI through a loopback forwarder (user `ARTEX`, password in `deploy/compose/secrets/artex_admin_password`) |

Juice Shop has no internet access and is not published on the host. ARTEX,
and every container ARTEX can reach, is on internal-only networks: its only
way out is an egress proxy that allows just the LLM provider hosts in
`LLM_EGRESS_ALLOW`. `./lab.sh test` proves it
from inside the ARTEX container (including a pivot attempt through Juice
Shop's SSRF) and logs Snare's ARTEX client in to the real
container. No LLM key is configured by the lab; set one in
`deploy/compose/.env` yourself.

Recording legitimate traffic (milestone M1):

```sh
./lab.sh traffic        # Playwright happy path through Snare: register, log in, search, basket, checkout
./lab.sh corpus-check   # fail if any value the suite typed in was stored unredacted
./lab.sh coverage       # per-route corpus coverage: endpoints, methods, statuses, parameter names
./lab.sh latency '/rest/products/search?q=apple'   # gateway overhead against the real Juice Shop
```

## Gateway overhead

Measured 2026-11-19 on the lab machine (Apple silicon, Docker Desktop).
Details and method: [bench/results/2026-11-18-gateway-overhead.md](bench/results/2026-11-18-gateway-overhead.md).

| Measurement | added p50 | added p99 |
| --- | --- | --- |
| In-process, `record` mode (pass-through + redact, encrypt, store; `go run ./bench/overhead`) | 0.04 ms | 0.10 ms |
| In-process, `detect` mode (proxy only, no rules yet) | 0.04 ms | 0.09 ms |
| Lab, Juice Shop API search, `record` mode | 0.08 ms | -0.07 ms (noise) |
| Lab, Juice Shop static image, `record` mode | 0.08 ms | 0.35 ms |

`./lab.sh latency` runs against a throwaway gateway, so benchmark requests
never enter the lab corpus.

The target is under 5 ms at p50. Coraza rules are not in the path yet (M4);
the numbers will be measured again then.

## What is recorded, and how

Routes in `record` mode store request and response pairs for a learning
period (72 hours by default) as the benign corpus that rules are validated
against later. Before anything is written:

- credentials are removed: `Authorization`, `Cookie` and `Set-Cookie` values,
  token headers, and password, token, key, session and similar fields in JSON,
  forms and query strings;
- personal data is removed: email addresses, card numbers (Luhn-checked),
  name, phone, address and date-of-birth fields;
- JWTs, bearer tokens and API-key-like strings are removed anywhere in text;
- compressed bodies are decoded first, and anything that cannot be decoded is
  not stored.

The redacted exchange is then encrypted with AES-256-GCM. Snare refuses to
start if encrypted data exists and the key is missing or wrong. No client
address is stored. Traffic the detector flags as agent-like is excluded
(from M2). The full rules are in `docs/ASSUMPTIONS.md`. Add your own header
and field names under `recorder.redact` in `snare.yaml`.

## Building and testing

```sh
go build ./cmd/snare
go test -race ./...
./snare config check -config deploy/compose/snare.lab.yaml
./snare config env        # every SNARE_* override
```

## Passive and active mode

- **Passive mode** (default, meant to be safe in production): gateway,
  recording, detection, honeytokens, decoys, tarpit for high-confidence
  triggers, credential rotation, and enforcement of rules already promoted.
  No attack traffic.
- **Active mode** (off by default): Snare creates ARTEX tasks against an
  ownership-verified target, by default a staging copy. Against production it
  needs an explicit opt-in, and Snare forces ARTEX's brakes on: target gate,
  quiet noise profile, task and intent budgets, and approval for
  state-changing requests.

**In active mode, the target's responses are sent to the LLM provider you
configure for ARTEX.** ARTEX is an LLM-driven tester: page contents, error
messages, and tool output from the target go to the model. For sensitive
targets, use a local model (for example Ollama, which ARTEX supports without
an API key) so nothing leaves your machines. Passive mode sends nothing to any
model.

## The autonomy rule

Snare acts on its own only when the action is reversible and logged with an
undo handle: deploying a rule in detect-only mode, promoting a rule that passed
the gate, deactivating an unused key. Anything irreversible needs a person to
approve it in the approvals queue. A model may propose; a deterministic policy
decides. The action log is append-only, enforced in the database schema.

## Ownership verification

Before any active test, the operator proves control of the target with a DNS
TXT record at `_snare-challenge.<domain>` or a file at
`/.well-known/snare-challenge/<token>`. Snare re-verifies before every task and
refuses to create a task for an unverified target. Private and loopback
addresses need an explicit `local_lab: true`. (Milestone M7.)

## Benchmark

Not run yet. M8 adds `snare bench`: ARTEX against Juice Shop directly, behind
Snare with patched holes blocked, and behind Snare with patched holes
tarpitted, with tokens, tool calls, wall time, findings, and legitimate
requests broken (which must be zero).

## Threat model and honest limits

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). In short: an attacker using a
local model leaves no LLM-egress signal; behavioral detection has false
positives; open-source deception will be studied; cheap models shrink the
money an attacker burns per decision, so the tarpit's main value is time,
worker slots, operator attention, empty-handed runs, and telemetry.

## Relationship to ARTEX

Snare is a separate program. It talks to ARTEX only over ARTEX's HTTP API and
webhooks and contains no ARTEX code. ARTEX is licensed AGPL-3.0; Snare is
licensed Apache-2.0. If Snare needs an ARTEX change, it is written as a patch
with a proposed pull request under `docs/upstream/`, and Snare works without
it.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Assumptions and defaults](docs/ASSUMPTIONS.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## License

Apache-2.0. See [LICENSE](LICENSE).
