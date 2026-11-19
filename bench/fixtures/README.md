# Test fixtures

Recorded data that the detector (M2), the connector (M3) and the compiler and
gate (M4) are built and tested against, so that live ARTEX runs, which cost
money, are needed only where a milestone's done condition requires one.

Each capture is a versioned directory, `<target>-capture-v<N>/`, and is never
edited in place: a new capture is a new version.

| File | What it holds | Source |
| --- | --- | --- |
| `README.md` | ARTEX pin, Snare commit, model, date, task id, budget, outcome summary, anything removed or replaced | written with the capture |
| `scanner.jsonl.gz` | every request ARTEX sent through Snare's gateway, with arrival time, duration, headers, bodies (first 1 MiB) and responses, in order | Snare's scanner capture (`scanner.capture_file`, set by `lab.sh capture-run`) |
| `findings.json` | ARTEX's findings for the task, with status, severity, vulnerability class and lineage | `GET /api/exploration/findings`, `.../{id}`, `.../{id}/lineage` |
| `evidence/<finding>.json` | `artex_bound`: the exchanges ARTEX bound to the finding (its proof); `snare_matched`: capture lines whose method and path appear in the finding's evidence text (a heuristic) | ARTEX's traffic store, by `traffic_bindings`; the capture |
| `outcome.json` | tokens, tool calls, wall time, findings by disposition | `GET /api/tasks/{id}/outcome` |

The captured traffic is ARTEX attacking the lab's Juice Shop, which holds
only fake data, so it is stored unredacted: redaction would destroy the
payloads the detector and gate are tested on. It never contains the scanner
identity header (Snare removes it before capture, and ARTEX records requests
before adding it).

Values that look like secrets (Juice Shop's JWTs, the demo data it leaks)
follow the rule in CONTRIBUTING.md: allowlisted for gitleaks by fingerprint,
after checking what each one is. Each capture's README lists what was
allowlisted and why. `snare fixture export -forbid FILE` refuses to write a
fixture that contains any of the lab's own secrets.

| Capture | Run | Notes |
| --- | --- | --- |
| `juice-shop-capture-v1/` | 2026-11-19, 11 findings, 219 requests | no ARTEX-bound evidence (ARTEX capture was off); see its README |
