# Threat model

Initial version (M0). It is extended as each component lands.

## Assets

- Real users' ability to use the protected application. Snare must never
  break or tarpit a legitimate request.
- Recorded traffic, which can contain personal data. Redacted before storage
  and encrypted at rest (M1).
- Secrets: Snare's API token, its encryption key, ARTEX credentials, the
  webhook shared secret, and cloud credentials used for rotation (M6).
- The integrity of the action log and the approvals queue.

## Adversaries

1. **An autonomous attack agent** (an ARTEX-like swarm) probing the protected
   application through Snare's gateway.
2. **A human attacker** who has read Snare's source, including the tarpit and
   decoy generators.
3. **Hostile content inside traffic or findings**: text crafted to influence
   any model Snare might consult, or to break Snare's parsers.
4. **A local attacker on the Snare host** without root.

## Trust boundaries and controls

| Boundary | Control | Milestone |
| --- | --- | --- |
| Internet to gateway | Hard limits on body, headers, time, concurrency; rules only block after passing the gate | M1, M4 |
| Gateway to store | Redaction before write, AES-256-GCM at rest, refusal to start without the key when encrypted data exists | M1 |
| ARTEX to Snare (webhook) | Shared-secret header, idempotent processing, webhook treated as a hint and re-fetched from the API | M3 |
| ARTEX output to compiler | Findings are data; deterministic templates; any model draft is only a candidate | M4 |
| Snare to ARTEX (active mode) | Ownership verification before every task; forced brakes; refusal tested | M7 |
| ARTEX to the internet (lab) | Internal-only networks; allowlisting egress proxy for the LLM host; isolation test from inside the container | M0 |
| ARTEX through a reachable container (pivot) | Containment rule (below); structural audit of every container on every ARTEX network; SSRF pivot test through Juice Shop | M0 |
| Operator to Snare API | Bearer token, loopback bind by default | M0 |
| Code to action log | Append-only triggers, actor limited to `policy` or `human` | M0 |

## Containment rule

Any container reachable from ARTEX is part of the containment boundary.
ARTEX and every container that shares a network with it must have no route to
the internet. Otherwise ARTEX can pivot: Juice Shop has a deliberate SSRF
(`POST /profile/image/url` fetches any URL server-side), and any proxying or
URL-fetching service would work the same way. The only exceptions are the
egress proxy (allowlisted LLM hosts only) and the ARTEX UI forwarder (dials
only `artex:8787`). `deploy/compose/lab.sh test-egress` audits every container
on every ARTEX network, so a new service that breaks the rule fails the test.
When Snare needs AWS access for rotation (M6), it gets its own allowlisting
egress proxy on a network ARTEX is not attached to, never a direct route.

## Data sent to the LLM provider

In active mode, ARTEX sends what it sees to the configured LLM provider: the
target's HTTP responses, tool output (scanner results, page contents, error
messages), and anything those contain, including data from the target that
may be sensitive. Snare cannot prevent this; it is how an LLM-driven tester
works. **For sensitive targets, use a local model** (for example Ollama on the
lab network, which ARTEX supports keyless), so nothing leaves your machines.
Passive mode sends nothing to any model, and real user traffic is never sent
to a model in either mode.

## Honest limits

- **Local-model attackers leave no LLM-egress signal.** Detection relies on
  behavior at the gateway, not on seeing model traffic.
- **Behavioral detection has false positives.** That is why rules block only
  after the validation gate, the tarpit needs a certain trigger, and sanctioned
  scanners can be allowlisted.
- **Open-source deception will be studied.** Attackers can read the tarpit and
  decoy generators. Per-deployment secret seeds keep individual deployments
  from looking identical, but the template space is public.
- **Cheap models shrink the cost per decision.** The tarpit's main value is
  time, occupied worker slots, operator attention, runs that end with nothing,
  and fingerprinting telemetry, more than money burned.
- **The lab's ARTEX can reach its LLM provider.** The network is the boundary:
  ARTEX and everything it can reach are on internal-only networks, and its
  single way out is an allowlisting proxy that permits only the configured
  LLM hosts. A compromised ARTEX could still send data to that LLM host; that
  is inherent in using a hosted model. A local model removes even that path.
- **Attack traffic in the benign corpus.** Rules are validated against the
  recorded corpus, so attack requests recorded as "benign" would teach the
  gate that the attack is normal. Snare's own scanner (ARTEX) is excluded by
  address (`recorder.exclude_sources`, failing closed when its hostname does
  not resolve), and common scanner User-Agents are excluded. An outside
  attacker probing during the learning period is not caught by either; that
  is the detector's job (M2), and its exclusion applies from then on.
- **Corpus poisoning by a slow attacker.** An attacker who sends exploit
  payloads slowly during the learning period, below anything the detector
  scores as agent-like, gets them recorded as benign. The gate replays the
  corpus against each candidate rule and refuses to promote a rule that
  matches benign traffic, so a few poisoned entries on a route would keep
  every rule for that route from ever blocking. That is a denial of
  protection, not an outage, and it is silent. Mitigations, in the gate's
  corpus preparation (M4):
  - quarantine: before the gate uses the corpus, every entry that matches one
    of the compiler's exploit-class templates (SQL injection, XSS, path
    traversal, command injection and the others the compiler emits) is set
    aside and never counted as benign; quarantined entries are listed for a
    human to release or delete;
  - source weighting: entries are grouped by similar request shape (route,
    method, parameter names, value class), and each group counts by how many
    distinct sources sent it, not by how many requests. A shape sent by one
    source alone cannot block promotion on its own; it needs several
    independent sources to count as "normal";
  - the gate reports why a rule was blocked (which corpus entries matched,
    how many sources), so a route where one source keeps blocking rules is
    visible.
  These reduce the problem; they do not remove it. An attacker with many
  sources (a botnet) can still fake "distinct sources". The corpus also
  stores no client address (privacy), so source weighting needs a keyed hash
  of the source (HMAC with a key Snare holds, rotated with the learning
  period) stored per entry; that is a schema change planned for M4.
- **The scanner identity secret.** ARTEX marks its requests with a secret
  header so Snare keeps them out of the benign corpus. Whoever learns the
  secret can keep their own requests out of the corpus too, which only
  shrinks it. The header must never become an allowlist: it does not exempt a
  request from detection, rules, the tarpit or blocking. The gateway removes
  it from every request, so the protected app and its logs never see it, and
  ARTEX stores its recorded requests without it.
- **A root attacker on the Snare host** can read the key file and the
  database. Snare does not defend against a compromised host.
- **A copied data directory includes the default key.** The default key file
  sits next to the database, so encryption at rest only helps when the
  database leaves without it (a backup of the database file alone, a stolen
  disk image of a separate volume). Set `SNARE_SECRET_KEY` or keep
  `secrets.key_file` on a separate mount to make it count.
