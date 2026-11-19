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
| Operator to Snare API | Bearer token, loopback bind by default | M0 |
| Code to action log | Append-only triggers, actor limited to `policy` or `human` | M0 |

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
  ARTEX is on internal-only networks and its single way out is an allowlisting
  proxy that permits only the configured LLM hosts. A compromised ARTEX could
  still send data to that LLM host; that is inherent in using a hosted model.
  A local model (Ollama on the lab network) removes even that path.
- **A root attacker on the Snare host** can read the key file and the
  database. Snare does not defend against a compromised host.
