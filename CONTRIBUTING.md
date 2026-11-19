# Contributing to Snare

Thanks for helping. This file covers how to build, test, and send changes.

## Ground rules

1. **No offensive capability.** Snare does not ship exploits, attack skills,
   scanners, or payload libraries beyond the recorded exploits needed to test
   Snare's own rules. Active testing goes through ARTEX only.
2. **No ARTEX code.** ARTEX is AGPL-3.0 and Snare is Apache-2.0. Reading ARTEX
   source to learn its API is fine; copying it is not. If Snare needs an ARTEX
   change, add a patch and a proposed pull request description under
   `docs/upstream/`.
3. **Lab only.** Tests and development runs point ARTEX only at the lab
   containers in `deploy/compose`. Never at an internet host. Unit tests must
   not need internet access.
4. **Autonomy rule.** Code that acts automatically must be reversible and
   write an action log entry with an undo handle. Irreversible actions go
   through the approvals queue. Model output never triggers an action
   directly.
5. **Untrusted input stays data.** Anything from the protected app, attacker
   traffic, or ARTEX findings is never interpreted as instructions.

## Setup

```sh
go test -race ./...
go vet ./...
gofmt -l .        # must print nothing
```

CI also runs `golangci-lint`, `govulncheck`, and a dependency license check;
the exact versions are in `.github/workflows/ci.yml`.

For the full lab, see the README.

## Changes

- One logical change per pull request, with tests.
- New defaults go in `docs/ASSUMPTIONS.md` in the same change, with the reason
  and where to change them.
- Schema changes are a new numbered file in `internal/store/migrations/`.
  Never edit a migration that has been released.
- New dependencies must be Apache-2.0 compatible (Apache-2.0, MIT, BSD, ISC,
  MPL-2.0). Prefer the standard library and boring, well-known packages.

## Writing style

Docs, UI text, and commit messages: plain and direct. No marketing tone, no
emojis, no em dashes. Write as an engineer explaining the system to another
engineer. Commit subjects in the imperative ("Add route validation").

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do not open a public issue.
