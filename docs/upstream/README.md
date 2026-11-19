# Upstream proposals for ARTEX

Snare never modifies ARTEX. When an ARTEX change would help, it is written
here as a patch file plus a proposed pull request description, and Snare
works around its absence.

Each proposal is a pair:

- `NNNN-short-name.patch`: a unified diff against the pinned ARTEX commit;
- `NNNN-short-name.md`: the pull request description (problem, change, tests,
  and how Snare behaves without it).

No proposals yet. Candidate for M3: expose `TaskID` and `Kind` in the webhook
template context (see `docs/ASSUMPTIONS.md`, ARTEX interface notes, item 5).
