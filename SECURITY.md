# Security policy

## Reporting a vulnerability

Do not open a public issue. Report privately through GitHub Security
Advisories on this repository (Security tab, "Report a vulnerability").

Please include the Snare version or commit, how you run it, minimal
reproduction steps, and the impact you expect. Remove real user data,
credentials, and tokens from logs and traffic samples.

We aim to acknowledge reports within a week. This is a volunteer project, so
fix timelines are best effort. The default disclosure window is 90 days after a
fix is available, or earlier by agreement.

## Supported versions

Only the latest release receives security fixes. Until the first release,
`main` is the only supported version.

## Scope

In scope: anything that lets an attacker bypass Snare's protections, make
Snare harm real users (for example tarpitting or blocking legitimate requests
without a promoted rule), leak recorded traffic or secrets, act without the
action log or approvals, or make Snare or ARTEX test a target that did not
pass ownership verification.

Out of scope: vulnerabilities in ARTEX itself (report those to ARTEX), in the
protected application, or in the lab's deliberately vulnerable Juice Shop.

## Testing Snare

Test only your own deployment. Snare's deception features are meant to be
studied; reports that the tarpit's generators can be fingerprinted are useful
as hardening issues, but they are a documented limit, not a vulnerability.
