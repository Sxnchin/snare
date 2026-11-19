# Gateway overhead (in-process)

Date: 2026-11-19. Go go1.27.4, darwin/arm64, 15 CPUs. 5000 sequential keep-alive GETs per side per mode, interleaved, after 500 warmup requests; response body 4094 bytes.

| Route mode | direct p50 | gateway p50 | added p50 | added p95 | added p99 |
|---|---|---|---|---|---|
| detect (proxy only, no rules yet) | 0.03 ms | 0.07 ms | 0.04 ms | 0.07 ms | 0.09 ms |
| record (pass-through + redact, encrypt, store) | 0.03 ms | 0.07 ms | 0.04 ms | 0.05 ms | 0.10 ms |

Recorder: 5500 exchanges stored, 0 dropped.

# Gateway overhead (lab, real Juice Shop)

Measured with `deploy/compose/lab.sh latency PATH 2000 [detect|record]`. It
starts a throwaway Snare gateway on the internal lab network (store in that
container's own /tmp, so benchmark requests never enter the lab corpus), then
a throwaway client container sends the same GET directly to Juice Shop
(`http://juice-shop:3000`) and through the throwaway gateway, 2000 times each,
interleaved, sequential, keep-alive, after 200 warmup requests per side.
Docker Desktop on macOS (Apple silicon), all containers on one machine.
Measured 2026-11-19.

Spec 7.1 defines `record` as "pass-through, recording only", so `record` is
the mode the 5 ms target applies to. `detect` is listed too: until rules
exist (M4) it proxies without recording, which isolates the proxy cost.

| Mode | Request | direct p50 | gateway p50 | added p50 | added p95 | added p99 |
|---|---|---|---|---|---|---|
| record | `GET /rest/products/search?q=apple` (API, database query) | 7.21 ms | 7.29 ms | 0.08 ms | 0.14 ms | -0.07 ms |
| record | `GET /assets/public/images/JuiceShop_Logo.png` (static file) | 0.20 ms | 0.28 ms | 0.08 ms | 0.17 ms | 0.35 ms |
| detect | `GET /rest/products/search?q=apple` | 6.15 ms | 6.29 ms | 0.14 ms | 0.32 ms | 0.79 ms |
| detect | `GET /assets/public/images/JuiceShop_Logo.png` | 0.21 ms | 0.29 ms | 0.08 ms | 0.15 ms | 0.38 ms |

Run-to-run noise on the API request is about 0.1 ms at p50 and larger at
p99 (negative values mean the gatewayed side happened to be faster), so the
API numbers say "well under 1 ms", not a precise figure. The static file
gives the cleaner reading.

Target (spec 7.1): under 5 ms added at p50 for pass-through (`record`). Met with a wide
margin. Coraza is not in the path yet (rules arrive in M4); this will be
measured again then.
