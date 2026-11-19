# Gateway overhead (in-process)

Date: 2026-11-19. Go go1.27.4, darwin/arm64, 15 CPUs. 5000 sequential keep-alive GETs per side per mode, interleaved, after 500 warmup requests; response body 4094 bytes.

| Route mode | direct p50 | gateway p50 | added p50 | added p95 | added p99 |
|---|---|---|---|---|---|
| pass-through (detect, no rules) | 0.03 ms | 0.07 ms | 0.04 ms | 0.07 ms | 0.09 ms |
| record (redact + encrypt + store) | 0.03 ms | 0.07 ms | 0.04 ms | 0.05 ms | 0.10 ms |

Recorder: 5500 exchanges stored, 0 dropped.

# Gateway overhead (lab, real Juice Shop)

Measured with `deploy/compose/lab.sh latency PATH 2000`: a throwaway container
on the internal lab network sends the same GET directly to Juice Shop
(`http://juice-shop:3000`) and through Snare's gateway (`http://snare:8000`),
2000 times each, interleaved, sequential, keep-alive, after 200 warmup
requests per side. The route is in `record` mode, so every gatewayed request
is also redacted, encrypted and stored. Docker Desktop on macOS (Apple
silicon), all containers on one machine.

| Request | direct p50 | gateway p50 | added p50 | added p95 | added p99 |
|---|---|---|---|---|---|
| `GET /rest/products/search?q=apple` (API, database query) | 6.20 ms | 6.20 ms | 0.00 ms | 0.04 ms | 0.31 ms |
| `GET /assets/public/images/JuiceShop_Logo.png` (static file) | 0.19 ms | 0.27 ms | 0.07 ms | 0.16 ms | 0.26 ms |

Target (spec 7.1): under 5 ms added at p50 for pass-through. Met with a wide
margin. Coraza is not in the path yet (rules arrive in M4); this will be
measured again then.
