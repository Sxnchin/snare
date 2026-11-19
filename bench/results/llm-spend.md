# LLM spend

Every ARTEX run that calls the LLM provider is recorded here, from ARTEX's
`GET /api/tasks/{id}/outcome`. `./lab.sh capture-run` appends its row and
updates the total.

- Provider and model: DeepSeek `deepseek-flash` through the OpenAI-compatible
  API (`https://api.deepseek.com`).
- Prices: $0.15 per million input tokens and $0.60 per million output tokens
  off-peak; double at peak (01:00 to 04:00 and 06:00 to 10:00 UTC on
  weekdays). A run that touches peak hours is priced entirely at peak.
- ARTEX folds cache hits into its input count, and cache hits are billed
  lower than this, so the cost column is an upper bound.
- Budget for the whole project: $5.00 of prepaid credit.

Total so far: $0.3809 of $5.00 (1 runs)

| Started (UTC) | ARTEX task | Run | Input tokens | Output tokens | Tool calls | Wall seconds | Price | Est. cost |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 2026-11-19T19:37Z | 1 | capture run (Juice Shop through Snare, 2000000-token budget) | 2225160 | 78621 | 49 | 296 | off-peak | $0.3809 |
