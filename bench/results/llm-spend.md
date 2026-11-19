# LLM spend

Every ARTEX run that calls the LLM provider is recorded here, from ARTEX's
`GET /api/tasks/{id}/outcome`. `./lab.sh capture-run` appends its row and
updates the total.

- Provider and model: DeepSeek `deepseek-flash` through the OpenAI-compatible
  API (`https://api.deepseek.com`).
- Prices per million tokens, off-peak: $0.15 input on a cache miss, $0.003
  input on a cache hit, $0.60 output. Every rate doubles at peak (01:00 to
  04:00 and 06:00 to 10:00 UTC on weekdays); a run that touches peak hours is
  priced entirely at peak.
- ARTEX's input count includes its cache reads. **Est. actual** prices cache
  reads at the cache-hit rate and the rest of the input at the miss rate.
  **Upper bound** prices every input token as a miss.
- Budget for the whole project: $5.00 of prepaid credit.

Total so far: $0.1887 estimated actual, $0.8717 upper bound, of $5.00 (2 runs)

| Started (UTC) | ARTEX task | Run | Input tokens | of which cache reads | Output tokens | Tool calls | Wall seconds | Price | Upper bound | Est. actual |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 2026-11-19T19:37Z | 1 | capture run v1 (Juice Shop through Snare, 2000000-token budget) | 2225160 | 2035328 | 78621 | 49 | 296 | off-peak | $0.3809 | $0.0818 |
| 2026-11-19T20:01Z | 2 | capture run v2 (Juice Shop through Snare, ARTEX capture on, 3000000-token budget) | 2838450 | 2611072 | 108345 | 86 | 401 | off-peak | $0.4908 | $0.1069 |
