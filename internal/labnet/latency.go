package labnet

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"
)

// Percentiles summarizes a latency sample.
type Percentiles struct {
	N             int
	P50, P95, P99 time.Duration
}

// Summarize computes percentiles (nearest rank) of d. d is sorted in place.
func Summarize(d []time.Duration) Percentiles {
	if len(d) == 0 {
		return Percentiles{}
	}
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	at := func(p float64) time.Duration {
		i := int(p*float64(len(d))+0.5) - 1
		if i < 0 {
			i = 0
		}
		if i >= len(d) {
			i = len(d) - 1
		}
		return d[i]
	}
	return Percentiles{N: len(d), P50: at(0.50), P95: at(0.95), P99: at(0.99)}
}

// Compare times n sequential GETs against each of a and b, interleaved
// (a, b, a, b, ...) so drift in the machine affects both equally, after
// warmup requests to each. Each response body is read fully. Any non-2xx or
// 3xx status is an error: the comparison is only meaningful when both URLs
// serve the same thing successfully.
func Compare(ctx context.Context, c *http.Client, a, b string, n, warmup int) (Percentiles, Percentiles, error) {
	get := func(u string) (time.Duration, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return 0, err
		}
		start := time.Now()
		resp, err := c.Do(req)
		if err != nil {
			return 0, err
		}
		_, err = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		d := time.Since(start)
		if err != nil {
			return 0, err
		}
		if resp.StatusCode >= 400 {
			return 0, fmt.Errorf("%s: HTTP %d", u, resp.StatusCode)
		}
		return d, nil
	}
	for i := 0; i < warmup; i++ {
		if _, err := get(a); err != nil {
			return Percentiles{}, Percentiles{}, err
		}
		if _, err := get(b); err != nil {
			return Percentiles{}, Percentiles{}, err
		}
	}
	da := make([]time.Duration, 0, n)
	db := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		x, err := get(a)
		if err != nil {
			return Percentiles{}, Percentiles{}, err
		}
		y, err := get(b)
		if err != nil {
			return Percentiles{}, Percentiles{}, err
		}
		da, db = append(da, x), append(db, y)
	}
	return Summarize(da), Summarize(db), nil
}

// Ms formats a duration in milliseconds with two decimals.
func Ms(d time.Duration) string { return fmt.Sprintf("%.2f", float64(d.Microseconds())/1000) }
