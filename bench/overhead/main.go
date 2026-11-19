// Command overhead measures the latency Snare's gateway adds, in one process,
// with no network or containers involved:
//
//	go run ./bench/overhead [-n 5000] [-size 4096] [-out bench/results/overhead.md]
//
// It starts an upstream that serves a JSON body of -size bytes, then times the
// same GET sent directly and through the gateway, interleaved, for two route
// modes: detect (proxy only; no rules exist yet) and record (the spec's
// "pass-through, recording only" mode: proxy plus redaction,
// encryption and a SQLite write per exchange, off the request path).
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Sxnchin/snare/internal/config"
	"github.com/Sxnchin/snare/internal/gateway"
	"github.com/Sxnchin/snare/internal/labnet"
	"github.com/Sxnchin/snare/internal/recorder"
	"github.com/Sxnchin/snare/internal/store"
)

func main() {
	n := flag.Int("n", 5000, "requests per side per mode")
	size := flag.Int("size", 4096, "upstream response body size in bytes")
	out := flag.String("out", "", "also write a markdown report to this file")
	flag.Parse()
	if err := run(*n, *size, *out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(n, size int, out string) error {
	body := `{"status":"success","data":[` + strings.Repeat(`{"id":1,"name":"Apple Juice (1000ml)","price":1.99},`, size/52) + `{"id":0}]}`
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	defer up.Close()

	dir, err := os.MkdirTemp("", "snare-overhead-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(dir, "snare.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	sealer, err := recorder.LoadSealer(ctx, st, "", filepath.Join(dir, "secret.key"))
	if err != nil {
		return err
	}
	rec := recorder.New(st, sealer, recorder.NewRedactor(nil, nil), recorder.Options{
		LearningPeriod: 24 * time.Hour, MaxBodyBytes: 256 << 10, QueueSize: 4096,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	recCtx, stop := context.WithCancel(ctx)
	defer stop()
	go rec.Run(recCtx)

	limits := config.Default().Gateway.Limits
	gw, err := gateway.New(gateway.Options{Limits: limits, Recorder: rec, Routes: []config.Route{
		{Name: "pass", PathPrefix: "/pass", Upstream: up.URL, Mode: config.ModeDetect},
		{Name: "record", PathPrefix: "/record", Upstream: up.URL, Mode: config.ModeRecord},
	}})
	if err != nil {
		return err
	}
	gsrv := httptest.NewServer(gw)
	defer gsrv.Close()

	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 4, DisableCompression: true}}
	type row struct {
		mode      string
		direct, g labnet.Percentiles
	}
	var rows []row
	for _, mode := range []string{"pass", "record"} {
		d, g, err := labnet.Compare(ctx, client, up.URL+"/"+mode+"/x", gsrv.URL+"/"+mode+"/x", n, 500)
		if err != nil {
			return err
		}
		rows = append(rows, row{mode, d, g})
	}
	stop()
	rec.Wait()
	stored, dropped := rec.Stats()

	var b strings.Builder
	fmt.Fprintf(&b, "# Gateway overhead (in-process)\n\n")
	fmt.Fprintf(&b, "Date: %s. Go %s, %s/%s, %d CPUs. %d sequential keep-alive GETs per side per mode, interleaved, after 500 warmup requests; response body %d bytes.\n\n",
		time.Now().UTC().Format("2006-01-02"), runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), n, len(body))
	fmt.Fprintf(&b, "| Route mode | direct p50 | gateway p50 | added p50 | added p95 | added p99 |\n|---|---|---|---|---|---|\n")
	for _, r := range rows {
		name := map[string]string{"pass": "detect (proxy only, no rules yet)", "record": "record (pass-through + redact, encrypt, store)"}[r.mode]
		fmt.Fprintf(&b, "| %s | %s ms | %s ms | %s ms | %s ms | %s ms |\n", name,
			labnet.Ms(r.direct.P50), labnet.Ms(r.g.P50), labnet.Ms(r.g.P50-r.direct.P50),
			labnet.Ms(r.g.P95-r.direct.P95), labnet.Ms(r.g.P99-r.direct.P99))
	}
	fmt.Fprintf(&b, "\nRecorder: %d exchanges stored, %d dropped.\n", stored, dropped)
	fmt.Print(b.String())
	if out != "" {
		if err := os.WriteFile(out, []byte(b.String()), 0o600); err != nil {
			return err
		}
	}
	return nil
}
