// Command labnet runs the compose lab's network helpers.
//
//	labnet egress  -listen :3128 -allow "api.openai.com,api.anthropic.com"
//	labnet forward -map :8787=artex:8787 [-map :8000=snare:8000 ...]
//	labnet probe   -url http://127.0.0.1:3128/healthz   (container healthcheck)
//	labnet latency -direct URL -gateway URL [-n 2000]    (gateway overhead in the lab)
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/snare-dev/snare/internal/labnet"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: labnet egress|forward|probe [flags]")
		os.Exit(2)
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch os.Args[1] {
	case "egress":
		err = egress(ctx, os.Args[2:], log)
	case "forward":
		err = forward(ctx, os.Args[2:], log)
	case "probe":
		err = probe(os.Args[2:])
	case "latency":
		err = latency(ctx, os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		log.Error("labnet", "err", err)
		os.Exit(1)
	}
}

func egress(ctx context.Context, args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("egress", flag.ExitOnError)
	listen := fs.String("listen", ":3128", "listen address")
	allow := fs.String("allow", os.Getenv("LLM_EGRESS_ALLOW"), "comma-separated host[:port] allowlist (env LLM_EGRESS_ALLOW)")
	allowPrivate := fs.Bool("allow-private", false, "permit allowlisted names that resolve to non-public addresses")
	_ = fs.Parse(args)
	set, err := labnet.ParseAllow(*allow)
	if err != nil {
		return err
	}
	if len(set) == 0 {
		log.Warn("egress allowlist is empty: every destination is denied")
	}
	e := &labnet.Egress{Allow: set, AllowPrivate: *allowPrivate, Log: log}
	log.Info("egress proxy listening", "addr", *listen, "allow", e.AllowList())
	srv := &http.Server{Addr: *listen, Handler: e, ReadHeaderTimeout: 10 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
}

// mapFlag collects repeated -map listen=to values.
type mapFlag []string

func (m *mapFlag) String() string     { return fmt.Sprint(*m) }
func (m *mapFlag) Set(v string) error { *m = append(*m, v); return nil }

func forward(ctx context.Context, args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("forward", flag.ExitOnError)
	var maps mapFlag
	fs.Var(&maps, "map", "listen=host:port, repeatable; each listener dials only its fixed destination")
	_ = fs.Parse(args)
	if len(maps) == 0 {
		return fmt.Errorf("at least one -map listen=host:port is required")
	}
	errc := make(chan error, len(maps))
	for _, m := range maps {
		listen, to, ok := strings.Cut(m, "=")
		if !ok || listen == "" || to == "" {
			return fmt.Errorf("bad -map %q, want listen=host:port", m)
		}
		ln, err := net.Listen("tcp", listen)
		if err != nil {
			return err
		}
		log.Info("forwarding", "listen", listen, "to", to)
		go func() { errc <- (&labnet.Forward{To: to, Log: log}).Serve(ctx, ln) }()
	}
	return <-errc
}

// latency compares the same request sent directly and through the gateway.
func latency(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("latency", flag.ExitOnError)
	direct := fs.String("direct", "", "URL served directly by the app")
	via := fs.String("gateway", "", "the same URL through Snare's gateway")
	n := fs.Int("n", 2000, "requests to each URL")
	warmup := fs.Int("warmup", 200, "warmup requests to each URL")
	_ = fs.Parse(args)
	if *direct == "" || *via == "" {
		return fmt.Errorf("-direct and -gateway are required")
	}
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 4, DisableCompression: true}}
	d, g, err := labnet.Compare(ctx, c, *direct, *via, *n, *warmup)
	if err != nil {
		return err
	}
	fmt.Printf("requests per side: %d (interleaved, sequential, keep-alive)\n", d.N)
	fmt.Printf("%-10s %8s %8s %8s\n", "", "p50 ms", "p95 ms", "p99 ms")
	fmt.Printf("%-10s %8s %8s %8s\n", "direct", labnet.Ms(d.P50), labnet.Ms(d.P95), labnet.Ms(d.P99))
	fmt.Printf("%-10s %8s %8s %8s\n", "gateway", labnet.Ms(g.P50), labnet.Ms(g.P95), labnet.Ms(g.P99))
	fmt.Printf("%-10s %8s %8s %8s\n", "added", labnet.Ms(g.P50-d.P50), labnet.Ms(g.P95-d.P95), labnet.Ms(g.P99-d.P99))
	return nil
}

// probe succeeds when something answers HTTP at url (any status).
func probe(args []string) error {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	url := fs.String("url", "http://127.0.0.1:3128/healthz", "URL to probe")
	_ = fs.Parse(args)
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(*url)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}
