// Command labnet runs the compose lab's network helpers.
//
//	labnet egress  -listen :3128 -allow "api.openai.com,api.anthropic.com"
//	labnet forward -listen :8787 -to artex:8787
//	labnet probe   -url http://127.0.0.1:3128/healthz   (container healthcheck)
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

func forward(ctx context.Context, args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("forward", flag.ExitOnError)
	listen := fs.String("listen", ":8787", "listen address")
	to := fs.String("to", "", "fixed destination host:port")
	_ = fs.Parse(args)
	if *to == "" {
		return fmt.Errorf("-to is required")
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	log.Info("forwarding", "listen", *listen, "to", *to)
	return (&labnet.Forward{To: *to, Log: log}).Serve(ctx, ln)
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
