// Command snare is the Snare server and CLI.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Sxnchin/snare/internal/artex"
	"github.com/Sxnchin/snare/internal/config"
	"github.com/Sxnchin/snare/internal/gateway"
	"github.com/Sxnchin/snare/internal/recorder"
	"github.com/Sxnchin/snare/internal/store"
	"github.com/Sxnchin/snare/internal/ui"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `snare: defend apps against autonomous attack agents

Usage:
  snare serve [-config snare.yaml]      run the gateway, API and UI
  snare config check [-config FILE]     validate configuration and exit
  snare config env                      list supported SNARE_* overrides
  snare corpus coverage [-config FILE] [-json]          per-route corpus coverage
  snare corpus import-har -route NAME [-host H,...] F.har  import a HAR file into the corpus
  snare corpus show [-config FILE] ID                    print one stored (redacted) exchange
  snare corpus dump -route NAME                          print every stored exchange of a route (redacted)
  snare fixture export -password-file F -task ID -out DIR  export an ARTEX task's findings and evidence as test data
  snare healthcheck [-url URL]          probe a running instance (for containers)
  snare version

Planned (not implemented yet):
  snare quickstart                      M8
  snare verify <target>                 M7
  snare bench                           M8
  snare rules list|show|promote|rollback M4
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "serve":
		return cmdServe(args[1:], stderr)
	case "config":
		return cmdConfig(args[1:], stdout, stderr)
	case "corpus":
		return cmdCorpus(args[1:], stdout, stderr)
	case "fixture":
		return cmdFixture(args[1:], stdout, stderr)
	case "healthcheck":
		return cmdHealthcheck(args[1:], stderr)
	case "version", "-version", "--version":
		fmt.Fprintln(stdout, version)
		return 0
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	case "quickstart", "bench":
		return notYet(stderr, args[0], "M8")
	case "verify":
		return notYet(stderr, args[0], "M7")
	case "rules":
		return notYet(stderr, args[0], "M4")
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

func notYet(w io.Writer, cmd, milestone string) int {
	fmt.Fprintf(w, "snare %s is not implemented yet (planned for %s)\n", cmd, milestone)
	return 2
}

func configFlag(fs *flag.FlagSet) *string {
	def := os.Getenv("SNARE_CONFIG")
	if def == "" {
		if _, err := os.Stat("snare.yaml"); err == nil {
			def = "snare.yaml"
		}
	}
	return fs.String("config", def, "path to snare.yaml (env SNARE_CONFIG)")
}

func cmdConfig(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: snare config check|env")
		return 2
	}
	switch args[0] {
	case "env":
		for _, n := range config.EnvNames() {
			fmt.Fprintln(stdout, n)
		}
		fmt.Fprintln(stdout, "SNARE_CONFIG")
		fmt.Fprintln(stdout, "SNARE_SECRET_KEY")
		return 0
	case "check":
		fs := flag.NewFlagSet("config check", flag.ContinueOnError)
		fs.SetOutput(stderr)
		path := configFlag(fs)
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if _, err := config.Load(*path, os.Environ()); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintln(stdout, "configuration ok")
		return 0
	}
	fmt.Fprintf(stderr, "unknown config subcommand %q\n", args[0])
	return 2
}

func cmdHealthcheck(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	url := fs.String("url", "http://127.0.0.1:8780/healthz", "health endpoint")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(*url)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(stderr, "health: HTTP %d\n", resp.StatusCode)
		return 1
	}
	return 0
}

func cmdServe(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := configFlag(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	cfg, err := config.Load(*path, os.Environ())
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := serve(ctx, cfg, log); err != nil {
		log.Error("snare stopped", "err", err)
		return 1
	}
	return 0
}

// newRecorder opens the encryption key and builds the corpus recorder.
func newRecorder(ctx context.Context, cfg config.Config, st *store.Store, log *slog.Logger) (*recorder.Recorder, error) {
	sealer, err := recorder.LoadSealer(ctx, st, os.Getenv(recorder.KeyEnv), cfg.Secrets.KeyFile)
	if err != nil {
		return nil, err
	}
	red := recorder.NewRedactor(cfg.Recorder.Redact.Headers, cfg.Recorder.Redact.JSONFields)
	return recorder.New(st, sealer, red, recorder.Options{
		LearningPeriod: cfg.Recorder.LearningPeriod.D(),
		MaxBodyBytes:   cfg.Recorder.MaxBodyBytes,
		QueueSize:      cfg.Recorder.QueueSize,
		Log:            log,
	}), nil
}

func serve(ctx context.Context, cfg config.Config, log *slog.Logger) error {
	st, err := store.Open(ctx, cfg.Store.Path)
	if err != nil {
		return err
	}
	defer st.Close()

	token, created, err := store.LoadOrCreateSecret(cfg.Server.APITokenFile, 32)
	if err != nil {
		return fmt.Errorf("api token: %w", err)
	}
	if created {
		log.Info("generated API token", "file", cfg.Server.APITokenFile)
	}

	rec, err := newRecorder(ctx, cfg, st, log)
	if err != nil {
		return err
	}
	recCtx, stopRec := context.WithCancel(context.Background())
	go rec.Run(recCtx)
	defer func() { stopRec(); rec.Wait() }() // drain queued exchanges on shutdown

	exclude := gateway.NewExclusions(cfg.Recorder.ExcludeSources, cfg.Recorder.ExcludeUserAgents, log)
	if cfg.Scanner.SecretFile != "" {
		secret, err := store.ReadSecret(cfg.Scanner.SecretFile)
		if err != nil {
			return fmt.Errorf("scanner.secret_file: %w", err)
		}
		exclude.SetScannerHeader(cfg.Scanner.Header, secret)
		log.Info("scanner header identity on", "header", cfg.Scanner.Header)
	}
	exclude.Refresh(ctx)
	go exclude.Run(recCtx, 5*time.Second)
	var capture *gateway.ScannerCapture
	if cfg.Scanner.CaptureFile != "" {
		capture, err = gateway.OpenScannerCapture(gateway.CaptureOptions{Path: cfg.Scanner.CaptureFile, Log: log})
		if err != nil {
			return err
		}
		defer func() { // after the gateway has stopped (defers run last-in first-out)
			if err := capture.Close(); err != nil {
				log.Warn("scanner capture close failed", "err", err)
			}
		}()
		log.Warn("scanner capture on: scanner traffic is written unredacted (lab only)", "file", cfg.Scanner.CaptureFile)
	}
	gw, err := gateway.New(gateway.Options{
		Routes:         cfg.Gateway.Routes,
		Limits:         cfg.Gateway.Limits,
		TrustedProxies: cfg.Gateway.TrustedProxies,
		Recorder:       rec,
		Exclusions:     exclude,
		Capture:        capture,
		Log:            log,
	})
	if err != nil {
		return err
	}

	var ac *artex.Client
	if cfg.Artex.URL != "" {
		pwFile := cfg.Artex.PasswordFile
		ac = artex.New(cfg.Artex.URL, cfg.Artex.Username,
			func() (string, error) { return store.ReadSecret(pwFile) }, cfg.Artex.Timeout.D())
	}
	routes := make([]string, 0, len(cfg.Gateway.Routes))
	for _, r := range cfg.Gateway.Routes {
		routes = append(routes, r.Name)
	}
	srv := &ui.Server{Store: st, Artex: ac, APIToken: token, Version: version, Active: cfg.Active.Enabled,
		Gateway: gw, Recorder: rec, Routes: routes}
	apiSrv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	servers := []*http.Server{apiSrv}
	if len(cfg.Gateway.Routes) > 0 {
		servers = append(servers, gateway.Server(cfg.Gateway.Listen, gw, cfg.Gateway.Limits))
	} else {
		log.Warn("no gateway routes configured; gateway not started")
	}
	errc := make(chan error, len(servers))
	for i, hs := range servers {
		name := "api"
		if i == 1 {
			name = "gateway"
		}
		go func() {
			log.Info(name+" listening", "addr", hs.Addr, "version", version)
			errc <- hs.ListenAndServe()
		}()
	}
	var runErr error
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			runErr = err
		}
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, hs := range servers {
		if err := hs.Shutdown(shutCtx); err != nil && runErr == nil {
			runErr = err
		}
	}
	return runErr
}
