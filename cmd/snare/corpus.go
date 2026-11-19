package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/snare-dev/snare/internal/config"
	"github.com/snare-dev/snare/internal/recorder"
	"github.com/snare-dev/snare/internal/store"
)

// cmdCorpus works on the store directly, so it runs next to a live server
// (SQLite WAL) or with the server stopped.
func cmdCorpus(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: snare corpus coverage|import-har|show|dump")
		return 2
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("corpus "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := configFlag(fs)
	asJSON := fs.Bool("json", false, "print JSON")
	route := fs.String("route", "", "route name (import-har, dump)")
	hosts := fs.String("host", "", "comma-separated hosts to import from the HAR; empty imports every host (import-har)")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	cfg, err := config.Load(*path, os.Environ())
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	ctx := context.Background()
	st, err := store.Open(ctx, cfg.Store.Path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer st.Close()
	rec, err := newRecorder(ctx, cfg, st, slog.New(slog.NewTextHandler(stderr, nil)))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	switch sub {
	case "coverage":
		names := make([]string, 0, len(cfg.Gateway.Routes))
		for _, r := range cfg.Gateway.Routes {
			names = append(names, r.Name)
		}
		cov, err := rec.Coverage(ctx, names)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if *asJSON {
			return printJSON(stdout, map[string]any{"routes": cov})
		}
		printCoverage(stdout, cov)
		return 0
	case "import-har":
		if *route == "" || fs.NArg() != 1 {
			fmt.Fprintln(stderr, "usage: snare corpus import-har -route NAME [-host h1,h2] FILE.har")
			return 2
		}
		if !routeExists(cfg, *route) {
			fmt.Fprintf(stderr, "route %q is not configured\n", *route)
			return 1
		}
		f, err := os.Open(fs.Arg(0))
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		defer f.Close()
		var hl []string
		for _, h := range strings.Split(*hosts, ",") {
			if h = strings.TrimSpace(h); h != "" {
				hl = append(hl, h)
			}
		}
		res, err := rec.ImportHAR(ctx, *route, hl, f)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return printJSON(stdout, res)
	case "dump":
		// One redacted record per line, for audits such as the lab's check
		// that none of the Playwright suite's typed values were stored.
		if *route == "" {
			fmt.Fprintln(stderr, "usage: snare corpus dump -route NAME")
			return 2
		}
		ids, err := rec.IDs(ctx, *route)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		enc := json.NewEncoder(stdout)
		for _, id := range ids {
			r, err := rec.Read(ctx, id)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			if err := enc.Encode(map[string]any{"id": id, "record": r}); err != nil {
				return 1
			}
		}
		return 0
	case "show":
		if fs.NArg() != 1 {
			fmt.Fprintln(stderr, "usage: snare corpus show ID")
			return 2
		}
		id, err := strconv.ParseInt(fs.Arg(0), 10, 64)
		if err != nil {
			fmt.Fprintln(stderr, "ID must be a number")
			return 2
		}
		r, err := rec.Read(ctx, id)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return printJSON(stdout, r)
	}
	fmt.Fprintf(stderr, "unknown corpus subcommand %q\n", sub)
	return 2
}

func routeExists(cfg config.Config, name string) bool {
	for _, r := range cfg.Gateway.Routes {
		if r.Name == name {
			return true
		}
	}
	return false
}

func printJSON(w io.Writer, v any) int {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return 1
	}
	return 0
}

func printCoverage(w io.Writer, cov []recorder.RouteCoverage) {
	for _, rc := range cov {
		learning := "ended"
		if rc.LearningActive {
			learning = "active"
		}
		fmt.Fprintf(w, "route %s: %d requests (", rc.Route, rc.Requests)
		srcs := make([]string, 0, len(rc.BySource))
		for k, v := range rc.BySource {
			srcs = append(srcs, fmt.Sprintf("%s %d", k, v))
		}
		sort.Strings(srcs)
		fmt.Fprintf(w, "%s), learning %s", strings.Join(srcs, ", "), learning)
		if rc.LearningSince != "" {
			fmt.Fprintf(w, " since %s", rc.LearningSince)
		}
		fmt.Fprintln(w)
		if len(rc.Endpoints) == 0 {
			fmt.Fprintln(w, "  no corpus coverage: rules on this route may not block")
			continue
		}
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "  METHOD\tPATH\tREQS\tSTATUS\tPARAMS")
		for _, e := range rc.Endpoints {
			st := make([]string, 0, len(e.Statuses))
			for k, v := range e.Statuses {
				st = append(st, fmt.Sprintf("%s:%d", k, v))
			}
			sort.Strings(st)
			params := strings.Join(e.Params, " ")
			if len(params) > 80 {
				params = params[:77] + "..."
			}
			fmt.Fprintf(tw, "  %s\t%s\t%d\t%s\t%s\n", e.Method, e.Path, e.Requests, strings.Join(st, " "), params)
		}
		tw.Flush()
	}
}
