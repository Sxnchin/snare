package gateway

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DefaultScannerAgents are User-Agent substrings of common scanners and
// fuzzers, matched case-insensitively. Requests carrying them are proxied
// as usual but never recorded into the benign corpus. Tools can change their
// User-Agent, so this is a second line; ExcludeSources is the main control.
// Entries are specific enough not to match ordinary HTTP client libraries.
var DefaultScannerAgents = []string{
	"sqlmap/",
	"nuclei",
	"fuzz faster u fool", // ffuf
	"nikto",
	"gobuster/",
	"feroxbuster/",
	"wfuzz/",
	"nmap scripting engine",
	"masscan/",
	"zgrab/",
	"dirbuster",
	"wpscan",
	"commix",
	"acunetix",
	"netsparker",
	"openvas",
	"burpcollaborator",
}

// Exclusion reasons reported by Exclusions.Match.
const (
	ExcludeNone       = ""
	ExcludeSource     = "source"     // client is in exclude_sources
	ExcludeAgent      = "user_agent" // User-Agent matches the scanner list
	ExcludeUnresolved = "unresolved" // an exclude_sources hostname has no current address
)

// Exclusions decides which requests must stay out of the benign corpus.
// Hostnames are resolved by Run; until every hostname has resolved at least
// once, and whenever one stops resolving, nothing is recorded (fail closed),
// because an unresolved scanner hostname means its traffic cannot be told
// apart from legitimate traffic.
type Exclusions struct {
	nets   []*net.IPNet
	ips    map[string]bool // literal IPs from config, normalized
	hosts  []string
	agents []string // lower case
	lookup func(ctx context.Context, host string) ([]net.IPAddr, error)
	log    *slog.Logger

	mu         sync.RWMutex
	resolved   map[string]bool // addresses of hosts
	unresolved int             // hosts with no current address
	warned     bool            // a "recording paused" warning is outstanding (Refresh only)
}

// NewExclusions builds the exclusion set. sources are IPs, CIDRs or
// hostnames (validated by config). agents are added to DefaultScannerAgents.
func NewExclusions(sources, agents []string, log *slog.Logger) *Exclusions {
	e := &Exclusions{
		ips:      map[string]bool{},
		resolved: map[string]bool{},
		lookup:   net.DefaultResolver.LookupIPAddr,
		log:      log,
	}
	if e.log == nil {
		e.log = slog.New(slog.DiscardHandler)
	}
	for _, s := range sources {
		if ip := net.ParseIP(s); ip != nil {
			e.ips[ip.String()] = true
		} else if _, n, err := net.ParseCIDR(s); err == nil {
			e.nets = append(e.nets, n)
		} else {
			e.hosts = append(e.hosts, strings.ToLower(s))
		}
	}
	e.unresolved = len(e.hosts)
	for _, a := range append(append([]string{}, DefaultScannerAgents...), agents...) {
		e.agents = append(e.agents, strings.ToLower(a))
	}
	return e
}

// Refresh resolves the configured hostnames once.
func (e *Exclusions) Refresh(ctx context.Context) {
	if e == nil || len(e.hosts) == 0 {
		return
	}
	next := map[string]bool{}
	missing := 0
	for _, h := range e.hosts {
		lctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		addrs, err := e.lookup(lctx, h)
		cancel()
		if err != nil || len(addrs) == 0 {
			missing++
			continue
		}
		for _, a := range addrs {
			next[a.IP.String()] = true
		}
	}
	e.mu.Lock()
	e.resolved, e.unresolved = next, missing
	e.mu.Unlock()
	// Log state changes only; Run calls this every few seconds.
	switch {
	case missing > 0 && !e.warned:
		e.warned = true
		e.log.Warn("recording paused: cannot resolve an excluded source", "unresolved", missing, "hosts", e.hosts)
	case missing == 0 && e.warned:
		e.warned = false
		e.log.Info("recording resumed: every excluded source resolves")
	}
}

// Run refreshes hostnames every interval until ctx ends.
func (e *Exclusions) Run(ctx context.Context, interval time.Duration) {
	if e == nil || len(e.hosts) == 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.Refresh(ctx)
		}
	}
}

// Match reports why a request from src must not be recorded, or
// ExcludeNone.
func (e *Exclusions) Match(src string, r *http.Request) string {
	if e == nil {
		return ExcludeNone
	}
	ua := strings.ToLower(r.Header.Get("User-Agent"))
	for _, a := range e.agents {
		if ua != "" && strings.Contains(ua, a) {
			return ExcludeAgent
		}
	}
	ip := net.ParseIP(src)
	if ip != nil {
		if e.ips[ip.String()] {
			return ExcludeSource
		}
		for _, n := range e.nets {
			if n.Contains(ip) {
				return ExcludeSource
			}
		}
	}
	if len(e.hosts) == 0 {
		return ExcludeNone
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.unresolved > 0 {
		return ExcludeUnresolved
	}
	if ip != nil && e.resolved[ip.String()] {
		return ExcludeSource
	}
	return ExcludeNone
}
