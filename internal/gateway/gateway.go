// Package gateway is Snare's reverse proxy in front of protected apps.
//
// Per request it: identifies the source, applies the global and per-source
// concurrency caps, matches a route, enforces the body cap, proxies to the
// route's upstream, and, for routes in record mode inside their learning
// period, hands a copy of the exchange to the recorder without blocking.
//
// Rules (Coraza) attach here in M4; detect and enforce modes are pass-through
// until then.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/snare-dev/snare/internal/config"
	"github.com/snare-dev/snare/internal/recorder"
)

// Flagger reports sources the detector considers agent-like. Their traffic is
// kept out of the benign corpus. The detector arrives in M2; nil means none.
type Flagger interface {
	AgentLike(source string) bool
}

// Stats are gateway counters since start.
type Stats struct {
	Requests        int64 `json:"requests"`
	Recorded        int64 `json:"recorded"`
	NoRoute         int64 `json:"no_route"`
	Overloaded      int64 `json:"rejected_overloaded"`
	PerSourceLimit  int64 `json:"rejected_per_source"`
	BodyTooLarge    int64 `json:"rejected_body_too_large"`
	UpstreamErrors  int64 `json:"upstream_errors"`
	ExcludedFlagged int64 `json:"excluded_agent_like"`
}

type route struct {
	cfg      config.Route
	host     string // lower-cased, no port; "" matches any
	upstream *url.URL
	proxy    *httputil.ReverseProxy
}

// Gateway is an http.Handler.
type Gateway struct {
	routes  []*route
	rec     *recorder.Recorder
	flagger Flagger
	limits  config.Limits
	trusted []*net.IPNet
	log     *slog.Logger

	sem chan struct{}

	mu        sync.Mutex
	perSource map[string]int

	requests, recorded, noRoute, overloaded, perSourceLimit,
	tooLarge, upstreamErrors, excluded atomic.Int64
}

// Options configures New.
type Options struct {
	Routes         []config.Route
	Limits         config.Limits
	TrustedProxies []string
	Recorder       *recorder.Recorder // nil disables recording
	Flagger        Flagger
	Log            *slog.Logger
	// Transport overrides the upstream transport (tests).
	Transport http.RoundTripper
}

// New builds a gateway. Routes are matched by exact host (any host when the
// route has none), then longest path prefix.
func New(opt Options) (*Gateway, error) {
	g := &Gateway{
		rec:       opt.Recorder,
		flagger:   opt.Flagger,
		limits:    opt.Limits,
		log:       opt.Log,
		sem:       make(chan struct{}, opt.Limits.MaxConcurrent),
		perSource: map[string]int{},
	}
	if g.log == nil {
		g.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	for _, c := range opt.TrustedProxies {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q: %w", c, err)
		}
		g.trusted = append(g.trusted, n)
	}
	transport := opt.Transport
	if transport == nil {
		transport = &http.Transport{
			Proxy:                 nil, // never use HTTP_PROXY from the environment
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			MaxIdleConns:          512,
			MaxIdleConnsPerHost:   256,
			IdleConnTimeout:       90 * time.Second,
			ResponseHeaderTimeout: opt.Limits.UpstreamTimeout.D(),
			// Pass the client's Accept-Encoding through unchanged; do not
			// let the transport add gzip and decode on its own.
			DisableCompression: true,
		}
	}
	for _, rc := range opt.Routes {
		u, err := url.Parse(rc.Upstream)
		if err != nil {
			return nil, fmt.Errorf("route %s: %w", rc.Name, err)
		}
		rt := &route{cfg: rc, host: strings.ToLower(rc.Host), upstream: u}
		rt.proxy = &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(u)
				pr.SetXForwarded()
			},
			Transport:    transport,
			ErrorHandler: g.proxyError,
			// No identifying headers are added to responses: a Via or
			// Server header would tell an agent Snare is in the path.
		}
		g.routes = append(g.routes, rt)
	}
	sort.SliceStable(g.routes, func(i, j int) bool {
		a, b := g.routes[i], g.routes[j]
		if (a.host != "") != (b.host != "") {
			return a.host != "" // host-specific routes first
		}
		return len(a.cfg.PathPrefix) > len(b.cfg.PathPrefix)
	})
	return g, nil
}

// Stats returns a snapshot of the counters.
func (g *Gateway) Stats() Stats {
	return Stats{
		Requests: g.requests.Load(), Recorded: g.recorded.Load(), NoRoute: g.noRoute.Load(),
		Overloaded: g.overloaded.Load(), PerSourceLimit: g.perSourceLimit.Load(),
		BodyTooLarge: g.tooLarge.Load(), UpstreamErrors: g.upstreamErrors.Load(),
		ExcludedFlagged: g.excluded.Load(),
	}
}

func (g *Gateway) match(r *http.Request) *route {
	host := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	for _, rt := range g.routes {
		if rt.host != "" && rt.host != host {
			continue
		}
		if prefixMatch(r.URL.Path, rt.cfg.PathPrefix) {
			return rt
		}
	}
	return nil
}

// prefixMatch matches on path segment boundaries: /api matches /api and
// /api/x but not /apix.
func prefixMatch(path, prefix string) bool {
	if prefix == "/" || path == prefix {
		return true
	}
	p := strings.TrimSuffix(prefix, "/")
	return strings.HasPrefix(path, p) && (len(path) == len(p) || path[len(p)] == '/')
}

// SourceOf returns the client address. X-Forwarded-For is used only when the
// direct peer is a trusted proxy; then the right-most address that is not a
// trusted proxy is the client.
func (g *Gateway) SourceOf(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if !g.isTrusted(host) {
		return host
	}
	parts := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(parts[i])
		if net.ParseIP(ip) == nil {
			break // malformed: stop trusting the chain
		}
		if !g.isTrusted(ip) {
			return ip
		}
	}
	return host
}

func (g *Gateway) isTrusted(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range g.trusted {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

func (g *Gateway) acquireSource(src string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.perSource[src] >= g.limits.MaxPerSource {
		return false
	}
	g.perSource[src]++
	return true
}

func (g *Gateway) releaseSource(src string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.perSource[src]--; g.perSource[src] <= 0 {
		delete(g.perSource, src)
	}
}

type ctxKey struct{}

// reqState travels with the request so the error handler can report why the
// proxy failed.
type reqState struct{ tooLarge bool }

func (g *Gateway) proxyError(w http.ResponseWriter, r *http.Request, err error) {
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		if st, ok := r.Context().Value(ctxKey{}).(*reqState); ok {
			st.tooLarge = true
		}
		g.tooLarge.Add(1)
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	if errors.Is(err, context.Canceled) {
		// The client went away; nothing useful to send.
		w.WriteHeader(499)
		return
	}
	g.upstreamErrors.Add(1)
	g.log.Warn("upstream error", "path", r.URL.Path, "err", err)
	http.Error(w, "bad gateway", http.StatusBadGateway)
}

// ServeHTTP implements http.Handler.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.requests.Add(1)
	select {
	case g.sem <- struct{}{}:
		defer func() { <-g.sem }()
	default:
		g.overloaded.Add(1)
		w.Header().Set("Retry-After", "1")
		http.Error(w, "service overloaded", http.StatusServiceUnavailable)
		return
	}
	src := g.SourceOf(r)
	if !g.acquireSource(src) {
		g.perSourceLimit.Add(1)
		w.Header().Set("Retry-After", "1")
		http.Error(w, "too many concurrent requests", http.StatusTooManyRequests)
		return
	}
	defer g.releaseSource(src)

	rt := g.match(r)
	if rt == nil {
		g.noRoute.Add(1)
		http.NotFound(w, r)
		return
	}
	maxBody := g.limits.MaxRequestBodyBytes
	if r.ContentLength > maxBody {
		g.tooLarge.Add(1)
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)

	record := g.shouldRecord(r.Context(), rt, src)
	if !record {
		rt.proxy.ServeHTTP(w, r)
		return
	}

	st := &reqState{}
	r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, st))
	capN := g.rec.MaxBodyBytes()
	reqHeader := r.Header.Clone()
	tee := &teeBody{c: capture{limit: capN}}
	if r.Body != nil && r.Body != http.NoBody {
		tee.ReadCloser = r.Body
		r.Body = tee
	}
	cw := &captureWriter{ResponseWriter: w, body: capture{limit: capN}}
	start := time.Now()
	rt.proxy.ServeHTTP(cw, r)
	if st.tooLarge || cw.status == 0 || cw.status == 499 {
		return // rejected or aborted exchanges are not benign samples
	}
	reqBody, reqTotal := tee.snapshot()
	if g.rec.Submit(recorder.Exchange{
		Route:         rt.cfg.Name,
		Source:        recorder.SourceLive,
		Time:          start,
		Duration:      time.Since(start),
		Method:        r.Method,
		Host:          r.Host,
		Path:          r.URL.EscapedPath(),
		RawQuery:      r.URL.RawQuery,
		ReqHeader:     reqHeader,
		ReqBody:       reqBody,
		ReqBodyBytes:  reqTotal,
		Status:        cw.status,
		RespHeader:    cw.header,
		RespBody:      cw.body.buf,
		RespBodyBytes: cw.body.total,
	}) {
		g.recorded.Add(1)
	}
}

func (g *Gateway) shouldRecord(ctx context.Context, rt *route, src string) bool {
	if g.rec == nil || rt.cfg.Mode != config.ModeRecord {
		return false
	}
	if g.flagger != nil && g.flagger.AgentLike(src) {
		g.excluded.Add(1)
		return false
	}
	return g.rec.Learning(ctx, rt.cfg.Name)
}

// capture keeps the first limit bytes written and counts the total.
type capture struct {
	limit int
	buf   []byte
	total int64
}

func (c *capture) add(p []byte) {
	c.total += int64(len(p))
	if room := c.limit - len(c.buf); room > 0 {
		if len(p) > room {
			p = p[:room]
		}
		c.buf = append(c.buf, p...)
	}
}

// teeBody captures the request body as the upstream transport reads it.
// The transport may still be reading in its own goroutine after the proxy
// returns, so access is locked and the gateway takes a copy.
type teeBody struct {
	io.ReadCloser
	mu sync.Mutex
	c  capture
}

func (t *teeBody) Read(p []byte) (int, error) {
	n, err := t.ReadCloser.Read(p)
	t.mu.Lock()
	t.c.add(p[:n])
	t.mu.Unlock()
	return n, err
}

func (t *teeBody) snapshot() ([]byte, int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]byte(nil), t.c.buf...), t.c.total
}

// captureWriter records status, headers and the start of the body while
// passing everything through.
type captureWriter struct {
	http.ResponseWriter
	status int
	header http.Header
	body   capture
}

func (c *captureWriter) WriteHeader(code int) {
	if c.status == 0 {
		c.status = code
		c.header = c.ResponseWriter.Header().Clone()
	}
	c.ResponseWriter.WriteHeader(code)
}

func (c *captureWriter) Write(p []byte) (int, error) {
	if c.status == 0 {
		c.WriteHeader(http.StatusOK)
	}
	c.body.add(p)
	return c.ResponseWriter.Write(p)
}

// Unwrap lets http.ResponseController reach the underlying writer (flush,
// deadlines, hijack).
func (c *captureWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

// Flush supports streaming responses.
func (c *captureWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Server returns an http.Server for the gateway with the configured limits.
func Server(addr string, h http.Handler, l config.Limits) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       l.ReadTimeout.D(),
		WriteTimeout:      l.WriteTimeout.D(),
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    l.MaxHeaderBytes,
	}
}
