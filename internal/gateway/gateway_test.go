package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/snare-dev/snare/internal/config"
	"github.com/snare-dev/snare/internal/recorder"
	"github.com/snare-dev/snare/internal/store"
)

func limits() config.Limits {
	l := config.Default().Gateway.Limits
	l.MaxRequestBodyBytes = 1024
	l.MaxConcurrent = 8
	l.MaxPerSource = 2
	return l
}

// upstream echoes method, path, query, a header and the body length.
func upstream(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Upstream", "yes")
		w.Header().Set("X-Seen-Xff", r.Header.Get("X-Forwarded-For"))
		w.WriteHeader(201)
		_, _ = io.WriteString(w, `{"method":"`+r.Method+`","path":"`+r.URL.Path+`","q":"`+r.URL.RawQuery+`","n":`+strconv.Itoa(len(b))+`,"email":"bob@example.org"}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newRec(t *testing.T, period time.Duration) (*recorder.Recorder, context.CancelFunc) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(context.Background(), filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	sealer, err := recorder.LoadSealer(context.Background(), st, "", filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	rec := recorder.New(st, sealer, recorder.NewRedactor(nil, nil),
		recorder.Options{LearningPeriod: period, MaxBodyBytes: 4096, QueueSize: 64})
	ctx, cancel := context.WithCancel(context.Background())
	go rec.Run(ctx)
	return rec, func() { cancel(); rec.Wait() }
}

func TestRoutingAndPassThrough(t *testing.T) {
	a, b := upstream(t), upstream(t)
	g, err := New(Options{Limits: limits(), Routes: []config.Route{
		{Name: "any", PathPrefix: "/", Upstream: a.URL, Mode: config.ModeDetect},
		{Name: "api", PathPrefix: "/api", Upstream: b.URL, Mode: config.ModeDetect},
		{Name: "admin", Host: "admin.lab", PathPrefix: "/", Upstream: b.URL, Mode: config.ModeDetect},
	}})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ host, path, want string }{
		{"shop.lab", "/api/Products?x=1", b.URL},
		{"shop.lab", "/apix", a.URL},
		{"shop.lab", "/", a.URL},
		{"ADMIN.lab:8000", "/anything", b.URL},
	}
	for _, c := range cases {
		req := httptest.NewRequest("POST", c.path, strings.NewReader("hello"))
		req.Host = c.host
		rt := g.match(req)
		if rt == nil || rt.cfg.Upstream != c.want {
			t.Errorf("%s%s routed to %v", c.host, c.path, rt)
		}
	}
	req := httptest.NewRequest("POST", "/api/Products?x=1", strings.NewReader("hello"))
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, req)
	if rec.Code != 201 || rec.Header().Get("X-Upstream") != "yes" {
		t.Fatalf("pass-through: %d %v", rec.Code, rec.Header())
	}
	if body := rec.Body.String(); !strings.Contains(body, `"path":"/api/Products"`) || !strings.Contains(body, `"q":"x=1"`) || !strings.Contains(body, `"n":5`) {
		t.Fatalf("body: %s", body)
	}
	if rec.Header().Get("X-Seen-Xff") != "192.0.2.1" {
		t.Fatalf("X-Forwarded-For upstream = %q", rec.Header().Get("X-Seen-Xff"))
	}
	for _, h := range []string{"Via", "Server"} {
		if rec.Header().Get(h) != "" {
			t.Errorf("gateway added identifying header %s", h)
		}
	}
}

func TestNoRoute(t *testing.T) {
	g, _ := New(Options{Limits: limits(), Routes: []config.Route{
		{Name: "api", PathPrefix: "/api", Upstream: "http://127.0.0.1:1", Mode: config.ModeRecord},
	}})
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, httptest.NewRequest("GET", "/other", nil))
	if rec.Code != 404 || g.Stats().NoRoute != 1 {
		t.Fatalf("got %d, stats %+v", rec.Code, g.Stats())
	}
}

func TestRecordMode(t *testing.T) {
	up := upstream(t)
	rec, stop := newRec(t, time.Hour)
	g, _ := New(Options{Limits: limits(), Recorder: rec, Routes: []config.Route{
		{Name: "shop", PathPrefix: "/", Upstream: up.URL, Mode: config.ModeRecord},
		{Name: "detect", PathPrefix: "/d", Upstream: up.URL, Mode: config.ModeDetect},
	}})
	req := httptest.NewRequest("POST", "/rest/user/login?next=1", strings.NewReader(`{"email":"bob@example.org","password":"Pw-12345"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer secret-token-value")
	g.ServeHTTP(httptest.NewRecorder(), req)
	g.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/d/x", nil)) // detect mode: not recorded
	stop()

	ids, _ := rec.IDs(context.Background(), "shop")
	if len(ids) != 1 {
		t.Fatalf("recorded %d exchanges, want 1", len(ids))
	}
	if others, _ := rec.IDs(context.Background(), "detect"); len(others) != 0 {
		t.Fatal("detect-mode route was recorded")
	}
	r, err := rec.Read(context.Background(), ids[0])
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != 201 || r.Path != "/rest/user/login" || r.ReqBodyBytes == 0 {
		t.Fatalf("record: %+v", r)
	}
	all := r.ReqBody + r.RespBody + strings.Join(r.ReqHeaders["Authorization"], "")
	for _, s := range []string{"bob@example.org", "Pw-12345", "secret-token-value"} {
		if strings.Contains(all, s) {
			t.Errorf("stored record contains %q", s)
		}
	}
}

func TestLearningExpiredStopsRecording(t *testing.T) {
	up := upstream(t)
	rec, stop := newRec(t, time.Nanosecond)
	g, _ := New(Options{Limits: limits(), Recorder: rec, Routes: []config.Route{
		{Name: "shop", PathPrefix: "/", Upstream: up.URL, Mode: config.ModeRecord},
	}})
	if err := rec.Store(context.Background(), recorder.Exchange{Route: "shop", Source: recorder.SourceLive, Method: "GET", Path: "/", Status: 200,
		ReqHeader: http.Header{}, RespHeader: http.Header{}, Time: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	g.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/x", nil))
	stop()
	if ids, _ := rec.IDs(context.Background(), "shop"); len(ids) != 1 {
		t.Fatalf("recorded after learning ended: %d", len(ids))
	}
}

type flagAll struct{}

func (flagAll) AgentLike(string) bool { return true }

func TestFlaggedSourcesExcluded(t *testing.T) {
	up := upstream(t)
	rec, stop := newRec(t, time.Hour)
	g, _ := New(Options{Limits: limits(), Recorder: rec, Flagger: flagAll{}, Routes: []config.Route{
		{Name: "shop", PathPrefix: "/", Upstream: up.URL, Mode: config.ModeRecord},
	}})
	w := httptest.NewRecorder()
	g.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	stop()
	if w.Code != 201 {
		t.Fatalf("flagged traffic must still be served (detection is not blocking): %d", w.Code)
	}
	if ids, _ := rec.IDs(context.Background(), "shop"); len(ids) != 0 || g.Stats().ExcludedFlagged != 1 {
		t.Fatalf("agent-like traffic entered the corpus")
	}
}

func TestBodyCap(t *testing.T) {
	up := upstream(t)
	rec, stop := newRec(t, time.Hour)
	g, _ := New(Options{Limits: limits(), Recorder: rec, Routes: []config.Route{
		{Name: "shop", PathPrefix: "/", Upstream: up.URL, Mode: config.ModeRecord},
	}})
	big := strings.Repeat("a", 2048)
	w := httptest.NewRecorder()
	g.ServeHTTP(w, httptest.NewRequest("POST", "/", strings.NewReader(big)))
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("declared length over cap: %d", w.Code)
	}
	// Chunked (unknown length): the cap trips while streaming.
	req := httptest.NewRequest("POST", "/", io.MultiReader(strings.NewReader(big)))
	req.ContentLength = -1
	w = httptest.NewRecorder()
	g.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("streamed body over cap: %d", w.Code)
	}
	stop()
	if ids, _ := rec.IDs(context.Background(), "shop"); len(ids) != 0 {
		t.Fatal("rejected requests must not enter the corpus")
	}
}

// blockingUpstream holds every request until release is called. Cleanup
// always releases, so a failed assertion cannot leave handlers blocked.
func blockingUpstream(t *testing.T) (*httptest.Server, func(), *sync.WaitGroup) {
	ch := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(ch) }) }
	var inflight sync.WaitGroup
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		inflight.Done()
		<-ch
	}))
	t.Cleanup(func() { release(); srv.Close() })
	return srv, release, &inflight
}

func TestPerSourceAndGlobalCaps(t *testing.T) {
	up, release, inflight := blockingUpstream(t)
	l := limits() // per source 2
	l.MaxConcurrent = 4
	g, _ := New(Options{Limits: l, Routes: []config.Route{{Name: "shop", PathPrefix: "/", Upstream: up.URL, Mode: config.ModeDetect}}})
	send := func(src string) <-chan int {
		ch := make(chan int, 1)
		go func() {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = src + ":1234"
			w := httptest.NewRecorder()
			g.ServeHTTP(w, req)
			ch <- w.Code
		}()
		return ch
	}
	inflight.Add(3)
	held := []<-chan int{send("10.0.0.1"), send("10.0.0.1"), send("10.0.0.2")}
	inflight.Wait() // three requests are inside the upstream

	if code := <-send("10.0.0.1"); code != http.StatusTooManyRequests {
		t.Fatalf("third concurrent request from one source: %d, want 429", code)
	}
	inflight.Add(1)
	held = append(held, send("10.0.0.3"))
	inflight.Wait() // the global cap of 4 is now full
	if code := <-send("10.0.0.4"); code != http.StatusServiceUnavailable {
		t.Fatalf("request over the global cap: %d, want 503", code)
	}
	release()
	for _, ch := range held {
		if code := <-ch; code != 200 {
			t.Fatalf("held request: %d", code)
		}
	}
	if s := g.Stats(); s.PerSourceLimit != 1 || s.Overloaded != 1 {
		t.Fatalf("stats %+v", s)
	}
	g.mu.Lock()
	left := len(g.perSource)
	g.mu.Unlock()
	if left != 0 {
		t.Fatalf("per-source counters leaked: %d", left)
	}
}

func TestSourceOfTrustedProxies(t *testing.T) {
	g, _ := New(Options{Limits: limits(), TrustedProxies: []string{"10.0.0.0/8"}})
	cases := []struct{ remote, xff, want string }{
		{"203.0.113.9:5", "1.2.3.4", "203.0.113.9"},                       // untrusted peer: header ignored
		{"10.1.1.1:5", "198.51.100.7", "198.51.100.7"},                    // trusted peer
		{"10.1.1.1:5", "6.6.6.6, 198.51.100.7, 10.2.2.2", "198.51.100.7"}, // right-most untrusted
		{"10.1.1.1:5", "garbage", "10.1.1.1"},                             // malformed chain
		{"10.1.1.1:5", "", "10.1.1.1"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := g.SourceOf(r); got != c.want {
			t.Errorf("remote %s xff %q: got %s want %s", c.remote, c.xff, got, c.want)
		}
	}
}

func TestUpstreamDown(t *testing.T) {
	g, _ := New(Options{Limits: limits(), Routes: []config.Route{{Name: "x", PathPrefix: "/", Upstream: "http://127.0.0.1:1", Mode: config.ModeRecord}}})
	w := httptest.NewRecorder()
	g.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusBadGateway || g.Stats().UpstreamErrors != 1 {
		t.Fatalf("got %d", w.Code)
	}
}
