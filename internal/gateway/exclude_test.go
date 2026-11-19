package gateway

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Sxnchin/snare/internal/config"
)

type fakeDNS struct {
	mu sync.Mutex
	m  map[string][]string
}

func (f *fakeDNS) set(host string, ips ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[host] = ips
}

func (f *fakeDNS) lookup(_ context.Context, host string) ([]net.IPAddr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ips := f.m[host]
	if len(ips) == 0 {
		return nil, errors.New("no such host")
	}
	var out []net.IPAddr
	for _, s := range ips {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out, nil
}

func withDNS(e *Exclusions) *fakeDNS {
	f := &fakeDNS{m: map[string][]string{}}
	e.lookup = f.lookup
	return f
}

func TestExclusionsMatch(t *testing.T) {
	e := NewExclusions([]string{"10.9.0.7", "192.168.50.0/24", "artex"}, []string{"InternalCrawler"}, nil)
	dns := withDNS(e)
	r := httptest.NewRequest("GET", "/", nil)

	// Before the hostname resolves, nothing is recorded.
	if got := e.Match("172.20.0.9", r, false); got != ExcludeUnresolved {
		t.Fatalf("unresolved host must fail closed, got %q", got)
	}
	dns.set("artex", "172.20.0.5")
	e.Refresh(context.Background())

	cases := []struct {
		src, ua, want string
	}{
		{"172.20.0.9", "Mozilla/5.0 (X11; Linux x86_64) Chrome/159.0", ExcludeNone},
		{"172.20.0.5", "Mozilla/5.0", ExcludeSource}, // resolved hostname
		{"10.9.0.7", "", ExcludeSource},              // literal IP
		{"192.168.50.33", "", ExcludeSource},         // CIDR
		{"172.20.0.9", "sqlmap/1.8.2#stable (https://sqlmap.org)", ExcludeAgent},
		{"172.20.0.9", "Fuzz Faster U Fool v2.1.0", ExcludeAgent},
		{"172.20.0.9", "Mozilla/5.0 (compatible; Nmap Scripting Engine)", ExcludeAgent},
		{"172.20.0.9", "internalcrawler/2", ExcludeAgent},  // configured, case-insensitive
		{"172.20.0.9", "python-httpx/0.27.0", ExcludeNone}, // ordinary client libraries stay
		{"172.20.0.9", "Go-http-client/1.1", ExcludeNone},
		{"172.20.0.9", "curl/8.10.1", ExcludeNone},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		if c.ua != "" {
			r.Header.Set("User-Agent", c.ua)
		}
		if got := e.Match(c.src, r, false); got != c.want {
			t.Errorf("Match(%s, %q) = %q, want %q", c.src, c.ua, got, c.want)
		}
	}

	// The scanner container restarts with a new address.
	dns.set("artex", "172.20.0.6")
	e.Refresh(context.Background())
	if e.Match("172.20.0.6", r, false) != ExcludeSource || e.Match("172.20.0.5", r, false) != ExcludeNone {
		t.Fatal("refresh did not follow the new address")
	}
	// It disappears from DNS: recording pauses rather than guessing.
	dns.set("artex")
	e.Refresh(context.Background())
	if got := e.Match("172.20.0.9", r, false); got != ExcludeUnresolved {
		t.Fatalf("lost hostname must fail closed, got %q", got)
	}
}

func TestExclusionsNil(t *testing.T) {
	var e *Exclusions
	if e.Match("1.2.3.4", httptest.NewRequest("GET", "/", nil), false) != ExcludeNone {
		t.Fatal("nil exclusions must exclude nothing")
	}
	e.Refresh(context.Background())
}

func TestScannerTrafficNotRecorded(t *testing.T) {
	up := upstream(t)
	rec, stop := newRec(t, time.Hour)
	ex := NewExclusions([]string{"artex"}, nil, nil)
	withDNS(ex).set("artex", "192.0.2.10")
	ex.Refresh(context.Background())
	g, _ := New(Options{Limits: limits(), Recorder: rec, Exclusions: ex, Routes: []config.Route{
		{Name: "shop", PathPrefix: "/", Upstream: up.URL, Mode: config.ModeRecord},
	}})
	send := func(remote, ua string) int {
		r := httptest.NewRequest("GET", "/rest/products/search?q=x", nil)
		r.RemoteAddr = remote
		if ua != "" {
			r.Header.Set("User-Agent", ua)
		}
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		return w.Code
	}
	codes := []int{
		send("192.0.2.10:40000", "Mozilla/5.0"),                       // the scanner's address
		send("198.51.100.4:40000", "sqlmap/1.8 (https://sqlmap.org)"), // a scanner User-Agent
		send("198.51.100.5:40000", "Mozilla/5.0 Chrome/159.0"),        // a browser
	}
	stop()
	for i, c := range codes {
		if c != 201 {
			t.Fatalf("request %d: excluded traffic must still be served, got %d", i, c)
		}
	}
	ids, _ := rec.IDs(context.Background(), "shop")
	st := g.Stats()
	if len(ids) != 1 || st.ExcludedSource != 1 || st.ExcludedAgent != 1 || st.Recorded != 1 {
		t.Fatalf("want only the browser request recorded; ids=%v stats=%+v", ids, st)
	}
}

func TestScannerHeaderIdentity(t *testing.T) {
	const secret = "lab-scanner-secret-obviously-fake" // gitleaks:allow (test value)
	var seen []string
	var mu sync.Mutex
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("X-Snare-Scanner"))
		mu.Unlock()
		w.WriteHeader(200)
	}))
	t.Cleanup(up.Close)
	rec, stop := newRec(t, time.Hour)
	ex := NewExclusions(nil, nil, nil)
	ex.SetScannerHeader("x-snare-scanner", secret)
	g, _ := New(Options{Limits: limits(), Recorder: rec, Exclusions: ex, Routes: []config.Route{
		{Name: "shop", PathPrefix: "/", Upstream: up.URL, Mode: config.ModeRecord},
	}})
	send := func(vals ...string) {
		r := httptest.NewRequest("GET", "/rest/products/search?q=x", nil)
		r.Header.Set("User-Agent", "Mozilla/5.0 Chrome/159.0")
		for _, v := range vals {
			r.Header.Add("X-Snare-Scanner", v)
		}
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("status %d", w.Code)
		}
	}
	send(secret)         // the scanner: not recorded
	send("guess")        // wrong value: stripped, treated like any request, recorded
	send(secret, secret) // repeated header is not the scanner: recorded
	send()               // no header: recorded
	stop()

	for i, v := range seen {
		if v != "" {
			t.Fatalf("request %d: upstream saw the scanner header (%q)", i, v)
		}
	}
	st := g.Stats()
	if st.ExcludedHeader != 1 || st.ScannerHeaderMismatch != 2 || st.Recorded != 3 {
		t.Fatalf("stats %+v", st)
	}
	ids, _ := rec.IDs(context.Background(), "shop")
	for _, id := range ids {
		rr, err := rec.Read(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if len(rr.ReqHeaders.Values("X-Snare-Scanner")) != 0 {
			t.Fatalf("record %d stored the scanner header", id)
		}
	}
}
