package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sxnchin/snare/internal/config"
)

func TestScannerCapture(t *testing.T) {
	const secret = "capture-test-secret-obviously-fake" // gitleaks:allow (test value)
	up := upstream(t)
	rec, stop := newRec(t, time.Hour)
	ex := NewExclusions([]string{"192.0.2.10"}, nil, nil)
	ex.SetScannerHeader("X-Snare-Scanner", secret)
	path := filepath.Join(t.TempDir(), "scanner.jsonl")
	capt, err := OpenScannerCapture(CaptureOptions{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	g, _ := New(Options{Limits: limits(), Recorder: rec, Exclusions: ex, Capture: capt, Routes: []config.Route{
		{Name: "shop", PathPrefix: "/", Upstream: up.URL, Mode: config.ModeRecord},
	}})
	send := func(remote, body string, hdr string) {
		r := httptest.NewRequest("POST", "/rest/user/login?x=1", strings.NewReader(body))
		r.RemoteAddr = remote
		r.Header.Set("User-Agent", "Mozilla/5.0")
		if hdr != "" {
			r.Header.Set("X-Snare-Scanner", hdr)
		}
		g.ServeHTTP(httptest.NewRecorder(), r)
	}
	send("198.51.100.7:1000", `{"email":"' OR 1=1--","password":"x"}`, secret) // header, other address
	send("192.0.2.10:1000", `{"email":"admin@juice-sh.op'--"}`, "")            // fixed scanner address
	send("198.51.100.8:1000", `{"email":"shopper@lab.test"}`, "")              // a user: never captured
	send("198.51.100.9:1000", `{"email":"guess@lab.test"}`, "wrong")           // wrong header: a user
	stop()
	if err := capt.Close(); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var got []CapturedExchange
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e CapturedExchange
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		got = append(got, e)
	}
	if len(got) != 2 {
		t.Fatalf("captured %d exchanges, want 2 (the scanner's only)", len(got))
	}
	if got[0].Identified != ExcludeHeader || got[1].Identified != ExcludeSource {
		t.Fatalf("identified as %q, %q", got[0].Identified, got[1].Identified)
	}
	if got[0].ReqBody != `{"email":"' OR 1=1--","password":"x"}` {
		t.Fatalf("payload not kept verbatim: %q", got[0].ReqBody)
	}
	if got[0].Status != 201 || !strings.Contains(got[0].RespBody, `"path":"/rest/user/login"`) || got[0].Time.IsZero() {
		t.Fatalf("response or timing missing: %+v", got[0])
	}
	for _, e := range got {
		if len(e.ReqHeader.Values("X-Snare-Scanner")) != 0 {
			t.Fatal("scanner header written to the capture")
		}
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), secret) || strings.Contains(string(raw), "shopper@lab.test") {
		t.Fatal("capture holds the secret or a user's request")
	}
	if c, d := capt.Stats(); c != 2 || d != 0 {
		t.Fatalf("stats %d captured %d dropped", c, d)
	}
	if ids, _ := rec.IDs(context.Background(), "shop"); len(ids) != 1 {
		t.Fatalf("want only the user's request recorded, got %d", len(ids))
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatalf("capture file mode %v", st.Mode().Perm())
	}
}
