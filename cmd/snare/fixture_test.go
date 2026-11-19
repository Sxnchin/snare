package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sxnchin/snare/internal/artex"
)

// fakeArtex serves the documents exportTask reads.
func fakeArtex(t *testing.T, leak string) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/auth/login", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"token":"t"}`))
	})
	mux.HandleFunc("GET /api/tasks/7", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"id":"7","name":"x"}`)) })
	mux.HandleFunc("GET /api/tasks/7/outcome", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"task_id":7,"tokens":{"input_tokens":10,"output_tokens":2}}`))
	})
	mux.HandleFunc("GET /api/exploration/findings", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("task") != "7" {
			http.Error(w, "bad task filter", 400)
			return
		}
		_, _ = w.Write([]byte(`[{"id":"40","finding_id":"12"},{"id":"9","finding_id":"3"}]`))
	})
	mux.HandleFunc("GET /api/exploration/findings/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		_, _ = w.Write([]byte(`{"id":"` + id + `","vulnclass":"sqli","traffic_bindings":[{"traffic_id":"t-` + id + `","role":"proof"}]}`))
	})
	mux.HandleFunc("GET /api/exploration/findings/{id}/lineage", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"nodes":[]}`))
	})
	mux.HandleFunc("GET /api/traffic/exchange", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"req":"GET /?q=` + leak + ` HTTP/1.1","resp":"HTTP 200"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestFixtureExport(t *testing.T) {
	srv := fakeArtex(t, "x")
	c := artex.New(srv.URL, "ARTEX", func() (string, error) { return "pw-0123456789", nil }, 5*time.Second)
	files, err := exportTask(t.Context(), c, 7)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"task.json", "outcome.json", "findings.json", "evidence/3.json", "evidence/12.json"} {
		if _, ok := files[want]; !ok {
			t.Fatalf("missing %s; have %v", want, keys(files))
		}
	}
	var fs []struct {
		Finding struct {
			ID string `json:"id"`
		} `json:"finding"`
	}
	if err := json.Unmarshal(files["findings.json"], &fs); err != nil || len(fs) != 2 || fs[0].Finding.ID != "3" {
		t.Fatalf("findings not in numeric order: %s", files["findings.json"])
	}
	dir := filepath.Join(t.TempDir(), "v1")
	if err := writeFixture(dir, files, nil); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "evidence", "12.json"))
	if !strings.Contains(string(b), "\n  \"finding_id\": \"12\"") {
		t.Fatalf("not pretty-printed: %s", b)
	}
	if err := writeFixture(dir, files, nil); err == nil {
		t.Fatal("an existing fixture directory must not be overwritten")
	}
}

func TestFixtureExportRefusesSecrets(t *testing.T) {
	const secret = "fixture-test-secret-obviously-fake" // gitleaks:allow (test value)
	srv := fakeArtex(t, secret)
	c := artex.New(srv.URL, "ARTEX", func() (string, error) { return "pw-0123456789", nil }, 5*time.Second)
	files, err := exportTask(t.Context(), c, 7)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "v1")
	if err := writeFixture(dir, files, []string{secret}); err == nil || !strings.Contains(err.Error(), "forbidden secret") {
		t.Fatalf("want refusal, got %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("nothing may be written when a secret is found")
	}
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestMatchEvidence(t *testing.T) {
	files := map[string][]byte{
		"findings.json": []byte(`[{"finding":{"id":"7","name":"SQLi in login","summary":"",` +
			`"evidence":"POST http://snare:8000/rest/user/login body: {\"email\":\"' OR 1=1--\"} -> 200; then GET /rest/basket/1."}}]`),
		"evidence/7.json": []byte(`{"finding_id":"7","artex_bound":[]}`),
	}
	lines := []captureLine{
		{Method: "GET", Path: "/rest/products/search"},
		{Method: "POST", Path: "/rest/user/login", Status: 200},
		{Method: "GET", Path: "/rest/basket/1", Status: 200},
		{Method: "GET", Path: "/rest/user/login"}, // same path, other method: not a match
	}
	if err := matchEvidence(files, lines); err != nil {
		t.Fatal(err)
	}
	var ev evidenceDoc
	if err := json.Unmarshal(files["evidence/7.json"], &ev); err != nil {
		t.Fatal(err)
	}
	if len(ev.SnareMatched) != 2 || ev.SnareMatched[0].Line != 2 || ev.SnareMatched[1].Line != 3 || ev.MatchRule == "" {
		t.Fatalf("matches %+v", ev.SnareMatched)
	}
}
