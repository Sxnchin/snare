package ui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snare-dev/snare/internal/store"
)

func newServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return &Server{Store: st, APIToken: "secret-token", Version: "test"}
}

func TestHealthzUnauthenticated(t *testing.T) {
	h := newServer(t).Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 200 {
		t.Fatalf("healthz = %d", rec.Code)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("security headers missing")
	}
}

func TestStatusRequiresToken(t *testing.T) {
	h := newServer(t).Handler()
	for _, auth := range []string{"", "Bearer wrong", "secret-token"} {
		req := httptest.NewRequest("GET", "/api/status", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("auth %q: got %d, want 401", auth, rec.Code)
		}
	}
}

func TestStatusWithoutArtex(t *testing.T) {
	h := newServer(t).Handler()
	req := httptest.NewRequest("GET", "/api/status", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	var out struct {
		SchemaVersion int         `json:"schema_version"`
		Artex         ArtexStatus `json:"artex"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.SchemaVersion < 1 || out.Artex.Configured {
		t.Fatalf("unexpected status: %+v", out)
	}
}
