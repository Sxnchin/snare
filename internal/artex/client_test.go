package artex

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// fakeArtex mimics the auth surface of server/auth.go at the pinned commit.
type fakeArtex struct {
	password string
	logins   atomic.Int32
	valid    atomic.Value // current valid token
}

func (f *fakeArtex) handler() http.Handler {
	mux := http.NewServeMux()
	writeJSON := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		if tok := f.valid.Load().(string); tok != "" && r.Header.Get("Authorization") == "Bearer "+tok {
			writeJSON(w, 200, map[string]any{"ok": true, "service": "artex"})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	})
	mux.HandleFunc("GET /api/auth/status", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"initialized": true})
	})
	mux.HandleFunc("POST /api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Username, Password string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Username != Username || req.Password != f.password {
			writeJSON(w, 401, map[string]any{"error": "Incorrect username or password"})
			return
		}
		n := f.logins.Add(1)
		tok := fmt.Sprintf("tok%d", n)
		f.valid.Store(tok)
		writeJSON(w, 200, map[string]any{"token": tok})
	})
	mux.HandleFunc("GET /api/settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+f.valid.Load().(string) {
			writeJSON(w, 401, map[string]any{"error": "token is invalid or expired"})
			return
		}
		writeJSON(w, 200, map[string]any{"noise_profile": "quiet"})
	})
	return mux
}

func newFake(t *testing.T, pw string) (*fakeArtex, *Client) {
	f := &fakeArtex{password: pw}
	f.valid.Store("")
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	c := New(srv.URL, Username, func() (string, error) { return "correct-horse", nil }, 5*time.Second)
	return f, c
}

func TestHealthAndStatus(t *testing.T) {
	_, c := newFake(t, "correct-horse")
	ctx := context.Background()
	if err := c.Health(ctx); err != nil {
		t.Fatal(err)
	}
	ok, err := c.Initialized(ctx)
	if err != nil || !ok {
		t.Fatalf("initialized=%v err=%v", ok, err)
	}
}

func TestBadPassword(t *testing.T) {
	_, c := newFake(t, "other")
	err := c.Login(context.Background())
	if !IsStatus(err, 401) {
		t.Fatalf("want 401, got %v", err)
	}
	var ae *APIError
	if !errors.As(err, &ae) || ae.Msg != "Incorrect username or password" {
		t.Fatalf("error message not extracted: %v", err)
	}
}

func TestAuthedLogsInLazilyAndRetriesOn401(t *testing.T) {
	f, c := newFake(t, "correct-horse")
	ctx := context.Background()
	var out map[string]any
	if err := c.Authed(ctx, http.MethodGet, "/api/settings", nil, &out); err != nil {
		t.Fatal(err)
	}
	if f.logins.Load() != 1 || out["noise_profile"] != "quiet" {
		t.Fatalf("logins=%d out=%v", f.logins.Load(), out)
	}
	// Invalidate the session: the next call must log in again exactly once.
	f.valid.Store("rotated")
	if err := c.Authed(ctx, http.MethodGet, "/api/settings", nil, &out); err != nil {
		t.Fatalf("retry after 401 should succeed: %v", err)
	}
	if f.logins.Load() != 2 {
		t.Fatalf("want 2 logins, got %d", f.logins.Load())
	}
}

func TestCheckSession(t *testing.T) {
	f, c := newFake(t, "correct-horse")
	ctx := context.Background()
	if err := c.CheckSession(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckSession(ctx); err != nil || f.logins.Load() != 1 {
		t.Fatalf("cached session should be reused: logins=%d err=%v", f.logins.Load(), err)
	}
	f.valid.Store("rotated")
	if err := c.CheckSession(ctx); err != nil || f.logins.Load() != 2 {
		t.Fatalf("stale session should trigger one login: logins=%d err=%v", f.logins.Load(), err)
	}
}
