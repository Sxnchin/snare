// Package ui serves Snare's authenticated API and, from M8, its htmx UI.
//
// M0 exposes:
//
//	GET /healthz      unauthenticated liveness: process up and store reachable
//	GET /api/status   authenticated: version, schema version, ARTEX reachability
package ui

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/snare-dev/snare/internal/artex"
	"github.com/snare-dev/snare/internal/store"
)

// Server is the API and UI handler.
type Server struct {
	Store    *store.Store
	Artex    *artex.Client // nil when no ARTEX is configured
	APIToken string
	Version  string
	Active   bool
}

// Handler returns the routed handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.Handle("GET /api/status", s.requireToken(http.HandlerFunc(s.status)))
	return securityHeaders(mux)
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.Store.DB.PingContext(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "store unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ArtexStatus is the connector section of /api/status.
type ArtexStatus struct {
	Configured  bool   `json:"configured"`
	Reachable   bool   `json:"reachable"`
	Initialized bool   `json:"initialized"`
	LoggedIn    bool   `json:"logged_in"`
	Error       string `json:"error,omitempty"`
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	schema, err := s.Store.SchemaVersion(ctx)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "store unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":        s.Version,
		"schema_version": schema,
		"mode":           map[string]any{"passive": true, "active": s.Active},
		"artex":          s.artexStatus(ctx),
	})
}

func (s *Server) artexStatus(ctx context.Context) ArtexStatus {
	st := ArtexStatus{Configured: s.Artex != nil}
	if s.Artex == nil {
		return st
	}
	if err := s.Artex.Health(ctx); err != nil {
		st.Error = err.Error()
		return st
	}
	st.Reachable = true
	initialized, err := s.Artex.Initialized(ctx)
	if err != nil {
		st.Error = err.Error()
		return st
	}
	st.Initialized = initialized
	if !initialized {
		st.Error = "ARTEX admin not initialized; run the lab bootstrap"
		return st
	}
	// CheckSession reuses the cached token, so polling this does not burn
	// ARTEX's login rate limit (10 per minute per IP).
	if err := s.Artex.CheckSession(ctx); err != nil {
		st.Error = err.Error()
		return st
	}
	st.LoggedIn = true
	return st
}

func (s *Server) requireToken(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(s.APIToken)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		h.ServeHTTP(w, r)
	})
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
