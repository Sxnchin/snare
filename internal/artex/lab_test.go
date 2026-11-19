//go:build lab

// Integration test against the real ARTEX container in deploy/compose.
// Run with: deploy/compose/lab.sh test-login
package artex

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLabLogin(t *testing.T) {
	url := os.Getenv("SNARE_LAB_ARTEX_URL")
	pwFile := os.Getenv("SNARE_LAB_ARTEX_PASSWORD_FILE")
	if url == "" || pwFile == "" {
		t.Skip("SNARE_LAB_ARTEX_URL and SNARE_LAB_ARTEX_PASSWORD_FILE not set")
	}
	pw := func() (string, error) {
		raw, err := os.ReadFile(pwFile)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(raw)), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := New(url, Username, pw, 10*time.Second)

	if err := c.Health(ctx); err != nil {
		t.Fatalf("health: %v", err)
	}
	ok, err := c.Initialized(ctx)
	if err != nil || !ok {
		t.Fatalf("initialized=%v err=%v", ok, err)
	}
	if err := c.Login(ctx); err != nil {
		t.Fatalf("login: %v", err)
	}
	t.Logf("login ok: received a %d-byte JWT", len(c.currentToken()))
	if err := c.CheckSession(ctx); err != nil {
		t.Fatalf("session check: %v", err)
	}
	// An authenticated read of a protected endpoint.
	var settings map[string]any
	if err := c.Authed(ctx, "GET", "/api/settings", nil, &settings); err != nil {
		t.Fatalf("GET /api/settings: %v", err)
	}
	if v, ok := settings["web_search_enabled"].(bool); !ok || v {
		t.Fatalf("web_search_enabled = %v, want false", settings["web_search_enabled"])
	}
	t.Logf("authenticated GET /api/settings ok; web_search_enabled=false")

	bad := New(url, Username, func() (string, error) { return "wrong-password-123", nil }, 10*time.Second)
	if err := bad.Login(ctx); !IsStatus(err, 401) {
		t.Fatalf("wrong password: want 401, got %v", err)
	}
}
