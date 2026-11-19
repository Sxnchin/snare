package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "snare.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaultsAreValid(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}
}

func TestLoadNoFile(t *testing.T) {
	cfg, err := Load("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Listen != "127.0.0.1:8780" {
		t.Fatalf("listen = %q", cfg.Server.Listen)
	}
}

func TestLoadEmptyFile(t *testing.T) {
	if _, err := Load(write(t, ""), nil); err != nil {
		t.Fatal(err)
	}
}

func TestLoadFileAndRouteDefaults(t *testing.T) {
	p := write(t, `
gateway:
  listen: 0.0.0.0:8000
  routes:
    - name: shop
      upstream: http://juice-shop:3000
  limits:
    upstream_timeout: 5s
`)
	cfg, err := Load(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.Gateway.Routes[0]
	if r.PathPrefix != "/" || r.Mode != ModeRecord {
		t.Fatalf("route defaults not applied: %+v", r)
	}
	if cfg.Gateway.Limits.UpstreamTimeout.D() != 5*time.Second {
		t.Fatalf("timeout = %v", cfg.Gateway.Limits.UpstreamTimeout.D())
	}
	// Unset limits keep their defaults.
	if cfg.Gateway.Limits.MaxConcurrent != 1024 {
		t.Fatalf("max_concurrent = %d", cfg.Gateway.Limits.MaxConcurrent)
	}
}

func TestUnknownFieldRejected(t *testing.T) {
	_, err := Load(write(t, "server:\n  lisen: 127.0.0.1:1\n"), nil)
	if err == nil || !strings.Contains(err.Error(), "lisen") {
		t.Fatalf("want unknown field error, got %v", err)
	}
}

func TestEnvOverrides(t *testing.T) {
	cfg, err := Load("", []string{
		"SNARE_STORE_PATH=/tmp/x.db",
		"SNARE_GATEWAY_LIMITS_MAX_PER_SOURCE=8",
		"SNARE_ARTEX_TIMEOUT=2s",
		"SNARE_ARTEX_URL=http://artex:8787",
		"SNARE_ARTEX_PASSWORD_FILE=/run/secrets/pw",
		"SNARE_SECRET_KEY=ignored-not-a-field",
		"UNRELATED=1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Store.Path != "/tmp/x.db" || cfg.Gateway.Limits.MaxPerSource != 8 ||
		cfg.Artex.Timeout.D() != 2*time.Second || cfg.Artex.URL != "http://artex:8787" {
		t.Fatalf("overrides not applied: %+v", cfg)
	}
}

func TestEnvBadValue(t *testing.T) {
	_, err := Load("", []string{"SNARE_ACTIVE_ENABLED=maybe"})
	if err == nil || !strings.Contains(err.Error(), "SNARE_ACTIVE_ENABLED") {
		t.Fatalf("want env error, got %v", err)
	}
}

func TestValidationCollectsAllProblems(t *testing.T) {
	p := write(t, `
server:
  listen: 0.0.0.0:8780
gateway:
  routes:
    - name: a
      upstream: ftp://x
      mode: block
    - name: a
      path_prefix: nope
      upstream: http://ok
active:
  enabled: true
`)
	_, err := Load(p, nil)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want ValidationError, got %v", err)
	}
	want := []string{
		"server.listen", "gateway.routes[0].upstream", "gateway.routes[0].mode",
		"gateway.routes[1].name", "gateway.routes[1].path_prefix", "active.enabled",
	}
	msg := err.Error()
	for _, w := range want {
		if !strings.Contains(msg, w) {
			t.Errorf("missing problem %q in:\n%s", w, msg)
		}
	}
}

func TestNonLoopbackNeedsOptIn(t *testing.T) {
	_, err := Load("", []string{"SNARE_SERVER_LISTEN=0.0.0.0:8780", "SNARE_SERVER_ALLOW_NON_LOOPBACK=true"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestEnvNamesStable(t *testing.T) {
	names := EnvNames()
	for _, want := range []string{"SNARE_SERVER_LISTEN", "SNARE_GATEWAY_LIMITS_READ_TIMEOUT", "SNARE_ARTEX_URL"} {
		found := false
		for _, n := range names {
			if n == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s missing from EnvNames", want)
		}
	}
}

func TestExcludeSourcesValidation(t *testing.T) {
	c := Default()
	c.Recorder.ExcludeSources = []string{"artex", "10.0.0.7", "172.16.0.0/12", "scanner.lab.internal", "not a host", "-bad"}
	c.Recorder.ExcludeUserAgents = []string{"crawler", " "}
	err := c.Validate()
	if err == nil {
		t.Fatal("want validation errors")
	}
	msg := err.Error()
	for _, want := range []string{`exclude_sources[4]`, `exclude_sources[5]`, `exclude_user_agents[1]`} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %s in %s", want, msg)
		}
	}
	for _, ok := range []string{`exclude_sources[0]`, `exclude_sources[1]`, `exclude_sources[2]`, `exclude_sources[3]`} {
		if strings.Contains(msg, ok) {
			t.Errorf("%s should be valid: %s", ok, msg)
		}
	}
}
