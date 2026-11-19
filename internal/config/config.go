// Package config loads snare.yaml, applies environment variable overrides,
// fills defaults, and validates the result. Every problem found during
// validation is reported at once so an operator can fix the file in one pass.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// EnvPrefix is the prefix for environment variable overrides. A scalar field
// at path server.listen is overridden by SNARE_SERVER_LISTEN.
const EnvPrefix = "SNARE_"

// Duration is a time.Duration that reads from YAML as a Go duration string
// ("72h", "30s").
type Duration time.Duration

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return fmt.Errorf("line %d: duration must be a string such as \"30s\" or \"72h\"", n.Line)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*d = Duration(v)
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// Config is the full Snare configuration.
type Config struct {
	Server   Server   `yaml:"server"`
	Store    Store    `yaml:"store"`
	Secrets  Secrets  `yaml:"secrets"`
	Gateway  Gateway  `yaml:"gateway"`
	Recorder Recorder `yaml:"recorder"`
	Artex    Artex    `yaml:"artex"`
	Active   Active   `yaml:"active"`
}

// Server is Snare's own API and UI listener.
type Server struct {
	// Listen is the address for the API and UI. Loopback by default.
	Listen string `yaml:"listen"`
	// APITokenFile holds the bearer token for Snare's API. Generated on first
	// start (mode 0600) when missing.
	APITokenFile string `yaml:"api_token_file"`
	// AllowNonLoopback must be true to bind the API to a non-loopback address.
	AllowNonLoopback bool `yaml:"allow_non_loopback"`
}

// Store is Snare's SQLite state.
type Store struct {
	Path string `yaml:"path"`
}

// Secrets configures encryption at rest.
type Secrets struct {
	// KeyFile is the AES-256 key file, generated on first start when missing.
	// SNARE_SECRET_KEY (base64 or hex, 32 bytes) takes precedence.
	KeyFile string `yaml:"key_file"`
}

// Gateway is the reverse proxy in front of protected apps.
type Gateway struct {
	Listen string  `yaml:"listen"`
	Routes []Route `yaml:"routes"`
	Limits Limits  `yaml:"limits"`
	// TrustedProxies are CIDRs of reverse proxies in front of Snare. Only
	// for a peer in this list is X-Forwarded-For used to find the client.
	TrustedProxies []string `yaml:"trusted_proxies"`
}

// Recorder configures the benign corpus.
type Recorder struct {
	// LearningPeriod is how long a route in record mode stores traffic,
	// counted from the first stored exchange on that route.
	LearningPeriod Duration `yaml:"learning_period"`
	// MaxBodyBytes is how much of each request and response body is kept.
	MaxBodyBytes int `yaml:"max_body_bytes"`
	// QueueSize bounds exchanges waiting to be written. When it is full,
	// exchanges are dropped (and counted) rather than slowing traffic.
	QueueSize int    `yaml:"queue_size"`
	Redact    Redact `yaml:"redact"`
	// ExcludeSources are clients whose traffic is never recorded: IP
	// addresses, CIDRs, or hostnames (resolved at start and every few
	// seconds). Point this at the scanner, for example ARTEX's container.
	// It only affects recording; the traffic is still proxied and, from M2,
	// scored by the detector.
	ExcludeSources []string `yaml:"exclude_sources"`
	// ExcludeUserAgents are extra case-insensitive User-Agent substrings
	// that are never recorded, on top of the built-in scanner list.
	ExcludeUserAgents []string `yaml:"exclude_user_agents"`
}

// Redact lists additions to the built-in redaction rules.
type Redact struct {
	Headers    []string `yaml:"headers"`
	JSONFields []string `yaml:"json_fields"`
}

// Route maps incoming requests to one upstream.
type Route struct {
	Name       string `yaml:"name"`
	Host       string `yaml:"host"`        // empty matches any host
	PathPrefix string `yaml:"path_prefix"` // defaults to "/"
	Upstream   string `yaml:"upstream"`
	Mode       string `yaml:"mode"` // record | detect | enforce
}

// Route modes.
const (
	ModeRecord  = "record"
	ModeDetect  = "detect"
	ModeEnforce = "enforce"
)

// Limits are the gateway's hard limits.
type Limits struct {
	MaxRequestBodyBytes int64    `yaml:"max_request_body_bytes"`
	MaxHeaderBytes      int      `yaml:"max_header_bytes"`
	ReadTimeout         Duration `yaml:"read_timeout"`
	WriteTimeout        Duration `yaml:"write_timeout"`
	UpstreamTimeout     Duration `yaml:"upstream_timeout"`
	MaxConcurrent       int      `yaml:"max_concurrent"`
	MaxPerSource        int      `yaml:"max_per_source"`
}

// Artex is the connection to an unmodified ARTEX instance.
type Artex struct {
	// URL is ARTEX's API base, for example http://artex:8787. Empty disables
	// the connector.
	URL          string `yaml:"url"`
	Username     string `yaml:"username"`
	PasswordFile string `yaml:"password_file"`
	// WebhookSecretFile holds the shared secret ARTEX sends in a header on
	// every webhook delivery.
	WebhookSecretFile string   `yaml:"webhook_secret_file"`
	Timeout           Duration `yaml:"timeout"`
}

// Active configures active mode (Snare drives ARTEX against verified targets).
type Active struct {
	Enabled bool `yaml:"enabled"`
	// AllowProduction must be set before active mode may run against a target
	// marked production.
	AllowProduction bool `yaml:"allow_production"`
}

// Default returns a configuration with every default filled in.
func Default() Config {
	return Config{
		Server: Server{
			Listen:       "127.0.0.1:8780",
			APITokenFile: "data/api.token",
		},
		Store:   Store{Path: "data/snare.db"},
		Secrets: Secrets{KeyFile: "data/secret.key"},
		Gateway: Gateway{
			Listen: "127.0.0.1:8000",
			Limits: Limits{
				MaxRequestBodyBytes: 10 << 20,
				MaxHeaderBytes:      64 << 10,
				ReadTimeout:         Duration(30 * time.Second),
				WriteTimeout:        Duration(60 * time.Second),
				UpstreamTimeout:     Duration(30 * time.Second),
				MaxConcurrent:       1024,
				MaxPerSource:        64,
			},
		},
		Recorder: Recorder{
			LearningPeriod: Duration(72 * time.Hour),
			MaxBodyBytes:   256 << 10,
			QueueSize:      4096,
		},
		Artex: Artex{
			Username: "ARTEX",
			Timeout:  Duration(30 * time.Second),
		},
	}
}

// Load reads path (if non-empty), applies environment overrides from env, and
// validates. env is usually os.Environ(); tests pass their own.
func Load(path string, env []string) (Config, error) {
	cfg := Default()
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("read config: %w", err)
		}
		dec := yaml.NewDecoder(bytes.NewReader(raw))
		dec.KnownFields(true)
		if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) { // empty file is fine
			return Config{}, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	if err := applyEnv(&cfg, env); err != nil {
		return Config{}, err
	}
	cfg.fillRouteDefaults()
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) fillRouteDefaults() {
	for i := range c.Gateway.Routes {
		r := &c.Gateway.Routes[i]
		if r.PathPrefix == "" {
			r.PathPrefix = "/"
		}
		if r.Mode == "" {
			r.Mode = ModeRecord
		}
	}
}

// ValidationError lists every problem found in a configuration.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string {
	return "invalid configuration:\n  - " + strings.Join(e.Problems, "\n  - ")
}

// Validate checks the configuration and returns a *ValidationError listing all
// problems, or nil.
func (c Config) Validate() error {
	var p []string
	add := func(format string, args ...any) { p = append(p, fmt.Sprintf(format, args...)) }

	if err := checkListen(c.Server.Listen); err != nil {
		add("server.listen: %v", err)
	} else if !c.Server.AllowNonLoopback && !isLoopbackListen(c.Server.Listen) {
		add("server.listen: %q is not a loopback address; set server.allow_non_loopback: true to expose the API", c.Server.Listen)
	}
	if c.Server.APITokenFile == "" {
		add("server.api_token_file: required")
	}
	if c.Store.Path == "" {
		add("store.path: required")
	}
	if c.Secrets.KeyFile == "" {
		add("secrets.key_file: required")
	}
	if err := checkListen(c.Gateway.Listen); err != nil {
		add("gateway.listen: %v", err)
	}
	l := c.Gateway.Limits
	if l.MaxRequestBodyBytes <= 0 {
		add("gateway.limits.max_request_body_bytes: must be positive")
	}
	if l.MaxHeaderBytes <= 0 {
		add("gateway.limits.max_header_bytes: must be positive")
	}
	if l.ReadTimeout <= 0 || l.WriteTimeout <= 0 || l.UpstreamTimeout <= 0 {
		add("gateway.limits: read_timeout, write_timeout and upstream_timeout must be positive")
	}
	if l.MaxConcurrent <= 0 || l.MaxPerSource <= 0 {
		add("gateway.limits: max_concurrent and max_per_source must be positive")
	}
	if l.MaxPerSource > l.MaxConcurrent {
		add("gateway.limits.max_per_source (%d) exceeds max_concurrent (%d)", l.MaxPerSource, l.MaxConcurrent)
	}
	for i, cidr := range c.Gateway.TrustedProxies {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			add("gateway.trusted_proxies[%d]: %q is not a CIDR", i, cidr)
		}
	}
	if c.Recorder.LearningPeriod <= 0 {
		add("recorder.learning_period: must be positive")
	}
	if c.Recorder.MaxBodyBytes < 0 || c.Recorder.MaxBodyBytes > 16<<20 {
		add("recorder.max_body_bytes: must be between 0 and 16 MiB")
	}
	if c.Recorder.QueueSize <= 0 {
		add("recorder.queue_size: must be positive")
	}
	for i, s := range c.Recorder.ExcludeSources {
		if !validSource(s) {
			add("recorder.exclude_sources[%d]: %q is not an IP address, CIDR or hostname", i, s)
		}
	}
	for i, s := range c.Recorder.ExcludeUserAgents {
		if strings.TrimSpace(s) == "" {
			add("recorder.exclude_user_agents[%d]: empty", i)
		}
	}
	names := map[string]bool{}
	for i, r := range c.Gateway.Routes {
		where := fmt.Sprintf("gateway.routes[%d]", i)
		if r.Name == "" {
			add("%s.name: required", where)
		} else if names[r.Name] {
			add("%s.name: duplicate route name %q", where, r.Name)
		}
		names[r.Name] = true
		if !strings.HasPrefix(r.PathPrefix, "/") {
			add("%s.path_prefix: must start with /", where)
		}
		if err := checkHTTPURL(r.Upstream); err != nil {
			add("%s.upstream: %v", where, err)
		}
		switch r.Mode {
		case ModeRecord, ModeDetect, ModeEnforce:
		default:
			add("%s.mode: %q is not one of record, detect, enforce", where, r.Mode)
		}
	}
	if c.Artex.URL != "" {
		if err := checkHTTPURL(c.Artex.URL); err != nil {
			add("artex.url: %v", err)
		}
		if c.Artex.Username == "" {
			add("artex.username: required when artex.url is set")
		}
		if c.Artex.PasswordFile == "" {
			add("artex.password_file: required when artex.url is set")
		}
		if c.Artex.Timeout <= 0 {
			add("artex.timeout: must be positive")
		}
	}
	if c.Active.Enabled && c.Artex.URL == "" {
		add("active.enabled: requires artex.url")
	}
	if c.Active.AllowProduction && !c.Active.Enabled {
		add("active.allow_production: has no effect unless active.enabled is true")
	}
	if len(p) > 0 {
		return &ValidationError{Problems: p}
	}
	return nil
}

func checkListen(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%q is not host:port", addr)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return fmt.Errorf("%q has an invalid port", addr)
	}
	if host != "" && net.ParseIP(host) == nil && host != "localhost" {
		return fmt.Errorf("%q: host must be an IP address or localhost", addr)
	}
	return nil
}

func isLoopbackListen(addr string) bool {
	host, _, _ := net.SplitHostPort(addr)
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func checkHTTPURL(raw string) error {
	if raw == "" {
		return errors.New("required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%q is not a URL", raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%q: scheme must be http or https", raw)
	}
	if u.Host == "" {
		return fmt.Errorf("%q: missing host", raw)
	}
	return nil
}

// applyEnv overrides scalar fields from SNARE_* variables. Lists (routes) are
// not overridable from the environment; use the file for those.
func applyEnv(cfg *Config, env []string) error {
	vars := map[string]string{}
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		if ok && strings.HasPrefix(k, EnvPrefix) {
			vars[k] = v
		}
	}
	fields := map[string]reflect.Value{}
	collectFields(reflect.ValueOf(cfg).Elem(), EnvPrefix[:len(EnvPrefix)-1], fields)
	var p []string
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		f, ok := fields[k]
		if !ok {
			continue // not a config field (for example SNARE_SECRET_KEY)
		}
		if err := setScalar(f, vars[k]); err != nil {
			p = append(p, fmt.Sprintf("%s: %v", k, err))
		}
	}
	if len(p) > 0 {
		return &ValidationError{Problems: p}
	}
	return nil
}

// EnvNames returns every supported override variable, for docs and tests.
func EnvNames() []string {
	cfg := Default()
	fields := map[string]reflect.Value{}
	collectFields(reflect.ValueOf(&cfg).Elem(), EnvPrefix[:len(EnvPrefix)-1], fields)
	out := make([]string, 0, len(fields))
	for k := range fields {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var durationType = reflect.TypeOf(Duration(0))

func collectFields(v reflect.Value, prefix string, out map[string]reflect.Value) {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		tag := strings.Split(sf.Tag.Get("yaml"), ",")[0]
		if tag == "" || tag == "-" {
			continue
		}
		name := prefix + "_" + strings.ToUpper(tag)
		fv := v.Field(i)
		switch {
		case sf.Type == durationType:
			out[name] = fv
		case fv.Kind() == reflect.Struct:
			collectFields(fv, name, out)
		case fv.Kind() == reflect.String, fv.Kind() == reflect.Bool,
			fv.Kind() == reflect.Int, fv.Kind() == reflect.Int64:
			out[name] = fv
		}
	}
}

func setScalar(f reflect.Value, s string) error {
	if f.Type() == durationType {
		d, err := time.ParseDuration(s)
		if err != nil {
			return err
		}
		f.SetInt(int64(d))
		return nil
	}
	switch f.Kind() {
	case reflect.String:
		f.SetString(s)
	case reflect.Bool:
		b, err := strconv.ParseBool(s)
		if err != nil {
			return fmt.Errorf("%q is not a boolean", s)
		}
		f.SetBool(b)
	case reflect.Int, reflect.Int64:
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return fmt.Errorf("%q is not an integer", s)
		}
		f.SetInt(n)
	}
	return nil
}

// validSource accepts an IP address, a CIDR, or a DNS hostname.
func validSource(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !hostChar(r) {
				return false
			}
		}
	}
	return true
}

func hostChar(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		return true
	}
	return false
}
