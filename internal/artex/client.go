// Package artex is Snare's connector to an unmodified ARTEX instance. It talks
// to ARTEX only over its HTTP API (pinned commit recorded in
// docs/ASSUMPTIONS.md). Everything ARTEX returns is treated as data.
//
// M0 implements only the endpoints needed to check that ARTEX is up and that
// Snare can authenticate: GET /api/health, GET /api/auth/status and
// POST /api/auth/login (server/auth.go). The full typed client lands in M3.
package artex

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Username is the fixed admin user name ARTEX accepts on login.
const Username = "ARTEX"

// maxResponseBytes caps how much of an ARTEX response Snare reads.
const maxResponseBytes = 8 << 20

// Client is an authenticated ARTEX API client. It logs in lazily and logs in
// again once when a request returns 401.
type Client struct {
	base     string
	username string
	password func() (string, error)
	http     *http.Client

	mu    sync.Mutex
	token string
}

// New returns a client for base (for example http://artex:8787). password is
// called when a login is needed, so a password file written after Snare starts
// is picked up.
func New(base, username string, password func() (string, error), timeout time.Duration) *Client {
	return &Client{
		base:     strings.TrimRight(base, "/"),
		username: username,
		password: password,
		http: &http.Client{
			Timeout: timeout,
			// ARTEX never needs to redirect API calls; refusing keeps a bearer
			// token from following a redirect elsewhere.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// APIError is a non-2xx response from ARTEX.
type APIError struct {
	Status int
	Msg    string
}

func (e *APIError) Error() string { return fmt.Sprintf("artex: HTTP %d: %s", e.Status, e.Msg) }

// IsStatus reports whether err is an APIError with the given status.
func IsStatus(err error, status int) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == status
}

// Health calls GET /api/health. ARTEX answers {"ok":true} without a token.
func (c *Client) Health(ctx context.Context) error {
	var out struct {
		OK bool `json:"ok"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/health", nil, &out, false); err != nil {
		return err
	}
	if !out.OK {
		return errors.New("artex: health reported not ok")
	}
	return nil
}

// Initialized calls GET /api/auth/status and reports whether the admin
// password has been set.
func (c *Client) Initialized(ctx context.Context) (bool, error) {
	var out struct {
		Initialized bool `json:"initialized"`
	}
	err := c.do(ctx, http.MethodGet, "/api/auth/status", nil, &out, false)
	return out.Initialized, err
}

// Login calls POST /api/auth/login and stores the returned JWT.
func (c *Client) Login(ctx context.Context) error {
	pw, err := c.password()
	if err != nil {
		return fmt.Errorf("artex: read password: %w", err)
	}
	var out struct {
		Token string `json:"token"`
	}
	in := map[string]string{"username": c.username, "password": pw}
	if err := c.do(ctx, http.MethodPost, "/api/auth/login", in, &out, false); err != nil {
		return err
	}
	if out.Token == "" {
		return errors.New("artex: login returned no token")
	}
	c.mu.Lock()
	c.token = out.Token
	c.mu.Unlock()
	return nil
}

// CheckSession proves the stored credentials work. ARTEX's /api/health never
// returns 401; it adds "service":"artex" only when the bearer token is a valid
// session (server/server.go health). A missing field means the cached token is
// stale, so CheckSession logs in once and checks again.
func (c *Client) CheckSession(ctx context.Context) error {
	for attempt := 0; attempt < 2; attempt++ {
		if c.currentToken() == "" || attempt == 1 {
			if err := c.Login(ctx); err != nil {
				return err
			}
		}
		var out struct {
			Service string `json:"service"`
		}
		if err := c.do(ctx, http.MethodGet, "/api/health", nil, &out, true); err != nil {
			return err
		}
		if out.Service == "artex" {
			return nil
		}
	}
	return errors.New("artex: session not accepted after login")
}

// Authed performs an authenticated JSON request, logging in first if needed
// and retrying once after a 401.
func (c *Client) Authed(ctx context.Context, method, path string, in, out any) error {
	if c.currentToken() == "" {
		if err := c.Login(ctx); err != nil {
			return err
		}
	}
	err := c.do(ctx, method, path, in, out, true)
	if IsStatus(err, http.StatusUnauthorized) {
		if lerr := c.Login(ctx); lerr != nil {
			return lerr
		}
		err = c.do(ctx, method, path, in, out, true)
	}
	return err
}

func (c *Client) currentToken() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.token
}

func (c *Client) do(ctx context.Context, method, path string, in, out any, auth bool) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if auth {
		req.Header.Set("Authorization", "Bearer "+c.currentToken())
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("artex: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("artex: read %s: %w", path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &APIError{Status: resp.StatusCode, Msg: errorMessage(raw)}
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("artex: decode %s: %w", path, err)
	}
	return nil
}

// errorMessage extracts ARTEX's {"error": "..."} message, bounded in length so
// an unexpected body never floods logs.
func errorMessage(raw []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	msg := strings.TrimSpace(string(raw))
	if json.Unmarshal(raw, &e) == nil && e.Error != "" {
		msg = e.Error
	}
	if len(msg) > 300 {
		msg = msg[:300] + "..."
	}
	return msg
}
