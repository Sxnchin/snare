// Package labnet holds the two network helpers the compose lab uses to keep
// ARTEX on an internal-only network:
//
//   - Egress is an HTTP CONNECT proxy that lets ARTEX reach only the LLM
//     provider hosts named in configuration and denies everything else.
//   - Forward is a fixed-destination TCP forwarder that publishes ARTEX's UI
//     on host loopback. It only ever dials its one configured destination, so
//     it cannot be used as a way out.
//
// Neither is part of Snare's product surface; they exist for the lab.
package labnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DeniedHeader is set on every response the proxy refuses, so tests can tell
// a policy denial from an upstream error.
const DeniedHeader = "X-Lab-Egress-Denied"

// Egress is an allowlisting CONNECT proxy.
type Egress struct {
	// Allow is the set of permitted "host:port" destinations, lower-cased.
	Allow map[string]bool
	// AllowPrivate permits allowlisted names that resolve to private,
	// loopback, link-local or otherwise non-public addresses. Off by default
	// so an allowlisted name cannot be pointed at an internal service.
	AllowPrivate bool
	// MaxConns caps concurrent tunnels.
	MaxConns int
	// IdleTimeout closes a tunnel with no traffic in either direction.
	IdleTimeout time.Duration
	// Resolver resolves allowlisted names. nil means net.DefaultResolver.
	Resolver interface {
		LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	}
	// Dial dials the resolved address. nil means a net.Dialer.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	Log  *slog.Logger

	once sync.Once
	sem  chan struct{}
}

// ParseAllow turns "a.example:443, b.example" into an allow set. A missing
// port means 443.
func ParseAllow(list string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, item := range strings.Split(list, ",") {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		if !strings.Contains(item, ":") {
			item += ":443"
		}
		host, port, err := net.SplitHostPort(item)
		if err != nil || host == "" {
			return nil, fmt.Errorf("allow entry %q is not host[:port]", item)
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("allow entry %q has an invalid port", item)
		}
		if strings.ContainsAny(host, "*/ ") {
			return nil, fmt.Errorf("allow entry %q: wildcards are not supported; list exact hosts", item)
		}
		out[net.JoinHostPort(host, port)] = true
	}
	return out, nil
}

// AllowList returns the allow set sorted, for logging.
func (e *Egress) AllowList() []string {
	out := make([]string, 0, len(e.Allow))
	for k := range e.Allow {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (e *Egress) init() {
	e.once.Do(func() {
		if e.MaxConns <= 0 {
			e.MaxConns = 256
		}
		if e.IdleTimeout <= 0 {
			e.IdleTimeout = 5 * time.Minute
		}
		if e.Resolver == nil {
			e.Resolver = net.DefaultResolver
		}
		if e.Dial == nil {
			d := &net.Dialer{Timeout: 10 * time.Second}
			e.Dial = d.DialContext
		}
		if e.Log == nil {
			e.Log = slog.New(slog.NewJSONHandler(io.Discard, nil))
		}
		e.sem = make(chan struct{}, e.MaxConns)
	})
}

func (e *Egress) deny(w http.ResponseWriter, r *http.Request, dest, reason string) {
	e.Log.Warn("egress denied", "dest", dest, "method", r.Method, "client", r.RemoteAddr, "reason", reason)
	w.Header().Set(DeniedHeader, reason)
	http.Error(w, "egress denied: "+reason, http.StatusForbidden)
}

// ServeHTTP handles CONNECT requests. Every other method is refused: the LLM
// providers are HTTPS, and plain HTTP forwarding would let a client choose
// arbitrary absolute URLs.
func (e *Egress) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.init()
	// Health probe addressed to the proxy itself (origin-form, not a proxy
	// request). Proxy-form requests carry an absolute URL and fall through
	// to the denial below.
	if r.Method == http.MethodGet && !r.URL.IsAbs() && r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
		return
	}
	if r.Method != http.MethodConnect {
		e.deny(w, r, r.Host, "only CONNECT is supported")
		return
	}
	dest := strings.ToLower(r.Host)
	host, port, err := net.SplitHostPort(dest)
	if err != nil {
		e.deny(w, r, dest, "bad CONNECT target")
		return
	}
	if !e.Allow[dest] {
		e.deny(w, r, dest, "not in allowlist")
		return
	}
	select {
	case e.sem <- struct{}{}:
		defer func() { <-e.sem }()
	default:
		e.deny(w, r, dest, "too many connections")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	ip, err := e.resolve(ctx, host)
	if err != nil {
		e.deny(w, r, dest, err.Error())
		return
	}
	upstream, err := e.Dial(ctx, "tcp", net.JoinHostPort(ip.String(), port))
	if err != nil {
		e.Log.Warn("egress dial failed", "dest", dest, "ip", ip.String(), "err", err)
		http.Error(w, "upstream dial failed", http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	client, buf, err := hj.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		return
	}
	e.Log.Info("egress allowed", "dest", dest, "ip", ip.String(), "client", r.RemoteAddr)
	// Bytes the client sent after the CONNECT head are already buffered.
	br := buf.Reader
	if n := br.Buffered(); n > 0 {
		pending, _ := br.Peek(n)
		if _, err := upstream.Write(pending); err != nil {
			return
		}
	}
	pipe(client, upstream, e.IdleTimeout)
}

// resolve returns the first acceptable address for host.
func (e *Egress) resolve(ctx context.Context, host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if !e.AllowPrivate && !isPublic(ip) {
			return nil, errors.New("destination address is not public")
		}
		return ip, nil
	}
	addrs, err := e.Resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, errors.New("resolve failed")
	}
	for _, a := range addrs {
		if e.AllowPrivate || isPublic(a.IP) {
			return a.IP, nil
		}
	}
	return nil, errors.New("name resolves only to non-public addresses")
}

func isPublic(ip net.IP) bool {
	nonPublic := ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || isCGNAT(ip)
	return !nonPublic
}

// isCGNAT reports 100.64.0.0/10, which net.IP.IsPrivate does not cover.
func isCGNAT(ip net.IP) bool {
	v4 := ip.To4()
	return v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64
}

// idleConn resets a deadline on every read and write.
type idleConn struct {
	net.Conn
	idle time.Duration
}

func (c idleConn) Read(p []byte) (int, error) {
	_ = c.SetDeadline(time.Now().Add(c.idle))
	return c.Conn.Read(p)
}

func (c idleConn) Write(p []byte) (int, error) {
	_ = c.SetDeadline(time.Now().Add(c.idle))
	return c.Conn.Write(p)
}

// pipe copies in both directions until either side closes or goes idle.
func pipe(a, b net.Conn, idle time.Duration) {
	ia, ib := idleConn{a, idle}, idleConn{b, idle}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(ib, ia); done <- struct{}{} }()
	go func() { _, _ = io.Copy(ia, ib); done <- struct{}{} }()
	<-done
	// Closing both ends unblocks the other copy.
	a.Close()
	b.Close()
	<-done
}

// Forward accepts TCP connections and pipes each to one fixed destination.
type Forward struct {
	To          string
	IdleTimeout time.Duration
	MaxConns    int
	Log         *slog.Logger
}

// Serve runs until ctx is cancelled or ln fails.
func (f *Forward) Serve(ctx context.Context, ln net.Listener) error {
	if f.IdleTimeout <= 0 {
		f.IdleTimeout = 10 * time.Minute
	}
	if f.MaxConns <= 0 {
		f.MaxConns = 128
	}
	if f.Log == nil {
		f.Log = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	sem := make(chan struct{}, f.MaxConns)
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case sem <- struct{}{}:
		default:
			c.Close()
			continue
		}
		go func() {
			defer func() { <-sem }()
			defer c.Close()
			d := net.Dialer{Timeout: 5 * time.Second}
			up, err := d.DialContext(ctx, "tcp", f.To)
			if err != nil {
				f.Log.Warn("forward dial failed", "to", f.To, "err", err)
				return
			}
			pipe(c, up, f.IdleTimeout)
		}()
	}
}
