package labnet

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type fakeResolver map[string]string

func (f fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	ip, ok := f[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host}
	}
	return []net.IPAddr{{IP: net.ParseIP(ip)}}, nil
}

// echoServer accepts one line and writes it back prefixed with "echo:".
func echoServer(t *testing.T) (port string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				line, _ := bufio.NewReader(c).ReadString('\n')
				_, _ = io.WriteString(c, "echo:"+line)
			}()
		}
	}()
	_, port, _ = net.SplitHostPort(ln.Addr().String())
	return port
}

func connect(t *testing.T, proxy, dest string) (*http.Response, net.Conn) {
	t.Helper()
	u, _ := url.Parse(proxy)
	c, err := net.DialTimeout("tcp", u.Host, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, "CONNECT "+dest+" HTTP/1.1\r\nHost: "+dest+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	return resp, &bufConn{Conn: c, r: br}
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func TestParseAllow(t *testing.T) {
	got, err := ParseAllow(" API.OpenAI.com , api.anthropic.com:443,,local.test:8443")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"api.openai.com:443", "api.anthropic.com:443", "local.test:8443"} {
		if !got[want] {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	for _, bad := range []string{"*.openai.com", "host:0", "host:http", ":443"} {
		if _, err := ParseAllow(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestAllowedTunnel(t *testing.T) {
	port := echoServer(t)
	e := &Egress{
		Allow:        map[string]bool{"llm.test:" + port: true},
		AllowPrivate: true, // the echo server is on loopback
		Resolver:     fakeResolver{"llm.test": "127.0.0.1"},
	}
	srv := httptest.NewServer(e)
	defer srv.Close()
	resp, c := connect(t, srv.URL, "llm.test:"+port)
	defer c.Close()
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT status %d", resp.StatusCode)
	}
	if _, err := io.WriteString(c, "hello\n"); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || line != "echo:hello\n" {
		t.Fatalf("tunnel did not carry data: %q %v", line, err)
	}
}

func TestDenials(t *testing.T) {
	port := echoServer(t)
	e := &Egress{
		Allow:    map[string]bool{"llm.test:" + port: true, "internal.test:443": true},
		Resolver: fakeResolver{"llm.test": "127.0.0.1", "internal.test": "10.0.0.5"},
	}
	srv := httptest.NewServer(e)
	defer srv.Close()

	cases := map[string]string{
		"example.com:443":       "not in allowlist",
		"llm.test:" + port:      "non-public", // allowlisted but resolves to loopback
		"internal.test:443":     "non-public",
		"llm.test:9":            "not in allowlist", // right host, wrong port
		"169.254.169.254:80":    "not in allowlist",
		"LLM.TEST:" + port + "": "non-public", // case-insensitive match, still private
	}
	for dest, reason := range cases {
		resp, c := connect(t, srv.URL, dest)
		resp.Body.Close()
		c.Close()
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(resp.Header.Get(DeniedHeader), reason) {
			t.Errorf("%s: status %d reason %q, want 403 containing %q", dest, resp.StatusCode, resp.Header.Get(DeniedHeader), reason)
		}
	}

	// Plain HTTP forwarding is refused even for an allowlisted host.
	proxyURL, _ := url.Parse(srv.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 3 * time.Second}
	resp, err := client.Get("http://llm.test:" + port + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get(DeniedHeader) == "" {
		t.Fatalf("plain HTTP: status %d", resp.StatusCode)
	}
}

func TestPublicAddressCheck(t *testing.T) {
	for ip, want := range map[string]bool{
		"8.8.8.8": true, "2606:4700::1": true,
		"127.0.0.1": false, "10.1.2.3": false, "172.20.0.2": false, "192.168.1.1": false,
		"169.254.169.254": false, "100.64.0.1": false, "::1": false, "fd00::1": false, "0.0.0.0": false,
	} {
		if got := isPublic(net.ParseIP(ip)); got != want {
			t.Errorf("isPublic(%s) = %v, want %v", ip, got, want)
		}
	}
}

func TestForward(t *testing.T) {
	port := echoServer(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &Forward{To: "127.0.0.1:" + port}
	go func() { _ = f.Serve(ctx, ln) }()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.WriteString(c, "ping\n")
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || line != "echo:ping\n" {
		t.Fatalf("forward: %q %v", line, err)
	}
}

func TestHealthzIsNotAProxyPath(t *testing.T) {
	e := &Egress{Allow: map[string]bool{}}
	srv := httptest.NewServer(e)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("healthz = %d", resp.StatusCode)
	}
	// The same path in proxy form must still be refused.
	proxyURL, _ := url.Parse(srv.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 3 * time.Second}
	resp, err = client.Get("http://example.com/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("proxy-form /healthz = %d, want 403", resp.StatusCode)
	}
}
