package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sxnchin/snare/internal/config"
)

func TestRunUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(nil, &out, &errb); code != 2 {
		t.Fatalf("no args: code %d", code)
	}
	if code := run([]string{"version"}, &out, &errb); code != 0 || strings.TrimSpace(out.String()) != version {
		t.Fatalf("version: code %d out %q", code, out.String())
	}
	errb.Reset()
	if code := run([]string{"verify", "example.test"}, &out, &errb); code != 2 || !strings.Contains(errb.String(), "M7") {
		t.Fatalf("verify placeholder: code %d err %q", code, errb.String())
	}
}

func TestServeAndHealthcheck(t *testing.T) {
	dir := t.TempDir()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := config.Default()
	cfg.Server.Listen = addr
	cfg.Server.APITokenFile = filepath.Join(dir, "api.token")
	cfg.Store.Path = filepath.Join(dir, "snare.db")
	cfg.Secrets.KeyFile = filepath.Join(dir, "secret.key")
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil))) }()

	url := "http://" + addr + "/healthz"
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not come up: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	var errb bytes.Buffer
	if code := cmdHealthcheck([]string{"-url", url}, &errb); code != 0 {
		t.Fatalf("healthcheck failed: %s", errb.String())
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serve returned %v", err)
	}
}
