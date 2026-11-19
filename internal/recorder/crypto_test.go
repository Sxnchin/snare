package recorder

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/snare-dev/snare/internal/store"
)

func openStore(t *testing.T, path string) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestSealOpen(t *testing.T) {
	s, err := NewSealer(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := s.Seal([]byte("hello"), "route:a")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("hello")) {
		t.Fatal("plaintext visible in ciphertext")
	}
	if got, err := s.Open(sealed, "route:a"); err != nil || string(got) != "hello" {
		t.Fatalf("open: %q %v", got, err)
	}
	if _, err := s.Open(sealed, "route:b"); err == nil {
		t.Fatal("open with different associated data must fail")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := s.Open(sealed, "route:a"); err == nil {
		t.Fatal("tampered ciphertext must fail")
	}
	s2, _ := s.Seal([]byte("hello"), "route:a")
	s3, _ := s.Seal([]byte("hello"), "route:a")
	if bytes.Equal(s2, s3) {
		t.Fatal("nonces must differ")
	}
}

func TestParseKey(t *testing.T) {
	raw := bytes.Repeat([]byte{0xab}, 32)
	if k, err := ParseKey(hex.EncodeToString(raw)); err != nil || !bytes.Equal(k, raw) {
		t.Fatalf("hex: %v", err)
	}
	if k, err := ParseKey("q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s="); err != nil || !bytes.Equal(k, raw) {
		t.Fatalf("base64: %v", err)
	}
	if _, err := ParseKey("too-short"); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestLoadSealerLifecycle(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "secret.key")
	dbPath := filepath.Join(dir, "s.db")
	st := openStore(t, dbPath)

	// First start: key file generated with mode 0600.
	s1, err := LoadSealer(ctx, st, "", keyFile)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(keyFile)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v mode %v", err, fi.Mode().Perm())
	}
	sealed, _ := s1.Seal([]byte("x"), "a")

	// Restart with the same key file works.
	s2, err := LoadSealer(ctx, st, "", keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s2.Open(sealed, "a"); err != nil || string(got) != "x" {
		t.Fatal("restart cannot read data")
	}

	// Key file lost while encrypted data exists: refuse, do not regenerate.
	keyBytes, _ := os.ReadFile(keyFile)
	os.Remove(keyFile)
	if _, err := LoadSealer(ctx, st, "", keyFile); err == nil || !strings.Contains(err.Error(), "no key is available") {
		t.Fatalf("want refusal, got %v", err)
	}
	if _, err := os.Stat(keyFile); !os.IsNotExist(err) {
		t.Fatal("a new key file must not be generated over existing data")
	}

	// The env variable supplies the key instead.
	if _, err := LoadSealer(ctx, st, string(keyBytes), keyFile); err != nil {
		t.Fatalf("env key: %v", err)
	}

	// A wrong key is detected at startup.
	wrong := hex.EncodeToString(bytes.Repeat([]byte{1}, 32))
	if _, err := LoadSealer(ctx, st, wrong, keyFile); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("want key mismatch, got %v", err)
	}
	if _, err := LoadSealer(ctx, st, "nonsense", keyFile); err == nil || !strings.Contains(err.Error(), KeyEnv) {
		t.Fatalf("want env parse error, got %v", err)
	}
}
