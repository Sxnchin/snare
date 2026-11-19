package store

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadOrCreateSecret(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "token")
	v1, created, err := LoadOrCreateSecret(p, 32)
	if err != nil || !created || len(v1) != 64 {
		t.Fatalf("v=%q created=%v err=%v", v1, created, err)
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(p)
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %v, want 0600", st.Mode().Perm())
		}
	}
	v2, created, err := LoadOrCreateSecret(p, 32)
	if err != nil || created || v2 != v1 {
		t.Fatalf("second load must return the same secret: %q %v %v", v2, created, err)
	}
}

func TestEmptySecretRejected(t *testing.T) {
	p := filepath.Join(t.TempDir(), "token")
	os.WriteFile(p, []byte("\n"), 0o600)
	if _, _, err := LoadOrCreateSecret(p, 32); err == nil {
		t.Fatal("empty secret file must be an error, not silently replaced")
	}
	if _, err := ReadSecret(p); err == nil {
		t.Fatal("ReadSecret must reject empty file")
	}
}
