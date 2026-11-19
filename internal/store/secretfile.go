package store

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LoadOrCreateSecret reads a secret from path. When the file does not exist
// it writes a new random value of n bytes (hex encoded) with mode 0600 and
// returns it. An existing file is never overwritten.
func LoadOrCreateSecret(path string, n int) (value string, created bool, err error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		v := strings.TrimSpace(string(raw))
		if v == "" {
			return "", false, fmt.Errorf("secret file %s is empty; fix or remove it", path)
		}
		return v, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", false, err
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", false, err
	}
	v := hex.EncodeToString(buf)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", false, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", false, err
	}
	if _, err := f.WriteString(v + "\n"); err != nil {
		f.Close()
		os.Remove(path)
		return "", false, err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return "", false, err
	}
	return v, true, nil
}

// ReadSecret reads a secret file that must already exist.
func ReadSecret(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(raw))
	if v == "" {
		return "", fmt.Errorf("secret file %s is empty", path)
	}
	return v, nil
}
