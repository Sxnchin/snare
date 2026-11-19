package recorder

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/snare-dev/snare/internal/store"
)

// KeyEnv is the environment variable that supplies the encryption key (32
// bytes, base64 or hex). It takes precedence over the key file.
const KeyEnv = "SNARE_SECRET_KEY"

// metaKeyCheck stores a sealed known value so a wrong key is detected at
// startup instead of when the corpus is read.
const (
	metaKeyCheck  = "crypto.key_check"
	keyCheckPlain = "snare key check v1"
	aadKeyCheck   = "snare:key-check"
)

// Sealer encrypts and decrypts records with AES-256-GCM. Each record has a
// random 96-bit nonce prepended to its ciphertext, and associated data binds
// a ciphertext to its purpose so records cannot be swapped between uses.
type Sealer struct{ aead cipher.AEAD }

// NewSealer returns a sealer for a 32-byte key.
func NewSealer(key []byte) (*Sealer, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead}, nil
}

// Seal encrypts plain with associated data aad.
func (s *Sealer) Seal(plain []byte, aad string) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, plain, []byte(aad)), nil
}

// Open decrypts a record sealed with the same aad.
func (s *Sealer) Open(sealed []byte, aad string) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("sealed record too short")
	}
	return s.aead.Open(nil, sealed[:n], sealed[n:], []byte(aad))
}

// ParseKey decodes a 32-byte key given as base64 (standard or URL) or hex.
func ParseKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, dec := range []func(string) ([]byte, error){
		hex.DecodeString,
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
	} {
		if k, err := dec(s); err == nil && len(k) == 32 {
			return k, nil
		}
	}
	return nil, errors.New("key must be 32 bytes encoded as hex or base64")
}

// LoadSealer finds the encryption key and checks it against the store.
//
// Order: the SNARE_SECRET_KEY value from env, then keyFile. A key file is
// generated (mode 0600) only when the store holds no encrypted data yet.
// When encrypted data exists and no key is available, or the key does not
// match the stored check value, LoadSealer refuses: generating a fresh key
// would silently make the existing corpus unreadable.
func LoadSealer(ctx context.Context, st *store.Store, envKey, keyFile string) (*Sealer, error) {
	check, haveData, err := st.GetMeta(ctx, metaKeyCheck)
	if err != nil {
		return nil, err
	}
	var key []byte
	switch {
	case strings.TrimSpace(envKey) != "":
		if key, err = ParseKey(envKey); err != nil {
			return nil, fmt.Errorf("%s: %w", KeyEnv, err)
		}
	default:
		raw, rerr := os.ReadFile(keyFile)
		switch {
		case rerr == nil:
			if key, err = ParseKey(string(raw)); err != nil {
				return nil, fmt.Errorf("key file %s: %w", keyFile, err)
			}
		case errors.Is(rerr, os.ErrNotExist):
			if haveData {
				return nil, fmt.Errorf("encrypted data exists but no key is available: set %s or restore %s", KeyEnv, keyFile)
			}
			if key, err = createKeyFile(keyFile); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("read key file: %w", rerr)
		}
	}
	s, err := NewSealer(key)
	if err != nil {
		return nil, err
	}
	if haveData {
		sealed, err := base64.StdEncoding.DecodeString(check)
		if err != nil {
			return nil, fmt.Errorf("stored key check is corrupt: %w", err)
		}
		plain, err := s.Open(sealed, aadKeyCheck)
		if err != nil || string(plain) != keyCheckPlain {
			return nil, errors.New("encryption key does not match the key this data was encrypted with")
		}
		return s, nil
	}
	sealed, err := s.Seal([]byte(keyCheckPlain), aadKeyCheck)
	if err != nil {
		return nil, err
	}
	if err := st.SetMeta(ctx, metaKeyCheck, base64.StdEncoding.EncodeToString(sealed)); err != nil {
		return nil, err
	}
	return s, nil
}

func createKeyFile(path string) ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create key file: %w", err)
	}
	if _, err := f.WriteString(base64.StdEncoding.EncodeToString(key) + "\n"); err != nil {
		f.Close()
		os.Remove(path)
		return nil, err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return nil, err
	}
	return key, nil
}
