package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrationsContiguous(t *testing.T) {
	ms, err := Migrations()
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) == 0 {
		t.Fatal("no migrations embedded")
	}
}

func TestOpenAppliesMigrationsOnce(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "s.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	v1, _ := s.SchemaVersion(ctx)
	if err := s.SetMeta(ctx, "k", "v"); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	v2, _ := s.SchemaVersion(ctx)
	ms, _ := Migrations()
	if v1 != len(ms) || v2 != v1 {
		t.Fatalf("versions %d then %d, want %d", v1, v2, len(ms))
	}
	got, ok, err := s.GetMeta(ctx, "k")
	if err != nil || !ok || got != "v" {
		t.Fatalf("meta lost across reopen: %q %v %v", got, ok, err)
	}
}

func TestRefusesNewerSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "s.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO schema_migrations VALUES (9999, 'future', 'now')`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	_, err = Open(ctx, path)
	if err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("want newer-schema refusal, got %v", err)
	}
}

func TestActionLogAppendOnly(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.DB.Exec(`INSERT INTO action_log(ts, actor, kind, subject) VALUES ('t', 'policy', 'test', 'x')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE action_log SET kind = 'y'`); err == nil {
		t.Fatal("update on action_log must fail")
	}
	if _, err := s.DB.Exec(`DELETE FROM action_log`); err == nil {
		t.Fatal("delete on action_log must fail")
	}
	if _, err := s.DB.Exec(`INSERT INTO action_log(ts, actor, kind, subject) VALUES ('t', 'model', 'test', 'x')`); err == nil {
		t.Fatal("actor 'model' must be rejected: a model may propose, never act")
	}
}

func TestMissingMeta(t *testing.T) {
	s, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, ok, err := s.GetMeta(context.Background(), "absent")
	if err != nil || ok {
		t.Fatalf("got ok=%v err=%v", ok, err)
	}
}
