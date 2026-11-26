package policypool

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/bbmumford/filekind"
)

// Every new physical connection of an identity pool reads its own file's kind
// before it is used: a file replaced at the path by one of another kind after
// the pool opened is refused with ErrFileIdentity, and a file of the pool's
// kind at another generation is served.
func TestANewConnectionChecksTheFileItOpened(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.db")
	db, err := openIdentity(t, path, fixtureIdentity)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxIdleConns(0)
	if _, err := db.ExecContext(ctx, "SELECT 1"); err != nil {
		t.Fatalf("a query on the opened pool = %v", err)
	}
	other := filepath.Join(dir, "other.db")
	plainFile(t, other, int64(filekind.RunLedger.ApplicationID()), 1, "CREATE TABLE x (a)")
	if err := os.Rename(other, path); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "SELECT 1"); !errors.Is(err, ErrFileIdentity) || !errors.Is(err, filekind.ErrWrongKind) {
		t.Fatalf("a query once the file is another kind's = %v, want ErrFileIdentity (wrong kind)", err)
	}
	newer := filepath.Join(dir, "newer.db")
	plainFile(t, newer, int64(filekind.Fixture.ApplicationID()), 5, "CREATE TABLE y (a)")
	if err := os.Rename(newer, path); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "SELECT 1"); err != nil {
		t.Fatalf("a query on a file of the pool's kind at another generation = %v", err)
	}
}
