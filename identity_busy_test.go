package policypool

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbmumford/filekind"
)

// walReader opens path in WAL mode through an ordinary pool and holds a read
// transaction on it, which keeps a TRUNCATE checkpoint from finishing until
// the returned release runs.
func walReader(t *testing.T, path string) (release func()) {
	t.Helper()
	ctx := context.Background()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.ExecContext(ctx, "PRAGMA journal_mode = WAL"); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return func() { _ = tx.Rollback() }
}

// A reader holding a new file's WAL through its first stamp keeps the
// checkpoint busy: the open is answered ErrFileBusy (matching filekind's
// ErrCheckpointBusy), never ErrFileIdentity, so a cache's opener retries rather
// than rebuilding a file stamped correctly; the file carries the identity as
// the engine reads it, and a reopen once the reader is gone opens it.
func TestABusyFirstStampIsBusyNotAnIdentityRefusal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "busy.db")
	release := walReader(t, path)
	_, err := openIdentity(t, path, fixtureIdentity)
	if errors.Is(err, ErrFileIdentity) || !errors.Is(err, ErrFileBusy) || !errors.Is(err, filekind.ErrCheckpointBusy) {
		t.Fatalf("OpenFile with a reader holding the WAL = %v, want ErrFileBusy and not ErrFileIdentity", err)
	}
	release()
	db, err := openIdentity(t, path, fixtureIdentity)
	if err != nil {
		t.Fatalf("reopening after the reader left = %v", err)
	}
	h, err := filekind.Read(context.Background(), db)
	if err != nil || h != (filekind.Header{ApplicationID: filekind.Fixture.ApplicationID(), UserVersion: 1}) {
		t.Fatalf("header read through the engine after the reopen = %+v, %v", h, err)
	}
}

// A reader that leaves while the first stamp's checkpoint is retried lets the
// open finish: the busy checkpoint is retried, and the header reaches the file.
func TestAFirstStampWaitsOutABriefReader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "brief.db")
	release := walReader(t, path)
	go func() {
		time.Sleep(30 * time.Millisecond)
		release()
	}()
	if _, err := openIdentity(t, path, fixtureIdentity); err != nil {
		t.Fatalf("OpenFile with a reader leaving after 30ms = %v, want the open", err)
	}
	h, err := filekind.ReadFileHeader(path)
	if err != nil || h != (filekind.Header{ApplicationID: filekind.Fixture.ApplicationID(), UserVersion: 1}) {
		t.Fatalf("header after the open = %+v, %v", h, err)
	}
}
