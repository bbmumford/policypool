package policypool

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/bbmumford/filekind"
)

var copyIdentity = Identity{Kind: filekind.Fixture, Generation: 1, CheckOnly: true}

// TestCheckOnlyIdentityNeverStampsTheCopy: a CheckOnly identity refuses a file
// with no stamp, new or holding a schema, and leaves its header unstamped,
// where a stamping identity would have stamped the new file.
func TestCheckOnlyIdentityNeverStampsTheCopy(t *testing.T) {
	cases := []struct {
		name   string
		schema []string
		exists bool
	}{
		{"a new file", nil, false},
		{"an empty existing file", nil, true},
		{"an unstamped file with a schema", []string{"CREATE TABLE t (k INTEGER PRIMARY KEY)"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "copy.db")
			if c.exists {
				plainFile(t, path, 0, 0, c.schema...)
			}
			db, err := openIdentity(t, path, copyIdentity)
			if db != nil || !errors.Is(err, ErrFileIdentity) || !errors.Is(err, filekind.ErrUnstamped) {
				t.Fatalf("OpenFile(CheckOnly) = %v, %v, want ErrFileIdentity and ErrUnstamped", db, err)
			}
			if h, rerr := filekind.ReadFileHeader(path); rerr == nil && h != (filekind.Header{}) {
				t.Fatalf("a check-only open stamped the copy: %+v", h)
			}
		})
	}
}

// TestCheckOnlyIdentityOpensAStampedCopy: a copy carrying the kind at a
// generation the identity reads opens, its connections refuse header
// assignments, and a copy of another kind or generation is refused unchanged.
func TestCheckOnlyIdentityOpensAStampedCopy(t *testing.T) {
	ctx := context.Background()
	fixtureID := int64(filekind.Fixture.ApplicationID())
	path := filepath.Join(t.TempDir(), "copy.db")
	plainFile(t, path, fixtureID, 1, "CREATE TABLE t (k INTEGER PRIMARY KEY)")
	db, err := openIdentity(t, path, copyIdentity)
	if err != nil {
		t.Fatalf("OpenFile(CheckOnly) of a stamped copy: %v", err)
	}
	for _, s := range identityAssignments {
		if _, err := db.ExecContext(ctx, s); !errors.Is(err, ErrPolicyRefused) {
			t.Errorf("Exec(%q) = %v, want ErrPolicyRefused", s, err)
		}
	}
	for _, c := range []struct {
		name         string
		app, version int64
		reason       error
	}{
		{"another kind", int64(filekind.RunLedger.ApplicationID()), 1, filekind.ErrWrongKind},
		{"a newer generation", fixtureID, 2, filekind.ErrNewerGeneration},
	} {
		p := filepath.Join(t.TempDir(), "other.db")
		plainFile(t, p, c.app, c.version, "CREATE TABLE t (k INTEGER PRIMARY KEY)")
		if db, err := openIdentity(t, p, copyIdentity); db != nil || !errors.Is(err, c.reason) {
			t.Errorf("%s: OpenFile(CheckOnly) = %v, %v, want %v", c.name, db, err, c.reason)
		}
		if h, _ := filekind.ReadFileHeader(p); h != (filekind.Header{ApplicationID: int32(c.app), UserVersion: int32(c.version)}) {
			t.Errorf("%s: the refused copy's header moved to %+v", c.name, h)
		}
	}
}

// TestCheckIdentityChecksAPoolItDidNotOpen: CheckIdentity accepts a stamped
// file behind a plain pool, refuses an unstamped one without stamping it even
// for an identity that is not CheckOnly, refuses another kind, and refuses a
// nil pool or an identity no file carries.
func TestCheckIdentityChecksAPoolItDidNotOpen(t *testing.T) {
	ctx := context.Background()
	open := func(path string) *sql.DB {
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	dir := t.TempDir()
	stamped := filepath.Join(dir, "stamped.db")
	plainFile(t, stamped, int64(filekind.Fixture.ApplicationID()), 1)
	if err := CheckIdentity(ctx, open(stamped), fixtureIdentity); err != nil {
		t.Fatalf("CheckIdentity of a stamped file: %v", err)
	}
	empty := filepath.Join(dir, "empty.db")
	if err := CheckIdentity(ctx, open(empty), fixtureIdentity); !errors.Is(err, ErrFileIdentity) || !errors.Is(err, filekind.ErrUnstamped) {
		t.Fatalf("CheckIdentity of an unstamped file = %v, want ErrFileIdentity and ErrUnstamped", err)
	}
	if h, err := filekind.Read(ctx, open(empty)); err != nil || h != (filekind.Header{}) {
		t.Fatalf("CheckIdentity stamped the file it checked: %+v, %v", h, err)
	}
	other := filepath.Join(dir, "other.db")
	plainFile(t, other, int64(filekind.RunLedger.ApplicationID()), 1)
	if err := CheckIdentity(ctx, open(other), fixtureIdentity); !errors.Is(err, filekind.ErrWrongKind) {
		t.Fatalf("CheckIdentity of another kind = %v, want ErrWrongKind", err)
	}
	if err := CheckIdentity(ctx, nil, fixtureIdentity); !errors.Is(err, ErrPolicyRefused) {
		t.Fatalf("CheckIdentity(nil pool) = %v, want ErrPolicyRefused", err)
	}
	if err := CheckIdentity(ctx, open(stamped), Identity{Generation: 1}); !errors.Is(err, ErrPolicyRefused) {
		t.Fatalf("CheckIdentity(no kind) = %v, want ErrPolicyRefused", err)
	}
}

// TestAdvanceGenerationRefusesACheckOnlyPool: only the copy's source changes
// its format, so a CheckOnly pool cannot advance its file.
func TestAdvanceGenerationRefusesACheckOnlyPool(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "copy.db")
	plainFile(t, path, int64(filekind.Fixture.ApplicationID()), 1)
	db, err := openIdentity(t, path, copyIdentity)
	if err != nil {
		t.Fatal(err)
	}
	ran := false
	err = AdvanceGeneration(ctx, db, 2, func(context.Context, *sql.Tx) error { ran = true; return nil })
	if !errors.Is(err, ErrPolicyRefused) || ran {
		t.Fatalf("AdvanceGeneration on a CheckOnly pool = %v (migrate ran %v), want ErrPolicyRefused", err, ran)
	}
	if h, _ := filekind.ReadFileHeader(path); h.UserVersion != 1 {
		t.Fatalf("the copy's header moved to %+v", h)
	}
}
