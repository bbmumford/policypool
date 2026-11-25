package policypool

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/bbmumford/filekind"
	_ "modernc.org/sqlite"
)

var fixtureIdentity = Identity{Kind: filekind.Fixture, Generation: 1}

func openIdentity(t *testing.T, path string, id Identity) (*sql.DB, error) {
	t.Helper()
	db, err := OpenFile(context.Background(), "sqlite", path, ForeignKeysRequired, id)
	if db != nil {
		t.Cleanup(func() { _ = db.Close() })
	}
	return db, err
}

// plainFile writes a file through an ordinary pool, with the header given.
func plainFile(t *testing.T, path string, app, version int64, statements ...string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Errorf("db.Close: %v", err)
		}
	}()
	all := append(statements, fmt.Sprintf("PRAGMA application_id = %d", app), fmt.Sprintf("PRAGMA user_version = %d", version))
	for _, s := range all {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
}

// TestOpenFileStampsANewFile: a new file opened with an Identity carries its
// kind and generation in the header bytes once OpenFile returns.
func TestOpenFileStampsANewFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new.db")
	if _, err := openIdentity(t, path, fixtureIdentity); err != nil {
		t.Fatal(err)
	}
	h, err := filekind.ReadFileHeader(path)
	if err != nil || h != (filekind.Header{ApplicationID: filekind.Fixture.ApplicationID(), UserVersion: 1}) {
		t.Fatalf("header after OpenFile = %+v, %v", h, err)
	}
	if _, err := openIdentity(t, path, fixtureIdentity); err != nil {
		t.Fatalf("reopening the stamped file: %v", err)
	}
}

func TestOpenFileStampsOnceUnderARace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "race.db") + "?_pragma=busy_timeout(10000)"
	var wg sync.WaitGroup
	errs := make([]error, 6)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			db, err := OpenFile(context.Background(), "sqlite", path, ForeignKeysRequired, fixtureIdentity)
			if err == nil {
				_ = db.Close()
			}
			errs[i] = err
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("opener %d: %v", i, err)
		}
	}
}

// TestOpenFileRefusesAFileOfAnotherIdentity: each header the Identity does not
// accept is ErrFileIdentity carrying filekind's reason, and no pool is
// returned.
func TestOpenFileRefusesAFileOfAnotherIdentity(t *testing.T) {
	fixtureID := int64(filekind.Fixture.ApplicationID())
	cases := []struct {
		name         string
		app, version int64
		schema       []string
		id           Identity
		reason       error
	}{
		{"another kind", int64(filekind.RunLedger.ApplicationID()), 2, nil, fixtureIdentity, filekind.ErrWrongKind},
		{"another application", 0x12345678, 1, nil, fixtureIdentity, filekind.ErrForeignFile},
		{"an unknown kind", 0x4F5242EE, 1, nil, fixtureIdentity, filekind.ErrUnknownKind},
		{"a newer generation", fixtureID, 2, nil, fixtureIdentity, filekind.ErrNewerGeneration},
		{"an older generation", fixtureID, 1, nil, Identity{Kind: filekind.Fixture, Generation: 2}, filekind.ErrOlderGeneration},
		{"no generation", fixtureID, 0, nil, fixtureIdentity, filekind.ErrNoGeneration},
		{"unstamped with a schema", 0, 0, []string{"CREATE TABLE t (k INTEGER PRIMARY KEY)"}, fixtureIdentity, filekind.ErrUnstamped},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "f.db")
			plainFile(t, path, c.app, c.version, c.schema...)
			db, err := openIdentity(t, path, c.id)
			if db != nil || !errors.Is(err, ErrFileIdentity) || !errors.Is(err, c.reason) {
				t.Fatalf("OpenFile = %v, %v, want ErrFileIdentity and %v", db, err, c.reason)
			}
			h, rerr := filekind.ReadFileHeader(path)
			if rerr != nil || h != (filekind.Header{ApplicationID: int32(c.app), UserVersion: int32(c.version)}) {
				t.Fatalf("a refused open changed the header to %+v, %v", h, rerr)
			}
		})
	}
}

func TestOpenFileReadsTheOldestDeclared(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.db")
	plainFile(t, path, int64(filekind.Fixture.ApplicationID()), 1)
	if _, err := openIdentity(t, path, Identity{Kind: filekind.Fixture, Generation: 2, Oldest: 1}); err != nil {
		t.Fatalf("a release that still reads generation 1: %v", err)
	}
}

func TestOpenFileRefusesAnIdentityNoFileCarries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.db")
	for _, id := range []Identity{
		{Kind: 0xEE, Generation: 1},
		{Kind: filekind.Fixture, Generation: 0},
		{Kind: filekind.Fixture, Generation: 1, Oldest: 2},
		{Kind: filekind.Fixture, Generation: 1, Oldest: -1},
	} {
		if db, err := openIdentity(t, path, id); db != nil || !errors.Is(err, ErrPolicyRefused) {
			t.Fatalf("OpenFile(%+v) = %v, %v, want ErrPolicyRefused", id, db, err)
		}
	}
}

// identityAssignments are statements that would change what a file says it is.
var identityAssignments = []string{
	"PRAGMA user_version = 5",
	"PRAGMA application_id = 1",
	"pragma USER_VERSION=0",
	"PRAGMA main.user_version = 5",
	`PRAGMA "main"."application_id" = 7`,
	"PRAGMA user_version(5)",
	"PRAGMA [application_id] (1)",
	"EXPLAIN PRAGMA user_version = 2",
	"EXPLAIN QUERY PLAN PRAGMA application_id = 2",
	"SELECT 1; PRAGMA user_version = 2",
	"PRAGMA/* a */user_version/* b */=/* c */9",
}

// TestOpenFilePoolRefusesHeaderAssignments: every connection of an identity
// pool refuses each spelling, through every entry that takes SQL, and the bare
// read passes.
func TestOpenFilePoolRefusesHeaderAssignments(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "f.db")
	db, err := openIdentity(t, path, fixtureIdentity)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range identityAssignments {
		if _, err := db.ExecContext(ctx, s); !errors.Is(err, ErrPolicyRefused) {
			t.Errorf("Exec(%q) = %v, want ErrPolicyRefused", s, err)
		}
		if _, err := db.QueryContext(ctx, s); !errors.Is(err, ErrPolicyRefused) {
			t.Errorf("Query(%q) = %v, want ErrPolicyRefused", s, err)
		}
		if _, err := db.PrepareContext(ctx, s); !errors.Is(err, ErrPolicyRefused) {
			t.Errorf("Prepare(%q) = %v, want ErrPolicyRefused", s, err)
		}
	}
	if h, err := filekind.Check(ctx, db, filekind.Want{Kind: filekind.Fixture, Newest: 1}); err != nil {
		t.Fatalf("the bare reads: %+v, %v", h, err)
	}
	if h, _ := filekind.ReadFileHeader(path); h.UserVersion != 1 {
		t.Fatalf("the header moved to %+v", h)
	}
}

// TestOpenLeavesHeaderAssignmentsToItsCaller: a pool opened without an
// Identity is unchanged, and still lets its caller set either field.
func TestOpenLeavesHeaderAssignmentsToItsCaller(t *testing.T) {
	db, err := Open(context.Background(), "sqlite", filepath.Join(t.TempDir(), "f.db"), ForeignKeysRequired)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Errorf("db.Close: %v", err)
		}
	}()
	for _, s := range []string{"PRAGMA user_version = 5", "PRAGMA application_id = 1"} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("Exec(%q) on a pool without an Identity: %v", s, err)
		}
	}
}

func TestAdvanceGenerationMovesTheFormatWithItsMigration(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "f.db")
	db, err := openIdentity(t, path, fixtureIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE t (k INTEGER PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	failing := errors.New("migration failed")
	err = AdvanceGeneration(ctx, db, 2, func(ctx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "ALTER TABLE t ADD COLUMN v TEXT"); err != nil {
			return err
		}
		return failing
	})
	if !errors.Is(err, failing) {
		t.Fatalf("a failing migration = %v", err)
	}
	if h, _ := filekind.ReadFileHeader(path); h.UserVersion != 1 {
		t.Fatalf("a failed migration moved the generation to %d", h.UserVersion)
	}
	if _, err := db.Exec("SELECT v FROM t"); err == nil {
		t.Fatal("a failed migration kept its column")
	}

	err = AdvanceGeneration(ctx, db, 2, func(ctx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "PRAGMA user_version = 9"); !errors.Is(err, ErrPolicyRefused) {
			return fmt.Errorf("migrate set the header: %v", err)
		}
		_, err := tx.ExecContext(ctx, "ALTER TABLE t ADD COLUMN v TEXT")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if h, err := filekind.ReadFileHeader(path); err != nil || h.UserVersion != 2 {
		t.Fatalf("after AdvanceGeneration the file holds %+v, %v", h, err)
	}
	if _, err := db.Exec("SELECT v FROM t"); err != nil {
		t.Fatalf("the migration's column: %v", err)
	}
	if _, err := db.Exec("PRAGMA user_version = 3"); !errors.Is(err, ErrPolicyRefused) {
		t.Fatalf("the refusal is lifted after AdvanceGeneration: %v", err)
	}
	if err := AdvanceGeneration(ctx, db, 1, func(context.Context, *sql.Tx) error { return nil }); !errors.Is(err, ErrFileIdentity) ||
		!errors.Is(err, filekind.ErrNewerGeneration) {
		t.Fatalf("lowering the generation = %v", err)
	}

	plain, err := Open(ctx, "sqlite", filepath.Join(t.TempDir(), "p.db"), ForeignKeysRequired)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := plain.Close(); err != nil {
			t.Errorf("plain.Close: %v", err)
		}
	}()
	if err := AdvanceGeneration(ctx, plain, 2, func(context.Context, *sql.Tx) error { return nil }); !errors.Is(err, ErrPolicyRefused) {
		t.Fatalf("AdvanceGeneration on a pool without an Identity = %v", err)
	}
}
