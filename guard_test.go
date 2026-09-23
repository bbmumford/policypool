package policypool

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// offSpellings are statements the engine obeys by switching foreign-key
// enforcement off. TestEngineObeysEveryOffSpelling proves each one does so on
// modernc SQLite, so every refusal asserted below closes a path the engine
// honours rather than a spelling nothing reads.
var offSpellings = []string{
	"PRAGMA foreign_keys=OFF",
	"PRAGMA foreign_keys=0",
	"PRAGMA foreign_keys = false",
	"PRAGMA foreign_keys = no",
	"pragma FOREIGN_KEYS = Off",
	"PRAGMA\tforeign_keys\r\n=\f0",
	"PRAGMA main.foreign_keys=no",
	"PRAGMA main . foreign_keys = off",
	"PRAGMA temp.foreign_keys=false",
	`PRAGMA "main"."foreign_keys" = 'off'`,
	"PRAGMA [foreign_keys] = [off]",
	"PRAGMA `foreign_keys` = `off`",
	`PRAGMA 'foreign_keys' = "no"`,
	"PRAGMA foreign_keys(0)",
	"PRAGMA foreign_keys ( off )",
	"PRAGMA/* a */foreign_keys/* b */=/* c */off",
	"PRAGMA -- a\nforeign_keys -- b\n= -- c\noff",
	// The engine reads a value it does not recognise as true as off, and a
	// number by its low byte.
	"PRAGMA foreign_keys = -1",
	"PRAGMA foreign_keys = 256",
	"PRAGMA foreign_keys = 00",
	"PRAGMA foreign_keys = ''",
	"PRAGMA foreign_keys = full",
	"PRAGMA foreign_keys = banana",
	// U+017F folds to 's' under Unicode case folding and never under the
	// engine's ASCII comparison, so this reads as off, not yes.
	"PRAGMA foreign_keys = yeſ",
	// The assignment takes effect when the statement compiles.
	"EXPLAIN PRAGMA foreign_keys=OFF",
	"EXPLAIN QUERY PLAN PRAGMA foreign_keys=OFF",
	// Every statement of a multi-statement string runs.
	"SELECT 1; PRAGMA foreign_keys=OFF",
	"PRAGMA foreign_keys=ON; PRAGMA foreign_keys=OFF;",
	"SELECT ';'; PRAGMA foreign_keys = 0",
	"/* ; */ SELECT 1 -- ;\n; PRAGMA main.foreign_keys = false",
}

// onSpellings leave enforcement on. Refusing any of them would stop a consumer
// establishing, reading or checking the invariant this package proves.
var onSpellings = []string{
	"PRAGMA foreign_keys=ON",
	"PRAGMA foreign_keys = on",
	"pragma main.FOREIGN_KEYS = 'Yes'",
	"PRAGMA foreign_keys(1)",
	"PRAGMA foreign_keys = TRUE",
	`PRAGMA "foreign_keys" = "on"`,
	"PRAGMA foreign_keys",
	"PRAGMA main.foreign_keys",
	"PRAGMA foreign_key_check",
	"PRAGMA foreign_key_list(child)",
	"PRAGMA defer_foreign_keys = OFF",
	"SELECT 'PRAGMA foreign_keys=OFF'",
	"SELECT 1 -- PRAGMA foreign_keys=OFF",
	"/* PRAGMA foreign_keys=OFF */ SELECT 1",
	`SELECT 1 AS "PRAGMA foreign_keys=OFF"`,
	"PRAGMA foreign_keys=ON; SELECT 1",
}

type statementEntry struct {
	name string
	run  func(context.Context, *sql.Conn, string) error
}

// statementEntries reach every policyConn method that takes SQL text,
// including the context-free Prepare a caller holding the driver connection
// through sql.Conn.Raw can call directly.
var statementEntries = []statementEntry{
	{name: "exec", run: func(ctx context.Context, conn *sql.Conn, query string) error {
		_, err := conn.ExecContext(ctx, query)
		return err
	}},
	{name: "query", run: func(ctx context.Context, conn *sql.Conn, query string) error {
		rows, err := conn.QueryContext(ctx, query)
		if rows != nil {
			_ = rows.Close()
		}
		return err
	}},
	{name: "prepare", run: func(ctx context.Context, conn *sql.Conn, query string) error {
		stmt, err := conn.PrepareContext(ctx, query)
		if stmt != nil {
			_ = stmt.Close()
		}
		return err
	}},
	{name: "raw prepare", run: func(_ context.Context, conn *sql.Conn, query string) error {
		return conn.Raw(func(driverConn any) error {
			stmt, err := driverConn.(driver.Conn).Prepare(query)
			if stmt != nil {
				_ = stmt.Close()
			}
			return err
		})
	}},
}

func TestPolicyConnectionRefusesEverySpellingThatTurnsForeignKeysOff(t *testing.T) {
	for i, query := range offSpellings {
		for _, entry := range statementEntries {
			t.Run(fmt.Sprintf("%s/%02d", entry.name, i), func(t *testing.T) {
				ctx := context.Background()
				conn := pinnedModerncConnection(t)
				err := entry.run(ctx, conn, query)
				if !errors.Is(err, ErrPolicyRefused) {
					t.Fatalf("%q = %v, want a policy refusal", query, err)
				}
				if errors.Is(err, driver.ErrBadConn) {
					t.Fatalf("%q refusal carries driver.ErrBadConn, which makes database/sql retry it on another connection", query)
				}
				if strings.Contains(err.Error(), query) || strings.Contains(err.Error(), "foreign_keys") {
					t.Fatalf("refusal echoes the statement: %q", err)
				}
				assertForeignKeysEnforced(t, conn, query)
			})
		}
	}
}

func TestPolicyConnectionPassesStatementsThatLeaveForeignKeysOn(t *testing.T) {
	for i, query := range onSpellings {
		for _, entry := range statementEntries {
			t.Run(fmt.Sprintf("%s/%02d", entry.name, i), func(t *testing.T) {
				conn := pinnedModerncConnection(t)
				if err := entry.run(context.Background(), conn, query); err != nil {
					t.Fatalf("%q = %v, want it to reach the engine", query, err)
				}
				assertForeignKeysEnforced(t, conn, query)
			})
		}
	}
}

// TestEngineObeysEveryOffSpelling runs each refused spelling on a connection
// with no policy, so a spelling the engine ignores cannot sit in offSpellings
// looking like coverage.
func TestEngineObeysEveryOffSpelling(t *testing.T) {
	for i, query := range offSpellings {
		t.Run(fmt.Sprintf("%02d", i), func(t *testing.T) {
			ctx := context.Background()
			conn := unguardedModerncConnection(t)
			if _, err := conn.ExecContext(ctx, query); err != nil {
				t.Fatalf("%q: %v", query, err)
			}
			if got := foreignKeysOn(t, conn); got != 0 {
				t.Fatalf("%q left foreign_keys=%d; it does not turn enforcement off and proves nothing here", query, got)
			}
		})
	}
}

// TestEngineAppliesTheAssignmentWhenItCompiles is why PrepareContext and the
// raw Prepare are guarded and not only the entries that run a statement.
func TestEngineAppliesTheAssignmentWhenItCompiles(t *testing.T) {
	ctx := context.Background()
	conn := unguardedModerncConnection(t)
	stmt, err := conn.PrepareContext(ctx, "PRAGMA foreign_keys=OFF")
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := stmt.Close(); err != nil {
		t.Fatalf("close unexecuted statement: %v", err)
	}
	if got := foreignKeysOn(t, conn); got != 0 {
		t.Fatalf("foreign_keys=%d after preparing the assignment without running it, want 0", got)
	}
}

// TestUnrecognisedAssignmentShapesAreRefused keeps the guard an allowlist: an
// assignment to foreign_keys passes only as one token spelling on, whatever
// else the engine might make of the rest.
func TestUnrecognisedAssignmentShapesAreRefused(t *testing.T) {
	for _, query := range []string{
		"PRAGMA foreign_keys = +1",
		"PRAGMA foreign_keys = 1.0",
		"PRAGMA foreign_keys = 0x1",
		"PRAGMA foreign_keys = 'on",
		"PRAGMA foreign_keys = [on",
		"PRAGMA foreign_keys = on on",
		"PRAGMA foreign_keys off",
		"PRAGMA foreign_keys(on",
		"PRAGMA foreign_keys = ?",
	} {
		if !disablesForeignKeys(query) {
			t.Errorf("%q passed; an assignment shape the guard does not recognise must be refused", query)
		}
	}
	for _, query := range []string{
		"",
		";;",
		"SELECT 1",
		"PRAGMA",
		"PRAGMA ;",
		"PRAGMA foreign_keys . = off",
		`"PRAGMA" foreign_keys = off`,
	} {
		if disablesForeignKeys(query) {
			t.Errorf("%q refused; it is not a foreign_keys assignment", query)
		}
	}
}

func pinnedModerncConnection(t *testing.T) *sql.Conn {
	t.Helper()
	db, err := Open(context.Background(), "sqlite", filepath.Join(t.TempDir(), "guard.db"), ForeignKeysRequired)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return pinnedWithSchema(t, db)
}

func unguardedModerncConnection(t *testing.T) *sql.Conn {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "engine.db"))
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	conn := pinnedWithSchema(t, db)
	if _, err := conn.ExecContext(context.Background(), "PRAGMA foreign_keys=ON"); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if got := foreignKeysOn(t, conn); got != 1 {
		t.Fatalf("foreign_keys=%d after enabling, want 1", got)
	}
	return conn
}

func pinnedWithSchema(t *testing.T, db *sql.DB) *sql.Conn {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("Conn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	for _, statement := range []string{
		"CREATE TABLE parent (id INTEGER PRIMARY KEY)",
		"CREATE TABLE child (parent_id INTEGER NOT NULL REFERENCES parent(id))",
	} {
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	return conn
}

func foreignKeysOn(t *testing.T, conn *sql.Conn) int64 {
	t.Helper()
	var enabled int64
	if err := conn.QueryRowContext(context.Background(), "PRAGMA foreign_keys").Scan(&enabled); err != nil {
		t.Fatalf("read foreign_keys: %v", err)
	}
	return enabled
}

// assertForeignKeysEnforced checks the setting and the behaviour it stands
// for, on the connection the statement ran on.
func assertForeignKeysEnforced(t *testing.T, conn *sql.Conn, query string) {
	t.Helper()
	if got := foreignKeysOn(t, conn); got != 1 {
		t.Fatalf("after %q foreign_keys=%d, want 1", query, got)
	}
	if _, err := conn.ExecContext(context.Background(), "INSERT INTO child(parent_id) VALUES (424242)"); err == nil {
		t.Fatalf("after %q the connection admitted an orphan", query)
	}
}
