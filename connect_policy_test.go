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

// TestConnectOnlyPolicyProvesEachPhysicalConnectionOnce is the property the
// connect-only policy exists for: a reused connection costs no proof. The
// ForeignKeysRequired rows are the control, one proof at connect plus one per
// reuse, so a connect-only pool that re-proved would read like them.
func TestConnectOnlyPolicyProvesEachPhysicalConnectionOnce(t *testing.T) {
	const reuses = 20
	for _, test := range []struct {
		name        string
		policy      ConnectionPolicy
		state       int64
		wantQueries int
		wantEnables int
	}{
		{name: "connect only, engine starts on", policy: ForeignKeysRequiredAtConnect, state: 1, wantQueries: 1},
		{name: "connect only, engine starts off", policy: ForeignKeysRequiredAtConnect, state: 0, wantQueries: 2, wantEnables: 1},
		{name: "control, engine starts on", policy: ForeignKeysRequired, state: 1, wantQueries: 1 + reuses},
		{name: "control, engine starts off", policy: ForeignKeysRequired, state: 0, wantQueries: 2 + reuses, wantEnables: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			scenario := &hostileScenario{plans: []hostilePlan{{state: test.state}}}
			db, err := OpenConnector(context.Background(), &dsnConnector{base: scenario, dsn: "ignored"}, test.policy)
			if err != nil {
				t.Fatalf("OpenConnector: %v", err)
			}
			t.Cleanup(func() { _ = db.Close() })
			db.SetMaxOpenConns(1)

			for i := 0; i < reuses; i++ {
				if _, err := db.ExecContext(context.Background(), "WORK"); err != nil {
					t.Fatalf("use %d: %v", i, err)
				}
			}
			got := scenario.snapshot()
			if got.opens != 1 || got.runtimeByConnection[0] != reuses {
				t.Fatalf("physical use = %+v, want one connection used %d times", got, reuses)
			}
			if got.queries != test.wantQueries || got.enables != test.wantEnables {
				t.Fatalf("proofs = %d reads and %d establishes, want %d and %d: %+v",
					got.queries, got.enables, test.wantQueries, test.wantEnables, got)
			}
			if got.uninitialized != 0 {
				t.Fatalf("a statement ran without enforcement: %+v", got)
			}
		})
	}
}

// TestConnectOnlyPolicyProvesEveryNewPhysicalConnection keeps the connect-time
// proof on every connection a growing pool opens, not only the first.
func TestConnectOnlyPolicyProvesEveryNewPhysicalConnection(t *testing.T) {
	const physical = 4
	scenario := &hostileScenario{factory: func(int) hostilePlan { return hostilePlan{state: 0} }}
	db, err := OpenConnector(context.Background(), &dsnConnector{base: scenario, dsn: "ignored"}, ForeignKeysRequiredAtConnect)
	if err != nil {
		t.Fatalf("OpenConnector: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(physical)
	db.SetMaxIdleConns(physical)

	held := make([]*sql.Conn, physical)
	for i := range held {
		if held[i], err = db.Conn(context.Background()); err != nil {
			t.Fatalf("Conn %d: %v", i, err)
		}
	}
	for i, conn := range held {
		if _, err := conn.ExecContext(context.Background(), "WORK"); err != nil {
			t.Fatalf("connection %d use: %v", i, err)
		}
		if err := conn.Close(); err != nil {
			t.Fatalf("connection %d return: %v", i, err)
		}
	}
	for i := 0; i < 10; i++ {
		if _, err := db.ExecContext(context.Background(), "WORK"); err != nil {
			t.Fatalf("reuse %d: %v", i, err)
		}
	}
	got := scenario.snapshot()
	if got.opens != physical || got.enables != physical || got.queries != 2*physical || got.uninitialized != 0 {
		t.Fatalf("proofs = %+v, want each of %d connections established and read back twice, once", got, physical)
	}
}

// TestConnectOnlyPolicyRefusesEverySpellingThatTurnsForeignKeysOff is the
// guard under the connect-only policy, where nothing proves the setting again
// after Connect: every off spelling is refused at every entry that takes SQL
// text, with ErrPolicyRefused and never driver.ErrBadConn.
func TestConnectOnlyPolicyRefusesEverySpellingThatTurnsForeignKeysOff(t *testing.T) {
	for i, query := range offSpellings {
		for _, entry := range statementEntries {
			t.Run(fmt.Sprintf("%s/%02d", entry.name, i), func(t *testing.T) {
				conn := pinnedModerncConnectionUnder(t, ForeignKeysRequiredAtConnect)
				err := entry.run(context.Background(), conn, query)
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

// TestConnectOnlyPolicyPassesStatementsThatLeaveForeignKeysOn is the guard's
// other side: it must not refuse the statements that read, establish or check
// the setting.
func TestConnectOnlyPolicyPassesStatementsThatLeaveForeignKeysOn(t *testing.T) {
	for i, query := range onSpellings {
		for _, entry := range statementEntries {
			t.Run(fmt.Sprintf("%s/%02d", entry.name, i), func(t *testing.T) {
				conn := pinnedModerncConnectionUnder(t, ForeignKeysRequiredAtConnect)
				if err := entry.run(context.Background(), conn, query); err != nil {
					t.Fatalf("%q = %v, want it to reach the engine", query, err)
				}
				assertForeignKeysEnforced(t, conn, query)
			})
		}
	}
}

// TestConnectOnlyPoolKeepsEnforcementAcrossReuse runs every off spelling
// through one pooled physical connection and then uses it again. Under this
// policy no reset re-proves the setting, so an off statement that reached the
// engine would leave every later statement on that connection accepting
// orphans.
func TestConnectOnlyPoolKeepsEnforcementAcrossReuse(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, "sqlite", filepath.Join(t.TempDir(), "reuse.db"), ForeignKeysRequiredAtConnect)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)
	for _, statement := range []string{
		"CREATE TEMP TABLE same_connection (x INTEGER)",
		"CREATE TABLE parent (id INTEGER PRIMARY KEY)",
		"CREATE TABLE child (parent_id INTEGER NOT NULL REFERENCES parent(id))",
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	for _, query := range offSpellings {
		if _, err := db.ExecContext(ctx, query); !errors.Is(err, ErrPolicyRefused) {
			t.Fatalf("%q = %v, want a policy refusal", query, err)
		}
	}
	for _, query := range onSpellings {
		if _, err := db.ExecContext(ctx, query); err != nil {
			t.Fatalf("%q = %v, want it to reach the engine", query, err)
		}
	}
	// A temporary table belongs to the connection that made it, so reading it
	// shows the checks below ran on the connection every statement above used.
	if _, err := db.ExecContext(ctx, "SELECT count(*) FROM temp.same_connection"); err != nil {
		t.Fatalf("the pool replaced its connection, so reuse was not exercised: %v", err)
	}
	var enabled int64
	if err := db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&enabled); err != nil || enabled != 1 {
		t.Fatalf("foreign_keys = %d (%v) on the reused connection, want 1", enabled, err)
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO child(parent_id) VALUES (424242)"); err == nil {
		t.Fatal("the reused connection admitted an orphan")
	}
}

// TestConnectOnlyPolicyRefusesAnUnprovedConnection keeps the connect-time
// proof load-bearing: a connection whose engine does not show enforcement is
// refused whether it is the pool's first or a later one, which is what stops a
// connection opened while the primary is unreachable from serving.
func TestConnectOnlyPolicyRefusesAnUnprovedConnection(t *testing.T) {
	secret := "password=never-disclose"
	for _, test := range []struct {
		name string
		plan hostilePlan
	}{
		{name: "setting does not take", plan: hostilePlan{state: 0, refuseEnable: true}},
		{name: "out of range", plan: hostilePlan{rows: []hostileRows{singleRow(int64(2))}}},
		{name: "read-back fails", plan: hostilePlan{queryErr: errors.New(secret)}},
	} {
		t.Run("first/"+test.name, func(t *testing.T) {
			scenario := &hostileScenario{plans: []hostilePlan{test.plan}}
			db, err := OpenConnector(context.Background(), &dsnConnector{base: scenario, dsn: "dsn=" + secret}, ForeignKeysRequiredAtConnect)
			if db != nil {
				_ = db.Close()
				t.Fatal("OpenConnector published a pool without a proof")
			}
			wantKind := ErrPolicyUnproved
			if test.plan.queryErr != nil {
				wantKind = ErrDriverFailed
			}
			if !errors.Is(err, wantKind) || strings.Contains(err.Error(), secret) {
				t.Fatalf("OpenConnector = %v, want %v with nothing of the cause", err, wantKind)
			}
			if got := scenario.snapshot(); got.opens != 1 || got.closes != 1 {
				t.Fatalf("unpublished connection was not closed exactly once: %+v", got)
			}
		})
	}

	t.Run("later", func(t *testing.T) {
		scenario := &hostileScenario{factory: func(index int) hostilePlan {
			if index == 0 {
				return hostilePlan{state: 1}
			}
			return hostilePlan{state: 0, refuseEnable: true}
		}}
		db, err := OpenConnector(context.Background(), &dsnConnector{base: scenario, dsn: "ignored"}, ForeignKeysRequiredAtConnect)
		if err != nil {
			t.Fatalf("OpenConnector: %v", err)
		}
		t.Cleanup(func() { _ = db.Close() })
		first, err := db.Conn(context.Background())
		if err != nil {
			t.Fatalf("first Conn: %v", err)
		}
		defer first.Close()
		second, err := db.Conn(context.Background())
		if second != nil {
			_ = second.Close()
		}
		if !errors.Is(err, ErrPolicyUnproved) {
			t.Fatalf("second physical connection = %v, want ErrPolicyUnproved", err)
		}
		got := scenario.snapshot()
		if got.opens != 2 || got.closedByConnection[1] != 1 || got.runtimeByConnection[1] != 0 {
			t.Fatalf("the unproved connection was used or kept: %+v", got)
		}
	})
}

// TestConnectOnlyResetStillRunsTheDriversReset keeps the half of ResetSession
// the connect-only policy does not skip: a driver that reports its connection
// unusable at reset still has it discarded and replaced by a proved one.
func TestConnectOnlyResetStillRunsTheDriversReset(t *testing.T) {
	secret := "reset-secret=never-disclose"
	scenario := &hostileScenario{plans: []hostilePlan{
		{state: 1, resetErr: errors.New(secret)},
		{state: 0},
	}}
	db, err := OpenConnector(context.Background(), &dsnConnector{base: scenario, dsn: "ignored"}, ForeignKeysRequiredAtConnect)
	if err != nil {
		t.Fatalf("OpenConnector: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.ExecContext(context.Background(), "WORK"); err != nil {
		t.Fatalf("use after a failed reset: %v", err)
	}
	got := scenario.snapshot()
	if got.opens != 2 || got.closedByConnection[0] != 1 {
		t.Fatalf("the connection whose reset failed was not replaced: %+v", got)
	}
	if got.runtimeByConnection[0] != 0 || got.runtimeByConnection[1] != 1 || got.enables != 1 || got.uninitialized != 0 {
		t.Fatalf("the statement did not run on a freshly proved replacement: %+v", got)
	}
}

// TestUndefinedPoliciesAreRefused covers every place a policy value is read. A
// value past the defined ones opens nothing, and a connection carrying one is
// discarded at reset rather than kept without a proof.
func TestUndefinedPoliciesAreRefused(t *testing.T) {
	for _, policy := range []ConnectionPolicy{0, ForeignKeysRequiredAtConnect + 1, 255} {
		t.Run(fmt.Sprintf("policy_%d", policy), func(t *testing.T) {
			scenario := &hostileScenario{plans: []hostilePlan{{state: 1}}}
			db, err := Open(context.Background(), registerHostileDriver(t, scenario), "ignored", policy)
			if db != nil || !errors.Is(err, ErrPolicyRefused) {
				t.Fatalf("Open = (%v, %v), want ErrPolicyRefused", db, err)
			}
			db, err = OpenConnector(context.Background(), &dsnConnector{base: scenario, dsn: "ignored"}, policy)
			if db != nil || !errors.Is(err, ErrPolicyRefused) {
				t.Fatalf("OpenConnector = (%v, %v), want ErrPolicyRefused", db, err)
			}
			if got := scenario.snapshot(); got.opens != 0 {
				t.Fatalf("an undefined policy opened %d physical connections", got.opens)
			}

			raw, err := scenario.Open("ignored")
			if err != nil {
				t.Fatalf("raw open: %v", err)
			}
			defer raw.Close()
			if err := enforce(context.Background(), raw, policy); !errors.Is(err, ErrPolicyRefused) {
				t.Fatalf("enforce = %v, want ErrPolicyRefused", err)
			}
			err = (&policyConn{Conn: raw, policy: policy}).ResetSession(context.Background())
			if !errors.Is(err, driver.ErrBadConn) || !errors.Is(err, ErrPolicyRefused) {
				t.Fatalf("ResetSession = %v, want the connection discarded as refused", err)
			}
			if got := scenario.snapshot(); got.queries != 0 {
				t.Fatalf("an undefined policy ran %d proofs", got.queries)
			}
		})
	}
}

func pinnedModerncConnectionUnder(t *testing.T, policy ConnectionPolicy) *sql.Conn {
	t.Helper()
	db, err := Open(context.Background(), "sqlite", filepath.Join(t.TempDir(), "guard.db"), policy)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return pinnedWithSchema(t, db)
}
