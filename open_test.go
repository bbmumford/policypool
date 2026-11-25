package policypool

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	_ "modernc.org/sqlite"
)

func TestOpenEstablishesAndVerifiesBeforePublication(t *testing.T) {
	scenario := &hostileScenario{plans: []hostilePlan{{state: 0}}}
	driverName := registerHostileDriver(t, scenario)

	db, err := Open(context.Background(), driverName, "ignored", ForeignKeysRequired)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	got := scenario.snapshot()
	if got.opens != 1 || got.queries != 2 || got.enables != 1 {
		t.Fatalf("eager enforcement = %+v, want one open, two proofs, one establish", got)
	}
	if got.uninitialized != 0 {
		t.Fatalf("published an uninitialized connection: %+v", got)
	}
}

func TestOpenAlreadyEnabledIsQueryOnly(t *testing.T) {
	scenario := &hostileScenario{plans: []hostilePlan{{state: 1}}}
	driverName := registerHostileDriver(t, scenario)

	db, err := Open(context.Background(), driverName, "ignored", ForeignKeysRequired)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	got := scenario.snapshot()
	if got.opens != 1 || got.queries != 1 || got.enables != 0 {
		t.Fatalf("query-only verification = %+v, want one proof and no mutation", got)
	}
}

func TestPolicyUsesPreparedStatementFallback(t *testing.T) {
	driverName := fmt.Sprintf("policypool_prepared_%d", hostileDriverSequence.Add(1))
	prepared := &preparedOnlyDriver{}
	sql.Register(driverName, prepared)

	db, err := Open(context.Background(), driverName, "ignored", ForeignKeysRequired)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.ExecContext(context.Background(), "WORK"); err != nil {
		t.Fatalf("prepared application execution: %v", err)
	}
	prepared.mu.Lock()
	defer prepared.mu.Unlock()
	if prepared.opens != 1 || prepared.queries < 2 || prepared.enables != 1 || prepared.uninitialized != 0 {
		t.Fatalf("prepared fallback state: %+v", prepared)
	}
}

func TestOpenRejectsUnprovedConnections(t *testing.T) {
	secret := "password=never-disclose"
	tests := []struct {
		name string
		plan hostilePlan
	}{
		{name: "missing row", plan: hostilePlan{rows: []hostileRows{{columns: []string{"foreign_keys"}}}}},
		{name: "malformed string", plan: hostilePlan{rows: []hostileRows{singleRow("1")}}},
		{name: "out of range", plan: hostilePlan{rows: []hostileRows{singleRow(int64(2))}}},
		{
			name: "extra row",
			plan: hostilePlan{rows: []hostileRows{{
				columns: []string{"foreign_keys"},
				values:  [][]driver.Value{{int64(1)}, {int64(1)}},
			}}},
		},
		{
			name: "extra column",
			plan: hostilePlan{rows: []hostileRows{{
				columns: []string{"foreign_keys", "ambiguous"},
				values:  [][]driver.Value{{int64(1), int64(1)}},
			}}},
		},
		{name: "rows close failure", plan: hostilePlan{rows: []hostileRows{{columns: []string{"foreign_keys"}, values: [][]driver.Value{{int64(1)}}, closeErr: errors.New(secret)}}}},
		{name: "rows iteration failure", plan: hostilePlan{rows: []hostileRows{{columns: []string{"foreign_keys"}, values: [][]driver.Value{{int64(1)}}, nextErr: errors.New(secret)}}}},
		{name: "query unsupported", plan: hostilePlan{queryErr: errors.New(secret)}},
		{name: "ambiguous rows and skip", plan: hostilePlan{state: 1, queryErr: driver.ErrSkip, queryRowsOnError: true}},
		{name: "establish unsupported", plan: hostilePlan{state: 0, enableErr: errors.New(secret)}},
		{name: "establish mismatch", plan: hostilePlan{state: 0, refuseEnable: true}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scenario := &hostileScenario{plans: []hostilePlan{test.plan}}
			driverName := registerHostileDriver(t, scenario)
			db, err := Open(context.Background(), driverName, "dsn="+secret, ForeignKeysRequired)
			if err == nil || db != nil {
				if db != nil {
					_ = db.Close()
				}
				t.Fatal("Open succeeded without an exact proof")
			}
			if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), driverName) {
				t.Fatalf("unredacted error: %q", err)
			}
			if got := scenario.snapshot(); got.opens != 1 || got.closes != 1 {
				t.Fatalf("unpublished connection was not closed exactly once: %+v", got)
			}
		})
	}
}

func TestOpenRejectsInvalidPolicyAndRedactsOpenFailure(t *testing.T) {
	for _, policy := range []ConnectionPolicy{0, ForeignKeysRequiredAtConnect + 1, 255} {
		t.Run(fmt.Sprintf("policy_%d", policy), func(t *testing.T) {
			scenario := &hostileScenario{plans: []hostilePlan{{state: 1}}}
			driverName := registerHostileDriver(t, scenario)
			db, err := Open(context.Background(), driverName, "ignored", policy)
			if err == nil || db != nil {
				t.Fatalf("Open policy %d = (%v, %v), want refusal", policy, db, err)
			}
			if got := scenario.snapshot(); got.opens != 0 {
				t.Fatalf("invalid policy opened %d physical connections", got.opens)
			}
		})
	}

	secret := "token=top-secret"
	scenario := &hostileScenario{openErr: errors.New(secret)}
	driverName := registerHostileDriver(t, scenario)
	db, err := Open(context.Background(), driverName, "dsn="+secret, ForeignKeysRequired)
	if err == nil || db != nil {
		t.Fatalf("Open = (%v, %v), want redacted failure", db, err)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), driverName) {
		t.Fatalf("unredacted open error: %q", err)
	}

	unknown := "unregistered-" + secret
	db, err = Open(context.Background(), unknown, "dsn="+secret, ForeignKeysRequired)
	if err == nil || db != nil {
		t.Fatalf("unknown driver Open = (%v, %v), want failure", db, err)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), unknown) {
		t.Fatalf("unredacted unknown-driver error: %q", err)
	}
}

func TestOpenPreservesCancellationAndBadConnectionIdentity(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	scenario := &hostileScenario{plans: []hostilePlan{{state: 1}}}
	driverName := registerHostileDriver(t, scenario)
	if db, err := Open(canceled, driverName, "ignored", ForeignKeysRequired); db != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("entry cancellation = (%v, %v), want context.Canceled", db, err)
	}
	if got := scenario.snapshot(); got.opens != 0 {
		t.Fatalf("entry cancellation opened %d connections", got.opens)
	}

	// Use a driver result to prove DeadlineExceeded identity independently of
	// wall-clock timing.
	scenario = &hostileScenario{plans: []hostilePlan{{queryErr: context.DeadlineExceeded}}}
	driverName = registerHostileDriver(t, scenario)
	if db, err := Open(context.Background(), driverName, "ignored", ForeignKeysRequired); db != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline failure = (%v, %v), want DeadlineExceeded", db, err)
	}

	scenario = &hostileScenario{plans: []hostilePlan{{queryErr: driver.ErrBadConn}}}
	driverName = registerHostileDriver(t, scenario)
	if db, err := Open(context.Background(), driverName, "ignored", ForeignKeysRequired); db != nil || !errors.Is(err, driver.ErrBadConn) {
		t.Fatalf("bad connection = (%v, %v), want driver.ErrBadConn", db, err)
	}
}

func TestOpenClosesPostConnectAndPrePublicationCancellation(t *testing.T) {
	t.Run("post connect", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		scenario := &hostileScenario{
			plans:  []hostilePlan{{state: 1}},
			onOpen: func(int) { cancel() },
		}
		driverName := registerHostileDriver(t, scenario)
		db, err := Open(ctx, driverName, "ignored", ForeignKeysRequired)
		if db != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("Open = (%v, %v), want post-connect cancellation", db, err)
		}
		if got := scenario.snapshot(); got.opens != 1 || got.closes != 1 {
			t.Fatalf("post-connect cancellation leaked connection: %+v", got)
		}
	})

	t.Run("pre publication", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		row := singleRow(int64(1))
		row.onClose = cancel
		scenario := &hostileScenario{plans: []hostilePlan{{rows: []hostileRows{row}}}}
		driverName := registerHostileDriver(t, scenario)
		db, err := Open(ctx, driverName, "ignored", ForeignKeysRequired)
		if db != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("Open = (%v, %v), want pre-publication cancellation", db, err)
		}
		if got := scenario.snapshot(); got.opens != 1 || got.closes != 1 {
			t.Fatalf("pre-publication cancellation leaked connection: %+v", got)
		}
	})
}

func TestEveryPhysicalConnectionIsVerifiedBeforeUse(t *testing.T) {
	scenario := &hostileScenario{factory: func(int) hostilePlan { return hostilePlan{state: 0} }}
	driverName := registerHostileDriver(t, scenario)
	db, err := Open(context.Background(), driverName, "ignored", ForeignKeysRequired)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(8)

	connections := make([]*sql.Conn, 8)
	for i := range connections {
		connections[i], err = db.Conn(context.Background())
		if err != nil {
			t.Fatalf("Conn %d: %v", i, err)
		}
	}
	var wg sync.WaitGroup
	for i, conn := range connections {
		wg.Add(1)
		go func(i int, conn *sql.Conn) {
			defer wg.Done()
			defer func() {
				if err := conn.Close(); err != nil {
					t.Errorf("conn.Close: %v", err)
				}
			}()
			if _, err := conn.ExecContext(context.Background(), "WORK", i); err != nil {
				t.Errorf("connection %d use: %v", i, err)
			}
		}(i, conn)
	}
	wg.Wait()

	got := scenario.snapshot()
	if got.opens != 8 || got.enables != 8 || got.uninitialized != 0 {
		t.Fatalf("physical enforcement = %+v, want 8 established and no uninitialized use", got)
	}
}

func TestBadConnectionReplacementIsReverified(t *testing.T) {
	scenario := &hostileScenario{factory: func(index int) hostilePlan {
		return hostilePlan{state: 1, badRuntimeOnce: index == 0}
	}}
	driverName := registerHostileDriver(t, scenario)
	db, err := Open(context.Background(), driverName, "ignored", ForeignKeysRequired)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if _, err := db.ExecContext(context.Background(), "WORK"); err != nil {
		t.Fatalf("replacement retry: %v", err)
	}
	got := scenario.snapshot()
	if got.opens < 2 || got.queries < 2 || got.uninitialized != 0 {
		t.Fatalf("replacement was not reverified: %+v", got)
	}
}

func TestModerncTwoPhysicalConnectionsRejectOrphans(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "policypool.db")
	db, err := Open(context.Background(), "sqlite", dsn, ForeignKeysRequired)
	if err != nil {
		t.Fatalf("Open modernc SQLite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(2)

	first, err := db.Conn(context.Background())
	if err != nil {
		t.Fatalf("first Conn: %v", err)
	}
	defer func() {
		if err := first.Close(); err != nil {
			t.Errorf("first.Close: %v", err)
		}
	}()
	second, err := db.Conn(context.Background())
	if err != nil {
		t.Fatalf("second Conn: %v", err)
	}
	defer func() {
		if err := second.Close(); err != nil {
			t.Errorf("second.Close: %v", err)
		}
	}()

	for i, conn := range []*sql.Conn{first, second} {
		var enabled int64
		if err := conn.QueryRowContext(context.Background(), "PRAGMA foreign_keys").Scan(&enabled); err != nil {
			t.Fatalf("connection %d proof: %v", i+1, err)
		}
		if enabled != 1 {
			t.Fatalf("connection %d foreign_keys = %d, want 1", i+1, enabled)
		}
	}
	if _, err := first.ExecContext(context.Background(), "CREATE TABLE parent (id INTEGER PRIMARY KEY)"); err != nil {
		t.Fatalf("create parent: %v", err)
	}
	if _, err := first.ExecContext(context.Background(), "CREATE TABLE child (parent_id INTEGER NOT NULL REFERENCES parent(id))"); err != nil {
		t.Fatalf("create child: %v", err)
	}
	for i, conn := range []*sql.Conn{first, second} {
		if _, err := conn.ExecContext(context.Background(), "INSERT INTO child(parent_id) VALUES (424242)"); err == nil {
			t.Fatalf("connection %d admitted an orphan", i+1)
		}
	}
	if got := db.Stats().MaxOpenConnections; got != 2 {
		t.Fatalf("MaxOpenConnections = %d, want 2 (no one-connection substitute)", got)
	}
}

func TestApplicationErrorsAreNotCollapsedIntoPolicyErrors(t *testing.T) {
	runtimeErr := errors.New("application constraint failure")
	scenario := &hostileScenario{plans: []hostilePlan{{state: 1, runtimeErr: runtimeErr}}}
	driverName := registerHostileDriver(t, scenario)
	db, err := Open(context.Background(), driverName, "ignored", ForeignKeysRequired)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.ExecContext(context.Background(), "WORK"); !errors.Is(err, runtimeErr) {
		t.Fatalf("application error = %v, want %v", err, runtimeErr)
	}
}
