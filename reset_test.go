package policypool

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
)

func TestSessionResetRestoresForeignKeys(t *testing.T) {
	scenario := &hostileScenario{plans: []hostilePlan{{state: 1}}}
	driverName := registerHostileDriver(t, scenario)
	db, err := Open(context.Background(), driverName, "ignored", ForeignKeysRequired)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatalf("Conn: %v", err)
	}
	if _, err := conn.ExecContext(context.Background(), hostileDrift); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("return connection: %v", err)
	}
	if _, err := db.ExecContext(context.Background(), "WORK"); err != nil {
		t.Fatalf("use after reset: %v", err)
	}
	got := scenario.snapshot()
	if got.enables != 1 || got.uninitialized != 0 {
		t.Fatalf("session reset did not restore invariant: %+v", got)
	}
}

func TestSessionResetFailuresDiscardPhysicalConnection(t *testing.T) {
	secret := "reset-secret=never-disclose"
	tests := []struct {
		name string
		plan hostilePlan
	}{
		{
			name: "malformed verification",
			plan: hostilePlan{state: 1, rows: []hostileRows{
				singleRow(int64(1)),
				singleRow("1"),
			}},
		},
		{
			name: "extra verification row",
			plan: hostilePlan{state: 1, rows: []hostileRows{
				singleRow(int64(1)),
				{columns: []string{"foreign_keys"}, values: [][]driver.Value{{int64(1)}, {int64(1)}}},
			}},
		},
		{
			name: "verification rows close failure",
			plan: hostilePlan{state: 1, rows: []hostileRows{
				singleRow(int64(1)),
				{columns: []string{"foreign_keys"}, values: [][]driver.Value{{int64(1)}}, closeErr: errors.New(secret)},
			}},
		},
		{
			name: "underlying reset failure",
			plan: hostilePlan{state: 1, resetErr: errors.New(secret)},
		},
		{
			name: "reset cancellation",
			plan: hostilePlan{state: 1, resetErr: context.Canceled},
		},
		{
			name: "reset deadline",
			plan: hostilePlan{state: 1, resetErr: context.DeadlineExceeded},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertResetFailureReplaced(t, test.plan, nil)
		})
	}
}

func TestSessionResetReenableFailureDiscardsPhysicalConnection(t *testing.T) {
	secret := "enable-secret=never-disclose"
	assertResetFailureReplaced(t, hostilePlan{
		state:     1,
		enableErr: errors.New(secret),
	}, func(t *testing.T, db *sql.DB) {
		conn, err := db.Conn(context.Background())
		if err != nil {
			t.Fatalf("Conn: %v", err)
		}
		if _, err := conn.ExecContext(context.Background(), hostileDrift); err != nil {
			_ = conn.Close()
			t.Fatalf("disable: %v", err)
		}
		if err := conn.Close(); err != nil {
			t.Fatalf("return disabled connection: %v", err)
		}
	})
}

func TestResetErrorIdentitiesAndRedaction(t *testing.T) {
	secret := errors.New("reset-secret=never-disclose")
	tests := []struct {
		name       string
		cause      error
		contextErr error
	}{
		{name: "ordinary", cause: secret},
		{name: "bad connection", cause: driver.ErrBadConn},
		{name: "canceled", cause: errors.Join(context.Canceled, driver.ErrBadConn, secret), contextErr: context.Canceled},
		{name: "deadline", cause: errors.Join(context.DeadlineExceeded, driver.ErrBadConn, secret), contextErr: context.DeadlineExceeded},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := resetError(test.cause)
			if !errors.Is(err, driver.ErrBadConn) {
				t.Fatalf("resetError(%v) = %v, want driver.ErrBadConn identity", test.cause, err)
			}
			if test.contextErr != nil && !errors.Is(err, test.contextErr) {
				t.Fatalf("resetError(%v) = %v, want %v identity", test.cause, err, test.contextErr)
			}
			if strings.Contains(err.Error(), secret.Error()) {
				t.Fatalf("reset error leaked cause: %q", err)
			}
		})
	}
	if err := resetError(nil); err != nil {
		t.Fatalf("resetError(nil) = %v, want nil", err)
	}
}

func assertResetFailureReplaced(t *testing.T, first hostilePlan, prepare func(*testing.T, *sql.DB)) {
	t.Helper()
	scenario := &hostileScenario{plans: []hostilePlan{
		first,
		{state: 0},
	}}
	driverName := registerHostileDriver(t, scenario)
	db, err := Open(context.Background(), driverName, "ignored", ForeignKeysRequired)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if prepare != nil {
		prepare(t, db)
	}
	if _, err := db.ExecContext(context.Background(), "WORK"); err != nil {
		t.Fatalf("application use after reset failure: %v", err)
	}

	got := scenario.snapshot()
	if got.opens != 2 {
		t.Fatalf("physical opens = %d, want failed connection plus replacement: %+v", got.opens, got)
	}
	if len(got.closedByConnection) < 2 || got.closedByConnection[0] != 1 {
		t.Fatalf("failed physical connection was not closed: %+v", got)
	}
	if len(got.runtimeByConnection) < 2 || got.runtimeByConnection[0] != 0 || got.runtimeByConnection[1] != 1 {
		t.Fatalf("application reached failed connection or missed replacement: %+v", got)
	}
	if got.enables != 1 || got.uninitialized != 0 {
		t.Fatalf("replacement was not freshly enforced: %+v", got)
	}
}
