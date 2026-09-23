package policypool

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
)

// TestOpenConnectorProvesTheSamePolicyAsOpen is the reason the connector entry
// exists: a caller that cannot express its settings in a DSN must not have to
// choose between reaching this package and keeping its connector.
func TestOpenConnectorProvesTheSamePolicyAsOpen(t *testing.T) {
	scenario := &hostileScenario{plans: []hostilePlan{{state: 0}}}

	db, err := OpenConnector(
		context.Background(),
		&dsnConnector{base: scenario, dsn: "ignored"},
		ForeignKeysRequired,
	)
	if err != nil {
		t.Fatalf("OpenConnector: %v", err)
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

// TestOpenConnectorVerifiesEveryPhysicalConnection is the half a caller writing
// its own wrapper is most likely to lose. Proving the connector once at open
// says nothing about the connections the pool creates later, and a pool that
// grows under load is exactly when it stops being one connection.
func TestOpenConnectorVerifiesEveryPhysicalConnection(t *testing.T) {
	scenario := &hostileScenario{factory: func(int) hostilePlan { return hostilePlan{state: 0} }}
	db, err := OpenConnector(
		context.Background(),
		&dsnConnector{base: scenario, dsn: "ignored"},
		ForeignKeysRequired,
	)
	if err != nil {
		t.Fatalf("OpenConnector: %v", err)
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
	for i, conn := range connections {
		if _, err := conn.ExecContext(context.Background(), "WORK", i); err != nil {
			t.Errorf("connection %d use: %v", i, err)
		}
		if err := conn.Close(); err != nil {
			t.Errorf("connection %d close: %v", i, err)
		}
	}

	got := scenario.snapshot()
	if got.opens != 8 || got.enables != 8 || got.uninitialized != 0 {
		t.Fatalf("physical enforcement = %+v, want 8 established and no uninitialized use", got)
	}
}

// TestOpenConnectorRefusesWhatItCannotProve covers the arguments that would
// otherwise publish a pool proving nothing. A nil connector is the one Open
// cannot produce and this entry can, because the caller supplies it.
func TestOpenConnectorRefusesWhatItCannotProve(t *testing.T) {
	base := &dsnConnector{base: &hostileScenario{plans: []hostilePlan{{state: 1}}}, dsn: "ignored"}
	for _, test := range []struct {
		name   string
		base   driver.Connector
		policy ConnectionPolicy
	}{
		{name: "nil connector", base: nil, policy: ForeignKeysRequired},
		{name: "zero policy", base: base, policy: 0},
		{name: "unknown policy", base: base, policy: 255},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, err := OpenConnector(context.Background(), test.base, test.policy)
			if db != nil {
				_ = db.Close()
			}
			if !errors.Is(err, ErrPolicyRefused) {
				t.Fatalf("got %v, want a refusal — an unauthorized argument must not open a pool", err)
			}
		})
	}
}

// TestOpenConnectorRejectsAnUnprovedConnection keeps the read-back load-bearing
// on this path too. A connector whose engine reports something other than
// enforcement must fail the pool, not publish it.
func TestOpenConnectorRejectsAnUnprovedConnection(t *testing.T) {
	secret := "password=never-disclose"
	for _, test := range []struct {
		name string
		plan hostilePlan
	}{
		{name: "out of range", plan: hostilePlan{rows: []hostileRows{singleRow(int64(2))}}},
		{name: "establish mismatch", plan: hostilePlan{state: 0, refuseEnable: true}},
		{name: "query unsupported", plan: hostilePlan{queryErr: errors.New(secret)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			scenario := &hostileScenario{plans: []hostilePlan{test.plan}}
			db, err := OpenConnector(
				context.Background(),
				&dsnConnector{base: scenario, dsn: "dsn=" + secret},
				ForeignKeysRequired,
			)
			if err == nil || db != nil {
				if db != nil {
					_ = db.Close()
				}
				t.Fatal("OpenConnector succeeded without an exact proof")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("unredacted error: %q", err)
			}
			if got := scenario.snapshot(); got.opens != 1 || got.closes != 1 {
				t.Fatalf("unpublished connection was not closed exactly once: %+v", got)
			}
		})
	}
}

// TestProbeReportsAnEngineThatIgnoresTheSettingInsteadOfRefusingIt is the whole
// reason the probe exists. Open would refuse this engine's every connection,
// which is right for a surface that can stop serving and wrong for a database a
// product reads on every request.
func TestProbeReportsAnEngineThatIgnoresTheSettingInsteadOfRefusingIt(t *testing.T) {
	for _, test := range []struct {
		name string
		plan hostilePlan
		want bool
	}{
		{name: "already on", plan: hostilePlan{state: 1}, want: true},
		{name: "off, and turning it on takes", plan: hostilePlan{state: 0}, want: true},
		{name: "off, and it refuses to take", plan: hostilePlan{state: 0, refuseEnable: true}, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			scenario := &hostileScenario{plans: []hostilePlan{test.plan}}
			got, err := ProbeForeignKeys(context.Background(),
				&dsnConnector{base: scenario, dsn: "ignored"})
			if err != nil {
				t.Fatalf("ProbeForeignKeys: %v", err)
			}
			if got != test.want {
				t.Errorf("reported enforced=%v, want %v", got, test.want)
			}
			// The connection is a probe, not a pool — it must not be left open.
			if s := scenario.snapshot(); s.opens != 1 || s.closes != 1 {
				t.Errorf("opened %d and closed %d; a probe that leaks a connection is worse "+
					"than the question it answers", s.opens, s.closes)
			}
		})
	}
}

// TestTheProbeAndThePoolDisagreeOnTheSameEngine pins the distinction between
// them, which is the thing a reader is most likely to collapse: the probe
// ANSWERS about an engine, the pool REFUSES one.
func TestTheProbeAndThePoolDisagreeOnTheSameEngine(t *testing.T) {
	refusing := func() *hostileScenario {
		return &hostileScenario{factory: func(int) hostilePlan {
			return hostilePlan{state: 0, refuseEnable: true}
		}}
	}

	enforced, err := ProbeForeignKeys(context.Background(),
		&dsnConnector{base: refusing(), dsn: "ignored"})
	if err != nil {
		t.Fatalf("the probe errored on an engine that simply does not enforce: %v", err)
	}
	if enforced {
		t.Fatal("the probe reported enforcement on an engine that refuses to enable it")
	}

	db, err := OpenConnector(context.Background(),
		&dsnConnector{base: refusing(), dsn: "ignored"}, ForeignKeysRequired)
	if db != nil {
		_ = db.Close()
	}
	if err == nil {
		t.Fatal("the pool accepted the same engine the probe reported unenforced; one of them " +
			"is not doing its job, and the pool is the one that must refuse")
	}
}

// TestTheProbeRefusesWhatItCannotAsk keeps its arguments honest — a nil connector
// answering false would read as "this engine does not enforce".
func TestTheProbeRefusesWhatItCannotAsk(t *testing.T) {
	if _, err := ProbeForeignKeys(context.Background(), nil); !errors.Is(err, ErrPolicyRefused) {
		t.Errorf("a nil connector returned %v; answering false would read as a measured result", err)
	}
}
