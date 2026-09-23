// Package policypool opens database pools whose physical connections satisfy
// required, fail-closed connection policy.
//
// WHY PER CONNECTION. PRAGMA foreign_keys is a property of one connection, and
// engines differ in where it starts: the Turso Database engine
// (turso.tech/database/tursogo) opens every connection with it OFF, so a PRAGMA
// issued once through a *sql.DB reaches whichever connection ran it and leaves
// every other connection the pool opens accepting orphans. The policy is
// therefore established AND read back on every new physical connection, and
// under ForeignKeysRequired again after every session reset; a connection that
// cannot prove it is refused with driver.ErrBadConn so database/sql discards
// it. Between those proofs, a policy connection refuses any statement that
// would switch foreign keys off, since a caller holding a connection is not
// reset until it returns; under ForeignKeysRequiredAtConnect that refusal is
// what holds the setting for the rest of the connection's life.
package policypool

import (
	"context"
	"database/sql"
	"database/sql/driver"
)

// ConnectionPolicy identifies an invariant required of every physical
// connection in a pool. The zero value does not authorize a connection.
type ConnectionPolicy uint8

const (
	// ForeignKeysRequired requires SQLite foreign-key enforcement to be active,
	// proved on every new physical connection and again each time database/sql
	// hands a pooled connection out (ResetSession). It is the policy for every
	// pool whose connection can lose the setting without a statement the guard
	// sees: a remote session the driver reopens under the same connection starts
	// at the server's default, which this package cannot know.
	ForeignKeysRequired ConnectionPolicy = iota + 1

	// ForeignKeysRequiredAtConnect requires the same enforcement, proved on
	// every new physical connection and not again when the connection is reused;
	// a statement that would turn it off is refused on the connection for its
	// whole life, as under ForeignKeysRequired.
	//
	// WHAT CONSUMES IT: a pool over a go-libsql embedded replica connector.
	//
	// CONDITIONS. Only a connector whose connection cannot lose the setting
	// except by a statement may use it. An embedded replica's connection is one:
	// its writes run on the primary under that connection's setting, a session
	// the libSQL primary starts again begins with foreign keys on, and the
	// guard refuses every statement that would turn them off. Every other pool
	// uses ForeignKeysRequired.
	//
	// WHY IT EXISTS. go-libsql answers a replica's reads from the local file but
	// sends PRAGMA foreign_keys to the primary, so ForeignKeysRequired's proof on
	// each reuse costs every pooled statement a round trip to the primary and
	// fails every pooled read while the primary is unreachable. A physical
	// connection opened during an outage still fails its proof, so reads during
	// an outage are served by connections proved before it.
	ForeignKeysRequiredAtConnect
)

// defined reports whether p is a policy this package proves. Open,
// OpenConnector and enforce refuse every other value, the zero value included,
// so an unknown policy never opens a pool.
func (p ConnectionPolicy) defined() bool {
	return p == ForeignKeysRequired || p == ForeignKeysRequiredAtConnect
}

// Open opens a pool and proves policy on one physical connection before the
// pool is returned. Policy is also established and proved on every later
// physical connection created by the pool.
//
// Connection and policy errors are redacted because a driver can include a
// data-source name or authentication material in them. What a caller gets
// instead is one kind, told apart with errors.Is: ErrPolicyRefused,
// ErrPolicyUnproved, ErrUnreachable, ErrUnauthorized, ErrNotADatabase or
// ErrDriverFailed. No kind carries any of the driver's text. Cancellation and
// driver.ErrBadConn retain errors.Is identity; an open that ctx cancelled or
// that reached ctx's deadline carries no kind, and a timeout the driver set for
// itself that stopped a dial while ctx was live is ErrUnreachable.
func Open(ctx context.Context, driverName, dsn string, policy ConnectionPolicy) (*sql.DB, error) {
	if ctx == nil || !policy.defined() {
		return nil, ErrPolicyRefused
	}
	if err := ctx.Err(); err != nil {
		return nil, publicErrorUnder(ctx, err)
	}

	registered, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, publicErrorUnder(ctx, err)
	}
	baseDriver := registered.Driver()
	if err := registered.Close(); err != nil {
		return nil, publicErrorUnder(ctx, err)
	}
	base, err := connectorFor(baseDriver, dsn)
	if err != nil || base == nil {
		return nil, publicErrorUnder(ctx, preferredCause(err, ErrDriverFailed))
	}

	return openProved(ctx, base, policy)
}

// OpenConnector is Open for a caller that must build its own connector, and
// proves the same policy on the same terms.
//
// WHAT IT CONSUMES: a connector the caller constructed. WHAT CONSUMES IT: a
// composition root whose driver takes connection settings as constructor
// OPTIONS rather than DSN parameters, which Open cannot reach.
//
// WHY BOTH EXIST. Open is written around a registered driver name and a DSN,
// and that pair cannot carry a setting the driver only accepts as an option —
// an auth token supplied that way never appears in a DSN, so a caller holding
// one has nothing to hand Open that still carries it. Without this entry the
// caller's only remaining move is to write the connector wrapper itself, and a
// second implementation of a fail-closed invariant is the thing most likely to
// omit the half that is not obvious: not the establish, but the read-back, and
// the re-proof on session reset that has to surface as driver.ErrBadConn.
//
// OWNERSHIP FOLLOWS THE POOL, NOT THE CALLER. Closing the returned *sql.DB
// closes the supplied connector when it implements io.Closer, so a caller that
// keeps using its connector afterwards is using a closed one.
//
// ⚠ AND KEEP THE REFERENCE, because only the pool comes back. A connector is not
// always just a way to open connections: a replicating driver's connector is also
// the handle its owner drives replication from, and constructing one inline in
// this call discards that handle. The pool then works, policy holds on every
// connection, and the replica stops advancing with nothing reporting it.
func OpenConnector(ctx context.Context, base driver.Connector, policy ConnectionPolicy) (*sql.DB, error) {
	if ctx == nil || !policy.defined() || base == nil {
		return nil, ErrPolicyRefused
	}
	if err := ctx.Err(); err != nil {
		return nil, publicErrorUnder(ctx, err)
	}
	return openProved(ctx, base, policy)
}

// openProved publishes the pool only after policy holds on a real connection.
// The Ping is what forces one open, so a pool whose first physical connection
// cannot satisfy policy is never returned to a caller that would then discover
// it on a query.
func openProved(ctx context.Context, base driver.Connector, policy ConnectionPolicy) (*sql.DB, error) {
	db := sql.OpenDB(&policyConnector{base: base, policy: policy})
	if err := db.PingContext(ctx); err != nil {
		return nil, publicErrorUnder(ctx, preferredCause(err, db.Close()))
	}
	if err := ctx.Err(); err != nil {
		return nil, publicErrorUnder(ctx, preferredCause(err, db.Close()))
	}
	return db, nil
}

// ProbeForeignKeys opens ONE connection through base, tries to turn foreign-key
// enforcement on, reads it back, and reports what it saw — refusing nothing.
//
// WHAT IT CONSUMES: a connector for the engine in question. WHAT CONSUMES IT: a
// composition root that wants to know whether ITS engine honours the setting
// before it holds a pool to it.
//
// 🔴 IT EXISTS BECAUSE FAIL-CLOSED IS THE WRONG FIRST MOVE ON A PATH YOU CANNOT
// TURN OFF. Open with ForeignKeysRequired and every connection whose read-back
// disagrees is refused, which is correct for a surface that can stop serving and
// wrong for the database a product reads on every request: an engine that ignores
// the pragma turns "references are not enforced" into "there is no database". The
// remedy has to be provable before it is mandatory, and on a remote engine the
// only place that proof exists is against the live server.
//
// ⇒ SO THIS ANSWERS THE QUESTION WITHOUT TAKING THE RISK. Run it at boot, record
// the answer, and adopt ForeignKeysRequired once the answer is known — the order
// that gets a pool enforcing rather than a deployment refusing.
//
// ⚠ ONE CONNECTION, ONE ANSWER. It says what this engine did with the setting on
// the connection it opened; it is not a pool guarantee and does not replace
// Open's per-connection proof. And "enforced" here means the engine REPORTED the
// setting active — an engine that reports 1 and enforces nothing is outside what
// any read-back can see, and only a rejected write proves the rest.
//
// Its errors are Open's kinds with the same redaction, so a boot that records
// the answer can also record why there was none. An error leaves the answer
// unknown; the false beside it is not a measured result. ErrUnreachable,
// ErrUnauthorized and ErrNotADatabase name what stopped the probe before it saw
// the setting on, which can come after it read the setting off, as with a
// credential that may read the setting but not change it.
func ProbeForeignKeys(ctx context.Context, base driver.Connector) (enforced bool, err error) {
	if ctx == nil || base == nil {
		return false, ErrPolicyRefused
	}
	if err := ctx.Err(); err != nil {
		return false, publicErrorUnder(ctx, err)
	}
	conn, err := base.Connect(ctx)
	if err != nil {
		if conn != nil {
			return false, publicErrorUnder(ctx, preferredCause(err, conn.Close()))
		}
		return false, publicErrorUnder(ctx, err)
	}
	if conn == nil {
		return false, ErrDriverFailed
	}
	defer func() { _ = conn.Close() }()

	state, err := foreignKeyState(ctx, conn)
	if err != nil {
		return false, publicErrorUnder(ctx, err)
	}
	if state == 1 {
		return true, nil
	}
	if err := establishForeignKeys(ctx, conn); err != nil {
		return false, publicErrorUnder(ctx, err)
	}
	state, err = foreignKeyState(ctx, conn)
	if err != nil {
		return false, publicErrorUnder(ctx, err)
	}
	return state == 1, nil
}

func connectorFor(base driver.Driver, dsn string) (driver.Connector, error) {
	if contextual, ok := base.(driver.DriverContext); ok {
		return contextual.OpenConnector(dsn)
	}
	return &dsnConnector{base: base, dsn: dsn}, nil
}

type dsnConnector struct {
	base driver.Driver
	dsn  string
}

func (c *dsnConnector) Connect(ctx context.Context) (driver.Conn, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	conn, err := c.base.Open(c.dsn)
	if err != nil {
		if conn != nil {
			return nil, preferredCause(err, conn.Close())
		}
		return nil, err
	}
	if conn == nil {
		return nil, ErrDriverFailed
	}
	if err := contextError(ctx); err != nil {
		return nil, preferredCause(err, conn.Close())
	}
	return conn, nil
}

func (c *dsnConnector) Driver() driver.Driver { return c.base }
