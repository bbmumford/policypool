package policypool

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"math"
	"sync/atomic"

	"github.com/bbmumford/filekind"
)

type policyConnector struct {
	base   driver.Connector
	policy ConnectionPolicy
	// identity is set on a pool opened with OpenFile or OpenFileConnector,
	// and makes every connection it opens refuse header assignments.
	identity *Identity
	// proved is set by openProved once the pool's first connection proved
	// identity; from then on every new physical connection reads its own
	// file's kind before it is handed out (connectionKind), so a file
	// replaced at the path after the pool opened is refused, not used.
	proved atomic.Bool
}

func (c *policyConnector) Connect(ctx context.Context) (driver.Conn, error) {
	if err := contextError(ctx); err != nil {
		return nil, publicErrorUnder(ctx, err)
	}
	conn, err := c.base.Connect(ctx)
	if err != nil {
		if conn != nil {
			return nil, publicErrorUnder(ctx, preferredCause(err, conn.Close()))
		}
		return nil, publicErrorUnder(ctx, err)
	}
	if conn == nil {
		return nil, ErrDriverFailed
	}
	if err := contextError(ctx); err != nil {
		return nil, publicErrorUnder(ctx, preferredCause(err, conn.Close()))
	}
	if err := enforce(ctx, conn, c.policy); err != nil {
		return nil, publicErrorUnder(ctx, preferredCause(err, conn.Close()))
	}
	if c.identity != nil && c.proved.Load() {
		if err := connectionKind(ctx, conn, c.identity.Kind); err != nil {
			if closeErr := conn.Close(); closeErr != nil {
				return nil, errors.Join(err, publicErrorUnder(ctx, closeErr))
			}
			return nil, err
		}
	}
	if err := contextError(ctx); err != nil {
		return nil, publicErrorUnder(ctx, preferredCause(err, conn.Close()))
	}
	return &policyConn{Conn: conn, policy: c.policy, identity: c.identity}, nil
}

func (c *policyConnector) Driver() driver.Driver { return c.base.Driver() }

func (c *policyConnector) Close() error {
	closer, ok := c.base.(io.Closer)
	if !ok {
		return nil
	}
	return publicError(closer.Close())
}

// policyConn embeds the physical connection so the required driver.Conn
// surface stays native. Standard optional interfaces are forwarded below.
//
// Every method that takes SQL text refuses a statement that turns foreign keys
// off, before the driver sees any of it. The proof runs only in Connect and,
// under ForeignKeysRequired, in ResetSession, and a connection a caller holds
// through sql.Conn or a transaction is not reset until it returns to the pool,
// so without the refusal that caller could write orphans between two proofs.
// Under ForeignKeysRequiredAtConnect there is no second proof, and the refusal
// alone keeps the connection's setting on after Connect.
type policyConn struct {
	driver.Conn
	policy ConnectionPolicy
	// identity is the pool's Identity, nil on a pool opened without one.
	identity *Identity
	// stamping lifts the header-assignment refusal while this package itself
	// stamps the header (withStamping), on a connection it holds alone.
	stamping bool
}

// refuses reports whether query must not reach the physical connection. The
// refusal is ErrPolicyRefused and never driver.ErrBadConn, so database/sql
// returns it to the caller instead of retrying the statement on another
// connection, and it carries none of the statement text.
//
// On a pool opened with an Identity it also refuses a statement assigning
// application_id or user_version, so the file's kind and format generation
// change only through this package's stamp and AdvanceGeneration.
func (c *policyConn) refuses(query string) bool {
	return c.policy.defined() && (disablesForeignKeys(query) ||
		c.identity != nil && !c.stamping && assignsIdentity(query))
}

func (c *policyConn) Close() error { return publicError(c.Conn.Close()) }

// Prepare is the context-free entry the embedded driver.Conn would otherwise
// promote unguarded. database/sql calls PrepareContext instead, but a caller
// holding the driver connection through sql.Conn.Raw can call this one directly.
func (c *policyConn) Prepare(query string) (driver.Stmt, error) {
	if c.refuses(query) {
		return nil, ErrPolicyRefused
	}
	return c.Conn.Prepare(query)
}

func (c *policyConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if c.refuses(query) {
		return nil, ErrPolicyRefused
	}
	if contextual, ok := c.Conn.(driver.ConnPrepareContext); ok {
		stmt, err := contextual.PrepareContext(ctx, query)
		if err != nil || stmt == nil {
			return stmt, err
		}
		if err := contextError(ctx); err != nil {
			return nil, preferredCause(err, stmt.Close())
		}
		return stmt, nil
	}
	stmt, err := c.Conn.Prepare(query)
	if err != nil {
		return nil, err
	}
	if err := contextError(ctx); err != nil {
		return nil, preferredCause(err, stmt.Close())
	}
	return stmt, nil
}

func (c *policyConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if contextual, ok := c.Conn.(driver.ConnBeginTx); ok {
		tx, err := contextual.BeginTx(ctx, opts)
		if err != nil || tx == nil {
			return tx, err
		}
		if err := contextError(ctx); err != nil {
			return nil, preferredCause(err, tx.Rollback())
		}
		return tx, nil
	}
	if opts.Isolation != driver.IsolationLevel(sql.LevelDefault) {
		return nil, errIsolationUnsupported
	}
	if opts.ReadOnly {
		return nil, errReadOnlyUnsupported
	}
	tx, err := c.Conn.Begin() //nolint:staticcheck // a driver without ConnBeginTx begins only through Begin; database/sql falls back to it the same way.
	if err != nil {
		return nil, err
	}
	if err := contextError(ctx); err != nil {
		return nil, preferredCause(err, tx.Rollback())
	}
	return tx, nil
}

func (c *policyConn) Ping(ctx context.Context) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if pinger, ok := c.Conn.(driver.Pinger); ok {
		return withContext(ctx, pinger.Ping(ctx))
	}
	return nil
}

func (c *policyConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if c.refuses(query) {
		return nil, ErrPolicyRefused
	}
	if contextual, ok := c.Conn.(driver.ExecerContext); ok {
		result, err := contextual.ExecContext(ctx, query, args)
		return result, withContext(ctx, err)
	}
	legacy, ok := c.Conn.(driver.Execer) //nolint:staticcheck // a wrapped driver without ExecerContext may still offer Execer, which database/sql also falls back to.
	if !ok || hasNamedValue(args) {
		return nil, driver.ErrSkip
	}
	result, err := legacy.Exec(query, namedToValues(args))
	if err != nil {
		return nil, err
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *policyConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if c.refuses(query) {
		return nil, ErrPolicyRefused
	}
	if contextual, ok := c.Conn.(driver.QueryerContext); ok {
		rows, err := contextual.QueryContext(ctx, query, args)
		return checkedRows(ctx, rows, err)
	}
	legacy, ok := c.Conn.(driver.Queryer) //nolint:staticcheck // a wrapped driver without QueryerContext may still offer Queryer, which database/sql also falls back to.
	if !ok || hasNamedValue(args) {
		return nil, driver.ErrSkip
	}
	rows, err := legacy.Query(query, namedToValues(args))
	if err != nil {
		return nil, err
	}
	if err := contextError(ctx); err != nil {
		return nil, preferredCause(err, rows.Close())
	}
	return rows, nil
}

// ResetSession runs each time database/sql hands a pooled connection out again.
// The driver's own reset always runs, so a driver that reports its connection
// unusable still has it discarded. Only ForeignKeysRequiredAtConnect skips the
// re-proof after it; every other value is proved again, and a value enforce
// does not define fails, so a policy this method does not name never loses its
// proof by default.
func (c *policyConn) ResetSession(ctx context.Context) error {
	if err := contextError(ctx); err != nil {
		return resetError(err)
	}
	if resetter, ok := c.Conn.(driver.SessionResetter); ok {
		if err := resetter.ResetSession(ctx); err != nil {
			return resetError(err)
		}
	}
	if c.policy == ForeignKeysRequiredAtConnect {
		return nil
	}
	return resetError(enforce(ctx, c.Conn, c.policy))
}

func (c *policyConn) IsValid() bool {
	validator, ok := c.Conn.(driver.Validator)
	return !ok || validator.IsValid()
}

func (c *policyConn) CheckNamedValue(value *driver.NamedValue) error {
	checker, ok := c.Conn.(driver.NamedValueChecker)
	if !ok {
		return driver.ErrSkip
	}
	return checker.CheckNamedValue(value)
}

// connectionKind reads the header of the file conn opened and refuses it
// (ErrFileIdentity) unless it is a stamped file of kind. Any generation is
// accepted: AdvanceGeneration moves the file past the pool's Identity, which
// its holder reopens with once the update is confirmed, and the pool's own
// connections keep serving until then. Engine failures keep the package's
// redaction.
func connectionKind(ctx context.Context, conn driver.Conn, kind filekind.Kind) error {
	app, err := pragmaValue(ctx, conn, "PRAGMA application_id")
	if err != nil {
		return connectionKindError(ctx, err)
	}
	version, err := pragmaValue(ctx, conn, "PRAGMA user_version")
	if err != nil {
		return connectionKindError(ctx, err)
	}
	if app < math.MinInt32 || app > math.MaxInt32 || version < math.MinInt32 || version > math.MaxInt32 {
		return &identityError{cause: filekind.ErrUnreadableHeader}
	}
	h := filekind.Header{ApplicationID: int32(app), UserVersion: int32(version)}
	if err := h.Expect(filekind.Want{Kind: kind, Newest: math.MaxInt32}); err != nil {
		return &identityError{cause: err}
	}
	return nil
}

// connectionKindError is ErrFileIdentity for a header pragma that did not
// answer one integer, and the package's redacted kind for anything else.
func connectionKindError(ctx context.Context, err error) error {
	if errors.Is(err, filekind.ErrUnreadableHeader) {
		return &identityError{cause: err}
	}
	return publicErrorUnder(ctx, err)
}

// pragmaValue reads the one integer a header pragma answers on conn.
func pragmaValue(ctx context.Context, conn driver.Conn, query string) (int64, error) {
	rows, err := queryPolicy(ctx, conn, query)
	if err != nil {
		return 0, err
	}
	dest := make([]driver.Value, 1)
	if len(rows.Columns()) != 1 {
		return 0, closeRows(ctx, rows, filekind.ErrUnreadableHeader)
	}
	if err := rows.Next(dest); err != nil {
		if errors.Is(err, io.EOF) {
			err = filekind.ErrUnreadableHeader
		}
		return 0, closeRows(ctx, rows, err)
	}
	v, ok := dest[0].(int64)
	if !ok {
		return 0, closeRows(ctx, rows, filekind.ErrUnreadableHeader)
	}
	return v, closeRows(ctx, rows, nil)
}
