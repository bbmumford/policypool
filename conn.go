package policypool

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"io"
)

type policyConnector struct {
	base   driver.Connector
	policy ConnectionPolicy
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
	if err := contextError(ctx); err != nil {
		return nil, publicErrorUnder(ctx, preferredCause(err, conn.Close()))
	}
	return &policyConn{Conn: conn, policy: c.policy}, nil
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
// off, before the driver sees any of it. The proof runs only in Connect and
// ResetSession, and a connection a caller holds through sql.Conn or a
// transaction is not reset until it returns to the pool, so without the refusal
// that caller could write orphans between two proofs.
type policyConn struct {
	driver.Conn
	policy ConnectionPolicy
}

// refuses reports whether query must not reach the physical connection. The
// refusal is ErrPolicyRefused and never driver.ErrBadConn, so database/sql
// returns it to the caller instead of retrying the statement on another
// connection, and it carries none of the statement text.
func (c *policyConn) refuses(query string) bool {
	return c.policy == ForeignKeysRequired && disablesForeignKeys(query)
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
	tx, err := c.Conn.Begin()
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
	legacy, ok := c.Conn.(driver.Execer)
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
	legacy, ok := c.Conn.(driver.Queryer)
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

func (c *policyConn) ResetSession(ctx context.Context) error {
	if err := contextError(ctx); err != nil {
		return resetError(err)
	}
	if resetter, ok := c.Conn.(driver.SessionResetter); ok {
		if err := resetter.ResetSession(ctx); err != nil {
			return resetError(err)
		}
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
