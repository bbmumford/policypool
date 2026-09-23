package policypool

import (
	"context"
	"database/sql/driver"
	"errors"
	"io"
)

func enforce(ctx context.Context, conn driver.Conn, policy ConnectionPolicy) error {
	if !policy.defined() {
		return ErrPolicyRefused
	}
	state, err := foreignKeyState(ctx, conn)
	if err != nil {
		return err
	}
	if state == 1 {
		return nil
	}
	if state != 0 {
		return ErrPolicyUnproved
	}
	if err := establishForeignKeys(ctx, conn); err != nil {
		return err
	}
	state, err = foreignKeyState(ctx, conn)
	if err != nil {
		return err
	}
	if state != 1 {
		return ErrPolicyUnproved
	}
	return nil
}

func foreignKeyState(ctx context.Context, conn driver.Conn) (int64, error) {
	rows, err := queryPolicy(ctx, conn, "PRAGMA foreign_keys")
	if err != nil {
		return 0, err
	}
	columns := rows.Columns()
	if len(columns) != 1 {
		return 0, closeRows(ctx, rows, ErrPolicyUnproved)
	}

	dest := make([]driver.Value, 1)
	if err := contextError(ctx); err != nil {
		return 0, closeRows(ctx, rows, err)
	}
	if err := rows.Next(dest); err != nil {
		if errors.Is(err, io.EOF) {
			err = ErrPolicyUnproved
		}
		return 0, closeRows(ctx, rows, err)
	}
	state, ok := dest[0].(int64)
	if !ok || (state != 0 && state != 1) {
		return 0, closeRows(ctx, rows, ErrPolicyUnproved)
	}

	if err := contextError(ctx); err != nil {
		return 0, closeRows(ctx, rows, err)
	}
	dest[0] = nil
	err = rows.Next(dest)
	if err == nil {
		return 0, closeRows(ctx, rows, ErrPolicyUnproved)
	}
	if !errors.Is(err, io.EOF) {
		return 0, closeRows(ctx, rows, err)
	}
	if err := closeRows(ctx, rows, nil); err != nil {
		return 0, err
	}
	return state, nil
}

func establishForeignKeys(ctx context.Context, conn driver.Conn) error {
	const statement = "PRAGMA foreign_keys=ON"
	if contextual, ok := conn.(driver.ExecerContext); ok {
		result, err := contextual.ExecContext(ctx, statement, nil)
		if errors.Is(err, driver.ErrSkip) && result != nil {
			return ErrDriverFailed
		}
		if !errors.Is(err, driver.ErrSkip) {
			return withContext(ctx, err)
		}
	}
	if legacy, ok := conn.(driver.Execer); ok {
		if err := contextError(ctx); err != nil {
			return err
		}
		result, err := legacy.Exec(statement, nil)
		if errors.Is(err, driver.ErrSkip) && result != nil {
			return ErrDriverFailed
		}
		if !errors.Is(err, driver.ErrSkip) {
			return withContext(ctx, err)
		}
	}

	stmt, err := preparePolicy(ctx, conn, statement)
	if err != nil {
		return err
	}
	if contextual, ok := stmt.(driver.StmtExecContext); ok {
		var result driver.Result
		result, err = contextual.ExecContext(ctx, nil)
		if errors.Is(err, driver.ErrSkip) && result != nil {
			return preferredCause(ErrDriverFailed, stmt.Close())
		}
		if errors.Is(err, driver.ErrSkip) {
			err = nil
		} else {
			return preferredCause(withContext(ctx, err), stmt.Close())
		}
	}
	if err == nil {
		if err := contextError(ctx); err != nil {
			return preferredCause(err, stmt.Close())
		}
		_, err = stmt.Exec(nil)
	}
	return preferredCause(withContext(ctx, err), stmt.Close())
}

func queryPolicy(ctx context.Context, conn driver.Conn, query string) (driver.Rows, error) {
	if contextual, ok := conn.(driver.QueryerContext); ok {
		rows, err := contextual.QueryContext(ctx, query, nil)
		if errors.Is(err, driver.ErrSkip) && rows != nil {
			return nil, preferredCause(ErrDriverFailed, rows.Close())
		}
		if !errors.Is(err, driver.ErrSkip) {
			return checkedRows(ctx, rows, err)
		}
	}
	if legacy, ok := conn.(driver.Queryer); ok {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		rows, err := legacy.Query(query, nil)
		if errors.Is(err, driver.ErrSkip) && rows != nil {
			return nil, preferredCause(ErrDriverFailed, rows.Close())
		}
		if !errors.Is(err, driver.ErrSkip) {
			return checkedRows(ctx, rows, err)
		}
	}

	stmt, err := preparePolicy(ctx, conn, query)
	if err != nil {
		return nil, err
	}
	if contextual, ok := stmt.(driver.StmtQueryContext); ok {
		rows, err := contextual.QueryContext(ctx, nil)
		if errors.Is(err, driver.ErrSkip) && rows != nil {
			return nil, preferredCause(ErrDriverFailed, preferredCause(rows.Close(), stmt.Close()))
		}
		if !errors.Is(err, driver.ErrSkip) {
			if err != nil || rows == nil {
				return nil, preferredCause(withContext(ctx, err), stmt.Close())
			}
			return checkedRows(ctx, &statementRows{Rows: rows, stmt: stmt}, nil)
		}
	}
	if err := contextError(ctx); err != nil {
		return nil, preferredCause(err, stmt.Close())
	}
	rows, err := stmt.Query(nil)
	if err != nil || rows == nil {
		return nil, preferredCause(withContext(ctx, err), stmt.Close())
	}
	return checkedRows(ctx, &statementRows{Rows: rows, stmt: stmt}, nil)
}

func preparePolicy(ctx context.Context, conn driver.Conn, query string) (driver.Stmt, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if contextual, ok := conn.(driver.ConnPrepareContext); ok {
		stmt, err := contextual.PrepareContext(ctx, query)
		if errors.Is(err, driver.ErrSkip) && stmt != nil {
			return nil, preferredCause(ErrDriverFailed, stmt.Close())
		}
		if !errors.Is(err, driver.ErrSkip) {
			if err != nil || stmt == nil {
				return nil, withContext(ctx, preferredCause(err, ErrDriverFailed))
			}
			return stmt, nil
		}
	}
	stmt, err := conn.Prepare(query)
	if err != nil || stmt == nil {
		return nil, withContext(ctx, preferredCause(err, ErrDriverFailed))
	}
	if err := contextError(ctx); err != nil {
		return nil, preferredCause(err, stmt.Close())
	}
	return stmt, nil
}

type statementRows struct {
	driver.Rows
	stmt   driver.Stmt
	closed bool
}

func (r *statementRows) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	return preferredCause(r.Rows.Close(), r.stmt.Close())
}

func checkedRows(ctx context.Context, rows driver.Rows, err error) (driver.Rows, error) {
	if err != nil {
		if rows != nil {
			return nil, preferredCause(withContext(ctx, err), rows.Close())
		}
		return nil, withContext(ctx, err)
	}
	if rows == nil {
		return nil, ErrDriverFailed
	}
	if err := contextError(ctx); err != nil {
		return nil, preferredCause(err, rows.Close())
	}
	return rows, nil
}

func closeRows(ctx context.Context, rows driver.Rows, cause error) error {
	err := preferredCause(cause, rows.Close())
	if contextErr := contextError(ctx); contextErr != nil {
		return preferredCause(contextErr, err)
	}
	return err
}
