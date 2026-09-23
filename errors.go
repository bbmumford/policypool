package policypool

import (
	"context"
	"database/sql/driver"
	"errors"
)

var (
	errPolicyRefused        = errors.New("policypool: connection policy refused")
	errPolicyFailed         = errors.New("policypool: connection policy failed")
	errIsolationUnsupported = errors.New("policypool: isolation level unsupported")
	errReadOnlyUnsupported  = errors.New("policypool: read-only transaction unsupported")
)

func contextError(ctx context.Context) error {
	if ctx == nil {
		return errPolicyRefused
	}
	return ctx.Err()
}

func withContext(ctx context.Context, err error) error {
	if contextErr := contextError(ctx); contextErr != nil {
		return preferredCause(contextErr, err)
	}
	return err
}

func hasNamedValue(values []driver.NamedValue) bool {
	for _, value := range values {
		if value.Name != "" {
			return true
		}
	}
	return false
}

func namedToValues(values []driver.NamedValue) []driver.Value {
	args := make([]driver.Value, len(values))
	for i := range values {
		args[i] = values[i].Value
	}
	return args
}

func preferredCause(primary, secondary error) error {
	if primary != nil && (errors.Is(primary, context.Canceled) || errors.Is(primary, context.DeadlineExceeded) || errors.Is(primary, driver.ErrBadConn)) {
		return primary
	}
	if secondary != nil && (errors.Is(secondary, context.Canceled) || errors.Is(secondary, context.DeadlineExceeded) || errors.Is(secondary, driver.ErrBadConn)) {
		return secondary
	}
	if primary != nil {
		return primary
	}
	return secondary
}

func publicError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return errors.Join(errPolicyFailed, context.Canceled)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(errPolicyFailed, context.DeadlineExceeded)
	}
	if errors.Is(err, driver.ErrBadConn) {
		return errors.Join(errPolicyFailed, driver.ErrBadConn)
	}
	if errors.Is(err, errPolicyRefused) {
		return errPolicyRefused
	}
	return errPolicyFailed
}

// resetError makes every reset failure discard-bearing. database/sql ignores
// SessionResetter errors that are not driver.ErrBadConn, so returning an
// ordinary policy or context error here could publish a connection after its
// invariant failed re-verification.
func resetError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return errors.Join(errPolicyFailed, context.Canceled, driver.ErrBadConn)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(errPolicyFailed, context.DeadlineExceeded, driver.ErrBadConn)
	}
	return driver.ErrBadConn
}
