package policypool

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
)

var (
	errIsolationUnsupported = errors.New("policypool: isolation level unsupported")
	errReadOnlyUnsupported  = errors.New("policypool: read-only transaction unsupported")

	// errCanceled and errDeadline are publicError's form of a cancelled or
	// expired context: the standard sentinel under a package prefix, never the
	// cause that carried it.
	errCanceled = fmt.Errorf("policypool: %w", context.Canceled)
	errDeadline = fmt.Errorf("policypool: %w", context.DeadlineExceeded)
)

func contextError(ctx context.Context) error {
	if ctx == nil {
		return ErrPolicyRefused
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

// publicError is the form every open, probe, reset and close failure takes
// before it leaves the package.
//
// WHAT IT CONSUMES: a driver error, one of this package's own, or an earlier
// publicError result. WHAT CONSUMES IT: Open, OpenConnector, ProbeForeignKeys,
// the pool connector's Connect and Close, a policy connection's Close, and
// resetError.
//
// CONDITIONS. A cancelled or expired context keeps its identity and carries no
// kind, and is checked first because a dial the context stopped is also a
// *net.OpError. Otherwise the result is the error's kind, joined with
// driver.ErrBadConn when the error carries it so database/sql still discards
// and replaces the connection. The cause is never joined or wrapped: Join's
// message concatenates every member's, so joining a driver error would publish
// its data-source name.
func publicError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return errCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errDeadline
	}
	kind := kindOf(err)
	if errors.Is(err, driver.ErrBadConn) {
		return errors.Join(kind, driver.ErrBadConn)
	}
	return kind
}

// resetError makes every reset failure discard-bearing. database/sql ignores
// SessionResetter errors that are not driver.ErrBadConn, so returning an
// ordinary policy or context error here could publish a connection after its
// invariant failed re-verification. The failure's publicError form rides
// beside driver.ErrBadConn and never replaces it.
func resetError(err error) error {
	if err == nil {
		return nil
	}
	public := publicError(err)
	if errors.Is(public, driver.ErrBadConn) {
		return public
	}
	return errors.Join(public, driver.ErrBadConn)
}
