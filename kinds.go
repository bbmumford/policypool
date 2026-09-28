package policypool

import (
	"errors"
	"net"
	"strings"
)

// The kinds below are the errors Open, OpenConnector and ProbeForeignKeys
// return, and the errors a pool's own connection opens, resets and closes fail
// with. A caller tells them apart with errors.Is.
//
// Each is a fixed message with no arguments. A driver's error can carry a
// data-source name, a server URL or a file path, and a data-source name can
// hold an auth token or an encryption key, so the cause is read to choose the
// kind and then dropped; no kind wraps or joins it. An error carries at most
// one kind. driver.ErrBadConn keeps its errors.Is identity beside the kind. A
// timeout or cancellation under a caller's context that has ended keeps that
// context's identity and carries no kind, because the caller's deadline says
// nothing about the server. A deadline the driver set for itself, reached while
// the caller's context is live, is not the caller's and does not carry its
// identity.
var (
	// ErrPolicyRefused is policypool refusing the call itself: a nil context or
	// connector, a policy other than ForeignKeysRequired or
	// ForeignKeysRequiredAtConnect, or, on a policy connection under either, a
	// statement that would turn foreign keys off. It is never
	// driver.ErrBadConn, so database/sql returns a refused statement to its
	// caller instead of retrying it on another connection. Retrying the same
	// call cannot succeed.
	ErrPolicyRefused = errors.New("policypool: connection policy refused")

	// ErrPolicyUnproved is an engine that answered without showing foreign-key
	// enforcement on: PRAGMA foreign_keys read 0 after it was set, or its
	// read-back was not exactly one row holding the integer 0 or 1. Open and
	// OpenConnector refuse such a pool. ProbeForeignKeys reports an engine that
	// stays at 0 as enforced=false with no error, and returns this kind only for
	// a read-back it cannot read.
	ErrPolicyUnproved = errors.New("policypool: connection policy not proved")

	// ErrUnreachable is a database server that could not be reached: a dial,
	// name lookup or network transfer failed, including one the driver's own
	// timeout stopped while the caller's context was live, or the driver
	// reported that it could not connect. A name that does not resolve is this
	// kind too, so it does not say whether a database was deleted. A caller may
	// retry, or read from a replica it already holds.
	ErrUnreachable = errors.New("policypool: database server unreachable")

	// ErrUnauthorized is a database server that refused the credential, or a
	// credential that does not permit the statements the policy runs. Retrying
	// with the same credential cannot succeed. A statement denied by an engine's
	// own authorizer callback is not this kind.
	ErrUnauthorized = errors.New("policypool: database credential refused")

	// ErrNotADatabase is a file the engine could not read as a database under
	// the key it was given. That includes a file encrypted under another key or
	// opened without its key: go-libsql reports a wrong local key as "file is
	// not a database", and tursogo's decryption failure is read as this kind so
	// that both engines report the same condition the same way. It includes a
	// file shorter than one page opened under a key, which tursogo reports as
	// a short read of page 1 where the same file opened without a key reads as
	// "not a database". A replica that can be synced again may be deleted on
	// this kind; a file that is the only copy of its data must not be.
	ErrNotADatabase = errors.New("policypool: file is not a readable database")

	// ErrDriverFailed is every other failure: an unregistered driver name, a
	// driver error no other kind describes, or a driver that breaks the
	// database/sql contract by returning driver.ErrSkip beside a result, or a
	// nil connection, statement or rows with no error.
	ErrDriverFailed = errors.New("policypool: driver failed")
)

// kinds lets kindOf keep a kind an earlier pass chose. Open and OpenConnector
// classify twice: the pool's connector classifies a failed connection, and
// database/sql's Ping hands that result to openProved, which classifies again.
var kinds = [...]error{
	ErrPolicyRefused,
	ErrPolicyUnproved,
	ErrUnreachable,
	ErrUnauthorized,
	ErrNotADatabase,
	ErrDriverFailed,
}

// kindOf returns the one kind err carries or reads as, and ErrDriverFailed
// when classify finds none.
func kindOf(err error) error {
	for _, kind := range kinds {
		if errors.Is(err, kind) {
			return kind
		}
	}
	if kind := classify(err); kind != nil {
		return kind
	}
	return ErrDriverFailed
}

// sqliteNotADatabase is SQLITE_NOTADB, the primary result code an SQLite
// engine gives a file it cannot read as a database.
const sqliteNotADatabase = 26

// The text each driver below gives a condition it reports only as text,
// matched lower-cased. Every entry is a phrase the named driver produces:
// libsql-client-go for a refused token ("error code 401: Unauthorized"
// over HTTP, "handshake error: Authentication failed" over WebSocket); go-libsql
// for a refused or read-only token ("status=401 Unauthorized", "status:
// PermissionDenied ... Not authorized to execute query"), a server it could not
// connect to ("error trying to connect", "status: Unavailable") and a file
// under the wrong key ("file is not a database"); tursogo for a file that is
// not a database ("not a database"), is under the wrong key ("Decryption
// failed") or is shorter than one page under a key ("short read on page 1:").
// The colon ends the page number, so a short read of a later page, which
// comes after page 1 decrypted and so is a damaged database rather than a
// file that is not one, matches nothing.
//
// "not authorized" alone is deliberately absent: it is the whole message of
// SQLite's own authorizer denial, which is a statement refused, not a
// credential.
var (
	unauthorizedText = [...]string{
		"unauthorized",
		"authentication failed",
		"error code 401",
		"status=401",
		"status: permissiondenied",
		"not authorized to execute query",
	}
	notADatabaseText = [...]string{
		"not a database",
		"decryption failed",
		"short read on page 1:",
	}
	unreachableText = [...]string{
		"error trying to connect",
		"status: unavailable",
	}
)

// classify names the kind of a driver error, or returns nil when none applies.
// It returns only a sentinel and keeps nothing of cause.
//
// WHAT CONSUMES IT: kindOf, for publicError and resetError, and
// publicErrorUnder, which asks whether a driver's own timeout stopped a dial.
//
// CONDITIONS. Typed checks run first because they do not depend on wording.
// A *net.OpError or *net.DNSError anywhere in the chain is ErrUnreachable:
// libsql-client-go's dial failures reach the caller as a *url.Error whose text
// holds the server's URL, with the *net.OpError inside it. The exception is
// the *net.OpError crypto/tls returns for a TLS alert, whose Op is "remote
// error" when the server sent the alert and "local error" when this side did:
// the server was reached and the connection refused, so it is not this kind.
// The net.Error interface alone is not enough either, because *url.Error
// satisfies it whatever it wraps, a refused TLS certificate included. An error
// with a Code() int method whose primary code is SQLITE_NOTADB is
// ErrNotADatabase: modernc's *sqlite.Error is one, and it surfaces at Ping on
// a file that is not a database. SQLITE_AUTH (23) maps to nothing, because it
// is an authorizer callback denying a statement, not a server refusing a
// credential. The text checks come last and are the only signal from drivers
// that build their errors as text; a credential or file message proves the
// server or file was reached, so both are tried before the connect phrases.
func classify(cause error) error {
	var dial *net.OpError
	var lookup *net.DNSError
	if (errors.As(cause, &dial) && !isTLSAlert(dial)) || errors.As(cause, &lookup) {
		return ErrUnreachable
	}
	var coded interface{ Code() int }
	if errors.As(cause, &coded) && coded.Code()&0xff == sqliteNotADatabase {
		return ErrNotADatabase
	}
	text := strings.ToLower(cause.Error())
	switch {
	case containsAny(text, unauthorizedText[:]):
		return ErrUnauthorized
	case containsAny(text, notADatabaseText[:]):
		return ErrNotADatabase
	case containsAny(text, unreachableText[:]):
		return ErrUnreachable
	}
	return nil
}

// isTLSAlert reports whether err is the *net.OpError crypto/tls returns for a
// TLS alert rather than a failed dial or transfer.
func isTLSAlert(err *net.OpError) bool {
	return err.Op == "remote error" || err.Op == "local error"
}

func containsAny(text string, phrases []string) bool {
	for _, phrase := range phrases {
		if strings.Contains(text, phrase) {
			return true
		}
	}
	return false
}
