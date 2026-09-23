package policypool

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"modernc.org/sqlite"
)

// kindSecret stands for what a driver's error can carry: a URL query holding an
// auth token. Every kind test appends it to the cause and asserts it is gone.
const kindSecret = "authToken=SECRET-never-disclose"

// engineError is an engine error that reports an SQLite result code, as
// modernc's *sqlite.Error does, with whatever text the test gives it.
type engineError struct {
	code int
	text string
}

func (e *engineError) Error() string { return e.text }
func (e *engineError) Code() int     { return e.code }

func dialRefused(host string) error {
	return &url.Error{
		Op:  "Post",
		URL: "http://" + host + "/v2/pipeline?" + kindSecret,
		Err: &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)},
	}
}

func secretCause(text string) error { return errors.New(text + " " + kindSecret) }

// assertKind requires err to be want and no other kind, and to disclose none of
// hidden.
func assertKind(t *testing.T, err, want error, hidden ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("got no error, want %v", want)
	}
	if !errors.Is(err, want) {
		t.Fatalf("error %q is not %v", err, want)
	}
	for _, kind := range kinds {
		if kind != want && errors.Is(err, kind) {
			t.Fatalf("error %q is %v as well as %v", err, kind, want)
		}
	}
	assertHidden(t, err, hidden...)
}

func assertNoKind(t *testing.T, err error, hidden ...string) {
	t.Helper()
	for _, kind := range kinds {
		if errors.Is(err, kind) {
			t.Fatalf("error %q carries %v", err, kind)
		}
	}
	assertHidden(t, err, hidden...)
}

func assertHidden(t *testing.T, err error, hidden ...string) {
	t.Helper()
	for _, text := range append(hidden, kindSecret, "SECRET") {
		if text != "" && strings.Contains(err.Error(), text) {
			t.Fatalf("error %q discloses %q", err, text)
		}
	}
}

// kindEntry opens scenario through one of the three redacted entries and
// returns the error with the text that must not appear in it.
type kindEntry struct {
	name string
	open func(*testing.T, *hostileScenario) (error, string)
}

var (
	openEntry = kindEntry{name: "Open", open: func(t *testing.T, scenario *hostileScenario) (error, string) {
		name := registerHostileDriver(t, scenario)
		db, err := Open(context.Background(), name, "dsn="+kindSecret, ForeignKeysRequired)
		if db != nil {
			_ = db.Close()
			t.Fatal("Open published a pool")
		}
		return err, name
	}}
	connectorEntry = kindEntry{name: "OpenConnector", open: func(t *testing.T, scenario *hostileScenario) (error, string) {
		db, err := OpenConnector(context.Background(), &dsnConnector{base: scenario, dsn: "dsn=" + kindSecret}, ForeignKeysRequired)
		if db != nil {
			_ = db.Close()
			t.Fatal("OpenConnector published a pool")
		}
		return err, ""
	}}
	probeEntry = kindEntry{name: "ProbeForeignKeys", open: func(t *testing.T, scenario *hostileScenario) (error, string) {
		_, err := ProbeForeignKeys(context.Background(), &dsnConnector{base: scenario, dsn: "dsn=" + kindSecret})
		return err, ""
	}}
	everyEntry = []kindEntry{openEntry, connectorEntry, probeEntry}
)

type kindCase struct {
	name    string
	plan    hostilePlan
	openErr error
	entries []kindEntry
}

func runKindCases(t *testing.T, want error, cases []kindCase) {
	t.Helper()
	for _, test := range cases {
		entries := test.entries
		if entries == nil {
			entries = everyEntry
		}
		for _, entry := range entries {
			t.Run(test.name+"/"+entry.name, func(t *testing.T) {
				scenario := &hostileScenario{plans: []hostilePlan{test.plan}, openErr: test.openErr}
				err, hidden := entry.open(t, scenario)
				assertKind(t, err, want, hidden)
			})
		}
	}
}

func TestUnreachableServersAreReportedAsUnreachable(t *testing.T) {
	runKindCases(t, ErrUnreachable, []kindCase{
		{name: "dial refused under a url.Error", openErr: dialRefused("db.example")},
		{name: "name that does not resolve", openErr: &net.DNSError{Err: "no such host", Name: "SECRET.invalid", IsNotFound: true}},
		{name: "go-libsql remote connect", plan: hostilePlan{queryErr: secretCause(
			"failed to execute query PRAGMA foreign_keys\nerror code = 1: Error executing statement: Hrana: `http error: `error trying to connect: tcp connect error: Connection refused (os error 61)``")}},
		{name: "go-libsql remote lookup", plan: hostilePlan{queryErr: secretCause(
			"failed to execute query PRAGMA foreign_keys\nerror code = 1: Error executing statement: Hrana: `http error: `error trying to connect: dns error: failed to lookup address information: nodename nor servname provided, or not known``")}},
		{name: "go-libsql replica write delegation", plan: hostilePlan{queryErr: secretCause(
			"failed to execute query PRAGMA foreign_keys\nerror code = 1: Error executing statement: Write delegation: `status: Unavailable, message: \"error trying to connect: tcp connect error: Connection refused (os error 61)\"`")}},
	})
}

func TestRefusedCredentialsAreReportedAsUnauthorized(t *testing.T) {
	runKindCases(t, ErrUnauthorized, []kindCase{
		{name: "libsql-client-go http invalid token", plan: hostilePlan{queryErr: secretCause(
			"failed to execute SQL:\nerror code 401: Unauthorized: `The JWT is invalid`")}},
		{name: "libsql-client-go http missing token", plan: hostilePlan{queryErr: secretCause(
			"failed to execute SQL:\nerror code 401: Unauthorized: `The `Authorization` HTTP header is required but was not specified`")}},
		{name: "libsql-client-go websocket", plan: hostilePlan{queryErr: secretCause(
			"handshake error: Authentication failed: The JWT is invalid")}},
		{name: "go-libsql remote invalid token", plan: hostilePlan{queryErr: secretCause(
			"failed to execute query PRAGMA foreign_keys\nerror code = 1: Error executing statement: Hrana: `api error: `status=401 Unauthorized, body={\"error\":\"Unauthorized: `The JWT is invalid`\"}``")}},
		{name: "go-libsql replica read-only token", plan: hostilePlan{queryErr: secretCause(
			"failed to execute query PRAGMA foreign_keys\nerror code = 1: Error executing statement: Write delegation: `status: PermissionDenied, message: \"Not authorized to execute query: Current session doest not have Write permission to namespace default\"`")}},
		{name: "go-libsql remote read-only token", plan: hostilePlan{state: 0, enableErr: secretCause(
			"failed to execute query PRAGMA foreign_keys=ON\nerror code = 2: Error executing statement: Hrana: `api error: `status=500 Internal Server Error, body={\"error\":\"Internal Error: `Not authorized to execute query: Current session doest not have Write permission to namespace default`\"}``")}},
	})
}

func TestUnreadableFilesAreReportedAsNotADatabase(t *testing.T) {
	runKindCases(t, ErrNotADatabase, []kindCase{
		{name: "tursogo not a database", plan: hostilePlan{queryErr: errors.New("turso: not a database: file is not a database")}},
		{name: "tursogo wrong key", plan: hostilePlan{queryErr: errors.New("turso: error: Decryption failed for page=1")}},
		{name: "go-libsql wrong local key", openErr: fmt.Errorf("read the schema of /var/SECRET/local.db with the key applied: %w", errors.New(
			"failed to execute query SELECT count(*) FROM sqlite_schema\nerror code = 1: Error executing statement: SQLite failure: `file is not a database`"))},
		{name: "result code alone", plan: hostilePlan{queryErr: &engineError{code: sqliteNotADatabase, text: kindSecret}}},
	})

	// modernc proves the policy on a text file and fails at Ping, which only
	// Open and OpenConnector run.
	path := filepath.Join(t.TempDir(), "SECRET-notadb.db")
	if err := os.WriteFile(path, []byte(strings.Repeat("this file holds text, not a database\n", 4)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Run("modernc text file/Open", func(t *testing.T) {
		db, err := Open(context.Background(), "sqlite", path, ForeignKeysRequired)
		if db != nil {
			_ = db.Close()
			t.Fatal("Open published a pool over a text file")
		}
		assertKind(t, err, ErrNotADatabase, path)
	})
	t.Run("modernc text file/OpenConnector", func(t *testing.T) {
		db, err := OpenConnector(context.Background(), &dsnConnector{base: &sqlite.Driver{}, dsn: path}, ForeignKeysRequired)
		if db != nil {
			_ = db.Close()
			t.Fatal("OpenConnector published a pool over a text file")
		}
		assertKind(t, err, ErrNotADatabase, path)
	})
}

func TestAnEngineThatDoesNotShowEnforcementIsPolicyUnproved(t *testing.T) {
	pools := []kindEntry{openEntry, connectorEntry}
	runKindCases(t, ErrPolicyUnproved, []kindCase{
		{name: "setting does not take", plan: hostilePlan{state: 0, refuseEnable: true}, entries: pools},
		{name: "out of range", plan: hostilePlan{rows: []hostileRows{singleRow(int64(2))}}},
		{name: "missing row", plan: hostilePlan{rows: []hostileRows{{columns: []string{"foreign_keys"}}}}},
		{name: "string value", plan: hostilePlan{rows: []hostileRows{singleRow("1")}}},
		{name: "extra row", plan: hostilePlan{rows: []hostileRows{{
			columns: []string{"foreign_keys"},
			values:  [][]driver.Value{{int64(1)}, {int64(1)}},
		}}}},
		{name: "extra column", plan: hostilePlan{rows: []hostileRows{{
			columns: []string{"foreign_keys", "ambiguous"},
			values:  [][]driver.Value{{int64(1), int64(1)}},
		}}}},
	})
}

func TestUnclassifiedFailuresAreReportedAsDriverFailed(t *testing.T) {
	runKindCases(t, ErrDriverFailed, []kindCase{
		{name: "driver text with no known phrase", openErr: secretCause("opaque driver failure")},
		{name: "skip beside rows", plan: hostilePlan{state: 1, queryErr: driver.ErrSkip, queryRowsOnError: true}},
		// *url.Error satisfies net.Error whatever it wraps; a refused certificate
		// means the server answered.
		{name: "certificate refused", openErr: &url.Error{Op: "Post", URL: "https://db.example/?" + kindSecret,
			Err: errors.New("tls: failed to verify certificate: x509: certificate signed by unknown authority")}},
		// SQLITE_AUTH is the engine's authorizer denying a statement.
		{name: "authorizer denial", plan: hostilePlan{queryErr: &engineError{code: 23, text: "not authorized"}}},
		{name: "authorizer result text", plan: hostilePlan{queryErr: &engineError{code: 23, text: "authorization denied"}}},
	})

	unknown := "unregistered-" + kindSecret
	db, err := Open(context.Background(), unknown, "dsn="+kindSecret, ForeignKeysRequired)
	if db != nil {
		_ = db.Close()
	}
	assertKind(t, err, ErrDriverFailed, unknown)
}

func TestRefusalsAreReportedAsPolicyRefused(t *testing.T) {
	var noContext context.Context
	base := &dsnConnector{base: &hostileScenario{plans: []hostilePlan{{state: 1}}}, dsn: "dsn=" + kindSecret}
	for _, test := range []struct {
		name string
		call func(*testing.T) error
	}{
		{name: "Open zero policy", call: func(*testing.T) error {
			_, err := Open(context.Background(), "sqlite", "dsn="+kindSecret, 0)
			return err
		}},
		{name: "Open nil context", call: func(*testing.T) error {
			_, err := Open(noContext, "sqlite", "dsn="+kindSecret, ForeignKeysRequired)
			return err
		}},
		{name: "OpenConnector nil connector", call: func(*testing.T) error {
			_, err := OpenConnector(context.Background(), nil, ForeignKeysRequired)
			return err
		}},
		{name: "OpenConnector unknown policy", call: func(*testing.T) error {
			_, err := OpenConnector(context.Background(), base, 255)
			return err
		}},
		{name: "ProbeForeignKeys nil connector", call: func(*testing.T) error {
			_, err := ProbeForeignKeys(context.Background(), nil)
			return err
		}},
		{name: "ProbeForeignKeys nil context", call: func(*testing.T) error {
			_, err := ProbeForeignKeys(noContext, base)
			return err
		}},
		{name: "guarded statement", call: func(t *testing.T) error {
			_, err := pinnedModerncConnection(t).ExecContext(context.Background(), "PRAGMA foreign_keys=OFF")
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.call(t)
			assertKind(t, err, ErrPolicyRefused)
			if errors.Is(err, driver.ErrBadConn) {
				t.Fatalf("refusal %q carries driver.ErrBadConn, which makes database/sql retry it", err)
			}
		})
	}
}

// TestCancellationAndBadConnectionKeepTheirIdentity pins the identities a
// kind rides beside. A dial stopped by its context is a *net.OpError too, and
// is reported as the context's error with no kind.
func TestCancellationAndBadConnectionKeepTheirIdentity(t *testing.T) {
	stoppedDial := func(cause error) error {
		return &url.Error{Op: "Post", URL: "http://db.example/?" + kindSecret, Err: &net.OpError{Op: "dial", Net: "tcp", Err: cause}}
	}
	for _, test := range []struct {
		name     string
		plan     hostilePlan
		openErr  error
		identity error
		kind     error
	}{
		{name: "canceled dial", openErr: stoppedDial(context.Canceled), identity: context.Canceled},
		{name: "expired dial", openErr: stoppedDial(context.DeadlineExceeded), identity: context.DeadlineExceeded},
		{name: "canceled query", plan: hostilePlan{queryErr: context.Canceled}, identity: context.Canceled},
		{name: "bad connection", plan: hostilePlan{queryErr: driver.ErrBadConn}, identity: driver.ErrBadConn, kind: ErrDriverFailed},
		{name: "bad connection over a reset transport", plan: hostilePlan{queryErr: errors.Join(driver.ErrBadConn,
			&url.Error{Op: "Post", URL: "http://db.example/?" + kindSecret, Err: &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}})},
			identity: driver.ErrBadConn, kind: ErrUnreachable},
	} {
		for _, entry := range everyEntry {
			t.Run(test.name+"/"+entry.name, func(t *testing.T) {
				scenario := &hostileScenario{plans: []hostilePlan{test.plan}, openErr: test.openErr}
				err, hidden := entry.open(t, scenario)
				if !errors.Is(err, test.identity) {
					t.Fatalf("error %q lost %v", err, test.identity)
				}
				if test.kind == nil {
					assertNoKind(t, err, hidden)
					return
				}
				assertKind(t, err, test.kind, hidden)
			})
		}
	}
}

// kindCauses are raw driver errors with the kind publicError must give each.
var kindCauses = []struct {
	name  string
	cause error
	kind  error
}{
	{name: "unreachable", cause: dialRefused("db.example"), kind: ErrUnreachable},
	{name: "unauthorized", cause: secretCause("error code 401: Unauthorized"), kind: ErrUnauthorized},
	{name: "not a database", cause: secretCause("file is not a database"), kind: ErrNotADatabase},
	{name: "unproved", cause: ErrPolicyUnproved, kind: ErrPolicyUnproved},
	{name: "refused", cause: ErrPolicyRefused, kind: ErrPolicyRefused},
	{name: "unclassified", cause: secretCause("opaque"), kind: ErrDriverFailed},
	{name: "bad connection", cause: errors.Join(driver.ErrBadConn, dialRefused("db.example")), kind: ErrUnreachable},
}

// TestAKindSurvivesASecondPass covers the open path's double classification:
// the pool connector's result is what openProved classifies again.
func TestAKindSurvivesASecondPass(t *testing.T) {
	for _, test := range kindCauses {
		t.Run(test.name, func(t *testing.T) {
			once := publicError(test.cause)
			twice := publicError(once)
			assertKind(t, once, test.kind)
			assertKind(t, twice, test.kind)
			if errors.Is(test.cause, driver.ErrBadConn) != errors.Is(twice, driver.ErrBadConn) {
				t.Fatalf("second pass changed driver.ErrBadConn identity: %q", twice)
			}
		})
	}
	for _, identity := range []error{context.Canceled, context.DeadlineExceeded} {
		twice := publicError(publicError(fmt.Errorf("%s: %w", kindSecret, identity)))
		if !errors.Is(twice, identity) {
			t.Fatalf("second pass lost %v: %q", identity, twice)
		}
		assertNoKind(t, twice)
	}
}

// TestResetFailuresStayDiscardBearingAndKeepTheirKind: database/sql ignores a
// SessionResetter error that is not driver.ErrBadConn, so the kind rides
// beside it.
func TestResetFailuresStayDiscardBearingAndKeepTheirKind(t *testing.T) {
	for _, test := range kindCauses {
		t.Run(test.name, func(t *testing.T) {
			err := resetError(test.cause)
			if !errors.Is(err, driver.ErrBadConn) {
				t.Fatalf("resetError(%s) = %q, want driver.ErrBadConn", test.name, err)
			}
			assertKind(t, err, test.kind)
		})
	}
	err := resetError(fmt.Errorf("%s: %w", kindSecret, context.Canceled))
	if !errors.Is(err, driver.ErrBadConn) || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled reset = %q, want driver.ErrBadConn and context.Canceled", err)
	}
	assertNoKind(t, err)
}
