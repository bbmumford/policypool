package policypool

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"

	"github.com/bbmumford/filekind"
)

// Identity is the kind and format generation a pool's database file carries
// in its header (PRAGMA application_id and user_version), as filekind's
// registry and format define them.
//
// WHAT CONSUMES IT: OpenFile and OpenFileConnector, which check the header when
// the pool opens, stamp a new empty file with it, and refuse every caller's
// statement that would assign either header field; AdvanceGeneration, the one
// way such a pool's file moves to a later generation.
//
// CONDITIONS. Generation is the generation this code writes and the newest it
// reads. Oldest is the oldest it reads; 0 reads Generation only, so a release
// that still reads the file an older release left declares that generation
// until its update is confirmed.
type Identity struct {
	Kind       filekind.Kind
	Generation int32
	Oldest     int32
}

func (id Identity) want() filekind.Want {
	oldest := id.Oldest
	if oldest == 0 {
		oldest = id.Generation
	}
	return filekind.Want{Kind: id.Kind, Newest: id.Generation, Oldest: oldest}
}

// valid refuses an Identity no file could carry: an unregistered kind, a
// generation below 1, an oldest above the generation.
func (id Identity) valid() bool {
	_, registered := filekind.Lookup(id.Kind)
	return registered && id.Generation >= 1 && id.Oldest >= 0 && id.Oldest <= id.Generation
}

// ErrFileIdentity is the kind of every header refusal: the file is unstamped
// and already holds a schema, belongs to another application, is another or an
// unknown kind, or carries a generation outside the Identity's range. The error
// also matches filekind's sentinel for the reason (errors.Is), and its text
// holds only the two header numbers. A cache's opener rebuilds the file on it;
// an authoritative file's opener stops and reports it.
var ErrFileIdentity = errors.New("policypool: file identity refused")

type identityError struct{ cause error }

func (e *identityError) Error() string        { return ErrFileIdentity.Error() + ": " + e.cause.Error() }
func (e *identityError) Is(target error) bool { return target == ErrFileIdentity }
func (e *identityError) Unwrap() error        { return e.cause }

// OpenFile is Open for a database file that must carry identity in its header.
// After the policy is proved on the first connection, the header is checked:
// a file holding identity's kind at a generation it reads opens; a new file,
// unstamped and holding no schema, is stamped with identity's kind and
// generation, once however many openers race (filekind.Create); anything else
// is ErrFileIdentity. Every connection of the pool then refuses a statement
// assigning application_id or user_version with ErrPolicyRefused.
//
// It is for a file one process owns; a file that is a copy of another database,
// as an embedded replica is, carries the header its source stamped.
func OpenFile(ctx context.Context, driverName, dsn string, policy ConnectionPolicy, identity Identity) (*sql.DB, error) {
	return openNamed(ctx, driverName, dsn, policy, &identity)
}

// OpenFileConnector is OpenFile for a caller that builds its own connector, on
// OpenConnector's terms.
func OpenFileConnector(ctx context.Context, base driver.Connector, policy ConnectionPolicy, identity Identity) (*sql.DB, error) {
	return openConnector(ctx, base, policy, &identity)
}

// releaseConn is the deferred Close of the one connection proveIdentity and
// AdvanceGeneration each take from the pool. Close only hands the connection
// back to the pool, and its one error, sql.ErrConnDone, means it is back
// already; the caller acts on the check's own result, so Close's is dropped.
func releaseConn(conn *sql.Conn) { _ = conn.Close() }

// proveIdentity checks the pool's file against identity on one connection,
// stamping a new file. Engine failures keep the package's redaction; a header
// refusal is ErrFileIdentity.
func proveIdentity(ctx context.Context, db *sql.DB, identity Identity) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return publicErrorUnder(ctx, err)
	}
	defer releaseConn(conn)
	h, err := filekind.Check(ctx, conn, identity.want())
	if err != nil && h == (filekind.Header{}) && errors.Is(err, filekind.ErrUnstamped) {
		err = withStamping(conn, func() error {
			_, err := filekind.Create(ctx, conn, identity.Kind, identity.Generation, nil)
			return err
		})
	}
	return identityRefusal(ctx, err)
}

// AdvanceGeneration moves the file of a pool opened with OpenFile or
// OpenFileConnector to generation, for an update's confirm step. migrate runs
// in one transaction with the new user_version, so the format change and the
// number that names it commit together or not at all; the header is then
// checkpointed into the file. migrate runs under the pool's refusals, header
// assignments included.
//
// It refuses (ErrPolicyRefused) a pool opened without an Identity, and refuses
// (ErrFileIdentity) a file not of the pool's kind or already past generation;
// advancing to the generation a file holds runs migrate and changes nothing
// else. The pool's own Identity is not changed: the caller reopens with the
// new one once the update is confirmed.
func AdvanceGeneration(ctx context.Context, db *sql.DB, generation int32, migrate func(context.Context, *sql.Tx) error) error {
	if ctx == nil || db == nil || migrate == nil || generation < 1 {
		return ErrPolicyRefused
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return publicErrorUnder(ctx, err)
	}
	defer releaseConn(conn)
	var identity *Identity
	if err := conn.Raw(func(dc any) error {
		pc, ok := dc.(*policyConn)
		if !ok || pc.identity == nil {
			return ErrPolicyRefused
		}
		identity = pc.identity
		return nil
	}); err != nil {
		return err
	}
	if _, err := filekind.Check(ctx, conn, filekind.Want{Kind: identity.Kind, Newest: generation}); err != nil {
		return identityRefusal(ctx, err)
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return publicErrorUnder(ctx, err)
	}
	if err := migrate(ctx, tx); err != nil {
		return errors.Join(err, tx.Rollback())
	}
	if err := withStamping(conn, func() error { return filekind.SetHeader(ctx, tx, identity.Kind, generation) }); err != nil {
		_ = tx.Rollback()
		return identityRefusal(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return publicErrorUnder(ctx, err)
	}
	return identityRefusal(ctx, filekind.Checkpoint(ctx, conn))
}

// withStamping runs f with conn's header-assignment refusal lifted, and always
// restores it. conn is held by the caller alone, so nothing else runs a
// statement on that connection while the refusal is lifted.
func withStamping(conn *sql.Conn, f func() error) error {
	set := func(on bool) error {
		return conn.Raw(func(dc any) error {
			pc, ok := dc.(*policyConn)
			if !ok || pc.identity == nil {
				return ErrPolicyRefused
			}
			pc.stamping = on
			return nil
		})
	}
	if err := set(true); err != nil {
		return err
	}
	err := f()
	if restore := set(false); restore != nil {
		return errors.Join(err, restore)
	}
	return err
}

// identityRefusal is nil for nil; ErrFileIdentity around a header refusal, a
// header the engine did not answer as one integer, or a checkpoint that could
// not finish, whose texts hold only numbers; and the package's redacted kind
// for anything else the engine returned.
func identityRefusal(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	var refused *filekind.HeaderError
	if errors.As(err, &refused) {
		return &identityError{cause: refused}
	}
	if errors.Is(err, filekind.ErrCheckpointBusy) || errors.Is(err, filekind.ErrUnreadableHeader) {
		return &identityError{cause: err}
	}
	if errors.Is(err, ErrPolicyRefused) {
		return ErrPolicyRefused
	}
	return publicErrorUnder(ctx, err)
}
