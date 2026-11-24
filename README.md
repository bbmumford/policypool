# policypool

policypool opens a `database/sql` pool over a SQLite-family engine (modernc SQLite, Turso's tursogo, go-libsql replicas, sqld) in which every physical connection is proved to enforce foreign keys before it is used, and is refused when the proof fails (`driver.ErrBadConn`, so `database/sql` discards it). `PRAGMA foreign_keys` binds only the connection that ran it, so a pragma issued once through a `*sql.DB` leaves the pool's other connections accepting orphan rows; this package closes that gap. A statement that would turn enforcement off is refused for the connection's whole life.

Every driver error comes back as one of six fixed, redacted kinds, so no DSN, token, key or path reaches an error message: `ErrPolicyRefused`, `ErrPolicyUnproved`, `ErrUnreachable`, `ErrUnauthorized`, `ErrNotADatabase`, `ErrDriverFailed`.

## Use

```sh
go get github.com/bbmumford/policypool
```

```go
db, err := policypool.Open(ctx, "sqlite", dsn, policypool.ForeignKeysRequired)
// or, over a driver.Connector:
db, err = policypool.OpenConnector(ctx, connector, policypool.ForeignKeysRequiredAtConnect)

if errors.Is(err, policypool.ErrUnreachable) { /* retry later */ }
```

| Policy | Proved | For |
|---|---|---|
| `ForeignKeysRequired` | on every new connection and each time the pool hands a connection out | every pool whose connection can lose the setting without a statement (a remote session the driver reopens starts at the server's default) |
| `ForeignKeysRequiredAtConnect` | on every new connection only | a go-libsql embedded replica, whose connection loses the setting only by a statement; proving on each reuse would send every pooled read to the primary |

`ProbeForeignKeys` reports whether a connector's connections enforce foreign keys, without opening a pool.

### A file of a known kind

`OpenFile` and `OpenFileConnector` open a pool as `Open` and `OpenConnector` do, then check the file's identity header against an `Identity` (a filekind kind, the generation the code writes and the oldest it reads). A new empty file is stamped once however many openers race; a file of another kind or application, an unregistered kind, or a generation outside the range is refused with `ErrFileIdentity`. Every connection of such a pool refuses a statement that assigns `application_id` or `user_version`, so the identity changes only through `AdvanceGeneration`, which runs the caller's migration and the new generation in one transaction.

## Dependencies

- `github.com/bbmumford/filekind`: the identity header check and stamp behind
  `OpenFile`. `go.mod` replaces it with the sibling checkout `../filekind`.
- No external module in its production code: policypool works over whichever
  driver the caller names. Tests only: `modernc.org/sqlite`.

## Used by

Importers in the ORBTR estate:

- `github.com/bbmumford/tursoraft/localdb` and `replica`,
  `github.com/bbmumford/tursokv/sqlx` and `github.com/bbmumford/loom/node`.
- `github.com/ORBTR/Library/identity/provisioning/partitiondb`,
  `github.com/ORBTR/cortex/tenant/tenantdb`,
  `github.com/ORBTR/xyz/library/controldb` and `library/tenantdb`, and
  `github.com/ORBTR/constellation/domain/identity/provisioning/tenantdb`:
  the per-partition and control databases.
- `github.com/ORBTR/agent/internal/store`, `github.com/ORBTR/api.orbtr.ai`,
  `github.com/ORBTR/help.orbtr.io` and `github.com/ORBTR/tools/schemaref`.

## Platforms and build

Pure Go, no cgo and no build tags. The module's `go` directive is 1.25.0.

## Licence

MIT. Copyright (c) 2026 Brandon Miller-Mumford. The full text is in
[LICENSE](LICENSE).

## Contributing

[AGENTS.md](AGENTS.md) holds the repository's two rules, for people and coding
agents alike: no temporary documents in the repository, and conventional commit
messages that stand on their own. [CLAUDE.md](CLAUDE.md) imports it for Claude
Code.
