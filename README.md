# policypool

Opens a `database/sql` pool over a SQLite-family engine (modernc SQLite, Turso's tursogo, go-libsql replicas, sqld) in which every physical connection is proved to enforce foreign keys before it is used, and is refused when the proof fails (`driver.ErrBadConn`, so `database/sql` discards it). `PRAGMA foreign_keys` binds only the connection that ran it, so a pragma issued once through a `*sql.DB` leaves the pool's other connections accepting orphan rows; this package closes that gap. A statement that would turn enforcement off is refused for the connection's whole life.

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

## Consumers

ORBTR library, ai cortex, xyz and the api.orbtr.ai endpoint, io constellation, agent, tools and the help.orbtr.io endpoint, and the tursoraft, tursokv and loom packages.
