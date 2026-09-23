package policypool

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
)

// hostileDrift turns a hostile connection's foreign keys off through a
// statement the guard does not read as a pragma. It stands for an engine that
// loses the setting by a path no statement text shows, which the session-reset
// tests need at checkout: the guard refuses every pragma spelling that would
// put a connection there.
const hostileDrift = "HOSTILE DRIFT"

type hostileScenario struct {
	mu      sync.Mutex
	plans   []hostilePlan
	factory func(int) hostilePlan
	openErr error
	onOpen  func(int)

	opens               int
	closes              int
	queries             int
	enables             int
	uninitialized       int
	closedByConnection  []int
	runtimeByConnection []int
}

type hostilePlan struct {
	state            int64
	rows             []hostileRows
	queryErr         error
	queryRowsOnError bool
	resetErr         error
	enableErr        error
	refuseEnable     bool
	closeErr         error
	pingErr          error
	runtimeErr       error
	badRuntimeOnce   bool
}

type hostileSnapshot struct {
	opens               int
	closes              int
	queries             int
	enables             int
	uninitialized       int
	closedByConnection  []int
	runtimeByConnection []int
}

func (s *hostileScenario) Open(string) (driver.Conn, error) {
	s.mu.Lock()
	index := s.opens
	s.opens++
	s.closedByConnection = append(s.closedByConnection, 0)
	s.runtimeByConnection = append(s.runtimeByConnection, 0)
	plan := hostilePlan{}
	if s.factory != nil {
		plan = s.factory(index)
	} else if len(s.plans) > 0 {
		plan = s.plans[min(index, len(s.plans)-1)]
	}
	openErr := s.openErr
	onOpen := s.onOpen
	s.mu.Unlock()
	if onOpen != nil {
		onOpen(index)
	}
	if openErr != nil {
		return nil, openErr
	}
	return &hostileConn{scenario: s, plan: plan, index: index, state: plan.state, badRuntime: plan.badRuntimeOnce}, nil
}

func (s *hostileScenario) snapshot() hostileSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return hostileSnapshot{
		opens:               s.opens,
		closes:              s.closes,
		queries:             s.queries,
		enables:             s.enables,
		uninitialized:       s.uninitialized,
		closedByConnection:  append([]int(nil), s.closedByConnection...),
		runtimeByConnection: append([]int(nil), s.runtimeByConnection...),
	}
}

type hostileConn struct {
	scenario   *hostileScenario
	plan       hostilePlan
	index      int
	mu         sync.Mutex
	state      int64
	query      int
	badRuntime bool
	closeOnce  sync.Once
}

func (c *hostileConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare unsupported")
}

func (c *hostileConn) Close() error {
	c.closeOnce.Do(func() {
		c.scenario.mu.Lock()
		c.scenario.closes++
		c.scenario.closedByConnection[c.index]++
		c.scenario.mu.Unlock()
	})
	return c.plan.closeErr
}

func (c *hostileConn) Begin() (driver.Tx, error) {
	return nil, errors.New("transactions unsupported")
}

func (c *hostileConn) Ping(context.Context) error { return c.plan.pingErr }

func (c *hostileConn) ResetSession(context.Context) error { return c.plan.resetErr }

func (c *hostileConn) QueryContext(ctx context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if query != "PRAGMA foreign_keys" {
		return nil, errors.New("query unsupported")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.scenario.mu.Lock()
	c.scenario.queries++
	c.scenario.mu.Unlock()
	if c.plan.queryErr != nil {
		if c.plan.queryRowsOnError {
			return &hostileResultRows{spec: singleRow(c.state)}, c.plan.queryErr
		}
		return nil, c.plan.queryErr
	}
	var rows hostileRows
	if len(c.plan.rows) > 0 {
		rows = c.plan.rows[min(c.query, len(c.plan.rows)-1)]
	} else {
		rows = singleRow(c.state)
	}
	c.query++
	return &hostileResultRows{spec: rows}, nil
}

func (c *hostileConn) ExecContext(ctx context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	switch query {
	case "PRAGMA foreign_keys=ON":
		if c.plan.enableErr != nil {
			return nil, c.plan.enableErr
		}
		c.scenario.mu.Lock()
		c.scenario.enables++
		c.scenario.mu.Unlock()
		if !c.plan.refuseEnable {
			c.state = 1
		}
		return driver.RowsAffected(0), nil
	case hostileDrift:
		c.state = 0
		return driver.RowsAffected(0), nil
	default:
		c.scenario.mu.Lock()
		c.scenario.runtimeByConnection[c.index]++
		c.scenario.mu.Unlock()
		if c.state != 1 {
			c.scenario.mu.Lock()
			c.scenario.uninitialized++
			c.scenario.mu.Unlock()
		}
		if c.badRuntime {
			c.badRuntime = false
			return nil, driver.ErrBadConn
		}
		if c.plan.runtimeErr != nil {
			return nil, c.plan.runtimeErr
		}
		return driver.RowsAffected(1), nil
	}
}

type hostileRows struct {
	columns  []string
	values   [][]driver.Value
	nextErr  error
	closeErr error
	onClose  func()
}

func singleRow(value driver.Value) hostileRows {
	return hostileRows{columns: []string{"foreign_keys"}, values: [][]driver.Value{{value}}}
}

type hostileResultRows struct {
	spec      hostileRows
	index     int
	nextErr   bool
	closeOnce sync.Once
}

func (r *hostileResultRows) Columns() []string { return r.spec.columns }

func (r *hostileResultRows) Close() error {
	r.closeOnce.Do(func() {
		if r.spec.onClose != nil {
			r.spec.onClose()
		}
	})
	return r.spec.closeErr
}

func (r *hostileResultRows) Next(dest []driver.Value) error {
	if r.index < len(r.spec.values) {
		copy(dest, r.spec.values[r.index])
		r.index++
		return nil
	}
	if r.spec.nextErr != nil && !r.nextErr {
		r.nextErr = true
		return r.spec.nextErr
	}
	return io.EOF
}

var hostileDriverSequence atomic.Uint64

func registerHostileDriver(t *testing.T, scenario *hostileScenario) string {
	t.Helper()
	name := fmt.Sprintf("policypool_hostile_%d", hostileDriverSequence.Add(1))
	sql.Register(name, scenario)
	return name
}

type preparedOnlyDriver struct {
	mu            sync.Mutex
	opens         int
	queries       int
	enables       int
	uninitialized int
}

func (d *preparedOnlyDriver) Open(string) (driver.Conn, error) {
	d.mu.Lock()
	d.opens++
	d.mu.Unlock()
	return &preparedOnlyConn{owner: d}, nil
}

type preparedOnlyConn struct {
	owner *preparedOnlyDriver
	mu    sync.Mutex
	state int64
}

func (c *preparedOnlyConn) Prepare(query string) (driver.Stmt, error) {
	switch query {
	case "PRAGMA foreign_keys", "PRAGMA foreign_keys=ON", "WORK":
		return &preparedOnlyStmt{conn: c, query: query}, nil
	default:
		return nil, errors.New("unsupported statement")
	}
}

func (*preparedOnlyConn) Close() error { return nil }
func (*preparedOnlyConn) Begin() (driver.Tx, error) {
	return nil, errors.New("transactions unsupported")
}

type preparedOnlyStmt struct {
	conn  *preparedOnlyConn
	query string
}

func (*preparedOnlyStmt) Close() error  { return nil }
func (*preparedOnlyStmt) NumInput() int { return 0 }

func (s *preparedOnlyStmt) Exec([]driver.Value) (driver.Result, error) {
	s.conn.mu.Lock()
	defer s.conn.mu.Unlock()
	switch s.query {
	case "PRAGMA foreign_keys=ON":
		s.conn.state = 1
		s.conn.owner.mu.Lock()
		s.conn.owner.enables++
		s.conn.owner.mu.Unlock()
		return driver.RowsAffected(0), nil
	case "WORK":
		if s.conn.state != 1 {
			s.conn.owner.mu.Lock()
			s.conn.owner.uninitialized++
			s.conn.owner.mu.Unlock()
		}
		return driver.RowsAffected(1), nil
	default:
		return nil, errors.New("statement is not executable")
	}
}

func (s *preparedOnlyStmt) Query([]driver.Value) (driver.Rows, error) {
	if s.query != "PRAGMA foreign_keys" {
		return nil, errors.New("statement is not queryable")
	}
	s.conn.mu.Lock()
	state := s.conn.state
	s.conn.mu.Unlock()
	s.conn.owner.mu.Lock()
	s.conn.owner.queries++
	s.conn.owner.mu.Unlock()
	return &hostileResultRows{spec: singleRow(state)}, nil
}
