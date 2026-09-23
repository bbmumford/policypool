package policypool

import (
	"context"
	"crypto/tls"
	"database/sql/driver"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"
)

// tlsVersionRefused runs a real TLS handshake that the server ends with an
// alert, and returns the error net/http gives the client for a URL carrying
// kindSecret.
func tlsVersionRefused(t *testing.T) error {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)
	client := server.Client()
	client.Transport.(*http.Transport).TLSClientConfig.MaxVersion = tls.VersionTLS12
	response, err := client.Post(server.URL+"/v2/pipeline?"+kindSecret, "application/json", nil)
	if response != nil {
		_ = response.Body.Close()
	}
	var alert *net.OpError
	if !errors.As(err, &alert) || alert.Op != "remote error" {
		t.Fatalf("handshake error %v is not the alert *net.OpError this test pins", err)
	}
	return err
}

// driverDialTimeout is a dial stopped by the dialer's own timeout, as
// net/http's default transport sets one, rather than by the caller's context.
func driverDialTimeout(t *testing.T) error {
	t.Helper()
	dialer := net.Dialer{Timeout: time.Nanosecond}
	conn, err := dialer.Dial("tcp", "127.0.0.1:1")
	if conn != nil {
		_ = conn.Close()
	}
	var dial *net.OpError
	if !errors.As(err, &dial) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("dial error %v is not the DeadlineExceeded *net.OpError this test pins", err)
	}
	return &url.Error{Op: "Post", URL: "http://db.example/v2/pipeline?" + kindSecret, Err: err}
}

// socketTimeout is a dial whose socket deadline fired: a bare i/o timeout,
// which is not DeadlineExceeded.
func socketTimeout() error {
	return &url.Error{Op: "Post", URL: "http://db.example/v2/pipeline?" + kindSecret,
		Err: &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}}
}

// endingContext is a caller context that ends with err when end is called, so
// a test can end it at the moment the driver's dial gives up.
type endingContext struct {
	context.Context
	done chan struct{}
	once sync.Once
	err  error
}

func newEndingContext(err error) *endingContext {
	return &endingContext{Context: context.Background(), done: make(chan struct{}), err: err}
}

func (c *endingContext) end()                  { c.once.Do(func() { close(c.done) }) }
func (c *endingContext) Done() <-chan struct{} { return c.done }
func (c *endingContext) Err() error {
	select {
	case <-c.done:
		return c.err
	default:
		return nil
	}
}

// pastDeadlineContext has reached its deadline but is not yet marked expired,
// as a context is between its deadline and its timer firing.
type pastDeadlineContext struct{ context.Context }

func (pastDeadlineContext) Deadline() (time.Time, bool) { return time.Now().Add(-time.Second), true }

// TestTLSAlertsAreNotUnreachable: crypto/tls reports an alert as a
// *net.OpError, but the server it came from was reached.
func TestTLSAlertsAreNotUnreachable(t *testing.T) {
	runKindCases(t, ErrDriverFailed, []kindCase{
		{name: "server alert from a real handshake", openErr: tlsVersionRefused(t)},
		{name: "local alert", openErr: &url.Error{Op: "Post", URL: "https://db.example/v2/pipeline?" + kindSecret,
			Err: &net.OpError{Op: "local error", Err: errors.New("tls: unexpected message")}}},
	})
}

// TestADriversOwnTimeoutIsUnreachable: with the caller's context live, a
// timed-out dial is the driver's own timeout, so it names the server and does
// not claim the caller's DeadlineExceeded.
func TestADriversOwnTimeoutIsUnreachable(t *testing.T) {
	for _, cause := range []struct {
		name string
		err  error
	}{
		{name: "dialer timeout", err: driverDialTimeout(t)},
		{name: "socket timeout", err: socketTimeout()},
	} {
		for _, entry := range everyEntry {
			t.Run(cause.name+"/"+entry.name, func(t *testing.T) {
				err, hidden := entry.open(context.Background(), t, &hostileScenario{openErr: cause.err})
				assertKind(t, err, ErrUnreachable, hidden)
				if errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("error %q claims the caller's deadline", err)
				}
			})
		}
	}

	// A deadline error classify cannot place keeps its identity and no kind.
	for _, entry := range everyEntry {
		t.Run("bare deadline/"+entry.name, func(t *testing.T) {
			scenario := &hostileScenario{plans: []hostilePlan{{queryErr: context.DeadlineExceeded}}}
			err, hidden := entry.open(context.Background(), t, scenario)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("error %q lost context.DeadlineExceeded", err)
			}
			assertNoKind(t, err, hidden)
		})
	}

	err := publicErrorUnder(context.Background(), errors.Join(driver.ErrBadConn, driverDialTimeout(t)))
	assertKind(t, err, ErrUnreachable)
	if !errors.Is(err, driver.ErrBadConn) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("bad connection timeout = %q, want driver.ErrBadConn and no DeadlineExceeded", err)
	}
}

// TestATimeoutUnderTheCallersEndedContextCarriesNoKind: once the caller's
// context has ended, a timeout or cancellation is the caller's, whatever form
// the driver gave it. The driver must have been reached, or the entry's own
// context check would pass the test without the path under test running.
func TestATimeoutUnderTheCallersEndedContextCarriesNoKind(t *testing.T) {
	canceledDial := &url.Error{Op: "Post", URL: "http://db.example/v2/pipeline?" + kindSecret,
		Err: &net.OpError{Op: "dial", Net: "tcp", Err: context.Canceled}}
	for _, test := range []struct {
		name  string
		cause error
		ended error
	}{
		{name: "dialer timeout at the caller's deadline", cause: driverDialTimeout(t), ended: context.DeadlineExceeded},
		{name: "socket timeout at the caller's deadline", cause: socketTimeout(), ended: context.DeadlineExceeded},
		{name: "dial cancelled with the caller", cause: canceledDial, ended: context.Canceled},
	} {
		for _, entry := range everyEntry {
			t.Run(test.name+"/"+entry.name, func(t *testing.T) {
				ctx := newEndingContext(test.ended)
				scenario := &hostileScenario{openErr: test.cause, onOpen: func(int) { ctx.end() }}
				err, hidden := entry.open(ctx, t, scenario)
				assertReachedOnce(t, scenario)
				if !errors.Is(err, test.ended) {
					t.Fatalf("error %q lost the caller's %v", err, test.ended)
				}
				assertNoKind(t, err, hidden)
			})
		}
	}

	for _, entry := range everyEntry {
		t.Run("socket timeout before the deadline is marked/"+entry.name, func(t *testing.T) {
			scenario := &hostileScenario{openErr: socketTimeout()}
			err, hidden := entry.open(pastDeadlineContext{context.Background()}, t, scenario)
			assertReachedOnce(t, scenario)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("error %q lost the caller's deadline", err)
			}
			assertNoKind(t, err, hidden)
		})
		// A failure that is not a timeout keeps its kind after the caller's
		// context ends.
		t.Run("refused dial/"+entry.name, func(t *testing.T) {
			ctx := newEndingContext(context.DeadlineExceeded)
			scenario := &hostileScenario{openErr: dialRefused("db.example"), onOpen: func(int) { ctx.end() }}
			err, hidden := entry.open(ctx, t, scenario)
			assertReachedOnce(t, scenario)
			assertKind(t, err, ErrUnreachable, hidden)
		})
	}
}

func assertReachedOnce(t *testing.T, scenario *hostileScenario) {
	t.Helper()
	if got := scenario.snapshot().opens; got != 1 {
		t.Fatalf("driver opened %d connections, want 1", got)
	}
}

// TestATimeoutsKindSurvivesASecondPass covers the pool connector's result
// classified again by openProved under the same context.
func TestATimeoutsKindSurvivesASecondPass(t *testing.T) {
	live := context.Background()
	twice := publicErrorUnder(live, publicErrorUnder(live, driverDialTimeout(t)))
	assertKind(t, twice, ErrUnreachable)
	if errors.Is(twice, context.DeadlineExceeded) {
		t.Fatalf("second pass %q claims the caller's deadline", twice)
	}

	ended := newEndingContext(context.DeadlineExceeded)
	ended.end()
	twice = publicErrorUnder(ended, publicErrorUnder(ended, socketTimeout()))
	if !errors.Is(twice, context.DeadlineExceeded) {
		t.Fatalf("second pass %q lost the caller's deadline", twice)
	}
	assertNoKind(t, twice)

	// The context ends between the passes: the connector saw it live.
	late := newEndingContext(context.DeadlineExceeded)
	first := publicErrorUnder(late, driverDialTimeout(t))
	late.end()
	assertKind(t, publicErrorUnder(late, first), ErrUnreachable)
}
