package gostls_test

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/tarantool/go-gostls"
	"github.com/tarantool/go-gostls/internal/testutil"
)

// ============================================================================
// crypto/tls-compatible entry points: Dialer.Dial, Dial, DialWithDialer,
// Client. The stdlib TLS 1.2 echo server they dial is startStdlibTLSServer
// from dialer_dial_test.go.
// ============================================================================.

// Client and NewConn are one constructor under two names — the crypto/tls
// spelling and the native one. The compiler checks that they stay identical.
var (
	_ func(net.Conn, *gostls.Config) *gostls.Conn = gostls.Client
	_ func(net.Conn, *gostls.Config) *gostls.Conn = gostls.NewConn
)

// roundTrip writes a small payload and reads it back, confirming the
// connection carries application data after the handshake.
func roundTrip(t *testing.T, conn net.Conn) {
	t.Helper()

	want := []byte("ping")

	_, err := conn.Write(want)
	testutil.NoErr(t, err, "Write")

	got := make([]byte, len(want))

	_, err = conn.Read(got)
	testutil.NoErr(t, err, "Read")

	testutil.EqualBytes(t, got, want, "round-trip payload")
}

// startStallingTCPListener accepts connections, drains whatever the client
// sends and never replies — a peer that completes the TCP connect and then
// hangs mid-handshake.
func startStallingTCPListener(t *testing.T) net.Listener {
	t.Helper()

	lc := &net.ListenConfig{}

	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	testutil.NoErr(t, err, "listen")

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return // listener closed.
			}

			go func(c net.Conn) {
				defer func() { _ = c.Close() }()

				_, _ = io.Copy(io.Discard, c)
			}(conn)
		}
	}()

	return ln
}

// TestDialer_Dial_Success dials a real stdlib TLS 1.2 server through
// Dialer.Dial (the context-free wrapper) and round-trips a payload, so the
// handshake is known to have completed before Dial returned.
func TestDialer_Dial_Success(t *testing.T) {
	t.Parallel()

	ln := startStdlibTLSServer(t)

	defer func() { _ = ln.Close() }()

	d := &gostls.Dialer{
		Config: &gostls.Config{
			RootCAs:    rootCAsForTest(t),
			ServerName: "test.example.com",
		},
	}

	conn, err := d.Dial("tcp", ln.Addr().String())
	testutil.NoErr(t, err, "Dialer.Dial")

	defer func() { _ = conn.Close() }()

	roundTrip(t, conn)
}

// TestDialer_Dial_ClosedPort verifies that Dialer.Dial reports a failed
// connect as an error rather than handing back an unusable connection.
func TestDialer_Dial_ClosedPort(t *testing.T) {
	t.Parallel()

	d := &gostls.Dialer{Config: &gostls.Config{InsecureSkipVerify: true}}

	_, err := d.Dial("tcp", closedPortAddr(t))
	testutil.WantErr(t, err, "Dialer.Dial against a closed port")
}

// TestDial_Success exercises the package-level Dial, the shorthand entry point
// ported crypto/tls code uses most.
func TestDial_Success(t *testing.T) {
	t.Parallel()

	ln := startStdlibTLSServer(t)

	defer func() { _ = ln.Close() }()

	cfg := &gostls.Config{
		RootCAs:    rootCAsForTest(t),
		ServerName: "test.example.com",
	}

	// The concrete *Conn is part of the signature: assigning it to a *Conn
	// variable is what keeps it that way.
	var conn *gostls.Conn

	conn, err := gostls.Dial("tcp", ln.Addr().String(), cfg)
	testutil.NoErr(t, err, "Dial")

	defer func() { _ = conn.Close() }()

	roundTrip(t, conn)
}

// TestDial_ClosedPort verifies that a failed Dial returns an error and no
// connection to close.
func TestDial_ClosedPort(t *testing.T) {
	t.Parallel()

	conn, err := gostls.Dial("tcp", closedPortAddr(t), &gostls.Config{InsecureSkipVerify: true})
	testutil.WantErr(t, err, "Dial against a closed port")

	if conn != nil {
		t.Fatalf("Dial returned a non-nil *Conn together with error %v", err)
	}
}

// TestDialWithDialer_UsesSuppliedDialer confirms that the supplied net.Dialer
// is the one that opens the socket: its Control hook fires exactly on the dial
// this test performs.
func TestDialWithDialer_UsesSuppliedDialer(t *testing.T) {
	t.Parallel()

	ln := startStdlibTLSServer(t)

	defer func() { _ = ln.Close() }()

	var controlled atomic.Bool

	nd := &net.Dialer{
		Control: func(_, _ string, _ syscall.RawConn) error {
			controlled.Store(true)

			return nil
		},
	}

	cfg := &gostls.Config{
		RootCAs:    rootCAsForTest(t),
		ServerName: "test.example.com",
	}

	conn, err := gostls.DialWithDialer(nd, "tcp", ln.Addr().String(), cfg)
	testutil.NoErr(t, err, "DialWithDialer")

	defer func() { _ = conn.Close() }()

	testutil.Ok(t, controlled.Load(), "supplied net.Dialer.Control was invoked")

	roundTrip(t, conn)
}

// TestDialWithDialer_TimeoutCoversHandshake verifies that the dialer's Timeout
// bounds the TLS handshake and not just the TCP connect: the peer here accepts
// the connection and then goes silent, so only a handshake-covering timeout
// ends the attempt.
func TestDialWithDialer_TimeoutCoversHandshake(t *testing.T) {
	t.Parallel()

	ln := startStallingTCPListener(t)

	defer func() { _ = ln.Close() }()

	nd := &net.Dialer{Timeout: 300 * time.Millisecond}

	start := time.Now()

	_, err := gostls.DialWithDialer(nd, "tcp", ln.Addr().String(), &gostls.Config{InsecureSkipVerify: true})
	elapsed := time.Since(start)

	testutil.WantErr(t, err, "DialWithDialer against a stalling peer")

	if elapsed > 2*time.Second {
		t.Fatalf("DialWithDialer blocked %v despite a 300ms dialer timeout (handshake unbounded)", elapsed)
	}
}

// TestClient_HandshakeOverExistingConn checks that Client turns an already
// established net.Conn into a working TLS client connection — the crypto/tls
// name for what NewConn does.
func TestClient_HandshakeOverExistingConn(t *testing.T) {
	t.Parallel()

	ln := startStdlibTLSServer(t)

	defer func() { _ = ln.Close() }()

	nd := &net.Dialer{}

	raw, err := nd.DialContext(context.Background(), "tcp", ln.Addr().String())
	testutil.NoErr(t, err, "raw dial")

	cfg := &gostls.Config{
		RootCAs:    rootCAsForTest(t),
		ServerName: "test.example.com",
	}

	conn := gostls.Client(raw, cfg)

	defer func() { _ = conn.Close() }()

	testutil.NoErr(t, conn.Handshake(), "Handshake on a Client connection")

	roundTrip(t, conn)
}

// closedPortAddr returns the address of a listener that has been closed, so a
// dial to it is refused.
func closedPortAddr(t *testing.T) string {
	t.Helper()

	lc := &net.ListenConfig{}

	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	testutil.NoErr(t, err, "listen")

	addr := ln.Addr().String()

	_ = ln.Close()

	return addr
}
