package gostls_test

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/tarantool/go-gostls"
	"github.com/tarantool/go-gostls/internal/suites"
	"github.com/tarantool/go-gostls/internal/testutil"
)

// handshakedPipeConn completes a real TLS 1.2 handshake over net.Pipe against
// the scripted test server and returns the post-handshake client *Conn. It lets
// the Conn transport behaviour (deadlines, close, concurrent Read/Write) be
// exercised through the public API instead of reaching into unexported fields.
//
// If drain is true the server keeps reading after the handshake, so the client
// can Write without blocking; otherwise the server sits idle, so a client Write
// blocks until its write deadline fires (the synchronous net.Pipe semantics the
// deadline tests rely on).
func handshakedPipeConn(t *testing.T, drain bool) (*gostls.Conn, func()) {
	t.Helper()
	initTestFixtures(t)

	suite, ok := suites.LookupByName("ECDHE-RSA-AES128-GCM-SHA256")
	testutil.Ok(t, ok, "test suite ECDHE-RSA-AES128-GCM-SHA256 registered")

	clientConn, serverConn := net.Pipe()

	var serverRandom [32]byte

	serverRandom[0] = 0xDE
	serverRandom[1] = 0xAD

	stop := make(chan struct{})
	srvDone := make(chan error, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				srvDone <- fmt.Errorf("server panic: %v", r)
			}
		}()

		srv := newScriptedServer(t, serverConn)
		runner := newServerRunner(t, srv, suite)
		runner.runFullHandshake(serverRandom)

		srvDone <- nil

		// Keep the peer open after the handshake so the client Conn stays
		// usable: drain to let Write succeed, or sit idle so Write blocks.
		if drain {
			buf := make([]byte, 4096)
			for {
				_, err := serverConn.Read(buf)
				if err != nil {
					return
				}
			}
		}

		<-stop
	}()

	conn := gostls.NewConn(clientConn, &gostls.Config{
		ServerName: "test.example.com",
		RootCAs:    rootCAsForTest(t),
	})

	testutil.NoErr(t, conn.Handshake(), "client handshake")
	testutil.NoErr(t, <-srvDone, "server handshake")

	cleanup := func() {
		close(stop)

		_ = clientConn.Close()
		_ = serverConn.Close()
	}

	return conn, cleanup
}

// TestNewConn_NilConfig verifies that NewConn accepts a nil config and returns
// a usable connection (the nil-config fallback to a zero-value Config). The
// fallback is observed through the public API: a method that delegates to the
// underlying transport works without panicking.
func TestNewConn_NilConfig(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()

	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	conn := gostls.NewConn(client, nil)
	if conn == nil {
		t.Fatal("NewConn(_, nil) returned nil")
	}

	testutil.Equal(t, conn.LocalAddr(), client.LocalAddr(), "NewConn(_, nil): LocalAddr()")
}

// TestConn_AddrDelegation verifies that LocalAddr and RemoteAddr on a *Conn
// delegate to the underlying net.Conn (no handshake required).
func TestConn_AddrDelegation(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()

	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	conn := gostls.NewConn(client, &gostls.Config{})

	if got, want := conn.LocalAddr(), client.LocalAddr(); got != want {
		t.Errorf("LocalAddr() = %v, want %v", got, want)
	}

	if got, want := conn.RemoteAddr(), client.RemoteAddr(); got != want {
		t.Errorf("RemoteAddr() = %v, want %v", got, want)
	}
}

// TestConn_SetDeadline verifies that SetDeadline is forwarded to the underlying
// net.Conn without error (it does not trigger the handshake).
func TestConn_SetDeadline(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()

	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	conn := gostls.NewConn(client, &gostls.Config{})

	testutil.NoErr(t, conn.SetDeadline(time.Now().Add(time.Hour)), "SetDeadline")
	testutil.NoErr(t, conn.SetDeadline(time.Time{}), "SetDeadline(zero)")
}

// TestConn_SetReadDeadline verifies the passthrough reaches the transport: a
// past read deadline makes the next Read return a timeout error.
func TestConn_SetReadDeadline(t *testing.T) {
	t.Parallel()

	conn, cleanup := handshakedPipeConn(t, false)
	defer cleanup()

	testutil.NoErr(t, conn.SetReadDeadline(time.Now().Add(-time.Second)), "SetReadDeadline")

	buf := make([]byte, 1)

	_, readErr := conn.Read(buf)

	netErr := testutil.ErrAs[net.Error](t, readErr, "Read after a past read deadline")
	testutil.Equal(t, netErr.Timeout(), true, "Read error Timeout()")
}

// TestConn_SetWriteDeadline verifies the passthrough reaches the transport: a
// past write deadline makes the next Write return a timeout error (the idle
// server never reads, so the synchronous net.Pipe Write blocks until the
// deadline fires).
func TestConn_SetWriteDeadline(t *testing.T) {
	t.Parallel()

	conn, cleanup := handshakedPipeConn(t, false)
	defer cleanup()

	testutil.NoErr(t, conn.SetWriteDeadline(time.Now().Add(-time.Second)), "SetWriteDeadline")

	_, writeErr := conn.Write([]byte("hello"))

	netErr := testutil.ErrAs[net.Error](t, writeErr, "Write after a past write deadline")
	testutil.Equal(t, netErr.Timeout(), true, "Write error Timeout()")
}

// TestConn_Read_ClosedConn exercises the early-return path in Read when the
// connection has been closed via the public Close method. The server drains so
// Close's close_notify write completes.
func TestConn_Read_ClosedConn(t *testing.T) {
	t.Parallel()

	conn, cleanup := handshakedPipeConn(t, true)
	defer cleanup()

	testutil.NoErr(t, conn.Close(), "Close")

	buf := make([]byte, 1)

	_, readErr := conn.Read(buf)
	testutil.WantErr(t, readErr, "Read from a closed conn")
}
