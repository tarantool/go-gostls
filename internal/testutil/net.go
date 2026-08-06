package testutil

import (
	"context"
	"io"
	"net"
	"testing"
)

// StallingListener starts a loopback TCP listener whose connections accept and
// discard everything the client sends but never reply — a peer that completes
// the TCP connect and then hangs mid-handshake, which is how the timeout,
// cancellation and Close-interrupts-handshake tests reach their failure paths.
//
// It lives here for the same reason the wire builders do: the root package is
// tested from two sides — the white-box audit_regression_test.go in package
// gostls and the black-box dial_test.go in package gostls_test — and an
// unexported helper in one is invisible to the other, so each had grown its own
// byte-identical copy under a different name.
//
// The listener is closed via tb.Cleanup, so callers do not repeat that and
// cannot leave the accept loop running past the test.
func StallingListener(tb testing.TB) net.Listener {
	tb.Helper()

	lc := &net.ListenConfig{}

	listener, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	NoErr(tb, err, "listen")

	tb.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return // Listener closed.
			}

			go func(c net.Conn) {
				defer func() { _ = c.Close() }()

				_, _ = io.Copy(io.Discard, c)
			}(conn)
		}
	}()

	return listener
}
