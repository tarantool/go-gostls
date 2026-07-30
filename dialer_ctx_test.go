package gostls_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tarantool/go-gostls"
	"github.com/tarantool/go-gostls/internal/testutil"
)

// TestDialContext_HonorsContextDeadline verifies that DialContext returns near
// the context deadline when a peer accepts the TCP connection but stalls during
// the TLS handshake, instead of blocking indefinitely. The handshake is bounded
// by ctx (its deadline is applied to the connection and cancellation interrupts
// it).
func TestDialContext_HonorsContextDeadline(t *testing.T) {
	t.Parallel()

	lc := &net.ListenConfig{}

	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	testutil.NoErr(t, err, "listen")

	defer func() { _ = ln.Close() }()

	// Accept connections, consume the ClientHello, and never reply — a stalling
	// peer. io.Copy holds a reference to the conn and blocks until it is closed.
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}

			go func(c net.Conn) {
				defer func() { _ = c.Close() }()

				_, _ = io.Copy(io.Discard, c)
			}(conn)
		}
	}()

	d := &gostls.Dialer{Config: &gostls.Config{InsecureSkipVerify: true}}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, derr := d.DialContext(ctx, "tcp", ln.Addr().String())
	elapsed := time.Since(start)

	testutil.WantErr(t, derr, "DialContext against a stalling peer")

	if elapsed > 2*time.Second {
		t.Fatalf("DialContext blocked %v despite a 300ms ctx deadline (handshake ignored ctx)", elapsed)
	}
}
