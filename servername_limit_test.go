//nolint:testpackage // white-box: constructs a Conn via the unexported newConn.
package gostls

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/tarantool/go-gostls/internal/testutil"
)

// TestHandshake_ServerNameTooLong verifies the boundary check rejects a name
// that cannot fit the SNI extension's uint16 length prefix. Without it the
// length silently wrapped and the client put a malformed ClientHello on the
// wire.
func TestHandshake_ServerNameTooLong(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()

	defer func() { _ = server.Close() }()

	c := newConn(client, &Config{
		ServerName:         strings.Repeat("a", maxServerNameLen+1),
		InsecureSkipVerify: true,
	})

	testutil.ErrIs(t, c.Handshake(), errServerNameTooLong, "Handshake with an over-long ServerName")
}

// TestHandshake_ServerNameAtLimit verifies the check does not reject a name of
// exactly the maximum representable length: it must fail later (no peer on the
// pipe), not with errServerNameTooLong.
func TestHandshake_ServerNameAtLimit(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()

	// Drain whatever the client writes so the handshake fails on read, not on a
	// blocked write.
	go func() {
		buf := make([]byte, 4096)

		for {
			_, err := server.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	defer func() { _ = server.Close() }()

	c := newConn(client, &Config{
		ServerName:         strings.Repeat("a", maxServerNameLen),
		InsecureSkipVerify: true,
	})

	go func() {
		// Unblock the handshake once the ClientHello has been written.
		_ = server.Close()
	}()

	testutil.ErrNotIs(t, c.Handshake(), errServerNameTooLong,
		fmt.Sprintf("Handshake with a ServerName of exactly %d bytes", maxServerNameLen))
}
