package gostls_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"testing"

	"github.com/tarantool/go-gostls"
	"github.com/tarantool/go-gostls/internal/testutil"
)

// ============================================================================
// Suite registry tests (AllSuites, LookupSuiteByName)
// ============================================================================.

// TestAllSuites_NonEmpty verifies that AllSuites returns at least one suite
// and that each entry has a non-zero ID and a non-empty name.
func TestAllSuites_NonEmpty(t *testing.T) {
	t.Parallel()

	all := gostls.AllSuites()

	testutil.MinLen(t, all, 1, "AllSuites()")

	for _, s := range all {
		if s.ID == 0 {
			t.Errorf("suite %q has zero ID", s.Name)
		}

		if s.Name == "" {
			t.Errorf("suite with ID 0x%04x has empty Name", s.ID)
		}
	}

	t.Logf("AllSuites() returned %d suites", len(all))
}

// TestAllSuites_ContainsKnownSuite checks that a well-known suite is present.
func TestAllSuites_ContainsKnownSuite(t *testing.T) {
	t.Parallel()

	const wantName = "ECDHE-RSA-AES128-GCM-SHA256"

	const wantID = uint16(0xC02F)

	all := gostls.AllSuites()

	found := false

	for _, s := range all {
		if s.Name == wantName {
			if s.ID != wantID {
				t.Errorf("suite %q has ID 0x%04x, want 0x%04x", wantName, s.ID, wantID)
			}

			found = true

			break
		}
	}

	if !found {
		t.Errorf("AllSuites() does not contain %q", wantName)
	}
}

// TestLookupSuiteByName_Known verifies that a registered suite name resolves
// to the correct IANA ID.
func TestLookupSuiteByName_Known(t *testing.T) {
	t.Parallel()

	id, ok := gostls.LookupSuiteByName("ECDHE-RSA-AES128-GCM-SHA256")
	testutil.Ok(t, ok, `LookupSuiteByName("ECDHE-RSA-AES128-GCM-SHA256")`)

	testutil.Equal(t, id, uint16(0xC02F), "LookupSuiteByName(ECDHE-RSA-AES128-GCM-SHA256) ID")
}

// TestLookupSuiteByName_Unknown verifies that an unregistered name returns
// (0, false) — the not-found result.
func TestLookupSuiteByName_Unknown(t *testing.T) {
	t.Parallel()

	id, ok := gostls.LookupSuiteByName("NOT-A-REAL-SUITE")
	testutil.NotOk(t, ok, fmt.Sprintf("LookupSuiteByName(unknown) (id=0x%04x)", id))

	testutil.Equal(t, id, uint16(0), "LookupSuiteByName(unknown) ID")
}

// ============================================================================
// Dialer.DialContext tests
// ============================================================================.

// startStdlibTLSServer starts a crypto/tls TLS 1.2 server using the shared
// test fixtures (testCACert, testServerKey, testServerCertDER). The server
// echoes every ApplicationData record it receives. The caller must call
// l.Close() when done.
func startStdlibTLSServer(t *testing.T) net.Listener {
	t.Helper()
	initTestFixtures(t)

	tlsCert := tls.Certificate{
		Certificate: [][]byte{testServerCertDER},
		PrivateKey:  testServerKey,
	}
	// G402 reads MaxVersion as "too low", but pinning it is the point: the
	// client under test speaks TLS 1.2 only, so the crypto/tls server it dials
	// has to stay there for the handshake to happen at all.
	cfg := &tls.Config{ //nolint:gosec
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	}

	lc := &net.ListenConfig{}

	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	testutil.NoErr(t, err, "listen")

	tlsLn := tls.NewListener(ln, cfg)

	go func() {
		for {
			conn, acceptErr := tlsLn.Accept()
			if acceptErr != nil {
				return // listener closed.
			}

			go func(c net.Conn) {
				defer func() { _ = c.Close() }()

				buf := make([]byte, 4096)
				for {
					n, readErr := c.Read(buf)
					if readErr != nil {
						return
					}

					_, writeErr := c.Write(buf[:n])
					if writeErr != nil {
						return
					}
				}
			}(conn)
		}
	}()

	return tlsLn
}

// TestDialer_DialContext_Success dials a real stdlib TLS 1.2 server using
// Dialer.DialContext and performs a round-trip to confirm the connection works.
func TestDialer_DialContext_Success(t *testing.T) {
	t.Parallel()
	initTestFixtures(t)

	ln := startStdlibTLSServer(t)

	defer func() { _ = ln.Close() }()

	pool := rootCAsForTest(t)

	d := &gostls.Dialer{
		Config: &gostls.Config{
			RootCAs:    pool,
			ServerName: "test.example.com",
		},
	}

	conn, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
	testutil.NoErr(t, err, "DialContext")

	defer func() { _ = conn.Close() }()

	// Round-trip a small payload.
	want := []byte("ping")

	_, err = conn.Write(want)
	testutil.NoErr(t, err, "Write")

	got := make([]byte, len(want))

	_, err = conn.Read(got)
	testutil.NoErr(t, err, "Read")

	testutil.EqualBytes(t, got, want, "round-trip payload")
}

// TestDialer_DialContext_InsecureSkipVerify verifies that a Dialer with
// InsecureSkipVerify reaches the server and completes the handshake even
// without a configured RootCAs pool.
func TestDialer_DialContext_InsecureSkipVerify(t *testing.T) {
	t.Parallel()
	initTestFixtures(t)

	ln := startStdlibTLSServer(t)

	defer func() { _ = ln.Close() }()

	d := &gostls.Dialer{
		Config: &gostls.Config{
			InsecureSkipVerify: true,
		},
	}

	conn, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
	testutil.NoErr(t, err, "DialContext with InsecureSkipVerify")

	_ = conn.Close()
}

// TestDialer_DialContext_NilNetDialer exercises the branch where
// Dialer.NetDialer is nil, which causes dialBackend to create a default
// net.Dialer internally.
func TestDialer_DialContext_NilNetDialer(t *testing.T) {
	t.Parallel()
	initTestFixtures(t)

	ln := startStdlibTLSServer(t)

	defer func() { _ = ln.Close() }()

	pool := rootCAsForTest(t)

	d := &gostls.Dialer{
		NetDialer: nil, // exercises the nil-NetDialer branch in dialBackend.
		Config: &gostls.Config{
			RootCAs:    pool,
			ServerName: "test.example.com",
		},
	}

	conn, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
	testutil.NoErr(t, err, "DialContext with a nil NetDialer")

	_ = conn.Close()
}

// TestDialer_DialContext_ClosedPort verifies that DialContext returns an error
// (not a panic) when the target port is closed.
func TestDialer_DialContext_ClosedPort(t *testing.T) {
	t.Parallel()

	lc := &net.ListenConfig{}

	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	testutil.NoErr(t, err, "listen")

	addr := ln.Addr().String()

	_ = ln.Close() // port is now closed.

	d := &gostls.Dialer{
		Config: &gostls.Config{
			InsecureSkipVerify: true,
		},
	}

	_, dialErr := d.DialContext(context.Background(), "tcp", addr)
	testutil.WantErr(t, dialErr, "DialContext against a closed port")

	t.Logf("correctly received error for closed port: %v", dialErr)
}

// TestDialer_DialContext_ContextCancelled verifies that a cancelled context
// causes DialContext to return promptly with an error.
func TestDialer_DialContext_ContextCancelled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately.

	d := &gostls.Dialer{
		Config: &gostls.Config{
			InsecureSkipVerify: true,
		},
	}

	// 192.0.2.1 is TEST-NET-1 (RFC 5737) — always unreachable on a normal
	// network, so the dial attempt blocks until the context fires.
	_, dialErr := d.DialContext(ctx, "tcp", "192.0.2.1:443")
	testutil.WantErr(t, dialErr, "DialContext with a cancelled context")

	t.Logf("correctly received error for cancelled context: %v", dialErr)
}
