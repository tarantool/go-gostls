package gostls_test

import (
	"net"
	"testing"

	"github.com/tarantool/go-gostls"
	"github.com/tarantool/go-gostls/internal/testutil"
)

// TestConnectionState_AfterHandshake dials a real stdlib TLS 1.2 server and
// checks that the state reports what was actually negotiated. Asking which
// suite was negotiated is the reason the type exists, so an ID that is merely
// non-zero is not enough — it has to be one this module offered.
func TestConnectionState_AfterHandshake(t *testing.T) {
	t.Parallel()

	ln := startStdlibTLSServer(t)

	defer func() { _ = ln.Close() }()

	conn, err := gostls.Dial("tcp", ln.Addr().String(), &gostls.Config{
		RootCAs:    rootCAsForTest(t),
		ServerName: "test.example.com",
	})
	testutil.NoErr(t, err, "Dial")

	defer func() { _ = conn.Close() }()

	state := conn.ConnectionState()

	if !state.HandshakeComplete {
		t.Error("HandshakeComplete = false after a successful Dial")
	}

	if state.Version != gostls.VersionTLS12 {
		t.Errorf("Version = 0x%04x, want 0x%04x", state.Version, gostls.VersionTLS12)
	}

	if state.ServerName != "test.example.com" {
		t.Errorf("ServerName = %q, want %q", state.ServerName, "test.example.com")
	}

	registered := false

	for _, s := range gostls.AllSuites() {
		if s.ID == state.CipherSuite {
			registered = true

			t.Logf("negotiated %s (0x%04x)", s.Name, s.ID)

			break
		}
	}

	if !registered {
		t.Errorf("CipherSuite = 0x%04x, which is not a registered suite", state.CipherSuite)
	}

	if len(state.PeerCertificates) == 0 {
		t.Fatal("PeerCertificates is empty")
	}

	if state.PeerCertificates[0].Subject.CommonName != "test.example.com" {
		t.Errorf(
			"leaf CommonName = %q, want %q",
			state.PeerCertificates[0].Subject.CommonName, "test.example.com",
		)
	}

	// The same chain has to be reachable in the GOST view, since that is the
	// only one that can carry a GOST key — even when, as here, the peer used
	// an RSA certificate.
	if len(state.GOSTPeerCertificates) != len(state.PeerCertificates) {
		t.Errorf(
			"GOSTPeerCertificates has %d entries, PeerCertificates has %d; want the same chain",
			len(state.GOSTPeerCertificates), len(state.PeerCertificates),
		)
	}
}

// TestConnectionState_BeforeHandshake checks that the state is readable on a
// connection whose handshake has not run, and that it does not claim a
// completed handshake or trigger one. crypto/tls behaves the same way.
func TestConnectionState_BeforeHandshake(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()

	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	conn := gostls.NewConn(client, &gostls.Config{InsecureSkipVerify: true})

	state := conn.ConnectionState()

	if state.HandshakeComplete {
		t.Error("HandshakeComplete = true before any handshake")
	}

	if state.Version != 0 || state.CipherSuite != 0 {
		t.Errorf(
			"Version = 0x%04x, CipherSuite = 0x%04x before any handshake, want both zero",
			state.Version, state.CipherSuite,
		)
	}

	if state.PeerCertificates != nil {
		t.Errorf("PeerCertificates = %v before any handshake, want nil", state.PeerCertificates)
	}
}

// TestConnectionState_AfterFailedHandshake checks that a handshake that failed
// leaves the state empty rather than half-filled. A caller that logs the state
// on error must not read a suite that was never agreed on.
func TestConnectionState_AfterFailedHandshake(t *testing.T) {
	t.Parallel()

	ln := startStdlibTLSServer(t)

	defer func() { _ = ln.Close() }()

	// NewConn rather than Dial: a failed Dial hands back no *Conn, and the
	// state after the failure is exactly what this test is about.
	raw, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", ln.Addr().String())
	testutil.NoErr(t, err, "net.Dialer.DialContext")

	defer func() { _ = raw.Close() }()

	// Wrong ServerName against a certificate for test.example.com: the
	// handshake gets far enough to pick a suite, then fails verification.
	conn := gostls.NewConn(raw, &gostls.Config{
		RootCAs:    rootCAsForTest(t),
		ServerName: "wrong.example.com",
	})

	testutil.WantErr(t, conn.Handshake(), "Handshake with a mismatched ServerName")

	state := conn.ConnectionState()

	if state.HandshakeComplete {
		t.Error("HandshakeComplete = true after a failed handshake")
	}

	if state.CipherSuite != 0 {
		t.Errorf("CipherSuite = 0x%04x after a failed handshake, want 0", state.CipherSuite)
	}

	if state.PeerCertificates != nil {
		t.Errorf("PeerCertificates = %v after a failed handshake, want nil", state.PeerCertificates)
	}
}

// TestConnectionState_ServerNameFromDialAddress checks that the state reports
// the effective name, not just Config.ServerName. When the config leaves it
// empty the dial address supplies it, and that is the name the certificate was
// verified against, so that is what the caller has to be able to read back.
func TestConnectionState_ServerNameFromDialAddress(t *testing.T) {
	t.Parallel()

	ln := startStdlibTLSServer(t)

	defer func() { _ = ln.Close() }()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	testutil.NoErr(t, err, "SplitHostPort")

	// InsecureSkipVerify, because the fixture certificate is for
	// test.example.com and the listener is reachable only as 127.0.0.1.
	conn, err := gostls.Dial("tcp", net.JoinHostPort("127.0.0.1", port), &gostls.Config{
		InsecureSkipVerify: true,
	})
	testutil.NoErr(t, err, "Dial")

	defer func() { _ = conn.Close() }()

	state := conn.ConnectionState()

	if state.ServerName != "127.0.0.1" {
		t.Errorf("ServerName = %q, want the host from the dial address (%q)", state.ServerName, "127.0.0.1")
	}
}
