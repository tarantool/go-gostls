package gostls_test

// A server that refuses the client's second flight answers it with an alert.
// These tests pin down that the handshake reports that alert, in crypto/tls's
// "remote error: tls: <alert>" shape, and that the flight reaches the server
// whole so the alert is there to be read.

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tarantool/go-gostls"
	"github.com/tarantool/go-gostls/internal/record"
	"github.com/tarantool/go-gostls/internal/suites"
	"github.com/tarantool/go-gostls/internal/testutil"
)

// TestHandshake_ServerAlertInPlaceOfCCS scripts a server that reads the whole
// client flight and answers with a fatal handshake_failure alert where its
// ChangeCipherSpec belongs — what a server does when it rejects the flight.
// The handshake must name the alert rather than complain about the record type
// it arrived in.
func TestHandshake_ServerAlertInPlaceOfCCS(t *testing.T) {
	t.Parallel()
	initTestFixtures(t)

	suite, ok := suites.LookupByName("AES128-GCM-SHA256")
	testutil.Ok(t, ok, `LookupByName("AES128-GCM-SHA256")`)

	clientConn, serverConn := net.Pipe()

	defer func() { _ = clientConn.Close() }()

	serverDone := make(chan struct{})

	go func() {
		defer close(serverDone)
		defer func() { _ = serverConn.Close() }()

		srv := newScriptedServer(t, serverConn)
		runner := newServerRunner(t, srv, suite)

		_ = srv.readClientHello()

		var serverRandom [32]byte

		sh := buildServerHello(serverRandom, suite.ID)
		srv.writeHandshake(sh)
		srv.writeHandshake(buildCertificate([][]byte{testServerCertDER}))

		_ = runner.doRSAKx() // ServerHelloDone, then the ClientKeyExchange.

		srv.readCCS()

		// The client Finished is sealed; the record header is all we need.
		_, _, err := srv.layer.ReadRecord()
		if err != nil {
			t.Errorf("scripted server: read client Finished: %v", err)

			return
		}

		err = srv.layer.WriteRecord(record.ContentTypeAlert,
			record.EncodeAlert(record.AlertLevelFatal, record.AlertHandshakeFailure))
		if err != nil {
			t.Errorf("scripted server: write alert: %v", err)
		}
	}()

	tlsConn := gostls.NewConn(withDeadline(clientConn), &gostls.Config{
		ServerName: "test.example.com",
		RootCAs:    rootCAsForTest(t),
	})

	err := tlsConn.Handshake()
	testutil.WantErr(t, err, "handshake answered with an alert")
	testutil.Equal(t, err.Error(), "remote error: tls: handshake failure", "handshake error")

	opErr := testutil.ErrAs[*net.OpError](t, err, "handshake error")
	testutil.Equal(t, opErr.Op, "remote error", "net.OpError.Op")

	<-serverDone
}

// TestHandshake_ClientSecondFlightIsOneWrite checks that ClientKeyExchange,
// ChangeCipherSpec and Finished leave the client in a single Write. Sent record
// by record, a server that acts on the first message and closes makes the
// client fail on its own write — see TestDial_ServerRequiresClientCert.
func TestHandshake_ClientSecondFlightIsOneWrite(t *testing.T) {
	t.Parallel()
	initTestFixtures(t)

	suite, ok := suites.LookupByName("AES128-GCM-SHA256")
	testutil.Ok(t, ok, `LookupByName("AES128-GCM-SHA256")`)

	clientConn, serverConn := net.Pipe()

	defer func() { _ = clientConn.Close() }()

	serverDone := make(chan struct{})

	go func() {
		defer close(serverDone)
		defer func() { _ = serverConn.Close() }()

		var serverRandom [32]byte

		runner := newServerRunner(t, newScriptedServer(t, serverConn), suite)
		runner.runFullHandshake(serverRandom)
	}()

	recorder := &writeRecorder{Conn: withDeadline(clientConn)}

	tlsConn := gostls.NewConn(recorder, &gostls.Config{
		ServerName: "test.example.com",
		RootCAs:    rootCAsForTest(t),
	})

	err := tlsConn.Handshake()
	testutil.NoErr(t, err, "Handshake")

	<-serverDone

	writes := recorder.snapshot()
	testutil.MinLen(t, writes, 1, "client writes")

	got := recordTypes(t, writes[len(writes)-1])
	want := []uint8{
		record.ContentTypeHandshake,        // ClientKeyExchange.
		record.ContentTypeChangeCipherSpec, // ChangeCipherSpec.
		record.ContentTypeHandshake,        // Finished.
	}

	testutil.Len(t, got, len(want), "records in the client's last handshake write")

	for i := range want {
		testutil.Equal(t, got[i], want[i], "content type of record in the last write")
	}
}

// TestDial_ServerRequiresClientCert dials a crypto/tls server that requires a
// client certificate without offering one. The server rejects the empty
// Certificate message with an alert and closes the connection as soon as it
// has read it, which is the mutual-TLS misconfiguration a client most often
// hits. The client must report the alert every time — not a broken pipe from
// writing the rest of its flight into the closed connection, and not the
// record type the alert arrived in. The dial repeats because the failure this
// guards against was a race.
//
// Which alert crypto/tls sends here has changed between Go releases, so the
// test holds the error to its shape rather than to one description.
func TestDial_ServerRequiresClientCert(t *testing.T) {
	t.Parallel()
	initTestFixtures(t)

	// G402 reads MaxVersion as "too low"; the client under test speaks TLS 1.2
	// only, so the server has to stay there.
	cfg := &tls.Config{ //nolint:gosec
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{testServerCertDER},
			PrivateKey:  testServerKey,
		}},
		ClientAuth: tls.RequireAnyClientCert,
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
	}

	lc := &net.ListenConfig{}

	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	testutil.NoErr(t, err, "listen")

	tlsLn := tls.NewListener(ln, cfg)

	defer func() { _ = tlsLn.Close() }()

	go func() {
		for {
			conn, acceptErr := tlsLn.Accept()
			if acceptErr != nil {
				return
			}

			go func(c net.Conn) {
				// Reading drives the server's side of the handshake, which
				// fails there too; Close right after is what a real server
				// does.
				_, _ = c.Read(make([]byte, 1))
				_ = c.Close()
			}(conn)
		}
	}()

	const dials = 20

	for range dials {
		d := &gostls.Dialer{Config: &gostls.Config{
			ServerName: "test.example.com",
			RootCAs:    rootCAsForTest(t),
		}}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, dialErr := d.DialContext(ctx, "tcp", tlsLn.Addr().String())

		cancel()

		if dialErr == nil {
			_ = conn.Close()

			t.Fatal("DialContext succeeded against a server that requires a client certificate")
		}

		opErr := testutil.ErrAs[*net.OpError](t, dialErr, "DialContext error")
		testutil.Equal(t, opErr.Op, "remote error", "net.OpError.Op")

		alert := testutil.ErrAs[*record.RemoteAlertError](t, dialErr, "DialContext error")
		testutil.Equal(t, alert.Level, record.AlertLevelFatal, "alert level")
		testutil.Equal(t, dialErr.Error(), "remote error: tls: "+record.AlertText(alert.Description),
			"DialContext error")
	}
}

// writeRecorder is a net.Conn that keeps a copy of every Write.
type writeRecorder struct {
	net.Conn

	mu     sync.Mutex
	writes [][]byte
}

func (w *writeRecorder) Write(b []byte) (int, error) {
	w.mu.Lock()

	w.writes = append(w.writes, append([]byte(nil), b...))

	w.mu.Unlock()

	return w.Conn.Write(b)
}

func (w *writeRecorder) snapshot() [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()

	return append([][]byte(nil), w.writes...)
}

// recordTypes splits b into TLS records and returns their content types,
// failing the test unless b is a whole number of records.
func recordTypes(t *testing.T, b []byte) []uint8 {
	t.Helper()

	const headerLen = 5

	var types []uint8

	for len(b) > 0 {
		if len(b) < headerLen {
			t.Fatalf("write ends in a partial record header (%d bytes)", len(b))
		}

		n := headerLen + int(binary.BigEndian.Uint16(b[3:5]))
		if len(b) < n {
			t.Fatalf("write ends in a partial record (%d of %d bytes)", len(b), n)
		}

		types = append(types, b[0])
		b = b[n:]
	}

	return types
}
