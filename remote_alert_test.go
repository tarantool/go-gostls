package gostls_test

// A server that refuses the client's second flight answers it with an alert.
// These tests pin down that the handshake reports that alert, in crypto/tls's
// "remote error: tls: <alert>" shape.

import (
	"net"
	"testing"

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
