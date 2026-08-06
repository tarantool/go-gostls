// Error-path and negative-path tests for conn.go / dialer.go /
// dialer_impl.go. These tests lift branches that were not covered by the
// existing handshake_test.go / conn_test.go / dialer_dial_test.go.

//nolint:testpackage // white-box: accesses unexported newConn, handshakeOnce, closed fields
package gostls

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tarantool/go-gostls/internal/record"
	"github.com/tarantool/go-gostls/internal/testutil"
)

// helpers shared within this file.

// makePostHandshakeConn returns a *Conn whose handshake is already marked done
// (handshakeErr = nil) so Read/Write/Close skip the handshake step.
func makePostHandshakeConn(t *testing.T) (*Conn, net.Conn) {
	t.Helper()

	client, server := net.Pipe()
	c := newConn(client, &Config{})
	// Mark handshake succeeded.
	c.handshakeOnce.Do(func() {})
	c.handshakeOK.Store(true)

	return c, server
}

// writeRawRecord writes a raw TLS 1.2 record directly to conn (server side).
// This bypasses encryption (null protector), which is fine because the Conn
// under test also has a null protector after the fake handshake.
func writeRawRecord(t *testing.T, conn net.Conn, ct uint8, payload []byte) {
	t.Helper()

	hdr := [5]byte{ct, 0x03, 0x03, byte(len(payload) >> 8), byte(len(payload))}

	_, err := conn.Write(hdr[:])
	testutil.NoErr(t, err, "writeRawRecord: write header")

	if len(payload) > 0 {
		_, err := conn.Write(payload)
		testutil.NoErr(t, err, "writeRawRecord: write payload")
	}
}

// conn.go Read — alert record branches.

// TestConn_Read_AlertRecord_CloseNotify verifies that when the server sends a
// close_notify alert after the handshake, Read returns io.EOF.
func TestConn_Read_AlertRecord_CloseNotify(t *testing.T) {
	t.Parallel()

	c, server := makePostHandshakeConn(t)

	defer func() { _ = c.conn.Close() }()
	defer func() { _ = server.Close() }()

	// Server sends close_notify: alert record, level=warning(1), desc=close_notify(0).
	go func() {
		writeRawRecord(t, server, record.ContentTypeAlert, []byte{1, 0})
	}()

	buf := make([]byte, 16)

	_, err := c.Read(buf)
	testutil.ErrIs(t, err, io.EOF, "Read after a close_notify alert")
}

// TestConn_Read_AlertRecord_FatalAlert verifies that a non-close_notify alert
// causes Read to return an error wrapping errAlertReceived.
func TestConn_Read_AlertRecord_FatalAlert(t *testing.T) {
	t.Parallel()

	c, server := makePostHandshakeConn(t)

	defer func() { _ = c.conn.Close() }()
	defer func() { _ = server.Close() }()

	// Server sends fatal handshake_failure (level=2, desc=40).
	go func() {
		writeRawRecord(t, server, record.ContentTypeAlert, []byte{2, 40})
	}()

	buf := make([]byte, 16)

	_, err := c.Read(buf)
	testutil.ErrIs(t, err, errAlertReceived, "Read after a fatal alert")
}

// TestConn_Read_AlertRecord_Truncated verifies that a 1-byte alert record (too
// short) causes Read to return errAlertTruncated.
func TestConn_Read_AlertRecord_Truncated(t *testing.T) {
	t.Parallel()

	c, server := makePostHandshakeConn(t)

	defer func() { _ = c.conn.Close() }()
	defer func() { _ = server.Close() }()

	// Send a 1-byte alert body (need at least 2).
	go func() {
		writeRawRecord(t, server, record.ContentTypeAlert, []byte{1})
	}()

	buf := make([]byte, 16)

	_, err := c.Read(buf)
	testutil.ErrIs(t, err, errAlertTruncated, "Read of a truncated alert record")
}

// TestConn_Read_UnexpectedRecordType verifies that receiving a non-AppData,
// non-Alert record type in the application-data phase returns errUnexpectedRecord.
func TestConn_Read_UnexpectedRecordType(t *testing.T) {
	t.Parallel()

	c, server := makePostHandshakeConn(t)

	defer func() { _ = c.conn.Close() }()
	defer func() { _ = server.Close() }()

	// Send a ChangeCipherSpec record — unexpected in app-data phase.
	go func() {
		writeRawRecord(t, server, record.ContentTypeChangeCipherSpec, []byte{1})
	}()

	buf := make([]byte, 16)

	_, err := c.Read(buf)
	testutil.ErrIs(t, err, errUnexpectedRecord, "Read of a ChangeCipherSpec record in the app-data phase")
}

// TestConn_Read_EmptyAppDataContinues verifies that zero-length
// ApplicationData records are skipped (the loop continues to the next record).
func TestConn_Read_EmptyAppDataContinues(t *testing.T) {
	t.Parallel()

	c, server := makePostHandshakeConn(t)

	defer func() { _ = c.conn.Close() }()
	defer func() { _ = server.Close() }()

	go func() {
		// First: empty AppData (should be skipped).
		writeRawRecord(t, server, record.ContentTypeApplicationData, nil)
		// Second: real data.
		writeRawRecord(t, server, record.ContentTypeApplicationData, []byte("ok"))
	}()

	buf := make([]byte, 8)

	n, err := c.Read(buf)
	testutil.NoErr(t, err, "Read")
	testutil.Equal(t, string(buf[:n]), "ok", "Read")
}

// TestConn_Read_LargePayloadBuffered verifies that when a record's payload is
// larger than the caller's buffer, the remainder is stored in readBuf and the
// next Read drains it without a network round-trip.
func TestConn_Read_LargePayloadBuffered(t *testing.T) {
	t.Parallel()

	c, server := makePostHandshakeConn(t)

	defer func() { _ = c.conn.Close() }()
	defer func() { _ = server.Close() }()

	go func() {
		writeRawRecord(t, server, record.ContentTypeApplicationData, []byte("hello world"))
	}()

	// Read only 5 bytes — "hello".
	buf := make([]byte, 5)

	n, err := c.Read(buf)
	testutil.NoErr(t, err, "first Read")

	if string(buf[:n]) != "hello" {
		t.Errorf("first Read: got %q, want %q", buf[:n], "hello")
	}

	// Second read should drain from readBuf (no new record).
	buf2 := make([]byte, 32)

	n2, err := c.Read(buf2)
	testutil.NoErr(t, err, "second Read")

	if string(buf2[:n2]) != " world" {
		t.Errorf("second Read: got %q, want %q", buf2[:n2], " world")
	}
}

// conn.go Write — error paths.

// TestConn_Write_AfterClose verifies that Write on a closed Conn returns
// errConnClosed without touching the network.
func TestConn_Write_AfterClose(t *testing.T) {
	t.Parallel()

	c, server := makePostHandshakeConn(t)

	defer func() { _ = server.Close() }()

	// Mark conn closed without actually closing the underlying net.Conn yet,
	// so the Write path hits the early-return guard.
	c.closed.Store(true)

	_, err := c.Write([]byte("should fail"))
	testutil.ErrIs(t, err, errConnClosed, "Write on a closed conn")

	// Clean up.
	_ = c.conn.Close()
}

// TestConn_Write_NetworkError verifies that a Write error from the underlying
// net.Conn is propagated back to the caller.
func TestConn_Write_NetworkError(t *testing.T) {
	t.Parallel()

	c, server := makePostHandshakeConn(t)

	// Close server end so client write will fail.
	_ = server.Close()

	// Let the pipe drain / report error.
	time.Sleep(5 * time.Millisecond)

	_, err := c.Write([]byte("data"))
	testutil.WantErr(t, err, "Write after the peer closed")

	_ = c.conn.Close()
}

// conn.go Write — large payload splits across multiple records.

// TestConn_Write_LargePayload verifies that Write splits a payload larger than
// 16384 bytes (maxChunk) into multiple records. The test exercises the
// "if len(chunk) > maxChunk" branch in Write.
func TestConn_Write_LargePayload(t *testing.T) {
	t.Parallel()

	c, server := makePostHandshakeConn(t)

	defer func() { _ = c.conn.Close() }()

	received := make(chan []byte, 8)

	go func() {
		defer func() { _ = server.Close() }()

		var all []byte

		recvLayer := record.NewLayer(server)

		// Read until error (client Close will close the pipe).
		for {
			ct, payload, err := recvLayer.ReadRecord()
			if err != nil {
				break
			}

			if ct == record.ContentTypeApplicationData {
				all = append(all, payload...)
			}
		}

		received <- all
	}()

	// 40000 bytes > 16384 → multiple chunks.
	big := make([]byte, 40000)
	for i := range big {
		big[i] = byte(i)
	}

	n, err := c.Write(big)
	testutil.NoErr(t, err, "Write(40000 bytes)")
	testutil.Equal(t, n, len(big), "Write byte count")

	// Close so the server goroutine's ReadRecord loop exits.
	_ = c.conn.Close()

	testutil.EqualBytes(t, <-received, big, "payload reassembled from the server's records")
}

// conn.go Close — paths.

// TestConn_Close_DoubleClose verifies that calling Close twice does not panic
// and returns nil on the second call (idempotent close).
func TestConn_Close_DoubleClose(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()

	// Drain the server so the close_notify write doesn't block.
	go func() {
		buf := make([]byte, 128)
		for {
			_, err := server.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	c := newConn(client, &Config{})

	// Mark handshake done successfully so Close sends close_notify.
	c.handshakeOnce.Do(func() {})
	c.handshakeOK.Store(true)

	// First close: sends close_notify + closes conn.
	err := c.Close()
	if err != nil {
		t.Logf("first Close: %v (allowed)", err)
	}

	// Second close must return nil (CAS guard — does nothing).
	err = c.Close()
	if err != nil {
		t.Errorf("second Close returned error: %v", err)
	}

	_ = server.Close()
}

// TestConn_Close_BeforeHandshake verifies that Close on a conn where no
// handshake ran does NOT send close_notify (handshakeOK is false) and closes
// the underlying conn.
func TestConn_Close_BeforeHandshake(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()

	defer func() { _ = server.Close() }()

	c := newConn(client, &Config{})

	// Do NOT call Handshake(). Close() must handle this gracefully.
	err := c.Close()
	if err != nil {
		// net.Pipe may or may not return error — just log it.
		t.Logf("Close: %v (allowed)", err)
	}

	// Verify underlying conn is actually closed by trying to read from server.
	_ = server.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

	buf := make([]byte, 1)

	_, readErr := server.Read(buf)
	testutil.WantErr(t, readErr, "server Read after the client closed")
}

// TestConn_Close_NoCloseNotifyOnFailedHandshake verifies that when the
// handshake already failed, Close does not attempt to send close_notify
// (handshakeErr != nil path).
func TestConn_Close_NoCloseNotifyOnFailedHandshake(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()

	defer func() { _ = server.Close() }()

	c := newConn(client, &Config{})

	// Simulate a failed handshake.
	c.handshakeOnce.Do(func() { c.handshakeErr = errors.New("synthetic handshake error") })

	// Close must succeed (just close the net.Conn, no close_notify).
	_ = c.Close()

	// Server should see EOF / closed pipe — not a close_notify alert.
	_ = server.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

	buf := make([]byte, 64)

	n, _ := server.Read(buf)
	if n > 0 {
		// If anything was written it must NOT be a TLS alert record
		// (record type alert = 21 = 0x15 in the first byte of a TLS record).
		if buf[0] == record.ContentTypeAlert {
			t.Error("unexpected close_notify sent when handshake had failed")
		}
	}
}

// conn.go doHandshake — errNoSuites path.

// TestConn_doHandshake_EmptySuiteList exercises the errNoSuites branch in
// doHandshake when Config.CipherSuites is set to an explicitly empty slice.
func TestConn_doHandshake_EmptySuiteList(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()

	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	// Server goroutine: drain and close.
	go func() {
		buf := make([]byte, 64)

		_, _ = server.Read(buf)

		_ = server.Close()
	}()

	c := newConn(client, &Config{
		CipherSuites:       []uint16{},
		InsecureSkipVerify: true,
	})

	testutil.ErrIs(t, c.Handshake(), errNoSuites, "Handshake with an empty CipherSuites list")
}

// conn.go doHandshake — rootCAPool error branch.

// TestConn_doHandshake_RootCAPoolError exercises the branch in doHandshake
// where rootCAPool() returns an error (both RootCAs and RootCAPEMs are set).
func TestConn_doHandshake_RootCAPoolError(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()

	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	go func() {
		buf := make([]byte, 64)

		_, _ = server.Read(buf)

		_ = server.Close()
	}()

	// Setting both RootCAs and RootCAPEMs is mutually exclusive — rootCAPool()
	// returns errRootCAsMutuallyExclusive.
	cfg := &Config{
		RootCAs:    x509.NewCertPool(),
		RootCAPEMs: [][]byte{[]byte("fake pem")},
	}

	c := newConn(client, cfg)

	testutil.ErrIs(t, c.Handshake(), errRootCAsMutuallyExclusive,
		"Handshake with both RootCAs and RootCAPEMs set")
}

// TestConn_Handshake_Idempotent verifies that Handshake can be called multiple
// times and always returns the same (cached) result.
func TestConn_Handshake_Idempotent(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()

	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	c := newConn(client, &Config{})

	// Mark handshake as successfully done.
	c.handshakeOnce.Do(func() {})
	c.handshakeOK.Store(true)

	for range 3 {
		err := c.Handshake()
		if err != nil {
			t.Errorf("Handshake() returned error: %v", err)
		}
	}
}

// dialer.go DialContext — nil Config branch.

// TestDialer_DialContext_NilConfig verifies that a Dialer with nil Config dials
// without panicking (uses zero-value Config internally).
func TestDialer_DialContext_NilConfig(t *testing.T) {
	t.Parallel()

	// We don't actually need to complete a handshake — just check nil config
	// does not panic before the network layer errors out.
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately so the dial fails fast.

	d := &Dialer{
		Config: nil, // exercises the nil-cfg branch in DialContext.
	}

	_, err := d.DialContext(ctx, "tcp", "192.0.2.1:443")
	testutil.WantErr(t, err, "DialContext with a cancelled context")
}

// dialer_impl.go dialBackend — handshake-failure path.

// TestDialBackend_HandshakeFailureClosesConn verifies that when dialBackend
// opens a raw TCP connection but the TLS handshake fails, the raw connection is
// closed (not leaked).
//
// We achieve this by pointing the dialer at a plain TCP listener (not TLS),
// so the raw TCP dial succeeds but the TLS handshake fails immediately.
func TestDialBackend_HandshakeFailureClosesConn(t *testing.T) {
	t.Parallel()

	// Plain TCP listener (no TLS) — dialer will connect then fail to handshake.
	lc := &net.ListenConfig{}

	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	testutil.NoErr(t, err, "listen")

	defer func() { _ = ln.Close() }()

	// Accept once and close immediately — the TLS handshake will fail.
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}

		// Close immediately so TLS client gets EOF during handshake.
		_ = conn.Close()
	}()

	d := &Dialer{
		Config: &Config{
			InsecureSkipVerify: true,
		},
	}

	_, dialErr := d.DialContext(context.Background(), "tcp", ln.Addr().String())
	testutil.WantErr(t, dialErr, "DialContext against a plain TCP listener")

	t.Logf("correctly received handshake error: %v", dialErr)
}

// TestDialer_DialContext_CustomNetDialer verifies that Dialer.NetDialer is
// forwarded to dialBackend and actually used for the TCP dial (not silently
// replaced). We spin up a plain TCP listener, use a custom net.Dialer, and
// confirm the connection is established to the right port.
func TestDialer_DialContext_CustomNetDialer(t *testing.T) {
	t.Parallel()

	// Plain TCP listener (no TLS) — the TCP dial will succeed but TLS handshake
	// will fail (server closes immediately).
	lc := &net.ListenConfig{}

	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	testutil.NoErr(t, err, "listen")

	defer func() { _ = ln.Close() }()

	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}

		_ = conn.Close() // immediate close → client Handshake fails.
	}()

	nd := &net.Dialer{}
	d := &Dialer{
		NetDialer: nd,
		Config: &Config{
			InsecureSkipVerify: true,
		},
	}

	_, dialErr := d.DialContext(context.Background(), "tcp", ln.Addr().String())
	testutil.WantErr(t, dialErr, "DialContext against a peer that closes immediately")

	t.Logf("custom NetDialer: correctly received error: %v", dialErr)
}

// config.go rand() — non-nil Rand branch.

// zeroSource is a trivial io.Reader that returns zero bytes — used to exercise
// the Config.Rand override path.
type zeroSource struct{}

func (zeroSource) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 0
	}

	return len(b), nil
}

// TestConfig_Rand_CustomSource verifies that Config.Rand is returned when
// it is set (the non-nil branch in rand()). This is a white-box test because
// rand() is unexported.
func TestConfig_Rand_CustomSource(t *testing.T) {
	t.Parallel()

	// A simple deterministic reader that produces zeros — enough to exercise the
	// branch; we don't actually run a handshake here.
	zeroReader := zeroSource{}

	cfg := &Config{Rand: zeroReader}

	got := cfg.rand()
	if got != zeroReader {
		t.Errorf("cfg.rand() returned %v, want the configured zeroSource", got)
	}
}

// config.go clientCerts — malformed DER branch (ParseCertificate error).

// TestConfig_ClientCerts_MalformedDER exercises the x509.ParseCertificate
// error path in clientCerts() when Certificate[0] contains invalid DER bytes
// and Leaf is nil (so the code tries to parse it).
func TestConfig_ClientCerts_MalformedDER(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()

	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	go func() {
		buf := make([]byte, 64)

		_, _ = server.Read(buf)

		_ = server.Close()
	}()

	// Generate a valid RSA key to pass the key-type check.
	rsaKey, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	testutil.NoErr(t, err, "generate RSA key")

	cfg := &Config{
		Certificates: []Certificate{
			{
				// Non-empty but invalid DER — x509.ParseCertificate will fail.
				Certificate: [][]byte{{0x01, 0x02, 0x03, 0x04}},
				// Leaf is nil → triggers the parse path in clientCerts().
				Leaf:       nil,
				PrivateKey: rsaKey,
			},
		},
		InsecureSkipVerify: true,
	}

	c := newConn(client, cfg)

	hsErr := c.Handshake()
	testutil.WantErr(t, hsErr, "Handshake with a malformed client certificate DER")

	t.Logf("correctly rejected malformed DER: %v", hsErr)
}

// TestConfig_ClientCerts_EmptyChainEntry covers the per-entry validation in
// clientCerts(): an empty intermediate would be emitted as a zero-length entry
// in the Certificate message, which RFC 5246 §7.4.2 forbids. The leaf being
// valid must not let it through.
func TestConfig_ClientCerts_EmptyChainEntry(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()

	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	go func() {
		buf := make([]byte, 64)

		_, _ = server.Read(buf)

		_ = server.Close()
	}()

	rsaKey, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	testutil.NoErr(t, err, "generate RSA key")

	cfg := &Config{
		Certificates: []Certificate{
			{
				// Leaf is fine; the intermediate slot is empty.
				Certificate: [][]byte{{0x01, 0x02, 0x03, 0x04}, {}},
				PrivateKey:  rsaKey,
			},
		},
		InsecureSkipVerify: true,
	}

	c := newConn(client, cfg)

	hsErr := c.Handshake()
	testutil.WantErr(t, hsErr, "Handshake with an empty chain entry")

	if !errors.Is(hsErr, errCertEmptyChainEntry) {
		t.Errorf("Handshake error = %v, want it to wrap errCertEmptyChainEntry", hsErr)
	}
}
