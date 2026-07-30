//nolint:testpackage // white-box: uses unexported readHandshakeRecord and hsBuf
package handshake

import (
	"bytes"
	"testing"

	"github.com/tarantool/go-gostls/internal/record"
	"github.com/tarantool/go-gostls/internal/testutil"
)

// hsRecord wraps a handshake payload in a TLS 1.2 record header.
func hsRecord(payload []byte) []byte {
	return testutil.AppendU16Prefixed([]byte{
		record.ContentTypeHandshake,
		0x03, 0x03, // TLS 1.2.
	}, payload)
}

// TestReadHandshakeRecord_ReassemblesAcrossRecords verifies that a single
// handshake message split across two TLS records is reassembled (RFC 5246
// §6.2.1 fragmentation) — the case that previously failed with errHSBodyTruncated
// and broke large certificate chains.
func TestReadHandshakeRecord_ReassemblesAcrossRecords(t *testing.T) {
	t.Parallel()

	// Certificate (type 0x0B) with a 6-byte body.
	msg := []byte{0x0B, 0x00, 0x00, 0x06, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66}

	// Split the message across two records, mid-body.
	stream := append(hsRecord(msg[:7]), hsRecord(msg[7:])...)

	rw := &readWriteBuffer{r: bytes.NewBuffer(stream), w: new(bytes.Buffer)}
	c := &ClientState{layer: record.NewLayer(rw), transcript: NewTranscript()}

	typ, body, err := c.readHandshakeRecord()
	testutil.NoErr(t, err, "readHandshakeRecord")

	if typ != Type(0x0B) {
		t.Errorf("type: got %d, want 0x0B", typ)
	}

	if !bytes.Equal(body, msg[4:]) {
		t.Errorf("body: got %x, want %x", body, msg[4:])
	}
}

// TestReadHandshakeRecord_DeframesCoalesced verifies that two handshake messages
// packed into one TLS record are returned one at a time — the case that
// previously silently dropped everything after the first message.
func TestReadHandshakeRecord_DeframesCoalesced(t *testing.T) {
	t.Parallel()

	msg1 := []byte{0x0B, 0x00, 0x00, 0x02, 0xAA, 0xBB} // Certificate, 2-byte body.
	msg2 := []byte{0x0E, 0x00, 0x00, 0x00}             // ServerHelloDone, empty body.

	rec := hsRecord(append(append([]byte{}, msg1...), msg2...))

	rw := &readWriteBuffer{r: bytes.NewBuffer(rec), w: new(bytes.Buffer)}
	c := &ClientState{layer: record.NewLayer(rw), transcript: NewTranscript()}

	typ, body, err := c.readHandshakeRecord()
	testutil.NoErr(t, err, "msg1 readHandshakeRecord")
	testutil.Equal(t, typ, Type(0x0B), "msg1 type")
	testutil.EqualBytes(t, body, []byte{0xAA, 0xBB}, "msg1 body")

	typ, body, err = c.readHandshakeRecord()
	testutil.NoErr(t, err, "msg2 readHandshakeRecord")
	testutil.Equal(t, typ, Type(0x0E), "msg2 type")
	testutil.Len(t, body, 0, "msg2 body")
}
