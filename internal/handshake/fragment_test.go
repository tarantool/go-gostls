//nolint:testpackage // white-box: exercises unexported methods (sendClientCertificate, writeHandshakeMessage).
package handshake

// Tests for handshake fragmentation on the send path (RFC 5246 §6.2.1): a
// handshake message larger than a TLSPlaintext fragment must be split over
// several records. The client Certificate message is the one that reaches that
// size in practice, once it carries a full chain rather than a bare leaf.

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/tarantool/go-gostls/internal/record"
	"github.com/tarantool/go-gostls/internal/testutil"
)

// maxRecordPayload is the TLSPlaintext fragment cap of RFC 5246 §6.2.1, also
// enforced by record.Layer.WriteRecord.
const maxRecordPayload = 1 << 14

// syntheticChain builds a certificate chain of len(sizes) entries, each filled
// with a distinct byte so the reassembled message can be checked for order as
// well as content. The bytes are not valid DER, which is fine: the Certificate
// message treats every entry as an opaque blob.
func syntheticChain(sizes []int) [][]byte {
	chain := make([][]byte, 0, len(sizes))

	for i, size := range sizes {
		chain = append(chain, bytes.Repeat([]byte{byte(i + 1)}, size))
	}

	return chain
}

// evenSizes splits total bytes over count entries as evenly as it can, giving
// the remainder to the last one.
func evenSizes(count, total int) []int {
	sizes := make([]int, count)
	each := total / count

	for i := range sizes {
		sizes[i] = each
	}

	sizes[count-1] += total - each*count

	return sizes
}

// newChainSender returns a ClientState ready to emit chain as its client
// Certificate, plus the buffer capturing everything it writes.
func newChainSender(t *testing.T, chain [][]byte) (*ClientState, *bytes.Buffer) {
	t.Helper()

	layer, w := makeRecordLayerWithCapture()

	c := &ClientState{
		params: ClientParams{
			Certificates: []ClientCertificate{
				// The key is only type-switched on: selectClientSigAlg needs an
				// *rsa.PrivateKey to pick sha256+rsa, and sendClientCertificate
				// never signs. A zero key keeps these cases off the RSA keygen
				// path entirely.
				{RawChain: chain, PrivateKey: &rsa.PrivateKey{}},
			},
		},
		layer:      layer,
		transcript: NewTranscript(),
		certReq: &CertificateRequest{
			SupportedSignatureAlgs: []SigAndHash{
				{Hash: 0x04, Sig: 0x01}, // sha256+rsa.
			},
		},
	}

	return c, w
}

// splitCapturedRecords de-frames the captured wire bytes into record payloads,
// checking each record header on the way: handshake content type, TLS 1.2
// version, and a payload within the fragment cap.
func splitCapturedRecords(t *testing.T, wire []byte) [][]byte {
	t.Helper()

	const recHdrLen = 5

	var payloads [][]byte

	for len(wire) > 0 {
		testutil.MinLen(t, wire, recHdrLen, "record header")

		idx := len(payloads)

		testutil.Equal(t, wire[0], record.ContentTypeHandshake, fmt.Sprintf("record[%d] content type", idx))
		testutil.Equal(t, wire[1], byte(0x03), fmt.Sprintf("record[%d] version major", idx))
		testutil.Equal(t, wire[2], byte(0x03), fmt.Sprintf("record[%d] version minor", idx))

		payloadLen := int(wire[3])<<8 | int(wire[4])
		if payloadLen > maxRecordPayload {
			t.Fatalf("record[%d] payload = %d bytes, want at most %d", idx, payloadLen, maxRecordPayload)
		}

		testutil.MinLen(t, wire, recHdrLen+payloadLen, fmt.Sprintf("record[%d] body", idx))

		payloads = append(payloads, wire[recHdrLen:recHdrLen+payloadLen])
		wire = wire[recHdrLen+payloadLen:]
	}

	return payloads
}

// wantChainMessage checks that the concatenated record payloads are exactly one
// Certificate message carrying chain, with nothing left over.
func wantChainMessage(t *testing.T, payloads [][]byte, chain [][]byte) {
	t.Helper()

	msg, rest, err := ParseMessage(bytes.Join(payloads, nil))
	testutil.NoErr(t, err, "ParseMessage(reassembled records)")
	testutil.Len(t, rest, 0, "bytes after the Certificate message")

	certMsg, ok := msg.(*Certificate)
	testutil.Ok(t, ok, fmt.Sprintf("reassembled message is a Certificate (got %T)", msg))
	testutil.Len(t, certMsg.RawCerts, len(chain), "reassembled certificate_list")

	for i, want := range chain {
		testutil.EqualBytes(t, certMsg.RawCerts[i], want, fmt.Sprintf("reassembled cert[%d]", i))
	}
}

// TestSendClientCertificate_FragmentsOverRecords verifies that a chain larger
// than a single TLSPlaintext fragment goes out as several handshake records
// that reassemble into one Certificate message. Before fragmentation existed on
// the send path the record layer rejected the write outright, so a client
// holding a real chain could not authenticate at all.
func TestSendClientCertificate_FragmentsOverRecords(t *testing.T) {
	t.Parallel()

	chain := syntheticChain([]int{8000, 8000, 8000})

	c, w := newChainSender(t, chain)

	sent, err := c.sendClientCertificate()
	testutil.NoErr(t, err, "sendClientCertificate(24000-byte chain)")
	testutil.Ok(t, sent, "sendClientCertificate: non-empty chain")

	payloads := splitCapturedRecords(t, w.Bytes())
	if len(payloads) < 2 {
		t.Fatalf("chain of 24000 DER bytes went out in %d record(s), want more than one", len(payloads))
	}

	// Every record but the last must be filled before a new one is started,
	// otherwise the message is being split more than the transport requires.
	for i, p := range payloads[:len(payloads)-1] {
		testutil.Len(t, p, maxRecordPayload, fmt.Sprintf("record[%d] payload", i))
	}

	wantChainMessage(t, payloads, chain)
}

// TestSendClientCertificate_TranscriptGetsWholeMessage pins the invariant that
// fragmentation stops at the wire: the transcript hash must cover the whole
// envelope exactly once, no matter how many records carried it. Hashing the
// fragments separately would still produce the same bytes here, but hashing per
// record with any framing would silently break Finished verification.
func TestSendClientCertificate_TranscriptGetsWholeMessage(t *testing.T) {
	t.Parallel()

	chain := syntheticChain([]int{9000, 9000})

	c, w := newChainSender(t, chain)

	_, err := c.sendClientCertificate()
	testutil.NoErr(t, err, "sendClientCertificate(18000-byte chain)")

	got, err := c.transcript.Sum(sha256.New)
	testutil.NoErr(t, err, "transcript.Sum")

	want := NewTranscript()
	want.Write(bytes.Join(splitCapturedRecords(t, w.Bytes()), nil))

	wantSum, err := want.Sum(sha256.New)
	testutil.NoErr(t, err, "reference transcript.Sum")

	testutil.EqualBytes(t, got, wantSum, "transcript over the reassembled message")
}

// TestSendClientCertificate_OldRecordLimitBoundary walks the send path across
// the ceiling that used to reject the write. With chainLen entries the envelope
// is 4 + 3 + 3*chainLen bytes of framing, so the largest chain that ever fit a
// single record was maxRecordPayload minus that. One byte past it used to fail;
// both sides of the boundary must now succeed, the second one by fragmenting.
func TestSendClientCertificate_OldRecordLimitBoundary(t *testing.T) {
	t.Parallel()

	const chainLen = 5

	framing := hsEnvelopeSize + certListOverhead + chainLen*certEntryOverhead
	oldMaxDER := maxRecordPayload - framing

	tests := []struct {
		name        string
		totalDER    int
		wantRecords int
	}{
		{name: "at the old limit", totalDER: oldMaxDER, wantRecords: 1},
		{name: "one byte over", totalDER: oldMaxDER + 1, wantRecords: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			chain := syntheticChain(evenSizes(chainLen, tt.totalDER))

			c, w := newChainSender(t, chain)

			sent, err := c.sendClientCertificate()
			testutil.NoErr(t, err, fmt.Sprintf("sendClientCertificate(%d DER bytes)", tt.totalDER))
			testutil.Ok(t, sent, "sendClientCertificate: non-empty chain")

			payloads := splitCapturedRecords(t, w.Bytes())
			testutil.Len(t, payloads, tt.wantRecords, "records written")

			wantChainMessage(t, payloads, chain)
		})
	}
}
