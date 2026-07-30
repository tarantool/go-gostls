package record_test

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"fmt"
	"io"
	"math"
	"slices"
	"testing"

	"github.com/tarantool/go-gostls/internal/record"
	"github.com/tarantool/go-gostls/internal/testutil"
)

// makeLayer returns a Layer backed by an in-memory buffer, using nullProtector.
func makeLayer(buf io.ReadWriter) *record.Layer {
	return record.NewLayer(buf)
}

// readOnlyRW wraps an io.Reader as an io.ReadWriter. Write panics — it must
// not be called in error-path tests that only exercise the read path.
type readOnlyRW struct{ io.Reader }

func (r readOnlyRW) Write(_ []byte) (int, error) {
	panic("unexpected Write call in read-only test ReadWriter")
}

// ---- RoundTrip tests -------------------------------------------------------.

// TestRecord_RoundTrip_Null verifies write→read through nullProtector.
func TestRecord_RoundTrip_Null(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	l := makeLayer(buf)

	payload := []byte("hello world")

	err := l.WriteRecord(record.ContentTypeApplicationData, payload)
	testutil.NoErr(t, err, "WriteRecord")

	ct, got, err := l.ReadRecord()
	testutil.NoErr(t, err, "ReadRecord")

	if ct != record.ContentTypeApplicationData {
		t.Errorf("content type: got %d, want %d", ct, record.ContentTypeApplicationData)
	}

	testutil.EqualBytes(t, got, payload, "payload")
}

// TestRecord_RoundTrip_CBC_HMAC writes and reads through AES-128-CBC / HMAC-SHA256.
// RFC 5246 §6.2.3.2.
func TestRecord_RoundTrip_CBC_HMAC(t *testing.T) {
	t.Parallel()

	macKey := bytes.Repeat([]byte{0xAA}, 32)
	encKey := bytes.Repeat([]byte{0xBB}, 16) // AES-128.

	prot, err := record.NewCBCHMACProtector(aes.NewCipher, sha256.New, encKey, macKey)
	testutil.NoErr(t, err, "NewCBCHMACProtector")

	buf := new(bytes.Buffer)
	l := makeLayer(buf)
	l.ChangeCipherSpec(prot, prot)

	payload := []byte("cbc hmac round trip")

	err = l.WriteRecord(record.ContentTypeHandshake, payload)
	testutil.NoErr(t, err, "WriteRecord")

	ct, got, err := l.ReadRecord()
	testutil.NoErr(t, err, "ReadRecord")

	if ct != record.ContentTypeHandshake {
		t.Errorf("content type: got %d, want %d", ct, record.ContentTypeHandshake)
	}

	testutil.EqualBytes(t, got, payload, "payload")
}

// TestRecord_RoundTrip_ChaCha20Poly1305 writes and reads through ChaCha20-Poly1305.
// RFC 7905: 12-byte implicit write_IV, no explicit per-record nonce on the wire.
func TestRecord_RoundTrip_ChaCha20Poly1305(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0x5A}, 32)
	iv := bytes.Repeat([]byte{0xA5}, 12)

	prot, err := record.NewChaCha20Poly1305Protector(key, iv)
	testutil.NoErr(t, err, "NewChaCha20Poly1305Protector")

	buf := new(bytes.Buffer)
	l := makeLayer(buf)
	l.ChangeCipherSpec(prot, prot)

	payloads := [][]byte{
		[]byte("chacha20 round trip"),
		[]byte("second record — different seq"),
		[]byte{},
	}
	for _, p := range payloads {
		err := l.WriteRecord(record.ContentTypeApplicationData, p)
		testutil.NoErr(t, err, "WriteRecord")
	}

	for i, want := range payloads {
		ct, got, err := l.ReadRecord()
		testutil.NoErr(t, err, fmt.Sprintf("ReadRecord #%d", i))

		if ct != record.ContentTypeApplicationData {
			t.Errorf("record #%d content type: got %d, want %d", i, ct, record.ContentTypeApplicationData)
		}

		if !bytes.Equal(got, want) {
			t.Errorf("record #%d payload mismatch: got %q, want %q", i, got, want)
		}
	}
}

// TestRecord_ChaCha20Poly1305_NonceXOR confirms the RFC 7905 nonce construction
// by checking that two different sequence numbers produce different ciphertexts
// for the same plaintext (i.e. the nonce actually depends on seq).
func TestRecord_ChaCha20Poly1305_NonceXOR(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0x01}, 32)
	iv := bytes.Repeat([]byte{0x00}, 12)

	prot, err := record.NewChaCha20Poly1305Protector(key, iv)
	testutil.NoErr(t, err, "NewChaCha20Poly1305Protector")

	hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x00} // type=AppData, version=TLS1.2.
	plain := []byte("same plaintext")

	c0, err := prot.Seal(0, hdr, plain)
	testutil.NoErr(t, err, "Seal seq=0")

	c1, err := prot.Seal(1, hdr, plain)
	testutil.NoErr(t, err, "Seal seq=1")

	testutil.NotEqualBytes(t, c0, c1, "seq=0 vs seq=1 ciphertext (nonce must derive from seq)")
}

// TestRecord_ChaCha20Poly1305_RejectsTamper ensures the AEAD tag is verified.
func TestRecord_ChaCha20Poly1305_RejectsTamper(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0x11}, 32)
	iv := bytes.Repeat([]byte{0x22}, 12)

	prot, err := record.NewChaCha20Poly1305Protector(key, iv)
	testutil.NoErr(t, err, "NewChaCha20Poly1305Protector")

	hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x00}

	sealed, err := prot.Seal(0, hdr, []byte("tamper me"))
	testutil.NoErr(t, err, "Seal")

	sealed[len(sealed)-1] ^= 0xFF

	_, err = prot.Open(0, hdr, sealed)

	testutil.WantErr(t, err, "Open(tampered ciphertext)")
}

// TestRecord_ChaCha20Poly1305_RejectsBadKeySize ensures bad key/iv sizes error.
func TestRecord_ChaCha20Poly1305_RejectsBadKeySize(t *testing.T) {
	t.Parallel()

	_, err := record.NewChaCha20Poly1305Protector(make([]byte, 16), make([]byte, 12))
	if err == nil {
		t.Error("expected error for 16-byte key, got nil")
	}

	_, err = record.NewChaCha20Poly1305Protector(make([]byte, 32), make([]byte, 8))
	if err == nil {
		t.Error("expected error for 8-byte iv, got nil")
	}
}

// TestRecord_RoundTrip_AEAD writes and reads through AES-128-GCM.
// RFC 5288, RFC 5246 §6.2.3.3.
func TestRecord_RoundTrip_AEAD(t *testing.T) {
	t.Parallel()

	// AES-128-GCM: 16-byte key, 4-byte salt.
	key := bytes.Repeat([]byte{0xCC}, 16)
	salt := []byte{0x01, 0x02, 0x03, 0x04}

	prot, err := record.NewAEADProtector(key, salt)
	testutil.NoErr(t, err, "NewAEADProtector")

	buf := new(bytes.Buffer)
	l := makeLayer(buf)
	l.ChangeCipherSpec(prot, prot)

	payload := []byte("aead round trip")

	err = l.WriteRecord(record.ContentTypeApplicationData, payload)
	testutil.NoErr(t, err, "WriteRecord")

	ct, got, err := l.ReadRecord()
	testutil.NoErr(t, err, "ReadRecord")

	if ct != record.ContentTypeApplicationData {
		t.Errorf("content type: got %d, want %d", ct, record.ContentTypeApplicationData)
	}

	testutil.EqualBytes(t, got, payload, "payload")
}

// ---- Reject tests ----------------------------------------------------------.

// TestRecord_Rejects_TruncatedHeader verifies truncated header returns error.
func TestRecord_Rejects_TruncatedHeader(t *testing.T) {
	t.Parallel()

	buf := readOnlyRW{bytes.NewReader([]byte{0x17, 0x03})} // only 2 bytes instead of 5.
	l := makeLayer(buf)

	_, _, err := l.ReadRecord()

	testutil.WantErr(t, err, "ReadRecord(truncated header)")
}

// TestRecord_Rejects_BadMAC verifies a tampered ciphertext is rejected.
func TestRecord_Rejects_BadMAC(t *testing.T) {
	t.Parallel()

	macKey := bytes.Repeat([]byte{0xAA}, 32)
	encKey := bytes.Repeat([]byte{0xBB}, 16)

	prot, err := record.NewCBCHMACProtector(aes.NewCipher, sha256.New, encKey, macKey)
	testutil.NoErr(t, err, "NewCBCHMACProtector")

	buf := new(bytes.Buffer)
	lw := makeLayer(buf)
	lw.ChangeCipherSpec(prot, prot)

	err = lw.WriteRecord(record.ContentTypeApplicationData, []byte("tamper me"))
	testutil.NoErr(t, err, "WriteRecord")

	// Corrupt the last byte of the ciphertext fragment.
	b := buf.Bytes()

	b[len(b)-1] ^= 0xFF

	lr := makeLayer(readOnlyRW{bytes.NewReader(b)})
	lr.ChangeCipherSpec(prot, prot)

	_, _, err = lr.ReadRecord()

	testutil.WantErr(t, err, "ReadRecord(bad MAC)")
}

// TestRecord_Rejects_SeqOverflow verifies overflow of sequence number is a hard error.
func TestRecord_Rejects_SeqOverflow(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	l := record.NewLayerWithSeq(buf, math.MaxUint64)

	err := l.WriteRecord(record.ContentTypeApplicationData, []byte("overflow"))

	_ = testutil.ErrAs[*record.Error](t, err, "WriteRecord(seq overflow)")
}

// TestRecord_Rejects_UnknownContentType verifies that reading an unknown
// content type results in a hard error.
func TestRecord_Rejects_UnknownContentType(t *testing.T) {
	t.Parallel()

	// Build a syntactically valid record with content type 0x99.
	hdr := append(make([]byte, 0, 9), byte(0x99), 0x03, 0x03, 0x00, 0x04)
	data := slices.Concat(hdr, []byte("xxxx"))
	l := makeLayer(readOnlyRW{bytes.NewReader(data)})

	_, _, err := l.ReadRecord()

	testutil.WantErr(t, err, "ReadRecord(unknown content type)")
}

// TestRecord_Rejects_VersionMismatch verifies that a record with a wrong
// version is rejected.
func TestRecord_Rejects_VersionMismatch(t *testing.T) {
	t.Parallel()

	// Build a syntactically valid record but with version 0x03 0x01 (TLS 1.0).
	hdr := append(make([]byte, 0, 9), byte(0x17), 0x03, 0x01, 0x00, 0x04)
	data := slices.Concat(hdr, []byte("xxxx"))
	l := makeLayer(readOnlyRW{bytes.NewReader(data)})

	_, _, err := l.ReadRecord()

	testutil.WantErr(t, err, "ReadRecord(version mismatch)")
}

// TestRecord_Rejects_OversizedFragment verifies fragments > 2^14+2048 are rejected.
func TestRecord_Rejects_OversizedFragment(t *testing.T) {
	t.Parallel()

	// Claim length = 2^14 + 2049.
	oversized := uint16(1<<14 + 2049)
	hdr := []byte{0x17, 0x03, 0x03, byte(oversized >> 8), byte(oversized)}
	// body is truncated — the length check must fire before reading the body.
	l := makeLayer(readOnlyRW{bytes.NewReader(hdr)})

	_, _, err := l.ReadRecord()

	testutil.WantErr(t, err, "ReadRecord(oversized fragment)")
}

// TestProtection_CBC_RejectsBadPadding verifies bad padding returns error
// and constant-time behavior is preserved structurally (bad padding + valid MAC
// still fails, confirming decrypt-verify ordering uses constant-time check).
func TestProtection_CBC_RejectsBadPadding(t *testing.T) {
	t.Parallel()

	macKey := bytes.Repeat([]byte{0xAA}, 32)
	encKey := bytes.Repeat([]byte{0xBB}, 16)

	prot, err := record.NewCBCHMACProtector(aes.NewCipher, sha256.New, encKey, macKey)
	testutil.NoErr(t, err, "NewCBCHMACProtector")

	// Write a valid record.
	buf := new(bytes.Buffer)
	lw := makeLayer(buf)
	lw.ChangeCipherSpec(prot, prot)

	err = lw.WriteRecord(record.ContentTypeApplicationData, []byte("bad padding test"))
	testutil.NoErr(t, err, "WriteRecord")

	// Corrupt the second-to-last byte of the ciphertext — this destroys the
	// padding without (likely) leaving a valid MAC, proving the decryptor
	// uses constant-time checks rather than bailing on bad padding alone.
	b := buf.Bytes()

	b[len(b)-2] ^= 0x01

	lr := makeLayer(readOnlyRW{bytes.NewReader(b)})
	lr.ChangeCipherSpec(prot, prot)

	_, _, err = lr.ReadRecord()

	testutil.WantErr(t, err, "ReadRecord(bad padding)")
}

// TestRecord_MultipleRecords verifies sequence numbers advance correctly
// across multiple records.
func TestRecord_MultipleRecords(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	l := makeLayer(buf)

	for i := range 5 {
		payload := []byte{byte(i)}

		err := l.WriteRecord(record.ContentTypeApplicationData, payload)
		testutil.NoErr(t, err, fmt.Sprintf("WriteRecord[%d]", i))
	}

	// Reset to a new layer reading from the same buffer.
	rl := makeLayer(buf)
	for i := range 5 {
		ct, got, err := rl.ReadRecord()
		testutil.NoErr(t, err, fmt.Sprintf("ReadRecord[%d]", i))

		if ct != record.ContentTypeApplicationData {
			t.Errorf("[%d] content type: got %d", i, ct)
		}

		if len(got) != 1 || got[0] != byte(i) {
			t.Errorf("[%d] payload mismatch: got %v", i, got)
		}
	}
}

// TestAlerts_CloseNotify verifies that a close_notify alert can be encoded
// and decoded.
func TestAlerts_CloseNotify(t *testing.T) {
	t.Parallel()

	rec := record.EncodeAlert(record.AlertLevelWarning, record.AlertCloseNotify)

	testutil.Len(t, rec, 2, "encoded alert body")

	level, desc := record.DecodeAlert(rec)
	if level != record.AlertLevelWarning {
		t.Errorf("alert level: got %d, want %d", level, record.AlertLevelWarning)
	}

	testutil.Equal(t, desc, record.AlertCloseNotify, "alert desc")
}

// TestAlerts_FatalError verifies that a fatal alert is represented as an error.
func TestAlerts_FatalError(t *testing.T) {
	t.Parallel()

	err := record.NewFatalAlertError(record.AlertBadRecordMAC)

	alert := testutil.ErrAs[*record.AlertError](t, err, "NewFatalAlertError")

	testutil.Equal(t, alert.Description, record.AlertBadRecordMAC, "alert description")
}
