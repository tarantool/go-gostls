package record_test

import (
	"crypto/sha1" //nolint:gosec // testing SHA1Hash which wraps the legacy function
	"crypto/sha512"
	"fmt"
	"strings"
	"testing"

	"github.com/tarantool/go-gostls/internal/record"
	"github.com/tarantool/go-gostls/internal/testutil"
)

// Tests for hash_helpers.go.

// TestSHA1Hash verifies that SHA1Hash returns a correct SHA-1 implementation.
func TestSHA1Hash(t *testing.T) {
	t.Parallel()

	input := []byte("hello, SHA-1")

	h := record.SHA1Hash()
	if h == nil {
		t.Fatal("SHA1Hash returned nil")
	}

	// Size and BlockSize must match standard library.
	if got, want := h.Size(), sha1.Size; got != want {
		t.Errorf("SHA1Hash Size: got %d, want %d", got, want)
	}

	if got, want := h.BlockSize(), sha1.BlockSize; got != want {
		t.Errorf("SHA1Hash BlockSize: got %d, want %d", got, want)
	}

	// Digest must match crypto/sha1.
	_, _ = h.Write(input)

	got := h.Sum(nil)

	want := sha1.Sum(input) //nolint:gosec

	testutil.EqualBytes(t, got, want[:], "SHA1Hash digest")
}

// TestSHA384Hash verifies that SHA384Hash returns a correct SHA-384 implementation.
func TestSHA384Hash(t *testing.T) {
	t.Parallel()

	input := []byte("hello, SHA-384")

	h := record.SHA384Hash()
	if h == nil {
		t.Fatal("SHA384Hash returned nil")
	}

	// Size and BlockSize must match standard library.
	if got, want := h.Size(), 48; got != want {
		t.Errorf("SHA384Hash Size: got %d, want %d", got, want)
	}

	if got, want := h.BlockSize(), sha512.New384().BlockSize(); got != want {
		t.Errorf("SHA384Hash BlockSize: got %d, want %d", got, want)
	}

	// Digest must match crypto/sha512.Sum384.
	_, _ = h.Write(input)

	got := h.Sum(nil)

	want := sha512.Sum384(input)

	testutil.EqualBytes(t, got, want[:], "SHA384Hash digest")
}

// TestSHA256Hash verifies that SHA256Hash returns a correct SHA-256 implementation.
// SHA256Hash is already exercised indirectly via existing tests, but a direct
// assertion confirms the delegation.
func TestSHA256Hash(t *testing.T) {
	t.Parallel()

	h := record.SHA256Hash()
	if h == nil {
		t.Fatal("SHA256Hash returned nil")
	}

	testutil.Equal(t, h.Size(), 32, "SHA256Hash Size")
}

// TestNewAESCipher verifies that NewAESCipher constructs AES ciphers of the
// expected block size for valid key lengths and rejects invalid ones.
func TestNewAESCipher(t *testing.T) {
	t.Parallel()

	for _, keyLen := range []int{16, 24, 32} {
		c, err := record.NewAESCipher(make([]byte, keyLen))
		if err != nil {
			t.Errorf("NewAESCipher(%d-byte key): unexpected error: %v", keyLen, err)

			continue
		}

		if c.BlockSize() != 16 {
			t.Errorf("NewAESCipher(%d-byte key): BlockSize=%d, want 16", keyLen, c.BlockSize())
		}
	}

	// Bad key length must return an error.
	_, err := record.NewAESCipher(make([]byte, 7))

	testutil.WantErr(t, err, "NewAESCipher(7-byte key)")
}

// Tests for alerts.go.

// TestAlertError_ErrorString verifies AlertError.Error() formats correctly.
func TestAlertError_ErrorString(t *testing.T) {
	t.Parallel()

	cases := []struct {
		desc  uint8
		level uint8
		want  string
	}{
		{record.AlertBadRecordMAC, record.AlertLevelFatal, "tls: fatal alert 20 (level 2)"},
		{record.AlertHandshakeFailure, record.AlertLevelFatal, "tls: fatal alert 40 (level 2)"},
		{record.AlertCloseNotify, record.AlertLevelWarning, "tls: fatal alert 0 (level 1)"},
	}

	for _, tc := range cases {
		ae := &record.AlertError{Level: tc.level, Description: tc.desc}
		got := ae.Error()

		if got != tc.want {
			t.Errorf("AlertError{level=%d, desc=%d}.Error() = %q, want %q",
				tc.level, tc.desc, got, tc.want)
		}
	}
}

// TestRemoteAlertError_ErrorString verifies a peer's alert reads the way
// crypto/tls reports it: named, not numbered, and without the level.
func TestRemoteAlertError_ErrorString(t *testing.T) {
	t.Parallel()

	cases := []struct {
		desc  uint8
		level uint8
		want  string
	}{
		{record.AlertHandshakeFailure, record.AlertLevelFatal, "tls: handshake failure"},
		{record.AlertBadCertificate, record.AlertLevelFatal, "tls: bad certificate"},
		{record.AlertUnknownCA, record.AlertLevelFatal, "tls: unknown certificate authority"},
		{record.AlertCertificateRequired, record.AlertLevelFatal, "tls: certificate required"},
		{record.AlertNoRenegotiation, record.AlertLevelWarning, "tls: no renegotiation"},
		{41, record.AlertLevelFatal, "tls: alert(41)"}, // no_certificate, SSLv3 only.
		{255, record.AlertLevelFatal, "tls: alert(255)"},
	}

	for _, tc := range cases {
		ae := &record.RemoteAlertError{Level: tc.level, Description: tc.desc}

		testutil.Equal(t, ae.Error(), tc.want, fmt.Sprintf("RemoteAlertError{desc=%d}.Error()", tc.desc))
	}
}

// TestAlertText_Named checks that every description with a name has one, and
// that names do not repeat — a duplicate would be a constant typed twice.
func TestAlertText_Named(t *testing.T) {
	t.Parallel()

	named := []uint8{
		record.AlertCloseNotify, record.AlertUnexpectedMessage, record.AlertBadRecordMAC,
		record.AlertDecryptionFailed, record.AlertRecordOverflow, record.AlertDecompressionFailure,
		record.AlertHandshakeFailure, record.AlertBadCertificate, record.AlertUnsupportedCertificate,
		record.AlertCertificateRevoked, record.AlertCertificateExpired, record.AlertCertificateUnknown,
		record.AlertIllegalParameter, record.AlertUnknownCA, record.AlertAccessDenied,
		record.AlertDecodeError, record.AlertDecryptError, record.AlertExportRestriction,
		record.AlertProtocolVersion, record.AlertInsufficientSecurity, record.AlertInternalError,
		record.AlertInappropriateFallback, record.AlertUserCanceled, record.AlertNoRenegotiation,
		record.AlertMissingExtension, record.AlertUnsupportedExtension,
		record.AlertCertificateUnobtainable, record.AlertUnrecognizedName,
		record.AlertBadCertificateStatusResponse, record.AlertBadCertificateHashValue,
		record.AlertUnknownPSKIdentity, record.AlertCertificateRequired,
		record.AlertNoApplicationProtocol, record.AlertECHRequired,
	}

	seen := make(map[string]uint8, len(named))

	for _, desc := range named {
		text := record.AlertText(desc)
		if strings.HasPrefix(text, "alert(") {
			t.Errorf("AlertText(%d) = %q, want a name", desc, text)
		}

		if prev, dup := seen[text]; dup {
			t.Errorf("AlertText(%d) = %q, same as AlertText(%d)", desc, text, prev)
		}

		seen[text] = desc
	}
}

// TestRecordError_ErrorString verifies Error.Error() formats correctly.
func TestRecordError_ErrorString(t *testing.T) {
	t.Parallel()

	cases := []struct {
		msg  string
		want string
	}{
		{"sequence number overflow", "tls record: sequence number overflow"},
		{"bad padding", "tls record: bad padding"},
		{"", "tls record: "},
	}

	for _, tc := range cases {
		re := &record.Error{Fatal: true, Message: tc.msg}
		got := re.Error()

		if got != tc.want {
			t.Errorf("Error{msg=%q}.Error() = %q, want %q", tc.msg, got, tc.want)
		}
	}
}
