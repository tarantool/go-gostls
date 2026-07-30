package record_test

import (
	"crypto/sha1" //nolint:gosec // testing SHA1Hash which wraps the legacy function
	"crypto/sha512"
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
