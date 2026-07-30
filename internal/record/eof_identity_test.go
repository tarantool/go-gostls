package record_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/tarantool/go-gostls/internal/record"
	"github.com/tarantool/go-gostls/internal/testutil"
)

// TestReadRecord_CleanEOFKeepsIdentity pins that a clean end of stream comes
// back as io.EOF itself, not wrapped.
//
// This is not stylistic. io.Copy — and a lot of other code — tests the read
// error with `== io.EOF` rather than errors.Is, so wrapping it turns an
// ordinary connection close into an error for anyone copying from a Conn.
// wrapcheck asks for that wrap; it must not be applied here.
func TestReadRecord_CleanEOFKeepsIdentity(t *testing.T) {
	t.Parallel()

	layer := record.NewLayer(struct {
		io.Reader
		io.Writer
	}{bytes.NewReader(nil), io.Discard})

	_, _, err := layer.ReadRecord()

	testutil.WantErr(t, err, "ReadRecord on an empty stream (want io.EOF)")

	//nolint:errorlint // the point of this test is the identity comparison.
	if err != io.EOF {
		t.Fatalf("clean EOF must be returned unwrapped, got %#v", err)
	}
}

// TestReadRecord_TruncatedFragmentIsWrapped is the counterpart: an EOF partway
// through a record is a truncation, not a clean close, so it carries context.
func TestReadRecord_TruncatedFragmentIsWrapped(t *testing.T) {
	t.Parallel()

	// A valid header declaring 16 bytes, followed by only 2.
	stream := []byte{0x17, 0x03, 0x03, 0x00, 0x10, 0xAA, 0xBB}

	layer := record.NewLayer(struct {
		io.Reader
		io.Writer
	}{bytes.NewReader(stream), io.Discard})

	_, _, err := layer.ReadRecord()

	testutil.WantErr(t, err, "ReadRecord on a truncated record")

	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("expected the underlying io.ErrUnexpectedEOF to survive wrapping, got %v", err)
	}

	if err.Error() == io.ErrUnexpectedEOF.Error() {
		t.Error("a truncated record should carry context, not be returned bare")
	}
}
