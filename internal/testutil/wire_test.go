package testutil_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tarantool/go-gostls/internal/testutil"
)

// wantBytes compares a builder's output against the bytes spelled out by hand,
// which is the only comparison worth making here: a helper that assembles wire
// format has to be checked against the literal bytes, not against another
// expression built from the same helper.
func wantBytes(t *testing.T, what string, got, want []byte) {
	t.Helper()

	if !bytes.Equal(got, want) {
		t.Errorf("%s: got %x, want %x", what, got, want)
	}
}

// wantPanicMsg asserts that body panics with a message containing substr, so
// that an overflowing vector is reported as such rather than by whatever the
// append happens to do afterwards.
func wantPanicMsg(t *testing.T, what string, substr string, body func()) {
	t.Helper()

	recovered := testutil.WantPanic(t, what, body)

	msg, ok := recovered.(string)
	if !ok {
		t.Fatalf("%s: recovered %T (%v), want a string", what, recovered, recovered)
	}

	if !strings.Contains(msg, substr) {
		t.Errorf("%s: panicked with %q, want it to mention %q", what, msg, substr)
	}
}

func TestAppendU16(t *testing.T) {
	t.Parallel()

	wantBytes(t, "zero", testutil.AppendU16(nil, 0), []byte{0x00, 0x00})
	wantBytes(t, "max", testutil.AppendU16(nil, 0xFFFF), []byte{0xFF, 0xFF})
	wantBytes(t, "big-endian", testutil.AppendU16(nil, 0x1234), []byte{0x12, 0x34})

	// Appending to a non-empty destination must extend it, not replace it:
	// every real call site chains these.
	wantBytes(t, "appends", testutil.AppendU16([]byte{0xAA}, 0x0301), []byte{0xAA, 0x03, 0x01})
}

func TestAppendU24(t *testing.T) {
	t.Parallel()

	wantBytes(t, "zero", testutil.AppendU24(nil, 0), []byte{0x00, 0x00, 0x00})
	wantBytes(t, "max", testutil.AppendU24(nil, 1<<24-1), []byte{0xFF, 0xFF, 0xFF})
	wantBytes(t, "big-endian", testutil.AppendU24(nil, 0x123456), []byte{0x12, 0x34, 0x56})
	wantBytes(t, "appends", testutil.AppendU24([]byte{0xAA}, 1), []byte{0xAA, 0x00, 0x00, 0x01})

	// The whole point of the bound: without it the high byte is dropped and
	// 1<<24 would be written as a zero length.
	wantPanicMsg(t, "AppendU24 overflow", "24 bits", func() {
		testutil.AppendU24(nil, 1<<24)
	})
}

func TestAppendU8Prefixed(t *testing.T) {
	t.Parallel()

	wantBytes(t, "empty", testutil.AppendU8Prefixed(nil, nil), []byte{0x00})
	wantBytes(t, "payload", testutil.AppendU8Prefixed(nil, []byte{0xDE, 0xAD}), []byte{0x02, 0xDE, 0xAD})
	wantBytes(t, "appends", testutil.AppendU8Prefixed([]byte{0xAA}, []byte{0xBB}), []byte{0xAA, 0x01, 0xBB})

	wantPanicMsg(t, "AppendU8Prefixed overflow", "uint8 length prefix", func() {
		testutil.AppendU8Prefixed(nil, make([]byte, 256))
	})
}

func TestAppendU16Prefixed(t *testing.T) {
	t.Parallel()

	wantBytes(t, "empty", testutil.AppendU16Prefixed(nil, nil), []byte{0x00, 0x00})
	wantBytes(t, "payload", testutil.AppendU16Prefixed(nil, []byte{0xDE, 0xAD}), []byte{0x00, 0x02, 0xDE, 0xAD})
	wantBytes(t, "appends", testutil.AppendU16Prefixed([]byte{0xAA}, []byte{0xBB}), []byte{0xAA, 0x00, 0x01, 0xBB})

	// A 256-byte vector is where a one-byte prefix would have wrapped to zero;
	// the two-byte prefix has to carry it.
	got := testutil.AppendU16Prefixed(nil, make([]byte, 256))
	wantBytes(t, "256-byte prefix", got[:2], []byte{0x01, 0x00})

	wantPanicMsg(t, "AppendU16Prefixed overflow", "uint16 length prefix", func() {
		testutil.AppendU16Prefixed(nil, make([]byte, 1<<16))
	})
}

func TestAppendU24Prefixed(t *testing.T) {
	t.Parallel()

	wantBytes(t, "empty", testutil.AppendU24Prefixed(nil, nil), []byte{0x00, 0x00, 0x00})
	wantBytes(t, "payload", testutil.AppendU24Prefixed(nil, []byte{0xDE}), []byte{0x00, 0x00, 0x01, 0xDE})

	// 1<<16 bytes is where a two-byte prefix would have wrapped to zero.
	got := testutil.AppendU24Prefixed(nil, make([]byte, 1<<16))
	wantBytes(t, "65536-byte prefix", got[:3], []byte{0x01, 0x00, 0x00})

	// The 16 MiB allocation is the cheapest way to reach the bound, and it is
	// freed as soon as the panic unwinds.
	wantPanicMsg(t, "AppendU24Prefixed overflow", "uint24 length prefix", func() {
		testutil.AppendU24Prefixed(nil, make([]byte, 1<<24))
	})
}

// TestAppendPrefixed_Chained builds a miniature handshake message the way the
// ported test suites do, to pin down that the builders compose: a u24-framed
// body holding a u16 field and a u8 field.
func TestAppendPrefixed_Chained(t *testing.T) {
	t.Parallel()

	body := testutil.AppendU16(nil, 0x0303)

	body = testutil.AppendU8Prefixed(body, []byte{0x01, 0x02})
	body = testutil.AppendU16Prefixed(body, []byte{0xC0, 0x2F})

	want := []byte{
		0x00, 0x00, 0x09, // u24 body length.
		0x03, 0x03, // version.
		0x02, 0x01, 0x02, // u8-prefixed vector.
		0x00, 0x02, 0xC0, 0x2F, // u16-prefixed vector.
	}

	wantBytes(t, "chained", testutil.AppendU24Prefixed(nil, body), want)
}
