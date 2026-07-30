// Package testutil holds the assertion helpers shared by the gostls test
// suites. It exists because the same five shapes — "no error", "an error",
// "that error", "these bytes", "this hex vector" — account for most of the
// assertions across the root, handshake, ke, record and suites packages, and a
// helper in a _test.go file cannot be shared between them.
//
// The helpers are deliberately dependency-free: no testify, no reflection-based
// deep equality. Comparisons are either == on a comparable type or
// bytes.Equal, which is all the protocol tests need and keeps failure messages
// readable.
//
// Every check is fatal — it reports via tb.Fatalf, so the calling test stops at
// the first broken assumption instead of dereferencing a nil the assertion just
// proved was there. Use plain if/t.Errorf where a test should keep going and
// collect several failures.
//
// The what argument labels the assertion in the failure message. Keep it short
// and specific ("ClientHello marshal", "record #3 payload"); it is prepended
// verbatim, so use fmt.Sprintf for anything that needs interpolation.
package testutil

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// NoErr fails the test if err is non-nil.
func NoErr(tb testing.TB, err error, what string) {
	tb.Helper()

	if err != nil {
		tb.Fatalf("%s: unexpected error: %v", what, err)
	}
}

// WantErr fails the test if err is nil. It is the counterpart to NoErr for the
// negative paths: use ErrIs or ErrContains instead whenever the test can name
// the error it expects, so that a different failure does not pass silently.
func WantErr(tb testing.TB, err error, what string) {
	tb.Helper()

	if err == nil {
		tb.Fatalf("%s: got nil error, want an error", what)
	}
}

// ErrIs fails the test unless err matches target under errors.Is. A nil err is
// reported as such rather than as a mismatch, since the two say different
// things about what went wrong.
func ErrIs(tb testing.TB, err, target error, what string) {
	tb.Helper()

	if err == nil {
		tb.Fatalf("%s: got nil error, want %v", what, target)
	}

	if !errors.Is(err, target) {
		tb.Fatalf("%s: got error %v, want %v", what, err, target)
	}
}

// ErrNotIs fails the test if err matches target under errors.Is. It pins down
// the case where an operation must fail, but for a different reason than the
// one the test is guarding against.
func ErrNotIs(tb testing.TB, err, target error, what string) {
	tb.Helper()

	if errors.Is(err, target) {
		tb.Fatalf("%s: got error %v, want anything but %v", what, err, target)
	}
}

// ErrAs fails the test unless err unwraps to type T, and returns the matched
// error so its fields can be asserted on directly:
//
//	alert := testutil.ErrAs[*record.AlertError](t, err, "Open")
//	testutil.Equal(t, alert.Description, record.AlertBadRecordMAC, "alert")
//
// This is the typed counterpart to ErrIs. The type parameter works here and
// cannot work there: errors.As dispatches on the error's type, while errors.Is
// compares against a sentinel value, and the sentinels are all
// errors.New results sharing one dynamic type.
//
// The signature deliberately mirrors the stdlib's
// errors.AsType[E error](error) (E, bool), which does this unwrapping natively.
// The body cannot call it yet: AsType landed in Go 1.26 and go.mod declares
// go 1.25.0, so go vet rejects it as "requires go1.26 or later". Once the
// module floor moves to 1.26 the two ifs below collapse into
//
//	target, ok := errors.AsType[T](err)
//
// with no change to any caller. The helper still earns its place at that point:
// AsType returns a bool, and this turns it into the fatal assertion.
func ErrAs[T error](tb testing.TB, err error, what string) T {
	tb.Helper()

	var target T

	if err == nil {
		tb.Fatalf("%s: got nil error, want %T", what, target)
	}

	if !errors.As(err, &target) {
		tb.Fatalf("%s: got %T (%v), want %T", what, err, err, target)
	}

	return target
}

// ErrContains fails the test unless err is non-nil and its message contains
// substr. Prefer ErrIs where a sentinel exists; this is for the errors that are
// only reachable by their text.
func ErrContains(tb testing.TB, err error, substr, what string) {
	tb.Helper()

	if err == nil {
		tb.Fatalf("%s: got nil error, want one containing %q", what, substr)
	}

	if !strings.Contains(err.Error(), substr) {
		tb.Fatalf("%s: got error %q, want one containing %q", what, err, substr)
	}
}

// Ok fails the test unless ok is true. It is for the comma-ok idiom, which is
// how every registry and map lookup here reports a miss:
//
//	suite, ok := suites.LookupByName(name)
//	testutil.Ok(tb, ok, fmt.Sprintf("LookupByName(%q)", name))
//
// Deliberately not a general-purpose True. A bool that came from an expression
// — !bytes.Equal(a, b), n > limit — should stay an if, because the failure
// message can then name the operands, and "got false, want true" cannot. The
// second half of a comma-ok has no operands to name: the whole diagnostic is
// the what string, so folding it into a helper loses nothing.
func Ok(tb testing.TB, ok bool, what string) {
	tb.Helper()

	if !ok {
		tb.Fatalf("%s: got ok=false, want true", what)
	}
}

// NotOk is the counterpart to Ok, for the lookups a test expects to miss — an
// unregistered suite id, a name that must not resolve. It is separate rather
// than an argument to Ok for the same reason ErrNotIs is separate from ErrIs:
// the two say opposite things and a flipped boolean should not read as a typo.
func NotOk(tb testing.TB, ok bool, what string) {
	tb.Helper()

	if ok {
		tb.Fatalf("%s: got ok=true, want false", what)
	}
}

// Equal fails the test unless got == want. It covers the scalar comparisons
// (lengths, cipher suite ids, protocol versions, enum values); byte slices go
// through EqualBytes.
func Equal[T comparable](tb testing.TB, got, want T, what string) {
	tb.Helper()

	if got != want {
		tb.Fatalf("%s: got %v, want %v", what, got, want)
	}
}

// EqualBytes fails the test unless got and want hold the same bytes, treating
// nil and empty as equal the way bytes.Equal does. Both operands are reported
// in hex, which is what a wire-format or key-schedule mismatch has to be read
// in; lengths are called out separately because a truncation is the common
// case and the hex dumps bury it.
func EqualBytes(tb testing.TB, got, want []byte, what string) {
	tb.Helper()

	if len(got) != len(want) {
		tb.Fatalf("%s: got %d bytes, want %d\n got: %x\nwant: %x", what, len(got), len(want), got, want)
	}

	if !bytes.Equal(got, want) {
		tb.Fatalf("%s: bytes differ\n got: %x\nwant: %x", what, got, want)
	}
}

// NotEqualBytes fails the test if got and want hold the same bytes. It guards
// the checks that something actually changed — a ciphertext that must differ
// from its plaintext, a key that must differ after meshing — where an
// accidentally correct-looking equality is the bug.
func NotEqualBytes(tb testing.TB, got, want []byte, what string) {
	tb.Helper()

	if bytes.Equal(got, want) {
		tb.Fatalf("%s: bytes are equal, want them to differ: %x", what, got)
	}
}

// Len fails the test unless s has exactly want elements. Byte slices get their
// contents dumped in hex, since a wrong length there is usually a truncation
// and the bytes show where it stopped.
func Len[S ~[]E, E any](tb testing.TB, s S, want int, what string) {
	tb.Helper()

	if len(s) == want {
		return
	}

	if b, ok := any(s).([]byte); ok {
		tb.Fatalf("%s: got %d bytes, want %d: %x", what, len(b), want, b)
	}

	tb.Fatalf("%s: got %d elements, want %d", what, len(s), want)
}

// MinLen fails the test unless s has at least n elements. It guards the
// indexed reads that follow it — cke[0], written[:5] — where an exact Len would
// over-specify: the test cares that the prefix is there, not that nothing
// follows it. Byte slices get their contents dumped in hex, as in Len.
func MinLen[S ~[]E, E any](tb testing.TB, s S, n int, what string) {
	tb.Helper()

	if len(s) >= n {
		return
	}

	if b, ok := any(s).([]byte); ok {
		tb.Fatalf("%s: got %d bytes, want at least %d: %x", what, len(b), n, b)
	}

	tb.Fatalf("%s: got %d elements, want at least %d", what, len(s), n)
}

// WantPanic fails the test unless body panics, and returns the recovered value so
// the caller can assert on it. Panicking is how the Must helpers and the
// parsers' internal invariants report, so tests need a way to pin it down.
//
// A panic(nil) counts as a panic: since Go 1.21 the runtime turns it into a
// *runtime.PanicNilError, so recover does not return nil for it.
func WantPanic(tb testing.TB, what string, body func()) any {
	tb.Helper()

	var (
		recovered any
		panicked  bool
	)

	func() {
		defer func() {
			recovered = recover()
			panicked = recovered != nil
		}()

		body()
	}()

	if !panicked {
		tb.Fatalf("%s: did not panic, want a panic", what)
	}

	return recovered
}

// MustHex decodes a hex test vector, failing the test if it is malformed.
// Whitespace is stripped first so that vectors copied out of a specification
// can keep their grouping:
//
//	key := testutil.MustHex(t, "8899aabb ccddeeff 00112233 44556677")
func MustHex(tb testing.TB, s string) []byte {
	tb.Helper()

	compact := strings.Join(strings.Fields(s), "")

	b, err := hex.DecodeString(compact)
	if err != nil {
		tb.Fatalf("MustHex(%q): %v", s, err)
	}

	return b
}

// Must unwraps a (value, error) pair, panicking on error. Unlike the rest of
// this package it takes no testing.TB, because Go does not allow a multi-valued
// call to be mixed with other arguments — Must(t, f()) does not compile. That
// makes it the only form that can wrap a call inline:
//
//	block := testutil.Must(aes.NewCipher(key))
//
// The panic surfaces as a test failure with a stack trace, but names no test
// and runs no cleanup, so keep it to package-level fixtures and setup that
// cannot fail for reasons the test is about. Anywhere the error is part of what
// is under test, bind it and use NoErr.
func Must[T any](v T, err error) T {
	if err != nil {
		panic("testutil.Must: " + err.Error())
	}

	return v
}
