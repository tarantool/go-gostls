package testutil_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/tarantool/go-gostls/internal/testutil"
)

// fatalSentinel is panicked by fakeTB.Fatalf to emulate the runtime.Goexit that
// a real testing.T performs, so that a helper under test does not run on past
// the point where it reported a failure.
type fatalSentinel struct{}

// fakeTB records what a helper reported instead of failing the enclosing test.
// testing.TB has an unexported method, so it can only be implemented by
// embedding the interface; every method the helpers actually call is overridden
// below, and the nil embedded value makes any other call panic loudly rather
// than pass unnoticed.
type fakeTB struct {
	testing.TB

	failed bool
	msg    string
}

func (f *fakeTB) Helper() {}

func (f *fakeTB) Fatalf(format string, args ...any) {
	f.failed = true
	f.msg = fmt.Sprintf(format, args...)

	panic(fatalSentinel{})
}

// run invokes check with a fresh fakeTB and returns it holding whatever the
// check reported. The checks take *fakeTB rather than testing.TB — it satisfies
// that interface either way, and the concrete type keeps the case closures from
// being mistaken for test helpers that ought to call tb.Helper().
func run(check func(tb *fakeTB)) *fakeTB {
	fake := &fakeTB{}

	// The sentinel panic has to be absorbed here, not in the caller, so that a
	// failing check does not skip the assertions that follow it.
	func() {
		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(fatalSentinel); !ok {
					panic(r)
				}
			}
		}()

		check(fake)
	}()

	return fake
}

// wantPass asserts that check reported no failure.
func wantPass(t *testing.T, what string, check func(tb *fakeTB)) {
	t.Helper()

	if fake := run(check); fake.failed {
		t.Errorf("%s: reported a failure on a passing input: %s", what, fake.msg)
	}
}

// wantFail asserts that check reported a failure whose message mentions each of
// the given substrings, so that the diagnostic actually names the operands.
func wantFail(t *testing.T, what string, check func(tb *fakeTB), substrs ...string) {
	t.Helper()

	fake := run(check)
	if !fake.failed {
		t.Errorf("%s: reported no failure on a failing input", what)

		return
	}

	for _, substr := range substrs {
		if !strings.Contains(fake.msg, substr) {
			t.Errorf("%s: message %q does not mention %q", what, fake.msg, substr)
		}
	}
}

var (
	errSentinel     = errors.New("sentinel")
	errOther        = errors.New("other")
	errBadRecordMAC = errors.New("tls: bad record MAC")
)

func TestNoErr(t *testing.T) {
	t.Parallel()

	wantPass(t, "nil error", func(tb *fakeTB) {
		testutil.NoErr(tb, nil, "op")
	})

	wantFail(t, "non-nil error", func(tb *fakeTB) {
		testutil.NoErr(tb, errSentinel, "op")
	}, "op", "sentinel")
}

func TestWantErr(t *testing.T) {
	t.Parallel()

	wantPass(t, "non-nil error", func(tb *fakeTB) {
		testutil.WantErr(tb, errSentinel, "op")
	})

	wantFail(t, "nil error", func(tb *fakeTB) {
		testutil.WantErr(tb, nil, "op")
	}, "op", "want an error")
}

func TestErrIs(t *testing.T) {
	t.Parallel()

	wantPass(t, "identical error", func(tb *fakeTB) {
		testutil.ErrIs(tb, errSentinel, errSentinel, "op")
	})

	wantPass(t, "wrapped error", func(tb *fakeTB) {
		testutil.ErrIs(tb, fmt.Errorf("tls: %w", errSentinel), errSentinel, "op")
	})

	wantFail(t, "different error", func(tb *fakeTB) {
		testutil.ErrIs(tb, errOther, errSentinel, "op")
	}, "op", "other", "sentinel")

	// A nil error must be called out as nil, not as a plain mismatch.
	wantFail(t, "nil error", func(tb *fakeTB) {
		testutil.ErrIs(tb, nil, errSentinel, "op")
	}, "op", "nil error", "sentinel")
}

func TestErrNotIs(t *testing.T) {
	t.Parallel()

	wantPass(t, "different error", func(tb *fakeTB) {
		testutil.ErrNotIs(tb, errOther, errSentinel, "op")
	})

	// Failing for no reason at all is still not failing for this reason.
	wantPass(t, "nil error", func(tb *fakeTB) {
		testutil.ErrNotIs(tb, nil, errSentinel, "op")
	})

	wantFail(t, "wrapped target", func(tb *fakeTB) {
		testutil.ErrNotIs(tb, fmt.Errorf("tls: %w", errSentinel), errSentinel, "op")
	}, "op", "sentinel")
}

// wireError stands in for the typed errors ErrAs is meant for, such as
// *record.AlertError, whose fields the caller asserts on after matching.
type wireError struct {
	code int
}

func (e *wireError) Error() string {
	return fmt.Sprintf("wire error %d", e.code)
}

func TestErrAs(t *testing.T) {
	t.Parallel()

	// The matched error comes back typed, so its fields are reachable.
	wantPass(t, "wrapped typed error", func(tb *fakeTB) {
		err := fmt.Errorf("tls: %w", &wireError{code: 7})

		got := testutil.ErrAs[*wireError](tb, err, "op")
		testutil.Equal(tb, got.code, 7, "code")
	})

	wantPass(t, "unwrapped typed error", func(tb *fakeTB) {
		got := testutil.ErrAs[*wireError](tb, &wireError{code: 3}, "op")
		testutil.Equal(tb, got.code, 3, "code")
	})

	// A sentinel is not the wanted type; the message must name both types.
	wantFail(t, "wrong type", func(tb *fakeTB) {
		_ = testutil.ErrAs[*wireError](tb, errSentinel, "op")
	}, "op", "wireError", "sentinel")

	wantFail(t, "nil error", func(tb *fakeTB) {
		_ = testutil.ErrAs[*wireError](tb, nil, "op")
	}, "op", "nil error", "wireError")
}

func TestErrContains(t *testing.T) {
	t.Parallel()

	wantPass(t, "matching substring", func(tb *fakeTB) {
		testutil.ErrContains(tb, errBadRecordMAC, "bad record MAC", "op")
	})

	wantFail(t, "missing substring", func(tb *fakeTB) {
		testutil.ErrContains(tb, errBadRecordMAC, "handshake failure", "op")
	}, "op", "bad record MAC", "handshake failure")

	wantFail(t, "nil error", func(tb *fakeTB) {
		testutil.ErrContains(tb, nil, "handshake failure", "op")
	}, "op", "nil error", "handshake failure")
}

func TestEqual(t *testing.T) {
	t.Parallel()

	wantPass(t, "equal ints", func(tb *fakeTB) {
		testutil.Equal(tb, 42, 42, "length")
	})

	wantPass(t, "equal strings", func(tb *fakeTB) {
		testutil.Equal(tb, "TLS 1.2", "TLS 1.2", "version")
	})

	wantFail(t, "unequal ints", func(tb *fakeTB) {
		testutil.Equal(tb, 41, 42, "length")
	}, "length", "41", "42")

	// uint16 is the shape of a cipher suite id, the most common use.
	wantFail(t, "unequal uint16", func(tb *fakeTB) {
		testutil.Equal(tb, uint16(0xc102), uint16(0xc100), "suite id")
	}, "suite id")
}

func TestEqualBytes(t *testing.T) {
	t.Parallel()

	wantPass(t, "equal bytes", func(tb *fakeTB) {
		testutil.EqualBytes(tb, []byte{1, 2, 3}, []byte{1, 2, 3}, "payload")
	})

	// bytes.Equal semantics: nil and empty are the same value here.
	wantPass(t, "nil vs empty", func(tb *fakeTB) {
		testutil.EqualBytes(tb, nil, []byte{}, "payload")
	})

	wantFail(t, "same length, different bytes", func(tb *fakeTB) {
		testutil.EqualBytes(tb, []byte{1, 2, 3}, []byte{1, 2, 4}, "payload")
	}, "payload", "010203", "010204")

	// A truncation must report the lengths, since the hex alone hides it.
	wantFail(t, "truncated", func(tb *fakeTB) {
		testutil.EqualBytes(tb, []byte{1, 2}, []byte{1, 2, 3}, "payload")
	}, "payload", "got 2 bytes", "want 3")
}

func TestNotEqualBytes(t *testing.T) {
	t.Parallel()

	wantPass(t, "different bytes", func(tb *fakeTB) {
		testutil.NotEqualBytes(tb, []byte{1, 2, 3}, []byte{1, 2, 4}, "ciphertext")
	})

	wantPass(t, "different lengths", func(tb *fakeTB) {
		testutil.NotEqualBytes(tb, []byte{1, 2}, []byte{1, 2, 3}, "ciphertext")
	})

	wantFail(t, "equal bytes", func(tb *fakeTB) {
		testutil.NotEqualBytes(tb, []byte{1, 2, 3}, []byte{1, 2, 3}, "ciphertext")
	}, "ciphertext", "010203")

	// The nil/empty equivalence has to hold in the negative direction too.
	wantFail(t, "nil vs empty", func(tb *fakeTB) {
		testutil.NotEqualBytes(tb, nil, []byte{}, "ciphertext")
	}, "ciphertext")
}

func TestLen(t *testing.T) {
	t.Parallel()

	wantPass(t, "matching byte length", func(tb *fakeTB) {
		testutil.Len(tb, []byte{1, 2, 3, 4}, 4, "key")
	})

	wantPass(t, "matching slice length", func(tb *fakeTB) {
		testutil.Len(tb, []string{"a", "b"}, 2, "names")
	})

	wantPass(t, "empty slice", func(tb *fakeTB) {
		testutil.Len(tb, []byte(nil), 0, "key")
	})

	// A byte slice reports its contents, since a bad length is a truncation.
	wantFail(t, "wrong byte length", func(tb *fakeTB) {
		testutil.Len(tb, []byte{1, 2}, 4, "key")
	}, "key", "got 2 bytes", "want 4", "0102")

	// A non-byte slice reports elements, with no hex dump to give.
	wantFail(t, "wrong slice length", func(tb *fakeTB) {
		testutil.Len(tb, []string{"a"}, 3, "names")
	}, "names", "got 1 elements", "want 3")
}

func TestOk(t *testing.T) {
	t.Parallel()

	wantPass(t, "ok", func(tb *fakeTB) {
		testutil.Ok(tb, true, "LookupByName")
	})

	wantFail(t, "not ok", func(tb *fakeTB) {
		testutil.Ok(tb, false, "LookupByName")
	}, "LookupByName", "got ok=false", "want true")
}

func TestNotOk(t *testing.T) {
	t.Parallel()

	wantPass(t, "not ok", func(tb *fakeTB) {
		testutil.NotOk(tb, false, "Lookup(0x0000)")
	})

	wantFail(t, "unexpectedly ok", func(tb *fakeTB) {
		testutil.NotOk(tb, true, "Lookup(0x0000)")
	}, "Lookup(0x0000)", "got ok=true", "want false")
}

func TestMinLen(t *testing.T) {
	t.Parallel()

	// The bound is inclusive: exactly n elements passes.
	wantPass(t, "exact length", func(tb *fakeTB) {
		testutil.MinLen(tb, []byte{1, 2}, 2, "cke")
	})

	wantPass(t, "longer than the bound", func(tb *fakeTB) {
		testutil.MinLen(tb, []byte{1, 2, 3, 4}, 2, "cke")
	})

	// MinLen(1) is the "not empty" case, which is why no separate helper exists.
	wantPass(t, "non-empty", func(tb *fakeTB) {
		testutil.MinLen(tb, []string{"a"}, 1, "names")
	})

	wantFail(t, "too short", func(tb *fakeTB) {
		testutil.MinLen(tb, []byte{1}, 2, "cke")
	}, "cke", "got 1 bytes", "want at least 2", "01")

	wantFail(t, "empty", func(tb *fakeTB) {
		testutil.MinLen(tb, []byte(nil), 1, "cke")
	}, "cke", "got 0 bytes", "want at least 1")

	// A non-byte slice reports elements, with no hex dump to give.
	wantFail(t, "too few elements", func(tb *fakeTB) {
		testutil.MinLen(tb, []string{"a"}, 3, "names")
	}, "names", "got 1 elements", "want at least 3")
}

func TestWantPanic(t *testing.T) {
	t.Parallel()

	wantPass(t, "panics", func(tb *fakeTB) {
		got := testutil.WantPanic(tb, "op", func() {
			panic("boom")
		})
		testutil.Equal(tb, got, any("boom"), "recovered value")
	})

	// panic(nil) still counts, via runtime.PanicNilError.
	wantPass(t, "panics with nil", func(tb *fakeTB) {
		got := testutil.WantPanic(tb, "op", func() {
			// Exercising the Go 1.21+ PanicNilError behaviour on purpose.
			panic(nil)
		})
		if got == nil {
			tb.Fatalf("recovered value: got nil, want a *runtime.PanicNilError")
		}
	})

	// It composes with Must, which is the main thing it is for.
	wantPass(t, "catches Must", func(tb *fakeTB) {
		testutil.WantPanic(tb, "Must", func() {
			_ = testutil.Must(0, errSentinel)
		})
	})

	wantFail(t, "does not panic", func(tb *fakeTB) {
		testutil.WantPanic(tb, "op", func() {})
	}, "op", "did not panic")
}

func TestMustHex(t *testing.T) {
	t.Parallel()

	wantPass(t, "plain vector", func(tb *fakeTB) {
		got := testutil.MustHex(tb, "8899aabb")
		testutil.EqualBytes(tb, got, []byte{0x88, 0x99, 0xaa, 0xbb}, "decoded")
	})

	// Grouping and newlines, as copied out of a specification.
	wantPass(t, "grouped vector", func(tb *fakeTB) {
		got := testutil.MustHex(tb, "8899aabb ccddeeff\n\t00112233")
		want := []byte{0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33}
		testutil.EqualBytes(tb, got, want, "decoded")
	})

	wantPass(t, "empty vector", func(tb *fakeTB) {
		testutil.Equal(tb, len(testutil.MustHex(tb, "")), 0, "decoded length")
	})

	wantFail(t, "non-hex digit", func(tb *fakeTB) {
		testutil.MustHex(tb, "zz")
	}, "MustHex", "zz")

	wantFail(t, "odd length", func(tb *fakeTB) {
		testutil.MustHex(tb, "abc")
	}, "MustHex", "abc")
}

func TestMust(t *testing.T) {
	t.Parallel()

	// The happy path returns the value untouched.
	if got := testutil.Must(42, nil); got != 42 {
		t.Errorf("Must: got %d, want 42", got)
	}

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("Must: did not panic on a non-nil error")
		}

		text, ok := r.(string)
		if !ok {
			t.Fatalf("Must: panicked with %T, want string", r)
		}

		if !strings.Contains(text, "sentinel") {
			t.Errorf("Must: panic %q does not mention the error", text)
		}
	}()

	testutil.Must(0, errSentinel)
}
