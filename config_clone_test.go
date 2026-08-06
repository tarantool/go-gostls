package gostls_test

import (
	"crypto/x509"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/tarantool/go-gostcrypto/x509gost"

	"github.com/tarantool/go-gostls"
	"github.com/tarantool/go-gostls/internal/testutil"
)

// fieldFixture builds the non-zero values the Clone sweep fills a Config with,
// handing out a value that differs from every value it handed out before.
//
// The distinctness is the point, not an implementation detail. The sweep below
// compares each cloned field against its source, and that comparison can only
// catch Clone reading a field from the wrong source when the two fields hold
// telling-apart values. Fill both uint16 fields with 1 and both
// []*x509gost.Certificate fields with the same certificate pointer — as this
// fixture used to — and swapping MinVersion with MaxVersion, or GOSTRoots with
// GOSTIntermediates, inside Clone's literal produces a clone that is
// indistinguishable from a correct one, field by field.
//
// That swap is not hypothetical bookkeeping. `MinVersion: c.MaxVersion` turns a
// config carrying the deliberate policy `MinVersion: VersionTLS13` into a clone
// with MinVersion zero, which is "unset": every checkVersions branch is skipped
// and "TLS 1.3 or nothing" silently becomes an accepted TLS 1.2 handshake — the
// exact downgrade checkVersions exists to refuse.
//
// The counter lives on the fixture rather than on a type, so every leaf value
// in the whole filled Config is unique, nested ones included.
type fieldFixture struct {
	counter uint64
}

// next returns the following fixture ordinal. It starts at 1, since 0 is the
// one value the sweep reads as "Clone forgot this field".
func (f *fieldFixture) next() uint64 {
	f.counter++

	return f.counter
}

// value builds a value of typ that reflect.Value.IsZero reports as non-zero and
// that no other field of the same Config shares. It is the engine behind the
// field sweep below: filling a Config generically is what lets the test notice a
// field nobody taught Clone about, which naming the fields by hand would not.
//
// Composite kinds are built one level deep — a one-element slice, a struct with
// every exported field filled, a fresh pointer — which is enough for IsZero,
// enough for the value comparison, and enough for the aliasing checks to have
// something to mutate.
func (f *fieldFixture) value(t *testing.T, typ reflect.Type) reflect.Value {
	t.Helper()

	val := reflect.New(typ).Elem()

	switch typ.Kind() { //nolint:exhaustive // the default arm fails on every kind Config does not use
	case reflect.Bool:
		// A bool has exactly one non-zero value, so two bool fields can never be
		// told apart here. Config has one; a second would need another tactic.
		val.SetBool(true)
	case reflect.String:
		val.SetString(fmt.Sprintf("non-zero-%d", f.next()))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n := f.next()
		if val.OverflowUint(n) {
			t.Fatalf("fixture ordinal %d overflows %s: give the generator narrower values", n, typ)
		}

		val.SetUint(n)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n := int64(f.next())
		if val.OverflowInt(n) {
			t.Fatalf("fixture ordinal %d overflows %s: give the generator narrower values", n, typ)
		}

		val.SetInt(n)
	case reflect.Pointer:
		// A fresh allocation per call, so no two pointer-valued fields alias and
		// a swap between them shows up as a different address.
		val.Set(reflect.New(typ.Elem()))
	case reflect.Slice:
		slice := reflect.MakeSlice(typ, 1, 1)
		slice.Index(0).Set(f.value(t, typ.Elem()))
		val.Set(slice)
	case reflect.Struct:
		for i := range typ.NumField() {
			field := typ.Field(i)
			if !field.IsExported() {
				continue
			}

			val.Field(i).Set(f.value(t, field.Type))
		}
	case reflect.Func:
		val.Set(zeroReturningFunc(typ))
	case reflect.Interface:
		val.Set(f.nonZeroInterface(t, typ))
	default:
		t.Fatalf("no non-zero fixture for kind %s (type %s): teach fieldFixture.value about it", typ.Kind(), typ)
	}

	return val
}

// nonZeroInterface picks a concrete stand-in for an interface-typed field.
// Unlike the other kinds this cannot be derived from the type, so an unknown
// interface fails the test rather than being skipped: a skipped field is a
// field Clone could silently drop.
func (f *fieldFixture) nonZeroInterface(t *testing.T, typ reflect.Type) reflect.Value {
	t.Helper()

	// An empty interface (crypto.PrivateKey) accepts anything.
	if typ.NumMethod() == 0 {
		return reflect.ValueOf(fmt.Sprintf("non-zero-%d", f.next()))
	}

	if typ == reflect.TypeFor[io.Reader]() {
		// A fresh reader per call: the value is compared by identity, like every
		// other reference Clone shares rather than duplicates.
		return reflect.ValueOf(strings.NewReader(fmt.Sprintf("non-zero-%d", f.next())))
	}

	t.Fatalf("no non-zero fixture for interface type %s: add one so Clone stays covered", typ)

	return reflect.Value{}
}

// zeroReturningFunc synthesizes a callable of the given signature. Nothing here
// calls it; it exists so a func-typed field is non-nil.
func zeroReturningFunc(typ reflect.Type) reflect.Value {
	return reflect.MakeFunc(typ, func(_ []reflect.Value) []reflect.Value {
		out := make([]reflect.Value, typ.NumOut())
		for i := range out {
			out[i] = reflect.Zero(typ.Out(i))
		}

		return out
	})
}

// assertCopiedFrom reports whether got holds what want holds, comparing each
// level the way Clone's contract describes it:
//
//   - slices element by element, recursively. Clone deep-copies them, down to
//     the byte slices inside RootCAPEMs and Certificate.Certificate, so the
//     question is what they contain, never where they live.
//   - pointers and funcs by identity. RootCAs, the certificates in
//     GOSTRoots/GOSTIntermediates, each Certificate's Leaf and PrivateKey and
//     VerifyPeerCertificate are shared by design, and a func cannot be compared
//     any other way — Pointer() is the only handle reflect offers.
//   - everything else by value.
//
// path names the field being compared, extended as the walk descends, so a
// failure points at Config.Certificates[0].Certificate[0] rather than at "a
// byte".
func assertCopiedFrom(t *testing.T, got, want reflect.Value, path string) {
	t.Helper()

	switch want.Kind() { //nolint:exhaustive // the default arm compares every remaining kind by value
	case reflect.Slice:
		if got.Len() != want.Len() {
			t.Errorf("Clone() gave %s length %d, want %d", path, got.Len(), want.Len())

			return
		}

		for i := range want.Len() {
			assertCopiedFrom(t, got.Index(i), want.Index(i), fmt.Sprintf("%s[%d]", path, i))
		}
	case reflect.Struct:
		for i := range want.NumField() {
			field := want.Type().Field(i)
			if !field.IsExported() {
				continue
			}

			assertCopiedFrom(t, got.Field(i), want.Field(i), path+"."+field.Name)
		}
	case reflect.Interface:
		if got.IsNil() != want.IsNil() {
			t.Errorf("Clone() gave %s IsNil() = %t, want %t", path, got.IsNil(), want.IsNil())

			return
		}

		if want.IsNil() {
			return
		}

		if got.Elem().Type() != want.Elem().Type() {
			t.Errorf("Clone() gave %s dynamic type %s, want %s", path, got.Elem().Type(), want.Elem().Type())

			return
		}

		assertCopiedFrom(t, got.Elem(), want.Elem(), path)
	case reflect.Pointer, reflect.Func:
		if got.Pointer() != want.Pointer() {
			t.Errorf("Clone() pointed %s at %#x, want the original's %#x", path, got.Pointer(), want.Pointer())
		}
	default:
		if !got.Equal(want) {
			t.Errorf("Clone() gave %s = %v, want %v", path, got, want)
		}
	}
}

// TestConfig_Clone_CopiesEveryField is the regression guard for Clone drifting
// behind Config: every exported field is filled with a distinct non-zero value,
// and the clone must have none of them left zero and none of them holding
// anything but what its own source held.
//
// The two checks catch different mistakes. A zero field is a field nobody
// taught Clone about, or an interface-typed field this test has no fixture for.
// A non-zero field that differs from its source is a field Clone assigned from
// the wrong place — the swapped pair in Clone's literal that the zero check
// alone cannot see, because both halves of the swap are non-zero.
func TestConfig_Clone_CopiesEveryField(t *testing.T) {
	t.Parallel()

	typ := reflect.TypeFor[gostls.Config]()
	filled := reflect.New(typ).Elem()
	fixture := &fieldFixture{}

	for i := range typ.NumField() {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}

		filled.Field(i).Set(fixture.value(t, field.Type))
	}

	original, ok := filled.Addr().Interface().(*gostls.Config)
	testutil.Ok(t, ok, "filled value is a *gostls.Config")

	clone := original.Clone()
	if clone == nil {
		t.Fatal("Clone() = nil for a non-nil Config")
	}

	cloned := reflect.ValueOf(clone).Elem()

	for i := range typ.NumField() {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}

		// The zero check runs first because it names the likelier cause in
		// plainer terms; reporting the same omission as a value mismatch as
		// well would only bury it.
		if cloned.Field(i).IsZero() {
			t.Errorf("Clone() left Config.%s zero; teach Clone about the field", field.Name)

			continue
		}

		assertCopiedFrom(t, cloned.Field(i), filled.Field(i), "Config."+field.Name)
	}
}

// TestConfig_Clone_NilReceiver pins the nil guard: crypto/tls.Config.Clone
// returns nil for a nil receiver, so callers pass an optional *Config straight
// through without checking first.
func TestConfig_Clone_NilReceiver(t *testing.T) {
	t.Parallel()

	var cfg *gostls.Config

	if cfg.Clone() != nil {
		t.Fatal("(nil *Config).Clone() = non-nil, want nil")
	}
}

// TestConfig_Clone_SlicesAreIndependent is the point of cloning: a caller holds
// a template Config and adjusts a per-connection copy. Mutating the copy —
// including two levels down, inside a certificate's DER chain — must not be
// visible through the template.
//
// The clone's contents are checked before anything is mutated. Independence
// alone is a one-sided property: a Clone that dropped a slice, or filled it
// from the wrong field, would pass every "the original is untouched" assertion
// below precisely because it never carried the original's data in the first
// place.
func TestConfig_Clone_SlicesAreIndependent(t *testing.T) {
	t.Parallel()

	// Two distinct certificates rather than one shared pointer: with the same
	// pointer in both GOST fields, a Clone filling GOSTRoots from
	// GOSTIntermediates (or the reverse) would be indistinguishable here.
	root := &x509gost.Certificate{}
	intermediate := &x509gost.Certificate{}
	pool := x509.NewCertPool()

	original := &gostls.Config{
		RootCAs:           pool,
		RootCAPEMs:        [][]byte{{'a'}},
		GOSTRoots:         []*x509gost.Certificate{root},
		GOSTIntermediates: []*x509gost.Certificate{intermediate},
		Certificates:      []gostls.Certificate{{Certificate: [][]byte{{0x01}}}},
		CipherSuites:      []uint16{0x1301},
	}

	clone := original.Clone()

	testutil.EqualBytes(t, clone.RootCAPEMs[0], []byte{'a'}, "clone RootCAPEMs[0]")
	testutil.EqualBytes(t, clone.Certificates[0].Certificate[0], []byte{0x01}, "clone Certificates[0] chain")
	testutil.Equal(t, clone.CipherSuites[0], uint16(0x1301), "clone CipherSuites[0]")

	if clone.GOSTRoots[0] != root {
		t.Fatal("Clone() did not carry GOSTRoots[0] over from the original")
	}

	if clone.GOSTIntermediates[0] != intermediate {
		t.Fatal("Clone() did not carry GOSTIntermediates[0] over from the original")
	}

	clone.RootCAPEMs[0][0] = 'b'
	clone.GOSTRoots[0] = nil
	clone.GOSTIntermediates[0] = nil
	clone.Certificates[0].Certificate[0][0] = 0xff
	clone.CipherSuites[0] = 0xffff

	testutil.EqualBytes(t, original.RootCAPEMs[0], []byte{'a'}, "original RootCAPEMs[0]")
	testutil.EqualBytes(t, original.Certificates[0].Certificate[0], []byte{0x01}, "original Certificates[0] chain")
	testutil.Equal(t, original.CipherSuites[0], uint16(0x1301), "original CipherSuites[0]")

	if original.GOSTRoots[0] != root {
		t.Error("clearing clone.GOSTRoots[0] changed the original")
	}

	if original.GOSTIntermediates[0] != intermediate {
		t.Error("clearing clone.GOSTIntermediates[0] changed the original")
	}

	// Pointer-valued fields are shared by design, as Clone documents.
	if clone.RootCAs != pool {
		t.Error("Clone() duplicated RootCAs; the pool is meant to be shared")
	}
}
