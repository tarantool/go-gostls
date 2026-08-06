package gostls_test

import (
	"crypto/x509"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/tarantool/go-gostcrypto/x509gost"

	"github.com/tarantool/go-gostls"
	"github.com/tarantool/go-gostls/internal/testutil"
)

// nonZeroValue builds a value of typ that reflect.Value.IsZero reports as
// non-zero. It is the engine behind the field sweep below: filling a Config
// generically is what lets the test notice a field nobody taught Clone about,
// which naming the fields by hand would not.
//
// Composite kinds are built one level deep — a one-element slice, a struct with
// every exported field filled, a fresh pointer — which is enough for IsZero and
// enough for the aliasing checks to have something to mutate.
func nonZeroValue(t *testing.T, typ reflect.Type) reflect.Value {
	t.Helper()

	val := reflect.New(typ).Elem()

	switch typ.Kind() { //nolint:exhaustive // the default arm fails on every kind Config does not use
	case reflect.Bool:
		val.SetBool(true)
	case reflect.String:
		val.SetString("non-zero")
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		val.SetUint(1)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		val.SetInt(1)
	case reflect.Pointer:
		val.Set(reflect.New(typ.Elem()))
	case reflect.Slice:
		slice := reflect.MakeSlice(typ, 1, 1)
		slice.Index(0).Set(nonZeroValue(t, typ.Elem()))
		val.Set(slice)
	case reflect.Struct:
		for i := range typ.NumField() {
			field := typ.Field(i)
			if !field.IsExported() {
				continue
			}

			val.Field(i).Set(nonZeroValue(t, field.Type))
		}
	case reflect.Func:
		val.Set(zeroReturningFunc(typ))
	case reflect.Interface:
		val.Set(nonZeroInterface(t, typ))
	default:
		t.Fatalf("no non-zero fixture for kind %s (type %s): teach nonZeroValue about it", typ.Kind(), typ)
	}

	return val
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

// nonZeroInterface picks a concrete stand-in for an interface-typed field.
// Unlike the other kinds this cannot be derived from the type, so an unknown
// interface fails the test rather than being skipped: a skipped field is a
// field Clone could silently drop.
func nonZeroInterface(t *testing.T, typ reflect.Type) reflect.Value {
	t.Helper()

	// An empty interface (crypto.PrivateKey) accepts anything.
	if typ.NumMethod() == 0 {
		return reflect.ValueOf("non-zero")
	}

	if typ == reflect.TypeFor[io.Reader]() {
		return reflect.ValueOf(strings.NewReader("non-zero"))
	}

	t.Fatalf("no non-zero fixture for interface type %s: add one so Clone stays covered", typ)

	return reflect.Value{}
}

// TestConfig_Clone_CopiesEveryField is the regression guard for Clone drifting
// behind Config: every exported field is filled with a non-zero value, and the
// clone must have none of them left zero. Adding a field to Config without
// carrying it through Clone fails here, and so does an interface-typed field
// this test has no fixture for.
func TestConfig_Clone_CopiesEveryField(t *testing.T) {
	t.Parallel()

	typ := reflect.TypeFor[gostls.Config]()
	filled := reflect.New(typ).Elem()

	for i := range typ.NumField() {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}

		filled.Field(i).Set(nonZeroValue(t, field.Type))
	}

	original, ok := filled.Addr().Interface().(*gostls.Config)
	testutil.Ok(t, ok, "filled value is a *gostls.Config")

	clone := original.Clone()
	if clone == nil {
		t.Fatal("Clone() = nil for a non-nil Config")
	}

	cloned := reflect.ValueOf(clone).Elem()

	for i := range typ.NumField() {
		if !typ.Field(i).IsExported() {
			continue
		}

		if cloned.Field(i).IsZero() {
			t.Errorf("Clone() left Config.%s zero; teach Clone about the field", typ.Field(i).Name)
		}
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
func TestConfig_Clone_SlicesAreIndependent(t *testing.T) {
	t.Parallel()

	root := &x509gost.Certificate{}
	pool := x509.NewCertPool()

	original := &gostls.Config{
		RootCAs:           pool,
		RootCAPEMs:        [][]byte{{'a'}},
		GOSTRoots:         []*x509gost.Certificate{root},
		GOSTIntermediates: []*x509gost.Certificate{root},
		Certificates:      []gostls.Certificate{{Certificate: [][]byte{{0x01}}}},
		CipherSuites:      []uint16{0x1301},
	}

	clone := original.Clone()

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

	if original.GOSTIntermediates[0] != root {
		t.Error("clearing clone.GOSTIntermediates[0] changed the original")
	}

	// Pointer-valued fields are shared by design, as Clone documents.
	if clone.RootCAs != pool {
		t.Error("Clone() duplicated RootCAs; the pool is meant to be shared")
	}
}
