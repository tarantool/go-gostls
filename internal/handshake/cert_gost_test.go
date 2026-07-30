//nolint:testpackage // white-box: exercises unexported extractGOSTRoots
package handshake

import (
	"testing"

	"github.com/tarantool/go-gostcrypto/x509gost"

	"github.com/tarantool/go-gostls/internal/testutil"
)

// TestExtractGOSTRoots_Nil returns ErrGOSTRootsRequired for nil.
func TestExtractGOSTRoots_Nil(t *testing.T) {
	t.Parallel()

	_, err := extractGOSTRoots(nil)
	testutil.ErrIs(t, err, ErrGOSTRootsRequired, "extractGOSTRoots(nil)")
}

// TestExtractGOSTRoots_EmptySlice also returns ErrGOSTRootsRequired.
func TestExtractGOSTRoots_EmptySlice(t *testing.T) {
	t.Parallel()

	_, err := extractGOSTRoots([]*x509gost.Certificate{})
	testutil.ErrIs(t, err, ErrGOSTRootsRequired, "extractGOSTRoots(empty slice)")
}

// TestExtractGOSTRoots_WrongType returns a typed error naming the bad type.
func TestExtractGOSTRoots_WrongType(t *testing.T) {
	t.Parallel()

	_, err := extractGOSTRoots("not a roots list")
	testutil.WantErr(t, err, "extractGOSTRoots(wrong type)")
	testutil.ErrNotIs(t, err, ErrGOSTRootsRequired, "extractGOSTRoots(wrong type)")
}

// TestExtractGOSTRoots_Valid returns the slice unchanged on success.
func TestExtractGOSTRoots_Valid(t *testing.T) {
	t.Parallel()

	roots := []*x509gost.Certificate{{}}

	got, err := extractGOSTRoots(roots)
	testutil.NoErr(t, err, "extractGOSTRoots(valid roots)")
	testutil.Len(t, got, 1, "extractGOSTRoots(valid roots) result")
}

// TestExtractGOSTIntermediates_Nil yields a nil pool and no error: unlike the
// roots, intermediates are optional (a direct leaf-signed-by-root chain).
func TestExtractGOSTIntermediates_Nil(t *testing.T) {
	t.Parallel()

	got, err := extractGOSTIntermediates(nil)
	testutil.NoErr(t, err, "extractGOSTIntermediates(nil)")

	if got != nil {
		t.Errorf("nil intermediates: got %v, want nil pool", got)
	}
}

// TestExtractGOSTIntermediates_WrongType errors on a non-nil value of the
// wrong concrete type.
func TestExtractGOSTIntermediates_WrongType(t *testing.T) {
	t.Parallel()

	_, err := extractGOSTIntermediates("not an intermediates list")
	testutil.WantErr(t, err, "extractGOSTIntermediates(wrong type)")
}

// TestExtractGOSTIntermediates_Valid returns the slice unchanged on success.
func TestExtractGOSTIntermediates_Valid(t *testing.T) {
	t.Parallel()

	intermediates := []*x509gost.Certificate{{}, {}}

	got, err := extractGOSTIntermediates(intermediates)
	testutil.NoErr(t, err, "extractGOSTIntermediates(valid)")
	testutil.Len(t, got, 2, "extractGOSTIntermediates(valid) result")
}
