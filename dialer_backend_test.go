package gostls_test

import (
	"testing"

	"github.com/tarantool/go-gostls"
	"github.com/tarantool/go-gostls/internal/testutil"
)

// TestDialer_Default_BackendInUse asserts that this module keeps reporting
// itself as the pure-Go backend: go-tlsdialer reads the tag to say which
// backend it selected, so the value is part of the API.
func TestDialer_Default_BackendInUse(t *testing.T) {
	t.Parallel()

	testutil.Equal(t, gostls.BackendTag(), "default", "BackendTag()")

	t.Logf("backend: %s", gostls.BackendTag())
}
