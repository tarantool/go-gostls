package gostls_test

import (
	"testing"

	"github.com/tarantool/go-gostls"
	"github.com/tarantool/go-gostls/internal/testutil"
)

// TestDialer_Default_BackendInUse asserts that the default (pure-Go) backend
// is compiled in when the openssl build tag is absent.
func TestDialer_Default_BackendInUse(t *testing.T) {
	t.Parallel()

	testutil.Equal(t, gostls.BackendTag(), "default", "BackendTag()")

	t.Logf("backend: %s", gostls.BackendTag())
}
