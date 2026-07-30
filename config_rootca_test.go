//nolint:testpackage // white-box: tests unexported rootCAPool error branches
package gostls

import (
	"crypto/x509"
	"testing"

	"github.com/tarantool/go-gostls/internal/testutil"
)

// TestConfig_RootCAPool_NilConfig checks that (nil *Config).rootCAPool()
// returns (nil, nil) — the nil receiver guard.
func TestConfig_RootCAPool_NilConfig(t *testing.T) {
	t.Parallel()

	var cfg *Config

	pool, err := cfg.rootCAPool()
	testutil.NoErr(t, err, "nil Config.rootCAPool()")

	if pool != nil {
		t.Fatal("nil Config.rootCAPool() expected nil pool")
	}
}

// TestConfig_RootCAPool_RootCAsOnly checks the happy path where only
// RootCAs is set: the exact pool is returned unchanged.
func TestConfig_RootCAPool_RootCAsOnly(t *testing.T) {
	t.Parallel()

	pool := x509.NewCertPool()
	cfg := &Config{RootCAs: pool}

	got, err := cfg.rootCAPool()
	testutil.NoErr(t, err, "rootCAPool()")

	if got != pool {
		t.Fatal("expected the exact pool passed in RootCAs to be returned")
	}
}

// TestConfig_RootCAPool_EmptyPEM verifies that an element containing no
// CERTIFICATE blocks at all triggers errRootCAPEMNoCerts.
func TestConfig_RootCAPool_EmptyPEM(t *testing.T) {
	t.Parallel()

	// A valid PEM block but type "PRIVATE KEY" — no CERTIFICATE block.
	const keyPEM = `-----BEGIN PRIVATE KEY-----
dGhpcyBpcyBub3QgYSByZWFsIGtleQ==
-----END PRIVATE KEY-----
`

	cfg := &Config{RootCAPEMs: [][]byte{[]byte(keyPEM)}}

	_, err := cfg.rootCAPool()
	testutil.ErrIs(t, err, errRootCAPEMNoCerts, "rootCAPool() with a PEM holding no CERTIFICATE block")
}

// TestConfig_RootCAPool_MalformedCERTIFICATEBlock verifies that a PEM block
// labelled CERTIFICATE but with invalid DER content triggers errRootCAPEMParseFailed.
func TestConfig_RootCAPool_MalformedCERTIFICATEBlock(t *testing.T) {
	t.Parallel()

	// A PEM block whose type is CERTIFICATE but the bytes are garbage DER.
	const badCertPEM = `-----BEGIN CERTIFICATE-----
dGhpcyBpcyBub3QgYSB2YWxpZCBERVIgY2VydGlmaWNhdGU=
-----END CERTIFICATE-----
`

	cfg := &Config{RootCAPEMs: [][]byte{[]byte(badCertPEM)}}

	_, err := cfg.rootCAPool()
	testutil.ErrIs(t, err, errRootCAPEMParseFailed, "rootCAPool() with a malformed CERTIFICATE block")
}

// TestConfig_RootCAPool_NotPEMAtAll verifies that raw bytes that contain
// no PEM blocks at all return errRootCAPEMNoCerts.
func TestConfig_RootCAPool_NotPEMAtAll(t *testing.T) {
	t.Parallel()

	cfg := &Config{RootCAPEMs: [][]byte{[]byte("this is not PEM data at all")}}

	_, err := cfg.rootCAPool()
	testutil.ErrIs(t, err, errRootCAPEMNoCerts, "rootCAPool() with bytes that are not PEM at all")
}
