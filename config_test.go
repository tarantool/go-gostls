//nolint:testpackage // white-box: tests unexported rootCAPool method on Config
package gostls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/tarantool/go-gostcrypto/x509gost"

	"github.com/tarantool/go-gostls/internal/testutil"
)

// selfSignedPEM generates a minimal self-signed certificate and returns it
// PEM-encoded as a []byte.
func selfSignedPEM(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	testutil.NoErr(t, err, "generate key")

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	testutil.NoErr(t, err, "create certificate")

	var buf bytes.Buffer

	testutil.NoErr(t, pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der}), "pem encode")

	return buf.Bytes()
}

func TestConfig_RootCAPool_PEMOnly(t *testing.T) {
	t.Parallel()

	pemBlock := selfSignedPEM(t)
	cfg := &Config{RootCAPEMs: [][]byte{pemBlock}}

	pool, err := cfg.rootCAPool()
	testutil.NoErr(t, err, "rootCAPool()")

	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
}

func TestConfig_RootCAPool_BothSetErrors(t *testing.T) {
	t.Parallel()

	pemBlock := selfSignedPEM(t)
	existing := x509.NewCertPool()
	cfg := &Config{
		RootCAs:    existing,
		RootCAPEMs: [][]byte{pemBlock},
	}

	_, err := cfg.rootCAPool()
	testutil.WantErr(t, err, "rootCAPool() with both RootCAs and RootCAPEMs set")
}

func TestConfig_RootCAPool_NeitherSetReturnsNil(t *testing.T) {
	t.Parallel()

	cfg := &Config{}

	pool, err := cfg.rootCAPool()
	testutil.NoErr(t, err, "rootCAPool()")

	if pool != nil {
		t.Fatal("expected nil pool when neither RootCAs nor RootCAPEMs is set")
	}
}

// TestGostCertsParam_NilSliceBecomesNilInterface guards the typed-nil pitfall:
// an unset Config.GOSTRoots ([]*x509gost.Certificate)(nil) must reach the
// any-typed handshake field as a genuine nil interface, so the "no GOST roots
// configured" check fires instead of seeing a non-nil interface wrapping nil.
func TestGostCertsParam_NilSliceBecomesNilInterface(t *testing.T) {
	t.Parallel()

	var unset []*x509gost.Certificate

	if got := gostCertsParam(unset); got != nil {
		t.Errorf("gostCertsParam(nil slice) = %v (%T), want nil interface", got, got)
	}
}

// TestGostCertsParam_NonNilPassesThrough confirms a populated slice is boxed
// unchanged and is observable as a non-nil interface.
func TestGostCertsParam_NonNilPassesThrough(t *testing.T) {
	t.Parallel()

	certs := []*x509gost.Certificate{{}, {}}

	got := gostCertsParam(certs)
	if got == nil {
		t.Fatal("gostCertsParam(non-nil slice) = nil interface, want non-nil")
	}

	boxed, ok := got.([]*x509gost.Certificate)
	testutil.Ok(t, ok, fmt.Sprintf("gostCertsParam type assertion to []*x509gost.Certificate (got %T)", got))

	testutil.Len(t, boxed, len(certs), "boxed slice")
}
