//nolint:testpackage // white-box: exercises unexported state (recordPeerChain, ClientState fields).
package handshake

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/tarantool/go-gostcrypto/x509gost"

	"github.com/tarantool/go-gostls/internal/suites"
	"github.com/tarantool/go-gostls/internal/testutil"
)

// DER encodings of two signature-algorithm OIDs, each 8 content bytes:
// ecdsa-with-SHA256 (1.2.840.10045.4.3.2) and GOST R 34.10-2012-256
// (1.2.643.7.1.1.3.2). Equal lengths let one be swapped for the other inside a
// signed certificate without disturbing any enclosing DER length.
var (
	oidECDSAWithSHA256 = []byte{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02}
	oidGOST2012Sig256  = []byte{0x06, 0x08, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x01, 0x03, 0x02}
)

// newGOSTSignedNonGOSTKeyCert builds the certificate shape that separates the
// two parsers: a GOST signature algorithm over an EC public key. This is what a
// GOST root cross-signing a non-GOST sub-CA produces, and it is the transitional
// arrangement mixed PKIs really deploy. crypto/x509 accepts it — an unrecognised
// signature algorithm is not a parse error — while x509gost rejects it outright.
//
// It is forged by OID substitution rather than by real cross-signing, because
// the signature is never checked here; only the parsers' verdicts matter.
func newGOSTSignedNonGOSTKeyCert(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	testutil.NoErr(t, err, "generate EC key")

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "transitional-sub-CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	testutil.NoErr(t, err, "create EC cert")

	// The OID appears twice: in tbsCertificate.signature and in the outer
	// signatureAlgorithm. Both must move for the certificate to stay well formed.
	patched := bytes.ReplaceAll(der, oidECDSAWithSHA256, oidGOST2012Sig256)

	if count := bytes.Count(patched, oidGOST2012Sig256); count != 2 {
		t.Fatalf("patched %d signature OIDs, want 2 — fixture no longer matches the DER layout", count)
	}

	return patched
}

// TestRecordPeerChain_BothViews checks that the peer chain is kept in both
// shapes and in wire order. The GOST view is the one that matters here: it is
// the only representation that can carry a GOST public key, so losing it would
// leave a GOST handshake unable to report its own peer.
func TestRecordPeerChain_BothViews(t *testing.T) {
	t.Parallel()

	_, leafCert, leafDER := newTestRSACert(t)
	_, interCert, interDER := newTestRSACert(t)

	c := &ClientState{}

	testutil.NoErr(t, c.recordPeerChain([][]byte{leafDER, interDER}), "recordPeerChain")

	res := c.Result()

	if len(res.PeerCertificates) != 2 {
		t.Fatalf("PeerCertificates has %d entries, want 2", len(res.PeerCertificates))
	}

	testutil.EqualBytes(t, res.PeerCertificates[0].Raw, leafCert.Raw, "leaf, stdlib view")
	testutil.EqualBytes(t, res.PeerCertificates[1].Raw, interCert.Raw, "intermediate, stdlib view")

	gostChain, ok := res.GOSTPeerCertificates.([]*x509gost.Certificate)
	if !ok {
		t.Fatalf("GOSTPeerCertificates is %T, want []*x509gost.Certificate", res.GOSTPeerCertificates)
	}

	if len(gostChain) != 2 {
		t.Fatalf("GOSTPeerCertificates has %d entries, want 2", len(gostChain))
	}

	testutil.EqualBytes(t, gostChain[0].Stdlib.Raw, leafCert.Raw, "leaf, GOST view")
}

// TestRecordPeerChain_MalformedEntry checks that an unparsable certificate is
// rejected. Trust settings do not enter into it: malformed DER is malformed
// whether or not the chain would have been verified.
func TestRecordPeerChain_MalformedEntry(t *testing.T) {
	t.Parallel()

	_, _, leafDER := newTestRSACert(t)

	c := &ClientState{params: ClientParams{InsecureSkipVerify: true}}

	err := c.recordPeerChain([][]byte{leafDER, {0x01, 0x02, 0x03}})
	testutil.WantErr(t, err, "recordPeerChain with a malformed intermediate")

	if c.peerCertificates != nil {
		t.Errorf("peerCertificates = %v, want nil after a failed parse", c.peerCertificates)
	}
}

// TestRecordPeerChain_GOSTUnparsableEntryIsNotFatal is the regression test for
// the escape hatch: x509gost is stricter than crypto/x509, so holding the peer
// chain to it would reject certificates that are legal, that crypto/tls accepts,
// and that the connection may not even need — killing handshakes that have
// nothing to do with GOST, InsecureSkipVerify included.
func TestRecordPeerChain_GOSTUnparsableEntryIsNotFatal(t *testing.T) {
	t.Parallel()

	_, _, leafDER := newTestRSACert(t)
	interDER := newGOSTSignedNonGOSTKeyCert(t)

	// Precondition: the two parsers really do disagree about this certificate.
	// Without it the test would still pass if x509gost stopped being stricter,
	// and would no longer be testing anything.
	_, stdlibErr := x509.ParseCertificate(interDER)
	testutil.NoErr(t, stdlibErr, "crypto/x509 must accept the fixture")

	_, gostErr := x509gost.ParseCertificate(interDER)
	testutil.WantErr(t, gostErr, "x509gost must reject the fixture")

	c := &ClientState{params: ClientParams{InsecureSkipVerify: true}}

	testutil.NoErr(t, c.recordPeerChain([][]byte{leafDER, interDER}), "recordPeerChain")

	res := c.Result()

	if len(res.PeerCertificates) != 2 {
		t.Fatalf("PeerCertificates has %d entries, want 2 — the stdlib view is never sparse", len(res.PeerCertificates))
	}

	gostChain, ok := res.GOSTPeerCertificates.([]*x509gost.Certificate)
	if !ok {
		t.Fatalf("GOSTPeerCertificates is %T, want []*x509gost.Certificate", res.GOSTPeerCertificates)
	}

	if gostChain[0] == nil {
		t.Error("GOSTPeerCertificates[0] is nil, want the parsed leaf")
	}

	if gostChain[1] != nil {
		t.Error("GOSTPeerCertificates[1] is non-nil, want nil for a certificate x509gost cannot express")
	}
}

// TestResult_BeforeHandshake checks the zero state: Result is callable at any
// time, and reports nothing negotiated rather than inventing a suite.
func TestResult_BeforeHandshake(t *testing.T) {
	t.Parallel()

	res := (&ClientState{}).Result()

	if res.Complete {
		t.Error("Complete = true on a fresh state, want false")
	}

	if res.SuiteID != 0 {
		t.Errorf("SuiteID = %d on a fresh state, want 0", res.SuiteID)
	}
}

// TestResult_ReportsSuite checks that a negotiated suite is reported, since
// asking which suite was negotiated is the whole point of the type.
func TestResult_ReportsSuite(t *testing.T) {
	t.Parallel()

	all := suites.All()
	if len(all) == 0 {
		t.Fatal("no registered suites")
	}

	want := all[0]

	res := (&ClientState{suite: want, done: true}).Result()

	if !res.Complete {
		t.Error("Complete = false, want true")
	}

	if res.SuiteID != want.ID {
		t.Errorf("SuiteID = %d, want %d", res.SuiteID, want.ID)
	}
}
