//nolint:testpackage // white-box: exercises unexported state (recordPeerChain, ClientState fields).
package handshake

import (
	"testing"

	"github.com/tarantool/go-gostcrypto/x509gost"

	"github.com/tarantool/go-gostls/internal/suites"
	"github.com/tarantool/go-gostls/internal/testutil"
)

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
