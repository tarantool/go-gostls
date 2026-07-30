//nolint:testpackage // white-box: exercises unexported parsers, verifiers and error sentinels
package handshake

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/tarantool/go-gostls/internal/record"
	"github.com/tarantool/go-gostls/internal/suites"
	"github.com/tarantool/go-gostls/internal/testutil"
)

// TestVerifyECDHESKE_RejectsUnadvertisedSigAlg covers M2: the ServerKeyExchange
// signature algorithm must be one the client advertised. SHA-1 is not
// advertised, so an SKE that uses rsa_pkcs1_sha1 is rejected before the
// signature is even checked.
func TestVerifyECDHESKE_RejectsUnadvertisedSigAlg(t *testing.T) {
	t.Parallel()

	priv, cert := newTestECDSACert(t)

	var clientRandom, serverRandom [32]byte

	body := buildECDHESKEBody(t, priv, clientRandom, serverRandom)

	// Patch the (hash, sig) bytes to sha1+rsa (0x02, 0x01), which is not in
	// clientSigAlgsAdvertised. Layout: curve_type(1) named_curve(2) point_len(1)
	// point(point_len) hashAlg sigAlg ...
	algOff := 4 + int(body[3])

	body[algOff] = 0x02
	body[algOff+1] = 0x01

	suite := mustLookupSuite(t, "ECDHE-ECDSA-AES128-SHA256")
	c := makeMinimalClientState(t, suite)

	c.clientRandom = clientRandom
	c.serverRandom = serverRandom

	_, err := c.verifyServerKeyExchange(body, cert)
	testutil.ErrIs(t, err, errSKEUnadvertisedSigAlg, "verifyServerKeyExchange with sha1+rsa")
}

// TestParseServerHello_RejectsTrailingBytes covers L5: bytes after the extension
// block must be rejected, not silently ignored.
func TestParseServerHello_RejectsTrailingBytes(t *testing.T) {
	t.Parallel()

	sh := &ServerHello{Version: tlsVersion12, CipherSuite: 0x002F}

	marshaled, marshaledErr := sh.Marshal()
	testutil.NoErr(t, marshaledErr, "ServerHello marshal")

	body := marshaled // no extensions -> no extension bytes.

	// Append an empty extension list (uint16 length = 0) followed by a stray byte.
	body = append(body, 0x00, 0x00, 0xFF)

	_, err := parseServerHello(body)
	testutil.ErrIs(t, err, errSHTrailingData, "parseServerHello with trailing bytes")
}

// TestParseCertificate_RejectsTrailingBytes covers L5/D1: bytes after the
// certificate_list must be rejected.
func TestParseCertificate_RejectsTrailingBytes(t *testing.T) {
	t.Parallel()

	cert := &Certificate{RawCerts: [][]byte{{0x01, 0x02, 0x03}}}

	body, bodyMErr := cert.Marshal()
	testutil.NoErr(t, bodyMErr, "Certificate marshal")

	body = append(body, 0xAA) // stray byte after the certificate_list.

	_, err := parseCertificate(body)
	testutil.ErrIs(t, err, errCertTrailingData, "parseCertificate with trailing bytes")
}

// TestRecvServerHello_RejectsUnofferedExtension covers L6: a ServerHello carrying
// an extension the client did not offer must abort the handshake. Here the
// client offers no SNI (ServerName == ""), so a server_name extension in the
// ServerHello is un-offered.
func TestRecvServerHello_RejectsUnofferedExtension(t *testing.T) {
	t.Parallel()

	ids := AvailableSuites()
	testutil.MinLen(t, ids, 1, "AvailableSuites")

	suiteID := ids[0]

	suite, ok := suites.Lookup(suiteID)
	testutil.Ok(t, ok, fmt.Sprintf("suites.Lookup(0x%04x)", suiteID))

	// ServerHello body with an (un-offered) empty server_name extension.
	shBody := serverHelloBytesWithExt(suiteID, extServerName, nil)
	rec := hsRecord(buildEnvelope(TypeServerHello, shBody))

	c := makeClientStateForFlight(t, rec, suite)

	c.params.OfferedSuites = []uint16{suiteID}
	c.params.ServerName = "" // no SNI offered -> server_name echo is un-offered.

	err := c.recvServerHello()
	testutil.ErrIs(t, err, errSHUnofferedExt, "recvServerHello with un-offered extension")
}

// TestReadHandshakeRecord_RejectsInterleavedAlert covers M1's interleaving guard:
// a non-handshake record arriving while a handshake message is only partially
// buffered is a protocol violation (RFC 5246 §6.2.1).
func TestReadHandshakeRecord_RejectsInterleavedAlert(t *testing.T) {
	t.Parallel()

	// A Certificate message declaring a 6-byte body but carrying only 2.
	partial := hsRecord([]byte{0x0B, 0x00, 0x00, 0x06, 0xAA, 0xBB})
	// An alert record arriving before the message completes.
	alertRec := []byte{record.ContentTypeAlert, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28}

	stream := slices.Concat(partial, alertRec)

	rw := &readWriteBuffer{r: bytes.NewBuffer(stream), w: new(bytes.Buffer)}
	c := &ClientState{layer: record.NewLayer(rw), transcript: NewTranscript()}

	_, _, err := c.readHandshakeRecord()
	testutil.ErrIs(t, err, errInterleavedHandshake, "readHandshakeRecord with interleaved alert")
}

// TestParseAndVerifyChain_UsesWireIntermediates covers L4: the intermediate
// certificate the server sends after the leaf must be used to bridge the leaf to
// a trusted root. Verification succeeds with the intermediate present and fails
// when only the leaf is supplied.
func TestParseAndVerifyChain_UsesWireIntermediates(t *testing.T) {
	t.Parallel()

	rootDER, interDER, leafDER, rootCert := genECDSAChain(t)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	c := &ClientState{
		params:     ClientParams{RootCAs: rootPool, ServerName: "leaf.example.com"},
		transcript: NewTranscript(),
	}

	// Leaf + intermediate on the wire: the chain bridges to the root.
	_, chains, err := parseAndVerifyChain(c, [][]byte{leafDER, interDER})
	testutil.NoErr(t, err, "verify with wire intermediate")

	if len(chains) == 0 {
		t.Error("expected a non-empty verified chain")
	}

	// Leaf alone: no path to the root, so verification must fail.
	_, _, err = parseAndVerifyChain(c, [][]byte{leafDER})
	testutil.WantErr(t, err, "verify without intermediate")

	_ = rootDER
}

// serverHelloBytesWithExt builds a ServerHello body carrying a single extension.
func serverHelloBytesWithExt(suiteID, extType uint16, extBody []byte) []byte {
	var b []byte

	b = appendUint16(b, tlsVersion12)
	b = append(b, make([]byte, tlsRandomLen)...)
	b = append(b, 0x00) // session_id length = 0.
	b = appendUint16(b, suiteID)
	b = append(b, 0x00) // compression = null.

	var ext []byte

	ext = appendUint16(ext, extType)
	ext = testutil.AppendU16Prefixed(ext, extBody)

	b = testutil.AppendU16Prefixed(b, ext)

	return b
}

// genECDSAChain creates a root CA, an intermediate CA signed by the root, and a
// leaf signed by the intermediate (SAN leaf.example.com, server-auth EKU). It
// returns the DER for root, intermediate and leaf plus the parsed root.
func genECDSAChain(t *testing.T) (rootDER, interDER, leafDER []byte, rootCert *x509.Certificate) {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	testutil.NoErr(t, err, "root key")

	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	testutil.NoErr(t, err, "intermediate key")

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	testutil.NoErr(t, err, "leaf key")

	now := time.Now()

	caTmpl := func(serial int64, cn string) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(time.Hour),
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
	}

	rootTmpl := caTmpl(1, "root")

	rootDER, err = x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	testutil.NoErr(t, err, "create root")

	rootCert, err = x509.ParseCertificate(rootDER)
	testutil.NoErr(t, err, "parse root")

	interTmpl := caTmpl(2, "intermediate")

	interDER, err = x509.CreateCertificate(rand.Reader, interTmpl, rootCert, &interKey.PublicKey, rootKey)
	testutil.NoErr(t, err, "create intermediate")

	interCert, err := x509.ParseCertificate(interDER)
	testutil.NoErr(t, err, "parse intermediate")

	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"leaf.example.com"},
	}

	leafDER, err = x509.CreateCertificate(rand.Reader, leafTmpl, interCert, &leafKey.PublicKey, interKey)
	testutil.NoErr(t, err, "create leaf")

	return rootDER, interDER, leafDER, rootCert
}
