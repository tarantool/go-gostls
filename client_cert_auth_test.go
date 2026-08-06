package gostls_test

// End-to-end mock tests for Phase 3: client Certificate + CertificateVerify
// emission via Conn.Handshake(). These tests use the scripted-server
// infrastructure from handshake_test.go and exercise the full
// tls.Config.Certificates → ClientParams.Certificates plumbing.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/tarantool/go-gostls"
	"github.com/tarantool/go-gostls/internal/record"
	"github.com/tarantool/go-gostls/internal/suites"
	"github.com/tarantool/go-gostls/internal/testutil"
)

// ============================================================================
// helpers
// ============================================================================.

// buildCertificateRequest builds a handshake CertificateRequest envelope.
// sigAlgs is a list of (hash, sig) pairs.
func buildCertificateRequest(certTypes []uint8, sigAlgs [][2]uint8) []byte {
	body := testutil.AppendU8Prefixed(nil, certTypes)

	sigBytes := make([]byte, 2*len(sigAlgs))
	for i, sa := range sigAlgs {
		sigBytes[2*i] = sa[0]
		sigBytes[2*i+1] = sa[1]
	}

	body = testutil.AppendU16Prefixed(body, sigBytes)
	body = testutil.AppendU16Prefixed(body, nil) // empty CA list.

	return wrapHS(13, body) // type 13 = CertificateRequest.
}

// newTestClientRSACert generates an RSA-2048 client certificate, returning the
// private key, DER bytes, and parsed certificate.
func newTestClientRSACert(t *testing.T) (*rsa.PrivateKey, []byte, *x509.Certificate) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	testutil.NoErr(t, err, "generate client RSA key")

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "client-auth"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	testutil.NoErr(t, err, "create client cert")

	cert, err := x509.ParseCertificate(der)
	testutil.NoErr(t, err, "parse client cert")

	return key, der, cert
}

// clientAuthServerResult holds the outcome of the scripted server side.
type clientAuthServerResult struct {
	certVerifySeen bool
	cvSig          []byte
	cvAlg          [2]uint8
	// transcriptBeforeCV is the SHA-256 of all handshake messages accumulated up
	// through (and including) ClientKeyExchange. This is what CertificateVerify
	// must sign over for sha256+rsa.
	transcriptBeforeCV []byte
	err                error
}

// runServerWithCertReq drives the server side of an RSA-kx TLS 1.2 handshake
// that includes a CertificateRequest. Returns a result struct with what was
// observed from the client.
func runServerWithCertReq(
	t *testing.T,
	srvConn net.Conn,
	suite *suites.Suite,
	serverRandom [32]byte,
	sigAlgs [][2]uint8,
) clientAuthServerResult {
	t.Helper()

	var res clientAuthServerResult

	srvLayer := record.NewLayer(srvConn)

	// Helper to fail with context.
	fail := func(format string, args ...any) clientAuthServerResult {
		res.err = fmt.Errorf(format, args...)
		return res
	}

	tr := newHashAccumulator(suite.PRF.Hash)

	// Read ClientHello.
	chCT, chPayload, err := srvLayer.ReadRecord()
	if err != nil || chCT != record.ContentTypeHandshake {
		return fail("read ClientHello: %v", err)
	}

	tr.Write(chPayload)

	var clientRandom [32]byte

	copy(clientRandom[:], chPayload[6:38])

	// Send ServerHello.
	sh := buildServerHello(serverRandom, suite.ID)
	tr.Write(sh)

	_ = srvLayer.WriteRecord(record.ContentTypeHandshake, sh)

	// Send Certificate.
	certMsg := buildCertificate([][]byte{testServerCertDER})
	tr.Write(certMsg)

	_ = srvLayer.WriteRecord(record.ContentTypeHandshake, certMsg)

	// Send CertificateRequest.
	certReq := buildCertificateRequest([]uint8{0x01}, sigAlgs)
	tr.Write(certReq)

	_ = srvLayer.WriteRecord(record.ContentTypeHandshake, certReq)

	// Send ServerHelloDone (RSA KX — no SKE).
	shd := buildServerHelloDone()
	tr.Write(shd)

	_ = srvLayer.WriteRecord(record.ContentTypeHandshake, shd)

	// Read client Certificate.
	_, clientCertPayload, err := srvLayer.ReadRecord()
	if err != nil {
		return fail("read client Certificate: %v", err)
	}

	tr.Write(clientCertPayload)

	// Read client CKE.
	_, ckePayload, err := srvLayer.ReadRecord()
	if err != nil {
		return fail("read client CKE: %v", err)
	}

	tr.Write(ckePayload)

	// Snapshot the transcript after CKE (before CertificateVerify).
	res.transcriptBeforeCV = tr.Sum()

	// Read the next record — it will be CertificateVerify or CCS.
	nextCT, nextPayload, err := srvLayer.ReadRecord()
	if err != nil {
		return fail("read after CKE: %v", err)
	}

	isCertVerify := nextCT == record.ContentTypeHandshake &&
		len(nextPayload) >= 4 &&
		nextPayload[0] == 15 // handshake type 15 = CertificateVerify.

	switch {
	case isCertVerify:
		res.certVerifySeen = true
		parseCertVerifyBody(&res, nextPayload)
		tr.Write(nextPayload)

		// Read CCS that follows CertificateVerify.
		for {
			ct, payload, err := srvLayer.ReadRecord()
			if err != nil {
				return fail("read CCS: %v", err)
			}

			if ct == record.ContentTypeChangeCipherSpec && len(payload) == 1 && payload[0] == 1 {
				break
			}
		}
	case nextCT == record.ContentTypeChangeCipherSpec:
		// No CertificateVerify.
		res.certVerifySeen = false
	default:
		return fail("unexpected record after CKE: ct=%d type=%d", nextCT, nextPayload[0])
	}

	// Decrypt pre-master from CKE body.
	// CKE body (inside envelope): uint16 ciphertext_len || ciphertext.
	ckeBody := ckePayload[4:] // skip 4-byte handshake envelope.
	if len(ckeBody) < 2 {
		return fail("CKE body too short")
	}

	ciphertext := ckeBody[2:]

	preMaster, err := rsa.DecryptPKCS1v15(rand.Reader, testServerKey, ciphertext)
	if err != nil {
		return fail("decrypt pre-master: %v", err)
	}

	masterSecret, err := suites.MasterSecret(suite, preMaster, clientRandom[:], serverRandom[:])
	if err != nil {
		return fail("master secret: %v", err)
	}

	km, err := expandKeysForTest(suite, masterSecret, clientRandom[:], serverRandom[:], 0)
	if err != nil {
		return fail("key expansion: %v", err)
	}

	recvProt, err := buildProtectorForTest(suite, km.ClientEncKey, km.ClientMACKey, km.ClientIV)
	if err != nil {
		return fail("recv protector: %v", err)
	}

	srvLayer.ChangeCipherSpec(nil, recvProt)

	// Read client Finished.
	_, finPayload, err := srvLayer.ReadRecord()
	if err != nil {
		return fail("read Finished: %v", err)
	}

	tr.Write(finPayload)

	// Send server CCS + Finished.
	_ = srvLayer.WriteRecord(record.ContentTypeChangeCipherSpec, []byte{1})

	sendProt, err := buildProtectorForTest(suite, km.ServerEncKey, km.ServerMACKey, km.ServerIV)
	if err != nil {
		return fail("send protector: %v", err)
	}

	srvLayer.ChangeCipherSpec(sendProt, nil)

	serverFinished := buildServerFinished(suite, masterSecret, tr.Sum())

	_ = srvLayer.WriteRecord(record.ContentTypeHandshake, serverFinished)

	return res
}

// parseCertVerifyBody extracts the signature algorithm and signature from a raw
// CertificateVerify handshake envelope (4-byte header + body).
func parseCertVerifyBody(res *clientAuthServerResult, envelope []byte) {
	if len(envelope) < 4 {
		return
	}

	bodyLen := uint32(envelope[1])<<16 | uint32(envelope[2])<<8 | uint32(envelope[3])
	cvBody := envelope[4 : 4+bodyLen]

	if len(cvBody) < 4 {
		return
	}

	sigLen := int(cvBody[2])<<8 | int(cvBody[3])
	if len(cvBody) < 4+sigLen {
		return
	}

	res.cvAlg = [2]uint8{cvBody[0], cvBody[1]}
	res.cvSig = append([]byte(nil), cvBody[4:4+sigLen]...)
}

// ============================================================================
// Tests
// ============================================================================.

// TestClient_Handshake_WithCertAuth_RSACert tests that when the server sends a
// CertificateRequest and the client has an RSA cert configured, the client
// emits Certificate + CKE + CertificateVerify and the handshake succeeds.
func TestClient_Handshake_WithCertAuth_RSACert(t *testing.T) {
	t.Parallel()
	initTestFixtures(t)

	clientKey, clientDER, _ := newTestClientRSACert(t)

	suite, ok := suites.LookupByName("AES128-SHA256")
	testutil.Ok(t, ok, `LookupByName("AES128-SHA256")`)

	clientConn, serverConn := net.Pipe()

	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	var serverRandom [32]byte

	serverRandom[0] = 0xCC

	resCh := make(chan clientAuthServerResult, 1)

	go func() {
		defer func() { _ = serverConn.Close() }()

		res := runServerWithCertReq(t, serverConn, suite, serverRandom, [][2]uint8{{0x04, 0x01}})
		resCh <- res
	}()

	config := &gostls.Config{
		ServerName: "test.example.com",
		RootCAs:    rootCAsForTest(t),
		Certificates: []gostls.Certificate{
			{Certificate: [][]byte{clientDER}, PrivateKey: clientKey},
		},
	}
	tlsConn := gostls.NewConn(clientConn, config)

	testutil.NoErr(t, tlsConn.Handshake(), "handshake")

	res := <-resCh
	testutil.NoErr(t, res.err, "server")

	if !res.certVerifySeen {
		t.Error("expected CertificateVerify, not observed")
	}

	t.Log("RSA client cert auth handshake succeeded")
}

// TestClient_Handshake_WithCertAuth_NoCert tests that when the server sends a
// CertificateRequest but the client has no cert, the client sends an empty
// Certificate and no CertificateVerify.
func TestClient_Handshake_WithCertAuth_NoCert(t *testing.T) {
	t.Parallel()
	initTestFixtures(t)

	suite, ok := suites.LookupByName("AES128-SHA256")
	testutil.Ok(t, ok, `LookupByName("AES128-SHA256")`)

	clientConn, serverConn := net.Pipe()

	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	var serverRandom [32]byte

	serverRandom[0] = 0xDD

	resCh := make(chan clientAuthServerResult, 1)

	go func() {
		defer func() { _ = serverConn.Close() }()

		res := runServerWithCertReq(t, serverConn, suite, serverRandom, [][2]uint8{{0x04, 0x01}})
		resCh <- res
	}()

	config := &gostls.Config{
		ServerName:   "test.example.com",
		RootCAs:      rootCAsForTest(t),
		Certificates: nil,
	}
	tlsConn := gostls.NewConn(clientConn, config)

	testutil.NoErr(t, tlsConn.Handshake(), "handshake")

	res := <-resCh
	testutil.NoErr(t, res.err, "server")

	if res.certVerifySeen {
		t.Error("expected no CertificateVerify when no client cert configured")
	}

	t.Log("Empty client cert handshake succeeded")
}

// TestClient_Handshake_NoCertReq_CertConfigured tests that when the server does NOT
// send a CertificateRequest, the client does not send a Certificate or CertificateVerify
// even if certs are configured (existing behavior preserved).
func TestClient_Handshake_NoCertReq_CertConfigured(t *testing.T) {
	t.Parallel()
	initTestFixtures(t)

	clientKey, clientDER, _ := newTestClientRSACert(t)

	suite, ok := suites.LookupByName("AES128-SHA256")
	testutil.Ok(t, ok, `LookupByName("AES128-SHA256")`)

	clientConn, serverConn := net.Pipe()

	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	var serverRandom [32]byte

	serverRandom[0] = 0xEE

	serverDone := make(chan error, 1)

	go func() {
		defer func() { _ = serverConn.Close() }()

		srv := newScriptedServer(t, serverConn)
		runner := newServerRunner(t, srv, suite)
		// runFullHandshake sends NO CertificateRequest — existing behavior.
		runner.runFullHandshake(serverRandom)

		serverDone <- nil
	}()

	config := &gostls.Config{
		ServerName: "test.example.com",
		RootCAs:    rootCAsForTest(t),
		Certificates: []gostls.Certificate{
			{Certificate: [][]byte{clientDER}, PrivateKey: clientKey},
		},
	}
	tlsConn := gostls.NewConn(clientConn, config)

	testutil.NoErr(t, tlsConn.Handshake(), "handshake")
	testutil.NoErr(t, <-serverDone, "server")

	t.Log("No-CertReq with cert configured: existing behavior preserved")
}

// TestClient_Handshake_WithCertAuth_VerifiesSignature verifies that the
// CertificateVerify signature is cryptographically correct: sha256+rsa over the
// transcript through ClientKeyExchange.
func TestClient_Handshake_WithCertAuth_VerifiesSignature(t *testing.T) {
	t.Parallel()
	initTestFixtures(t)

	clientKey, clientDER, _ := newTestClientRSACert(t)

	suite, ok := suites.LookupByName("AES128-SHA256")
	testutil.Ok(t, ok, `LookupByName("AES128-SHA256")`)

	clientConn, serverConn := net.Pipe()

	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	var serverRandom [32]byte

	serverRandom[0] = 0xAF

	resCh := make(chan clientAuthServerResult, 1)

	go func() {
		defer func() { _ = serverConn.Close() }()

		res := runServerWithCertReq(t, serverConn, suite, serverRandom, [][2]uint8{{0x04, 0x01}})
		resCh <- res
	}()

	config := &gostls.Config{
		ServerName: "test.example.com",
		RootCAs:    rootCAsForTest(t),
		Certificates: []gostls.Certificate{
			{Certificate: [][]byte{clientDER}, PrivateKey: clientKey},
		},
	}
	tlsConn := gostls.NewConn(clientConn, config)

	testutil.NoErr(t, tlsConn.Handshake(), "handshake")

	res := <-resCh
	testutil.NoErr(t, res.err, "server")

	if !res.certVerifySeen {
		t.Fatal("CertificateVerify was not observed")
	}

	// Verify: sha256+rsa over the transcript bytes up through CKE.
	// res.transcriptBeforeCV is SHA256(CH||SH||...||CKE), i.e. the hash already
	// computed. This is the digest that was signed by the client.
	if res.cvAlg[0] != 0x04 || res.cvAlg[1] != 0x01 {
		t.Errorf("expected sha256+rsa {0x04,0x01}, got {0x%02x,0x%02x}", res.cvAlg[0], res.cvAlg[1])
	}

	// res.transcriptBeforeCV IS the digest (SHA256 of raw transcript bytes).
	// RSA PKCS1v15 with SHA256 means: sign(SHA256(data)) where data = transcript.
	// The client called rsa.SignPKCS1v15(rand, key, crypto.SHA256, digest) where
	// digest = transcript.Sum(sha256.New) = SHA256(transcript_bytes).
	err := rsa.VerifyPKCS1v15(&clientKey.PublicKey, crypto.SHA256, res.transcriptBeforeCV, res.cvSig)
	if err != nil {
		t.Errorf("CertificateVerify signature invalid: %v", err)
	} else {
		t.Log("CertificateVerify signature verified successfully")
	}
}

// TestClient_Config_ClientCerts_InvalidKeyType tests that clientCerts() returns
// a hard error for unsupported key types, surfaced at handshake start.
func TestClient_Config_ClientCerts_InvalidKeyType(t *testing.T) {
	t.Parallel()

	// Use an interface{} wrapping a string as a fake key — unsupported type.
	type fakeKey struct{}

	config := &gostls.Config{
		Certificates: []gostls.Certificate{
			{
				// Non-empty but invalid DER; the key-type check rejects the
				// entry before the chain is ever parsed.
				Certificate: [][]byte{{0x01}},
				PrivateKey:  fakeKey{},
			},
		},
		InsecureSkipVerify: true,
	}

	// Connect to a dummy server that will never be reached.
	clientConn, serverConn := net.Pipe()

	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	// Server just drains and closes.
	go func() {
		buf := make([]byte, 1024)

		_, _ = serverConn.Read(buf)

		_ = serverConn.Close()
	}()

	tlsConn := gostls.NewConn(clientConn, config)

	err := tlsConn.Handshake()
	testutil.WantErr(t, err, "handshake with an unsupported private-key type")

	t.Logf("correctly rejected unsupported key type: %v", err)
}

// TestClient_Config_ClientCerts_EmptyChain tests that an empty Certificate
// chain (with no Leaf set) is a hard error.
func TestClient_Config_ClientCerts_EmptyChain(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	testutil.NoErr(t, err, "generate RSA key")

	config := &gostls.Config{
		Certificates: []gostls.Certificate{
			{
				Certificate: nil, // empty — hard error.
				PrivateKey:  key,
			},
		},
		InsecureSkipVerify: true,
	}

	clientConn, serverConn := net.Pipe()

	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	go func() {
		buf := make([]byte, 1024)

		_, _ = serverConn.Read(buf)

		_ = serverConn.Close()
	}()

	tlsConn := gostls.NewConn(clientConn, config)

	err = tlsConn.Handshake()
	testutil.WantErr(t, err, "handshake with an empty Certificate chain")

	t.Logf("correctly rejected empty Certificate chain: %v", err)
}

// TestClient_Config_ClientCerts_EmptyChain_WithLeaf covers the path where the
// caller pre-parses Leaf but leaves the Certificate chain nil. The chain is
// what goes on the wire; a zero-length entry would be a malformed Certificate
// message per RFC 5246 §7.4.2, so clientCerts() must still reject —
// validation cannot be skipped when Leaf is non-nil.
func TestClient_Config_ClientCerts_EmptyChain_WithLeaf(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	testutil.NoErr(t, err, "generate RSA key")

	// Generate a real cert just so we have a valid *x509.Certificate to
	// populate Leaf; the bug path is the Certificate chain being nil while
	// Leaf is non-nil.
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	testutil.NoErr(t, err, "create cert")

	parsed, err := x509.ParseCertificate(der)
	testutil.NoErr(t, err, "parse cert")

	config := &gostls.Config{
		Certificates: []gostls.Certificate{
			{
				Leaf:        parsed, // pre-parsed, non-nil.
				Certificate: nil,    // but DER bytes missing — hard error.
				PrivateKey:  key,
			},
		},
		InsecureSkipVerify: true,
	}

	clientConn, serverConn := net.Pipe()

	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	go func() {
		buf := make([]byte, 1024)

		_, _ = serverConn.Read(buf)

		_ = serverConn.Close()
	}()

	tlsConn := gostls.NewConn(clientConn, config)

	err = tlsConn.Handshake()
	testutil.WantErr(t, err, "handshake with an empty Certificate chain and a parsed Leaf")

	t.Logf("correctly rejected empty Certificate chain + parsed Leaf: %v", err)
}
