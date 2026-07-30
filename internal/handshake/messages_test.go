package handshake_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/tarantool/go-gostls/internal/handshake"
	"github.com/tarantool/go-gostls/internal/testutil"
)

// --- ClientHello ---.

func TestMessage_ClientHello_RoundTrip(t *testing.T) {
	t.Parallel()

	// Build a ClientHello struct.
	random := [32]byte{}
	for i := range random {
		random[i] = byte(i)
	}

	sessionID := []byte{0xAA, 0xBB, 0xCC}

	hello := &handshake.ClientHello{
		Version:            0x0303,
		Random:             random,
		SessionID:          sessionID,
		CipherSuites:       []uint16{0x002F, 0xC02C},
		CompressionMethods: []uint8{0x00},
		ServerName:         "example.com",
		SupportedGroups:    []uint16{0x0017, 0x0018},
		ECPointFormats:     []uint8{0x00},
		SignatureAlgorithms: []handshake.SigAndHash{
			{Hash: 0x04, Sig: 0x01},
			{Hash: 0x05, Sig: 0x01},
		},
	}

	// Marshal the body, wrap in message envelope.
	body, bodyMErr := hello.Marshal()
	testutil.NoErr(t, bodyMErr, "hello.Marshal")

	msg, msgMErr := handshake.MarshalMessage(hello)
	testutil.NoErr(t, msgMErr, "handshake.MarshalMessage")

	// Sanity check: envelope prefix is msg_type + 3-byte length.
	if msg[0] != byte(handshake.TypeClientHello) {
		t.Fatalf("expected TypeClientHello byte %02x, got %02x", handshake.TypeClientHello, msg[0])
	}

	bodyLen := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
	if bodyLen != len(body) {
		t.Fatalf("envelope length %d != body length %d", bodyLen, len(body))
	}

	// ParseMessage from the full wire bytes.
	parsed, remaining, err := handshake.ParseMessage(msg)
	testutil.NoErr(t, err, "ParseMessage")

	testutil.Len(t, remaining, 0, "remaining")

	got, ok := parsed.(*handshake.ClientHello)
	testutil.Ok(t, ok, fmt.Sprintf("ParseMessage: got %T, want *ClientHello", parsed))

	if got.Version != hello.Version {
		t.Errorf("Version: got %04x, want %04x", got.Version, hello.Version)
	}

	if got.Random != hello.Random {
		t.Errorf("Random mismatch")
	}

	if !bytes.Equal(got.SessionID, hello.SessionID) {
		t.Errorf("SessionID: got %v, want %v", got.SessionID, hello.SessionID)
	}

	if len(got.CipherSuites) != len(hello.CipherSuites) {
		t.Errorf("CipherSuites len: got %d, want %d", len(got.CipherSuites), len(hello.CipherSuites))
	} else {
		for i, cs := range hello.CipherSuites {
			if got.CipherSuites[i] != cs {
				t.Errorf("CipherSuites[%d]: got %04x, want %04x", i, got.CipherSuites[i], cs)
			}
		}
	}

	if got.ServerName != hello.ServerName {
		t.Errorf("ServerName: got %q, want %q", got.ServerName, hello.ServerName)
	}

	if len(got.SupportedGroups) != len(hello.SupportedGroups) {
		t.Errorf("SupportedGroups len mismatch")
	}

	if len(got.SignatureAlgorithms) != len(hello.SignatureAlgorithms) {
		t.Errorf("SignatureAlgorithms len mismatch")
	}
}

// --- ServerHello ---.

func TestMessage_ServerHello_RoundTrip(t *testing.T) {
	t.Parallel()

	random := [32]byte{}
	for i := range random {
		random[i] = byte(i + 32)
	}

	hello := &handshake.ServerHello{
		Version:           0x0303,
		Random:            random,
		SessionID:         []byte{0x01, 0x02},
		CipherSuite:       0xC02C,
		CompressionMethod: 0x00,
		RenegotiationInfo: true,
	}

	msg, msgMErr := handshake.MarshalMessage(hello)
	testutil.NoErr(t, msgMErr, "handshake.MarshalMessage")

	parsed, remaining, err := handshake.ParseMessage(msg)
	testutil.NoErr(t, err, "ParseMessage")

	testutil.Len(t, remaining, 0, "remaining")

	got, ok := parsed.(*handshake.ServerHello)
	testutil.Ok(t, ok, fmt.Sprintf("ParseMessage: got %T, want *ServerHello", parsed))

	if got.Version != hello.Version {
		t.Errorf("Version: got %04x, want %04x", got.Version, hello.Version)
	}

	if got.Random != hello.Random {
		t.Errorf("Random mismatch")
	}

	if got.CipherSuite != hello.CipherSuite {
		t.Errorf("CipherSuite: got %04x, want %04x", got.CipherSuite, hello.CipherSuite)
	}

	if got.CompressionMethod != hello.CompressionMethod {
		t.Errorf("CompressionMethod: got %02x, want %02x", got.CompressionMethod, hello.CompressionMethod)
	}

	if got.RenegotiationInfo != hello.RenegotiationInfo {
		t.Errorf("RenegotiationInfo: got %v, want %v", got.RenegotiationInfo, hello.RenegotiationInfo)
	}
}

// --- Certificate ---.

func TestMessage_Certificate_RoundTrip(t *testing.T) {
	t.Parallel()

	// Use two fake DER-encoded certs (just raw bytes for wire format test).
	cert1 := []byte{0x30, 0x82, 0x01, 0x00, 0xAA, 0xBB} // fake DER.
	cert2 := []byte{0x30, 0x82, 0x02, 0x00, 0xCC, 0xDD, 0xEE}

	certMsg := &handshake.Certificate{
		Certificates: []*x509.Certificate(nil),
		RawCerts:     [][]byte{cert1, cert2},
	}

	msg, msgMErr := handshake.MarshalMessage(certMsg)
	testutil.NoErr(t, msgMErr, "handshake.MarshalMessage")

	parsed, remaining, err := handshake.ParseMessage(msg)
	testutil.NoErr(t, err, "ParseMessage")

	testutil.Len(t, remaining, 0, "remaining")

	got, ok := parsed.(*handshake.Certificate)
	testutil.Ok(t, ok, fmt.Sprintf("ParseMessage: got %T, want *Certificate", parsed))

	testutil.Len(t, got.RawCerts, 2, "got.RawCerts")

	if !bytes.Equal(got.RawCerts[0], cert1) {
		t.Errorf("RawCerts[0] mismatch")
	}

	testutil.EqualBytes(t, got.RawCerts[1], cert2, "got.RawCerts[1]")
}

// --- ServerKeyExchange ---.

func TestMessage_ServerKeyExchange_RoundTrip(t *testing.T) {
	t.Parallel()

	params := []byte{0x03, 0x00, 0x17, 0x41, 0x04, 0xDE, 0xAD, 0xBE, 0xEF}

	ske := &handshake.ServerKeyExchange{
		Body: params,
	}

	msg, msgMErr := handshake.MarshalMessage(ske)
	testutil.NoErr(t, msgMErr, "handshake.MarshalMessage")

	parsed, remaining, err := handshake.ParseMessage(msg)
	testutil.NoErr(t, err, "ParseMessage")

	testutil.Len(t, remaining, 0, "remaining")

	got, ok := parsed.(*handshake.ServerKeyExchange)
	testutil.Ok(t, ok, fmt.Sprintf("ParseMessage: got %T, want *ServerKeyExchange", parsed))

	testutil.EqualBytes(t, got.Body, params, "got.Body")
}

// --- ServerHelloDone ---.

func TestMessage_ServerHelloDone_RoundTrip(t *testing.T) {
	t.Parallel()

	done := &handshake.ServerHelloDone{}

	msg, msgMErr := handshake.MarshalMessage(done)
	testutil.NoErr(t, msgMErr, "handshake.MarshalMessage")

	testutil.Len(t, msg, 4, "msg")

	parsed, remaining, err := handshake.ParseMessage(msg)
	testutil.NoErr(t, err, "ParseMessage")

	testutil.Len(t, remaining, 0, "remaining")

	_, ok := parsed.(*handshake.ServerHelloDone)
	testutil.Ok(t, ok, fmt.Sprintf("ParseMessage: got %T, want *ServerHelloDone", parsed))
}

// --- ClientKeyExchange ---.

func TestMessage_ClientKeyExchange_RoundTrip(t *testing.T) {
	t.Parallel()

	body := []byte{0x41, 0x04, 0xCA, 0xFE, 0xBA, 0xBE}

	cke := &handshake.ClientKeyExchange{
		Body: body,
	}

	msg, msgMErr := handshake.MarshalMessage(cke)
	testutil.NoErr(t, msgMErr, "handshake.MarshalMessage")

	parsed, remaining, err := handshake.ParseMessage(msg)
	testutil.NoErr(t, err, "ParseMessage")

	testutil.Len(t, remaining, 0, "remaining")

	got, ok := parsed.(*handshake.ClientKeyExchange)
	testutil.Ok(t, ok, fmt.Sprintf("ParseMessage: got %T, want *ClientKeyExchange", parsed))

	testutil.EqualBytes(t, got.Body, body, "got.Body")
}

// --- CertificateVerify ---.

func TestMessage_CertificateVerify_RoundTrip(t *testing.T) {
	t.Parallel()

	sig := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04}

	cv := &handshake.CertificateVerify{
		Algorithm: handshake.SigAndHash{Hash: 0x04, Sig: 0x01},
		Signature: sig,
	}

	msg, msgMErr := handshake.MarshalMessage(cv)
	testutil.NoErr(t, msgMErr, "handshake.MarshalMessage")

	parsed, remaining, err := handshake.ParseMessage(msg)
	testutil.NoErr(t, err, "ParseMessage")

	testutil.Len(t, remaining, 0, "remaining")

	got, ok := parsed.(*handshake.CertificateVerify)
	testutil.Ok(t, ok, fmt.Sprintf("ParseMessage: got %T, want *CertificateVerify", parsed))

	if got.Algorithm != cv.Algorithm {
		t.Errorf("Algorithm: got %v, want %v", got.Algorithm, cv.Algorithm)
	}

	testutil.EqualBytes(t, got.Signature, cv.Signature, "got.Signature")
}

// --- Finished ---.

func TestMessage_Finished_RoundTrip(t *testing.T) {
	t.Parallel()

	// verify_data is 12 bytes for standard TLS 1.2 / 32 bytes for GOST 2018.
	for _, vdLen := range []int{12, 32} {
		vd := make([]byte, vdLen)
		for i := range vd {
			vd[i] = byte(i + 1)
		}

		fin := &handshake.Finished{VerifyData: vd}

		msg, msgMErr := handshake.MarshalMessage(fin)
		testutil.NoErr(t, msgMErr, "handshake.MarshalMessage")

		parsed, remaining, err := handshake.ParseMessage(msg)
		testutil.NoErr(t, err, fmt.Sprintf("ParseMessage(len=%d)", vdLen))

		testutil.Len(t, remaining, 0, "remaining")

		got, ok := parsed.(*handshake.Finished)
		testutil.Ok(t, ok, fmt.Sprintf("ParseMessage(len=%d): got %T, want *Finished", vdLen, parsed))

		if !bytes.Equal(got.VerifyData, fin.VerifyData) {
			t.Errorf("len=%d VerifyData mismatch: got %x, want %x", vdLen, got.VerifyData, fin.VerifyData)
		}
	}
}

// --- Unknown extension rejection ---.

func TestMessage_ClientHello_RejectsUnknownExtension(t *testing.T) {
	t.Parallel()

	// Build a valid ClientHello wire body with an unknown extension type 0xFFFF.
	random := [32]byte{}
	hello := &handshake.ClientHello{
		Version:            0x0303,
		Random:             random,
		CipherSuites:       []uint16{0x002F},
		CompressionMethods: []uint8{0x00},
	}

	body, bodyMErr := hello.Marshal()
	testutil.NoErr(t, bodyMErr, "hello.Marshal")

	// Append an extension list with unknown type 0xFFFF.
	// Extensions list: uint16 total_len, then each: uint16 type, uint16 len, body.
	extBody := []byte{0xFF, 0xFF, 0x00, 0x02, 0xAA, 0xBB} // type=0xFFFF, len=2, body=AABB.
	extList := make([]byte, 2+len(extBody))

	extList[0] = 0x00
	extList[1] = byte(len(extBody))
	copy(extList[2:], extBody)

	wire := slices.Concat(body, extList)

	msg, marshalErr := handshake.MarshalMessage(&handshake.RawMessage{
		MsgType: handshake.TypeClientHello,
		Body:    wire,
	})
	testutil.NoErr(t, marshalErr, "MarshalMessage")

	_, _, err := handshake.ParseMessage(msg)
	testutil.WantErr(t, err, "handshake.ParseMessage")

	if !strings.Contains(err.Error(), "unknown extension") {
		t.Errorf("error should mention 'unknown extension', got: %v", err)
	}
}

// --- Truncated length rejection ---.

func TestMessage_Rejects_TruncatedLength(t *testing.T) {
	t.Parallel()

	// For each message type that has a non-trivial body, feed a buffer
	// that claims more bytes than actually present.
	tests := []struct {
		name string
		// wire is the full MarshalMessage output, then we truncate.
		build func() []byte
	}{
		{
			name: "ClientHello",
			build: func() []byte {
				random := [32]byte{}
				h := &handshake.ClientHello{
					Version:            0x0303,
					Random:             random,
					CipherSuites:       []uint16{0x002F},
					CompressionMethods: []uint8{0x00},
				}

				return mustMarshalMessage(h)
			},
		},
		{
			name: "ServerHello",
			build: func() []byte {
				random := [32]byte{}
				h := &handshake.ServerHello{
					Version:     0x0303,
					Random:      random,
					CipherSuite: 0x002F,
				}

				return mustMarshalMessage(h)
			},
		},
		{
			name: "Certificate",
			build: func() []byte {
				c := &handshake.Certificate{
					RawCerts: [][]byte{{0x30, 0x01, 0xAA}},
				}

				return mustMarshalMessage(c)
			},
		},
		{
			name: "CertificateVerify",
			build: func() []byte {
				cv := &handshake.CertificateVerify{
					Algorithm: handshake.SigAndHash{Hash: 0x04, Sig: 0x01},
					Signature: []byte{0xAA, 0xBB},
				}

				return mustMarshalMessage(cv)
			},
		},
		{
			name: "Finished",
			build: func() []byte {
				fin := &handshake.Finished{}
				return mustMarshalMessage(fin)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			wire := tc.build()
			// Truncate: remove last byte but keep the length field intact.
			truncated := wire[:len(wire)-1]

			_, _, err := handshake.ParseMessage(truncated)
			testutil.WantErr(t, err, fmt.Sprintf("ParseMessage(truncated %s)", tc.name))
		})
	}
}

// --- Transcript tests ---.

func TestTranscript_MultiHash_Before_Collapse(t *testing.T) {
	t.Parallel()

	tr := handshake.NewTranscript()

	msg1 := []byte("handshake message 1")
	msg2 := []byte("second message bytes")
	msg3 := []byte("third message content")

	tr.Write(msg1)
	tr.Write(msg2)
	tr.Write(msg3)

	// Concatenation of all messages.
	all := append(append(append([]byte{}, msg1...), msg2...), msg3...)

	// SHA-256 of the concatenation.
	h256 := sha256.New()
	h256.Write(all)

	wantSHA256 := h256.Sum(nil)

	// SHA-384 of the concatenation.
	h384 := sha512.New384()
	h384.Write(all)

	wantSHA384 := h384.Sum(nil)

	got256, err := tr.Sum(sha256.New)
	testutil.NoErr(t, err, "Sum(sha256)")

	if !bytes.Equal(got256, wantSHA256) {
		t.Errorf("SHA-256 mismatch:\n  got  %x\n  want %x", got256, wantSHA256)
	}

	got384, err := tr.Sum(sha512.New384)
	testutil.NoErr(t, err, "Sum(sha384)")

	testutil.EqualBytes(t, got384, wantSHA384, "got384")
}

// --- Renegotiation info ---.

func TestExtensions_RenegotiationInfo_EmptyOnly(t *testing.T) {
	t.Parallel()

	// Build a ServerHello with renegotiation_info extension.
	// Empty body → OK.
	random := [32]byte{}
	hello := &handshake.ServerHello{
		Version:           0x0303,
		Random:            random,
		CipherSuite:       0x002F,
		RenegotiationInfo: true,
	}
	msg := mustMarshalMessage(hello)

	parsed, _, err := handshake.ParseMessage(msg)
	testutil.NoErr(t, err, "empty renegotiation_info should be accepted")

	got, ok := parsed.(*handshake.ServerHello)
	testutil.Ok(t, ok, fmt.Sprintf("ParseMessage: got %T, want *ServerHello", parsed))

	if !got.RenegotiationInfo {
		t.Error("RenegotiationInfo should be true")
	}

	// Non-empty renegotiation_info body → must be rejected.
	// We build the wire manually by injecting bad extension bytes into a
	// ServerHello body that has no extensions.
	// renegotiation_info ext: type=0xFF01, len=3, content={0x01, 0xAA, 0xBB}
	// Per RFC 5746, the body is: uint8 renegotiated_connection length + data.
	// Non-empty means the uint8 length > 0.
	badExt := []byte{
		0xFF, 0x01, // type renegotiation_info.
		0x00, 0x03, // ext length = 3.
		0x02, 0xAA, 0xBB, // renegotiated_connection length=2 + 2 bytes data.
	}
	extList := make([]byte, 2+len(badExt))

	extList[0] = 0x00
	extList[1] = byte(len(badExt))
	copy(extList[2:], badExt)

	// Remove the old extension list from body (none was added since we had
	// renegotiation_info=true and it marshals with empty body).
	// Instead build a raw ServerHello without extensions first.
	helloNoExt := &handshake.ServerHello{
		Version:     0x0303,
		Random:      random,
		CipherSuite: 0x002F,
	}

	bodyNoExt, bodyNoExtErr := helloNoExt.Marshal()
	testutil.NoErr(t, bodyNoExtErr, "helloNoExt.Marshal")

	wireWithBadExt := mustMarshalMessage(&handshake.RawMessage{
		MsgType: handshake.TypeServerHello,
		Body:    slices.Concat(bodyNoExt, extList),
	})

	_, _, err = handshake.ParseMessage(wireWithBadExt)
	testutil.WantErr(t, err, "handshake.ParseMessage")

	if !strings.Contains(err.Error(), "renegotiation") {
		t.Errorf("error should mention renegotiation, got: %v", err)
	}
}

// --- CertificateRequest ---.

// buildCertificateRequestWire builds the raw wire body (no 4-byte envelope)
// for a CertificateRequest message from its parts.
//
// RFC 5246 §7.4.4 encoding:
//
//	uint8 cert_types_len + cert_types
//	uint16 sig_algs_byte_len + sig_alg pairs (hash, sig)
//	uint16 cas_byte_len + { uint16 dn_len + dn_bytes } *
func buildCertificateRequestWire(certTypes []uint8, sigAlgs []handshake.SigAndHash, cas [][]byte) []byte {
	// supported_signature_algorithms: uint16 byte-length prefix.
	sigBytes := make([]byte, 2*len(sigAlgs))
	for i, sa := range sigAlgs {
		sigBytes[2*i] = sa.Hash
		sigBytes[2*i+1] = sa.Sig
	}

	// certificate_authorities body.
	casLen := 0
	for _, dn := range cas {
		casLen += 2 + len(dn)
	}

	casBody := make([]byte, 0, casLen)

	for _, dn := range cas {
		casBody = append(casBody, uint8(len(dn)>>8), uint8(len(dn)))
		casBody = append(casBody, dn...)
	}

	body := make([]byte, 0, 1+len(certTypes)+2+len(sigBytes)+2+len(casBody))

	// certificate_types: uint8 length prefix.
	body = append(body, uint8(len(certTypes)))
	body = append(body, certTypes...)

	body = append(body, uint8(len(sigBytes)>>8), uint8(len(sigBytes)))
	body = append(body, sigBytes...)

	body = append(body, uint8(len(casBody)>>8), uint8(len(casBody)))
	body = append(body, casBody...)

	return body
}

// TestMessage_CertificateRequest_Minimal tests parsing of a CertificateRequest
// with 1 cert type, 2 sig-algs, and 1 empty CA (zero-length DN).
func TestMessage_CertificateRequest_Minimal(t *testing.T) {
	t.Parallel()

	certTypes := []uint8{0x01} // rsa_sign.
	sigAlgs := []handshake.SigAndHash{
		{Hash: 0x04, Sig: 0x01}, // sha256+rsa.
		{Hash: 0x05, Sig: 0x01}, // sha384+rsa.
	}
	// One CA with an empty DN (zero-length).
	cas := [][]byte{{}}

	wire := buildCertificateRequestWire(certTypes, sigAlgs, cas)
	envelope := mustMarshalMessage(&handshake.RawMessage{
		MsgType: handshake.TypeCertificateRequest,
		Body:    wire,
	})

	parsed, remaining, err := handshake.ParseMessage(envelope)
	testutil.NoErr(t, err, "ParseMessage")

	testutil.Len(t, remaining, 0, "remaining")

	got, ok := parsed.(*handshake.CertificateRequest)
	testutil.Ok(t, ok, fmt.Sprintf("ParseMessage: got %T, want *CertificateRequest", parsed))

	if len(got.CertificateTypes) != 1 || got.CertificateTypes[0] != 0x01 {
		t.Errorf("CertificateTypes: got %v, want [0x01]", got.CertificateTypes)
	}

	testutil.Len(t, got.SupportedSignatureAlgs, 2, "got.SupportedSignatureAlgs")

	if got.SupportedSignatureAlgs[0] != sigAlgs[0] {
		t.Errorf("SigAlgs[0]: got %v, want %v", got.SupportedSignatureAlgs[0], sigAlgs[0])
	}

	if got.SupportedSignatureAlgs[1] != sigAlgs[1] {
		t.Errorf("SigAlgs[1]: got %v, want %v", got.SupportedSignatureAlgs[1], sigAlgs[1])
	}

	testutil.Len(t, got.CertificateAuthorities, 1, "got.CertificateAuthorities")

	testutil.Len(t, got.CertificateAuthorities[0], 0, "got.CertificateAuthorities[0]")
}

// TestMessage_CertificateRequest_TwoCAs tests parsing with two non-empty CA DNs.
func TestMessage_CertificateRequest_TwoCAs(t *testing.T) {
	t.Parallel()

	certTypes := []uint8{0x01, 0x02} // rsa_sign, dss_sign.
	sigAlgs := []handshake.SigAndHash{
		{Hash: 0x04, Sig: 0x01},
	}
	ca1 := []byte{0x30, 0x0A, 0x31, 0x08, 0x30, 0x06}             // fake DN 1.
	ca2 := []byte{0x30, 0x12, 0x31, 0x10, 0x30, 0x0E, 0xAB, 0xCD} // fake DN 2.

	wire := buildCertificateRequestWire(certTypes, sigAlgs, [][]byte{ca1, ca2})
	envelope := mustMarshalMessage(&handshake.RawMessage{
		MsgType: handshake.TypeCertificateRequest,
		Body:    wire,
	})

	parsed, remaining, err := handshake.ParseMessage(envelope)
	testutil.NoErr(t, err, "ParseMessage")

	testutil.Len(t, remaining, 0, "remaining")

	got, ok := parsed.(*handshake.CertificateRequest)
	testutil.Ok(t, ok, fmt.Sprintf("ParseMessage: got %T, want *CertificateRequest", parsed))

	if len(got.CertificateTypes) != 2 {
		t.Errorf("CertificateTypes: got %d, want 2", len(got.CertificateTypes))
	}

	if len(got.SupportedSignatureAlgs) != 1 {
		t.Errorf("SupportedSignatureAlgs: got %d, want 1", len(got.SupportedSignatureAlgs))
	}

	testutil.Len(t, got.CertificateAuthorities, 2, "got.CertificateAuthorities")

	if !bytes.Equal(got.CertificateAuthorities[0], ca1) {
		t.Errorf("CA[0] mismatch: got %x, want %x", got.CertificateAuthorities[0], ca1)
	}

	testutil.EqualBytes(t, got.CertificateAuthorities[1], ca2, "got.CertificateAuthorities[1]")
}

// TestMessage_CertificateRequest_EmptyCAs tests parsing with an empty
// certificate_authorities list (legal per RFC 5246).
func TestMessage_CertificateRequest_EmptyCAs(t *testing.T) {
	t.Parallel()

	certTypes := []uint8{0x01}
	sigAlgs := []handshake.SigAndHash{{Hash: 0x04, Sig: 0x01}}

	var cas [][]byte // empty.

	wire := buildCertificateRequestWire(certTypes, sigAlgs, cas)
	envelope := mustMarshalMessage(&handshake.RawMessage{
		MsgType: handshake.TypeCertificateRequest,
		Body:    wire,
	})

	parsed, _, err := handshake.ParseMessage(envelope)
	testutil.NoErr(t, err, "ParseMessage with empty CAs")

	got, ok := parsed.(*handshake.CertificateRequest)
	testutil.Ok(t, ok, fmt.Sprintf("ParseMessage: got %T, want *CertificateRequest", parsed))

	testutil.Len(t, got.CertificateAuthorities, 0, "got.CertificateAuthorities")
}

// TestMessage_CertificateRequest_Truncated_CertTypes tests truncation at the
// certificate_types length prefix.
func TestMessage_CertificateRequest_Truncated_CertTypes(t *testing.T) {
	t.Parallel()

	// Only the cert_types length byte, no actual cert type bytes.
	// Declare 1 cert type but provide 0 bytes.
	body := []byte{0x01} // says 1 byte follows, but nothing does.
	envelope := mustMarshalMessage(&handshake.RawMessage{
		MsgType: handshake.TypeCertificateRequest,
		Body:    body,
	})

	_, _, err := handshake.ParseMessage(envelope)
	testutil.WantErr(t, err, "handshake.ParseMessage")
}

// TestMessage_CertificateRequest_Truncated_SigAlgs tests truncation at the
// supported_signature_algorithms length prefix.
func TestMessage_CertificateRequest_Truncated_SigAlgs(t *testing.T) {
	t.Parallel()

	// Valid cert types, then only 1 byte of the 2-byte sig_algs length prefix.
	body := []byte{
		0x01, 0x01, // cert_types: length=1, value=0x01.
		0x00, // only 1 byte of the uint16 sig_algs length (truncated).
	}
	envelope := mustMarshalMessage(&handshake.RawMessage{
		MsgType: handshake.TypeCertificateRequest,
		Body:    body,
	})

	_, _, err := handshake.ParseMessage(envelope)
	testutil.WantErr(t, err, "handshake.ParseMessage")
}

// TestMessage_CertificateRequest_Truncated_CAs tests truncation at the
// certificate_authorities length prefix.
func TestMessage_CertificateRequest_Truncated_CAs(t *testing.T) {
	t.Parallel()

	// Valid cert types and sig_algs, then only 1 byte of the 2-byte CA length prefix.
	body := []byte{
		0x01, 0x01, // cert_types: length=1, value=0x01.
		0x00, 0x02, // sig_algs: length=2 bytes.
		0x04, 0x01, // one sig_alg: sha256+rsa.
		0x00, // only 1 byte of the uint16 CA list length (truncated).
	}
	envelope := mustMarshalMessage(&handshake.RawMessage{
		MsgType: handshake.TypeCertificateRequest,
		Body:    body,
	})

	_, _, err := handshake.ParseMessage(envelope)
	testutil.WantErr(t, err, "handshake.ParseMessage")
}

// TestMessage_CertificateRequest_SigAlgsOddByteCount tests that an odd number
// of bytes in the sig_algs section is rejected.
func TestMessage_CertificateRequest_SigAlgsOddByteCount(t *testing.T) {
	t.Parallel()

	body := []byte{
		0x01, 0x01, // cert_types: length=1, value=0x01.
		0x00, 0x03, // sig_algs: length=3 bytes (odd — invalid).
		0x04, 0x01, 0x05, // 3 bytes: can't form whole SigAndHash pairs.
		0x00, 0x00, // CA list: empty.
	}
	envelope := mustMarshalMessage(&handshake.RawMessage{
		MsgType: handshake.TypeCertificateRequest,
		Body:    body,
	})

	_, _, err := handshake.ParseMessage(envelope)
	testutil.WantErr(t, err, "handshake.ParseMessage")
}

// TestMessage_CertificateRequest_Marshal tests that Marshal returns nil
// (client never sends this message; it is server-only).
func TestMessage_CertificateRequest_Marshal(t *testing.T) {
	t.Parallel()

	cr := &handshake.CertificateRequest{
		CertificateTypes:       []uint8{0x01},
		SupportedSignatureAlgs: []handshake.SigAndHash{{Hash: 0x04, Sig: 0x01}},
	}

	crBody, crErr := cr.Marshal()
	testutil.NoErr(t, crErr, "CertificateRequest.Marshal")

	if crBody != nil {
		t.Error("CertificateRequest.Marshal() should return nil (client never sends it)")
	}

	if cr.Type() != handshake.TypeCertificateRequest {
		t.Errorf("Type(): got %v, want TypeCertificateRequest", cr.Type())
	}
}

// mustMarshalMessage wraps handshake.MarshalMessage for table entries that
// build fixed, in-range messages, where a length-prefix overflow is impossible
// and would indicate a bug in the test itself.
func mustMarshalMessage(m handshake.Message) []byte {
	return testutil.Must(handshake.MarshalMessage(m))
}
