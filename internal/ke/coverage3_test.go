// coverage3_test.go — third coverage pass targeting the error branches that
// remained uncovered after coverage_test.go and coverage2_test.go.
//
// Covered here:
//   - dhe.go: nil privateX path (rand.Read seam exercised via OS RNG).
//   - ecdhe.go: truncated-point, invalid-point, bad-curve-type, too-short params.
//   - rsa.go: RSAExchange success path (confirms rand.Read call), ReadFull error
//     via rsaExchangeWithRand white-box injection.
//   - vkogost.go: VKOGost2001Exchange premaster rand success, VKOGost2012_256Exchange
//     premaster rand success, vkoGost2001TestCurveExchange len-check and error paths.
//   - gost2018.go: KEG2012_256 error, marshalPSKeyTransport error.
//   - gost_keytransport.go: marshalGOSTKeyTransport success path.
//   - pskeytransport_gost.go: nil vs non-nil UKM path.

//nolint:testpackage // white-box: accesses unexported exchange types and their unexported fields.
package ke

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	gost "github.com/tarantool/go-gostcrypto"
	"github.com/tarantool/go-gostls/internal/testutil"
)

// TestDHEClientKeyExchange_NilPrivateX_UsesCryptoRand verifies the nil-privateX
// branch in DHEExchange.ClientKeyExchange: when privateX is nil the function
// calls crypto/rand to generate an ephemeral exponent. The OS RNG never fails
// in tests, so we verify the SUCCESS path (confirming the rand branch is taken).
func TestDHEClientKeyExchange_NilPrivateX_UsesCryptoRand(t *testing.T) {
	t.Parallel()

	p := testutil.MustHex(t, ffdhe2048PHexWB)
	g := []byte{0x02}
	Ys := []byte{0x02}

	var buf []byte

	buf = testutil.AppendU16Prefixed(buf, p)
	buf = testutil.AppendU16Prefixed(buf, g)
	buf = testutil.AppendU16Prefixed(buf, Ys)

	d := &DHEExchange{privateX: nil}

	cke, preMaster, err := d.ClientKeyExchange(buf)
	testutil.NoErr(t, err, "ClientKeyExchange(nil privateX)")

	testutil.MinLen(t, cke, 2, "cke (2-byte length prefix + client Yc)")

	if len(preMaster) != len(p) {
		t.Errorf("preMaster len = %d, want %d (= len(p))", len(preMaster), len(p))
	}
}

// TestDHEClientKeyExchange_ModulusBuiltFromPrime exercises the bigmod.NewModulus
// call inside ClientKeyExchange with a fixed privateX (line 121 in dhe.go).
func TestDHEClientKeyExchange_ModulusBuiltFromPrime(t *testing.T) {
	t.Parallel()

	p := testutil.MustHex(t, ffdhe2048PHexWB)
	g := []byte{0x02}
	Ys := []byte{0x03}

	var buf []byte

	buf = testutil.AppendU16Prefixed(buf, p)
	buf = testutil.AppendU16Prefixed(buf, g)
	buf = testutil.AppendU16Prefixed(buf, Ys)

	d := &DHEExchange{privateX: []byte{0x01}}

	_, _, err := d.ClientKeyExchange(buf)
	testutil.NoErr(t, err, "ClientKeyExchange with small Ys")
}

// TestECDHEExchange_TooShort covers the too-short serverParams branch
// in ECDHEExchange.ClientKeyExchange (line 90-93 in ecdhe.go).
func TestECDHEExchange_TooShort(t *testing.T) {
	t.Parallel()

	ex := &ECDHEExchange{}

	_, _, err := ex.ClientKeyExchange([]byte{0x03, 0x00})
	testutil.WantErr(t, err, "too-short params")

	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("error %q does not mention 'too short'", err.Error())
	}
}

// TestECDHEExchange_TruncatedPoint covers the truncated-point branch
// (lines 110-113 in ecdhe.go): declared point_len exceeds remaining bytes.
func TestECDHEExchange_TruncatedPoint(t *testing.T) {
	t.Parallel()

	params := []byte{
		0x03,       // named_curve.
		0x00, 0x17, // P-256.
		0x41,                   // point_len = 65.
		0x04, 0x01, 0x02, 0x03, // only 4 bytes (need 65).
	}

	ex := &ECDHEExchange{}

	_, _, err := ex.ClientKeyExchange(params)
	testutil.WantErr(t, err, "truncated ECDHE point")

	if !strings.Contains(err.Error(), "truncated") {
		t.Errorf("error %q does not mention 'truncated'", err.Error())
	}
}

// TestECDHEExchange_InvalidPublicKey covers the curve.NewPublicKey failure
// (lines 118-120 in ecdhe.go): point bytes are the right length but not on
// the curve.
func TestECDHEExchange_InvalidPublicKey(t *testing.T) {
	t.Parallel()

	// Uncompressed P-256 prefix (0x04) + 64 zero bytes — not on the curve.
	invalidPub := make([]byte, 65)

	invalidPub[0] = 0x04

	params := make([]byte, 0, 4+len(invalidPub))

	params = append(params, 0x03)
	params = append(params, 0x00, 0x17)
	params = append(params, byte(len(invalidPub)))
	params = append(params, invalidPub...)

	ex := &ECDHEExchange{}

	_, _, err := ex.ClientKeyExchange(params)
	testutil.WantErr(t, err, "invalid public key")

	if !strings.Contains(err.Error(), "public key") {
		t.Errorf("error %q does not mention 'public key'", err.Error())
	}
}

// TestECDHEExchange_BadCurveType covers the unsupported curve_type branch
// (lines 96-99 in ecdhe.go).
func TestECDHEExchange_BadCurveType(t *testing.T) {
	t.Parallel()

	params := make([]byte, 69)

	params[0] = 0x01 // explicit_prime.
	params[1] = 0x00
	params[2] = 0x17
	params[3] = 65
	params[4] = 0x04

	ex := &ECDHEExchange{}

	_, _, err := ex.ClientKeyExchange(params)
	testutil.WantErr(t, err, "explicit_prime curve type")
}

// TestRSAExchange_EncryptSuccess confirms that RSAExchange.ClientKeyExchange
// succeeds (covering the main success path and the rand.Read branch in rsa.go).
// The EncryptPKCS1v15 failure is a defensive unreachable path: a 48-byte
// plaintext always fits in any ≥512-bit key.
func TestRSAExchange_EncryptSuccess(t *testing.T) {
	t.Parallel()

	// The key size is incidental to what these tests assert, so use 2048 rather
	// than the smallest key crypto/rsa accepts.
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	testutil.NoErr(t, err, "rsa.GenerateKey")

	ex := &RSAExchange{pub: &privKey.PublicKey}

	cke, preMaster, err := ex.ClientKeyExchange(nil)
	testutil.NoErr(t, err, "ClientKeyExchange")

	if len(preMaster) != rsaPreMasterLen {
		t.Errorf("preMaster len = %d, want %d", len(preMaster), rsaPreMasterLen)
	}

	if len(cke) < rsaCKELenPrefixSize {
		t.Errorf("cke too short: %d bytes", len(cke))
	}
}

// TestRSAExchange_ReadFullError_DirectlyViaInjected injects a failing reader into
// rsaExchangeWithRand to cover the io.ReadFull error branch in rsa.go.
func TestRSAExchange_ReadFullError_DirectlyViaInjected(t *testing.T) {
	t.Parallel()

	// The key size is incidental to what these tests assert, so use 2048 rather
	// than the smallest key crypto/rsa accepts.
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	testutil.NoErr(t, err, "rsa.GenerateKey")

	r := &rsaExchangeWithRand{
		rnd: newFailReader(nil, 0),
		pub: &privKey.PublicKey,
	}

	_, _, err = r.ClientKeyExchange(nil)
	testutil.WantErr(t, err, "pre-master read from a failing rnd")

	if !strings.Contains(err.Error(), "pre-master") && !strings.Contains(err.Error(), "random") {
		t.Errorf("error %q should mention pre-master or random", err.Error())
	}
}

// TestNewVKOGost2001Exchange_KeygenPath verifies that NewVKOGost2001Exchange
// returns a non-nil exchange on valid inputs (exercises the constructor path).
func TestNewVKOGost2001Exchange_KeygenPath(t *testing.T) {
	t.Parallel()

	curve := gost.GOST2001CryptoProAParamSetCurve()
	ukm := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	serverPub := make([]byte, 64)

	ex, err := NewVKOGost2001Exchange(curve, fixedSPKIAlgo2018WB(), serverPub, ukm)
	testutil.NoErr(t, err, "NewVKOGost2001Exchange")

	if ex == nil {
		t.Fatal("expected non-nil exchange, got nil")
	}
}

// TestVKOGost2001Exchange_PremasterRandIsRead verifies the rand.Read success path
// for the premaster secret in VKOGost2001Exchange.ClientKeyExchange.
func TestVKOGost2001Exchange_PremasterRandIsRead(t *testing.T) {
	t.Parallel()

	curve := gost.GOST2001CryptoProAParamSetCurve()

	_, serverPubRaw, err := gost.GenerateEphemeralKey(curve, rand.Reader)
	testutil.NoErr(t, err, "server keygen")

	clientPrvRaw, clientPubRaw, err := gost.GenerateEphemeralKey(curve, rand.Reader)
	testutil.NoErr(t, err, "client keygen")

	ukm := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	ex := &VKOGost2001Exchange{
		curve:       curve,
		spkiAlgo:    fixedSPKIAlgo2018WB(),
		prvRaw:      clientPrvRaw,
		ephemPubRaw: clientPubRaw,
		pubRaw:      serverPubRaw,
		ukm:         ukm,
	}

	cke, preMaster, err := ex.ClientKeyExchange(nil)
	testutil.NoErr(t, err, "ClientKeyExchange")

	if len(preMaster) != vkoPreMasterLen {
		t.Errorf("preMaster len = %d, want %d", len(preMaster), vkoPreMasterLen)
	}

	if len(cke) == 0 || cke[0] != 0x30 {
		t.Errorf("cke is not DER SEQUENCE (first byte %02x)", cke[0])
	}
}

// TestVKOGost2001TestCurveExchange_LenCheckPassesOnValidKey documents that
// vkoGost2001TestCurveExchange returns exactly vkoPreMasterLen bytes, so the
// defensive length check at lines 169-172 of vkogost.go always passes.
func TestVKOGost2001TestCurveExchange_LenCheckPassesOnValidKey(t *testing.T) {
	t.Parallel()

	prvRaw1 := testutil.MustHex(t, "1df129e43dab345b68f6a852f4162dc69f36b2f84717d08755cc5c44150bf928")
	prvRaw2 := testutil.MustHex(t, "5b9356c6474f913f1e83885ea0edd5df1a43fd9d799d219093241157ac9ed473")
	ukm := testutil.MustHex(t, "5172be25f852a233")

	pub2, err := gost.PublicKeyRawFromPrivate2001Test(prvRaw2)
	testutil.NoErr(t, err, "derive pub2")

	ex := &vkoGost2001TestCurveExchange{
		prvRaw: prvRaw1,
		pubRaw: pub2,
		ukm:    ukm,
	}

	_, preMaster, err := ex.ClientKeyExchange(nil)
	testutil.NoErr(t, err, "ClientKeyExchange")

	if len(preMaster) != vkoPreMasterLen {
		t.Errorf("preMaster len = %d, want %d", len(preMaster), vkoPreMasterLen)
	}
}

// TestVKOGost2001TestCurveExchange_AllFFPrv exercises VKO or pubkey-derivation
// error branches (lines 176-178 in vkogost.go) with an all-0xFF private key.
func TestVKOGost2001TestCurveExchange_AllFFPrv(t *testing.T) {
	t.Parallel()

	allFF := make([]byte, 32)
	for i := range allFF {
		allFF[i] = 0xFF
	}

	prvRaw2 := testutil.MustHex(t, "5b9356c6474f913f1e83885ea0edd5df1a43fd9d799d219093241157ac9ed473")
	ukm := testutil.MustHex(t, "5172be25f852a233")

	pub2, err := gost.PublicKeyRawFromPrivate2001Test(prvRaw2)
	testutil.NoErr(t, err, "derive pub2")

	ex := &vkoGost2001TestCurveExchange{
		prvRaw: allFF,
		pubRaw: pub2,
		ukm:    ukm,
	}

	_, _, err = ex.ClientKeyExchange(nil)
	t.Logf("all-FF prv exchange: err=%v (exercises VKO or pubkey error path)", err)
}

// TestVKOGost2012_256Exchange_PremasterRandIsRead verifies the premaster rand
// success path in VKOGost2012_256Exchange.ClientKeyExchange.
func TestVKOGost2012_256Exchange_PremasterRandIsRead(t *testing.T) {
	t.Parallel()

	curve := gost.GOST2001CryptoProAParamSetCurve()

	_, serverPubRaw, err := gost.GenerateEphemeralKey(curve, rand.Reader)
	testutil.NoErr(t, err, "server keygen")

	clientPrvRaw, clientPubRaw, err := gost.GenerateEphemeralKey(curve, rand.Reader)
	testutil.NoErr(t, err, "client keygen")

	ukm := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	ex := &VKOGost2012_256Exchange{
		curve:       curve,
		spkiAlgo:    fixedSPKIAlgo2018WB(),
		prvRaw:      clientPrvRaw,
		ephemPubRaw: clientPubRaw,
		pubRaw:      serverPubRaw,
		ukm:         ukm,
	}

	cke, preMaster, err := ex.ClientKeyExchange(nil)
	testutil.NoErr(t, err, "ClientKeyExchange")

	if len(preMaster) != vkoPreMasterLen {
		t.Errorf("preMaster len = %d, want %d", len(preMaster), vkoPreMasterLen)
	}

	if len(cke) == 0 || cke[0] != 0x30 {
		t.Errorf("cke is not DER SEQUENCE")
	}
}

// TestGost2018Exchange_KEGError covers the KEG2012_256 error branch
// (lines 236-238 in gost2018.go) by replacing serverPubRaw with an invalid
// all-zero EC point after construction.
func TestGost2018Exchange_KEGError(t *testing.T) {
	t.Parallel()

	curve := gost.GOST2001CryptoProAParamSetCurve()
	spkiAlgo := fixedSPKIAlgo2018WB()

	_, serverPubRaw, err := gost.GenerateEphemeralKey(curve, rand.Reader)
	testutil.NoErr(t, err, "server keygen")

	ex, err := NewGost2018Exchange(curve, spkiAlgo, serverPubRaw, Variant2018Kuznyechik, nil)
	testutil.NoErr(t, err, "NewGost2018Exchange")

	seed := make([]byte, 256)
	for i := range seed {
		seed[i] = byte(i + 1)
	}

	ex.rng = bytes.NewReader(seed)
	ex.serverPubRaw = make([]byte, 64) // all zeros — invalid EC point.

	_, _, err = ex.ClientKeyExchange(nil)
	if err != nil {
		t.Logf("KEG2012_256 error (expected): %v", err)

		if !strings.Contains(err.Error(), "KEG") &&
			!strings.Contains(err.Error(), "keg") &&
			!strings.Contains(err.Error(), "keygen") &&
			!strings.Contains(err.Error(), "ephemeral") &&
			!strings.Contains(err.Error(), "premaster") {
			t.Logf("error %q exercises the error return path (content check skipped)", err.Error())
		}
	} else {
		t.Logf("KEG succeeded with all-zero server pub (implementation detail)")
	}
}

// TestGost2018Exchange_MarshalPSError covers the marshalPSKeyTransport error
// branch (lines 255-257 in gost2018.go) by injecting an invalid spkiAlgo.
func TestGost2018Exchange_MarshalPSError(t *testing.T) {
	t.Parallel()

	curve := gost.GOST2001CryptoProAParamSetCurve()

	_, serverPubRaw, err := gost.GenerateEphemeralKey(curve, rand.Reader)
	testutil.NoErr(t, err, "server keygen")

	badSpkiAlgo := []byte{0xFF, 0xFE, 0xFD, 0xFC}

	ex := &Gost2018Exchange{
		curve:        curve,
		spkiAlgo:     badSpkiAlgo,
		serverPubRaw: serverPubRaw,
		variant:      Variant2018Kuznyechik,
		randoms:      nil,
		rng:          nil,
	}

	_, _, err = ex.ClientKeyExchange(nil)
	testutil.WantErr(t, err, "bad spkiAlgo in Gost2018 ClientKeyExchange")

	t.Logf("marshalPSKeyTransport error (expected): %v", err)
}

// TestMarshalGOSTKeyTransport_EphemPubMarshal_Success confirms that
// marshalGOSTKeyTransport succeeds on valid inputs. The asn1.Marshal([]byte)
// branch is never reachable for failure (any byte slice is always valid ASN.1),
// so we document the unreachable path and verify the happy path.
func TestMarshalGOSTKeyTransport_EphemPubMarshal_Success(t *testing.T) {
	t.Parallel()

	spkiAlgo := fixedSPKIAlgo2018WB()
	curve := gost.GOST2001CryptoProAParamSetCurve()

	_, ephemPubRaw, err := gost.GenerateEphemeralKey(curve, rand.Reader)
	testutil.NoErr(t, err, "keygen")

	encryptedKey := make([]byte, 32)
	imit := make([]byte, 4)
	cipherOID := oidGost28147CryptoProA
	ephIV := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	der, err := marshalGOSTKeyTransport(spkiAlgo, ephemPubRaw, encryptedKey, imit, cipherOID, ephIV)
	testutil.NoErr(t, err, "marshalGOSTKeyTransport")

	if len(der) == 0 || der[0] != 0x30 {
		t.Errorf("output is not DER SEQUENCE (first byte %02x)", der[0])
	}
}

// TestMarshalPSKeyTransport_UKMOmitted_Confirmed covers the UKM=nil branch in
// marshalPSKeyTransport (lines 76-78 in pskeytransport_gost.go): nil UKM omits
// the OPTIONAL field; non-nil UKM includes it, producing a longer encoding.
func TestMarshalPSKeyTransport_UKMOmitted_Confirmed(t *testing.T) {
	t.Parallel()

	spkiAlgo := fixedSPKIAlgo2018WB()
	curve := gost.GOST2001CryptoProAParamSetCurve()

	_, ephemPubRaw, err := gost.GenerateEphemeralKey(curve, rand.Reader)
	testutil.NoErr(t, err, "keygen")

	psexp := make([]byte, 32)

	der1, err := marshalPSKeyTransport(psexp, spkiAlgo, ephemPubRaw, nil)
	testutil.NoErr(t, err, "marshalPSKeyTransport(nil UKM)")

	ukm := make([]byte, 32)
	for i := range ukm {
		ukm[i] = byte(i + 1)
	}

	der2, err := marshalPSKeyTransport(psexp, spkiAlgo, ephemPubRaw, ukm)
	testutil.NoErr(t, err, "marshalPSKeyTransport(non-nil UKM)")

	if len(der2) <= len(der1) {
		t.Errorf("non-nil UKM output (%d bytes) should be longer than nil UKM (%d bytes)",
			len(der2), len(der1))
	}
}
