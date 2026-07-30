package ke_test

import (
	"bytes"
	"testing"

	gost "github.com/tarantool/go-gostcrypto"
	"github.com/tarantool/go-gostls/internal/ke"
	"github.com/tarantool/go-gostls/internal/testutil"
)

// TestGOST_VKO2001_Exchange_RoundTrip verifies that VKOGost2001Exchange produces
// the correct pre-master secret using known VKO2001 test vectors.
//
// These vectors are from the gogost upstream gost3410/vko2001_test.go, which uses
// CurveIdGostR34102001TestParamSet. The VKOGost2001Exchange for TLS uses
// CurveIdGostR34102001CryptoProAParamSet (the production curve). This test uses
// NewVKOGost2001ExchangeTestCurve — a test-only variant that operates on the
// test-param-set curve and emits raw public-key CKE — to verify the KEK
// round-trip logic, independent of curve selection and of the GOST_KEY_TRANSPORT
// envelope used by the production ClientKeyExchange.
//
// UKM = first 8 bytes of client_random per RFC 9189 §4.1. Confirmed
// against Tarantool-EE 3.5.0 via TestTarantoolEE_Ping_GOST_Pure.
func TestGOST_VKO2001_Exchange_RoundTrip(t *testing.T) {
	t.Parallel()

	// Test vectors from upstream gost3410/vko2001_test.go
	// (CurveIdGostR34102001TestParamSet).
	ukmRaw := testutil.MustHex(t, "5172be25f852a233")
	prvRaw1 := testutil.MustHex(t, "1df129e43dab345b68f6a852f4162dc69f36b2f84717d08755cc5c44150bf928")
	prvRaw2 := testutil.MustHex(t, "5b9356c6474f913f1e83885ea0edd5df1a43fd9d799d219093241157ac9ed473")
	wantKEK := testutil.MustHex(t, "ee4618a0dbb10cb31777b4b86a53d9e7ef6cb3e400101410f0c0f2af46c494a6")

	// Derive public keys from private keys using the test param set curve.
	// GOST2001TestPublicKeyFromPrivate uses CurveIdGostR34102001TestParamSet.
	pub2, err := ke.GOST2001TestPublicKeyFromPrivate(prvRaw2)
	testutil.NoErr(t, err, "derive pub2")

	pub1, err := ke.GOST2001TestPublicKeyFromPrivate(prvRaw1)
	testutil.NoErr(t, err, "derive pub1")

	// Party 1 computes KEK using their private key and party 2's public key.
	// NewVKOGost2001ExchangeTestCurve uses the test-param-set curve (for the
	// vko2001 vectors); the actual TLS exchange uses CryptoPro-A.
	ex1 := ke.NewVKOGost2001ExchangeTestCurve(prvRaw1, pub2, ukmRaw)

	cke, preMaster1, err := ex1.ClientKeyExchange(nil)
	testutil.NoErr(t, err, "party1 ClientKeyExchange")

	if len(preMaster1) != 32 {
		t.Errorf("preMaster1: want 32 bytes, got %d", len(preMaster1))
	}

	if !bytes.Equal(preMaster1, wantKEK) {
		t.Errorf("preMaster1 mismatch\ngot:  %x\nwant: %x", preMaster1, wantKEK)
	}

	if len(cke) == 0 {
		t.Error("cke is empty")
	}

	// Party 2 computes the same KEK using their private key and party 1's public key.
	ex2 := ke.NewVKOGost2001ExchangeTestCurve(prvRaw2, pub1, ukmRaw)

	_, preMaster2, err := ex2.ClientKeyExchange(nil)
	testutil.NoErr(t, err, "party2 ClientKeyExchange")

	if !bytes.Equal(preMaster1, preMaster2) {
		t.Errorf("VKO2001 parties disagree:\nparty1: %x\nparty2: %x", preMaster1, preMaster2)
	}
}

// TestGOST_VKO2012_256_RoundTrip verifies the VKO GOST R 34.10-2012 256-bit
// shared-key derivation (the KEK later used by CryptoPro key wrap) using
// upstream gogost vectors on CurveIdtc26gost341012512paramSetA. The
// high-level VKOGost2012_256Exchange now produces a GOST_KEY_TRANSPORT
// envelope with a random premaster; round-trip equivalence at the exchange
// level is not meaningful, so this test exercises the underlying
// primitive directly.
func TestGOST_VKO2012_256_RoundTrip(t *testing.T) {
	t.Parallel()

	ukmRaw := testutil.MustHex(t, "1d80603c8544c727")
	prvRawA := testutil.MustHex(t,
		"c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8"+
			"c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667")
	pubRawA := testutil.MustHex(t,
		"aab0eda4abff21208d18799fb9a8556654ba783070eba10cb9abb253ec56dcf5"+
			"d3ccba6192e464e6e5bcb6dea137792f2431f6c897eb1b3c0cc14327b1adc0a79"+
			"14613a3074e363aedb204d38d3563971bd8758e878c9db11403721b48002d3846"+
			"1f92472d40ea92f9958c0ffa4c93756401b97f89fdbe0b5e46e4a4631cdb5a")
	prvRawB := testutil.MustHex(t,
		"48c859f7b6f11585887cc05ec6ef1390cfea739b1a18c0d4662293ef63b79e3b"+
			"8014070b44918590b4b996acfea4edfbbbcccc8c06edd8bf5bda92a51392d0db")
	pubRawB := testutil.MustHex(t,
		"192fe183b9713a077253c72c8735de2ea42a3dbc66ea317838b65fa32523cd5e"+
			"fca974eda7c863f4954d1147f1f2b25c395fce1c129175e876d132e94ed5a6510"+
			"4883b414c9b592ec4dc84826f07d0b6d9006dda176ce48c391e3f97d102e03bb5"+
			"98bf132a228a45f7201aba08fc524a2d77e43a362ab022ad4028f75bde3b79")
	wantKEK := testutil.MustHex(t, "c9a9a77320e2cc559ed72dce6f47e2192ccea95fa648670582c054c0ef36c221")

	kekA, err := gost.VKO2012_256(prvRawA, pubRawB, ukmRaw)
	testutil.NoErr(t, err, "partyA VKO2012_256")

	if !bytes.Equal(kekA, wantKEK) {
		t.Errorf("partyA KEK mismatch\ngot:  %x\nwant: %x", kekA, wantKEK)
	}

	kekB, err := gost.VKO2012_256(prvRawB, pubRawA, ukmRaw)
	testutil.NoErr(t, err, "partyB VKO2012_256")

	if !bytes.Equal(kekA, kekB) {
		t.Errorf("VKO2012_256 parties disagree:\nA: %x\nB: %x", kekA, kekB)
	}
}
