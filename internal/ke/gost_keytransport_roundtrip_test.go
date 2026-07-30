package ke //nolint:testpackage // white-box test: accesses unexported internal ASN.1 types.

import (
	"bytes"
	"encoding/asn1"
	"testing"

	gost "github.com/tarantool/go-gostcrypto"
	"github.com/tarantool/go-gostls/internal/testutil"
)

// TestGOSTKeyTransport_RoundTrip_2012_256_CryptoProA verifies end-to-end that
// our VKOGost2012_256Exchange produces a CKE that, when decrypted by a
// synthetic "server" using the same primitives, yields the original premaster.
//
// This checks that VKO + KeyWrapCryptoPro + ASN.1 marshal form an invertible
// pipeline — independent of gost-engine wire parity. If this test passes but
// integration still fails, the bug is on the server side of the wire format,
// not in our crypto primitives.
func TestGOSTKeyTransport_RoundTrip_2012_256_CryptoProA(t *testing.T) {
	t.Parallel()

	curve := gost.GOST2001CryptoProAParamSetCurve()

	// Server's long-term key pair (fake — just any valid key on the curve).
	srvPrv := make([]byte, 32)
	for i := range srvPrv {
		srvPrv[i] = byte(i + 1)
	}

	srvPubRaw, err := gost.PublicKeyRawFromPrivate(curve, srvPrv)
	testutil.NoErr(t, err, "server pubkey")

	// Fake SPKI AlgorithmIdentifier DER (for our ephem SPKI reuse).
	// Use the standard GOST 2012-256 AlgorithmIdentifier with CryptoPro-A + streebog256.
	spkiAlgo := []byte{
		0x30, 0x1f,
		0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x01, 0x01, // pubkey OID.
		0x30, 0x13,
		0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01, // curve OID.
		0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02, // hash OID.
	}

	ukm := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	ex, err := NewVKOGost2012_256Exchange(curve, spkiAlgo, srvPubRaw, ukm)
	testutil.NoErr(t, err, "new exchange")

	cke, preMaster, err := ex.ClientKeyExchange(nil)
	testutil.NoErr(t, err, "ClientKeyExchange")

	t.Logf("CKE len=%d preMaster=%x", len(cke), preMaster)

	// Server side: parse the CKE bytes to extract ephemPubRaw, encrypted_key, imit, ukm.
	var params gostClientKeyExchangeParams

	rest, err := asn1.Unmarshal(cke, &params)
	testutil.NoErr(t, err, "unmarshal params")

	testutil.Len(t, rest, 0, "bytes trailing the CKE")

	gkt := params.GKT
	encryptedKey := gkt.KeyInfo.EncryptedKey
	imit := gkt.KeyInfo.IMIT
	wireUKM := gkt.KeyAgreementInfo.EphIV
	t.Logf("encrypted_key=%x imit=%x ukm=%x", encryptedKey, imit, wireUKM)

	// Parse [0] IMPLICIT SPKI to recover the ephemeral pubkey bytes.
	// gkt.KeyAgreementInfo.EphemKey.Bytes is the body of the tagged SPKI (body
	// of [0] IMPLICIT SEQUENCE after the outer tag is stripped).
	ephBytes := gkt.KeyAgreementInfo.EphemKey.FullBytes
	// asn1.RawValue with context tag: FullBytes includes the tag+length.
	// Re-tag as a universal SEQUENCE so a stdlib SPKI parser works.
	spkiDER := make([]byte, len(ephBytes))
	copy(spkiDER, ephBytes)

	spkiDER[0] = 0x30 // reset [0] IMPLICIT → SEQUENCE.

	var ephemSPKI keSPKI

	rest2, err := asn1.Unmarshal(spkiDER, &ephemSPKI)
	testutil.NoErr(t, err, "unmarshal ephem SPKI")

	testutil.Len(t, rest2, 0, "bytes trailing the ephemeral SPKI")

	bitBytes := ephemSPKI.SubjectPublicKey.Bytes

	var pubOctet []byte

	rest3, err := asn1.Unmarshal(bitBytes, &pubOctet)
	testutil.NoErr(t, err, "unmarshal pubkey OCTET STRING")

	testutil.Len(t, rest3, 0, "bytes trailing the pubkey OCTET STRING")

	// Server VKO using its private key + client's ephemeral public key + UKM.
	kek, err := gost.VKO2012_256OnCurve(curve, srvPrv, pubOctet, wireUKM)
	testutil.NoErr(t, err, "server VKO")

	// Reconstruct the 44-byte wrapped key [ukm | encrypted_key | imit] and
	// unwrap via our own primitives. We don't have an Unwrap helper, so just
	// replicate the primitive logic inline: decrypt encrypted_key with
	// diversified KEK, recompute IMIT, compare.
	//
	// We reuse KeyWrapCryptoPro with the same preMaster as a self-check:
	// it must produce the same encrypted_key / imit given (kek, ukm, preMaster).
	reWrapped, err := gost.KeyWrapCryptoPro(gost.SboxTC26Z, kek, wireUKM, preMaster)
	testutil.NoErr(t, err, "re-wrap")

	if !bytes.Equal(reWrapped[8:40], encryptedKey) {
		t.Errorf("encrypted_key mismatch\nwire: %x\nrewrap: %x", encryptedKey, reWrapped[8:40])
	}

	if !bytes.Equal(reWrapped[40:44], imit) {
		t.Errorf("imit mismatch\nwire: %x\nrewrap: %x", imit, reWrapped[40:44])
	}
}
