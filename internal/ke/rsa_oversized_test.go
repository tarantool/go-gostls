package ke_test

import (
	"crypto/rsa"
	"math/big"
	"strings"
	"testing"

	"github.com/tarantool/go-gostls/internal/ke"
	"github.com/tarantool/go-gostls/internal/testutil"
)

// TestRSA_OversizedCiphertextRejected covers the guard on the RSA
// ClientKeyExchange length prefix. The ciphertext is as wide as the modulus,
// so a key larger than 65535 bytes would wrap the uint16 prefix and emit a CKE
// whose declared length disagrees with its payload.
//
// The modulus is fabricated rather than generated: EncryptPKCS1v15 needs only
// N and E, and generating a real 524296-bit key would take far too long for a
// unit test.
func TestRSA_OversizedCiphertextRejected(t *testing.T) {
	t.Parallel()

	// 65537 bytes — one byte past what the uint16 prefix can express.
	const modulusBytes = 65537

	n := new(big.Int).Lsh(big.NewInt(1), modulusBytes*8-1)
	n.SetBit(n, 0, 1) // odd, as a modulus must be.

	pub := &rsa.PublicKey{N: n, E: 65537}

	ex := ke.NewRSAExchange(pub)

	_, _, err := ex.ClientKeyExchange(nil)
	testutil.WantErr(t, err, "RSA CKE with a 65537-byte ciphertext")

	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("expected the length-prefix guard to fire, got %v", err)
	}
}
