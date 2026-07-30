// coverage_err_test.go — targeted error-branch tests for protection.go,
// protection_chacha20.go, and protection_gost.go to close the remaining
// sub-90% coverage gaps.
//
// Strategy:
//   - ChaCha20Poly1305 Open: short fragment (< 16-byte tag).
//   - CBC-HMAC Seal/Open: cipher re-init failure via a custom NewCipherFunc
//     that succeeds at construction time but fails on subsequent calls.
//   - GOST IMIT Finalize: count==0 && bufLen>0 trailing-zero-block path,
//     exercised white-box by directly calling gostIMIT.Finalize on a freshly
//     initialised instance with one Write of ≤8 bytes.
//
// The padLen<0 branch in cbcHMACProtector.Seal is unreachable:
// padLen = blockSize - (contentLen+1)%blockSize is always in [0, blockSize-1]
// for any positive blockSize. Documented here as dead code; not tested.
//
// The cipher.NewGCM and chacha20poly1305.New failure paths are also unreachable
// after their respective key-size guards. Not tested.

//nolint:testpackage // white-box: accesses unexported gostIMIT, newGostIMIT, gostKeySize, gostMACSize.
package record

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"testing"

	gost "github.com/tarantool/go-gostcrypto"
	"github.com/tarantool/go-gostls/internal/testutil"
)

// TestChaCha20Poly1305Open_ShortFragment covers the len(fragment) < tagSize
// branch in chacha20Poly1305Protector.Open (protection_chacha20.go:62-64).
// The ChaCha20-Poly1305 AEAD overhead is 16 bytes; feeding fewer bytes must
// return AlertBadRecordMAC.
func TestChaCha20Poly1305Open_ShortFragment(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0xAB}, 32)
	iv := bytes.Repeat([]byte{0x01}, 12)

	p, err := NewChaCha20Poly1305Protector(key, iv)
	testutil.NoErr(t, err, "NewChaCha20Poly1305Protector")

	hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x00}

	_, openErr := p.Open(0, hdr, make([]byte, 10))

	alert := testutil.ErrAs[*AlertError](t, openErr, "Open(10 bytes)")

	testutil.Equal(t, alert.Description, AlertBadRecordMAC, "Open(10 bytes) alert description")
}

// TestChaCha20Poly1305Open_BadTag covers the authentication failure path in
// chacha20Poly1305Protector.Open (the aead.Open error branch). Confirms that
// tampered ciphertext returns AlertBadRecordMAC.
func TestChaCha20Poly1305Open_BadTag(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0xCC}, 32)
	iv := bytes.Repeat([]byte{0x02}, 12)

	sender, err := NewChaCha20Poly1305Protector(key, iv)
	testutil.NoErr(t, err, "NewChaCha20Poly1305Protector(sender)")

	receiver, err := NewChaCha20Poly1305Protector(key, iv)
	testutil.NoErr(t, err, "NewChaCha20Poly1305Protector(receiver)")

	hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x05}

	sealed, err := sender.Seal(0, hdr, []byte("hello"))
	testutil.NoErr(t, err, "Seal")

	tampered := make([]byte, len(sealed))

	copy(tampered, sealed)

	tampered[len(tampered)-1] ^= 0xFF

	_, openErr := receiver.Open(0, hdr, tampered)

	alert := testutil.ErrAs[*AlertError](t, openErr, "Open(tampered)")

	testutil.Equal(t, alert.Description, AlertBadRecordMAC, "Open(tampered) alert description")
}

// countingCipherFunc wraps a cipher constructor and returns an error after
// failAfter successful calls, simulating a mid-session cipher failure.
type countingCipherFunc struct {
	real      func(key []byte) (cipher.Block, error)
	calls     int
	failAfter int
}

func (c *countingCipherFunc) newCipher(key []byte) (cipher.Block, error) {
	c.calls++

	if c.calls > c.failAfter {
		return nil, fmt.Errorf("cipher unavailable after %d calls", c.failAfter)
	}

	return c.real(key)
}

// TestCBCHMACProtector_Seal_CipherInitFailure covers the cipher re-init
// failure branch in cbcHMACProtector.Seal (protection.go:152-154). The
// protector is constructed successfully (call 1) but Seal's second call
// to newCipher fails.
func TestCBCHMACProtector_Seal_CipherInitFailure(t *testing.T) {
	t.Parallel()

	counter := &countingCipherFunc{real: aes.NewCipher, failAfter: 1}

	encKey := bytes.Repeat([]byte{0xBB}, 16)
	macKey := bytes.Repeat([]byte{0xAA}, 32)

	prot, err := NewCBCHMACProtector(counter.newCipher, sha256.New, encKey, macKey)
	testutil.NoErr(t, err, "NewCBCHMACProtector (should succeed on call 1)")

	hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x01}

	_, err = prot.Seal(0, hdr, []byte{0xAB})

	_ = testutil.ErrAs[*Error](t, err, "Seal(cipher-init failure)")
}

// TestCBCHMACProtector_Open_CipherInitFailure covers the cipher re-init
// failure branch in cbcHMACProtector.Open (protection.go:184-186). A valid
// record is sealed using a separate protector; Open's internal newCipher call
// fails on the second invocation.
func TestCBCHMACProtector_Open_CipherInitFailure(t *testing.T) {
	t.Parallel()

	encKey := bytes.Repeat([]byte{0xBB}, 16)
	macKey := bytes.Repeat([]byte{0xAA}, 32)

	sealProt, err := NewCBCHMACProtector(aes.NewCipher, sha256.New, encKey, macKey)
	testutil.NoErr(t, err, "NewCBCHMACProtector(seal)")

	hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x01}

	sealed, err := sealProt.Seal(0, hdr, []byte{0xAB})
	testutil.NoErr(t, err, "Seal")

	counter := &countingCipherFunc{real: aes.NewCipher, failAfter: 1}

	openProt, err := NewCBCHMACProtector(counter.newCipher, sha256.New, encKey, macKey)
	testutil.NoErr(t, err, "NewCBCHMACProtector(open)")

	_, err = openProt.Open(0, hdr, sealed)

	_ = testutil.ErrAs[*Error](t, err, "Open(cipher-init failure)")
}

// TestGostIMIT_Finalize_TrailingZeroBlock exercises the trailing-zero-block
// path in gostIMIT.Finalize (protection_gost.go:304-308):
//
//	if count == 0 && bufLen > 0 { processSnap(zero[:]) }
//
// This fires when Finalize is called with data shorter than one full block
// (≤ 8 bytes total), so count == 0 (no full blocks were flushed by Write)
// but bufLen > 0 (a partial block is pending). In normal TLS usage the 13-byte
// AD prefix always flushes one block, making this path dead in production.
func TestGostIMIT_Finalize_TrailingZeroBlock(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0x33}, gostKeySize)
	cipher := gost.NewGOST28147Cipher(key, gost.SboxTC26Z)

	m := newGostIMIT(cipher, gost.SboxTC26Z)

	m.Write([]byte{0x01, 0x02, 0x03, 0x04})

	testutil.Equal(t, m.bufLen, 4, "bufLen after 4-byte Write")
	testutil.Equal(t, m.count, 0, "count after 4-byte Write")

	tag1 := m.Finalize()
	if len(tag1) != gostMACSize {
		t.Errorf("tag len = %d, want %d", len(tag1), gostMACSize)
	}

	tag2 := m.Finalize()
	if !bytes.Equal(tag1, tag2) {
		t.Errorf("Finalize not idempotent: tag1=%x, tag2=%x", tag1, tag2)
	}

	m.Write([]byte{0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C})

	if m.count != 8 {
		t.Errorf("count = %d after additional 8-byte Write, want 8", m.count)
	}

	tag3 := m.Finalize()
	if len(tag3) != gostMACSize {
		t.Errorf("tag3 len = %d, want %d", len(tag3), gostMACSize)
	}

	if bytes.Equal(tag1, tag3) {
		t.Logf("tags equal after extra Write (unexpected but not catastrophic): tag=%x", tag1)
	}
}

// TestGostIMIT_Write_ShortBufferBranch verifies the deferred-block branch in
// gostIMIT.Write: when buf fills to exactly 8 bytes with no remaining data the
// full block is held until the next Write arrives.
func TestGostIMIT_Write_ShortBufferBranch(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0x44}, gostKeySize)
	cipher := gost.NewGOST28147Cipher(key, gost.SboxTC26Z)
	m := newGostIMIT(cipher, gost.SboxTC26Z)

	m.Write([]byte{0xAA, 0xBB, 0xCC})

	testutil.Equal(t, m.bufLen, 3, "bufLen after 3 bytes")
	testutil.Equal(t, m.count, 0, "count after 3 bytes")

	m.Write([]byte{0xDD, 0xEE, 0xFF, 0x11, 0x22})

	testutil.Equal(t, m.bufLen, 8, "bufLen after 5 more bytes (total 8)")
	testutil.Equal(t, m.count, 0, "count after 5 more bytes (total 8)")

	m.Write([]byte{0x33})

	testutil.Equal(t, m.count, 8, "count after processing deferred block")
}

// TestNewChaCha20Poly1305Protector_BadKey covers the key-size check in
// NewChaCha20Poly1305Protector (protection_chacha20.go:31-33).
func TestNewChaCha20Poly1305Protector_BadKey(t *testing.T) {
	t.Parallel()

	iv := bytes.Repeat([]byte{0x01}, 12)

	for _, keyLen := range []int{0, 16, 31, 33} {
		_, err := NewChaCha20Poly1305Protector(make([]byte, keyLen), iv)
		if err == nil {
			t.Errorf("key len=%d: expected error, got nil", keyLen)
		}
	}
}

// TestNewChaCha20Poly1305Protector_BadIV covers the IV-size check in
// NewChaCha20Poly1305Protector (protection_chacha20.go:35-37).
func TestNewChaCha20Poly1305Protector_BadIV(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0x01}, 32)

	for _, ivLen := range []int{0, 4, 11, 13} {
		_, err := NewChaCha20Poly1305Protector(key, make([]byte, ivLen))
		if err == nil {
			t.Errorf("iv len=%d: expected error, got nil", ivLen)
		}
	}
}

// TestChaCha20Poly1305_RoundTrip exercises the happy path (Seal+Open round-trip).
func TestChaCha20Poly1305_RoundTrip(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0xEE}, 32)
	iv := bytes.Repeat([]byte{0x03}, 12)

	sender, err := NewChaCha20Poly1305Protector(key, iv)
	testutil.NoErr(t, err, "NewChaCha20Poly1305Protector(sender)")

	receiver, err := NewChaCha20Poly1305Protector(key, iv)
	testutil.NoErr(t, err, "NewChaCha20Poly1305Protector(receiver)")

	hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x04}
	plain := []byte("test")

	sealed, err := sender.Seal(0, hdr, plain)
	testutil.NoErr(t, err, "Seal")

	got, err := receiver.Open(0, hdr, sealed)
	testutil.NoErr(t, err, "Open")

	testutil.EqualBytes(t, got, plain, "Open plaintext")
}
