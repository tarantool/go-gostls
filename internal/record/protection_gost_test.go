package record_test

import (
	"bytes"
	"fmt"
	"testing"

	gost "github.com/tarantool/go-gostcrypto"
	"github.com/tarantool/go-gostls/internal/record"
	"github.com/tarantool/go-gostls/internal/testutil"
)

// TestGOST_Protection_GOST28147_RoundTrip verifies Seal+Open round-trip with the
// TLS wire format Encrypt(plaintext || MAC). Uses separate send/recv protectors
// as in a real TLS session (each has its own CTR state).
func TestGOST_Protection_GOST28147_RoundTrip(t *testing.T) {
	t.Parallel()

	encKey := bytes.Repeat([]byte{0xAA}, 32)
	macKey := bytes.Repeat([]byte{0xBB}, 32)
	iv := bytes.Repeat([]byte{0x01}, 8)

	sender, err := record.NewGOST28147Protector(encKey, macKey, iv, gost.SboxTC26Z)
	testutil.NoErr(t, err, "NewGOST28147Protector (sender)")

	receiver, err := record.NewGOST28147Protector(encKey, macKey, iv, gost.SboxTC26Z)
	testutil.NoErr(t, err, "NewGOST28147Protector (receiver)")

	seq := uint64(0)
	hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x00}
	plain := []byte("hello GOST world")

	sealed, err := sender.Seal(seq, hdr, plain)
	testutil.NoErr(t, err, "Seal")

	testutil.Len(t, sealed, len(plain)+4, "sealed record")

	got, err := receiver.Open(seq, hdr, sealed)
	testutil.NoErr(t, err, "Open")

	testutil.EqualBytes(t, got, plain, "Open plaintext")
}

func TestGOST_Protection_TamperedMAC(t *testing.T) {
	t.Parallel()

	encKey := bytes.Repeat([]byte{0xCC}, 32)
	macKey := bytes.Repeat([]byte{0xDD}, 32)
	iv := bytes.Repeat([]byte{0x02}, 8)

	sender, err := record.NewGOST28147Protector(encKey, macKey, iv, gost.SboxTC26Z)
	testutil.NoErr(t, err, "NewGOST28147Protector (sender)")

	receiver, err := record.NewGOST28147Protector(encKey, macKey, iv, gost.SboxTC26Z)
	testutil.NoErr(t, err, "NewGOST28147Protector (receiver)")

	seq := uint64(1)
	hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x00}
	plain := []byte("tamper test data")

	sealed, err := sender.Seal(seq, hdr, plain)
	testutil.NoErr(t, err, "Seal")

	tampered := make([]byte, len(sealed))
	copy(tampered, sealed)

	tampered[len(tampered)-1] ^= 0xFF

	_, err = receiver.Open(seq, hdr, tampered)

	testutil.WantErr(t, err, "Open with tampered MAC")
}

func TestGOST_Protection_TamperedCiphertext(t *testing.T) {
	t.Parallel()

	encKey := bytes.Repeat([]byte{0xEE}, 32)
	macKey := bytes.Repeat([]byte{0xFF}, 32)
	iv := bytes.Repeat([]byte{0x03}, 8)

	sender, err := record.NewGOST28147Protector(encKey, macKey, iv, gost.SboxTC26Z)
	testutil.NoErr(t, err, "NewGOST28147Protector (sender)")

	receiver, err := record.NewGOST28147Protector(encKey, macKey, iv, gost.SboxTC26Z)
	testutil.NoErr(t, err, "NewGOST28147Protector (receiver)")

	seq := uint64(2)
	hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x00}
	plain := []byte("ciphertext tamper test")

	sealed, err := sender.Seal(seq, hdr, plain)
	testutil.NoErr(t, err, "Seal")

	tampered := make([]byte, len(sealed))
	copy(tampered, sealed)

	tampered[0] ^= 0x01

	_, err = receiver.Open(seq, hdr, tampered)

	testutil.WantErr(t, err, "Open with tampered ciphertext")
}

func TestGOST_Protection_MultiRecord(t *testing.T) {
	t.Parallel()

	encKey := bytes.Repeat([]byte{0x11}, 32)
	macKey := bytes.Repeat([]byte{0x22}, 32)
	iv := bytes.Repeat([]byte{0x04}, 8)

	sender, err := record.NewGOST28147Protector(encKey, macKey, iv, gost.SboxTC26Z)
	testutil.NoErr(t, err, "NewGOST28147Protector (sender)")

	receiver, err := record.NewGOST28147Protector(encKey, macKey, iv, gost.SboxTC26Z)
	testutil.NoErr(t, err, "NewGOST28147Protector (receiver)")

	// Send multiple records and verify CTR state carries across them.
	for seq := range uint64(5) {
		plain := make([]byte, 100)
		for i := range plain {
			plain[i] = byte(seq*100 + uint64(i))
		}

		hdr := []byte{0x17, 0x03, 0x03, 0x00, 0x00}

		sealed, err := sender.Seal(seq, hdr, plain)
		testutil.NoErr(t, err, fmt.Sprintf("Seal seq=%d", seq))

		got, err := receiver.Open(seq, hdr, sealed)
		testutil.NoErr(t, err, fmt.Sprintf("Open seq=%d", seq))

		if !bytes.Equal(got, plain) {
			t.Errorf("Open seq=%d: plaintext mismatch", seq)
		}
	}
}
