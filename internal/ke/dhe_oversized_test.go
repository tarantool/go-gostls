//nolint:testpackage // white-box: drives validateDHEParams and the unexported limits.
package ke

import (
	"errors"
	"fmt"
	"testing"

	"github.com/tarantool/go-gostls/internal/testutil"
)

// TestDHE_OversizedPrimeRejected is the regression test for a
// server-triggerable defect: p had a minimum but no maximum, while a handshake
// message may be up to 256 KiB. A prime longer than 65535 bytes made
// len(YcPadded) wrap its uint16 length prefix, so the client emitted a
// ClientKeyExchange whose declared length disagreed with its payload.
func TestDHE_OversizedPrimeRejected(t *testing.T) {
	t.Parallel()

	// 70000-byte odd "prime": over the uint16 prefix, under maxHandshakeMsg.
	const oversized = 70000

	pBytes := make([]byte, oversized)

	pBytes[0] = 0xFF
	pBytes[len(pBytes)-1] = 0x01 // odd, so the primality precondition passes.

	err := validateDHEParams(pBytes, []byte{0x02}, []byte{0x03})
	testutil.WantErr(t, err, "a 70000-byte prime must be rejected")

	if !errors.Is(err, errDHEPTooLong) {
		t.Errorf("expected errDHEPTooLong, got %v", err)
	}
}

// TestDHE_OversizedPrime_WouldHaveWrapped documents the concrete wire damage
// the check prevents, so the reason for the bound is not lost.
func TestDHE_OversizedPrime_WouldHaveWrapped(t *testing.T) {
	t.Parallel()

	// A variable, not a constant: Go rejects a constant conversion that
	// overflows, but the runtime conversion this guards silently wraps.
	oversized := 70000

	got := uint16(oversized)

	testutil.Equal(t, got, uint16(4464), "uint16(70000)")

	t.Logf("uint16(%d) wraps to %d — the length prefix would have understated "+
		"the payload by %d bytes", oversized, got, oversized-int(got))
}

// TestDHE_PrimeAtLimitAccepted pins the upper edge: a prime of exactly
// dheMaxPBits must still pass parameter validation.
func TestDHE_PrimeAtLimitAccepted(t *testing.T) {
	t.Parallel()

	pBytes := make([]byte, dheMaxPBits/8)

	pBytes[0] = 0xFF
	pBytes[len(pBytes)-1] = 0x01

	err := validateDHEParams(pBytes, []byte{0x02}, []byte{0x03})
	testutil.ErrNotIs(t, err, errDHEPTooLong, fmt.Sprintf("a prime of exactly %d bits must be accepted", dheMaxPBits))
}
