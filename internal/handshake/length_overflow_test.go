//nolint:testpackage // white-box: exercises the unexported length-prefix guards.
package handshake

import (
	"strings"
	"testing"

	"github.com/tarantool/go-gostls/internal/testutil"
)

// TestMarshal_OverLongServerName_Errors is the regression test for the silent
// truncation that used to happen here: marshalServerName wrote
// uint16(len(name)) with no check, so a name of 65536 bytes emitted a length
// field of 0 and produced a well-formed-looking but wrong extension.
func TestMarshal_OverLongServerName_Errors(t *testing.T) {
	t.Parallel()

	hello := &ClientHello{
		Version:            0x0303,
		CipherSuites:       []uint16{0x002F},
		CompressionMethods: []uint8{0x00},
		ServerName:         strings.Repeat("a", 1<<16),
	}

	_, err := hello.Marshal()
	testutil.ErrIs(t, err, errLenOverflow, "Marshal with a 65536-byte ServerName")
}

// TestMarshal_OverLongSessionID_Errors covers the uint8-prefixed field.
func TestMarshal_OverLongSessionID_Errors(t *testing.T) {
	t.Parallel()

	hello := &ClientHello{
		Version:            0x0303,
		SessionID:          make([]byte, 256), // uint8 prefix holds at most 255.
		CipherSuites:       []uint16{0x002F},
		CompressionMethods: []uint8{0x00},
	}

	_, err := hello.Marshal()
	testutil.ErrIs(t, err, errLenOverflow, "Marshal with a 256-byte SessionID")
}

// TestMarshal_OverLongCertificate_Errors covers the uint24-prefixed field.
func TestMarshal_OverLongCertificate_Errors(t *testing.T) {
	t.Parallel()

	certMsg := &Certificate{RawCerts: [][]byte{make([]byte, 1<<24)}}

	_, err := certMsg.Marshal()
	testutil.ErrIs(t, err, errLenOverflow, "Marshal with a 16MiB certificate")
}

// TestLenHelpers_Boundaries pins the exact accept/reject edge of each helper.
func TestLenHelpers_Boundaries(t *testing.T) {
	t.Parallel()

	_, err := u8Len(maxUint8, "x")
	if err != nil {
		t.Errorf("u8Len(%d): unexpected error: %v", maxUint8, err)
	}

	_, err = u8Len(maxUint8+1, "x")
	if err == nil {
		t.Errorf("u8Len(%d): expected an error", maxUint8+1)
	}

	_, err = u16Len(maxUint16, "x")
	if err != nil {
		t.Errorf("u16Len(%d): unexpected error: %v", maxUint16, err)
	}

	_, err = u16Len(maxUint16+1, "x")
	if err == nil {
		t.Errorf("u16Len(%d): expected an error", maxUint16+1)
	}

	_, err = u24Len(maxUint24, "x")
	if err != nil {
		t.Errorf("u24Len(%d): unexpected error: %v", maxUint24, err)
	}

	_, err = u24Len(maxUint24+1, "x")
	if err == nil {
		t.Errorf("u24Len(%d): expected an error", maxUint24+1)
	}
}
