package testutil

import (
	"fmt"
	"math"
)

// The builders below assemble the big-endian integers and length-prefixed
// vectors that TLS wire formats are made of (RFC 8446 section 3.4, RFC 5246
// section 4.3). Every test package that constructs a message by hand had grown
// its own copy — appendU16LenPrefixed in the root and ke suites,
// appendU16FieldWB in ke's white-box tests, appendU16PrefixedSlice in
// handshake's — with the same body and different names.
//
// They append to dst and return the extended slice, the same shape as the
// stdlib's append and binary.BigEndian.AppendUint16, so a message is built as
// one expression:
//
//	body := testutil.AppendU16(nil, uint16(suiteID))
//	body = testutil.AppendU8Prefixed(body, sessionID)
//
// A vector too long for its length prefix panics rather than silently writing a
// truncated length. The copies this replaces all truncated, which is a lie the
// test cannot see: the prefix says 4 bytes, the payload is 65540, and the parser
// under test is then measured against a message no peer would send. Tests that
// deliberately want a lying prefix — the length-overflow and fuzz cases — must
// write those two bytes themselves, so that the lie is visible at the call site.

// AppendU16 appends v as two big-endian bytes.
func AppendU16(dst []byte, v uint16) []byte {
	//nolint:gosec // Splitting a uint16 into its two bytes; the truncation is the operation.
	return append(dst, byte(v>>shift8), byte(v))
}

// AppendU24 appends the low 24 bits of v as three big-endian bytes. TLS uses
// this width for handshake message lengths and certificate vectors; v must fit
// in 24 bits.
func AppendU24(dst []byte, v uint32) []byte {
	if v > maxU24 {
		panic(fmt.Sprintf("testutil.AppendU24: %d does not fit in 24 bits", v))
	}

	//nolint:gosec // Bounded by the check above; the truncation is the operation.
	return append(dst, byte(v>>shift16), byte(v>>shift8), byte(v))
}

// AppendU8Prefixed appends data behind a one-byte length prefix.
func AppendU8Prefixed(dst, data []byte) []byte {
	if len(data) > math.MaxUint8 {
		panic(fmt.Sprintf("testutil.AppendU8Prefixed: %d bytes exceed a uint8 length prefix", len(data)))
	}

	//nolint:gosec // The bound above is exactly what makes this conversion exact.
	return append(append(dst, byte(len(data))), data...)
}

// AppendU16Prefixed appends data behind a two-byte big-endian length prefix.
// This is the common case: extensions, DHE parameters, signatures and most
// handshake vectors are framed this way.
func AppendU16Prefixed(dst, data []byte) []byte {
	if len(data) > math.MaxUint16 {
		panic(fmt.Sprintf("testutil.AppendU16Prefixed: %d bytes exceed a uint16 length prefix", len(data)))
	}

	//nolint:gosec // The bound above is exactly what makes this conversion exact.
	return append(AppendU16(dst, uint16(len(data))), data...)
}

// AppendU24Prefixed appends data behind a three-byte big-endian length prefix,
// the framing of a handshake message body and of the certificate list inside it.
func AppendU24Prefixed(dst, data []byte) []byte {
	if len(data) > maxU24 {
		panic(fmt.Sprintf("testutil.AppendU24Prefixed: %d bytes exceed a uint24 length prefix", len(data)))
	}

	//nolint:gosec // The bound above is exactly what makes this conversion exact.
	return append(AppendU24(dst, uint32(len(data))), data...)
}

const (
	// maxU24 is the largest value a three-byte TLS length prefix can carry.
	maxU24 = 1<<24 - 1

	// shift8 and shift16 name the byte positions the big-endian splits above
	// pick out, matching the spelling in internal/record/protection_gost.go.
	shift8  = 8
	shift16 = 16
)
