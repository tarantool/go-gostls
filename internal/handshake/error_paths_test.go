// Tests for the malformed-input / error branches that were below target
// coverage in wire.go, extensions.go, messages.go, crypto.go, and client.go.

//nolint:testpackage // white-box: exercises unexported parsing helpers
package handshake

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/tarantool/go-gostls/internal/record"
	"github.com/tarantool/go-gostls/internal/suites"
	"github.com/tarantool/go-gostls/internal/testutil"
)

// ============================================================.
// wire.go — readUint16.
// ============================================================.

func TestReadUint16_Empty(t *testing.T) {
	t.Parallel()

	_, _, err := readUint16(nil)
	testutil.ErrIs(t, err, errTruncated2, "readUint16")
}

func TestReadUint16_OneByte(t *testing.T) {
	t.Parallel()

	_, _, err := readUint16([]byte{0x01})
	testutil.ErrIs(t, err, errTruncated2, "readUint16")
}

func TestReadUint16_Success(t *testing.T) {
	t.Parallel()

	v, rest, err := readUint16([]byte{0x01, 0x02, 0x03})
	testutil.NoErr(t, err, "readUint16")

	if v != 0x0102 {
		t.Errorf("value: got 0x%04x, want 0x0102", v)
	}

	if !bytes.Equal(rest, []byte{0x03}) {
		t.Errorf("rest: got %x, want [03]", rest)
	}
}

// ============================================================.
// wire.go — readLenPrefixed8.
// ============================================================.

func TestReadLenPrefixed8_EmptyInput(t *testing.T) {
	t.Parallel()

	_, _, err := readLenPrefixed8(nil)
	testutil.ErrIs(t, err, errPfxUint8, "readLenPrefixed8")
}

func TestReadLenPrefixed8_BodyTruncated(t *testing.T) {
	t.Parallel()

	// Length byte = 5 but only 2 bytes of body follow.
	_, _, err := readLenPrefixed8([]byte{0x05, 0xAA, 0xBB})
	testutil.ErrIs(t, err, errBodyShort, "readLenPrefixed8")
}

func TestReadLenPrefixed8_Success(t *testing.T) {
	t.Parallel()

	body, rest, err := readLenPrefixed8([]byte{0x02, 0xAA, 0xBB, 0xCC})
	testutil.NoErr(t, err, "readLenPrefixed8")

	if !bytes.Equal(body, []byte{0xAA, 0xBB}) {
		t.Errorf("body: got %x, want [AA BB]", body)
	}

	if !bytes.Equal(rest, []byte{0xCC}) {
		t.Errorf("rest: got %x, want [CC]", rest)
	}
}

// ============================================================.
// wire.go — readLenPrefixed16.
// ============================================================.

func TestReadLenPrefixed16_EmptyInput(t *testing.T) {
	t.Parallel()

	_, _, err := readLenPrefixed16(nil)
	testutil.ErrIs(t, err, errPfxUint16, "readLenPrefixed16")
}

func TestReadLenPrefixed16_OneByte(t *testing.T) {
	t.Parallel()

	_, _, err := readLenPrefixed16([]byte{0x00})
	testutil.ErrIs(t, err, errPfxUint16, "readLenPrefixed16")
}

func TestReadLenPrefixed16_BodyTruncated(t *testing.T) {
	t.Parallel()

	// Prefix declares 10 bytes, only 3 follow.
	_, _, err := readLenPrefixed16([]byte{0x00, 0x0A, 0x01, 0x02, 0x03})
	testutil.ErrIs(t, err, errBodyShort, "readLenPrefixed16")
}

func TestReadLenPrefixed16_Success(t *testing.T) {
	t.Parallel()

	body, rest, err := readLenPrefixed16([]byte{0x00, 0x02, 0xAA, 0xBB, 0xCC})
	testutil.NoErr(t, err, "readLenPrefixed16")

	if !bytes.Equal(body, []byte{0xAA, 0xBB}) {
		t.Errorf("body: got %x, want [AA BB]", body)
	}

	if !bytes.Equal(rest, []byte{0xCC}) {
		t.Errorf("rest: got %x, want [CC]", rest)
	}
}

// ============================================================.
// wire.go — readLenPrefixed24.
// ============================================================.

func TestReadLenPrefixed24_EmptyInput(t *testing.T) {
	t.Parallel()

	_, _, err := readLenPrefixed24(nil)
	testutil.ErrIs(t, err, errPfxUint24, "readLenPrefixed24")
}

func TestReadLenPrefixed24_TwoBytesOnly(t *testing.T) {
	t.Parallel()

	_, _, err := readLenPrefixed24([]byte{0x00, 0x00})
	testutil.ErrIs(t, err, errPfxUint24, "readLenPrefixed24")
}

func TestReadLenPrefixed24_BodyTruncated(t *testing.T) {
	t.Parallel()

	// Prefix declares 5 bytes, only 2 follow.
	_, _, err := readLenPrefixed24([]byte{0x00, 0x00, 0x05, 0xAA, 0xBB})
	testutil.ErrIs(t, err, errBodyShort, "readLenPrefixed24")
}

func TestReadLenPrefixed24_Success(t *testing.T) {
	t.Parallel()

	body, rest, err := readLenPrefixed24([]byte{0x00, 0x00, 0x02, 0xAA, 0xBB, 0xCC})
	testutil.NoErr(t, err, "readLenPrefixed24")

	if !bytes.Equal(body, []byte{0xAA, 0xBB}) {
		t.Errorf("body: got %x, want [AA BB]", body)
	}

	if !bytes.Equal(rest, []byte{0xCC}) {
		t.Errorf("rest: got %x, want [CC]", rest)
	}
}

// ============================================================.
// extensions.go — parseServerName.
// ============================================================.

func TestParseServerName_EmptyBody(t *testing.T) {
	t.Parallel()

	// Empty body is valid in ServerHello — returns ("", nil).
	name, err := parseServerName(nil)
	testutil.NoErr(t, err, "empty body should be OK")

	if name != "" {
		t.Errorf("expected empty name, got %q", name)
	}
}

func TestParseServerName_TruncatedListLen(t *testing.T) {
	t.Parallel()

	// 1 byte only — need 2 for the uint16 list length.
	_, err := parseServerName([]byte{0x00})
	testutil.ErrIs(t, err, errSNITruncatedListLen, "parseServerName")
}

func TestParseServerName_ListLenExceeds(t *testing.T) {
	t.Parallel()

	// list_len=100 but only 2 bytes of data follow the length field.
	_, err := parseServerName([]byte{0x00, 0x64, 0xAA, 0xBB})
	testutil.ErrIs(t, err, errSNIListLenExceeds, "parseServerName")
}

func TestParseServerName_TruncatedEntry(t *testing.T) {
	t.Parallel()

	// list_len = 2, content = [0xAA, 0xBB] — too short for min entry (3 bytes).
	_, err := parseServerName([]byte{0x00, 0x02, 0xAA, 0xBB})
	testutil.ErrIs(t, err, errSNITruncatedEntry, "parseServerName")
}

func TestParseServerName_NameLenExceeds(t *testing.T) {
	t.Parallel()

	// list_len=5: [type=0x00, name_len_hi=0x00, name_len_lo=0x64, AA, BB].
	// name_len=100 but list only has 2 bytes after the 3-byte header.
	_, err := parseServerName([]byte{0x00, 0x05, 0x00, 0x00, 0x64, 0xAA, 0xBB})
	testutil.ErrIs(t, err, errSNINameLenExceeds, "parseServerName")
}

func TestParseServerName_UnsupportedNameType(t *testing.T) {
	t.Parallel()

	// name_type = 0x01 (not host_name=0x00). list_len=6: type=0x01, name_len=3, name=[AA BB CC].
	_, err := parseServerName([]byte{0x00, 0x06, 0x01, 0x00, 0x03, 0xAA, 0xBB, 0xCC})
	testutil.ErrIs(t, err, errSNIUnsupportedNameType, "parseServerName")
}

func TestParseServerName_HappyPath(t *testing.T) {
	t.Parallel()

	name := "example.com"

	body, bodyMErr := marshalServerName(name)
	testutil.NoErr(t, bodyMErr, "marshalServerName")

	got, err := parseServerName(body)
	testutil.NoErr(t, err, fmt.Sprintf("parseServerName(%q)", name))

	if got != name {
		t.Errorf("got %q, want %q", got, name)
	}
}

// ============================================================.
// extensions.go — parseSupportedGroups.
// ============================================================.

func TestParseSupportedGroups_TruncatedListLen(t *testing.T) {
	t.Parallel()

	// Only 1 byte when 2 are needed for the list length.
	_, err := parseSupportedGroups([]byte{0x00})
	testutil.ErrIs(t, err, errSGTruncatedListLen, "parseSupportedGroups")
}

func TestParseSupportedGroups_ListLenExceeds(t *testing.T) {
	t.Parallel()

	// list_len=100 but only 2 bytes of data follow.
	_, err := parseSupportedGroups([]byte{0x00, 0x64, 0xAA, 0xBB})
	testutil.ErrIs(t, err, errSGListLenExceeds, "parseSupportedGroups")
}

func TestParseSupportedGroups_OddListLen(t *testing.T) {
	t.Parallel()

	// list_len=3 (odd) with 3 bytes of data.
	_, err := parseSupportedGroups([]byte{0x00, 0x03, 0xAA, 0xBB, 0xCC})
	testutil.ErrIs(t, err, errSGOddListLen, "parseSupportedGroups")
}

func TestParseSupportedGroups_HappyPath(t *testing.T) {
	t.Parallel()

	groups := []uint16{0x0017, 0x0018}

	body, bodyMErr := marshalSupportedGroups(groups)
	testutil.NoErr(t, bodyMErr, "marshalSupportedGroups")

	got, err := parseSupportedGroups(body)
	testutil.NoErr(t, err, "parseSupportedGroups")

	if len(got) != len(groups) {
		t.Fatalf("len: got %d, want %d", len(got), len(groups))
	}

	for i, g := range groups {
		if got[i] != g {
			t.Errorf("[%d]: got 0x%04x, want 0x%04x", i, got[i], g)
		}
	}
}

// ============================================================.
// extensions.go — parseSignatureAlgorithms.
// ============================================================.

func TestParseSignatureAlgorithms_TruncatedListLen(t *testing.T) {
	t.Parallel()

	_, err := parseSignatureAlgorithms([]byte{0x00})
	testutil.ErrIs(t, err, errSATruncatedListLen, "parseSignatureAlgorithms")
}

func TestParseSignatureAlgorithms_ListLenExceeds(t *testing.T) {
	t.Parallel()

	// list_len=100 but only 2 bytes follow.
	_, err := parseSignatureAlgorithms([]byte{0x00, 0x64, 0xAA, 0xBB})
	testutil.ErrIs(t, err, errSAListLenExceeds, "parseSignatureAlgorithms")
}

func TestParseSignatureAlgorithms_OddListLen(t *testing.T) {
	t.Parallel()

	// list_len=3 (odd) with 3 bytes of data.
	_, err := parseSignatureAlgorithms([]byte{0x00, 0x03, 0x04, 0x01, 0x05})
	testutil.ErrIs(t, err, errSAOddListLen, "parseSignatureAlgorithms")
}

func TestParseSignatureAlgorithms_HappyPath(t *testing.T) {
	t.Parallel()

	pairs := []SigAndHash{{Hash: 0x04, Sig: 0x01}, {Hash: 0x05, Sig: 0x03}}

	body, bodyMErr := marshalSignatureAlgorithms(pairs)
	testutil.NoErr(t, bodyMErr, "marshalSignatureAlgorithms")

	got, err := parseSignatureAlgorithms(body)
	testutil.NoErr(t, err, "parseSignatureAlgorithms")

	if len(got) != len(pairs) {
		t.Fatalf("len: got %d, want %d", len(got), len(pairs))
	}

	for i, p := range pairs {
		if got[i] != p {
			t.Errorf("[%d]: got %v, want %v", i, got[i], p)
		}
	}
}

// ============================================================.
// extensions.go — parseECPointFormats.
// ============================================================.

func TestParseECPointFormats_EmptyInput(t *testing.T) {
	t.Parallel()

	_, err := parseECPointFormats(nil)
	testutil.ErrIs(t, err, errEPFTruncatedListLen, "parseECPointFormats")
}

func TestParseECPointFormats_ListLenExceeds(t *testing.T) {
	t.Parallel()

	// Length byte = 10, but only 2 bytes follow.
	_, err := parseECPointFormats([]byte{0x0A, 0xAA, 0xBB})
	testutil.ErrIs(t, err, errEPFListLenExceeds, "parseECPointFormats")
}

func TestParseECPointFormats_HappyPath(t *testing.T) {
	t.Parallel()

	formats := []uint8{0x00, 0x01}

	body, bodyMErr := marshalECPointFormats(formats)
	testutil.NoErr(t, bodyMErr, "marshalECPointFormats")

	got, err := parseECPointFormats(body)
	testutil.NoErr(t, err, "parseECPointFormats")

	if len(got) != len(formats) {
		t.Fatalf("len: got %d, want %d", len(got), len(formats))
	}

	for i, f := range formats {
		if got[i] != f {
			t.Errorf("[%d]: got 0x%02x, want 0x%02x", i, got[i], f)
		}
	}
}

// ============================================================.
// extensions.go — parseRenegotiationInfo.
// ============================================================.

func TestParseRenegotiationInfo_EmptyInput(t *testing.T) {
	t.Parallel()

	err := parseRenegotiationInfo(nil)
	testutil.ErrIs(t, err, errRITruncatedBody, "parseRenegotiationInfo")
}

func TestParseRenegotiationInfo_DeclaredLenExceeds(t *testing.T) {
	t.Parallel()

	// ri_len=5 but only 2 bytes of data follow the length byte.
	err := parseRenegotiationInfo([]byte{0x05, 0xAA, 0xBB})
	testutil.ErrIs(t, err, errRIDeclaredLenExceeds, "parseRenegotiationInfo")
}

func TestParseRenegotiationInfo_NonEmpty(t *testing.T) {
	t.Parallel()

	// ri_len=2 with 2 bytes — body is non-empty (renegotiation active).
	err := parseRenegotiationInfo([]byte{0x02, 0xAA, 0xBB})
	testutil.ErrIs(t, err, errRINonEmpty, "parseRenegotiationInfo")
}

func TestParseRenegotiationInfo_EmptyRIBody(t *testing.T) {
	t.Parallel()

	// ri_len=0 — valid initial-handshake marker.
	err := parseRenegotiationInfo([]byte{0x00})
	testutil.NoErr(t, err, "empty RI body should be OK")
}

// ============================================================.
// extensions.go — parseExtensions (header-level errors).
// ============================================================.

func TestParseExtensions_TruncatedHeader(t *testing.T) {
	t.Parallel()

	// 3 bytes — need 4 for the extension header (type=2 + len=2).
	_, _, err := parseExtensions([]byte{0x00, 0x00, 0x00})
	testutil.ErrIs(t, err, errExtHeaderTruncated, "parseExtensions")
}

func TestParseExtensions_BodyTruncated(t *testing.T) {
	t.Parallel()

	// Header: type=0x0000 (SNI), len=10 — but only 0 bytes of body follow.
	_, _, err := parseExtensions([]byte{0x00, 0x00, 0x00, 0x0A})
	testutil.ErrIs(t, err, errExtBodyTruncated, "parseExtensions")
}

// ============================================================.
// messages.go — parseClientHello error paths.
// ============================================================.

// buildMinimalClientHelloBytes marshals a valid minimal ClientHello body.
func buildMinimalClientHelloBytes() []byte {
	ch := &ClientHello{
		Version:            0x0303,
		CipherSuites:       []uint16{0x002F},
		CompressionMethods: []uint8{0x00},
	}

	// Fixed, in-range input: it cannot overflow a length prefix.
	return testutil.Must(ch.Marshal())
}

func TestParseClientHello_TruncatedVersion(t *testing.T) {
	t.Parallel()

	// Only 1 byte — can't read 2-byte version.
	_, err := parseClientHello([]byte{0x03})
	testutil.WantErr(t, err, "parseClientHello")
}

func TestParseClientHello_TruncatedRandom(t *testing.T) {
	t.Parallel()

	// version OK, but random needs 32 bytes and we only have 4.
	_, err := parseClientHello([]byte{0x03, 0x03, 0x01, 0x02, 0x03, 0x04})
	testutil.WantErr(t, err, "parseClientHello")
}

func TestParseClientHello_SessionIDTooLong(t *testing.T) {
	t.Parallel()

	// Build a valid CH body and inject a session_id length of 33 at offset 34.
	// The session_id starts at offset 34 (2 version + 32 random).
	body := buildMinimalClientHelloBytes()
	sessionIDOffset := 34

	injected := make([]byte, sessionIDOffset+1+33)
	copy(injected, body[:sessionIDOffset])

	injected[sessionIDOffset] = 33 // length byte = 33 > maxSessionIDLen(32).

	for i := 1; i <= 33; i++ {
		injected[sessionIDOffset+i] = byte(i)
	}

	_, err := parseClientHello(injected)
	testutil.ErrIs(t, err, errCHSessionIDTooLong, "parseClientHello")
}

func TestParseClientHello_CSOddByteCount(t *testing.T) {
	t.Parallel()

	// After version(2) + random(32) + session_id(1+0), cipher_suites has odd byte count.
	body := make([]byte, 0, 40)

	body = append(body, 0x03, 0x03)          // version.
	body = append(body, make([]byte, 32)...) // random.
	body = append(body, 0x00)                // session_id length = 0.
	body = append(body, 0x00, 0x03)          // cipher_suites byte_len = 3 (odd).
	body = append(body, 0x00, 0x2F, 0x01)    // 3 bytes (invalid).

	_, err := parseClientHello(body)
	testutil.ErrIs(t, err, errCHCSOddByteCount, "parseClientHello")
}

func TestParseClientHello_CSAtLeastOne(t *testing.T) {
	t.Parallel()

	// cipher_suites length = 0 — must have at least one.
	body := make([]byte, 0, 38)

	body = append(body, 0x03, 0x03)          // version.
	body = append(body, make([]byte, 32)...) // random.
	body = append(body, 0x00)                // session_id length = 0.
	body = append(body, 0x00, 0x00)          // cipher_suites: 0 bytes.

	_, err := parseClientHello(body)
	testutil.ErrIs(t, err, errCHCSAtLeastOne, "parseClientHello")
}

func TestParseClientHello_CMAtLeastOne(t *testing.T) {
	t.Parallel()

	// compression_methods length = 0 — must have at least one.
	body := make([]byte, 0, 41)

	body = append(body, 0x03, 0x03)          // version.
	body = append(body, make([]byte, 32)...) // random.
	body = append(body, 0x00)                // session_id length = 0.
	body = append(body, 0x00, 0x02)          // cipher_suites: 2 bytes.
	body = append(body, 0x00, 0x2F)          // one suite.
	body = append(body, 0x00)                // compression_methods length = 0.

	_, err := parseClientHello(body)
	testutil.ErrIs(t, err, errCHCMAtLeastOne, "parseClientHello")
}

func TestParseClientHello_ExtensionsTruncated(t *testing.T) {
	t.Parallel()

	// Valid minimal CH body, then append a 1-byte "extensions" section
	// (the outer uint16 prefix needs 2 bytes).
	body := buildMinimalClientHelloBytes()

	body = append(body, 0x00) // only 1 byte where 2 needed.

	_, err := parseClientHello(body)
	testutil.WantErr(t, err, "parseClientHello")
}

// ============================================================.
// messages.go — parseServerHello error paths.
// ============================================================.

func TestParseServerHello_TruncatedVersion(t *testing.T) {
	t.Parallel()

	_, err := parseServerHello([]byte{0x03})
	testutil.WantErr(t, err, "parseServerHello")
}

func TestParseServerHello_TruncatedRandom(t *testing.T) {
	t.Parallel()

	_, err := parseServerHello([]byte{0x03, 0x03, 0x00, 0x00})
	testutil.WantErr(t, err, "parseServerHello")
}

func TestParseServerHello_SessionIDTooLong(t *testing.T) {
	t.Parallel()

	// version(2) + random(32) + session_id_len(1)+data(33) — session_id > 32.
	body := make([]byte, 0, 68)

	body = append(body, 0x03, 0x03)          // version.
	body = append(body, make([]byte, 32)...) // random.
	body = append(body, 0x21)                // session_id_len = 33 > 32.
	body = append(body, make([]byte, 33)...) // session_id data.

	_, err := parseServerHello(body)
	testutil.ErrIs(t, err, errSHSessionIDTooLong, "parseServerHello")
}

func TestParseServerHello_TruncatedCipherSuite(t *testing.T) {
	t.Parallel()

	// version(2) + random(32) + session_id_len(1)=0 + only 1 byte of cipher_suite.
	body := make([]byte, 0, 36)

	body = append(body, 0x03, 0x03)          // version.
	body = append(body, make([]byte, 32)...) // random.
	body = append(body, 0x00)                // session_id_len = 0.
	body = append(body, 0x00)                // only 1 byte of cipher_suite (need 2).

	_, err := parseServerHello(body)
	testutil.WantErr(t, err, "parseServerHello")
}

func TestParseServerHello_TruncatedCompressionMethod(t *testing.T) {
	t.Parallel()

	// version(2) + random(32) + session_id_len(1)=0 + cipher_suite(2) — no compression_method.
	body := make([]byte, 0, 37)

	body = append(body, 0x03, 0x03)          // version.
	body = append(body, make([]byte, 32)...) // random.
	body = append(body, 0x00)                // session_id_len = 0.
	body = append(body, 0x00, 0x2F)          // cipher_suite.
	// compression_method byte absent.

	_, err := parseServerHello(body)
	testutil.WantErr(t, err, "parseServerHello")
}

func TestParseServerHello_ExtensionsTruncated(t *testing.T) {
	t.Parallel()

	sh := &ServerHello{
		Version:           0x0303,
		CipherSuite:       0x002F,
		CompressionMethod: 0x00,
	}

	body, bodyMErr := sh.Marshal()
	testutil.NoErr(t, bodyMErr, "sh.Marshal")

	body = append(body, 0x00) // only 1 byte of extensions prefix (need 2).

	_, err := parseServerHello(body)
	testutil.WantErr(t, err, "parseServerHello")
}

// ============================================================.
// messages.go — parseCertificate error paths.
// ============================================================.

func TestParseCertificate_TruncatedOuterLen(t *testing.T) {
	t.Parallel()

	// Only 2 bytes — need 3 for the outer uint24 length prefix.
	_, err := parseCertificate([]byte{0x00, 0x00})
	testutil.WantErr(t, err, "parseCertificate")
}

func TestParseCertificate_OuterLenExceedsData(t *testing.T) {
	t.Parallel()

	// outer_len=100 but only 2 bytes of cert list follow.
	_, err := parseCertificate([]byte{0x00, 0x00, 0x64, 0xAA, 0xBB})
	testutil.WantErr(t, err, "parseCertificate")
}

func TestParseCertificate_EntryLenExceedsData(t *testing.T) {
	t.Parallel()

	// outer_len=6: entry_len=100 but only 2 bytes follow in the list.
	_, err := parseCertificate([]byte{0x00, 0x00, 0x06, 0x00, 0x00, 0x64, 0xAA, 0xBB})
	testutil.WantErr(t, err, "parseCertificate")
}

func TestParseCertificate_ZeroLengthEntry(t *testing.T) {
	t.Parallel()

	// outer_len=3: entry_len=0 → errCertEntryZeroLen.
	_, err := parseCertificate([]byte{0x00, 0x00, 0x03, 0x00, 0x00, 0x00})
	testutil.ErrIs(t, err, errCertEntryZeroLen, "parseCertificate")
}

func TestParseCertificate_HappyPath(t *testing.T) {
	t.Parallel()

	cert := &Certificate{RawCerts: [][]byte{{0x30, 0x01, 0xAA}}}

	body, bodyMErr := cert.Marshal()
	testutil.NoErr(t, bodyMErr, "cert.Marshal")

	got, err := parseCertificate(body)
	testutil.NoErr(t, err, "parseCertificate")

	testutil.Len(t, got.RawCerts, 1, "got.RawCerts")

	testutil.EqualBytes(t, got.RawCerts[0], cert.RawCerts[0], "got.RawCerts[0]")
}

// ============================================================.
// messages.go — parseCertificateVerify error paths.
// ============================================================.

func TestParseCertificateVerify_TruncatedHash(t *testing.T) {
	t.Parallel()

	// Empty body — can't read hash byte.
	_, err := parseCertificateVerify(nil)
	testutil.WantErr(t, err, "parseCertificateVerify")
}

func TestParseCertificateVerify_TruncatedSig(t *testing.T) {
	t.Parallel()

	// hash=0x04, sig=0x01, but no sig_len or sig data.
	_, err := parseCertificateVerify([]byte{0x04, 0x01})
	testutil.WantErr(t, err, "parseCertificateVerify")
}

func TestParseCertificateVerify_SigTruncated(t *testing.T) {
	t.Parallel()

	// hash=0x04, sig=0x01, sig_len=10 but only 2 bytes of sig data.
	_, err := parseCertificateVerify([]byte{0x04, 0x01, 0x00, 0x0A, 0xAA, 0xBB})
	testutil.WantErr(t, err, "parseCertificateVerify")
}

func TestParseCertificateVerify_HappyPath(t *testing.T) {
	t.Parallel()

	cv := &CertificateVerify{
		Algorithm: SigAndHash{Hash: 0x04, Sig: 0x01},
		Signature: []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}

	body, bodyMErr := cv.Marshal()
	testutil.NoErr(t, bodyMErr, "cv.Marshal")

	got, err := parseCertificateVerify(body)
	testutil.NoErr(t, err, "parseCertificateVerify")

	if got.Algorithm != cv.Algorithm {
		t.Errorf("algorithm: got %v, want %v", got.Algorithm, cv.Algorithm)
	}

	testutil.EqualBytes(t, got.Signature, cv.Signature, "got.Signature")
}

// ============================================================.
// crypto.go — buildProtector: unsupported AEAD and MAC branches.
// ============================================================.

func TestBuildProtector_UnsupportedAEAD(t *testing.T) {
	t.Parallel()

	// Synthesise a suite with AEAD=true but an unrecognised cipher name.
	validSuite := mustLookupSuite(t, "ECDHE-RSA-AES128-GCM-SHA256")
	fakeSuite := *validSuite

	fakeSuite.Cipher.Name = "AES-128-OCB" // not AES-GCM or ChaCha20.

	_, err := buildProtector(&fakeSuite, make([]byte, 16), nil, make([]byte, 4), nil)
	testutil.ErrIs(t, err, errUnsupportedAEAD, "buildProtector")
}

func TestBuildProtector_UnsupportedMACLen(t *testing.T) {
	t.Parallel()

	// CBC suite with an unusual MAC length (not 20/32/48).
	validSuite := mustLookupSuite(t, "ECDHE-RSA-AES128-SHA256")
	fakeSuite := *validSuite

	fakeSuite.MAC.MACLen = 24 // unsupported.

	_, err := buildProtector(&fakeSuite, make([]byte, 16), make([]byte, 24), nil, nil)
	testutil.ErrIs(t, err, errUnsupportedMACLen, "buildProtector")
}

func TestBuildProtector_UnsupportedCBCCipher(t *testing.T) {
	t.Parallel()

	// CBC suite with an unrecognised cipher name.
	validSuite := mustLookupSuite(t, "ECDHE-RSA-AES128-SHA256")
	fakeSuite := *validSuite

	fakeSuite.Cipher.Name = "DES-CBC" // not AES.

	_, err := buildProtector(&fakeSuite, make([]byte, 8), make([]byte, 20), nil, nil)
	testutil.ErrIs(t, err, errUnsupportedCBCCipher, "buildProtector")
}

func TestBuildProtector_SHA1MAC(t *testing.T) {
	t.Parallel()

	// Exercise the SHA-1 HMAC branch (MACLen=20).
	var suite *suites.Suite

	for _, s := range suites.All() {
		if !s.Cipher.AEAD && s.Cipher.Name == "AES-128-CBC" && s.MAC.MACLen == 20 {
			suite = s

			break
		}
	}

	if suite == nil {
		t.Skip("no AES-128-CBC/SHA-1 suite in registry")
	}

	prot, err := buildProtector(suite, make([]byte, suite.Cipher.KeyLen), make([]byte, suite.MAC.KeyLen), nil, nil)
	testutil.NoErr(t, err, "buildProtector SHA-1 CBC")

	if prot == nil {
		t.Error("expected non-nil protector")
	}
}

// ============================================================.
// client.go — computeKeyExchange: DHE dispatch.
// ============================================================.

func TestComputeKeyExchange_DHE(t *testing.T) {
	t.Parallel()

	rsaKey, cert, _ := newTestRSACert(t)

	var clientRandom, serverRandom [32]byte

	for i := range clientRandom {
		clientRandom[i] = byte(i + 1)
		serverRandom[i] = byte(i + 2)
	}

	dheBody := buildDHESKEBodyReal(t, rsaKey, clientRandom, serverRandom)

	suite := mustLookupSuite(t, "DHE-RSA-AES128-SHA256")
	c := makeMinimalClientState(t, suite)

	c.clientRandom = clientRandom
	c.serverRandom = serverRandom

	// Get the serverParams by verifying the SKE first.
	serverParams, err := c.verifyDHEServerKeyExchange(dheBody, cert)
	testutil.NoErr(t, err, "verifyDHEServerKeyExchange")

	preMaster, ckeBody, err := c.computeKeyExchange(cert, serverParams, nil)
	testutil.NoErr(t, err, "computeKeyExchange(DHE)")

	if len(preMaster) == 0 {
		t.Error("preMaster should be non-empty")
	}

	if len(ckeBody) == 0 {
		t.Error("ckeBody should be non-empty")
	}
}

// ============================================================.
// client.go — sendCertificateVerify: unknown hash alg branch.
// ============================================================.

func TestSendCertificateVerify_UnknownHashAlg(t *testing.T) {
	t.Parallel()

	rsaKey, _, _ := newTestRSACert(t)

	layer, _ := makeRecordLayerWithCapture()

	c := &ClientState{
		params: ClientParams{
			Rand:         nil,
			Certificates: []ClientCertificate{{PrivateKey: rsaKey}},
		},
		layer:      layer,
		transcript: NewTranscript(),
	}

	// hash byte 0xFF is unknown — hashForSigAlg should return an error.
	alg := SigAndHash{Hash: 0xFF, Sig: 0x01}

	err := c.sendCertificateVerify(alg)
	testutil.ErrIs(t, err, errUnsupportedHashAlg, "c.sendCertificateVerify")
}

// ============================================================.
// client.go — recvCertificate: wrong message type.
// ============================================================.

func TestRecvCertificate_WrongMsgType(t *testing.T) {
	t.Parallel()

	// Send a ServerHelloDone instead of Certificate.
	shdRec := buildHSRecord(TypeServerHelloDone, nil)

	rw := &readWriteBuffer{r: bytes.NewBuffer(shdRec), w: new(bytes.Buffer)}
	layer := record.NewLayer(rw)

	c := NewClientState(layer, ClientParams{InsecureSkipVerify: true})

	suite := mustLookupSuite(t, "AES128-SHA256")

	c.suite = suite

	_, _, err := c.recvCertificate()
	testutil.ErrIs(t, err, errExpectedCertificate, "c.recvCertificate")
}

func TestRecvCertificate_EmptyList(t *testing.T) {
	t.Parallel()

	// Send an empty Certificate message (zero certs in list).
	certMsg := &Certificate{}

	marshaled, marshaledErr := certMsg.Marshal()
	testutil.NoErr(t, marshaledErr, "certMsg.Marshal")

	certRec := buildHSRecord(TypeCertificate, marshaled)

	rw := &readWriteBuffer{r: bytes.NewBuffer(certRec), w: new(bytes.Buffer)}
	layer := record.NewLayer(rw)

	c := NewClientState(layer, ClientParams{InsecureSkipVerify: true})

	suite := mustLookupSuite(t, "AES128-SHA256")

	c.suite = suite

	_, _, err := c.recvCertificate()
	testutil.ErrIs(t, err, errEmptyCertList, "c.recvCertificate")
}

// ============================================================.
// client.go — recvServerFlight: SKE required for ECDHE but missing.
// ============================================================.

func TestRecvServerFlight_SKERequired_ECDHE(t *testing.T) {
	t.Parallel()

	// ECDHE suite but only SHD — no SKE. Should fail with errSKERequired.
	shdRec := buildHSRecord(TypeServerHelloDone, nil)

	suite := mustLookupSuite(t, "ECDHE-RSA-AES128-SHA256")
	c := makeClientStateForFlight(t, shdRec, suite)

	_, err := c.recvServerFlight(nil)
	testutil.ErrIs(t, err, errSKERequired, "c.recvServerFlight")
}

func TestRecvServerFlight_DuplicateSKE(t *testing.T) {
	t.Parallel()

	priv, cert := newTestECDSACert(t)

	var clientRandom, serverRandom [32]byte

	skeBody := buildECDHESKEBody(t, priv, clientRandom, serverRandom)
	skeRec := buildHSRecord(TypeServerKeyExchange, skeBody)
	shdRec := buildHSRecord(TypeServerHelloDone, nil)

	// Two SKE records before SHD.
	wire := append(append(append([]byte{}, skeRec...), skeRec...), shdRec...)

	suite := mustLookupSuite(t, "ECDHE-ECDSA-AES128-SHA256")
	c := makeClientStateForFlight(t, wire, suite)

	c.clientRandom = clientRandom
	c.serverRandom = serverRandom

	_, err := c.recvServerFlight(cert)
	testutil.ErrIs(t, err, errDuplicateSKE, "c.recvServerFlight")
}

func TestRecvServerFlight_UnexpectedMsgType(t *testing.T) {
	t.Parallel()

	// Send a ClientHello (type 0x01) in the server flight — should be rejected.
	body := buildMinimalClientHelloBytes()
	unexpectedRec := buildHSRecord(TypeClientHello, body)
	shdRec := buildHSRecord(TypeServerHelloDone, nil)

	wire := append(append([]byte{}, unexpectedRec...), shdRec...)

	suite := mustLookupSuite(t, "AES128-SHA256") // KexRSA.
	c := makeClientStateForFlight(t, wire, suite)

	_, err := c.recvServerFlight(nil)
	testutil.ErrIs(t, err, errUnexpectedFlightMsg, "c.recvServerFlight")
}

// ============================================================.
// client.go — verifyECDHEServerKeyExchange error paths.
// ============================================================.

func TestVerifyECDHESKE_TooShort(t *testing.T) {
	t.Parallel()

	c := makeMinimalClientState(t, mustLookupSuite(t, "ECDHE-RSA-AES128-SHA256"))

	_, cert, _ := newTestRSACert(t)

	_, err := c.verifyECDHEServerKeyExchange([]byte{0x03, 0x00}, cert)
	testutil.ErrIs(t, err, errECDHESKETooShort, "c.verifyECDHEServerKeyExchange")
}

func TestVerifyECDHESKE_UnsupportedCurveType(t *testing.T) {
	t.Parallel()

	c := makeMinimalClientState(t, mustLookupSuite(t, "ECDHE-RSA-AES128-SHA256"))

	_, cert, _ := newTestRSACert(t)

	// curve_type=0x01 (not 0x03 = named_curve).
	body := []byte{0x01, 0x00, 0x17, 0x00}

	_, err := c.verifyECDHEServerKeyExchange(body, cert)
	testutil.ErrIs(t, err, errECDHEUnsupportedCT, "c.verifyECDHEServerKeyExchange")
}

func TestVerifyECDHESKE_BodyTruncatedAfterPoint(t *testing.T) {
	t.Parallel()

	c := makeMinimalClientState(t, mustLookupSuite(t, "ECDHE-RSA-AES128-SHA256"))

	_, cert, _ := newTestRSACert(t)

	// curve_type=0x03, named_curve=0x0017, point_len=65, but only 2 bytes of point follow.
	// minECDHEBodyLen(4) + pointLen(65) + sigSectionMin(2) = 71 needed but only 6 provided.
	body := []byte{0x03, 0x00, 0x17, 0x41, 0xAA, 0xBB}

	_, err := c.verifyECDHEServerKeyExchange(body, cert)
	testutil.ErrIs(t, err, errECDHEBodyTruncated, "c.verifyECDHEServerKeyExchange")
}

func TestVerifyECDHESKE_SigSectionTooShort(t *testing.T) {
	t.Parallel()

	c := makeMinimalClientState(t, mustLookupSuite(t, "ECDHE-RSA-AES128-SHA256"))

	_, cert, _ := newTestRSACert(t)

	// curve_type=0x03, named_curve=0x0017, point_len=1, point=[0xFF].
	// sigData starts at offset 5. First body-truncation check requires
	// len(body) >= 4 + pointLen(1) + sigSectionMin(2) = 7 → must pass.
	// sigDataMin=4 requires sigData length >= 4.
	// We supply exactly 7 bytes so sigData has 2 bytes (< 4) → errECDHESigSectionShort.
	body := []byte{0x03, 0x00, 0x17, 0x01, 0xFF, 0x04, 0x01}

	_, err := c.verifyECDHEServerKeyExchange(body, cert)
	testutil.ErrIs(t, err, errECDHESigSectionShort, "c.verifyECDHEServerKeyExchange")
}

func TestVerifyECDHESKE_SigTruncated(t *testing.T) {
	t.Parallel()

	c := makeMinimalClientState(t, mustLookupSuite(t, "ECDHE-RSA-AES128-SHA256"))

	_, cert, _ := newTestRSACert(t)

	// curve_type=0x03, named_curve=0x0017, point_len=1, point=[0xFF].
	// sigData: hashAlg=0x04, sigAlg=0x01, sig_len=100, but only 1 byte of sig.
	body := []byte{0x03, 0x00, 0x17, 0x01, 0xFF, 0x04, 0x01, 0x00, 0x64, 0xAA}

	_, err := c.verifyECDHEServerKeyExchange(body, cert)
	testutil.ErrIs(t, err, errECDHESigTruncated, "c.verifyECDHEServerKeyExchange")
}
