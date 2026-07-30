package record

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

// TLS 1.2 content type values (RFC 5246 §6.2.1).
const (
	ContentTypeChangeCipherSpec uint8 = 20
	ContentTypeAlert            uint8 = 21
	ContentTypeHandshake        uint8 = 22
	ContentTypeApplicationData  uint8 = 23
)

// tlsVersion is the only version this layer accepts on the wire.
const tlsVersion = uint16(0x0303)

// tlsMaxPlaintextLen is the maximum plaintext fragment length (RFC 5246 §6.2.1):
// 2^14 bytes.
const tlsMaxPlaintextLen = 1 << 14

// tlsMaxCiphertextOverhead is the maximum overhead (in bytes) above plaintext
// length allowed for a TLSCiphertext record (RFC 5246 §6.2.2).
const tlsMaxCiphertextOverhead = 2048

// tlsVersionHi is the high byte of tlsVersion (TLS 1.2 major version).
const tlsVersionHi = byte(tlsVersion >> 8)

// tlsVersionLo is the low byte of tlsVersion (TLS 1.2 minor version).
const tlsVersionLo = byte(tlsVersion & 0xFF)

// maxFragmentLen is the maximum allowed fragment length (RFC 5246 §6.2.2).
// For TLSCiphertext (encrypted): 2^14 + 2048.
const maxFragmentLen = tlsMaxPlaintextLen + tlsMaxCiphertextOverhead

// maxRecordLen is the largest value the record layer's 2-byte length field can
// express. maxFragmentLen is far below it; this is the hard ceiling that makes
// a narrowing conversion to uint16 safe.
const maxRecordLen = 1<<16 - 1

// recordHeaderLen is the fixed size of a TLS record header.
const recordHeaderLen = 5

// isKnownContentType returns true for the four valid TLS 1.2 content types.
func isKnownContentType(ct uint8) bool {
	switch ct {
	case ContentTypeChangeCipherSpec,
		ContentTypeAlert,
		ContentTypeHandshake,
		ContentTypeApplicationData:
		return true
	}

	return false
}

// newAESCipher is the cipher.Block constructor used by aeadProtector.
// Keeping it in this package avoids an import cycle — protection.go calls it
// by name but does not import "crypto/aes" directly.
func newAESCipher(key []byte) (cipher.Block, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("tls record: AES cipher init: %w", err)
	}

	return block, nil
}

// Layer is a TLS record reader/writer over an io.ReadWriter.
// It tracks separate send and receive sequence numbers and Protectors,
// allowing ChangeCipherSpec to swap them independently.
//
// The send-side fields (sendSeq, sendProt) and recv-side fields (recvSeq,
// recvProt) are disjoint: a concurrent WriteRecord and ReadRecord on the
// same Layer is safe. Concurrent same-side calls (two Writers or two
// Readers) are not safe. ChangeCipherSpec touches both sides and is
// handshake-only — it must not race with WriteRecord or ReadRecord.
type Layer struct {
	rw       io.ReadWriter
	sendSeq  uint64
	recvSeq  uint64
	sendProt Protector
	recvProt Protector
}

// NewLayer returns a Layer using nullProtector for both directions.
func NewLayer(rw io.ReadWriter) *Layer {
	return NewLayerWithSeq(rw, 0)
}

// NewLayerWithSeq returns a Layer with the given initial sequence number for
// both send and receive directions. Used in tests to verify overflow behaviour.
func NewLayerWithSeq(rw io.ReadWriter, initialSeq uint64) *Layer {
	null := nullProtector{}

	return &Layer{
		rw:       rw,
		sendSeq:  initialSeq,
		recvSeq:  initialSeq,
		sendProt: null,
		recvProt: null,
	}
}

// ChangeCipherSpec swaps the send and/or receive Protectors.
// Pass nil to leave a direction unchanged.
func (l *Layer) ChangeCipherSpec(send, recv Protector) {
	if send != nil {
		l.sendProt = send
		l.sendSeq = 0
	}

	if recv != nil {
		l.recvProt = recv
		l.recvSeq = 0
	}
}

// WriteRecord encrypts and writes a single TLS record.
// contentType must be one of the four known values. payload must not exceed 2^14 bytes.
func (l *Layer) WriteRecord(contentType uint8, payload []byte) error {
	if !isKnownContentType(contentType) {
		return fatalRecordError(fmt.Sprintf("unknown content type 0x%02x", contentType))
	}

	if len(payload) > tlsMaxPlaintextLen {
		return fatalRecordError("plaintext payload exceeds 2^14 bytes")
	}

	if l.sendSeq == math.MaxUint64 {
		return fatalRecordError("sequence number overflow")
	}

	// Build the 5-byte header template (length will be updated after Seal).
	hdr := [recordHeaderLen]byte{
		contentType,
		tlsVersionHi,
		tlsVersionLo,
		0, 0, // placeholder length.
	}

	dumpPlaintext("send", l.sendSeq, contentType, tlsVersion, payload)

	fragment, err := l.sendProt.Seal(l.sendSeq, hdr[:], payload)
	if err != nil {
		return err
	}

	// Seal adds padding, a MAC or an AEAD tag, so the sealed fragment is longer
	// than the plaintext checked above. Enforce the same ceiling the read path
	// applies (maxFragmentLen) before writing the length: without it an
	// over-long fragment would wrap the uint16 and put a header on the wire
	// that disagrees with the bytes following it.
	if len(fragment) > maxFragmentLen {
		return fatalRecordError(fmt.Sprintf(
			"sealed fragment is %d bytes, exceeds the %d-byte record limit",
			len(fragment), maxFragmentLen))
	}

	// Write the actual 5-byte header with corrected length.
	//nolint:gosec // bounded by the maxFragmentLen check above;
	// see TestWriteRecord_OversizedSealedFragmentRejected.
	binary.BigEndian.PutUint16(hdr[3:5], uint16(len(fragment)))

	_, err = l.rw.Write(hdr[:])
	if err != nil {
		return fmt.Errorf("tls record: write header: %w", err)
	}

	_, err = l.rw.Write(fragment)
	if err != nil {
		return fmt.Errorf("tls record: write fragment: %w", err)
	}

	l.sendSeq++

	return nil
}

// ReadRecord reads and decrypts a single TLS record.
// Returns an error on truncated header, version mismatch, unknown content
// type, oversized fragment, or decryption failure. All errors are hard errors.
func (l *Layer) ReadRecord() (contentType uint8, payload []byte, err error) {
	if l.recvSeq == math.MaxUint64 {
		return 0, nil, fatalRecordError("sequence number overflow")
	}

	// Read 5-byte header.
	var hdr [recordHeaderLen]byte

	_, err = io.ReadFull(l.rw, hdr[:])
	if err != nil {
		// A clean EOF at a record boundary is the normal end of the stream and
		// must keep its identity: io.Copy and much other code compare against
		// io.EOF with ==, not errors.Is, so wrapping it here would turn an
		// ordinary close into an error for anyone copying from a Conn.
		if errors.Is(err, io.EOF) {
			//nolint:wrapcheck // deliberate: see the comment above and
			// TestReadRecord_CleanEOFKeepsIdentity. Wrapping here breaks io.Copy.
			return 0, nil, err
		}

		return 0, nil, fmt.Errorf("tls record: read header: %w", err)
	}

	ct := hdr[0]
	ver := binary.BigEndian.Uint16(hdr[1:3])
	length := binary.BigEndian.Uint16(hdr[3:5])

	if !isKnownContentType(ct) {
		return 0, nil, NewFatalAlertError(AlertIllegalParameter)
	}

	if ver != tlsVersion {
		return 0, nil, NewFatalAlertError(AlertProtocolVersion)
	}

	if int(length) > maxFragmentLen {
		return 0, nil, NewFatalAlertError(AlertRecordOverflow)
	}

	fragment := make([]byte, length)

	_, err = io.ReadFull(l.rw, fragment)
	if err != nil {
		// Unlike the header read above, an EOF here means the peer vanished
		// mid-record. That is a truncation, not a clean close, so it is wrapped.
		return 0, nil, fmt.Errorf("tls record: read fragment: %w", err)
	}

	plain, err := l.recvProt.Open(l.recvSeq, hdr[:], fragment)
	if err != nil {
		return 0, nil, err
	}

	dumpPlaintext("recv", l.recvSeq, ct, ver, plain)

	l.recvSeq++

	return ct, plain, nil
}
