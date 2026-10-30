package record

import (
	"fmt"
	"strconv"
)

// Alert levels (RFC 5246 §7.2).
const (
	AlertLevelWarning uint8 = 1
	AlertLevelFatal   uint8 = 2
)

// Alert descriptions: RFC 5246 §7.2, plus the later registrations crypto/tls
// knows by name (RFC 6066, RFC 7301, RFC 7507, RFC 8446, ECH), so that an
// alert any current peer sends can be reported by name.
const (
	AlertCloseNotify                  uint8 = 0
	AlertUnexpectedMessage            uint8 = 10
	AlertBadRecordMAC                 uint8 = 20
	AlertDecryptionFailed             uint8 = 21
	AlertRecordOverflow               uint8 = 22
	AlertDecompressionFailure         uint8 = 30
	AlertHandshakeFailure             uint8 = 40
	AlertBadCertificate               uint8 = 42
	AlertUnsupportedCertificate       uint8 = 43
	AlertCertificateRevoked           uint8 = 44
	AlertCertificateExpired           uint8 = 45
	AlertCertificateUnknown           uint8 = 46
	AlertIllegalParameter             uint8 = 47
	AlertUnknownCA                    uint8 = 48
	AlertAccessDenied                 uint8 = 49
	AlertDecodeError                  uint8 = 50
	AlertDecryptError                 uint8 = 51
	AlertExportRestriction            uint8 = 60
	AlertProtocolVersion              uint8 = 70
	AlertInsufficientSecurity         uint8 = 71
	AlertInternalError                uint8 = 80
	AlertInappropriateFallback        uint8 = 86
	AlertUserCanceled                 uint8 = 90
	AlertNoRenegotiation              uint8 = 100
	AlertMissingExtension             uint8 = 109
	AlertUnsupportedExtension         uint8 = 110
	AlertCertificateUnobtainable      uint8 = 111
	AlertUnrecognizedName             uint8 = 112
	AlertBadCertificateStatusResponse uint8 = 113
	AlertBadCertificateHashValue      uint8 = 114
	AlertUnknownPSKIdentity           uint8 = 115
	AlertCertificateRequired          uint8 = 116
	AlertNoApplicationProtocol        uint8 = 120
	AlertECHRequired                  uint8 = 121
)

// EncodeAlert returns the 2-byte alert body (level || description).
// The caller is responsible for wrapping this in a record with ContentTypeAlert.
func EncodeAlert(level, description uint8) []byte {
	return []byte{level, description}
}

// DecodeAlert parses a 2-byte alert body, returning level and description.
// If the slice is shorter than 2 bytes the values are undefined; callers must
// check length first.
func DecodeAlert(b []byte) (level, description uint8) {
	return b[0], b[1]
}

// AlertError is the error type for a fatal TLS alert.
type AlertError struct {
	Level       uint8
	Description uint8
}

func (e *AlertError) Error() string {
	return fmt.Sprintf("tls: fatal alert %d (level %d)", e.Description, e.Level)
}

// NewFatalAlertError returns an AlertError for a fatal alert with the given
// description code.
func NewFatalAlertError(description uint8) error {
	return &AlertError{Level: AlertLevelFatal, Description: description}
}

// RemoteAlertError is an alert the peer sent, as opposed to AlertError, which
// is one this side raises. Its message names the alert the way crypto/tls
// does — "tls: handshake failure" — so a failure reads the same whichever
// stack reported it, and says what the peer objected to rather than which
// record type turned up.
type RemoteAlertError struct {
	Level       uint8
	Description uint8
}

func (e *RemoteAlertError) Error() string {
	return "tls: " + AlertText(e.Description)
}

// AlertText returns the name of an alert description, spelled as crypto/tls
// spells it, or "alert(N)" for a description it does not know.
func AlertText(description uint8) string {
	switch description {
	case AlertCloseNotify:
		return "close notify"
	case AlertUnexpectedMessage:
		return "unexpected message"
	case AlertBadRecordMAC:
		return "bad record MAC"
	case AlertDecryptionFailed:
		return "decryption failed"
	case AlertRecordOverflow:
		return "record overflow"
	case AlertDecompressionFailure:
		return "decompression failure"
	case AlertHandshakeFailure:
		return "handshake failure"
	case AlertBadCertificate:
		return "bad certificate"
	case AlertUnsupportedCertificate:
		return "unsupported certificate"
	case AlertCertificateRevoked:
		return "revoked certificate"
	case AlertCertificateExpired:
		return "expired certificate"
	case AlertCertificateUnknown:
		return "unknown certificate"
	case AlertIllegalParameter:
		return "illegal parameter"
	case AlertUnknownCA:
		return "unknown certificate authority"
	case AlertAccessDenied:
		return "access denied"
	case AlertDecodeError:
		return "error decoding message"
	case AlertDecryptError:
		return "error decrypting message"
	case AlertExportRestriction:
		return "export restriction"
	case AlertProtocolVersion:
		return "protocol version not supported"
	case AlertInsufficientSecurity:
		return "insufficient security level"
	case AlertInternalError:
		return "internal error"
	case AlertInappropriateFallback:
		return "inappropriate fallback"
	case AlertUserCanceled:
		return "user canceled"
	case AlertNoRenegotiation:
		return "no renegotiation"
	case AlertMissingExtension:
		return "missing extension"
	case AlertUnsupportedExtension:
		return "unsupported extension"
	case AlertCertificateUnobtainable:
		return "certificate unobtainable"
	case AlertUnrecognizedName:
		return "unrecognized name"
	case AlertBadCertificateStatusResponse:
		return "bad certificate status response"
	case AlertBadCertificateHashValue:
		return "bad certificate hash value"
	case AlertUnknownPSKIdentity:
		return "unknown PSK identity"
	case AlertCertificateRequired:
		return "certificate required"
	case AlertNoApplicationProtocol:
		return "no application protocol"
	case AlertECHRequired:
		return "encrypted client hello required"
	default:
		return "alert(" + strconv.Itoa(int(description)) + ")"
	}
}

// Error represents a hard error in the record layer that is not
// necessarily tied to a TLS alert (e.g., sequence number overflow, local
// protocol violations). Fatal indicates whether the connection must be closed.
type Error struct {
	Fatal   bool
	Message string
}

func (e *Error) Error() string {
	return "tls record: " + e.Message
}

func fatalRecordError(msg string) *Error {
	return &Error{Fatal: true, Message: msg}
}
