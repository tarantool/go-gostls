package gostls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"github.com/tarantool/go-gostcrypto/x509gost"

	"github.com/tarantool/go-gostls/internal/handshake"
)

// Sentinel errors for static err113 compliance.
var (
	// errRootCAsMutuallyExclusive is returned when both RootCAs and RootCAPEMs are set.
	errRootCAsMutuallyExclusive = errors.New(
		"tls: Config.RootCAs and Config.RootCAPEMs are mutually exclusive; set only one",
	)
	// errRootCAPEMParseFailed is wrapped with the index to indicate a parse failure.
	errRootCAPEMParseFailed = errors.New("tls: RootCAPEMs: failed to parse certificate")
	// errRootCAPEMNoCerts is wrapped with the index to indicate no CERTIFICATE blocks.
	errRootCAPEMNoCerts = errors.New("tls: RootCAPEMs: no CERTIFICATE blocks found")
	// errCertUnsupportedKeyType is wrapped with cert index and key type.
	errCertUnsupportedKeyType = errors.New(
		"tls: Certificates: PrivateKey has unsupported type; want *rsa.PrivateKey or *ecdsa.PrivateKey",
	)
	// errCertEmptyChain is wrapped with the cert index.
	errCertEmptyChain = errors.New("tls: Certificates: Certificate chain is empty")
	// errCertEmptyChainEntry is wrapped with the cert index and the chain index.
	errCertEmptyChainEntry = errors.New("tls: Certificates: Certificate chain entry is empty")
)

// Certificate holds a certificate chain and its private key.
// The field layout matches crypto/tls.Certificate, so a value built for
// crypto/tls can be assigned field by field without reshaping.
type Certificate struct {
	// Certificate holds the DER-encoded certificate chain: the leaf first,
	// followed by any intermediates needed to let the peer build a path to a
	// CA it trusts. The chain is sent verbatim in the client Certificate
	// message. At least one entry is required, and no entry may be empty.
	Certificate [][]byte

	// PrivateKey is the private key corresponding to the leaf certificate's
	// public key. Required when using mutual TLS (client authentication).
	PrivateKey crypto.PrivateKey

	// Leaf is the parsed leaf certificate, i.e. Certificate[0]. It is optional
	// and is used for inspection only, never for what goes on the wire. When
	// nil, Certificate[0] is parsed on demand at handshake time.
	Leaf *x509.Certificate
}

// Config is the TLS 1.2 client configuration. Field names and semantics
// mirror crypto/tls.Config where the feature exists in stdlib.
//
// Only a subset of crypto/tls.Config is implemented.
type Config struct {
	// RootCAs defines the set of root certificate authorities used to verify
	// the server's certificate. If nil, the host's default root CA set is used.
	//
	// RootCAs and RootCAPEMs are mutually exclusive. Setting both is an error.
	RootCAs *x509.CertPool

	// RootCAPEMs holds PEM-encoded trusted root certificates. Each element may
	// be a single PEM block or a concatenation of multiple PEM blocks. Only
	// CERTIFICATE-typed blocks are used; other block types (keys, etc.) are
	// ignored, but each element must contain at least one CERTIFICATE block.
	//
	// This field is the preferred way to supply an in-memory trust store when
	// using the openssl backend, where RootCAs is not supported.
	//
	// RootCAs and RootCAPEMs are mutually exclusive. Setting both is an error.
	RootCAPEMs [][]byte

	// GOSTRoots is the trust store for GOST-signed server certificates. The
	// stdlib pools (RootCAs/RootCAPEMs) cannot verify GOST signatures, so a
	// GOST trust anchor must be supplied here as a parsed x509gost certificate.
	// If the server presents a GOST-signed certificate and GOSTRoots is empty,
	// verification fails (unless InsecureSkipVerify). It is not consulted for
	// non-GOST certificates.
	GOSTRoots []*x509gost.Certificate

	// GOSTIntermediates optionally bridges a GOST-signed leaf to a root in
	// GOSTRoots through intermediate CA certificates. Leave nil for a direct
	// leaf-signed-by-root chain.
	GOSTIntermediates []*x509gost.Certificate

	// Certificates contains client certificates for mutual TLS (mTLS) client
	// authentication. When the server sends a CertificateRequest during the
	// handshake, the first entry in this slice is offered, chain included. If
	// the server's requested signature algorithms do not include any algorithm
	// supported by the key, an empty Certificate message is sent (which is
	// valid per RFC 5246).
	//
	// Each Certificate.PrivateKey must be *rsa.PrivateKey or *ecdsa.PrivateKey;
	// any other type causes Handshake() to return a hard error. So does an
	// empty Certificate chain or an empty entry within it.
	Certificates []Certificate

	// ServerName is the server name sent in the SNI extension and used for
	// certificate verification. If empty and InsecureSkipVerify is false,
	// certificate verification will fail because x509 requires a DNS name.
	ServerName string

	// CipherSuites specifies the list of cipher suite IDs to offer in the
	// ClientHello. If nil, all registered suites whose cipher is AES-128-CBC,
	// AES-256-CBC, AES-128-GCM, AES-256-GCM, or CHACHA20-POLY1305 are offered.
	CipherSuites []uint16

	// InsecureSkipVerify controls whether the client verifies the server's
	// certificate chain and host name.
	//
	// WARNING: Setting this to true disables all certificate authentication.
	// The connection is susceptible to man-in-the-middle attacks. Use only
	// for debugging or with VerifyPeerCertificate performing custom verification.
	InsecureSkipVerify bool

	// VerifyPeerCertificate is called after normal certificate verification
	// (or instead of it if InsecureSkipVerify is true). The first argument is
	// the raw DER bytes of the certificates provided by the server. The second
	// is the verified chains (empty when InsecureSkipVerify is true).
	//
	// A non-nil error aborts the handshake with bad_certificate.
	VerifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

	// Rand provides the source of entropy for random values used during the
	// handshake: client random, client ephemeral keys, RSA pre-master secret,
	// and CBC per-record IVs.
	//
	// If nil, crypto/rand.Reader is used (the correct default for production).
	// Override in tests to produce deterministic handshake bytes.
	Rand io.Reader
}

// rand returns the configured random source, defaulting to crypto/rand.Reader.
func (c *Config) rand() io.Reader {
	if c != nil && c.Rand != nil {
		return c.Rand
	}

	return rand.Reader
}

// gostCertsParam boxes a GOST certificate slice for the any-typed
// ClientParams.GOSTRoots/GOSTIntermediates fields, mapping a nil slice to a
// genuine nil interface (rather than a non-nil interface wrapping a nil slice)
// so the handshake's GOST trust checks behave as documented.
func gostCertsParam(certs []*x509gost.Certificate) any {
	if certs == nil {
		return nil
	}

	return certs
}

// rootCAPool returns the certificate pool to use for server verification.
//
// Priority rules:
//   - If both RootCAs and RootCAPEMs are set, an error is returned.
//   - If only RootCAs is set, it is returned as-is.
//   - If only RootCAPEMs is set, a new pool is built from those PEM blocks.
//   - If neither is set, nil is returned (the backend uses the OS trust store).
//
// When c is nil, (nil, nil) is returned.
func (c *Config) rootCAPool() (*x509.CertPool, error) {
	if c == nil {
		return nil, nil //nolint:nilnil // nil pool means "use OS trust store", which is the intended zero value
	}

	if c.RootCAs != nil && len(c.RootCAPEMs) > 0 {
		return nil, errRootCAsMutuallyExclusive
	}

	if c.RootCAs != nil {
		return c.RootCAs, nil
	}

	if len(c.RootCAPEMs) == 0 {
		return nil, nil //nolint:nilnil // nil pool means "use OS trust store", which is the intended zero value
	}

	pool := x509.NewCertPool()
	for i, block := range c.RootCAPEMs {
		if !pool.AppendCertsFromPEM(block) {
			// AppendCertsFromPEM returns false when no CERTIFICATE blocks were
			// found. Other block types are silently ignored by AppendCertsFromPEM,
			// but an element with no certificates at all is a misconfiguration.
			//
			// We need to distinguish "no blocks at all" from "blocks present but
			// no CERTIFICATE type". Decode to check.
			hasCertBlock := false
			rest := block

			for {
				var pemBlock *pem.Block

				pemBlock, rest = pem.Decode(rest)

				if pemBlock == nil {
					break
				}

				if pemBlock.Type == "CERTIFICATE" {
					hasCertBlock = true
					break
				}
			}

			if hasCertBlock {
				// There was a CERTIFICATE block but it failed to parse.
				return nil, fmt.Errorf("tls: RootCAPEMs[%d]: %w", i, errRootCAPEMParseFailed)
			}

			return nil, fmt.Errorf("tls: RootCAPEMs[%d]: %w", i, errRootCAPEMNoCerts)
		}
	}

	return pool, nil
}

// clientCerts validates Config.Certificates and converts them to
// []handshake.ClientCertificate.
//
// Validation rules (hard errors — fail loud at handshake start):
//   - PrivateKey must be *rsa.PrivateKey or *ecdsa.PrivateKey.
//   - Certificate must hold at least one entry, and every entry must be
//     non-empty. The chain is what gets placed on the wire; a pre-populated
//     Leaf is auxiliary metadata and does not substitute for the DER bytes.
//   - When Leaf is nil, Certificate[0] is parsed, which also rejects a chain
//     whose leaf is not a certificate at all.
//
// Returns (nil, nil) when Certificates is empty.
func (c *Config) clientCerts() ([]handshake.ClientCertificate, error) {
	if len(c.Certificates) == 0 {
		return nil, nil
	}

	result := make([]handshake.ClientCertificate, 0, len(c.Certificates))
	for i, cert := range c.Certificates {
		// Validate key type.
		switch cert.PrivateKey.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			// OK.
		default:
			return nil, fmt.Errorf(
				"tls: Certificates[%d].PrivateKey type %T: %w", i, cert.PrivateKey, errCertUnsupportedKeyType,
			)
		}

		// The chain is what gets emitted on the wire; validate unconditionally,
		// regardless of whether Leaf is pre-parsed. An empty entry would
		// otherwise produce a malformed zero-length certificate entry (RFC 5246
		// §7.4.2 requires each entry in the list to be at least 1 byte).
		if len(cert.Certificate) == 0 {
			return nil, fmt.Errorf("tls: Certificates[%d]: %w", i, errCertEmptyChain)
		}

		for j, der := range cert.Certificate {
			if len(der) == 0 {
				return nil, fmt.Errorf("tls: Certificates[%d].Certificate[%d]: %w", i, j, errCertEmptyChainEntry)
			}
		}

		if cert.Leaf == nil {
			_, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				return nil, fmt.Errorf("tls: Certificates[%d].Certificate[0]: %w", i, err)
			}
		}

		result = append(result, handshake.ClientCertificate{
			RawChain:   cert.Certificate,
			PrivateKey: cert.PrivateKey,
		})
	}

	return result, nil
}
