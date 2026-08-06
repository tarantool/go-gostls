package handshake

import "crypto/x509"

// Result reports what a handshake negotiated. It is the read-only view the
// gostls package turns into its exported ConnectionState, so that the state
// machine's fields stay unexported and callers cannot reach in and mutate a
// live handshake.
type Result struct {
	// Complete is true once the full handshake finished successfully. The
	// remaining fields are only meaningful when it is.
	Complete bool

	// SuiteID is the IANA number of the negotiated cipher suite, zero if
	// ServerHello was never processed.
	SuiteID uint16

	// PeerCertificates is the server's chain, leaf first, in stdlib shape.
	PeerCertificates []*x509.Certificate

	// GOSTPeerCertificates is the same chain as []*x509gost.Certificate. It is
	// typed as any for the same reason ClientParams.GOSTRoots is: this package
	// does not put x509gost in its exported signatures.
	GOSTPeerCertificates any
}

// Result returns the negotiated parameters. It is safe to call before the
// handshake completes; Complete then reports false and the rest is whatever
// has been settled so far.
func (c *ClientState) Result() Result {
	res := Result{
		Complete:             c.done,
		PeerCertificates:     c.peerCertificates,
		GOSTPeerCertificates: c.gostPeerCertificates,
	}

	if c.suite != nil {
		res.SuiteID = c.suite.ID
	}

	return res
}
