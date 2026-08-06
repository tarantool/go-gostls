package gostls

import (
	"crypto/x509"

	"github.com/tarantool/go-gostcrypto/x509gost"

	"github.com/tarantool/go-gostls/internal/handshake"
)

// ConnectionState describes what a handshake negotiated.
//
// The stdlib-named fields carry stdlib meanings, so code that logs the
// negotiated suite or inspects the peer chain ports over unchanged. The fields
// crypto/tls has that this module cannot fill — everything about TLS 1.3,
// session resumption, ALPN and OCSP — are absent rather than present and
// always zero, so that reading a value never implies a feature that is not
// there.
//
// GOSTPeerCertificates has no stdlib counterpart: a GOST-signed certificate
// cannot be expressed as an *x509.Certificate, and since negotiating GOST is
// the point of this module, the peer chain has to be reachable in the form
// that carries the GOST key and signature.
type ConnectionState struct {
	// Version is the negotiated TLS version: VersionTLS12 once the handshake
	// completed, zero before that. This module negotiates nothing else.
	Version uint16

	// HandshakeComplete is true once the handshake finished successfully. Every
	// other field is zero valued until it is.
	HandshakeComplete bool

	// CipherSuite is the IANA number of the negotiated cipher suite. Resolve it
	// to a name with AllSuites if you need one.
	CipherSuite uint16

	// ServerName is the name sent in SNI and verified against the certificate.
	// It is the effective name: Config.ServerName when set, otherwise the host
	// taken from the dial address.
	ServerName string

	// PeerCertificates is the chain the server sent, leaf first, in stdlib
	// shape. A GOST-signed certificate appears here too, in the stdlib view
	// that x509gost derives from it — which is enough to read the subject and
	// validity, but not the GOST key or signature. Use GOSTPeerCertificates
	// for those.
	PeerCertificates []*x509.Certificate

	// GOSTPeerCertificates is the same chain, in the same order, parsed as
	// x509gost certificates. An entry is nil when that certificate is one
	// x509gost declines to parse but crypto/x509 accepts — a GOST signature
	// over a non-GOST key, or an unknown curve paramset. Such certificates are
	// legal and do occur in mixed PKIs, so they do not fail the handshake;
	// they simply have no GOST view. PeerCertificates is never sparse.
	GOSTPeerCertificates []*x509gost.Certificate
}

// ConnectionState returns the state of the connection. Before the handshake
// completes it reports the zero value, with HandshakeComplete false; it never
// starts a handshake itself, matching crypto/tls.
//
// The returned value is a snapshot and is safe to read while other goroutines
// use the connection.
func (c *Conn) ConnectionState() ConnectionState {
	state := c.connState.Load()
	if state == nil {
		return ConnectionState{}
	}

	return *state
}

// publishConnectionState converts the handshake's result into the exported
// shape and stores it for ConnectionState to hand out. It is called once, from
// doHandshake, before Handshake reports success.
func (c *Conn) publishConnectionState(res handshake.Result, serverName string) {
	state := ConnectionState{
		Version:           VersionTLS12,
		HandshakeComplete: res.Complete,
		CipherSuite:       res.SuiteID,
		ServerName:        serverName,
		PeerCertificates:  res.PeerCertificates,
	}

	// GOSTPeerCertificates is typed as any on the handshake side so that the
	// internal package keeps x509gost out of its exported signatures; see
	// ClientParams.GOSTRoots. A chain that is not the expected type is left
	// nil rather than papered over — the stdlib view is still populated.
	if gostChain, ok := res.GOSTPeerCertificates.([]*x509gost.Certificate); ok {
		state.GOSTPeerCertificates = gostChain
	}

	c.connState.Store(&state)
}
