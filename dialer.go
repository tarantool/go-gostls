package gostls

import (
	"context"
	"net"
	"time"
)

// Dialer dials TLS connections. Its API mirrors crypto/tls.Dialer.
type Dialer struct {
	// NetDialer is the underlying network dialer used to establish the TCP
	// (or other) connection before the TLS handshake. If nil, a zero-value
	// net.Dialer is used.
	NetDialer *net.Dialer

	// Config is the TLS configuration applied to each new connection.
	// If nil, a zero-value Config is used (which requires InsecureSkipVerify
	// or a matching RootCAs + ServerName to succeed).
	Config *Config
}

// DialContext connects to addr using the network dialer, then performs a TLS
// handshake and returns the fully negotiated connection.
//
// The returned net.Conn is a *Conn. The handshake is completed before
// DialContext returns.
//
// ctx controls the lifetime of the dial; it is not propagated to subsequent
// Read/Write calls on the returned Conn.
//
// gostls is the pure-Go TLS backend (CGO_ENABLED=0 compatible). The OpenSSL
// backend lives in the separate go-tlsdialer module, which selects between
// gostls and OpenSSL.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := d.dial(ctx, network, addr)
	if err != nil {
		// Return an untyped nil: a nil *Conn stored in a net.Conn is non-nil
		// when compared against nil by the caller.
		return nil, err
	}

	return conn, nil
}

// Dial is DialContext with context.Background(): it connects to addr and
// completes the TLS handshake, with no bound on the attempt beyond the ones
// NetDialer carries.
//
// It returns a net.Conn holding a *Conn, mirroring crypto/tls.Dialer.Dial; the
// package-level Dial returns the concrete type instead.
func (d *Dialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

// dial is the shared implementation behind every entry point. It supplies the
// zero-value Config that a nil d.Config stands for, folds NetDialer's own
// timeout into ctx, and yields the concrete *Conn that the net.Conn-returning
// wrappers widen.
func (d *Dialer) dial(ctx context.Context, network, addr string) (*Conn, error) {
	cfg := d.Config
	if cfg == nil {
		cfg = &Config{}
	}

	ctx, cancel := ctxWithDialerDeadline(ctx, d.NetDialer)
	defer cancel()

	return dialBackend(ctx, network, addr, d.NetDialer, cfg)
}

// ctxWithDialerDeadline folds a net.Dialer's Timeout and Deadline into ctx.
//
// net.Dialer applies them to the TCP connect alone, which would leave the
// handshake unbounded; crypto/tls documents them as covering "connection and
// TLS handshake as a whole", and putting them on ctx is what makes that true
// here — dialBackend bounds the handshake by ctx. The earliest of the three
// wins, as usual for context deadlines.
func ctxWithDialerDeadline(ctx context.Context, netDialer *net.Dialer) (context.Context, context.CancelFunc) {
	if netDialer == nil {
		return ctx, func() {}
	}

	deadline := netDialer.Deadline

	if netDialer.Timeout > 0 {
		fromTimeout := time.Now().Add(netDialer.Timeout)
		if deadline.IsZero() || fromTimeout.Before(deadline) {
			deadline = fromTimeout
		}
	}

	if deadline.IsZero() {
		return ctx, func() {}
	}

	return context.WithDeadline(ctx, deadline)
}

// Dial connects to addr with a zero-value net.Dialer, performs the TLS
// handshake and returns the negotiated connection. It is the shorthand entry
// point that crypto/tls callers reach for most often.
//
// config may be nil, which is treated as a zero-value Config — a configuration
// that only succeeds with InsecureSkipVerify or a matching RootCAs and
// ServerName, so most callers do pass one.
func Dial(network, addr string, config *Config) (*Conn, error) {
	return DialWithDialer(nil, network, addr, config)
}

// DialWithDialer is Dial over a caller-supplied net.Dialer, so that the local
// address, keep-alive and resolver settings of an existing dialer carry over
// to the TLS connection. A nil dialer means a zero-value one.
//
// The dialer's Timeout and Deadline bound the TCP connect and the TLS
// handshake together, not just the connect. Use a Dialer with DialContext to
// bound them by a context instead.
func DialWithDialer(dialer *net.Dialer, network, addr string, config *Config) (*Conn, error) {
	d := &Dialer{NetDialer: dialer, Config: config}

	return d.dial(context.Background(), network, addr)
}

// Client wraps conn in a *Conn that speaks the client side of TLS, deferring
// the handshake to the first Read, Write or explicit Handshake call.
//
// It is the crypto/tls-compatible spelling of NewConn and does exactly the
// same thing; both are supported, so code ported from crypto/tls compiles
// unchanged while code written against gostls need not be rewritten.
func Client(conn net.Conn, config *Config) *Conn {
	return newConn(conn, config)
}
