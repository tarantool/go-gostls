// Package gostls implements a TLS 1.2 client with a crypto/tls-shaped API.
//
// It speaks the ordinary AES / ECDHE / ChaCha20-Poly1305 suites and, in
// addition, the GOST suites that the standard library does not: GOST 28147-89,
// Kuznyechik and Magma in CTR-OMAC mode, and the VKO / GOST-2018 key exchanges.
// The implementation is pure Go, builds with CGO_ENABLED=0, and links no GPL
// code; the GOST primitives come from
// [github.com/tarantool/go-gostcrypto], GOST-signed X.509 from its
// [github.com/tarantool/go-gostcrypto/x509gost] subpackage.
//
// # Scope
//
// This implementation is TLS 1.2 only. TLS 1.3, session resumption,
// renegotiation, ALPN extensibility, and 0-RTT are not supported.
// There is no server role.
//
// # Cipher suites
//
// AES-128-CBC, AES-256-CBC, AES-128-GCM, AES-256-GCM, and CHACHA20-POLY1305
// (RFC 7905) suites are included in the default negotiation set. GOST suites
// are registered in every build but are not offered by default; request them
// explicitly via [Config.CipherSuites], resolving the ID with
// [LookupSuiteByName].
//
// # Usage
//
// Dial a server the same way you would with crypto/tls:
//
//	d := &gostls.Dialer{
//		Config: &gostls.Config{ServerName: "example.com"},
//	}
//
//	conn, err := d.DialContext(ctx, "tcp", "example.com:443")
//	if err != nil {
//		return err
//	}
//	defer conn.Close()
//
// The returned [Conn] is a net.Conn whose handshake has already completed.
// To negotiate a GOST suite, name it explicitly:
//
//	id, ok := gostls.LookupSuiteByName("GOST2012-KUZNYECHIK-KUZNYECHIKOMAC")
//	if !ok {
//		return errors.New("suite not registered")
//	}
//
//	cfg.CipherSuites = []uint16{id}
//
// Ordinary chains are verified against [Config.RootCAs] or
// [Config.RootCAPEMs]; GOST-signed server certificates are verified against
// [Config.GOSTRoots].
package gostls
