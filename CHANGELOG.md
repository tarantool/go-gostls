# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Fixed

## [v0.1.1] - 2026-10-30

Two handshake failures that hid the server's reason now report it: an alert
the server sends instead of its ChangeCipherSpec comes back the way
`crypto/tls` reports it, and the client's second flight leaves in one write,
so a server that closes on the client certificate no longer turns the failure
into a broken pipe.

### Changed

- An alert the server sends during the handshake is reported the way
  `crypto/tls` reports it: a `*net.OpError` with `Op` `"remote error"` whose
  text names the alert, e.g. `remote error: tls: handshake failure`. It used
  to read `tls: received alert level=2 desc=40` (#30).

### Fixed

- A server that answers the client's second flight with an alert instead of
  its ChangeCipherSpec — a mutual-TLS server rejecting a missing client
  certificate, for one — is reported as that alert, not as
  `tls: expected ChangeCipherSpec, got content type 21` (#30).
- The client's second flight — Certificate, ClientKeyExchange,
  CertificateVerify, ChangeCipherSpec, Finished — is sent in one write, as
  `crypto/tls` and OpenSSL send it. A server that rejects the client
  certificate closes the connection as soon as it has read it, and the client
  used to fail now and then on writing the rest of the flight
  (`write: broken pipe`) instead of reading the server's alert (#30).

## [v0.1.0] - 2026-08-06

First public release of go-gostls: a pure-Go, BSD-2-Clause TLS 1.2 client
shaped like `crypto/tls`, speaking both the ordinary AES / ECDHE /
ChaCha20-Poly1305 suites and the GOST suites the standard library does not,
with no OpenSSL, no cgo and no GPL in the module graph.

### Added

- Initial public release of `go-gostls`: a pure-Go TLS 1.2 client shaped like
  `crypto/tls` — `Config`, `Conn` and `Dialer`, with `NewConn` and its
  `crypto/tls` spelling `Client`, the package-level `Dial` and
  `DialWithDialer`, and `Dialer.Dial` / `Dialer.DialContext` (#7).
- GOST cipher suites: `GOST2001-GOST89-GOST89`,
  `GOST2012-GOST8912-GOST8912`, `GOST2012-MAGMA-MAGMAOMAC` and
  `GOST2012-KUZNYECHIK-KUZNYECHIKOMAC`.
- Standard cipher suites: ECDHE / DHE / RSA key exchange with AES-CBC,
  AES-GCM and ChaCha20-Poly1305 record protection.
- GOST key exchange: VKO GOST 2001 / 2012 and GOST-2018 key transport.
- Record protection: GOST 28147-89 CNT+IMIT and CTR-OMAC over Kuznyechik and
  Magma, with CTR-ACPKM rekeying.
- Certificate verification: `RootCAs` / `RootCAPEMs` for ordinary chains and
  `GOSTRoots` / `GOSTIntermediates` for GOST-signed ones (`x509gost`). A
  server certificate that does not parse as X.509 fails the handshake even
  under `InsecureSkipVerify`, matching `crypto/tls`; a certificate
  `crypto/x509` accepts but `x509gost` does not simply has no entry in
  `GOSTPeerCertificates` (#3).
- Mutual TLS client authentication through `Config.Certificates`, laid out as
  `crypto/tls.Certificate`: `Certificate` is a `[][]byte` DER chain (leaf
  first) and the parsed leaf lives in `Leaf`, so intermediates can be
  presented. Handshake messages fragment across records as RFC 5246 §6.2.1
  requires, so a chain over ~16 KB is sendable (#4).
- `Config.MinVersion` / `Config.MaxVersion`, plus the `VersionTLS10`…
  `VersionTLS13` constants. The module speaks TLS 1.2 only; a bound that
  excludes it fails the handshake instead of being ignored (#8).
- `Config.Clone()` (#6).
- `Conn.ConnectionState()`, reporting the negotiated version and suite, the
  effective server name and the peer chain — in stdlib shape and, for the GOST
  key and signature, as `GOSTPeerCertificates` (#3).
- A `NetDialer`'s `Timeout` and `Deadline` bound the TLS handshake as well as
  the TCP connect, matching `crypto/tls` (#7).
- Suite registry helpers `AllSuites()` and `LookupSuiteByName()`, plus the
  build identifier `BackendTag()`.
