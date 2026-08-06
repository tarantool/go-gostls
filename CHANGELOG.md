# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `Certificate.Certificate` now carries a full DER chain, so client
  authentication can present intermediates (#4).
- `Config.MinVersion` / `Config.MaxVersion`, plus the `VersionTLS10`…
  `VersionTLS13` constants. The module still speaks TLS 1.2 only; a bound that
  excludes it fails the handshake instead of being ignored (#8).
- `Config.Clone()` (#6).
- `Dialer.Dial`, the package-level `Dial` and `DialWithDialer`, and `Client` as
  the `crypto/tls` spelling of `NewConn` (#7).
- `Conn.ConnectionState()`, reporting the negotiated version and suite, the
  effective server name and the peer chain — in stdlib shape and, for the GOST
  key and signature, as `GOSTPeerCertificates` (#3).

### Changed

- A server certificate that does not parse as X.509 now fails the handshake even
  under `InsecureSkipVerify`, matching `crypto/tls`. Malformed DER is a protocol
  error, which is a separate question from whether the chain is trusted. A
  certificate `crypto/x509` accepts but `x509gost` does not — a GOST signature
  over a non-GOST key, an unknown paramset — is not malformed and does not fail
  the handshake; it simply has no entry in `GOSTPeerCertificates` (#3).
- Client `Certificate` chains are no longer capped at one TLS record. Handshake
  messages fragment across records as RFC 5246 §6.2.1 requires, so a chain over
  ~16 KB is sendable instead of failing locally (#4).

- A `NetDialer`'s `Timeout` and `Deadline` now bound the TLS handshake as well
  as the TCP connect, matching `crypto/tls`. Previously they bounded only the
  connect, leaving a handshake against a silent peer unbounded (#7).

- **Breaking:** `Certificate` matches the `crypto/tls.Certificate` field
  layout. `Certificate.Certificate` is now `[][]byte` (DER chain, leaf first),
  the parsed leaf moved to `Certificate.Leaf`, and `RawCertificate` is gone.
  Migration: `RawCertificate: der` becomes `Certificate: [][]byte{der}`, and
  `Certificate: parsed` becomes `Leaf: parsed` (#4).

### Fixed
