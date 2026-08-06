# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `Certificate.Certificate` now carries a full DER chain, so client
  authentication can present intermediates (#4).

### Changed

- **Breaking:** `Certificate` matches the `crypto/tls.Certificate` field
  layout. `Certificate.Certificate` is now `[][]byte` (DER chain, leaf first),
  the parsed leaf moved to `Certificate.Leaf`, and `RawCertificate` is gone.
  Migration: `RawCertificate: der` becomes `Certificate: [][]byte{der}`, and
  `Certificate: parsed` becomes `Leaf: parsed` (#4).

### Fixed
