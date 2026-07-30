# go-gostls

[![test](https://github.com/tarantool/go-gostls/actions/workflows/test.yml/badge.svg)](https://github.com/tarantool/go-gostls/actions/workflows/test.yml)
[![lint](https://github.com/tarantool/go-gostls/actions/workflows/lint.yml/badge.svg)](https://github.com/tarantool/go-gostls/actions/workflows/lint.yml)
[![fuzz](https://github.com/tarantool/go-gostls/actions/workflows/fuzz.yml/badge.svg)](https://github.com/tarantool/go-gostls/actions/workflows/fuzz.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/tarantool/go-gostls.svg)](https://pkg.go.dev/github.com/tarantool/go-gostls)

A pure-Go TLS 1.2 client with **GOST cipher suites**, shaped like `crypto/tls`:
`Dialer`, `Conn`, `Config`. It speaks the ordinary AES / ECDHE /
ChaCha20-Poly1305 suites *and* the GOST suites the standard library does not —
GOST 28147-89, Kuznyechik and Magma in CTR-OMAC mode, and the VKO / GOST-2018
key exchanges.

**Pure-Go, BSD-2-Clause, `CGO_ENABLED=0`.** No OpenSSL, no cgo, no build tags,
and no GPL code anywhere in the module graph. It is the pure-Go backend for the
go-tlsdialer dialer; the alternative cgo OpenSSL backend lives in that separate
module.

## Quick start

```sh
go get github.com/tarantool/go-gostls
```

```go
import "github.com/tarantool/go-gostls"

d := &gostls.Dialer{
	Config: &gostls.Config{
		ServerName: "example.com",
		// RootCAs/RootCAPEMs verify ordinary chains; GOSTRoots verifies
		// GOST-signed server certificates.
	},
}

conn, err := d.DialContext(ctx, "tcp", "example.com:443")
if err != nil {
	return err
}
defer conn.Close()
// conn is a *gostls.Conn (net.Conn); the handshake has already completed.
```

GOST suites are registered in every build but are not offered by default.
To negotiate one, request it explicitly:

```go
id, ok := gostls.LookupSuiteByName("GOST2012-KUZNYECHIK-KUZNYECHIKOMAC")
if !ok {
	return errors.New("suite not registered")
}

cfg.CipherSuites = []uint16{id}
```

## Documentation

Full API reference:
[pkg.go.dev/github.com/tarantool/go-gostls](https://pkg.go.dev/github.com/tarantool/go-gostls).

Runnable examples live in `example_test.go` and are executed by CI, so they do
not go stale. Locally, browse the docs with `go doc -http=:6060`.

## Scope

TLS 1.2 **client** only. TLS 1.3, the server role, session resumption,
renegotiation, ALPN extensibility and 0-RTT are not supported and are out of
scope.

## Layout

```
go-gostls/              package gostls — crypto/tls-shaped Dialer / Conn / Config
  doc.go config.go conn.go dialer.go suites.go
  internal/handshake/   client state machine
  internal/ke/          key exchange (ECDHE / DHE / RSA; VKO GOST 2001/2012; GOST-2018)
  internal/record/      record layer (null / CBC-HMAC / AEAD / ChaCha20 / GOST CNT-IMIT)
  internal/suites/      suite registry, key schedule, PRF (incl. the GOST suites)
```

Everything below `internal/` is private to the module: the compiler blocks
outside imports, so the public API surface is exactly the root package.

The non-standard TLS algorithms (GOST PRFs, the CTR-ACPKM record mode, the
VKO/GOST-2018 key-exchange glue) live here because they are welded to the
handshake and record state machines. The raw GOST primitives come from
[go-gostcrypto](https://github.com/tarantool/go-gostcrypto), GOST X.509 from
its `x509gost` subpackage; go-gostls supplies the *TLS protocol* use of them.

## Requirements

- **Go 1.25 or later** (tracked by the `go` directive in `go.mod`).
- No cgo and no C toolchain: the module builds and tests with
  `CGO_ENABLED=0`. The race detector needs cgo, so `make testrace` builds with
  `CGO_ENABLED=1`.
- Any OS and architecture supported by the Go toolchain.
- Dependencies — [`go-gostcrypto`](https://github.com/tarantool/go-gostcrypto)
  (BSD-2-Clause), `filippo.io/bigmod`, `golang.org/x/crypto` — all resolve from
  the public module proxy. No `GOPRIVATE` or `.netrc` is required.
- OpenSSL with the GOST reference engine is needed **only** for the optional
  `gostengine`-tagged interop test, which skips itself when the engine is
  absent.

## Building and testing

```sh
make build      # CGO-free build
make test       # unit and round-trip tests (replays the fuzz seed corpus)
make testrace   # tests under the race detector
make coverage   # coverage profile and per-function summary
make lint       # golangci-lint v2, strict `default: all` config
make ci         # the pre-push gate: lint + vet + test
```

## Contributing

Bug reports, feature requests and pull requests are welcome. Please read
[CONTRIBUTING.md](CONTRIBUTING.md) for branch naming, commit message format,
the test and changelog requirements, and the review process.

## License

BSD 2-Clause — see [LICENSE](LICENSE) and [NOTICE](NOTICE). The module links
zero GPL code and carries none in its `go.mod`/`go.sum`.
