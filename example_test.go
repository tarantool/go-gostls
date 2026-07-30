package gostls_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"

	stdtls "crypto/tls"

	"github.com/tarantool/go-gostls"
	"github.com/tarantool/go-gostls/internal/testutil"
)

// Example dials a TLS 1.2 server, completes the handshake, and exchanges
// application data. The server here is an in-process crypto/tls echo server
// using a freshly generated CA, so the example is self-contained.
func Example() {
	srv := newExampleServer()
	defer srv.Close()

	d := &gostls.Dialer{
		Config: &gostls.Config{
			// Trust only the example CA. In production, omit RootCAs/RootCAPEMs
			// to use the host's system trust store.
			RootCAPEMs: [][]byte{srv.CACertPEM},
			ServerName: "test.example.com",
		},
	}

	// On error these print and return rather than calling log.Fatal, so the
	// deferred Close calls still run and the mismatch surfaces as a failed
	// Output comparison instead of a killed test binary.
	conn, err := d.DialContext(context.Background(), "tcp", srv.Addr)
	if err != nil {
		fmt.Println("dial:", err)

		return
	}

	defer func() { _ = conn.Close() }()

	_, err = conn.Write([]byte("ping"))
	if err != nil {
		fmt.Println("write:", err)

		return
	}

	buf := make([]byte, 4)

	_, err = io.ReadFull(conn, buf)
	if err != nil {
		fmt.Println("read:", err)

		return
	}

	fmt.Printf("server echoed: %s\n", buf)

	// Output: server echoed: ping
}

// ExampleConfig_cipherSuites shows how to request a specific cipher suite —
// here a GOST suite, which is registered in every build but is not offered by
// default. Resolve the IANA ID by name and set it on Config.CipherSuites.
func ExampleConfig_cipherSuites() {
	id, ok := gostls.LookupSuiteByName("GOST2012-KUZNYECHIK-KUZNYECHIKOMAC")
	if !ok {
		fmt.Println("GOST suite not registered")

		return
	}

	cfg := &gostls.Config{
		ServerName:   "gost.example.com",
		CipherSuites: []uint16{id}, // offer only this suite.
	}

	fmt.Printf("offering 0x%04X (%d suite)\n", cfg.CipherSuites[0], len(cfg.CipherSuites))

	// Output: offering 0xC100 (1 suite)
}

// ExampleLookupSuiteByName resolves a suite name to its IANA cipher suite ID.
func ExampleLookupSuiteByName() {
	id, ok := gostls.LookupSuiteByName("ECDHE-RSA-AES128-GCM-SHA256")
	fmt.Printf("0x%04X %t\n", id, ok)

	_, ok = gostls.LookupSuiteByName("NO-SUCH-SUITE")
	fmt.Println(ok)

	// Output:
	// 0xC02F true
	// false
}

// ExampleAllSuites iterates the registered cipher suites. The order is stable
// but unspecified, so this example reports whether a known suite is present
// rather than printing the whole list.
func ExampleAllSuites() {
	want := "GOST2012-MAGMA-MAGMAOMAC"
	found := false

	for _, s := range gostls.AllSuites() {
		if s.Name == want {
			found = true

			break
		}
	}

	fmt.Printf("%s registered: %t\n", want, found)

	// Output: GOST2012-MAGMA-MAGMAOMAC registered: true
}

// ExampleBackendTag reports which TLS backend is compiled in. The pure-Go
// gostls module always reports "default"; the cgo OpenSSL backend (in the
// separate dialer module) reports "openssl".
func ExampleBackendTag() {
	fmt.Println(gostls.BackendTag())

	// Output: default
}

// exampleServer is a minimal in-process crypto/tls 1.2 echo server used by
// Example. It is helper machinery, not part of the documented API.

type exampleServer struct {
	Addr      string
	CACertPEM []byte
	listener  net.Listener
}

func (s *exampleServer) Close() { _ = s.listener.Close() }

// newExampleServer generates a CA + leaf certificate for "test.example.com"
// and starts a TLS 1.2 listener that echoes whatever it receives. It panics on
// any error (via testutil.Must), which is acceptable for an example.
func newExampleServer() *exampleServer {
	caKey := testutil.Must(rsa.GenerateKey(rand.Reader, 2048))

	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Example CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	caDER := testutil.Must(x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey))
	caCert := testutil.Must(x509.ParseCertificate(caDER))
	leafKey := testutil.Must(rsa.GenerateKey(rand.Reader, 2048))

	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		DNSNames:     []string{"test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	leafDER := testutil.Must(x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey))

	// G402 reads MaxVersion as "too low", but pinning it is the point: gostls
	// speaks TLS 1.2 only, so this example's server has to stay there.
	cfg := &stdtls.Config{ //nolint:gosec
		Certificates: []stdtls.Certificate{{
			Certificate: [][]byte{leafDER},
			PrivateKey:  leafKey,
		}},
		MinVersion: stdtls.VersionTLS12,
		MaxVersion: stdtls.VersionTLS12,
	}

	ln := testutil.Must(stdtls.Listen("tcp", "127.0.0.1:0", cfg))

	go func() {
		for {
			c, acceptErr := ln.Accept()
			if acceptErr != nil {
				return // listener closed.
			}

			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()

				buf := make([]byte, 4096)
				for {
					n, readErr := conn.Read(buf)
					if readErr != nil {
						return
					}

					_, writeErr := conn.Write(buf[:n])
					if writeErr != nil {
						return
					}
				}
			}(c)
		}
	}()

	return &exampleServer{
		Addr:      ln.Addr().String(),
		CACertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		listener:  ln,
	}
}
