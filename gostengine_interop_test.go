//go:build gostengine

// Real GOST TLS interop against an OpenSSL `s_server`
// driven by the GOST engine. This is the strongest validation of the GOST
// client path: it exercises the full handshake (GOST suite negotiation, GOST
// certificate verification via x509gost, VKO / 2018 key transport, the GOST
// PRF key schedule, and the CNT-IMIT / CTR-OMAC record protectors) against an
// independent implementation, not a self-referential Go server.
//
// It is gated behind the `gostengine` build tag and skips unless both an
// OpenSSL 3 binary and a loadable GOST engine are found, so the default
// pure-Go (`CGO_ENABLED=0 go test ./...`) build stays dependency-free:
//
//	go test -tags gostengine -run TestGOSTEngineInterop ./...
//
// Override discovery with OPENSSL_BIN and GOST_ENGINE_LIB. On macOS/Homebrew:
//
//	export OPENSSL_BIN=/opt/homebrew/opt/openssl@3/bin/openssl
//	export GOST_ENGINE_LIB=/opt/homebrew/Cellar/gost-engine@3.0.3/3.0.3/libexec/engines-3/gost.dylib
package gostls_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tarantool/go-gostcrypto/x509gost"

	"github.com/tarantool/go-gostls"
	"github.com/tarantool/go-gostls/internal/testutil"
)

// openSSL TLS-1.2 GOST cipher names mapped to the gostls suite IDs the client
// must offer to negotiate them.
var gostEngineSuites = []struct {
	opensslCipher string
	gostlsSuiteID uint16
}{
	{"GOST2012-MAGMA-MAGMAOMAC", 0xC101},
	{"GOST2012-KUZNYECHIK-KUZNYECHIKOMAC", 0xC100},
	{"GOST2012-GOST8912-GOST8912", 0xC102},
}

// engineCandidates are searched when GOST_ENGINE_LIB is unset.
var engineCandidates = []string{
	"/opt/homebrew/Cellar/gost-engine@3.0.3/3.0.3/libexec/engines-3/gost.dylib",
	"/usr/lib/x86_64-linux-gnu/engines-3/gost.so",
	"/usr/lib/aarch64-linux-gnu/engines-3/gost.so",
	"/usr/local/lib/engines-3/gost.so",
}

// opensslCandidates are searched when OPENSSL_BIN is unset.
var opensslCandidates = []string{
	"/opt/homebrew/opt/openssl@3/bin/openssl",
	"/usr/bin/openssl",
	"/usr/local/bin/openssl",
}

func firstExisting(env string, candidates []string) string {
	if v := os.Getenv(env); v != "" {
		return v
	}

	for _, c := range candidates {
		_, err := os.Stat(c)
		if err == nil {
			return c
		}
	}

	return ""
}

// gostEngineEnv locates the OpenSSL binary and GOST engine, writes an OpenSSL
// config that loads the engine, and returns (openssl, configPath). It skips the
// test if either is missing or the engine cannot be loaded.
func gostEngineEnv(ctx context.Context, t *testing.T, dir string) (openssl, conf string) {
	t.Helper()

	openssl = firstExisting("OPENSSL_BIN", opensslCandidates)
	if openssl == "" {
		t.Skip("openssl 3 binary not found (set OPENSSL_BIN)")
	}

	engine := firstExisting("GOST_ENGINE_LIB", engineCandidates)
	if engine == "" {
		t.Skip("GOST engine library not found (set GOST_ENGINE_LIB)")
	}

	conf = filepath.Join(dir, "gost.cnf")

	cfg := fmt.Sprintf(`openssl_conf = openssl_def
[openssl_def]
engines = engine_section
[engine_section]
gost = gost_section
[gost_section]
engine_id = gost
dynamic_path = %s
default_algorithms = ALL
`, engine)

	testutil.NoErr(t, os.WriteFile(conf, []byte(cfg), 0o600), "write engine config")

	// Confirm the engine actually loads on this host; skip (not fail) otherwise.
	probe := exec.CommandContext(ctx, openssl, "engine", "gost", "-t")

	probe.Env = append(os.Environ(), "OPENSSL_CONF="+conf)

	out, err := probe.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "available") {
		t.Skipf("GOST engine not loadable: %v\n%s", err, out)
	}

	return openssl, conf
}

// runOpenSSL runs an openssl subcommand with the GOST engine config loaded.
func runOpenSSL(ctx context.Context, t *testing.T, openssl, conf string, args ...string) {
	t.Helper()

	cmd := exec.CommandContext(ctx, openssl, args...)

	cmd.Env = append(os.Environ(), "OPENSSL_CONF="+conf)

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// gostServerCert generates a self-signed GOST2012-256 server cert+key.
func gostServerCert(ctx context.Context, t *testing.T, openssl, conf, dir string) (certPEM, certPath, keyPath string) {
	t.Helper()

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	runOpenSSL(ctx, t, openssl, conf,
		"req", "-x509", "-newkey", "gost2012_256", "-pkeyopt", "paramset:A", "-nodes",
		"-keyout", keyPath, "-out", certPath, "-days", "1",
		"-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
	)

	b, err := os.ReadFile(certPath)
	testutil.NoErr(t, err, "read cert")

	return string(b), certPath, keyPath
}

// freePort returns a currently-free localhost TCP port.
func freePort(ctx context.Context, t *testing.T) int {
	t.Helper()

	var lc net.ListenConfig

	l, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	testutil.NoErr(t, err, "reserve port")

	defer func() { _ = l.Close() }()

	tcpAddr, ok := l.Addr().(*net.TCPAddr)
	testutil.Ok(t, ok, fmt.Sprintf("listener addr type assertion to *net.TCPAddr (got %T)", l.Addr()))

	return tcpAddr.Port
}

// gostRoots parses the server cert PEM into a single-element GOST trust store.
func gostRoots(t *testing.T, certPEM string) []*x509gost.Certificate {
	t.Helper()

	blk, _ := pem.Decode([]byte(certPEM))
	if blk == nil {
		t.Fatal("server cert is not PEM")
	}

	c, err := x509gost.ParseCertificate(blk.Bytes)
	testutil.NoErr(t, err, "parse server GOST cert")

	return []*x509gost.Certificate{c}
}

func TestGOSTEngineInterop(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dir := t.TempDir()
	openssl, conf := gostEngineEnv(ctx, t, dir)
	certPEM, certPath, keyPath := gostServerCert(ctx, t, openssl, conf, dir)
	roots := gostRoots(t, certPEM)

	for _, sc := range gostEngineSuites {
		t.Run(sc.opensslCipher, func(t *testing.T) {
			t.Parallel()

			addr := startGOSTServer(ctx, t, openssl, conf, sc.opensslCipher, certPath, keyPath)

			cfg := &gostls.Config{
				ServerName:   "localhost",
				GOSTRoots:    roots,
				CipherSuites: []uint16{sc.gostlsSuiteID},
			}
			dialer := &gostls.Dialer{Config: cfg}

			dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			conn, err := dialer.DialContext(dialCtx, "tcp", addr)
			testutil.NoErr(t, err, "gostls dial/handshake against "+sc.opensslCipher)

			defer func() { _ = conn.Close() }()

			// Round-trip application data over the GOST channel.
			_, err = conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
			testutil.NoErr(t, err, "write")

			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

			line, err := bufio.NewReader(conn).ReadString('\n')
			testutil.NoErr(t, err, "read response")

			if !strings.Contains(line, "HTTP") {
				t.Fatalf("unexpected response %q", line)
			}

			t.Logf("GOST interop OK: %s -> %q", sc.opensslCipher, strings.TrimSpace(line))
		})
	}
}

const (
	// acceptLine is what `openssl s_server` prints on stdout once its listening
	// socket is bound.
	acceptLine = "ACCEPT"

	serverStartTimeout  = 15 * time.Second
	serverStartAttempts = 3
)

// startGOSTServer launches an `openssl s_server` pinned to a single GOST cipher
// and returns the address to dial once it is listening. The server is killed
// via t.Cleanup.
//
// Readiness comes from the ACCEPT line, not from probing the port: s_server
// accepts a probe connection and starts a handshake on it, and `-www` serves
// connections serially, so a probe that closes immediately leaves the server
// unwinding a failed handshake while the real dial lands — a flaky
// "connection reset by peer" reading ServerHello.
//
// freePort holds a port only long enough to read its number, so a sibling
// parallel subtest can take it before the bind. s_server then exits without
// printing ACCEPT; retry on a fresh port.
func startGOSTServer(ctx context.Context, t *testing.T, openssl, conf, cipher, certPath, keyPath string) string {
	t.Helper()

	for attempt := 1; ; attempt++ {
		port := freePort(ctx, t)
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

		srv := exec.CommandContext(ctx, openssl,
			"s_server", "-accept", strconv.Itoa(port),
			"-cert", certPath, "-key", keyPath,
			"-tls1_2", "-cipher", cipher, "-www",
		)

		srv.Env = append(os.Environ(), "OPENSSL_CONF="+conf)

		// exec guarantees one Write at a time when Stdout == Stderr.
		w := newAcceptWatcher()

		srv.Stdout = w
		srv.Stderr = w

		testutil.NoErr(t, srv.Start(), "start s_server")

		// The only Wait; cleanup drains the same channel. Catches a startup
		// death without waiting out the timeout.
		exited := make(chan error, 1)

		go func() { exited <- srv.Wait() }()

		timer := time.NewTimer(serverStartTimeout)

		var ready bool

		select {
		case <-w.accepted:
			ready = true
		case <-exited:
		case <-timer.C:
		}

		timer.Stop()

		if ready {
			t.Cleanup(func() { _ = srv.Process.Kill(); <-exited })

			return addr
		}

		_ = srv.Process.Kill()

		<-exited

		if attempt == serverStartAttempts {
			t.Fatalf("s_server never reported %s on %s after %d attempts; output:\n%s",
				acceptLine, addr, attempt, w.output())
		}
	}
}

// acceptWatcher closes accepted the first time acceptLine appears in what is
// written to it, retaining the output for diagnostics.
//
// An io.Writer rather than a Cmd.StdoutPipe reader: exec then keeps draining
// the server on its own (`-www` logs a line per connection, and a stalled pipe
// would block it mid-handshake), and nothing races Cmd.Wait.
type acceptWatcher struct {
	accepted chan struct{}
	once     sync.Once

	mu   sync.Mutex
	seen bool
	buf  bytes.Buffer
}

func newAcceptWatcher() *acceptWatcher {
	return &acceptWatcher{accepted: make(chan struct{})}
}

func (w *acceptWatcher) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.buf.Write(p)

	// Scanning the whole buffer, so a split write cannot hide acceptLine.
	found := !w.seen && bytes.Contains(w.buf.Bytes(), []byte(acceptLine))

	if found {
		w.seen = true
	}

	w.mu.Unlock()

	if found {
		w.once.Do(func() { close(w.accepted) })
	}

	return len(p), nil
}

func (w *acceptWatcher) output() string {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.buf.String()
}
