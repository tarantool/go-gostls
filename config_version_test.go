//nolint:testpackage // white-box: tests the unexported checkVersions validator
package gostls

import (
	"testing"

	"github.com/tarantool/go-gostls/internal/testutil"
)

// TestConfig_CheckVersions_Accepted covers the ranges that still contain
// TLS 1.2. They must all pass: the version fields exist for source
// compatibility, so anything that does not actually rule out TLS 1.2 has to
// behave exactly like an unset Config.
func TestConfig_CheckVersions_Accepted(t *testing.T) {
	t.Parallel()

	cases := map[string]Config{
		"unset":             {},
		"pinned to TLS 1.2": {MinVersion: VersionTLS12, MaxVersion: VersionTLS12},
		"floor only":        {MinVersion: VersionTLS12},
		"ceiling only":      {MaxVersion: VersionTLS12},
		"wide range":        {MinVersion: VersionTLS10, MaxVersion: VersionTLS13},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			testutil.NoErr(t, tt.checkVersions(), "checkVersions()")
		})
	}
}

// TestConfig_CheckVersions_Rejected covers the ranges TLS 1.2 falls outside of.
// Each must fail with errVersionRangeExcludesTLS12 rather than being ignored:
// a caller who asked for TLS 1.3 only did not agree to 1.2.
func TestConfig_CheckVersions_Rejected(t *testing.T) {
	t.Parallel()

	cases := map[string]Config{
		"floor above TLS 1.2":   {MinVersion: VersionTLS13},
		"ceiling below TLS 1.2": {MaxVersion: VersionTLS11},
		"inverted range":        {MinVersion: VersionTLS13, MaxVersion: VersionTLS10},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			testutil.ErrIs(t, tt.checkVersions(), errVersionRangeExcludesTLS12, "checkVersions()")
		})
	}
}

// TestConfig_CheckVersions_NilConfig pins the nil-receiver guard: an unset
// *Config constrains nothing and must not fault the handshake.
func TestConfig_CheckVersions_NilConfig(t *testing.T) {
	t.Parallel()

	var cfg *Config

	testutil.NoErr(t, cfg.checkVersions(), "nil Config.checkVersions()")
}

// TestVersionConstants pins the wire values, which are the crypto/tls ones.
// A caller porting `MinVersion: tls.VersionTLS12` over expects the constant to
// mean the same number here, and the validator compares against it directly.
func TestVersionConstants(t *testing.T) {
	t.Parallel()

	testutil.Equal(t, uint16(VersionTLS10), uint16(0x0301), "VersionTLS10")
	testutil.Equal(t, uint16(VersionTLS11), uint16(0x0302), "VersionTLS11")
	testutil.Equal(t, uint16(VersionTLS12), uint16(0x0303), "VersionTLS12")
	testutil.Equal(t, uint16(VersionTLS13), uint16(0x0304), "VersionTLS13")
}
