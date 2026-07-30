package suites

import (
	"crypto/sha1" //nolint:gosec // SHA-1 is used only for legacy CBC-SHA suites per RFC 5246
	"hash"
)

// sha1New returns a new SHA-1 hash. Used exclusively for legacy CBC-SHA suites
// (ECDHE-*-AES*-SHA, DHE-RSA-AES*-SHA, AES*-SHA) where the IANA definition
// mandates HMAC-SHA1 as the MAC. No new suites use SHA-1.
func sha1New() hash.Hash {
	// G401: SHA-1 is not a choice here. RFC 5246 defines the CBC-SHA suites as
	// HMAC-SHA1, so a client that wants to interoperate on them has to compute
	// it. These suites are registered but are not offered by default.
	return sha1.New() //nolint:gosec
}
