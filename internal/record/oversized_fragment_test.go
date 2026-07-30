package record_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/tarantool/go-gostls/internal/record"
	"github.com/tarantool/go-gostls/internal/testutil"
)

// oversizedProtector seals to a fragment larger than a TLS record may carry.
// A real protector cannot do this, but the record layer must not depend on
// every Protector being well-behaved: the sealed length goes straight into the
// header's uint16, so an over-long fragment would wrap and produce a header
// that disagrees with the bytes following it.
type oversizedProtector struct{ size int }

func (p oversizedProtector) Seal(_ uint64, _, _ []byte) ([]byte, error) {
	return make([]byte, p.size), nil
}

func (p oversizedProtector) Open(_ uint64, _, fragment []byte) ([]byte, error) {
	return fragment, nil
}

// TestWriteRecord_OversizedSealedFragmentRejected is the regression test for
// the asymmetry between the read and write paths: ReadRecord enforced
// maxFragmentLen, WriteRecord only checked the plaintext, never the sealed
// fragment (which is longer by the padding, MAC or AEAD tag).
func TestWriteRecord_OversizedSealedFragmentRejected(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	layer := record.NewLayer(buf)

	// 70000 bytes: over the uint16 the record header can express.
	layer.ChangeCipherSpec(oversizedProtector{size: 70000}, oversizedProtector{size: 70000})

	err := layer.WriteRecord(record.ContentTypeApplicationData, []byte("hi"))

	testutil.WantErr(t, err, "WriteRecord with a 70000-byte sealed fragment")

	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("expected an over-length error, got %v", err)
	}

	testutil.Equal(t, buf.Len(), 0, "bytes reaching the wire on rejection")
}

// TestWriteRecord_FragmentAtLimitAccepted pins the other edge so the guard
// cannot be tightened into rejecting legitimate records.
func TestWriteRecord_FragmentAtLimitAccepted(t *testing.T) {
	t.Parallel()

	const maxFragment = 16384 + 2048 // tlsMaxPlaintextLen + tlsMaxCiphertextOverhead.

	buf := new(bytes.Buffer)
	layer := record.NewLayer(buf)

	layer.ChangeCipherSpec(oversizedProtector{size: maxFragment}, oversizedProtector{size: maxFragment})

	err := layer.WriteRecord(record.ContentTypeApplicationData, []byte("hi"))

	testutil.NoErr(t, err, fmt.Sprintf("WriteRecord with a fragment of exactly %d bytes", maxFragment))
}
