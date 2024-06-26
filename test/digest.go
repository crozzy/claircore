package test

import (
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/quay/claircore"
)

// RandomSHA256Digest returns a random Digest.
func RandomSHA256Digest(t testing.TB) claircore.Digest {
	b := make([]byte, sha256.Size)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		t.Fatal(err)
	}
	d, err := claircore.NewDigest("sha256", b)
	if err != nil {
		t.Fatal(err)
	}
	return d
}
