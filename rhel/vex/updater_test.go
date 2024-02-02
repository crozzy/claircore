package vex

import (
	"errors"
	"testing"

	"github.com/quay/claircore/libvuln/driver"
)

func TestFingerprintRoundTrip(t *testing.T) {
	testcases := []struct {
		name string
		val  driver.Fingerprint
		err  bool
	}{
		{
			name: "simple",
			val:  `one\two\2006-01-02T15:04:05Z`,
			err:  false,
		},
		{
			name: "date error",
			val:  `one\two\2006-01-02T15:04:05ZMore`,
			err:  true,
		},
		{
			name: "etag error",
			val:  `one\tw\o\2006-01-02T15:04:05ZMore`,
			err:  true,
		},
	}
	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			fp, err := ParseFingerprint(tt.val)
			if !tt.err {
				if !errors.Is(err, nil) {
					t.Fatal("unexpected error:", err)
				}
				if fp.String() != string(tt.val) {
					t.Errorf("expected fingerprint: %s but got: %s", tt.val, fp)
				}

			}
			if tt.err && errors.Is(err, nil) {
				t.Fatal("unexpected non-error")
			}
		})
	}
}
