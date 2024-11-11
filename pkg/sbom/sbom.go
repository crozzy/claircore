package sbom

import (
	"context"
	"github.com/quay/claircore"
	"io"
)

type Encoder interface {
	Encode(ctx context.Context, ir *claircore.IndexReport) (io.Reader, error)
}

type Decoder interface {
	Decode(ctx context.Context, r io.Reader) (*claircore.IndexReport, error)
}

// TODO(DO NOT MERGE): Probably don't need this anymore?
func FromIndexReport(ctx context.Context, ir *claircore.IndexReport, e Encoder) (io.Reader, error) {
	return e.Encode(ctx, ir)
}
