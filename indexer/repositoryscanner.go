package indexer

import (
	"context"
	"iter"

	"github.com/quay/claircore"
)

type RepositoryScanner interface {
	VersionedScanner
	Scan(context.Context, *claircore.Layer) ([]*claircore.Repository, error)
}

type ComplexRepositoryDetector interface {
	VersionedScanner
	Analyze(context.Context, DataLookup, *claircore.Layer) (iter.Seq2[claircore.Repository, error], error)
}
