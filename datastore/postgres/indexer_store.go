package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/pkg/poolstats"
	"github.com/quay/zlog"
)

// InitDB initialize a postgres pgxpool.Pool based on the connection string
func InitDB(ctx context.Context, connString string) (*pgxpool.Pool, error) {
	// we are going to use pgx for more control over connection pool and
	// and a cleaner api around bulk inserts
	cfg, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ConnString: %v", err)
	}
	cfg.MaxConns = 30
	const appnameKey = `application_name`
	params := cfg.ConnConfig.RuntimeParams
	if _, ok := params[appnameKey]; !ok {
		params[appnameKey] = `libindex`
	}

	pool, err := pgxpool.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create ConnPool: %v", err)
	}

	if err := prometheus.Register(poolstats.NewCollector(pool, "libindex")); err != nil {
		zlog.Info(ctx).Msg("pool metrics already registered")
	}

	return pool, nil
}

var _ indexer.Store = (*IndexerStore)(nil)

// IndexerStore implements the claircore.Store interface.
//
// All the other exported methods live in their own files.
type IndexerStore struct {
	pool *pgxpool.Pool
}

func NewIndexerStore(pool *pgxpool.Pool) *IndexerStore {
	return &IndexerStore{
		pool: pool,
	}
}

func (s *IndexerStore) Close(_ context.Context) error {
	s.pool.Close()
	return nil
}

const selectScanner = `
SELECT
	id
FROM
	scanner
WHERE
	name = $1 AND version = $2 AND kind = $3;
`

func (s *IndexerStore) selectScanners(ctx context.Context, vs indexer.VersionedScanners) ([]int64, error) {
	ids := make([]int64, len(vs))
	for i, v := range vs {
		ctx, done := context.WithTimeout(ctx, time.Second)
		err := s.pool.QueryRow(ctx, selectScanner, v.Name(), v.Version(), v.Kind()).
			Scan(&ids[i])
		done()
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve id for scanner %q: %w", v.Name(), err)
		}
	}

	return ids, nil
}

func promTimer(h *prometheus.HistogramVec, name string, err *error) func() time.Duration {
	t := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
		h.WithLabelValues(name, success(*err)).Observe(v)
	}))
	return t.ObserveDuration
}

func success(err error) string {
	if err == nil {
		return "true"
	}
	return "false"
}
