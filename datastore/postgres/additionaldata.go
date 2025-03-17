package postgres

import (
	"context"
	"fmt"
	"io"

	"github.com/jackc/pgx/v4"
	"github.com/quay/claircore/updater/driver/v1"
)

func (s *IndexerStore) GetData(ctx context.Context, namespace string, key string, dec func(context.Context, io.Reader) (any, error)) (any, error) {
	return dec(ctx, nil) // I don't remember how this works
}

// TODO(crozzy): accept an iter here?
// TODO(crozzy): add tracing
func (s *IndexerStore) UpdateIndexerData(ctx context.Context, _ driver.Fingerprint, ds []driver.IndexerData) error {
	const (
		upsertAdditionalData = `
		INSERT INTO additional_data (
			namespace,
			lookup_key,
			data
		) VALUES (
			$1,
			$2,
			$3 
		)
		ON CONFLICT (namespace, lookup_key)
		DO UPDATE SET data = EXCLUDED.data;
		`
	)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to create transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	for _, d := range ds {
		// Deal with large object
		// TODO(crozzy): How to check for duplicate large objects in this process?
		lo := tx.LargeObjects()
		oid, err := lo.Create(ctx, 0)
		if err != nil {
			return fmt.Errorf("failed to create large object: %w", err)
		}
		obj, err := lo.Open(ctx, oid, pgx.LargeObjectModeWrite)
		if err != nil {
			return fmt.Errorf("failed to open large object: %w", err)
		}
		if _, err = obj.Write(d.Value); err != nil {
			return fmt.Errorf("failed to write large object: %w", err)
		}
		if _, err := tx.Exec(ctx, upsertAdditionalData, d.Namespace, d.Key, oid); err != nil {
			return fmt.Errorf("failed to upsert additional data: %w", err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}
