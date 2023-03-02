package postgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgtype"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/jackc/pgx/v4/stdlib"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/remind101/migrate"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore/postgres/migrations"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/pkg/microbatch"
	"github.com/quay/zlog"
)

// InitPostgresIndexerStore initialize a indexer.Store given the pgxpool.Pool
func InitPostgresIndexerStore(_ context.Context, pool *pgxpool.Pool, doMigration bool) (indexer.Store, error) {
	db := stdlib.OpenDB(*pool.Config().ConnConfig)
	defer db.Close()

	// do migrations if requested
	if doMigration {
		migrator := migrate.NewPostgresMigrator(db)
		migrator.Table = migrations.IndexerMigrationTable
		err := migrator.Exec(migrate.Up, migrations.IndexerMigrations...)
		if err != nil {
			return nil, fmt.Errorf("failed to perform migrations: %w", err)
		}
	}

	store := NewIndexerStore(pool)
	return store, nil
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

func (s *IndexerStore) IndexManifest(ctx context.Context, ir *claircore.IndexReport) error {
	const (
		query = `
		WITH manifests AS (
			SELECT id AS manifest_id
			FROM manifest
			WHERE hash = $4
		)
		INSERT
		INTO manifest_index(package_id, dist_id, repo_id, manifest_id)
		VALUES ($1, $2, $3, (SELECT manifest_id FROM manifests))
		ON CONFLICT DO NOTHING;
		`
	)
	ctx = zlog.ContextWithValues(ctx, "component", "datastore/postgres/indexManifest")

	if ir.Hash.String() == "" {
		return fmt.Errorf("received empty hash. cannot associate contents with a manifest hash")
	}
	hash := ir.Hash.String()

	records := ir.IndexRecords()
	if len(records) == 0 {
		zlog.Warn(ctx).Msg("manifest being indexed has 0 index records")
		return nil
	}

	// obtain a transaction scoped batch
	tctx, done := context.WithTimeout(ctx, 5*time.Second)
	tx, err := s.pool.Begin(tctx)
	done()
	if err != nil {
		return fmt.Errorf("postgres: indexManifest failed to create transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	tctx, done = context.WithTimeout(ctx, 5*time.Second)
	queryStmt, err := tx.Prepare(tctx, "queryStmt", query)
	done()
	if err != nil {
		return fmt.Errorf("failed to create statement: %w", err)
	}

	start := time.Now()
	mBatcher := microbatch.NewInsert(tx, 500, time.Minute)
	for _, record := range records {
		// ignore nil packages
		if record.Package == nil {
			continue
		}

		v, err := toValues(*record)
		if err != nil {
			return fmt.Errorf("received a record with an invalid id: %v", err)
		}

		// if source package exists create record
		if v[0] != nil {
			err = mBatcher.Queue(
				ctx,
				queryStmt.SQL,
				v[0],
				v[2],
				v[3],
				hash,
			)
			if err != nil {
				return fmt.Errorf("batch insert failed for source package record %v: %w", record, err)
			}
		}

		err = mBatcher.Queue(
			ctx,
			queryStmt.SQL,
			v[1],
			v[2],
			v[3],
			hash,
		)
		if err != nil {
			return fmt.Errorf("batch insert failed for package record %v: %w", record, err)
		}

	}
	err = mBatcher.Done(ctx)
	if err != nil {
		return fmt.Errorf("final batch insert failed: %w", err)
	}
	indexManifestCounter.WithLabelValues("query_batch").Add(1)
	indexManifestDuration.WithLabelValues("query_batch").Observe(time.Since(start).Seconds())

	tctx, done = context.WithTimeout(ctx, 15*time.Second)
	err = tx.Commit(tctx)
	done()
	if err != nil {
		return fmt.Errorf("failed to commit tx: %w", err)
	}
	return nil
}

// toValues is a helper method which checks for
// nil pointers inside an IndexRecord before
// returning an associated pointer to the artifact
// in question.
//
// v[0] source package id or nil
// v[1] package id or nil
// v[2] distribution id or nil
// v[3] repository id or nil
func toValues(r claircore.IndexRecord) ([4]*uint64, error) {
	res := [4]*uint64{}

	if r.Package.Source != nil {
		id, err := strconv.ParseUint(r.Package.Source.ID, 10, 64)
		if err != nil {
			return res, fmt.Errorf("source package id %v: %v", r.Package.ID, err)
		}
		res[0] = &id
	}

	if r.Package != nil {
		id, err := strconv.ParseUint(r.Package.ID, 10, 64)
		if err != nil {
			return res, fmt.Errorf("package id %v: %v", r.Package.ID, err)
		}
		res[1] = &id

	}

	if r.Distribution != nil {
		id, err := strconv.ParseUint(r.Distribution.ID, 10, 64)
		if err != nil {
			return res, fmt.Errorf("distribution id %v: %v", r.Distribution.ID, err)
		}
		res[2] = &id
	}

	if r.Repository != nil {
		id, err := strconv.ParseUint(r.Repository.ID, 10, 64)
		if err != nil {
			// return res, fmt.Errorf("repository id %v: %v", r.Package.ID, err)
			return res, nil
		}
		res[3] = &id
	}

	return res, nil
}

// AffectedManifests finds the manifests digests which are affected by the provided vulnerability.
//
// An exhaustive search for all indexed packages of the same name as the vulnerability is performed.
//
// The list of packages is filtered down to only the affected set.
//
// The manifest index is then queried to resolve a list of manifest hashes containing the affected
// artifacts.
func (s *IndexerStore) AffectedManifests(ctx context.Context, v claircore.Vulnerability, vulnFunc claircore.CheckVulnernableFunc) ([]claircore.Digest, error) {
	const (
		selectPackages = `
SELECT
	id,
	name,
	version,
	kind,
	norm_kind,
	norm_version,
	module,
	arch
FROM
	package
WHERE
	name = $1;
`
		selectAffected = `
SELECT
	manifest.hash
FROM
	manifest_index
	JOIN manifest ON
			manifest_index.manifest_id = manifest.id
WHERE
	package_id = $1
	AND (
			CASE
			WHEN $2::INT8 IS NULL THEN dist_id IS NULL
			ELSE dist_id = $2
			END
		)
	AND (
			CASE
			WHEN $3::INT8 IS NULL THEN repo_id IS NULL
			ELSE repo_id = $3
			END
		);
`
	)
	ctx = zlog.ContextWithValues(ctx, "component", "datastore/postgres/affectedManifests")

	// confirm the incoming vuln can be
	// resolved into a prototype index record
	pr, err := protoRecord(ctx, s.pool, v)
	switch {
	case err == nil:
		// break out
	case errors.Is(err, ErrNotIndexed):
		// This is a common case: the system knows of a vulnerability but
		// doesn't know of any manifests it could apply to.
		return nil, nil
	default:
		return nil, err
	}

	// collect all packages which may be affected
	// by the vulnerability in question.
	pkgsToFilter := []claircore.Package{}

	tctx, done := context.WithTimeout(ctx, 30*time.Second)
	defer done()
	start := time.Now()
	rows, err := s.pool.Query(tctx, selectPackages, v.Package.Name)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return []claircore.Digest{}, nil
	default:
		return nil, fmt.Errorf("failed to query packages associated with vulnerability %q: %w", v.ID, err)
	}
	defer rows.Close()
	affectedManifestsCounter.WithLabelValues("selectPackages").Add(1)
	affectedManifestsDuration.WithLabelValues("selectPackages").Observe(time.Since(start).Seconds())

	for rows.Next() {
		var pkg claircore.Package
		var id int64
		var nKind *string
		var nVer pgtype.Int4Array
		err := rows.Scan(
			&id,
			&pkg.Name,
			&pkg.Version,
			&pkg.Kind,
			&nKind,
			&nVer,
			&pkg.Module,
			&pkg.Arch,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan package: %w", err)
		}
		idStr := strconv.FormatInt(id, 10)
		pkg.ID = idStr
		if nKind != nil {
			pkg.NormalizedVersion.Kind = *nKind
			for i, n := range nVer.Elements {
				pkg.NormalizedVersion.V[i] = n.Int
			}
		}
		pkgsToFilter = append(pkgsToFilter, pkg)
	}
	zlog.Debug(ctx).Int("count", len(pkgsToFilter)).Msg("packages to filter")
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error scanning packages: %w", err)
	}

	// for each package discovered create an index record
	// and determine if any in-tree matcher finds the record vulnerable
	var filteredRecords []claircore.IndexRecord
	for _, pkg := range pkgsToFilter {
		pr.Package = &pkg
		match, err := vulnFunc(ctx, &pr, &v)
		if err != nil {
			return nil, err
		}
		if match {
			p := pkg // make a copy, or else you'll get a stale reference later
			filteredRecords = append(filteredRecords, claircore.IndexRecord{
				Package:      &p,
				Distribution: pr.Distribution,
				Repository:   pr.Repository,
			})
		}
	}
	zlog.Debug(ctx).Int("count", len(filteredRecords)).Msg("vulnerable index records")

	// Query the manifest index for manifests containing the vulnerable
	// IndexRecords and create a set containing each unique manifest.
	set := map[string]struct{}{}
	out := []claircore.Digest{}
	for _, record := range filteredRecords {
		v, err := toValues(record)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve record %+v to sql values for query: %w", record, err)
		}

		err = func() error {
			tctx, done := context.WithTimeout(ctx, 30*time.Second)
			defer done()
			start := time.Now()
			rows, err := s.pool.Query(tctx,
				selectAffected,
				record.Package.ID,
				v[2],
				v[3],
			)
			switch {
			case errors.Is(err, nil):
			case errors.Is(err, pgx.ErrNoRows):
				err = fmt.Errorf("failed to query the manifest index: %w", err)
				fallthrough
			default:
				return err
			}
			defer rows.Close()
			affectedManifestsCounter.WithLabelValues("selectAffected").Add(1)
			affectedManifestsDuration.WithLabelValues("selectAffected").Observe(time.Since(start).Seconds())

			for rows.Next() {
				var hash claircore.Digest
				err := rows.Scan(&hash)
				if err != nil {
					return fmt.Errorf("failed scanning manifest hash into digest: %w", err)
				}
				if _, ok := set[hash.String()]; !ok {
					set[hash.String()] = struct{}{}
					out = append(out, hash)
				}
			}
			return rows.Err()
		}()
		if err != nil {
			return nil, err
		}
	}
	zlog.Debug(ctx).Int("count", len(out)).Msg("affected manifests")
	return out, nil
}

// protoRecord is a helper method which resolves a Vulnerability to an IndexRecord with no Package defined.
//
// it is an error for both a distribution and a repo to be missing from the Vulnerability.
func protoRecord(ctx context.Context, pool *pgxpool.Pool, v claircore.Vulnerability) (claircore.IndexRecord, error) {
	const (
		selectDist = `
		SELECT id
		FROM dist
		WHERE arch = $1
		  AND cpe = $2
		  AND did = $3
		  AND name = $4
		  AND pretty_name = $5
		  AND version = $6
		  AND version_code_name = $7
		  AND version_id = $8;
		`
		selectRepo = `
		SELECT id
		FROM repo
		WHERE name = $1
			AND key = $2
			AND uri = $3;
		`
		timeout = 5 * time.Second
	)
	ctx = zlog.ContextWithValues(ctx, "component", "datastore/postgres/protoRecord")

	protoRecord := claircore.IndexRecord{}
	// fill dist into prototype index record if exists
	if (v.Dist != nil) && (v.Dist.Name != "") {
		start := time.Now()
		ctx, done := context.WithTimeout(ctx, timeout)
		row := pool.QueryRow(ctx,
			selectDist,
			v.Dist.Arch,
			v.Dist.CPE,
			v.Dist.DID,
			v.Dist.Name,
			v.Dist.PrettyName,
			v.Dist.Version,
			v.Dist.VersionCodeName,
			v.Dist.VersionID,
		)
		var id pgtype.Int8
		err := row.Scan(&id)
		done()
		if err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				return protoRecord, fmt.Errorf("failed to scan dist: %w", err)
			}
		}
		protoRecordCounter.WithLabelValues("selectDist").Add(1)
		protoRecordDuration.WithLabelValues("selectDist").Observe(time.Since(start).Seconds())

		if id.Status == pgtype.Present {
			id := strconv.FormatInt(id.Int, 10)
			protoRecord.Distribution = &claircore.Distribution{
				ID:              id,
				Arch:            v.Dist.Arch,
				CPE:             v.Dist.CPE,
				DID:             v.Dist.DID,
				Name:            v.Dist.Name,
				PrettyName:      v.Dist.PrettyName,
				Version:         v.Dist.Version,
				VersionCodeName: v.Dist.VersionCodeName,
				VersionID:       v.Dist.VersionID,
			}
			zlog.Debug(ctx).Str("id", id).Msg("discovered distribution id")
		}
	}

	// fill repo into prototype index record if exists
	if (v.Repo != nil) && (v.Repo.Name != "") {
		start := time.Now()
		ctx, done := context.WithTimeout(ctx, timeout)
		row := pool.QueryRow(ctx, selectRepo,
			v.Repo.Name,
			v.Repo.Key,
			v.Repo.URI,
		)
		var id pgtype.Int8
		err := row.Scan(&id)
		done()
		if err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				return protoRecord, fmt.Errorf("failed to scan repo: %w", err)
			}
		}
		protoRecordCounter.WithLabelValues("selectDist").Add(1)
		protoRecordDuration.WithLabelValues("selectDist").Observe(time.Since(start).Seconds())

		if id.Status == pgtype.Present {
			id := strconv.FormatInt(id.Int, 10)
			protoRecord.Repository = &claircore.Repository{
				ID:   id,
				Key:  v.Repo.Key,
				Name: v.Repo.Name,
				URI:  v.Repo.URI,
			}
			zlog.Debug(ctx).Str("id", id).Msg("discovered repo id")
		}
	}

	// we need at least a repo or distribution to continue
	if (protoRecord.Distribution == nil) && (protoRecord.Repository == nil) {
		return protoRecord, ErrNotIndexed
	}

	return protoRecord, nil
}

func (s *IndexerStore) DeleteManifests(ctx context.Context, d ...claircore.Digest) ([]claircore.Digest, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "datastore/postgres/DeleteManifests")
	rm, err := s.deleteManifests(ctx, d)
	if err != nil {
		return nil, err
	}
	return rm, s.layerCleanup(ctx)
}

func (s *IndexerStore) deleteManifests(ctx context.Context, d []claircore.Digest) ([]claircore.Digest, error) {
	const deleteManifest = `DELETE FROM manifest WHERE hash = ANY($1::TEXT[]) RETURNING manifest.hash;`
	var err error
	defer promTimer(deleteManifestsDuration, "deleteManifest", &err)()
	defer func(e *error) {
		deleteManifestsCounter.WithLabelValues("deleteManifest", success(*e)).Inc()
	}(&err)
	rows, err := s.pool.Query(ctx, deleteManifest, digestSlice(d))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rm := make([]claircore.Digest, 0, len(d)) // May over-allocate, but at least it's only doing it once.
	for rows.Next() {
		i := len(rm)
		rm = rm[:i+1]
		err = rows.Scan(&rm[i])
		if err != nil {
			return nil, err
		}
	}
	err = rows.Err()
	if err != nil {
		return nil, err
	}
	zlog.Debug(ctx).
		Int("count", len(rm)).
		Int("nonexistant", len(d)-len(rm)).
		Msg("deleted manifests")
	return rm, nil
}

func (s *IndexerStore) layerCleanup(ctx context.Context) (err error) {
	const layerCleanup = `DELETE FROM layer WHERE NOT EXISTS (SELECT FROM manifest_layer WHERE manifest_layer.layer_id = layer.id);`
	defer promTimer(deleteManifestsDuration, "layerCleanup", &err)()
	tag, err := s.pool.Exec(ctx, layerCleanup)
	deleteManifestsCounter.WithLabelValues("layerCleanup", success(err)).Inc()
	if err != nil {
		return err
	}
	zlog.Debug(ctx).
		Int64("count", tag.RowsAffected()).
		Msg("deleted layers")
	return nil
}

func (s *IndexerStore) DistributionsByLayer(ctx context.Context, hash claircore.Digest, scnrs indexer.VersionedScanners) ([]*claircore.Distribution, error) {
	const (
		selectScanner = `
		SELECT id
		FROM scanner
		WHERE name = $1
		  AND version = $2
		  AND kind = $3;
		`
		query = `
		SELECT dist.id,
			   dist.name,
			   dist.did,
			   dist.version,
			   dist.version_code_name,
			   dist.version_id,
			   dist.arch,
			   dist.cpe,
			   dist.pretty_name
		FROM dist_scanartifact
				 LEFT JOIN dist ON dist_scanartifact.dist_id = dist.id
				 JOIN layer ON layer.hash = $1
		WHERE dist_scanartifact.layer_id = layer.id
		  AND dist_scanartifact.scanner_id = ANY($2);
		`
	)

	if len(scnrs) == 0 {
		return []*claircore.Distribution{}, nil
	}

	// get scanner ids
	scannerIDs := make([]int64, len(scnrs))
	for i, scnr := range scnrs {
		ctx, done := context.WithTimeout(ctx, time.Second)
		start := time.Now()
		err := s.pool.QueryRow(ctx, selectScanner, scnr.Name(), scnr.Version(), scnr.Kind()).
			Scan(&scannerIDs[i])
		done()
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve distribution ids for scanner %q: %w", scnr, err)
		}
		distributionByLayerCounter.WithLabelValues("selectScanner").Add(1)
		distributionByLayerDuration.WithLabelValues("selectScanner").Observe(time.Since(start).Seconds())
	}

	ctx, done := context.WithTimeout(ctx, 30*time.Second)
	defer done()
	start := time.Now()
	rows, err := s.pool.Query(ctx, query, hash, scannerIDs)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return nil, fmt.Errorf("store:distributionsByLayer no distribution found for hash %v and scanners %v", hash, scnrs)
	default:
		return nil, fmt.Errorf("store:distributionsByLayer failed to retrieve package rows for hash %v and scanners %v: %w", hash, scnrs, err)
	}
	distributionByLayerCounter.WithLabelValues("query").Add(1)
	distributionByLayerDuration.WithLabelValues("query").Observe(time.Since(start).Seconds())
	defer rows.Close()

	res := []*claircore.Distribution{}
	for rows.Next() {
		var dist claircore.Distribution

		var id int64
		err := rows.Scan(
			&id,
			&dist.Name,
			&dist.DID,
			&dist.Version,
			&dist.VersionCodeName,
			&dist.VersionID,
			&dist.Arch,
			&dist.CPE,
			&dist.PrettyName,
		)
		dist.ID = strconv.FormatInt(id, 10)
		if err != nil {
			return nil, fmt.Errorf("failed to scan distribution: %w", err)
		}

		res = append(res, &dist)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return res, nil
}

func (s *IndexerStore) IndexDistributions(ctx context.Context, dists []*claircore.Distribution, layer *claircore.Layer, scnr indexer.VersionedScanner) error {
	const (
		insert = `
		INSERT INTO dist 
			(name, did, version, version_code_name, version_id, arch, cpe, pretty_name) 
		VALUES 
			($1, $2, $3, $4, $5, $6, $7, $8) 
		ON CONFLICT (name, did, version, version_code_name, version_id, arch, cpe, pretty_name) DO NOTHING;
		`

		insertWith = `
		WITH distributions AS (
			SELECT id AS dist_id
			FROM dist
			WHERE name = $1
			  AND did = $2
			  AND version = $3
			  AND version_code_name = $4
			  AND version_id = $5
			  AND arch = $6
			  AND cpe = $7
			  AND pretty_name = $8
		),
			 scanner AS (
				 SELECT id AS scanner_id
				 FROM scanner
				 WHERE name = $9
				   AND version = $10
				   AND kind = $11
			 ),
			 layer AS (
				 SELECT id AS layer_id
				 FROM layer
				 WHERE layer.hash = $12
			 )
		INSERT
		INTO dist_scanartifact (layer_id, dist_id, scanner_id)
		VALUES ((SELECT layer_id FROM layer),
				(SELECT dist_id FROM distributions),
				(SELECT scanner_id FROM scanner))
		ON CONFLICT DO NOTHING;
		`
	)

	// obtain a transaction scoped batch
	tctx, done := context.WithTimeout(ctx, 5*time.Second)
	tx, err := s.pool.Begin(tctx)
	done()
	if err != nil {
		return fmt.Errorf("store:indexDistributions failed to create transaction: %v", err)
	}
	defer tx.Rollback(ctx)

	tctx, done = context.WithTimeout(ctx, 5*time.Second)
	insertDistStmt, err := tx.Prepare(tctx, "insertDistStmt", insert)
	done()
	if err != nil {
		return fmt.Errorf("failed to create statement: %w", err)
	}
	tctx, done = context.WithTimeout(ctx, 5*time.Second)
	insertDistScanArtifactWithStmt, err := tx.Prepare(tctx, "insertDistScanArtifactWith", insertWith)
	done()
	if err != nil {
		return fmt.Errorf("failed to create statement: %w", err)
	}

	start := time.Now()
	mBatcher := microbatch.NewInsert(tx, 500, time.Minute)
	for _, dist := range dists {
		err := mBatcher.Queue(
			ctx,
			insertDistStmt.SQL,
			dist.Name,
			dist.DID,
			dist.Version,
			dist.VersionCodeName,
			dist.VersionID,
			dist.Arch,
			dist.CPE,
			dist.PrettyName,
		)
		if err != nil {
			return fmt.Errorf("batch insert failed for dist %v: %w", dist, err)
		}
	}
	err = mBatcher.Done(ctx)
	if err != nil {
		return fmt.Errorf("final batch insert failed for dist: %w", err)
	}
	indexDistributionsCounter.WithLabelValues("insert_batch").Add(1)
	indexDistributionsDuration.WithLabelValues("insert_batch").Observe(time.Since(start).Seconds())

	// make dist scan artifacts
	start = time.Now()
	mBatcher = microbatch.NewInsert(tx, 500, time.Minute)
	for _, dist := range dists {
		err := mBatcher.Queue(
			ctx,
			insertDistScanArtifactWithStmt.SQL,
			dist.Name,
			dist.DID,
			dist.Version,
			dist.VersionCodeName,
			dist.VersionID,
			dist.Arch,
			dist.CPE,
			dist.PrettyName,
			scnr.Name(),
			scnr.Version(),
			scnr.Kind(),
			layer.Hash,
		)
		if err != nil {
			return fmt.Errorf("batch insert failed for dist_scanartifact %v: %w", dist, err)
		}
	}
	err = mBatcher.Done(ctx)
	if err != nil {
		return fmt.Errorf("final batch insert failed for dist_scanartifact: %w", err)
	}
	indexDistributionsCounter.WithLabelValues("insertWith_batch").Add(1)
	indexDistributionsDuration.WithLabelValues("insertWith_batch").Observe(time.Since(start).Seconds())

	tctx, done = context.WithTimeout(ctx, 5*time.Second)
	err = tx.Commit(tctx)
	done()
	if err != nil {
		return fmt.Errorf("store:indexDistributions failed to commit tx: %w", err)
	}
	return nil
}

// IndexPackages indexes all provided packages along with creating a scan artifact.
//
// If a source package is nested inside a binary package we index the source
// package first and then create a relation between the binary package and
// source package.
//
// Scan artifacts are used to determine if a particular layer has been scanned by a
// particular scanner. See the LayerScanned method for more details.
func (s *IndexerStore) IndexPackages(ctx context.Context, pkgs []*claircore.Package, layer *claircore.Layer, scnr indexer.VersionedScanner) error {
	const (
		insert = ` 
		INSERT INTO package (name, kind, version, norm_kind, norm_version, module, arch)
		VALUES ($1, $2, $3, $4, $5::int[], $6, $7)
		ON CONFLICT (name, kind, version, module, arch) DO NOTHING;
		`

		insertWith = `
		WITH source_package AS (
			SELECT id AS source_id
			FROM package
			WHERE name = $1
			  AND kind = $2
			  AND version = $3
			  AND module = $4
			  AND arch = $5
		),
			 binary_package AS (
				 SELECT id AS package_id
				 FROM package
				 WHERE name = $6
				   AND kind = $7
				   AND version = $8
				   AND module = $9
				   AND arch = $10
			 ),
			 scanner AS (
				 SELECT id AS scanner_id
				 FROM scanner
				 WHERE name = $11
				   AND version = $12
				   AND kind = $13
			 ),
			 layer AS (
				 SELECT id AS layer_id
				 FROM layer
				 WHERE layer.hash = $14
			 )
		INSERT
		INTO package_scanartifact (layer_id, package_db, repository_hint, package_id, source_id, scanner_id)
		VALUES ((SELECT layer_id FROM layer),
				$15,
				$16,
				(SELECT package_id FROM binary_package),
				(SELECT source_id FROM source_package),
				(SELECT scanner_id FROM scanner))
		ON CONFLICT DO NOTHING;
		`
	)

	ctx = zlog.ContextWithValues(ctx, "component", "datastore/postgres/indexPackages")
	// obtain a transaction scoped batch
	tctx, done := context.WithTimeout(ctx, 5*time.Second)
	tx, err := s.pool.Begin(tctx)
	done()
	if err != nil {
		return fmt.Errorf("store:indexPackage failed to create transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	tctx, done = context.WithTimeout(ctx, 5*time.Second)
	insertPackageStmt, err := tx.Prepare(tctx, "insertPackageStmt", insert)
	done()
	if err != nil {
		return fmt.Errorf("failed to create statement: %w", err)
	}
	tctx, done = context.WithTimeout(ctx, 5*time.Second)
	insertPackageScanArtifactWithStmt, err := tx.Prepare(tctx, "insertPackageScanArtifactWith", insertWith)
	done()
	if err != nil {
		return fmt.Errorf("failed to create statement: %w", err)
	}

	skipCt := 0

	start := time.Now()
	mBatcher := microbatch.NewInsert(tx, 500, time.Minute)
	for _, pkg := range pkgs {
		if pkg.Name == "" {
			skipCt++
		}
		if pkg.Source == nil {
			pkg.Source = &zeroPackage
		}

		if err := queueInsert(ctx, mBatcher, insertPackageStmt.Name, pkg.Source); err != nil {
			return err
		}
		if err := queueInsert(ctx, mBatcher, insertPackageStmt.Name, pkg); err != nil {
			return err
		}
	}
	err = mBatcher.Done(ctx)
	if err != nil {
		return fmt.Errorf("final batch insert failed for pkg: %w", err)
	}
	indexPackageCounter.WithLabelValues("insert_batch").Add(1)
	indexPackageDuration.WithLabelValues("insert_batch").Observe(time.Since(start).Seconds())

	zlog.Debug(ctx).
		Int("skipped", skipCt).
		Int("inserted", len(pkgs)-skipCt).
		Msg("packages inserted")

	skipCt = 0
	// make package scan artifacts
	mBatcher = microbatch.NewInsert(tx, 500, time.Minute)

	start = time.Now()
	for _, pkg := range pkgs {
		if pkg.Name == "" {
			skipCt++
			continue
		}
		err := mBatcher.Queue(
			ctx,
			insertPackageScanArtifactWithStmt.SQL,
			pkg.Source.Name,
			pkg.Source.Kind,
			pkg.Source.Version,
			pkg.Source.Module,
			pkg.Source.Arch,
			pkg.Name,
			pkg.Kind,
			pkg.Version,
			pkg.Module,
			pkg.Arch,
			scnr.Name(),
			scnr.Version(),
			scnr.Kind(),
			layer.Hash,
			pkg.PackageDB,
			pkg.RepositoryHint,
		)
		if err != nil {
			return fmt.Errorf("batch insert failed for package_scanartifact %v: %w", pkg, err)
		}
	}
	err = mBatcher.Done(ctx)
	if err != nil {
		return fmt.Errorf("final batch insert failed for package_scanartifact: %w", err)
	}
	indexPackageCounter.WithLabelValues("insertWith_batch").Add(1)
	indexPackageDuration.WithLabelValues("insertWith_batch").Observe(time.Since(start).Seconds())
	zlog.Debug(ctx).
		Int("skipped", skipCt).
		Int("inserted", len(pkgs)-skipCt).
		Msg("scanartifacts inserted")

	tctx, done = context.WithTimeout(ctx, 5*time.Second)
	err = tx.Commit(tctx)
	done()
	if err != nil {
		return fmt.Errorf("store:indexPackages failed to commit tx: %w", err)
	}
	return nil
}

func queueInsert(ctx context.Context, b *microbatch.Insert, stmt string, pkg *claircore.Package) error {
	var vKind *string
	var vNorm []int32
	if pkg.NormalizedVersion.Kind != "" {
		vKind = &pkg.NormalizedVersion.Kind
		vNorm = pkg.NormalizedVersion.V[:]
	}
	err := b.Queue(ctx, stmt,
		pkg.Name, pkg.Kind, pkg.Version, vKind, vNorm, pkg.Module, pkg.Arch,
	)
	if err != nil {
		return fmt.Errorf("failed to queue insert for package %q: %w", pkg.Name, err)
	}
	return nil
}

func (s *IndexerStore) IndexReport(ctx context.Context, hash claircore.Digest) (*claircore.IndexReport, bool, error) {
	const query = `
	SELECT scan_result
	FROM indexreport
			 JOIN manifest ON manifest.hash = $1
	WHERE indexreport.manifest_id = manifest.id;
	`
	// we scan into a jsonbIndexReport which has value/scan method set
	// then type convert back to scanner.domain object
	var jsr jsonbIndexReport

	ctx, done := context.WithTimeout(ctx, 5*time.Second)
	defer done()
	start := time.Now()
	err := s.pool.QueryRow(ctx, query, hash).Scan(&jsr)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("failed to retrieve index report: %w", err)
	}
	indexReportCounter.WithLabelValues("query").Add(1)
	indexReportDuration.WithLabelValues("query").Observe(time.Since(start).Seconds())

	sr := claircore.IndexReport(jsr)
	return &sr, true, nil
}

func (s *IndexerStore) IndexRepositories(ctx context.Context, repos []*claircore.Repository, l *claircore.Layer, scnr indexer.VersionedScanner) error {
	const (
		insert = `
		INSERT INTO repo
			(name, key, uri, cpe)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (name, key, uri) DO NOTHING;
		`

		insertWith = `
		WITH repositories AS (
			SELECT id AS repo_id
			FROM repo
			WHERE name = $1
			  AND key = $2
			  AND uri = $3
		),
			 scanner AS (
				 SELECT id AS scanner_id
				 FROM scanner
				 WHERE name = $4
				   AND version = $5
				   AND kind = $6
			 ),
			 layer AS (
				 SELECT id AS layer_id
				 FROM layer
				 WHERE layer.hash = $7
			 )
		INSERT
		INTO repo_scanartifact (layer_id, repo_id, scanner_id)
		VALUES ((SELECT layer_id FROM layer),
				(SELECT repo_id FROM repositories),
				(SELECT scanner_id FROM scanner))
		ON CONFLICT DO NOTHING;
		`
	)
	// obtain a transaction scoped batch
	tctx, done := context.WithTimeout(ctx, 5*time.Second)
	tx, err := s.pool.Begin(tctx)
	done()
	if err != nil {
		return fmt.Errorf("store:indexRepositories failed to create transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	tctx, done = context.WithTimeout(ctx, 5*time.Second)
	insertRepoStmt, err := tx.Prepare(tctx, "insertRepoStmt", insert)
	done()
	if err != nil {
		return fmt.Errorf("failed to create insert repo statement: %w", err)
	}
	tctx, done = context.WithTimeout(ctx, 5*time.Second)
	insertRepoScanArtifactWithStmt, err := tx.Prepare(tctx, "insertRepoScanArtifactWith", insertWith)
	done()
	if err != nil {
		return fmt.Errorf("failed to create insert repo scanartifact statement: %w", err)
	}

	start := time.Now()
	mBatcher := microbatch.NewInsert(tx, 500, time.Minute)
	for _, repo := range repos {
		err := mBatcher.Queue(
			ctx,
			insertRepoStmt.SQL,
			repo.Name,
			repo.Key,
			repo.URI,
			repo.CPE,
		)
		if err != nil {
			return fmt.Errorf("batch insert failed for repo %v: %w", repo, err)
		}
	}
	err = mBatcher.Done(ctx)
	if err != nil {
		return fmt.Errorf("final batch insert failed for repo: %w", err)
	}
	indexRepositoriesCounter.WithLabelValues("insert_batch").Add(1)
	indexRepositoriesDuration.WithLabelValues("insert_batch").Observe(time.Since(start).Seconds())

	// make repo scan artifacts

	start = time.Now()
	mBatcher = microbatch.NewInsert(tx, 500, time.Minute)
	for _, repo := range repos {
		err := mBatcher.Queue(
			ctx,
			insertRepoScanArtifactWithStmt.SQL,
			repo.Name,
			repo.Key,
			repo.URI,
			scnr.Name(),
			scnr.Version(),
			scnr.Kind(),
			l.Hash,
		)
		if err != nil {
			return fmt.Errorf("batch insert failed for repo_scanartifact %v: %w", repo, err)
		}
	}
	err = mBatcher.Done(ctx)
	if err != nil {
		return fmt.Errorf("final batch insert failed for repo_scanartifact: %w", err)
	}
	indexRepositoriesCounter.WithLabelValues("insertWith_batch").Add(1)
	indexRepositoriesDuration.WithLabelValues("insertWith_batch").Observe(time.Since(start).Seconds())

	tctx, done = context.WithTimeout(ctx, 15*time.Second)
	err = tx.Commit(tctx)
	done()
	if err != nil {
		return fmt.Errorf("store:indexRepositories failed to commit tx: %w", err)
	}
	return nil
}

func (s *IndexerStore) LayerScanned(ctx context.Context, hash claircore.Digest, scnr indexer.VersionedScanner) (bool, error) {
	// TODO(hank) Could this be written as a single query that reports NULL if
	// the scanner isn't present?
	const (
		selectScanner = `
SELECT
	id
FROM
	scanner
WHERE
	name = $1 AND version = $2 AND kind = $3;
`
		selectScanned = `
SELECT
	EXISTS(
		SELECT
			1
		FROM
			layer
			JOIN scanned_layer ON
					scanned_layer.layer_id = layer.id
		WHERE
			layer.hash = $1
			AND scanned_layer.scanner_id = $2
	);
`
	)

	ctx, done := context.WithTimeout(ctx, 10*time.Second)
	defer done()
	start := time.Now()
	var scannerID int64
	err := s.pool.QueryRow(ctx, selectScanner, scnr.Name(), scnr.Version(), scnr.Kind()).
		Scan(&scannerID)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return false, fmt.Errorf("scanner %s not found", scnr.Name())
	default:
		return false, err
	}
	layerScannedCounter.WithLabelValues("selectScanner").Add(1)
	layerScannedDuration.WithLabelValues("selectScanner").Observe(time.Since(start).Seconds())

	var ok bool

	start = time.Now()
	err = s.pool.QueryRow(ctx, selectScanned, hash.String(), scannerID).
		Scan(&ok)
	if err != nil {
		return false, err
	}
	layerScannedCounter.WithLabelValues("selectScanned").Add(1)
	layerScannedDuration.WithLabelValues("selectScanned").Observe(time.Since(start).Seconds())

	return ok, nil
}

// ManifestScanned determines if a manifest has been scanned by ALL the provided
// scanners.
func (s *IndexerStore) ManifestScanned(ctx context.Context, hash claircore.Digest, vs indexer.VersionedScanners) (bool, error) {
	const (
		selectScanned = `
		SELECT scanner_id
		FROM scanned_manifest
				 JOIN manifest ON scanned_manifest.manifest_id = manifest.id
		WHERE manifest.hash = $1;
		`
	)

	// get the ids of the scanners we are testing for.
	expectedIDs, err := s.selectScanners(ctx, vs)
	if err != nil {
		return false, err
	}

	// get a map of the found ids which have scanned this package
	foundIDs := map[int64]struct{}{}

	ctx, done := context.WithTimeout(ctx, 10*time.Second)
	defer done()
	start := time.Now()
	rows, err := s.pool.Query(ctx, selectScanned, hash)
	if err != nil {
		return false, fmt.Errorf("failed to select scanner IDs for manifest: %w", err)
	}
	manifestScannedCounter.WithLabelValues("selectScanned").Add(1)
	manifestScannedDuration.WithLabelValues("selectScanned").Observe(time.Since(start).Seconds())
	defer rows.Close()
	var t int64
	for rows.Next() {
		if err := rows.Scan(&t); err != nil {
			return false, fmt.Errorf("failed to select scanner IDs for manifest: %w", err)
		}
		foundIDs[t] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("failed to select scanner IDs for manifest: %w", err)
	}

	// compare the expectedIDs array with our foundIDs. if we get a lookup
	// miss we can say the manifest has not been scanned by all the layers provided
	for _, id := range expectedIDs {
		if _, ok := foundIDs[id]; !ok {
			return false, nil
		}
	}

	return true, nil
}

func (s *IndexerStore) PackagesByLayer(ctx context.Context, hash claircore.Digest, scnrs indexer.VersionedScanners) ([]*claircore.Package, error) {
	const (
		selectScanner = `
SELECT
	id
FROM
	scanner
WHERE
	name = $1 AND version = $2 AND kind = $3;
`
		query = `
SELECT
	package.id,
	package.name,
	package.kind,
	package.version,
	package.norm_kind,
	package.norm_version,
	package.module,
	package.arch,
	source_package.id,
	source_package.name,
	source_package.kind,
	source_package.version,
	source_package.module,
	source_package.arch,
	package_scanartifact.package_db,
	package_scanartifact.repository_hint
FROM
	package_scanartifact
	LEFT JOIN package ON
			package_scanartifact.package_id = package.id
	LEFT JOIN package AS source_package ON
			package_scanartifact.source_id
			= source_package.id
	JOIN layer ON layer.hash = $1
WHERE
	package_scanartifact.layer_id = layer.id
	AND package_scanartifact.scanner_id = ANY ($2);
`
	)

	if len(scnrs) == 0 {
		return []*claircore.Package{}, nil
	}
	// get scanner ids
	scannerIDs := make([]int64, len(scnrs))
	for i, scnr := range scnrs {
		ctx, done := context.WithTimeout(ctx, time.Second)
		start := time.Now()
		err := s.pool.QueryRow(ctx, selectScanner, scnr.Name(), scnr.Version(), scnr.Kind()).
			Scan(&scannerIDs[i])
		done()
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve scanner ids: %w", err)
		}
		packagesByLayerCounter.WithLabelValues("selectScanner").Add(1)
		packagesByLayerDuration.WithLabelValues("selectScanner").Observe(time.Since(start).Seconds())
	}

	ctx, done := context.WithTimeout(ctx, 15*time.Second)
	defer done()
	start := time.Now()
	rows, err := s.pool.Query(ctx, query, hash, scannerIDs)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return nil, fmt.Errorf("store:packagesByLayer no packages found for hash %v and scanners %v", hash, scnrs)
	default:
		return nil, fmt.Errorf("store:packagesByLayer failed to retrieve package rows for hash %v and scanners %v: %w", hash, scnrs, err)
	}
	packagesByLayerCounter.WithLabelValues("query").Add(1)
	packagesByLayerDuration.WithLabelValues("query").Observe(time.Since(start).Seconds())
	defer rows.Close()

	res := []*claircore.Package{}
	for rows.Next() {
		var pkg claircore.Package
		var spkg claircore.Package

		var id, srcID int64
		var nKind *string
		var nVer pgtype.Int4Array
		err := rows.Scan(
			&id,
			&pkg.Name,
			&pkg.Kind,
			&pkg.Version,
			&nKind,
			&nVer,
			&pkg.Module,
			&pkg.Arch,

			&srcID,
			&spkg.Name,
			&spkg.Kind,
			&spkg.Version,
			&spkg.Module,
			&spkg.Arch,

			&pkg.PackageDB,
			&pkg.RepositoryHint,
		)
		pkg.ID = strconv.FormatInt(id, 10)
		spkg.ID = strconv.FormatInt(srcID, 10)
		if err != nil {
			return nil, fmt.Errorf("failed to scan packages: %w", err)
		}
		if nKind != nil {
			pkg.NormalizedVersion.Kind = *nKind
			for i, n := range nVer.Elements {
				pkg.NormalizedVersion.V[i] = n.Int
			}
		}
		// nest source package
		pkg.Source = &spkg

		res = append(res, &pkg)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return res, nil
}

func (s *IndexerStore) PersistManifest(ctx context.Context, manifest claircore.Manifest) error {
	const (
		insertManifest = `
		INSERT INTO manifest (hash)
		VALUES ($1)
		ON CONFLICT DO NOTHING;
		`
		insertLayer = `
		INSERT INTO layer (hash)
		VALUES ($1)
		ON CONFLICT DO NOTHING;
		`
		insertManifestLayer = `
		WITH manifests AS (
			SELECT id AS manifest_id
			FROM manifest
			WHERE hash = $1
		),
			 layers AS (
				 SELECT id AS layer_id
				 FROM layer
				 WHERE hash = $2
			 )
		INSERT
		INTO manifest_layer (manifest_id, layer_id, i)
		VALUES ((SELECT manifest_id FROM manifests),
				(SELECT layer_id FROM layers),
				$3)
		ON CONFLICT DO NOTHING;
		`
	)

	tctx, done := context.WithTimeout(ctx, 5*time.Second)
	tx, err := s.pool.Begin(tctx)
	done()
	if err != nil {
		return fmt.Errorf("failed to create transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	tctx, done = context.WithTimeout(ctx, 5*time.Second)
	start := time.Now()
	_, err = tx.Exec(tctx, insertManifest, manifest.Hash)
	done()
	if err != nil {
		return fmt.Errorf("failed to insert manifest: %w", err)
	}
	persistManifestCounter.WithLabelValues("insertManifest").Add(1)
	persistManifestDuration.WithLabelValues("insertManifest").Observe(time.Since(start).Seconds())

	for i, layer := range manifest.Layers {
		tctx, done = context.WithTimeout(ctx, 5*time.Second)
		start := time.Now()
		_, err = tx.Exec(tctx, insertLayer, layer.Hash)
		done()
		if err != nil {
			return fmt.Errorf("failed to insert layer: %w", err)
		}
		persistManifestCounter.WithLabelValues("insertLayer").Add(1)
		persistManifestDuration.WithLabelValues("insertLayer").Observe(time.Since(start).Seconds())

		tctx, done = context.WithTimeout(ctx, 5*time.Second)
		start = time.Now()
		_, err = tx.Exec(tctx, insertManifestLayer, manifest.Hash, layer.Hash, i)
		done()
		if err != nil {
			return fmt.Errorf("failed to insert manifest -> layer link: %w", err)
		}
		persistManifestCounter.WithLabelValues("insertManifestLayer").Add(1)
		persistManifestDuration.WithLabelValues("insertManifestLayer").Observe(time.Since(start).Seconds())
	}

	tctx, done = context.WithTimeout(ctx, 15*time.Second)
	err = tx.Commit(tctx)
	done()
	if err != nil {
		return fmt.Errorf("failed to commit tx: %w", err)
	}
	return nil
}

func (s *IndexerStore) RegisterScanners(ctx context.Context, vs indexer.VersionedScanners) error {
	const (
		insert = `
INSERT
INTO
	scanner (name, version, kind)
VALUES
	($1, $2, $3)
ON CONFLICT
	(name, version, kind)
DO
	NOTHING;
`
		exists = `
SELECT
	EXISTS(
		SELECT
			1
		FROM
			scanner
		WHERE
			name = $1 AND version = $2 AND kind = $3
	);
`
	)

	var ok bool
	var err error
	var tctx context.Context
	var done context.CancelFunc
	for _, v := range vs {
		tctx, done = context.WithTimeout(ctx, time.Second)
		start := time.Now()
		err = s.pool.QueryRow(tctx, exists, v.Name(), v.Version(), v.Kind()).
			Scan(&ok)
		done()
		if err != nil {
			return fmt.Errorf("failed getting id for scanner %q: %w", v.Name(), err)
		}
		registerScannerCounter.WithLabelValues("exists").Add(1)
		registerScannerDuration.WithLabelValues("exists").Observe(time.Since(start).Seconds())
		if ok {
			continue
		}

		tctx, done = context.WithTimeout(ctx, time.Second)
		start = time.Now()
		_, err = s.pool.Exec(tctx, insert, v.Name(), v.Version(), v.Kind())
		done()
		if err != nil {
			return fmt.Errorf("failed to insert scanner %q: %w", v.Name(), err)
		}
		registerScannerCounter.WithLabelValues("insert").Add(1)
		registerScannerDuration.WithLabelValues("insert").Observe(time.Since(start).Seconds())
	}

	return nil
}

func (s *IndexerStore) RepositoriesByLayer(ctx context.Context, hash claircore.Digest, scnrs indexer.VersionedScanners) ([]*claircore.Repository, error) {
	const query = `
SELECT
	repo.id, repo.name, repo.key, repo.uri, repo.cpe
FROM
	repo_scanartifact
	LEFT JOIN repo ON repo_scanartifact.repo_id = repo.id
	JOIN layer ON layer.hash = $1
WHERE
	repo_scanartifact.layer_id = layer.id
	AND repo_scanartifact.scanner_id = ANY ($2);
`

	if len(scnrs) == 0 {
		return []*claircore.Repository{}, nil
	}
	scannerIDs, err := s.selectScanners(ctx, scnrs)
	if err != nil {
		return nil, fmt.Errorf("unable to select scanners: %w", err)
	}

	ctx, done := context.WithTimeout(ctx, 15*time.Second)
	defer done()
	start := time.Now()
	rows, err := s.pool.Query(ctx, query, hash, scannerIDs)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return nil, fmt.Errorf("no repositories found for layer, scanners set")
	default:
		return nil, fmt.Errorf("failed to retrieve repositories for layer, scanners set: %w", err)
	}
	repositoriesByLayerCounter.WithLabelValues("query").Add(1)
	repositoriesByLayerDuration.WithLabelValues("query").Observe(time.Since(start).Seconds())
	defer rows.Close()

	res := []*claircore.Repository{}
	for rows.Next() {
		var repo claircore.Repository

		var id int64
		err := rows.Scan(
			&id,
			&repo.Name,
			&repo.Key,
			&repo.URI,
			&repo.CPE,
		)
		repo.ID = strconv.FormatInt(id, 10)
		if err != nil {
			return nil, fmt.Errorf("failed to scan repositories: %w", err)
		}

		res = append(res, &repo)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return res, nil
}

func (s *IndexerStore) SetIndexFinished(ctx context.Context, ir *claircore.IndexReport, scnrs indexer.VersionedScanners) error {
	const (
		insertManifestScanned = `
WITH
	manifests
		AS (
			SELECT
				id AS manifest_id
			FROM
				manifest
			WHERE
				hash = $1
		)
INSERT
INTO
	scanned_manifest (manifest_id, scanner_id)
VALUES
	((SELECT manifest_id FROM manifests), $2);
`
		upsertIndexReport = `
WITH
	manifests
		AS (
			SELECT
				id AS manifest_id
			FROM
				manifest
			WHERE
				hash = $1
		)
INSERT
INTO
	indexreport (manifest_id, scan_result)
VALUES
	((SELECT manifest_id FROM manifests), $2)
ON CONFLICT
	(manifest_id)
DO
	UPDATE SET scan_result = excluded.scan_result;
`
	)

	scannerIDs, err := s.selectScanners(ctx, scnrs)
	if err != nil {
		return fmt.Errorf("failed to select package scanner id: %w", err)
	}

	tctx, done := context.WithTimeout(ctx, 5*time.Second)
	tx, err := s.pool.Begin(tctx)
	done()
	if err != nil {
		return fmt.Errorf("failed to create transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// link extracted scanner IDs with incoming manifest
	for _, id := range scannerIDs {
		tctx, done := context.WithTimeout(ctx, 5*time.Second)
		start := time.Now()
		_, err := tx.Exec(tctx, insertManifestScanned, ir.Hash, id)
		done()
		if err != nil {
			return fmt.Errorf("failed to link manifest with scanner list: %w", err)
		}
		setIndexedFinishedCounter.WithLabelValues("insertManifestScanned").Add(1)
		setIndexedFinishedDuration.WithLabelValues("insertManifestScanned").Observe(time.Since(start).Seconds())
	}

	// push IndexReport to the store
	// we cast claircore.IndexReport to jsonbIndexReport in order to obtain the value/scan
	// implementations

	tctx, done = context.WithTimeout(ctx, 5*time.Second)
	start := time.Now()
	_, err = tx.Exec(tctx, upsertIndexReport, ir.Hash, jsonbIndexReport(*ir))
	done()
	if err != nil {
		return fmt.Errorf("failed to upsert scan result: %w", err)
	}
	setIndexedFinishedCounter.WithLabelValues("upsertIndexReport").Add(1)
	setIndexedFinishedDuration.WithLabelValues("upsertIndexReport").Observe(time.Since(start).Seconds())

	tctx, done = context.WithTimeout(ctx, 15*time.Second)
	err = tx.Commit(tctx)
	done()
	if err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

func (s *IndexerStore) SetIndexReport(ctx context.Context, ir *claircore.IndexReport) error {
	const query = `
WITH
	manifests
		AS (
			SELECT
				id AS manifest_id
			FROM
				manifest
			WHERE
				hash = $1
		)
INSERT
INTO
	indexreport (manifest_id, scan_result)
VALUES
	((SELECT manifest_id FROM manifests), $2)
ON CONFLICT
	(manifest_id)
DO
	UPDATE SET scan_result = excluded.scan_result;
`
	// we cast scanner.IndexReport to jsonbIndexReport in order to obtain the value/scan
	// implementations

	ctx, done := context.WithTimeout(ctx, 30*time.Second)
	defer done()
	start := time.Now()
	_, err := s.pool.Exec(ctx, query, ir.Hash, jsonbIndexReport(*ir))
	if err != nil {
		return fmt.Errorf("failed to upsert index report: %w", err)
	}
	setIndexReportCounter.WithLabelValues("query").Add(1)
	setIndexReportDuration.WithLabelValues("query").Observe(time.Since(start).Seconds())

	return nil
}

func (s *IndexerStore) SetLayerScanned(ctx context.Context, hash claircore.Digest, vs indexer.VersionedScanner) error {
	ctx = zlog.ContextWithValues(ctx, "scanner", vs.Name())
	const query = `
WITH
	scanner
		AS (
			SELECT
				id
			FROM
				scanner
			WHERE
				name = $2 AND version = $3 AND kind = $4
		),
	layer AS (SELECT id FROM layer WHERE hash = $1)
INSERT
INTO
	scanned_layer (layer_id, scanner_id)
VALUES
	(
		(SELECT id AS layer_id FROM layer),
		(SELECT id AS scanner_id FROM scanner)
	)
ON CONFLICT
	(layer_id, scanner_id)
DO
	NOTHING;
`

	ctx, done := context.WithTimeout(ctx, 15*time.Second)
	defer done()
	start := time.Now()
	_, err := s.pool.Exec(ctx, query, hash, vs.Name(), vs.Version(), vs.Kind())
	if err != nil {
		return fmt.Errorf("error setting layer scanned: %w", err)
	}
	setLayerScannedCounter.WithLabelValues("query").Add(1)
	setLayerScannedDuration.WithLabelValues("query").Observe(time.Since(start).Seconds())

	return nil
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
