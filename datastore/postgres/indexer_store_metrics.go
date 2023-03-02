package postgres

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/quay/claircore"
)

var (
	// ErrNotIndexed indicates the vulnerability being queried has a dist or repo not
	// indexed into the database.
	ErrNotIndexed            = fmt.Errorf("vulnerability containers data not indexed by any scannners")
	affectedManifestsCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "affectedmanifests_total",
			Help:      "Total number of database queries issued in the AffectedManifests method.",
		},
		[]string{"query"},
	)
	affectedManifestsDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "affectedmanifests_duration_seconds",
			Help:      "The duration of all queries issued in the AffectedManifests method",
		},
		[]string{"query"},
	)
	protoRecordCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "protorecord_total",
			Help:      "Total number of database queries issued in the protoRecord  method.",
		},
		[]string{"query"},
	)
	protoRecordDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "protorecord_duration_seconds",
			Help:      "The duration of all queries issued in the protoRecord method",
		},
		[]string{"query"},
	)

	setIndexedFinishedCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "setindexedfinished_total",
			Help:      "Total number of database queries issued in the SetIndexFinished method.",
		},
		[]string{"query"},
	)

	setIndexedFinishedDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "setindexfinished_duration_seconds",
			Help:      "The duration of all queries issued in the SetIndexFinished method",
		},
		[]string{"query"},
	)
	deleteManifestsCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "deletemanifests_total",
			Help:      "Total number of database queries issued in the DeleteManifests method.",
		},
		[]string{"query", "success"},
	)
	deleteManifestsDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "deletemanifests_duration_seconds",
			Help:      "The duration of all queries issued in the DeleteManifests method.",
		},
		[]string{"query", "success"},
	)
	distributionByLayerCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "distributionbylayer_total",
			Help:      "The count of all queries issued in the DistributionsByLayer method",
		},
		[]string{"query"},
	)

	distributionByLayerDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "distributionbylayer_duration_seconds",
			Help:      "The duration of all queries issued in the DistributionByLayer method",
		},
		[]string{"query"},
	)
	indexDistributionsCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "indexdistributions_total",
			Help:      "Total number of database queries issued in the IndexDistributions method.",
		},
		[]string{"query"},
	)

	indexDistributionsDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "indexdistributions_duration_seconds",
			Help:      "The duration of all queries issued in the IndexDistributions method",
		},
		[]string{"query"},
	)
	indexManifestCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "indexmanifest_total",
			Help:      "Total number of database queries issued in the IndexManifest method.",
		},
		[]string{"query"},
	)

	indexManifestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "indexmanifest_duration_seconds",
			Help:      "The duration of all queries issued in the IndexManifest method",
		},
		[]string{"query"},
	)
	indexPackageCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "indexpackage_total",
			Help:      "Total number of database queries issued in the IndexPackage method.",
		},
		[]string{"query"},
	)

	indexPackageDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "indexpackage_duration_seconds",
			Help:      "The duration of all queries issued in the IndexPackage method",
		},
		[]string{"query"},
	)
	indexReportCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "indexreport_total",
			Help:      "Total number of database queries issued in the IndexReport method.",
		},
		[]string{"query"},
	)

	indexReportDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "indexreport_duration_seconds",
			Help:      "The duration of all queries issued in the IndexReport method",
		},
		[]string{"query"},
	)
	indexRepositoriesCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "indexrepositories_total",
			Help:      "Total number of database queries issued in the IndexRepositories method.",
		},
		[]string{"query"},
	)

	indexRepositoriesDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "indexrepositories_duration_seconds",
			Help:      "The duration of all queries issued in the IndexRepositories method",
		},
		[]string{"query"},
	)
	layerScannedCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "layerscanned_total",
			Help:      "Total number of database queries issued in the LayerScanned method.",
		},
		[]string{"query"},
	)

	layerScannedDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "layerscanned_duration_seconds",
			Help:      "The duration of all queries issued in the LayerScanned method",
		},
		[]string{"query"},
	)
	manifestScannedCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "manifestscanned_total",
			Help:      "Total number of database queries issued in the ManifestScanned method.",
		},
		[]string{"query"},
	)

	manifestScannedDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "manifestscanned_duration_seconds",
			Help:      "The duration of all queries issued in the ManifestScanned method",
		},
		[]string{"query"},
	)
	packagesByLayerCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "packagesbylayer_total",
			Help:      "Total number of database queries issued in the PackagesByLayer method.",
		},
		[]string{"query"},
	)

	packagesByLayerDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "packagesbylayer_duration_seconds",
			Help:      "The duration of all queries issued in the PackagesByLayer method",
		},
		[]string{"query"},
	)
	persistManifestCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "persistmanifest_total",
			Help:      "Total number of database queries issued in the PersistManifest method.",
		},
		[]string{"query"},
	)

	persistManifestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "persistmanifest_duration_seconds",
			Help:      "The duration of all queries issued in the PersistManifest method",
		},
		[]string{"query"},
	)
	registerScannerCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "registerscanners_total",
			Help:      "Total number of database queries issued in the RegiterScanners method.",
		},
		[]string{"query"},
	)

	registerScannerDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "registerscanners_duration_seconds",
			Help:      "The duration of all queries issued in the RegiterScanners method",
		},
		[]string{"query"},
	)
	repositoriesByLayerCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "repositoriesbylayer_total",
			Help:      "Total number of database queries issued in the RepositoriesByLayer method.",
		},
		[]string{"query"},
	)

	repositoriesByLayerDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "repositoriesbylayer_duration_seconds",
			Help:      "The duration of all queries issued in the RepositoriesByLayer method",
		},
		[]string{"query"},
	)
	setIndexReportCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "setindexreport_total",
			Help:      "Total number of database queries issued in the SetIndexReport method.",
		},
		[]string{"query"},
	)

	setIndexReportDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "setindexreport_duration_seconds",
			Help:      "The duration of all queries issued in the SetIndexReport method",
		},
		[]string{"query"},
	)
	setLayerScannedCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "setlayerscanned_total",
			Help:      "Total number of database queries issued in the SetLayerScanned method.",
		},
		[]string{"query"},
	)

	setLayerScannedDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "setlayerscanned_duration_seconds",
			Help:      "The duration of all queries issued in the SetLayerScanned method",
		},
		[]string{"query"},
	)
)
var zeroPackage = claircore.Package{}
