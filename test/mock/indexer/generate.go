package mock_indexer

//go:generate -command mockgen mockgen -destination=./mocks.go github.com/quay/claircore/indexer
//go:generate mockgen Store,LayerScanner,PackageScanner,VersionedScanner,DistributionScanner,RepositoryScanner,Coalescer,Realizer
