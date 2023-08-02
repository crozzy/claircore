// Package rhel implements the machinery for processing layers and security data
// from the Red Hat ecosystem.
//
// See the various exported types for details on the heuristics employed.
//
// In addition, containers themselves are recognized via the
// [github.com/quay/claircore/rhel/rhcc] package.
package rhel // import "github.com/quay/claircore/rhel"

import (
	"context"
	"net/http"
	"net/url"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/ovalutil"
)

var (
	_ driver.Updater      = (*Updater)(nil)
	_ driver.Configurable = (*Updater)(nil)
)

// Updater fetches and parses RHEL-flavored OVAL databases.
type Updater struct {
	ovalutil.Fetcher // fetch method promoted via embed
	dist             *claircore.Distribution
	name             string
	ignoreUnpatched  bool
}

// UpdaterConfig is the configuration expected for any given updater.
//
// See also [ovalutil.FetcherConfig].
type UpdaterConfig struct {
	ovalutil.FetcherConfig
	Release         int64 `json:"release" yaml:"release"`
	IgnoreUnpatched bool  `json:"ignore_unpatched" yaml:"ignore_unpatched"`
}

// NewUpdater returns an Updater.
func NewUpdater(name string, release int, uri string) (*Updater, error) {
	u := &Updater{
		name: name,
		dist: mkRelease(int64(release)),
	}
	var err error
	u.Fetcher.URL, err = url.Parse(uri)
	if err != nil {
		return nil, err
	}
	return u, nil
}

// Configure implements [driver.Configurable].
func (u *Updater) Configure(ctx context.Context, cf driver.ConfigUnmarshaler, c *http.Client) error {
	ctx = zlog.ContextWithValues(ctx, "component", "rhel/Updater.Configure")
	var cfg UpdaterConfig
	if err := cf(&cfg); err != nil {
		return err
	}
	if cfg.Release != 0 {
		u.dist = mkRelease(cfg.Release)
	}
	u.ignoreUnpatched = cfg.IgnoreUnpatched
	return u.Fetcher.Configure(ctx, cf, c)
}

// Name implements [driver.Updater].
func (u *Updater) Name() string { return u.name }
