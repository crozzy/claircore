// Package python contains components for interrogating python packages in
// container layers.
package python

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"net/textproto"
	"path"
	"path/filepath"
	"runtime/trace"
	"strings"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/pkg/pep440"
	"github.com/quay/claircore/pkg/tarfs"
)

var (
	_ indexer.VersionedScanner = (*Scanner)(nil)
	_ indexer.PackageScanner   = (*Scanner)(nil)
)

// Scanner implements the scanner.PackageScanner interface.
//
// It looks for directories that seem like wheels or eggs, and looks at the
// metadata recorded there. This type attempts to follow the specs documented by
// the [PyPA], with the newer PEPs being preferred.
//
// The zero value is ready to use.
//
// [PyPA]: https://packaging.python.org/en/latest/specifications/recording-installed-packages/
type Scanner struct{}

// Name implements scanner.VersionedScanner.
func (*Scanner) Name() string { return "python" }

// Version implements scanner.VersionedScanner.
func (*Scanner) Version() string { return "3" }

// Kind implements scanner.VersionedScanner.
func (*Scanner) Kind() string { return "package" }

// Scan attempts to find wheel or egg info directories and record the package
// information there.
//
// A return of (nil, nil) is expected if there's nothing found.
func (ps *Scanner) Scan(ctx context.Context, layer *claircore.Layer) ([]*claircore.Package, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	trace.Log(ctx, "layer", layer.Hash.String())
	ctx = zlog.ContextWithValues(ctx,
		"component", "python/Scanner.Scan",
		"version", ps.Version(),
		"layer", layer.Hash.String())
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	r, err := layer.Reader()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	sys, err := tarfs.New(r)
	if err != nil {
		return nil, fmt.Errorf("python: unable to open tar: %w", err)
	}

	ms, err := findDeliciousEgg(ctx, sys)
	if err != nil {
		return nil, fmt.Errorf("python: failed to find delicious egg: %w", err)
	}
	var ret []*claircore.Package
	for _, n := range ms {
		b, err := fs.ReadFile(sys, n)
		if err != nil {
			return nil, fmt.Errorf("python: unable to read file: %w", err)
		}
		// The two files we read are in RFC8288 (email message) format, and the
		// keys we care about are shared.
		rd := textproto.NewReader(bufio.NewReader(bytes.NewReader(b)))
		hdr, err := rd.ReadMIMEHeader()
		if err != nil && hdr == nil {
			zlog.Warn(ctx).
				Err(err).
				Str("path", n).
				Msg("unable to read metadata, skipping")
			continue
		}
		v, err := pep440.Parse(hdr.Get("Version"))
		if err != nil {
			zlog.Warn(ctx).
				Err(err).
				Str("path", n).
				Msg("couldn't parse the version, skipping")
			continue
		}
		pkgDB := filepath.Join(n, "..", "..")
		// If the package is .egg-info format
		// with just the .egg-info file,
		// only go up one level.
		if strings.HasSuffix(n, `.egg-info`) {
			pkgDB = filepath.Join(n, "..")
		}
		ret = append(ret, &claircore.Package{
			Name:              strings.ToLower(hdr.Get("Name")),
			Version:           v.String(),
			PackageDB:         "python:" + pkgDB,
			Filepath:          n,
			Kind:              claircore.BINARY,
			NormalizedVersion: v.Version(),
			// TODO Is there some way to pick up on where a wheel or egg was
			// found?
			RepositoryHint: "https://pypi.org/simple",
		})
	}
	return ret, nil
}

// findDeliciousEgg finds eggs and wheels.
//
// Three formats are supported at this time:
//
// * .egg      - only when .egg is a directory. .egg as a zipfile is not supported at this time.
// * .egg-info - both as a standalone file and a directory which contains PKG-INFO.
// * wheel     - only .dist-info/METADATA is supported.
//
// See https://setuptools.pypa.io/en/latest/deprecated/python_eggs.html for more information about Python Eggs
// and https://peps.python.org/pep-0427/ for more information about Wheel.
func findDeliciousEgg(ctx context.Context, sys fs.FS) (out []string, err error) {
	// Is this layer an rpm layer?
	//
	// If so, files in the disto-managed directory can be skipped.
	var rpm bool
	for _, p := range []string{
		"var/lib/rpm/Packages",
		"var/lib/rpm/rpmdb.sqlite",
		"var/lib/rpm/Packages.db",
	} {
		if fi, err := fs.Stat(sys, p); err == nil && fi.Mode().IsRegular() {
			rpm = true
			break
		}
	}
	// Is this layer a dpkg layer?
	var dpkg bool
	if fi, err := fs.Stat(sys, `var/lib/dpkg/status`); err == nil && fi.Mode().IsRegular() {
		dpkg = true
	}

	return out, fs.WalkDir(sys, ".", func(p string, d fs.DirEntry, err error) error {
		ev := zlog.Debug(ctx).
			Str("file", p)
		switch {
		case err != nil:
			ev.Discard().Send()
			return err
		case (rpm || dpkg) && d.Type().IsDir():
			// Skip one level up from the "packages" directory so the walk also
			// skips the standard library.
			var pat string
			switch {
			case rpm:
				pat = `usr/lib*/python[23].*`
				ev = ev.Bool("rpm_dir", true)
			case dpkg:
				pat = `usr/lib*/python[23]`
				ev = ev.Bool("dpkg_dir", true)
			default:
				panic("programmer error: unreachable")
			}
			if m, _ := path.Match(pat, p); m {
				ev.Msg("skipping directory")
				return fs.SkipDir
			}
			fallthrough
		case !d.Type().IsRegular():
			ev.Discard().Send()
			// Should we chase symlinks with the correct name?
			return nil
		case strings.HasSuffix(p, `.egg/EGG-INFO/PKG-INFO`):
			ev = ev.Str("kind", ".egg")
		case strings.HasSuffix(p, `.egg-info`):
			fallthrough
		case strings.HasSuffix(p, `.egg-info/PKG-INFO`):
			ev = ev.Str("kind", ".egg-info")
		case strings.HasSuffix(p, `.dist-info/METADATA`):
			ev = ev.Str("kind", "wheel")
			// See if we can discern the installer.
			var installer string
			ip := path.Join(path.Dir(p), `INSTALLER`)
			if ic, err := fs.ReadFile(sys, ip); err == nil {
				installer = string(bytes.TrimSpace(ic))
				ev = ev.Str("installer", installer)
			}
			if _, ok := blocklist[installer]; ok {
				ev.Msg("skipping package")
				return nil
			}
		default:
			ev.Discard().Send()
			return nil
		}
		ev.Msg("found package")
		out = append(out, p)
		return nil
	})
}

// Blocklist of installers to ignore.
//
// Currently, rpm is the only known package manager that actually populates this
// information.
var blocklist = map[string]struct{}{
	"rpm":  {},
	"dpkg": {},
	"apk":  {},
}
