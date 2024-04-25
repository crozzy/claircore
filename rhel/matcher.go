package rhel

import (
	"context"
	"strings"

	version "github.com/knqyf263/go-rpm-version"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/toolkit/types/cpe"
)

// Matcher implements driver.Matcher.
type Matcher struct{}

var _ driver.Matcher = (*Matcher)(nil)

// Name implements driver.Matcher.
func (*Matcher) Name() string {
	return "rhel"
}

// Filter implements driver.Matcher.
func (*Matcher) Filter(record *claircore.IndexRecord) bool {
	return record.Repository != nil && record.Repository.Key == repositoryKey
}

// Query implements driver.Matcher.
func (*Matcher) Query() []driver.MatchConstraint {
	return []driver.MatchConstraint{
		driver.PackageModule,
	}
}

// isCPESubstringMatch is a hack that accounts for CPEs in the VEX
// data that are expected to be treated as subset matching CPEs but
// don't use the correct syntax defined in the spec.
// E.g. cpe:/a:redhat:openshift:4.13::el8 is expected to match to
// cpe:/a:redhat:openshift:4.
// TODO: Remove once RH VEX data updates CPEs with the correct matching
// syntax.
func isCPESubstringMatch(recordCPE cpe.WFN, vulnCPE cpe.WFN) bool {
	return strings.HasPrefix(strings.TrimRight(recordCPE.String(), ":*"), strings.TrimRight(vulnCPE.String(), ":*"))
}

// Vulnerable implements driver.Matcher.
//
// Vulnerable will interpret the claircore.Vulnerability.Repo.CPE
// as a CPE match expression, and to be considered vulnerable,
// the relationship between claircore.IndexRecord.Repository.CPE and
// the claircore.Vulnerability.Repo.CPE needs to be a CPE Name Comparison
// Relation of SUBSET(⊂)(source is a subset of, or equal to the target).
// https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7696.pdf Section 6.2.
func (m *Matcher) Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
	if vuln.Repo == nil || record.Repository == nil || vuln.Repo.Key != repositoryKey {
		return false, nil
	}
	var err error
	// This conversion has to be done because our current data structure doesn't
	// support the claircore.Vulnerability.Repo.CPE field.
	vuln.Repo.CPE, err = cpe.Unbind(vuln.Repo.Name)
	if err != nil {
		zlog.Warn(ctx).
			Str("vulnerability name", vuln.Name).
			Err(err).
			Msg("unable to unbind repo CPE")
		return false, nil
	}
	if !cpe.Compare(record.Repository.CPE, vuln.Repo.CPE).IsSubset() && !isCPESubstringMatch(record.Repository.CPE, vuln.Repo.CPE) {
		return false, nil
	}

	pkgVer := version.NewVersion(record.Package.Version)
	var vulnVer version.Version
	// Assume the vulnerability record we have is for the last known vulnerable
	// version, so greater versions aren't vulnerable.
	cmp := func(i int) bool { return i != version.GREATER }
	// But if it's explicitly marked as a fixed-in version, it's only vulnerable
	// if less than that version.
	if vuln.FixedInVersion != "" {
		vulnVer = version.NewVersion(vuln.FixedInVersion)
		cmp = func(i int) bool { return i == version.LESS }
	} else {
		// If a vulnerability doesn't have FixedInVersion, assume it is unfixed.
		vulnVer = version.NewVersion("65535:0")
	}
	// compare version and architecture
	return cmp(pkgVer.Compare(vulnVer)) && vuln.ArchOperation.Cmp(record.Package.Arch, vuln.Package.Arch), nil
}
