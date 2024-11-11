package spdx

import (
	"bytes"
	"context"
	"fmt"
	spdxjson "github.com/spdx/tools-golang/json"
	"io"
	"time"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/sbom"

	"github.com/spdx/tools-golang/convert"
	"github.com/spdx/tools-golang/spdx/common"
	v2common "github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_1"
	"github.com/spdx/tools-golang/spdx/v2/v2_2"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

type Version string

const (
	V2_1 Version = "v2.1"
	V2_2 Version = "v2.2"
	V2_3 Version = "v2.3"
)

type Creator struct {
	Creator string
	// In accordance to the SPDX v2 spec, CreatorType should be one of "Person", "Organization", or "Tool"
	CreatorType string
}

var _ sbom.Encoder = (*Encoder)(nil)

type Encoder struct {
	Version           Version
	Format            Format
	Creators          []Creator
	DocumentNamespace string
	DocumentComment   string
}

// Encode encodes a claircore IndexReport to an io.Reader.
// We first convert the IndexReport to an SPDX doc of the latest version, then
// convert that doc to the specified version. We assume there's no data munging
// going from latest to the specified version.
func (e *Encoder) Encode(ctx context.Context, ir *claircore.IndexReport) (io.Reader, error) {
	spdx, err := e.parseIndexReport(ctx, ir)
	if err != nil {
		return nil, err
	}

	var tmpConverterDoc common.AnyDocument
	switch e.Version {
	case V2_1:
		var targetDoc v2_1.Document
		if err := convert.Document(spdx, targetDoc); err != nil {
			return nil, err
		}
		tmpConverterDoc = targetDoc
	case V2_2:
		var targetDoc v2_2.Document
		if err := convert.Document(spdx, targetDoc); err != nil {
			return nil, err
		}
		tmpConverterDoc = targetDoc
	case V2_3:
		// parseIndexReport currently returns a v2_3.Document so do nothing
		tmpConverterDoc = spdx
	default:
		return nil, fmt.Errorf("unknown SPDX version: %v", e.Version)
	}

	switch e.Format {
	case JSON:
		// TODO(DO NOT MERGE): Should this be outside the switch? i.e., should
		//  we use this for all formatting cases? We could return it outside the
		//  switch as the "default" case
		buf := &bytes.Buffer{}
		if err := spdxjson.Write(tmpConverterDoc, buf); err != nil {
			return nil, err
		}
		return buf, nil
	}

	return nil, fmt.Errorf("unknown requested format: %v", e.Format)
}

func (e *Encoder) parseIndexReport(ctx context.Context, ir *claircore.IndexReport) (*v2_3.Document, error) {
	creatorInfo := e.Creators
	spdxCreators := make([]v2common.Creator, len(creatorInfo))
	for i, creator := range creatorInfo {
		spdxCreators[i].Creator = creator.Creator
		spdxCreators[i].CreatorType = creator.CreatorType
	}

	// Initial metadata
	out := &v2_3.Document{
		SPDXVersion:    v2_3.Version,
		DataLicense:    v2_3.DataLicense,
		SPDXIdentifier: "DOCUMENT",
		// TODO(DO NOT MERGE): Is this ok?
		DocumentName:      ir.Hash.String(),
		DocumentNamespace: e.DocumentNamespace,
		CreationInfo: &v2_3.CreationInfo{
			Creators: spdxCreators,
			Created:  time.Now().Format("2006-01-02T15:04:05Z"),
		},
		DocumentComment: e.DocumentComment,
	}

	var rels []*v2_3.Relationship
	repoMap := map[string]*v2_3.Package{}
	distMap := map[string]*v2_3.Package{}
	pkgMap := map[string]*v2_3.Package{}
	for _, r := range ir.IndexRecords() {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		// This could happen if the PackageScanner that found this package is
		// associated with two different Ecosystems and one of those Ecosystems
		// doesn't have the RepositoryScanner. If something like that happens,
		// we'll have the Repository information in another IndexRecord.
		if r.Repository == nil || r.Repository.ID == "" {
			continue
		}

		pkg, ok := pkgMap[r.Package.ID]

		// Record the package if we haven't seen it yet.
		if !ok {
			pkgDB := ""
			for _, env := range ir.Environments[r.Package.ID] {
				if env.PackageDB != "" {
					pkgDB = env.PackageDB
				}
			}

			pkg = &v2_3.Package{
				PackageName:             r.Package.Name,
				PackageSPDXIdentifier:   v2common.ElementID("pkg:" + r.Package.ID),
				PackageVersion:          r.Package.Version,
				PackageFileName:         pkgDB,
				PackageDownloadLocation: "NOASSERTION",
				FilesAnalyzed:           true,
			}
			pkgMap[r.Package.ID] = pkg
			out.Packages = append(out.Packages, pkg)

			if r.Package.Source != nil && r.Package.Source.Name != "" {
				srcPkg := &v2_3.Package{
					PackageName:             r.Package.Source.Name,
					PackageSPDXIdentifier:   v2common.ElementID("src-pkg:" + r.Package.Source.ID),
					PackageVersion:          r.Package.Source.Version,
					PackageDownloadLocation: "NOASSERTION",
				}
				out.Packages = append(out.Packages, srcPkg)
				rels = append(rels, &v2_3.Relationship{
					RefA:         v2common.MakeDocElementID("", string(pkg.PackageSPDXIdentifier)),
					RefB:         v2common.MakeDocElementID("", string(srcPkg.PackageSPDXIdentifier)),
					Relationship: "GENERATED_FROM",
				})
			}
		}

		// Record Repositories for this package.
		if r.Repository != nil {
			repo, ok := repoMap[r.Repository.ID]
			if !ok {
				extRefs := []*v2_3.PackageExternalReference{
					{
						Category: "SECURITY",
						RefType:  "cpe23Type",
						Locator:  r.Repository.CPE.String(),
					},
				}

				if r.Repository.URI != "" {
					extRefs = append(extRefs, &v2_3.PackageExternalReference{
						Category: "OTHER",
						RefType:  "url",
						Locator:  r.Repository.URI,
					})
				}

				if r.Repository.Key != "" {
					extRefs = append(extRefs, &v2_3.PackageExternalReference{
						Category: "OTHER",
						RefType:  "key",
						Locator:  r.Repository.Key,
					})
				}

				repo = &v2_3.Package{
					PackageName:               r.Repository.Name,
					PackageSPDXIdentifier:     v2common.ElementID("repo:" + r.Repository.ID),
					PackageDownloadLocation:   "NOASSERTION",
					FilesAnalyzed:             true,
					PackageSummary:            "repository",
					PackageExternalReferences: extRefs,
					PrimaryPackagePurpose:     "OTHER",
				}
				repoMap[r.Repository.ID] = repo
				out.Packages = append(out.Packages, repo)
			}
			rel := &v2_3.Relationship{
				RefA:         v2common.MakeDocElementID("", string(pkg.PackageSPDXIdentifier)),
				RefB:         v2common.MakeDocElementID("", string(repo.PackageSPDXIdentifier)),
				Relationship: "CONTAINED_BY",
			}
			rels = append(rels, rel)
		}

		// Record Distributions for this package.
		if r.Distribution != nil {
			dist, ok := distMap[r.Distribution.ID]
			if !ok {
				dist = &v2_3.Package{
					PackageName:             r.Distribution.Name,
					PackageSPDXIdentifier:   v2common.ElementID("dist:" + r.Distribution.ID),
					PackageVersion:          r.Distribution.Version,
					PackageDownloadLocation: "NOASSERTION",
					FilesAnalyzed:           true,
					PackageSummary:          "distribution",
					PackageExternalReferences: []*v2_3.PackageExternalReference{
						{
							Category: "SECURITY",
							RefType:  "cpe23Type",
							Locator:  r.Distribution.CPE.String(),
						},
						{
							Category: "OTHER",
							RefType:  "did",
							Locator:  r.Distribution.DID,
						},
						{
							Category: "OTHER",
							RefType:  "version_id",
							Locator:  r.Distribution.VersionID,
						},
						{
							Category: "OTHER",
							RefType:  "pretty_name",
							Locator:  r.Distribution.PrettyName,
						},
					},
					PrimaryPackagePurpose: "OPERATING-SYSTEM",
				}
				distMap[r.Distribution.ID] = dist
				out.Packages = append(out.Packages, dist)
			}
			rel := &v2_3.Relationship{
				RefA:         v2common.MakeDocElementID("", string(pkg.PackageSPDXIdentifier)),
				RefB:         v2common.MakeDocElementID("", string(dist.PackageSPDXIdentifier)),
				Relationship: "CONTAINED_BY",
			}
			rels = append(rels, rel)
		}
	}

	// TODO(DO NOT MERGE): In case we want to add layers to the first iteration
	//layerMap := map[string]*v2_3.Package{}
	//for pkgID, envs := range ir.Environments {
	//	for _, e := range envs {
	//		pkg, ok := layerMap[e.IntroducedIn.String()]
	//		if !ok {
	//			pkg = &v2_3.Package{
	//				PackageName:             e.IntroducedIn.String(),
	//				PackageSPDXIdentifier:   v2common.ElementID(uuid.New().String()),
	//				PackageDownloadLocation: "NOASSERTION",
	//				FilesAnalyzed:           true,
	//				PackageSummary:          "layer",
	//			}
	//			out.Packages = append(out.Packages, pkg)
	//			layerMap[e.IntroducedIn.String()] = pkg
	//		}
	//		rel := &v2_3.Relationship{
	//			RefA:         v2common.MakeDocElementID("", pkgID),
	//			RefB:         v2common.MakeDocElementID("", string(pkg.PackageSPDXIdentifier)),
	//			Relationship: "CONTAINED_BY",
	//		}
	//		rels = append(rels, rel)
	//	}
	//}

	out.Relationships = rels

	return out, nil
}
