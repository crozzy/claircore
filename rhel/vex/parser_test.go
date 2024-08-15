package vex

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/klauspost/compress/snappy"

	"github.com/quay/zlog"

	"github.com/quay/claircore/pkg/rhctag"
	"github.com/quay/claircore/toolkit/types/csaf"
)

func TestWalkRelationships(t *testing.T) {
	testcases := []struct {
		name                              string
		in                                string
		c                                 *csaf.CSAF
		expectedPkgName, expectedRepoName string
		err                               bool
	}{
		{
			c: &csaf.CSAF{
				ProductTree: csaf.ProductBranch{},
			},
			in:               "EAP 7.4 log4j async",
			expectedPkgName:  "",
			expectedRepoName: "",
			name:             "no_relationship",
			err:              true,
		},
		{
			c: &csaf.CSAF{
				ProductTree: csaf.ProductBranch{
					Relationships: csaf.Relationships{
						csaf.Relationship{
							Category: "default_component_of",
							FullProductName: csaf.Product{
								Name: "fence-agents-common-0:4.10.0-62.el9_4.3.noarch as a component of Red Hat Enterprise Linux ResilientStorage (v. 9)",
								ID:   "ResilientStorage-9.4.0.Z.MAIN.EUS:fence-agents-common-0:4.10.0-62.el9_4.3.noarch",
							},
							ProductRef:          "fence-agents-common-0:4.10.0-62.el9_4.3.noarch",
							RelatesToProductRef: "ResilientStorage-9.4.0.Z.MAIN.EUS",
						},
					},
				},
			},
			in:               "ResilientStorage-9.4.0.Z.MAIN.EUS:fence-agents-common-0:4.10.0-62.el9_4.3.noarch",
			expectedPkgName:  "fence-agents-common-0:4.10.0-62.el9_4.3.noarch",
			expectedRepoName: "ResilientStorage-9.4.0.Z.MAIN.EUS",
			name:             "simple_relationship",
		},
		{
			c: &csaf.CSAF{
				ProductTree: csaf.ProductBranch{
					Relationships: csaf.Relationships{
						csaf.Relationship{
							Category: "default_component_of",
							FullProductName: csaf.Product{
								Name: "httpd:2.4:8100020240612075645:489197e6 as a component of Red Hat Enterprise Linux AppStream (v. 8)",
								ID:   "AppStream-8.10.0.Z.MAIN.EUS:httpd:2.4:8100020240612075645:489197e6",
							},
							ProductRef:          "httpd:2.4:8100020240612075645:489197e6",
							RelatesToProductRef: "AppStream-8.10.0.Z.MAIN.EUS",
						},
						csaf.Relationship{
							Category: "default_component_of",
							FullProductName: csaf.Product{
								Name: "httpd-0:2.4.37-65.module+el8.10.0+21982+14717793.aarch64 as a component of httpd:2.4:8100020240612075645:489197e6 as a component of Red Hat Enterprise Linux AppStream (v. 8)",
								ID:   "AppStream-8.10.0.Z.MAIN.EUS:httpd:2.4:8100020240612075645:489197e6:httpd-0:2.4.37-65.module+el8.10.0+21982+14717793.aarch64",
							},
							ProductRef:          "httpd-0:2.4.37-65.module+el8.10.0+21982+14717793.aarch64",
							RelatesToProductRef: "AppStream-8.10.0.Z.MAIN.EUS:httpd:2.4:8100020240612075645:489197e6",
						},
					},
				},
			},
			in:               "AppStream-8.10.0.Z.MAIN.EUS:httpd:2.4:8100020240612075645:489197e6:httpd-0:2.4.37-65.module+el8.10.0+21982+14717793.aarch64",
			expectedPkgName:  "httpd-0:2.4.37-65.module+el8.10.0+21982+14717793.aarch64",
			expectedRepoName: "AppStream-8.10.0.Z.MAIN.EUS",
			name:             "two_level_relationship",
		},
		{
			c: &csaf.CSAF{
				ProductTree: csaf.ProductBranch{
					Relationships: csaf.Relationships{
						csaf.Relationship{
							Category: "default_component_of",
							FullProductName: csaf.Product{
								Name: "jmc package as part of cros OS",
								ID:   "J-COMP:JMC",
							},
							ProductRef:          "JMC",
							RelatesToProductRef: "J-COMP",
						},
						csaf.Relationship{
							Category: "default_component_of",
							FullProductName: csaf.Product{
								Name: "jmc package as part of J mod",
								ID:   "CROS:J-MOD",
							},
							ProductRef:          "J-MOD",
							RelatesToProductRef: "CROS",
						},
						csaf.Relationship{
							Category: "default_component_of",
							FullProductName: csaf.Product{
								Name: "jmc package as part of J-mod as part of J-COMP as part of cros OS",
								ID:   "CROS:J-MOD:J-COMP:JMC",
							},
							ProductRef:          "J-COMP:JMC",
							RelatesToProductRef: "CROS:J-MOD",
						},
					},
				},
			},
			in:               "CROS:J-MOD:J-COMP:JMC",
			expectedPkgName:  "JMC",
			expectedRepoName: "CROS",
			name:             "two_times_two_level_relationship",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			pkgName, repoName, err := walkRelationships(tc.in, tc.c)
			if err != nil && !tc.err {
				t.Errorf("expected no error but got %q", err)
			}
			if pkgName != tc.expectedPkgName {
				t.Errorf("expected %s but got %s", tc.expectedPkgName, pkgName)
			}
			if repoName != tc.expectedRepoName {
				t.Errorf("expected %s but got %s", tc.expectedRepoName, repoName)
			}
		})
	}
}

func TestEscapeCPE(t *testing.T) {
	testcases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "wildcard version",
			in:   "cpe:/a:redhat:openshift:4.*",
			want: "cpe:/a:redhat:openshift:4.%02",
		},
		{
			name: "product with a wildcard",
			in:   "cpe:/a:redhat:astarry.*.comp:4.*",
			want: "cpe:/a:redhat:astarry.*.comp:4.%02",
		},
		{
			name: "version with question",
			in:   "cpe:/a:redhat:openshift:4.?::el8",
			want: "cpe:/a:redhat:openshift:4.%01::el8",
		},
		{
			name: "question mark can be anywhere",
			in:   "cpe:/a:redhat:openshift:4.?.10::el8",
			want: "cpe:/a:redhat:openshift:4.%01.10::el8",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			out := escapeCPE(tc.in)
			if out != tc.want {
				t.Errorf("expected %s but got %s", tc.want, out)
			}
		})
	}
}
func TestRHTAGParse(t *testing.T) {
	testcases := []struct {
		name                  string
		versionIn             string
		min                   bool
		expectedVersionString string
	}{
		{
			name:                  "no_min",
			min:                   false,
			versionIn:             "1.9.0-9",
			expectedVersionString: "1!9.2147483647",
		},
		{
			name:                  "with_min",
			min:                   true,
			versionIn:             "1.9.0-9",
			expectedVersionString: "1!9",
		},
		{
			name:                  "with_v",
			min:                   true,
			versionIn:             "v3.4.0-2",
			expectedVersionString: "3!4",
		},
		{
			name:                  "check_minor",
			min:                   true,
			versionIn:             "v3.5.7-8",
			expectedVersionString: "3!4",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := rhctag.Parse(tc.versionIn)
			if err != nil {
				t.Fatal(err)
			}
			ccVer := v.Version(tc.min)
			rv := &ccVer
			if rv.String() != tc.expectedVersionString {
				t.Errorf("unexpected version %s but expected %s", rv.String(), tc.expectedVersionString)
			}
		})
	}
}

func TestParse(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	url, err := url.Parse(BaseURL)
	if err != nil {
		t.Error(err)
	}

	testcases := []struct {
		name            string
		filename        string
		expectedVulns   int
		expectedDeleted int
	}{
		// {
		// 	name:            "six_advisories_two_deletions",
		// 	filename:        "testdata/example_vex.jsonl",
		// 	expectedVulns:   546,
		// 	expectedDeleted: 2,
		// },
		{
			name:            "cve-2022-1705",
			filename:        "testdata/cve-2022-1705.jsonl",
			expectedVulns:   736,
			expectedDeleted: 0,
		},
		{
			name:            "cve-2024-24786",
			filename:        "testdata/cve-2024-24786.jsonl",
			expectedVulns:   246,
			expectedDeleted: 0,
		},
		{
			name:            "cve-2022-38752",
			filename:        "testdata/cve-2022-38752.jsonl",
			expectedVulns:   40,
			expectedDeleted: 0,
		},
	}

	u := &Updater{url: url, client: http.DefaultClient}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			f, err := os.Open(tc.filename)
			if err != nil {
				t.Fatalf("failed to open test data file %s: %v", tc.filename, err)
			}

			// Ideally, you'd just use snappy.Encode() but apparently
			// the stream format and the block format are not interchangeable:
			// https://pkg.go.dev/github.com/klauspost/compress/snappy#Writer.
			b, err := io.ReadAll(f)
			if err != nil {
				t.Fatalf("failed to read file bytes: %v", err)
			}
			var buf bytes.Buffer
			sw := snappy.NewBufferedWriter(&buf)
			bLen, err := sw.Write(b)
			if err != nil {
				t.Fatalf("error writing snappy data to buffer: %v", err)
			}
			if bLen != len(b) {
				t.Errorf("didn't write the correct # of bytes")
			}
			if err = sw.Close(); err != nil {
				t.Errorf("failed to close snappy Writer: %v", err)
			}

			vulns, deleted, err := u.DeltaParse(ctx, io.NopCloser(&buf))
			if err != nil {
				t.Fatalf("failed to parse CSAF JSON: %v", err)
			}
			if len(vulns) != tc.expectedVulns {
				t.Errorf("expected %d vulns but got %d", tc.expectedVulns, len(vulns))
			}
			for _, v := range vulns {
				fmt.Println(v.FixedInVersion)
				fmt.Println(v.Range)
			}
			if len(deleted) != tc.expectedDeleted {
				t.Fatalf("expected %d deleted but got %d", tc.expectedDeleted, len(deleted))
			}
		})
	}
}

func TestExtractVersion(t *testing.T) {
	testcases := []struct {
		name        string
		purl        packageurl.PackageURL
		expectedErr bool
		want        string
	}{
		{
			name: "rpm_with_epoch",
			purl: packageurl.PackageURL{
				Type:      packageurl.TypeRPM,
				Namespace: "redhat",
				Name:      "buildah-debugsource",
				Version:   "1.24.6-5.module+el8.8.0+18083+cd85596b",
				Qualifiers: packageurl.QualifiersFromMap(map[string]string{
					"arch":  "ppc64le",
					"epoch": "1",
				}),
			},
			want: "1:1.24.6-5.module+el8.8.0+18083+cd85596b",
		},
		{
			name: "rpm_without_epoch",
			purl: packageurl.PackageURL{
				Type:      packageurl.TypeRPM,
				Namespace: "redhat",
				Name:      "buildah-debugsource",
				Version:   "1.24.6-5.module+el8.8.0+18083+cd85596b",
				Qualifiers: packageurl.QualifiersFromMap(map[string]string{
					"arch": "ppc64le",
				}),
			},
			want: "0:1.24.6-5.module+el8.8.0+18083+cd85596b",
		},
		{
			name: "oci_with_tag",
			purl: packageurl.PackageURL{
				Type:      packageurl.TypeOCI,
				Namespace: "",
				Name:      "keepalived-rhel9",
				Version:   "sha256:36abd2b22ebabea813c5afde35b0b80a200056f811267e89f0270da9155b1a22",
				Qualifiers: packageurl.QualifiersFromMap(map[string]string{
					"arch":           "ppc64le",
					"repository_url": "registry.redhat.io/rhceph/keepalived-rhel9",
					"tag":            "2.2.4-3",
				}),
			},
			want: "2.2.4-3",
		},
		{
			name: "oci_without_tag",
			purl: packageurl.PackageURL{
				Type:      packageurl.TypeOCI,
				Namespace: "",
				Name:      "keepalived-rhel9",
				Version:   "sha256:36abd2b22ebabea813c5afde35b0b80a200056f811267e89f0270da9155b1a22",
				Qualifiers: packageurl.QualifiersFromMap(map[string]string{
					"arch":           "ppc64le",
					"repository_url": "registry.redhat.io/rhceph/keepalived-rhel9",
				}),
			},
			expectedErr: true,
		},

		{
			name: "unsupported_type",
			purl: packageurl.PackageURL{
				Type:      packageurl.TypeApk,
				Namespace: "",
				Name:      "nice APK",
				Version:   "v1.1.1",
				Qualifiers: packageurl.QualifiersFromMap(map[string]string{
					"arch": "ppc64le",
				}),
			},
			expectedErr: true,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := extractFixedInVersion(tc.purl)
			if !errors.Is(err, nil) && !tc.expectedErr {
				t.Fatalf("expected no err but got %v", err)
			}
			if errors.Is(err, nil) && tc.expectedErr {
				t.Fatal("expected err but got none")
			}
			if v != tc.want {
				t.Fatalf("expected version %v but got %v", tc.want, v)
			}
		})
	}
}

func TestExtractPackageName(t *testing.T) {
	testcases := []struct {
		name        string
		purl        packageurl.PackageURL
		expectedErr bool
		want        string
	}{
		{
			name: "rpm_simple",
			purl: packageurl.PackageURL{
				Type:      packageurl.TypeRPM,
				Namespace: "redhat",
				Name:      "buildah-debugsource",
				Version:   "1.24.6-5.module+el8.8.0+18083+cd85596b",
				Qualifiers: packageurl.QualifiersFromMap(map[string]string{
					"arch":  "ppc64le",
					"epoch": "1",
				}),
			},
			want: "buildah-debugsource",
		},
		{
			name: "oci_with_repository_url",
			purl: packageurl.PackageURL{
				Type:      packageurl.TypeOCI,
				Namespace: "",
				Name:      "keepalived-rhel9",
				Version:   "sha256:36abd2b22ebabea813c5afde35b0b80a200056f811267e89f0270da9155b1a22",
				Qualifiers: packageurl.QualifiersFromMap(map[string]string{
					"arch":           "ppc64le",
					"repository_url": "registry.redhat.io/rhceph/keepalived-rhel9",
					"tag":            "2.2.4-3",
				}),
			},
			want: "rhceph/keepalived-rhel9",
		},
		{
			name: "oci_without_repository_url",
			purl: packageurl.PackageURL{
				Type:      packageurl.TypeOCI,
				Namespace: "",
				Name:      "keepalived-rhel9",
				Version:   "sha256:36abd2b22ebabea813c5afde35b0b80a200056f811267e89f0270da9155b1a22",
				Qualifiers: packageurl.QualifiersFromMap(map[string]string{
					"arch": "ppc64le",
				}),
			},
			expectedErr: true,
		},
		{
			name: "oci_invalid_repository_url",
			purl: packageurl.PackageURL{
				Type:      packageurl.TypeOCI,
				Namespace: "",
				Name:      "keepalived-rhel9",
				Version:   "sha256:36abd2b22ebabea813c5afde35b0b80a200056f811267e89f0270da9155b1a22",
				Qualifiers: packageurl.QualifiersFromMap(map[string]string{
					"arch":           "ppc64le",
					"repository_url": "registry.redhat.iorhcephkeepalived-rhel9",
				}),
			},
			expectedErr: true,
		},
		{
			name: "unsupported_type",
			purl: packageurl.PackageURL{
				Type:      packageurl.TypeApk,
				Namespace: "",
				Name:      "nice APK",
				Version:   "v1.1.1",
				Qualifiers: packageurl.QualifiersFromMap(map[string]string{
					"arch": "ppc64le",
				}),
			},
			expectedErr: true,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := extractPackageName(tc.purl)
			if !errors.Is(err, nil) && !tc.expectedErr {
				t.Fatalf("expected no err but got %v", err)
			}
			if errors.Is(err, nil) && tc.expectedErr {
				t.Fatal("expected err but got none")
			}
			if v != tc.want {
				t.Fatalf("expected name %v but got %v", tc.want, v)
			}
		})
	}
}
