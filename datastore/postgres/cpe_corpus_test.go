package postgres

import (
	"bufio"
	"embed"
	"strings"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/rhel"
	"github.com/quay/claircore/toolkit/types/cpe"
)

//go:embed testdata/vex-feed-cpes.txt
var vexFeedCPEFile embed.FS

func loadVEXFeedCPEs(t *testing.T) []cpe.WFN {
	t.Helper()
	f, err := vexFeedCPEFile.Open("testdata/vex-feed-cpes.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []cpe.WFN
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		w, err := cpe.Unbind(line)
		if err != nil {
			t.Fatalf("line %d %q: %v", n, line, err)
		}
		if cpeProductPrefix(w) == "" {
			t.Fatalf("line %d %q: empty product prefix", n, line)
		}
		out = append(out, w)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("empty CPE corpus")
	}
	return out
}

func vexWFN(t *testing.T, uri string) cpe.WFN {
	t.Helper()
	w, err := cpe.Unbind(uri)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// sqlCPESubstring reports whether Get would keep vuln for record, mirroring
// cpeSubstringExpressions (product LIKE then starts_with + rtrim).
func sqlCPESubstring(record, vuln cpe.WFN) bool {
	repo := vuln.String()
	if prefix := cpeProductPrefix(record); prefix != "" && !strings.HasPrefix(repo, prefix) {
		return false
	}
	return strings.HasPrefix(record.String(), strings.TrimRight(repo, ":*"))
}

func TestVEXFeedCPERepresentative(t *testing.T) {
	// Pairs are URI-form product_identification_helper.cpe values from
	// vex-feed/vex-archive.tar.zst. Record is the indexed CPE, vuln is repo_name.
	tests := []struct {
		name, record, vuln string
		want               bool
	}{
		{"ocp short version", "cpe:/a:redhat:openshift:4.13::el8", "cpe:/a:redhat:openshift:4", true},
		{"ocp dotted version", "cpe:/a:redhat:openshift:4.13::el8", "cpe:/a:redhat:openshift:4.13", true},
		{"ocp same edition", "cpe:/a:redhat:openshift:4.13::el8", "cpe:/a:redhat:openshift:4.13::el8", true},
		{"ocp other minor", "cpe:/a:redhat:openshift:4.13::el8", "cpe:/a:redhat:openshift:4.12::el8", false},
		{"ocp v3", "cpe:/a:redhat:openshift:4.13::el8", "cpe:/a:redhat:openshift:3", false},
		{"ocp vs openshift_ai", "cpe:/a:redhat:openshift:4.13::el8", "cpe:/a:redhat:openshift_ai:2.16::el8", false},
		{"el8 os short", "cpe:/o:redhat:enterprise_linux:8::baseos", "cpe:/o:redhat:enterprise_linux:8", true},
		{"el8 os same", "cpe:/o:redhat:enterprise_linux:8::baseos", "cpe:/o:redhat:enterprise_linux:8::baseos", true},
		{"el8 vs el9 os", "cpe:/o:redhat:enterprise_linux:8::baseos", "cpe:/o:redhat:enterprise_linux:9::baseos", false},
		{"os vs appstream part", "cpe:/o:redhat:enterprise_linux:8::baseos", "cpe:/a:redhat:enterprise_linux:8::appstream", false},
		{"el9 appstream short", "cpe:/a:redhat:enterprise_linux:9::appstream", "cpe:/a:redhat:enterprise_linux:9", true},
		{"el9 appstream same", "cpe:/a:redhat:enterprise_linux:9::appstream", "cpe:/a:redhat:enterprise_linux:9::appstream", true},
		{"el9 appstream vs crb", "cpe:/a:redhat:enterprise_linux:9::appstream", "cpe:/a:redhat:enterprise_linux:9::crb", false},
		{"el10 dotted vs short", "cpe:/o:redhat:enterprise_linux:10.1", "cpe:/o:redhat:enterprise_linux:10", true},
		{"eus vs main os", "cpe:/o:redhat:rhel_eus:9.4::baseos", "cpe:/o:redhat:enterprise_linux:9::baseos", false},
		{"eus same", "cpe:/o:redhat:rhel_eus:9.4::baseos", "cpe:/o:redhat:rhel_eus:9.4::baseos", true},
		{"aap nover pattern", "cpe:/a:redhat:ansible_automation_platform:2.3::el8", "cpe:/a:redhat:ansible_automation_platform", true},
		{"aap short version", "cpe:/a:redhat:ansible_automation_platform:2.3::el8", "cpe:/a:redhat:ansible_automation_platform:2", true},
		{"aap developer vs aap", "cpe:/a:redhat:ansible_automation_platform_developer:2.3::el8", "cpe:/a:redhat:ansible_automation_platform", false},
		{"aap inside vs aap", "cpe:/a:redhat:ansible_automation_platform_inside:2.3::el9", "cpe:/a:redhat:ansible_automation_platform:2.3::el9", false},
		{"acm short version", "cpe:/a:redhat:acm:2.10::el9", "cpe:/a:redhat:acm:2", true},
		{"3scale short version", "cpe:/a:redhat:3scale_amp:2.11::el8", "cpe:/a:redhat:3scale_amp:2", true},
		{"a_mq_clients same", "cpe:/a:redhat:a_mq_clients:2::el7", "cpe:/a:redhat:a_mq_clients:2::el7", true},
		{"convert2rhel nover", "cpe:/a:redhat:convert2rhel", "cpe:/a:redhat:convert2rhel", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, vuln := vexWFN(t, tt.record), vexWFN(t, tt.vuln)
			if got := sqlCPESubstring(rec, vuln); got != tt.want {
				t.Fatalf("sql=%v want=%v\n record %s\n vuln   %s\n recFS  %s\n vulnFS %s",
					got, tt.want, tt.record, tt.vuln, rec, vuln)
			}
		})
	}
}

func TestVEXFeedCPESubstringSQL(t *testing.T) {
	cpes := loadVEXFeedCPEs(t)
	t.Logf("vex-feed corpus: %d CPEs", len(cpes))

	var sub, subFN, super, superOnly int
	type pair struct{ rec, vuln string }
	var fns []pair
	for _, rec := range cpes {
		for _, vuln := range cpes {
			goSub := rhel.IsCPESubstringMatch(rec, vuln)
			sql := sqlCPESubstring(rec, vuln)
			if goSub {
				sub++
				if !sql {
					subFN++
					fns = append(fns, pair{rec.String(), vuln.String()})
				}
			}
			if cpe.Compare(vuln, rec).IsSuperset() {
				super++
				if !goSub && !sql {
					superOnly++
					if superOnly <= 5 {
						t.Logf("IsSuperset-only (SQL drops) record=%q vuln=%q", rec, vuln)
					}
				}
			}
		}
	}
	t.Logf("substring matches=%d fn=%d IsSuperset=%d IsSuperset-only=%d", sub, subFN, super, superOnly)
	sameProduct := 0
	for _, fn := range fns {
		recP := cpeProductPrefix(vexWFN(t, fn.rec))
		vulnP := cpeProductPrefix(vexWFN(t, fn.vuln))
		if recP == vulnP {
			sameProduct++
			t.Errorf("same-product substring FN record=%q vuln=%q", fn.rec, fn.vuln)
			continue
		}
	}
	if sameProduct > 0 {
		t.Fatalf("%d same-product IsCPESubstringMatch hits dropped by SQL", sameProduct)
	}
}

func TestCPESubstringEmptyRecord(t *testing.T) {
	if got := cpeSubstringExpressions(nil); got != nil {
		t.Fatalf("nil record: %v", got)
	}
	if got := cpeSubstringExpressions(&claircore.IndexRecord{}); got != nil {
		t.Fatalf("nil repo: %v", got)
	}
	if got := cpeSubstringExpressions(&claircore.IndexRecord{Repository: &claircore.Repository{}}); got != nil {
		t.Fatalf("empty CPE: %v", got)
	}
}
