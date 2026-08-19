package toolbelt

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// TestLatestGitHubTag_PaginatesAndVersionCompares reproduces the
// golang/go shape that broke first-tag selection: page 1 holds only
// ancient non-matching tags (weekly.*), the real go1* tags appear on a
// later page, and response order is NOT newest-first. The resolver
// must paginate and pick the version-maximum, never the first match.
func TestLatestGitHubTag_PaginatesAndVersionCompares(t *testing.T) {
	type tag struct {
		Name string `json:"name"`
	}
	pages := map[int][]tag{}
	// Page 1: 100 ancient weekly tags (no go1* match).
	for i := range 100 {
		pages[1] = append(pages[1], tag{Name: "weekly.2012-" + strconv.Itoa(i)})
	}
	// Page 2: go tags in scrambled order — go1.9 BEFORE go1.24 (a
	// lexicographic or first-match pick would return the wrong one).
	pages[2] = []tag{
		{Name: "go1.9"},
		{Name: "go1.24rc1"}, // filtered out by the version_filter
		{Name: "go1.23.4"},
		{Name: "go1.24.0"},
		{Name: "go1.22beta2"}, // filtered out
	}

	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page == 0 {
			page = 1
		}
		_ = json.NewEncoder(w).Encode(pages[page])
	}))

	// srv.Client() routes every request to the handler whatever absolute
	// api.github.com URL the resolver builds, so nothing has to redirect
	// the request.
	v := newVersionResolver(srv.Client())

	aq := &AquaPackage{
		Type: "http", RepoOwner: "golang", RepoName: "go",
		VersionSource: "github_tag",
		VersionFilter: `Version startsWith "go" and not (Version contains "rc" or Version contains "beta")`,
	}
	got, err := v.latestGitHubTag(t.Context(), "golang", "go", aq)
	if err != nil {
		t.Fatal(err)
	}
	if got != "go1.24.0" {
		t.Fatalf("latest = %q, want go1.24.0", got)
	}
}

func TestLatestGitHubTag_NoMatchErrors(t *testing.T) {
	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `[{"name":"nope"}]`)
	}))
	v := newVersionResolver(srv.Client())
	aq := &AquaPackage{VersionFilter: `Version startsWith "go"`}
	if _, err := v.latestGitHubTag(t.Context(), "o", "r", aq); err == nil {
		t.Fatal("want error when nothing matches")
	}
}

func TestMaxVersionTag(t *testing.T) {
	cases := []struct {
		candidates []string
		prefix     string
		want       string
	}{
		{[]string{"v1.9.0", "v1.24.0", "v1.10.1"}, "", "v1.24.0"},
		{[]string{"go1.9", "go1.24.0", "go1.23.4"}, "", "go1.24.0"},
		{[]string{"jq-1.7.1", "jq-1.8.2"}, "", "jq-1.8.2"},
		{[]string{"2025-01-06", "2024-12-01"}, "", "2025-01-06"},
		{[]string{"only"}, "", "only"},
	}
	for _, c := range cases {
		if got := maxVersionTag(c.candidates, c.prefix); got != c.want {
			t.Errorf("maxVersionTag(%v) = %q, want %q", c.candidates, got, c.want)
		}
	}
}

func TestConstraint_AquaParity(t *testing.T) {
	// checkConstraint is a direct port of aqua's
	// pkg/expr/version_compare.go compare(): six operators over direct
	// go-version comparisons (NOT Constraints.Check, whose prerelease
	// gating aqua doesn't use), comma = AND, commit hashes never match.
	cases := []struct {
		constraint, ver string
		want            bool
	}{
		// Prereleases compare by semver precedence in plain ranges —
		// the divergence from Masterminds that motivated the port.
		{"<= 24.10.0", "24.9.0-rc.1", true},
		{"<= 24.10.0", "24.11.0-rc.1", false},
		{"< 1.0.0", "1.0.0-beta.1", true}, // prerelease sorts below release
		// Operator set.
		{">= 1.0, < 2.0", "1.5.0", true},
		{">= 1.0, < 2.0", "2.0.0", false},
		{"!= 1.2.3", "1.2.4", true},
		{"!= 1.2.3", "1.2.3", false},
		{"= 2.27.0", "2.27.0", true},
		{"> 0.4.5", "0.4.5", false},
		// Commit hashes never match (aqua guard).
		{">= 0.0.1", strings.Repeat("a1", 20), false},
		// Unparseable pieces are false (aqua would panic; we fail soft).
		{"garbage", "1.0.0", false},
		{"~> 1.0", "1.5.0", false}, // pessimistic operator: not in aqua's set
		{">= not-a-version", "1.0.0", false},
	}
	for _, c := range cases {
		if got := checkConstraint(c.constraint, c.ver); got != c.want {
			t.Errorf("checkConstraint(%q, %q) = %v, want %v", c.constraint, c.ver, got, c.want)
		}
	}
}

// TestLatestNpm_UsesDistTagEndpoint pins the npm lookup to the slim
// /{pkg}/latest dist-tag endpoint. The full packument (/{pkg}) carries
// every version ever published and exceeds the response-size cap on
// big packages (typescript's is >4 MiB — hit enabling the seed
// template on a live volume).
func TestLatestNpm_UsesDistTagEndpoint(t *testing.T) {
	var gotPath string
	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		fmt.Fprint(w, `{"version":"5.3.0"}`)
	}))
	v := newVersionResolver(srv.Client())
	got, err := v.Latest(t.Context(), "npm:typescript-language-server", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "5.3.0" {
		t.Fatalf("latest = %q, want 5.3.0", got)
	}
	if gotPath != "/typescript-language-server/latest" {
		t.Fatalf("endpoint = %q, want /typescript-language-server/latest", gotPath)
	}
}
