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
	v := newTestVersionResolver(srv.Client())

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
	v := newTestVersionResolver(srv.Client())
	aq := &AquaPackage{VersionFilter: `Version startsWith "go"`}
	if _, err := v.latestGitHubTag(t.Context(), "o", "r", aq); err == nil {
		t.Fatal("want error when nothing matches")
	}
}

// TestLatestGitHubTag_WalksEveryPageOfTheCap pins the documented walk
// depth. golang/go already needs ~6 pages before a usable tag appears, so
// a walk that stops one page short of the cap silently reports "no tag
// passes the version filter" for a repo whose newest tag is exactly that
// far down.
func TestLatestGitHubTag_WalksEveryPageOfTheCap(t *testing.T) {
	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page == tagPageCap {
			fmt.Fprint(w, `[{"name":"v1.0.0"}]`)
			return
		}
		// A full page of tags the prefix rejects: 100 entries is what
		// tells the resolver another page may follow.
		names := make([]string, 0, 100)
		for i := range 100 {
			names = append(names, fmt.Sprintf(`{"name":"ancient-%d"}`, i))
		}
		fmt.Fprint(w, "["+strings.Join(names, ",")+"]")
	}))
	v := newTestVersionResolver(srv.Client())

	got, err := v.latestGitHubTag(t.Context(), "o", "r", &AquaPackage{VersionPrefix: "v"})
	if err != nil {
		t.Fatalf("latestGitHubTag with the newest tag on page %d: %v", tagPageCap, err)
	}
	if got != "v1.0.0" {
		t.Errorf("latestGitHubTag = %q, want v1.0.0", got)
	}
}

// TestLatestGitHubTag_PrefixRejectsForeignTags pins version_prefix as a
// filter and not just a trim: a monorepo tags several components, and a
// sibling component's higher number must not be offered as this tool's
// latest version.
func TestLatestGitHubTag_PrefixRejectsForeignTags(t *testing.T) {
	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `[{"name":"cli/v1.2.0"},{"name":"v9.9.9"}]`)
	}))
	v := newTestVersionResolver(srv.Client())

	got, err := v.latestGitHubTag(t.Context(), "o", "r", &AquaPackage{VersionPrefix: "cli/v"})
	if err != nil {
		t.Fatalf("latestGitHubTag: %v", err)
	}
	if got != "cli/v1.2.0" {
		t.Errorf("latestGitHubTag with prefix cli/v = %q, want cli/v1.2.0", got)
	}
}

// TestLatestAqua_TagVersioningNeverReadsTheReleaseEndpoint pins the
// routing a definition asks for: version_source github_tag means the tag
// list decides, so a repo whose releases/latest is stale or absent still
// resolves.
func TestLatestAqua_TagVersioningNeverReadsTheReleaseEndpoint(t *testing.T) {
	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/tags") {
			fmt.Fprint(w, `[{"name":"v3.1.0"},{"name":"v3.0.0"}]`)
			return
		}
		fmt.Fprint(w, `{"tag_name":"v0.0.1"}`)
	}))
	v := newTestVersionResolver(srv.Client())

	got, err := v.Latest(t.Context(), "aqua:owner/repo", &AquaPackage{VersionSource: "github_tag"})
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got != "v3.1.0" {
		t.Errorf("Latest(aqua:owner/repo, version_source=github_tag) = %q, want v3.1.0", got)
	}
}

// TestLatestAqua_LatestReleaseFailingTheFilterFallsBackToTags covers the
// shape the fallback exists for: a repo carrying a permanent "latest"
// release tag. Handing that string back as a version would install a
// directory literally named latest and re-resolve to it forever.
func TestLatestAqua_LatestReleaseFailingTheFilterFallsBackToTags(t *testing.T) {
	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/tags") {
			fmt.Fprint(w, `[{"name":"v2.0.0"},{"name":"latest"}]`)
			return
		}
		fmt.Fprint(w, `{"tag_name":"latest"}`)
	}))
	v := newTestVersionResolver(srv.Client())
	aq := &AquaPackage{VersionFilter: `not (Version in ["latest", "stable"])`}

	got, err := v.Latest(t.Context(), "aqua:owner/repo", aq)
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got != "v2.0.0" {
		t.Errorf("Latest with a filtered-out release tag = %q, want v2.0.0", got)
	}
}

func TestLatestAqua_RuntimeResolvesFromItsOwnIndex(t *testing.T) {
	cases := []struct {
		name, source, host, path, body, want string
		aq                                   *AquaPackage
	}{
		{
			name: "node", source: "aqua:nodejs/node",
			host: "nodejs.org", path: "/dist/index.json",
			body: `[{"version":"v8.0.0"},{"version":"v26.10.0"},{"version":"v24.21.0"},{"version":"v26.9.0"}]`,
			aq:   &AquaPackage{Type: aquaTypeHTTP, RepoOwner: "nodejs", RepoName: "node"},
			want: "v26.10.0",
		},
		{
			name: "go", source: "aqua:golang/go",
			host: "go.dev", path: "/dl/",
			body: `[{"version":"go1.26.8"},{"version":"go1.28rc1"},{"version":"go1.27.1"}]`,
			aq: &AquaPackage{
				Type: aquaTypeHTTP, RepoOwner: "golang", RepoName: "go", VersionSource: "github_tag",
				VersionFilter: `Version startsWith "go" and not (Version contains "rc" or Version contains "beta")`,
			},
			want: "go1.27.1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Host == tc.host && r.URL.Path == tc.path {
					fmt.Fprint(w, tc.body)
					return
				}
				t.Errorf("request to %s%s, want only %s%s", r.Host, r.URL.Path, tc.host, tc.path)
				http.NotFound(w, r)
			}))
			v := newTestVersionResolver(srv.Client())

			got, err := v.Latest(t.Context(), tc.source, tc.aq)
			if err != nil {
				t.Fatalf("Latest(%s) = %v", tc.source, err)
			}
			if got != tc.want {
				t.Errorf("Latest(%s) = %q, want %q", tc.source, got, tc.want)
			}
		})
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
		// The undeclared prefix is skipped by scanning to the first
		// DIGIT, and 0 and 9 are digits: a tag whose version starts at a
		// 0 must not be read from the next digit along (0.9 is not 9),
		// and one whose version starts at a 9 must not lose it (9.1 is
		// not 1). Either slip inverts the comparison.
		{[]string{"jq-0.9", "jq-1.2"}, "", "jq-1.2"},
		{[]string{"go9.1", "go2.0"}, "", "go9.1"},
		// A tag that does not parse as a version never outranks one that
		// does, in either listing order; two that do not parse fall back
		// to lexicographic order.
		{[]string{"latest", "v1.0.0"}, "", "v1.0.0"},
		{[]string{"v1.0.0", "latest"}, "", "v1.0.0"},
		{[]string{"nightly", "stable"}, "", "stable"},
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
	v := newTestVersionResolver(srv.Client())
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

// newTestVersionResolver builds a resolver with no apt index: a test drives
// httptest servers, so the index has nothing to contribute.
func newTestVersionResolver(client *http.Client) *versionResolver {
	return newVersionResolver(client, nil)
}
