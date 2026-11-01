package toolbelt

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
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
	got, err := v.latestGitHubTag(t.Context(), "golang", "go", aq, false)
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
	if _, err := v.latestGitHubTag(t.Context(), "o", "r", aq, false); err == nil {
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
		if page == listPageCap {
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

	got, err := v.latestGitHubTag(t.Context(), "o", "r", &AquaPackage{VersionPrefix: "v"}, false)
	if err != nil {
		t.Fatalf("latestGitHubTag with the newest tag on page %d: %v", listPageCap, err)
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

	got, err := v.latestGitHubTag(t.Context(), "o", "r", &AquaPackage{VersionPrefix: "cli/v"}, false)
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

	got, err := v.Latest(t.Context(), &Tool{Source: "aqua:owner/repo"}, &AquaPackage{VersionSource: "github_tag"})
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

	got, err := v.Latest(t.Context(), &Tool{Source: "aqua:owner/repo"}, aq)
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got != "v2.0.0" {
		t.Errorf("Latest with a filtered-out release tag = %q, want v2.0.0", got)
	}
}

func TestLatestAqua_RuntimeResolvesFromItsOwnIndex(t *testing.T) {
	cases := []struct {
		name, source, version, host, path, body, want string
		aq                                            *AquaPackage
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
		// nodejs.org's index lists v27.0.0-alpha.0.0.0 first, above v26.13.0.
		{
			name: "node skips a prerelease above the stable line", source: "aqua:nodejs/node", version: "v26.12.1",
			host: "nodejs.org", path: "/dist/index.json",
			body: `[{"version":"v27.0.0-alpha.0.0.0"},{"version":"v26.13.0"},{"version":"v26.12.1"}]`,
			aq:   &AquaPackage{Type: aquaTypeHTTP, RepoOwner: "nodejs", RepoName: "node"},
			want: "v26.13.0",
		},
		{
			name: "node follows the prerelease line it is on", source: "aqua:nodejs/node", version: "v27.0.0-alpha.0.0.0",
			host: "nodejs.org", path: "/dist/index.json",
			body: `[{"version":"v27.0.0-alpha.0.0.0"},{"version":"v26.13.0"},{"version":"v26.12.1"}]`,
			aq:   &AquaPackage{Type: aquaTypeHTTP, RepoOwner: "nodejs", RepoName: "node"},
			want: "v27.0.0-alpha.0.0.0",
		},
		{
			name: "go skips a release candidate without a filter", source: "aqua:golang/go", version: "go1.27.1",
			host: "go.dev", path: "/dl/",
			body: `[{"version":"go1.28rc1"},{"version":"go1.27.3"}]`,
			aq:   &AquaPackage{Type: aquaTypeHTTP, RepoOwner: "golang", RepoName: "go"},
			want: "go1.27.3",
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

			got, err := v.Latest(t.Context(), &Tool{Source: tc.source, Version: tc.version}, tc.aq)
			if err != nil {
				t.Fatalf("Latest(%s) = %v", tc.source, err)
			}
			if got != tc.want {
				t.Errorf("Latest(%s) = %q, want %q", tc.source, got, tc.want)
			}
		})
	}
}

// A tag list's prereleases are skipped unless the recorded version is one.
func TestLatestGitHubTag_SkipsPrereleases(t *testing.T) {
	cases := []struct{ name, recorded, want string }{
		{name: "stable line skips the release candidate", recorded: "v2.8.0", want: "v2.9.0"},
		{name: "unrecorded version skips the release candidate", recorded: "", want: "v2.9.0"},
		{name: "prerelease line takes the release candidate", recorded: "v3.0.0-beta.1", want: "v3.0.0-rc.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasSuffix(r.URL.Path, "/tags") {
					t.Errorf("request to %s, want only the tag list", r.URL.Path)
				}
				fmt.Fprint(w, `[{"name":"v3.0.0-rc.1"},{"name":"v2.9.0"},{"name":"v2.8.0"}]`)
			}))
			v := newTestVersionResolver(srv.Client())
			tool := &Tool{Source: "aqua:o/r", Version: tc.recorded}
			got, err := v.Latest(t.Context(), tool, &AquaPackage{VersionSource: "github_tag"})
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("Latest(recorded %q) = %q, want %q", tc.recorded, got, tc.want)
			}
		})
	}
}

// GitLab marks no release as a prerelease and lists by release date
// (https://docs.gitlab.com/api/releases/#list-releases), so the engine picks
// by version from the newest page.
func TestLatestGitLabRelease_PicksByVersion(t *testing.T) {
	cases := []struct{ name, body, recorded, want string }{
		{
			name: "skips a newer prerelease", recorded: "v1.9.9",
			body: `[{"tag_name":"v2.1.0-rc1"},{"tag_name":"v2.0.0"},{"tag_name":"v1.9.9"}]`, want: "v2.0.0",
		},
		{
			name: "prerelease line takes the prerelease", recorded: "v2.1.0-rc0",
			body: `[{"tag_name":"v2.1.0-rc1"},{"tag_name":"v2.0.0"}]`, want: "v2.1.0-rc1",
		},
		{
			name: "a back-branch patch released last is not latest", recorded: "v1.9.9",
			body: `[{"tag_name":"v1.9.10"},{"tag_name":"v2.0.0"}]`, want: "v2.0.0",
		},
		{
			name: "no version-shaped tag keeps the newest release",
			body: `[{"tag_name":"nightly"},{"tag_name":"stable"}]`, want: "nightly",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var asked string
			srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				asked = r.Host + r.URL.EscapedPath() + "?" + r.URL.RawQuery
				fmt.Fprint(w, tc.body)
			}))
			v := newTestVersionResolver(srv.Client())
			got, err := v.Latest(t.Context(), &Tool{Source: "release:gitlab/o/r", Version: tc.recorded}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("Latest = %q, want %q", got, tc.want)
			}
			if want := "gitlab.com/api/v4/projects/o%2Fr/releases?per_page=100&page=1"; asked != want {
				t.Errorf("asked %q, want %q", asked, want)
			}
		})
	}
}

// fullPage renders a full 100-entry page of JSON objects whose key field
// holds name; a name with no digit parses as no version.
func fullPage(key, name string) string {
	entries := make([]string, 0, 100)
	for range 100 {
		entries = append(entries, fmt.Sprintf(`{%q:%q}`, key, name))
	}
	return "[" + strings.Join(entries, ",") + "]"
}

// GitLab paginates releases at most 100 per page
// (https://docs.gitlab.com/api/rest/#pagination); the highest version can sit
// on any page because the order is by release date.
func TestLatestGitLabRelease_WalksEveryPage(t *testing.T) {
	cases := []struct {
		name     string
		pages    map[int]string
		recorded string
		want     string
	}{
		{
			name: "a higher version on page 2 wins", recorded: "v1.0.0",
			pages: map[int]string{
				1: strings.Replace(fullPage("tag_name", "nightly"), `"nightly"`, `"v1.9.10"`, 1),
				2: `[{"tag_name":"v2.0.0"},{"tag_name":"v1.0.0"}]`,
			},
			want: "v2.0.0",
		},
		{
			name: "no version-shaped tag on any page keeps the newest release",
			pages: map[int]string{
				1: fullPage("tag_name", "nightly"),
				2: `[{"tag_name":"stable"}]`,
			},
			want: "nightly",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var asked []int
			srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.URL.Query().Get("per_page"); got != "100" {
					t.Errorf("per_page = %q, want 100", got)
				}
				page, _ := strconv.Atoi(r.URL.Query().Get("page"))
				asked = append(asked, page)
				body, ok := tc.pages[page]
				if !ok {
					body = `[]`
				}
				fmt.Fprint(w, body)
			}))
			v := newTestVersionResolver(srv.Client())
			got, err := v.Latest(t.Context(), &Tool{Source: "release:gitlab/o/r", Version: tc.recorded}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("Latest = %q, want %q", got, tc.want)
			}
			if !slices.Equal(asked, []int{1, 2}) {
				t.Errorf("pages asked = %v, want [1 2] (stop at the short page)", asked)
			}
		})
	}
}

// A walk that reaches the page cap with the cap page still full has not seen
// every version, so the highest it saw is not known to be the latest.
func TestLatest_FullCapPageIsAnIncompleteWalk(t *testing.T) {
	cases := []struct {
		name, source, key string
		aq                *AquaPackage
	}{
		{name: "gitlab releases", source: "release:gitlab/o/r", key: "tag_name"},
		{name: "github tag list", source: "aqua:o/r", key: "name", aq: &AquaPackage{VersionSource: "github_tag"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pagesAsked := 0
			srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				page, _ := strconv.Atoi(r.URL.Query().Get("page"))
				pagesAsked++
				body := fullPage(tc.key, "ancient")
				if page == 1 {
					body = strings.Replace(body, `"ancient"`, `"v1.0.0"`, 1)
				}
				fmt.Fprint(w, body)
			}))
			v := newTestVersionResolver(srv.Client())
			got, err := v.Latest(t.Context(), &Tool{Source: tc.source}, tc.aq)
			if !errors.Is(err, errIncompleteWalk) {
				t.Errorf("Latest = %q, %v; want errIncompleteWalk", got, err)
			}
			if pagesAsked != listPageCap {
				t.Errorf("pages asked = %d, want %d", pagesAsked, listPageCap)
			}
		})
	}
}

func TestLatestGitLabRelease_NoReleasesErrors(t *testing.T) {
	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `[]`)
	}))
	v := newTestVersionResolver(srv.Client())
	if _, err := v.Latest(t.Context(), &Tool{Source: "release:gitlab/o/r"}, nil); err == nil {
		t.Fatal("Latest succeeded with no releases, want an error")
	}
}

func TestLatestTag(t *testing.T) {
	cases := []struct {
		name       string
		candidates []string
		allowPre   bool
		want       string
	}{
		{name: "release beats a higher rc", candidates: []string{"v1.3.0-rc.1", "v1.2.0"}, want: "v1.2.0"},
		{name: "go rc is a prerelease", candidates: []string{"go1.28rc1", "go1.27.3"}, want: "go1.27.3"},
		{name: "prerelease allowed wins", candidates: []string{"v1.3.0-rc.1", "v1.2.0"}, allowPre: true, want: "v1.3.0-rc.1"},
		{name: "release above a prerelease wins when allowed", candidates: []string{"v1.3.0-rc.1", "v1.3.0"}, allowPre: true, want: "v1.3.0"},
		{name: "only prereleases leave nothing", candidates: []string{"v2.0.0-beta.1", "v2.0.0-rc.1"}, want: ""},
		{name: "only prereleases when allowed takes the highest", candidates: []string{"v2.0.0-beta.1", "v2.0.0-rc.1"}, allowPre: true, want: "v2.0.0-rc.1"},
		{name: "an unparsed tag is no release", candidates: []string{"latest", "v2.0.0-rc.1"}, want: ""},
		{name: "an unparsed tag never beats a prerelease", candidates: []string{"latest", "v2.0.0-rc.1"}, allowPre: true, want: "v2.0.0-rc.1"},
		{name: "unparsed tags alone compare by name", candidates: []string{"nightly", "stable"}, want: "stable"},
		{name: "date tags compare", candidates: []string{"2024-12-01", "2025-01-06"}, want: "2025-01-06"},
		{name: "a date tag beats a later dated prerelease", candidates: []string{"2025-01-06", "2025-02-01-rc1"}, want: "2025-01-06"},
		{name: "a v-prefixed date tag is a release", candidates: []string{"v1.2.3", "v2025-01-06"}, want: "v2025-01-06"},
		{name: "a nightly date is no release", candidates: []string{"v1.2.3", "nightly-2025-01-06"}, want: "v1.2.3"},
		{name: "a weekly date is no release", candidates: []string{"v26.13.0", "weekly.2025-01-06"}, want: "v26.13.0"},
		{name: "a snapshot date is no release", candidates: []string{"v1.2.3", "snapshot-2024-12-01"}, want: "v1.2.3"},
		{name: "no candidates", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := latestTag(tc.candidates, "", tc.allowPre); got != tc.want {
				t.Errorf("latestTag(%v, allowPre=%v) = %q, want %q", tc.candidates, tc.allowPre, got, tc.want)
			}
		})
	}
}

func TestIsPrereleaseTag(t *testing.T) {
	cases := []struct {
		tag    string
		prefix string
		want   bool
	}{
		{tag: "v27.0.0-alpha.0.0.0", want: true},
		{tag: "go1.28rc1", want: true},
		{tag: "v0.0.0-20261011093844-7a2c2c0b7aa6", want: true},
		{tag: "2025-02-01-rc1", want: true},
		{tag: "nightly-2025-01-06", want: true},
		{tag: "weekly.2025-01-06", want: true},
		{tag: "snapshot-2024-12-01", want: true},
		{tag: "v1.2.3", want: false},
		{tag: "2025-01-06", want: false},
		{tag: "v2025-01-06", want: false},
		{tag: "release-2025-01-06", prefix: "release-", want: false},
		{tag: "latest", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.tag, func(t *testing.T) {
			if got := isPrereleaseTag(tc.tag, tc.prefix); got != tc.want {
				t.Errorf("isPrereleaseTag(%q, %q) = %v, want %v", tc.tag, tc.prefix, got, tc.want)
			}
		})
	}
}

// Every list source refuses a row that is not on a prerelease line when it
// lists only prereleases (or, for Go, only a pseudo-version), and a row
// recorded at a prerelease follows them.
func TestLatest_OnlyPrereleasesListed(t *testing.T) {
	const pseudo = "v0.0.0-20261011093844-7a2c2c0b7aa6"
	node := &AquaPackage{Type: aquaTypeHTTP, RepoOwner: "nodejs", RepoName: "node"}
	golang := &AquaPackage{Type: aquaTypeHTTP, RepoOwner: "golang", RepoName: "go"}
	cases := []struct {
		name, source, stable, pre, want string
		aq                              *AquaPackage
		routes                          map[string]string
	}{
		{
			name: "node index", source: "aqua:nodejs/node", aq: node, stable: "v26.13.0", pre: "v27.0.0-alpha.0", want: "v27.0.0-alpha.0.0.0",
			routes: map[string]string{"nodejs.org/dist/index.json": `[{"version":"v27.0.0-alpha.0.0.0"}]`},
		},
		{
			name: "go index", source: "aqua:golang/go", aq: golang, stable: "go1.27.3", pre: "go1.28rc0", want: "go1.28rc1",
			routes: map[string]string{"go.dev/dl/": `[{"version":"go1.28rc1"}]`},
		},
		{
			name: "github tag list", source: "aqua:o/r", aq: &AquaPackage{VersionSource: "github_tag"}, pre: "v3.0.0-beta.1", want: "v3.0.0-rc.1",
			routes: map[string]string{"api.github.com/repos/o/r/tags": `[{"name":"v3.0.0-rc.1"}]`},
		},
		{
			name: "gitlab releases", source: "release:gitlab/o/r", stable: "v2.0.0", pre: "v2.1.0-rc0", want: "v2.1.0-rc1",
			routes: map[string]string{"gitlab.com/api/v4/projects/o/r/releases": `[{"tag_name":"v2.1.0-rc1"}]`},
		},
		{
			name: "go module list", source: "go:example.com/m", stable: "v1.2.0", pre: "v1.3.0-beta.1", want: "v1.3.0-rc.1",
			routes: map[string]string{"proxy.golang.org/example.com/m/@v/list": "v1.3.0-rc.1\n"},
		},
		{
			name: "go module pseudo-version", source: "go:mvdan.cc/unparam", pre: pseudo, want: pseudo,
			routes: map[string]string{
				"proxy.golang.org/mvdan.cc/unparam/@v/list": "",
				"proxy.golang.org/mvdan.cc/unparam/@latest": `{"Version":"` + pseudo + `"}`,
			},
		},
	}
	for _, tc := range cases {
		srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, ok := tc.routes[r.Host+r.URL.Path]
			if !ok {
				http.NotFound(w, r)
				return
			}
			fmt.Fprint(w, body)
		}))
		t.Run(tc.name+" refuses a stable row", func(t *testing.T) {
			v := newTestVersionResolver(srv.Client())
			got, err := v.Latest(t.Context(), &Tool{Source: tc.source, Version: tc.stable}, tc.aq)
			if !errors.Is(err, errOnlyPrereleases) {
				t.Errorf("Latest(recorded %q) = %q, %v; want errOnlyPrereleases", tc.stable, got, err)
			}
		})
		t.Run(tc.name+" follows a prerelease row", func(t *testing.T) {
			v := newTestVersionResolver(srv.Client())
			got, err := v.Latest(t.Context(), &Tool{Source: tc.source, Version: tc.pre}, tc.aq)
			if err != nil || got != tc.want {
				t.Errorf("Latest(recorded %q) = %q, %v; want %q", tc.pre, got, err, tc.want)
			}
		})
	}
}

// Two rows sharing a source but on different lines each read their own latest.
func TestVersionCache_KeysThePrereleaseLine(t *testing.T) {
	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `[{"version":"v27.0.0-alpha.0.0.0"},{"version":"v26.13.0"}]`)
	}))
	v := newTestVersionResolver(srv.Client())
	aq := &AquaPackage{Type: aquaTypeHTTP, RepoOwner: "nodejs", RepoName: "node"}
	stable := &Tool{Source: "aqua:nodejs/node", Version: "v26.12.1"}
	alpha := &Tool{Source: "aqua:nodejs/node", Version: "v27.0.0-alpha.0.0.0"}
	for _, tool := range []*Tool{stable, alpha} {
		if _, err := v.Latest(t.Context(), tool, aq); err != nil {
			t.Fatal(err)
		}
	}
	if got := v.Cached(stable, aq); got != "v26.13.0" {
		t.Errorf("Cached(stable row) = %q, want v26.13.0", got)
	}
	if got := v.Cached(alpha, aq); got != "v27.0.0-alpha.0.0.0" {
		t.Errorf("Cached(prerelease row) = %q, want v27.0.0-alpha.0.0.0", got)
	}
}

// A catalog refresh that changes how an aqua package picks its version makes
// the answer chosen under the old definition stale.
func TestVersionCache_KeysTheAquaDefinition(t *testing.T) {
	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `[{"version":"other-2.0.0"},{"version":"cli-1.0.0"},{"version":"cli-0.9.5"}]`)
	}))
	old := AquaPackage{Type: aquaTypeHTTP, VersionPrefix: "cli-"}
	tests := []struct {
		name   string
		edit   func(*AquaPackage)
		latest string // the new definition's answer; empty skips the resolve
	}{
		{"version_prefix", func(a *AquaPackage) { a.VersionPrefix = "other-" }, "other-2.0.0"},
		{"version_filter", func(a *AquaPackage) { a.VersionFilter = `Version != "cli-1.0.0"` }, "cli-0.9.5"},
		{"version_source", func(a *AquaPackage) { a.VersionSource = "github_tag" }, ""},
		{"type", func(a *AquaPackage) { a.Type = "github_release" }, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := newTestVersionResolver(srv.Client())
			tool := &Tool{Source: "aqua:nodejs/node", Version: "cli-0.9.0"}
			before := old
			if got, err := v.Latest(t.Context(), tool, &before); err != nil || got != "cli-1.0.0" {
				t.Fatalf("Latest(old definition) = %q, %v; want cli-1.0.0", got, err)
			}
			after := old
			tc.edit(&after)
			if got := v.Cached(tool, &after); got != "" {
				t.Errorf("Cached(changed %s) = %q, want a miss", tc.name, got)
			}
			if got := v.Cached(tool, &before); got != "cli-1.0.0" {
				t.Errorf("Cached(old definition) = %q, want cli-1.0.0", got)
			}
			if tc.latest == "" {
				return
			}
			if got, err := v.Latest(t.Context(), tool, &after); err != nil || got != tc.latest {
				t.Fatalf("Latest(changed %s) = %q, %v; want %q", tc.name, got, err, tc.latest)
			}
			if got := v.Cached(tool, &after); got != tc.latest {
				t.Errorf("Cached(changed %s) after Latest = %q, want %q", tc.name, got, tc.latest)
			}
		})
	}
}

// A tool with no aqua definition and one whose definition sets none of the
// version fields pick the same way, so they share a cache entry.
func TestVersionCache_NilDefinitionIsTheZeroDefinition(t *testing.T) {
	v := newTestVersionResolver(nil)
	tool := &Tool{Source: "aqua:cli/cli", Version: "v1.0.0"}
	v.cache[toolLatestKey(tool, nil)] = "v2.0.0"
	if got := v.Cached(tool, &AquaPackage{RepoOwner: "cli", RepoName: "cli"}); got != "v2.0.0" {
		t.Errorf("Cached(zero definition) = %q, want v2.0.0", got)
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
	got, err := v.Latest(t.Context(), &Tool{Source: "npm:typescript-language-server"}, nil)
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

// goProxy fakes proxy.golang.org: routes maps a request path to its body,
// every other path answers 404 as the proxy does for a path no module owns
// (https://go.dev/ref/mod#goproxy-protocol). It records the paths asked.
func goProxy(t *testing.T, routes map[string]string) (*versionResolver, *[]string) {
	t.Helper()
	var asked []string
	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path)
		if r.Host != "proxy.golang.org" {
			t.Errorf("request to host %s, want proxy.golang.org", r.Host)
		}
		body, ok := routes[r.URL.Path]
		if !ok {
			http.Error(w, "not found: module: no matching versions for query \"latest\"", http.StatusNotFound)
			return
		}
		fmt.Fprint(w, body)
	}))
	return newTestVersionResolver(srv.Client()), &asked
}

func TestLatestGoModule_ResolvesTheOwningModule(t *testing.T) {
	cases := []struct {
		name, pkg, want string
		routes          map[string]string
	}{
		{
			name: "command inside its module",
			pkg:  "github.com/rhysd/actionlint/cmd/actionlint",
			routes: map[string]string{
				"/github.com/rhysd/actionlint/@v/list":        "v1.7.11\nv1.7.12\n",
				"/github.com/rhysd/actionlint/@v/v1.7.12.mod": "module github.com/rhysd/actionlint\n",
			},
			want: "v1.7.12",
		},
		{
			name: "deep package of golang.org/x/tools",
			pkg:  "golang.org/x/tools/go/analysis/passes/fieldalignment/cmd/fieldalignment",
			routes: map[string]string{
				"/golang.org/x/tools/@v/list":        "v0.44.0\nv0.45.1\nv0.45.0\n",
				"/golang.org/x/tools/@v/v0.45.1.mod": "module golang.org/x/tools\n",
			},
			want: "v0.45.1",
		},
		{
			name: "nested module wins over its parent",
			pkg:  "golang.org/x/tools/gopls",
			routes: map[string]string{
				"/golang.org/x/tools/gopls/@v/list":        "v0.21.0\n",
				"/golang.org/x/tools/gopls/@v/v0.21.0.mod": "module golang.org/x/tools/gopls\n",
				"/golang.org/x/tools/@v/list":              "v0.45.1\n",
			},
			want: "v0.21.0",
		},
		{
			name: "upper-case path is case-escaped",
			pkg:  "github.com/BurntSushi/toml/cmd/tomlv",
			routes: map[string]string{
				"/github.com/!burnt!sushi/toml/@v/list":       "v1.5.0\nv1.6.0\n",
				"/github.com/!burnt!sushi/toml/@v/v1.6.0.mod": "module github.com/BurntSushi/toml\n",
			},
			want: "v1.6.0",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, _ := goProxy(t, tc.routes)
			got, err := v.Latest(t.Context(), &Tool{Source: "go:" + tc.pkg}, nil)
			if err != nil {
				t.Fatalf("Latest(go:%s) = %v", tc.pkg, err)
			}
			if got != tc.want {
				t.Errorf("Latest(go:%s) = %q, want %q", tc.pkg, got, tc.want)
			}
		})
	}
}

// The go command admits +incompatible versions to "latest" only when the
// highest unretracted compatible version's .mod is the synthesized
// "module <path>\n" (cmd/go/internal/modload query.go filterVersions). The
// archiver, blackfriday and docker cases are live proxy data, their answers
// those of `go list -m <module>@latest` (go1.27.3).
func TestLatestGoModule_IncompatibleVersions(t *testing.T) {
	const realMod = "module example.com/m\n\ngo 1.21\n"
	const legacyMod = "module example.com/m\n"
	cases := []struct {
		name, mod, pkg, list, recorded, want string
		routes                               map[string]string
		wantErr                              bool
	}{
		{
			name:   "a real go.mod on the highest compatible version excludes them",
			list:   "v1.4.0\nv2.0.0+incompatible\n",
			routes: map[string]string{"v1.4.0.mod": realMod},
			want:   "v1.4.0",
		},
		{
			name:   "a synthesized go.mod on the highest compatible version admits them",
			list:   "v1.4.0\nv2.0.0+incompatible\n",
			routes: map[string]string{"v1.4.0.mod": legacyMod},
			want:   "v2.0.0+incompatible",
		},
		{
			name:   "only incompatible versions listed",
			list:   "v2.0.0+incompatible\nv2.1.0+incompatible\n",
			routes: map[string]string{"v2.1.0+incompatible.mod": legacyMod},
			want:   "v2.1.0+incompatible",
		},
		{
			name: "mholt/archiver: legacy v1, the list beats a lagging @latest",
			mod:  "github.com/mholt/archiver",
			pkg:  "github.com/mholt/archiver/cmd/arc",
			list: "v1.1.1\nv1.1.2\nv2.0.0+incompatible\nv2.1.0+incompatible\nv3.0.0+incompatible\nv3.0.1+incompatible\nv3.1.0+incompatible\nv3.1.1+incompatible\n",
			routes: map[string]string{
				"v1.1.2.mod":              "module github.com/mholt/archiver\n",
				"v3.1.1+incompatible.mod": "module github.com/mholt/archiver\n",
				"latest":                  `{"Version":"v2.1.0+incompatible"}`,
			},
			want: "v3.1.1+incompatible",
		},
		{
			name:   "russross/blackfriday: v1.6.0 has a go.mod",
			mod:    "github.com/russross/blackfriday",
			pkg:    "github.com/russross/blackfriday",
			list:   "v1.5.1\nv1.5.2\nv1.6.0\nv1.6.0-pre.1\nv2.0.0+incompatible\n",
			routes: map[string]string{"v1.6.0.mod": "module github.com/russross/blackfriday\n\ngo 1.13\n"},
			want:   "v1.6.0",
		},
		{
			name: "docker/docker: a command inside a legacy module skips an incompatible rc",
			mod:  "github.com/docker/docker",
			pkg:  "github.com/docker/docker/cmd/dockerd",
			list: "v1.13.0\nv1.13.1\nv28.5.1+incompatible\nv28.5.2+incompatible\nv28.6.0-rc.1+incompatible\n",
			routes: map[string]string{
				"v1.13.1.mod":              "module github.com/docker/docker\n",
				"v28.5.2+incompatible.mod": "module github.com/docker/docker\n",
			},
			want: "v28.5.2+incompatible",
		},
		{
			name:     "a prerelease row follows an incompatible rc",
			list:     "v1.13.1\nv28.5.2+incompatible\nv28.6.0-rc.1+incompatible\n",
			recorded: "v28.6.0-rc.0+incompatible",
			routes: map[string]string{
				"v1.13.1.mod":              legacyMod,
				"v28.5.2+incompatible.mod": legacyMod,
			},
			want: "v28.6.0-rc.1+incompatible",
		},
		{
			name: "a compatible prerelease with a go.mod still excludes them",
			list: "v1.0.0\nv1.1.0-rc.1\nv2.0.0+incompatible\n",
			routes: map[string]string{
				"v1.0.0.mod":      legacyMod,
				"v1.1.0-rc.1.mod": realMod,
			},
			want: "v1.0.0",
		},
		{
			name: "a retracted compatible version does not decide",
			list: "v1.0.0\nv1.1.0\nv2.0.0+incompatible\n",
			routes: map[string]string{
				"v1.0.0.mod": legacyMod,
				"v1.1.0.mod": realMod + "retract v1.1.0\n",
			},
			want: "v2.0.0+incompatible",
		},
		{
			name:    "the deciding go.mod missing from the proxy is an error",
			list:    "v1.4.0\nv2.0.0+incompatible\n",
			routes:  map[string]string{},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mod, pkg := "example.com/m", "example.com/m"
			if tc.pkg != "" {
				mod, pkg = tc.mod, tc.pkg
			}
			base := "/" + mod + "/@"
			routes := map[string]string{base + "v/list": tc.list}
			for p, body := range tc.routes {
				if p == "latest" {
					routes[base+p] = body
				} else {
					routes[base+"v/"+p] = body
				}
			}
			v, asked := goProxy(t, routes)
			got, err := v.Latest(t.Context(), &Tool{Source: "go:" + pkg, Version: tc.recorded}, nil)
			for i, p := range *asked {
				if slices.Contains((*asked)[:i], p) {
					t.Errorf("asked %s twice", p)
				}
			}
			if tc.wantErr {
				if err == nil {
					t.Errorf("Latest(go:%s) = %q, want an error", pkg, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Latest(go:%s) = %v", pkg, err)
			}
			if got != tc.want {
				t.Errorf("Latest(go:%s) = %q, want %q", pkg, got, tc.want)
			}
		})
	}
}

// The proxy's @latest is the go command's fallback for an empty list, and it
// can lag @v/list (gremlins answered v0.5.1 on @latest with v0.6.0 listed).
func TestLatestGoModule_ListBeatsALaggingLatest(t *testing.T) {
	v, _ := goProxy(t, map[string]string{
		"/github.com/go-gremlins/gremlins/@v/list":       "v0.5.1\nv0.6.0\n",
		"/github.com/go-gremlins/gremlins/@latest":       `{"Version":"v0.5.1"}`,
		"/github.com/go-gremlins/gremlins/@v/v0.6.0.mod": "module github.com/go-gremlins/gremlins\n",
	})
	got, err := v.Latest(t.Context(), &Tool{Source: "go:github.com/go-gremlins/gremlins/cmd/gremlins"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "v0.6.0" {
		t.Errorf("Latest = %q, want v0.6.0", got)
	}
}

// The go command's "latest" is the highest release; a prerelease counts here
// only when the recorded version is one.
func TestLatestGoModule_SkipsPrereleases(t *testing.T) {
	cases := []struct{ name, recorded, want string }{
		{name: "release line", recorded: "v1.1.0", want: "v1.2.0"},
		{name: "prerelease line", recorded: "v1.3.0-beta.1", want: "v1.3.0-rc.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, _ := goProxy(t, map[string]string{
				"/example.com/m/@v/list": "v1.2.0\nv1.3.0-rc.1\n",
			})
			got, err := v.Latest(t.Context(), &Tool{Source: "go:example.com/m", Version: tc.recorded}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("Latest(recorded %q) = %q, want %q", tc.recorded, got, tc.want)
			}
		})
	}
}

// The go command leaves retracted versions out of "latest" and reads the
// retractions from the go.mod of the version "latest" names when nothing is
// retracted: the highest release, else the highest prerelease
// (https://go.dev/ref/mod#go-mod-file-retract).
func TestLatestGoModule_SkipsRetractedVersions(t *testing.T) {
	cases := []struct {
		name, list, recorded, want string
		mods                       map[string]string
		wantErr                    error
	}{
		{
			name: "single version retracted",
			list: "v1.0.0\nv1.1.0\n",
			mods: map[string]string{"v1.1.0": "module example.com/m\nretract v1.1.0\n"},
			want: "v1.0.0",
		},
		{
			name: "range retracted",
			list: "v1.0.0\nv1.1.0\n",
			mods: map[string]string{"v1.1.0": "module example.com/m\nretract [v1.0.5, v1.1.0]\n"},
			want: "v1.0.0",
		},
		{
			name:    "every version retracted",
			list:    "v1.0.0\nv1.1.0\n",
			mods:    map[string]string{"v1.1.0": "module example.com/m\nretract [v1.0.0, v1.1.0]\n"},
			wantErr: errAllRetracted,
		},
		{
			name:     "every version retracted on a prerelease row",
			list:     "v1.0.0\nv1.1.0-rc.1\n",
			recorded: "v1.1.0-beta.1",
			mods:     map[string]string{"v1.0.0": "module example.com/m\nretract [v1.0.0, v1.1.0-rc.1]\n"},
			wantErr:  errAllRetracted,
		},
		{
			name:    "only a prerelease survives on a stable row",
			list:    "v1.0.0\nv1.1.0-rc.1\n",
			mods:    map[string]string{"v1.0.0": "module example.com/m\nretract v1.0.0\n"},
			wantErr: errOnlyPrereleases,
		},
		{
			name:     "a prerelease row reads the retractions of the highest release",
			list:     "v1.0.0\nv1.1.0-rc.1\n",
			recorded: "v1.1.0-beta.1",
			mods: map[string]string{
				"v1.0.0":      "module example.com/m\nretract v1.1.0-rc.1\n",
				"v1.1.0-rc.1": "module example.com/m\n",
			},
			want: "v1.0.0",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			routes := map[string]string{"/example.com/m/@v/list": tc.list}
			for ver, mod := range tc.mods {
				routes["/example.com/m/@v/"+ver+".mod"] = mod
			}
			v, _ := goProxy(t, routes)
			got, err := v.Latest(t.Context(), &Tool{Source: "go:example.com/m", Version: tc.recorded}, nil)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Errorf("Latest = %q, %v; want %v", got, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("Latest = %q, want %q", got, tc.want)
			}
		})
	}
}

// Only "no such module" (404 or 410) moves the walk to a shorter prefix; any
// other answer is an outage, and a shorter prefix would name the wrong module.
func TestLatestGoModule_OtherErrorStopsTheWalk(t *testing.T) {
	var asked []string
	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path)
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	v := newTestVersionResolver(srv.Client())
	_, err := v.Latest(t.Context(), &Tool{Source: "go:example.com/m/cmd/x"}, nil)
	if err == nil {
		t.Fatal("Latest succeeded, want the 403 as an error")
	}
	if len(asked) != 1 || asked[0] != "/example.com/m/cmd/x/@v/list" {
		t.Errorf("asked %q, want only /example.com/m/cmd/x/@v/list", asked)
	}
}

func TestLatestGoModule_NoModuleOwnsThePath(t *testing.T) {
	v, asked := goProxy(t, map[string]string{})
	_, err := v.Latest(t.Context(), &Tool{Source: "go:example.com/a/b"}, nil)
	if err == nil || !strings.Contains(err.Error(), "example.com/a/b") {
		t.Fatalf("Latest = %v, want an error naming example.com/a/b", err)
	}
	want := []string{"/example.com/a/b/@v/list", "/example.com/a/@v/list", "/example.com/@v/list"}
	if !slices.Equal(*asked, want) {
		t.Errorf("asked %q, want %q", *asked, want)
	}
}
