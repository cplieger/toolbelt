package toolbelt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cplieger/httpx/v5"
	goversion "github.com/hashicorp/go-version"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// versionLookupBudget bounds one upstream request of a latest-version
// resolution, retries included (httpx retries transient failures and honors
// 429 Retry-After inside this window).
const versionLookupBudget = 45 * time.Second

// versionResponseCap bounds one version-lookup response body.
const versionResponseCap = 4 << 20

// versionResolver finds the latest upstream version for a tool source.
// Results are cached in memory so Inventory can surface "update
// available" without network calls; the cache is refreshed by update
// and reconcile jobs.
type versionResolver struct {
	client *http.Client
	cache  map[string]string // source -> latest version
	// aptIdx guarantees a package index exists before apt-cache is asked
	// anything. Both consumer images ship with /var/lib/apt/lists empty,
	// and apt-cache answers "no Candidate line" rather than erroring on a
	// missing index, so without this a first-ever apt add fails while
	// looking like a broken package name.
	aptIdx *aptIndex

	mu sync.Mutex
}

func newVersionResolver(client *http.Client, aptIdx *aptIndex) *versionResolver {
	return &versionResolver{client: client, cache: map[string]string{}, aptIdx: aptIdx}
}

// Cached returns the cached latest version for a source, if any.
func (v *versionResolver) Cached(source string) string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.cache[source]
}

// Latest resolves the newest upstream version for the tool and caches
// it. aq carries the catalog's aqua definition when the source is
// aqua: (for version_source/filter/prefix semantics).
func (v *versionResolver) Latest(ctx context.Context, source string, aq *AquaPackage) (string, error) {
	latest, err := v.resolve(ctx, source, aq)
	if err != nil {
		return "", err
	}
	if !validVersion(source, latest) {
		return "", fmt.Errorf("upstream %s: %v", source, versionRejected(source, latest))
	}
	v.mu.Lock()
	v.cache[source] = latest
	v.mu.Unlock()
	return latest, nil
}

func (v *versionResolver) resolve(ctx context.Context, source string, aq *AquaPackage) (string, error) {
	kind, ref, _ := strings.Cut(source, ":")
	switch kind {
	case SourceAqua:
		return v.latestAqua(ctx, ref, aq)
	case SourceNpm:
		return v.latestNpm(ctx, ref)
	case SourcePip:
		return v.latestPyPI(ctx, ref)
	case SourceCargo:
		return v.latestCrate(ctx, ref)
	case SourceGo:
		return v.latestGoModule(ctx, ref)
	case SourceRelease:
		return v.latestRelease(ctx, ref)
	case SourceApt:
		return v.latestApt(ctx, ref)
	default:
		return "", fmt.Errorf("no version source for %q", source)
	}
}

// latestRelease resolves the newest release tag of a forge repository.
//
// A release-backed tool's version IS the tag, so this reuses the same
// GitHub paths the aqua source already uses. The registry's version_prefix
// hint is not applied here: the tag is what the download URL needs, and
// stripping a prefix would produce a version that names no release.
func (v *versionResolver) latestRelease(ctx context.Context, ref string) (string, error) {
	rr, err := parseReleaseRef(ref)
	if err != nil {
		return "", err
	}
	switch rr.Host {
	case releaseHostGitLab:
		return v.latestGitLabRelease(ctx, rr)
	default:
		return v.latestGitHubRelease(ctx, rr)
	}
}

func (v *versionResolver) latestGitHubRelease(ctx context.Context, rr releaseRef) (string, error) {
	var rel struct {
		TagName string `json:"tag_name"`
	}
	api := "https://api.github.com/repos/" + url.PathEscape(rr.Owner) + "/" + url.PathEscape(rr.Repo) + "/releases/latest"
	if err := v.getJSON(ctx, api, &rel); err != nil {
		return "", err
	}
	if rel.TagName == "" {
		return "", fmt.Errorf("%s/%s has no latest release", rr.Owner, rr.Repo)
	}
	return rel.TagName, nil
}

func (v *versionResolver) latestGitLabRelease(ctx context.Context, rr releaseRef) (string, error) {
	var rels []struct {
		TagName string `json:"tag_name"`
	}
	project := url.PathEscape(rr.Owner + "/" + rr.Repo)
	api := "https://gitlab.com/api/v4/projects/" + project + "/releases?per_page=1"
	if err := v.getJSON(ctx, api, &rels); err != nil {
		return "", err
	}
	if len(rels) == 0 || rels[0].TagName == "" {
		return "", fmt.Errorf("%s/%s has no releases", rr.Owner, rr.Repo)
	}
	return rels[0].TagName, nil
}

// latestApt reports the version apt would install: the distro's current
// candidate. An apt package has no upstream version of its own to track,
// so this is both the resolved version and the update signal, and it can
// go DOWN when Debian reverts a package.
func (v *versionResolver) latestApt(ctx context.Context, pkg string) (string, error) {
	if !AptAvailable() {
		return "", ErrAptUnavailable
	}
	return aptPolicyCandidate(ctx, v.aptIdx, pkg)
}

// latestAqua resolves a package's latest version: the runtime's own
// release index when it publishes one; the tag list (filtered by
// version_filter/version_prefix) for github_tag versioning and for http
// and github_content types; else the GitHub releases/latest endpoint.
func (v *versionResolver) latestAqua(ctx context.Context, ref string, aq *AquaPackage) (string, error) {
	owner, repo, ok := strings.Cut(ref, "/")
	if !ok {
		return "", fmt.Errorf("bad aqua ref %q", ref)
	}
	if feed, ok := runtimeVersionFeeds[ref]; ok {
		return v.latestFromFeed(ctx, feed, aq)
	}
	if aq != nil && (aq.VersionSource == "github_tag" || aq.Type == aquaTypeHTTP || aq.Type == "github_content") {
		return v.latestGitHubTag(ctx, owner, repo, aq)
	}
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := v.getJSON(ctx, "https://api.github.com/repos/"+owner+"/"+repo+"/releases/latest", &rel); err != nil {
		return "", err
	}
	if rel.TagName == "" {
		return "", fmt.Errorf("no releases for %s", ref)
	}
	if aq != nil && !evalVersionFilter(aq.VersionFilter, rel.TagName, aq.VersionPrefix) {
		// Latest release fails the filter (e.g. a "latest"-named tag);
		// fall back to scanning the tag list.
		return v.latestGitHubTag(ctx, owner, repo, aq)
	}
	return rel.TagName, nil
}

// runtimeVersionFeeds maps an aqua ref to the project's first-party release
// index, which costs no GitHub API quota (a tag walk of nodejs/node is ten
// requests). A feed failure is not retried as a tag walk, which would spend
// the quota the feed exists to avoid.
var runtimeVersionFeeds = map[string]string{
	"nodejs/node": "https://nodejs.org/dist/index.json",
	"golang/go":   "https://go.dev/dl/?mode=json",
}

func (v *versionResolver) latestFromFeed(ctx context.Context, feedURL string, aq *AquaPackage) (string, error) {
	prefix, filter := "", ""
	if aq != nil {
		prefix, filter = aq.VersionPrefix, aq.VersionFilter
	}
	var releases []struct {
		Version string `json:"version"`
	}
	if err := v.getJSON(ctx, feedURL, &releases); err != nil {
		return "", err
	}
	var candidates []string
	for _, r := range releases {
		if r.Version != "" && tagPasses(r.Version, prefix, filter) {
			candidates = append(candidates, r.Version)
		}
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("no version in %s passes the version filter", feedURL)
	}
	return maxVersionTag(candidates, prefix), nil
}

// tagPageCap bounds the GitHub tag pagination walk. golang/go needs
// ~6 pages before go1* tags appear; 20 covers pathological repos while
// keeping the worst-case API cost bounded.
const tagPageCap = 20

// latestGitHubTag returns the newest repo tag passing the package's
// version_filter and version_prefix. The GitHub tags endpoint has NO
// documented ordering (golang/go's first page is 2012-era weekly.*
// tags), so — like aqua's own version getter — this paginates,
// collects every filter-passing candidate, and picks the maximum by
// version comparison, never trusting response order.
func (v *versionResolver) latestGitHubTag(ctx context.Context, owner, repo string, aq *AquaPackage) (string, error) {
	prefix := ""
	filter := ""
	if aq != nil {
		prefix = aq.VersionPrefix
		filter = aq.VersionFilter
	}
	var candidates []string
	for page := 1; page <= tagPageCap; page++ {
		tagURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/tags?per_page=100&page=%d", owner, repo, page)
		var tags []struct {
			Name string `json:"name"`
		}
		if err := v.getJSON(ctx, tagURL, &tags); err != nil {
			return "", err
		}
		for _, t := range tags {
			if tagPasses(t.Name, prefix, filter) {
				candidates = append(candidates, t.Name)
			}
		}
		if len(tags) < 100 {
			break
		}
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("no tag of %s/%s passes the version filter", owner, repo)
	}
	return maxVersionTag(candidates, prefix), nil
}

// tagPasses reports whether a tag satisfies the package's version prefix
// and version_filter.
func tagPasses(name, prefix, filter string) bool {
	if prefix != "" && !strings.HasPrefix(name, prefix) {
		return false
	}
	return evalVersionFilter(filter, name, prefix)
}

// maxVersionTag picks the highest candidate by go-version comparison
// (aqua's comparator), falling back to lexicographic order for tags
// that don't parse as versions.
func maxVersionTag(candidates []string, prefix string) string {
	best := candidates[0]
	bestV := parseTagVersion(best, prefix)
	for _, c := range candidates[1:] {
		cv := parseTagVersion(c, prefix)
		switch {
		case cv != nil && bestV != nil:
			if cv.GreaterThan(bestV) {
				best, bestV = c, cv
			}
		case cv != nil && bestV == nil:
			best, bestV = c, cv
		case cv == nil && bestV == nil:
			if c > best {
				best = c
			}
		}
	}
	return best
}

func parseTagVersion(tag, prefix string) *goversion.Version {
	s := strings.TrimPrefix(strings.TrimPrefix(tag, prefix), "v")
	if ver, err := goversion.NewVersion(s); err == nil {
		return ver
	}
	// Tags like "go1.24.0" or "jq-1.8.2" carry a non-numeric prefix the
	// definition doesn't declare (the version_filter does the matching
	// instead). Parse from the first digit so version comparison still
	// works — a lexicographic fallback would rank go1.9 above go1.24.
	if i := strings.IndexFunc(s, func(r rune) bool { return r >= '0' && r <= '9' }); i > 0 {
		if ver, err := goversion.NewVersion(s[i:]); err == nil {
			return ver
		}
	}
	return nil
}

func (v *versionResolver) latestNpm(ctx context.Context, pkg string) (string, error) {
	// The dist-tag endpoint returns just the tagged version manifest.
	// Never fetch the full packument (/{pkg}): it carries every version
	// ever published and blows the response-size cap on big packages
	// (typescript's is >4 MiB — found enabling the seed template).
	var doc struct {
		Version string `json:"version"`
	}
	if err := v.getJSON(ctx, "https://registry.npmjs.org/"+url.PathEscape(pkg)+"/latest", &doc); err != nil {
		return "", err
	}
	if doc.Version == "" {
		return "", fmt.Errorf("npm package %q has no latest version", pkg)
	}
	return doc.Version, nil
}

func (v *versionResolver) latestPyPI(ctx context.Context, pkg string) (string, error) {
	var doc struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
	}
	if err := v.getJSON(ctx, "https://pypi.org/pypi/"+url.PathEscape(pkg)+"/json", &doc); err != nil {
		return "", err
	}
	if doc.Info.Version == "" {
		return "", fmt.Errorf("pypi package %q has no version", pkg)
	}
	return doc.Info.Version, nil
}

func (v *versionResolver) latestCrate(ctx context.Context, name string) (string, error) {
	var doc struct {
		Crate struct {
			MaxStable string `json:"max_stable_version"`
			Newest    string `json:"newest_version"`
		} `json:"crate"`
	}
	if err := v.getJSON(ctx, "https://crates.io/api/v1/crates/"+url.PathEscape(name), &doc); err != nil {
		return "", err
	}
	if doc.Crate.MaxStable != "" {
		return doc.Crate.MaxStable, nil
	}
	if doc.Crate.Newest != "" {
		return doc.Crate.Newest, nil
	}
	return "", fmt.Errorf("crate %q has no versions", name)
}

// latestGoModule resolves a go: package path to the latest version of the
// module that owns it, as the go command does: the longest path prefix the
// proxy knows as a module, read from its version list.
func (v *versionResolver) latestGoModule(ctx context.Context, pkgPath string) (string, error) {
	if err := module.CheckImportPath(pkgPath); err != nil {
		return "", fmt.Errorf("invalid go package path %q: %w", pkgPath, err)
	}
	for _, mod := range goModulePrefixes(pkgPath) {
		ver, found, err := v.latestModuleVersion(ctx, mod)
		if err != nil {
			return "", err
		}
		if found {
			return ver, nil
		}
	}
	return "", fmt.Errorf("no module on the Go module proxy provides package %q", pkgPath)
}

// goModulePrefixes lists the module paths that could own pkgPath, longest
// first, so a nested module wins over its parent.
func goModulePrefixes(pkgPath string) []string {
	var out []string
	for p := pkgPath; p != "." && p != "/"; p = path.Dir(p) {
		if module.CheckPath(p) == nil {
			out = append(out, p)
		}
	}
	return out
}

// latestModuleVersion reads one module's latest version from the proxy;
// found is false when the proxy has no such module. The list is read rather
// than @latest because @latest is the go command's fallback for an empty
// list and can lag it (https://go.dev/ref/mod#goproxy-protocol).
func (v *versionResolver) latestModuleVersion(ctx context.Context, modPath string) (version string, found bool, err error) {
	esc, err := module.EscapePath(modPath)
	if err != nil {
		return "", false, fmt.Errorf("invalid module path %q: %w", modPath, err)
	}
	base := "https://proxy.golang.org/" + esc + "/@"
	body, err := v.getBytes(ctx, base+"v/list")
	if isNotFound(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	listed := strings.Fields(string(body))
	pick := highestModuleVersion(listed)
	if pick == "" {
		var doc struct {
			Version string `json:"Version"`
		}
		lerr := v.getJSON(ctx, base+"latest", &doc)
		if isNotFound(lerr) {
			return "", false, nil
		}
		if lerr != nil {
			return "", false, lerr
		}
		if doc.Version == "" {
			return "", false, fmt.Errorf("go module %q has no latest version", modPath)
		}
		return doc.Version, true, nil
	}
	retracted, err := v.moduleRetractions(ctx, base, pick)
	if err != nil {
		return "", false, err
	}
	kept := slices.DeleteFunc(slices.Clone(listed), func(ver string) bool {
		return slices.ContainsFunc(retracted, func(r modfile.VersionInterval) bool {
			return semver.Compare(r.Low, ver) <= 0 && semver.Compare(ver, r.High) <= 0
		})
	})
	if p := highestModuleVersion(kept); p != "" {
		pick = p
	}
	return pick, true, nil
}

// moduleRetractions reads the retract directives of the module's go.mod at
// version, which the go command applies to every listed version
// (https://go.dev/ref/mod#go-mod-file-retract).
func (v *versionResolver) moduleRetractions(ctx context.Context, base, version string) ([]modfile.VersionInterval, error) {
	escVer, err := module.EscapeVersion(version)
	if err != nil {
		return nil, fmt.Errorf("invalid module version %q: %w", version, err)
	}
	body, err := v.getBytes(ctx, base+"v/"+escVer+".mod")
	if isNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	f, err := modfile.ParseLax("go.mod", body, nil)
	if err != nil {
		return nil, fmt.Errorf("go.mod at %s: %w", version, err)
	}
	out := make([]modfile.VersionInterval, 0, len(f.Retract))
	for _, r := range f.Retract {
		out = append(out, r.VersionInterval)
	}
	return out, nil
}

// highestModuleVersion picks the go command's "latest" from a version list:
// canonical semver only, +incompatible versions only when nothing else is
// listed, the highest release, else the highest prerelease. Empty means the
// list holds no usable version.
func highestModuleVersion(listed []string) string {
	var compatible, incompatible []string
	for _, ver := range listed {
		switch canon := semver.Canonical(ver); ver {
		case canon:
			compatible = append(compatible, ver)
		case canon + "+incompatible":
			incompatible = append(incompatible, ver)
		}
	}
	candidates := compatible
	if len(candidates) == 0 {
		candidates = incompatible
	}
	best, bestPre := "", ""
	for _, ver := range candidates {
		if semver.Prerelease(ver) != "" {
			if bestPre == "" || semver.Compare(ver, bestPre) > 0 {
				bestPre = ver
			}
		} else if best == "" || semver.Compare(ver, best) > 0 {
			best = ver
		}
	}
	if best == "" {
		return bestPre
	}
	return best
}

// isNotFound reports whether err is the proxy saying it has no such module
// or version: 404 or 410, per https://go.dev/ref/mod#goproxy-protocol.
func isNotFound(err error) bool {
	se, ok := errors.AsType[*httpx.StatusError](err)
	return ok && (se.Code == http.StatusNotFound || se.Code == http.StatusGone)
}

func (v *versionResolver) getJSON(ctx context.Context, rawURL string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, versionLookupBudget)
	defer cancel()
	return fetchJSON(ctx, v.client, rawURL, versionResponseCap, out)
}

func (v *versionResolver) getBytes(ctx context.Context, rawURL string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, versionLookupBudget)
	defer cancel()
	return httpx.GetBytes(ctx, v.client, rawURL,
		httpx.WithMaxAttempts(3),
		httpx.WithMaxBodyBytes(versionResponseCap),
	)
}

func fetchJSON(ctx context.Context, client *http.Client, rawURL string, maxBytes int64, out any) error {
	body, err := httpx.GetBytes(ctx, client, rawURL,
		httpx.WithMaxAttempts(3),
		httpx.WithMaxBodyBytes(maxBytes),
	)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}
