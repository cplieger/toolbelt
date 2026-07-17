package toolbelt

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/cplieger/httpx/v3"
	goversion "github.com/hashicorp/go-version"
	"golang.org/x/mod/module"
)

// versionLookupBudget bounds one latest-version resolution end to end,
// retries included (httpx retries transient failures and honors 429
// Retry-After inside this window).
const versionLookupBudget = 45 * time.Second

// versionResolver finds the latest upstream version for a tool source.
// Results are cached in memory so Inventory can surface "update
// available" without network calls; the cache is refreshed by update
// and reconcile jobs.
type versionResolver struct {
	ghTokenChecked time.Time
	client         *http.Client
	cache          map[string]string // source -> latest version
	// ghToken caches the gh auth token lookup. Successes cache forever;
	// an empty result is retried after ghTokenRetry so a forge login
	// performed after boot is picked up.
	ghToken   string
	mu        sync.Mutex
	ghTokenMu sync.Mutex
}

// ghTokenRetry is how long an empty gh-token probe result is trusted.
const ghTokenRetry = time.Minute

func newVersionResolver(client *http.Client) *versionResolver {
	return &versionResolver{client: client, cache: map[string]string{}}
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
	if !validVersionString(latest) {
		return "", fmt.Errorf("upstream version %q contains illegal characters", latest)
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
	default:
		return "", fmt.Errorf("no version source for %q", source)
	}
}

// latestAqua resolves a GitHub-hosted package's latest version: the
// releases/latest endpoint for github_release types, or the tag list
// (filtered by version_filter/version_prefix) when the definition asks
// for github_tag versioning.
func (v *versionResolver) latestAqua(ctx context.Context, ref string, aq *AquaPackage) (string, error) {
	owner, repo, ok := strings.Cut(ref, "/")
	if !ok {
		return "", fmt.Errorf("bad aqua ref %q", ref)
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

func (v *versionResolver) latestGoModule(ctx context.Context, modPath string) (string, error) {
	// The module proxy requires case-escaped paths; x/mod validates the
	// path shape as a side effect.
	esc, err := module.EscapePath(modPath)
	if err != nil {
		return "", fmt.Errorf("invalid module path %q: %w", modPath, err)
	}
	var doc struct {
		Version string `json:"Version"`
	}
	if err := v.getJSON(ctx, "https://proxy.golang.org/"+esc+"/@latest", &doc); err != nil {
		return "", err
	}
	if doc.Version == "" {
		return "", fmt.Errorf("go module %q has no latest version", modPath)
	}
	return doc.Version, nil
}

// getJSON fetches a URL through httpx (bounded body, transient-error
// backoff, 429 Retry-After honored, redaction-safe errors) and decodes
// the JSON body. GitHub API calls attach a bearer token when one is
// available (gh auth token) to dodge the 60/hour anonymous rate limit.
func (v *versionResolver) getJSON(ctx context.Context, rawURL string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, versionLookupBudget)
	defer cancel()
	opts := []httpx.GetOption{
		httpx.WithMaxAttempts(3),
		httpx.WithMaxBodyBytes(4 << 20),
	}
	if strings.HasPrefix(rawURL, "https://api.github.com/") {
		if tok := v.githubToken(); tok != "" {
			opts = append(opts, httpx.WithHeaders(func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer "+tok)
			}))
		}
	}
	body, err := httpx.GetBytes(ctx, v.client, rawURL, opts...)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

// githubToken returns a GitHub API token when one is discoverable: the
// gh CLI's stored token (a forge login flow provisions it). Failure is
// fine — calls proceed anonymously and the probe retries later.
func (v *versionResolver) githubToken() string {
	v.ghTokenMu.Lock()
	defer v.ghTokenMu.Unlock()
	if v.ghToken != "" || time.Since(v.ghTokenChecked) < ghTokenRetry {
		return v.ghToken
	}
	v.ghTokenChecked = time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "gh", "auth", "token").Output()
	if err == nil {
		v.ghToken = strings.TrimSpace(string(out))
	}
	return v.ghToken
}

// validVersionString allows only the characters real upstream version
// tags use. The version lands in URLs, file paths, and (for manual
// installs) a shell environment variable, so anything exotic is
// rejected outright.
func validVersionString(s string) bool {
	if s == "" || len(s) > 100 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_' || r == '+':
		default:
			return false
		}
	}
	return true
}
