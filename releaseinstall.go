package toolbelt

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"runtime"
	"strings"

	"github.com/cplieger/httpx/v5"
)

// The release source's install path. Selection is release.go's job;
// this file turns a chosen asset into the same InstallSpec the aqua
// path consumes, so download/verify/extract/link is the code that
// already installs 648 tools rather than a second implementation.
//
// Source form: "release:<host>/<owner>/<repo>". The host is part of the
// source rather than inferred, so a source string says where it points
// without a lookup table.

// releaseHostGitHub and releaseHostGitLab are the forges a release source
// can name.
const (
	releaseHostGitHub = "github"
	releaseHostGitLab = "gitlab"
)

// releaseRef is a parsed release source.
type releaseRef struct {
	Host  string
	Owner string
	Repo  string
}

// parseReleaseRef splits "github/cli/cli" into its parts.
//
// The host is required. An earlier shape defaulted it to github, which
// reads as convenience and is a trap: a gitlab source that lost its host
// would resolve against a github repository of the same name, and the
// failure would be a wrong install rather than an error.
func parseReleaseRef(ref string) (releaseRef, error) {
	parts := strings.Split(ref, "/")
	if len(parts) != 3 {
		return releaseRef{}, fmt.Errorf("release source must be release:<github|gitlab>/<owner>/<repo>, got %q", ref)
	}
	host, owner, repo := parts[0], parts[1], parts[2]
	if host != releaseHostGitHub && host != releaseHostGitLab {
		return releaseRef{}, fmt.Errorf("unknown release host %q (want %s or %s)", host, releaseHostGitHub, releaseHostGitLab)
	}
	if owner == "" || repo == "" {
		return releaseRef{}, fmt.Errorf("release source %q names no owner or repository", ref)
	}
	return releaseRef{Host: host, Owner: owner, Repo: repo}, nil
}

// installRelease installs one tool from a forge release.
//
// Lists the release's assets, asks the matcher which one to take, then
// hands the result to the aqua path's machinery as an InstallSpec —
// nothing about downloading, verifying or extracting is reimplemented.
func (in *installer) installRelease(ctx context.Context, name, ref, version string, hints *ReleaseHints) (bins []string, checksum string, err error) {
	rr, err := parseReleaseRef(ref)
	if err != nil {
		return nil, "", err
	}
	assets, err := in.listReleaseAssets(ctx, rr, version)
	if err != nil {
		return nil, "", err
	}
	spec, err := in.releaseSpec(rr, name, version, assets, hints)
	if err != nil {
		return nil, "", err
	}
	return in.installFromSpec(ctx, name, version, spec)
}

// releaseSpec resolves the asset and builds the InstallSpec for it.
func (in *installer) releaseSpec(rr releaseRef, name, version string, assets []string, hints *ReleaseHints) (*InstallSpec, error) {
	choice, err := chooseReleaseAssetWithHints(assets, name, runtime.GOARCH, hints)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", name, version, err)
	}
	spec := &InstallSpec{
		URL:    releaseDownloadURL(rr, version, choice.Asset),
		Format: releaseFormat(choice.Asset),
		Files:  releaseFiles(name, hints),
		// Nothing declared where the binary lives, so the Files entry is
		// this source's best guess and a miss is searched for rather than
		// failed. See InstallSpec.SearchFiles.
		SearchFiles: true,
	}
	if choice.ChecksumAsset != "" {
		spec.ChecksumURL = releaseDownloadURL(rr, version, choice.ChecksumAsset)
		spec.ChecksumAlg = algSHA256
		// NOT ChecksumDeclared: that flag means "upstream promises a
		// checksum" and its contract is to refuse the install if one
		// cannot be obtained. Here nobody promised anything — the digest
		// was DISCOVERED from the asset list — so setting it would turn
		// every upstream that drops its checksums file into a hard
		// failure for a tool that worked yesterday.
	}
	return spec, nil
}

// releaseDownloadURL builds the asset download URL for a forge.
func releaseDownloadURL(rr releaseRef, version, asset string) string {
	switch rr.Host {
	case releaseHostGitLab:
		// GitLab serves release assets from the project's uploads path.
		return fmt.Sprintf("https://gitlab.com/%s/%s/-/releases/%s/downloads/%s",
			url.PathEscape(rr.Owner), url.PathEscape(rr.Repo), url.PathEscape(version), asset)
	default:
		return fmt.Sprintf("https://github.com/%s/%s/releases/download/%s/%s",
			url.PathEscape(rr.Owner), url.PathEscape(rr.Repo), url.PathEscape(version), asset)
	}
}

// releaseFormat maps an asset name onto the extractor's format vocabulary.
func releaseFormat(asset string) string {
	lower := strings.ToLower(asset)
	switch {
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		return "tar.gz"
	case strings.HasSuffix(lower, ".tar.xz"), strings.HasSuffix(lower, ".txz"):
		return "tar.xz"
	case strings.HasSuffix(lower, ".tar.bz2"), strings.HasSuffix(lower, ".tbz2"):
		return "tar.bz2"
	case strings.HasSuffix(lower, ".tar.zst"):
		return "tar.zst"
	case strings.HasSuffix(lower, ".tar"):
		return "tar"
	case strings.HasSuffix(lower, ".zip"):
		return "zip"
	case strings.HasSuffix(lower, ".gz"):
		return "gz"
	case strings.HasSuffix(lower, ".xz"):
		return "xz"
	default:
		return formatRaw
	}
}

// releaseFiles decides which files to link into bin.
//
// A release ships no manifest of its contents, so the default is the
// tool's own name (right for 112 of 158 entries): a bare binary is
// renamed to it, an archive searched for it. ReleaseHints override both
// where a repository is known to differ.
func releaseFiles(name string, hints *ReleaseHints) []AquaFile {
	if hints == nil {
		return []AquaFile{{Name: name}}
	}
	// What lands in bin/ is upstream's binary set when the registry states
	// one — the shell calls what the binary is actually named: `qdns` is
	// a registry label for a binary named `q`.
	publish := hints.Bins
	if len(publish) == 0 {
		publish = []string{name}
	}
	out := make([]AquaFile, 0, len(publish))
	for _, b := range publish {
		f := AquaFile{Name: b}
		// Src is where to find it inside the artifact (Bin the file,
		// BinPath the directory), and both describe the TOOL's own
		// executable, never a sibling binary that travels with it.
		inner := b
		if b == name && hints.Bin != "" {
			inner = hints.Bin
		}
		if hints.BinPath != "" {
			f.Src = path.Join(hints.BinPath, inner)
		} else if inner != b {
			f.Src = inner
		}
		out = append(out, f)
	}
	return out
}

// listReleaseAssets returns the asset file names of one release.
func (in *installer) listReleaseAssets(ctx context.Context, rr releaseRef, version string) ([]string, error) {
	switch rr.Host {
	case releaseHostGitLab:
		return in.listGitLabAssets(ctx, rr, version)
	default:
		return in.listGitHubAssets(ctx, rr, version)
	}
}

func (in *installer) listGitHubAssets(ctx context.Context, rr releaseRef, version string) ([]string, error) {
	api := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/tags/%s",
		url.PathEscape(rr.Owner), url.PathEscape(rr.Repo), url.PathEscape(version))
	var doc struct {
		Assets []struct {
			Name string `json:"name"`
		} `json:"assets"`
	}
	if err := in.getJSON(ctx, api, &doc); err != nil {
		return nil, fmt.Errorf("list assets for %s/%s %s: %w", rr.Owner, rr.Repo, version, err)
	}
	names := make([]string, 0, len(doc.Assets))
	for _, a := range doc.Assets {
		if a.Name != "" {
			names = append(names, a.Name)
		}
	}
	return names, nil
}

func (in *installer) listGitLabAssets(ctx context.Context, rr releaseRef, version string) ([]string, error) {
	project := url.PathEscape(rr.Owner + "/" + rr.Repo)
	api := fmt.Sprintf("https://gitlab.com/api/v4/projects/%s/releases/%s", project, url.PathEscape(version))
	var doc struct {
		Assets struct {
			Links []struct {
				Name string `json:"name"`
			} `json:"links"`
		} `json:"assets"`
	}
	if err := in.getJSON(ctx, api, &doc); err != nil {
		return nil, fmt.Errorf("list assets for %s/%s %s: %w", rr.Owner, rr.Repo, version, err)
	}
	names := make([]string, 0, len(doc.Assets.Links))
	for _, l := range doc.Assets.Links {
		if l.Name != "" {
			names = append(names, l.Name)
		}
	}
	return names, nil
}

// getJSON fetches and decodes a small JSON document through the
// installer's own client, so a release listing inherits the same
// SSRF-guarded transport and retry policy every other fetch here uses.
// GitHub API calls carry the shared token when one is available: the
// anonymous ceiling is 60 requests an hour for the whole process and a
// release install spends two of them.
func (in *installer) getJSON(ctx context.Context, rawURL string, out any) error {
	opts := append([]httpx.GetOption{
		httpx.WithMaxAttempts(3),
		httpx.WithMaxBodyBytes(releaseListingCap),
	}, githubAuth(rawURL, in.tokens)...)
	body, err := httpx.GetBytes(ctx, in.client, rawURL, opts...)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

// releaseListingCap bounds a release listing. A release with hundreds of
// assets is a few tens of kilobytes of JSON; this is a runaway guard.
const releaseListingCap = 4 << 20
