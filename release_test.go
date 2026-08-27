package toolbelt

import (
	"bufio"
	"cmp"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

// fixtureAssets reads one testdata/release-assets/<tool>.txt: leading
// "# " lines are provenance, the rest are asset names as the forge
// reported them.
func fixtureAssets(t *testing.T, path string) (repo string, assets []string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if r, ok := strings.CutPrefix(line, "# repo "); ok {
			repo = r
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		assets = append(assets, line)
	}
	return repo, assets
}

// TestChooseReleaseAsset_OverTheRealCorpus is the ship requirement for the
// matcher: every repository the release source has to serve, with the
// asset list its latest release actually publishes, on both
// architectures.
//
// It exists because the selection ORDER cannot be reasoned about from
// examples. Ordering architecture before the single-candidate rule looked
// obviously right and lost 19 repositories on amd64, which only a run over
// the whole population showed. The corpus is a snapshot, so a repository
// that stops resolving is a finding to read rather than a failure to
// silence: raise it here with its asset list.
func TestChooseReleaseAsset_OverTheRealCorpus(t *testing.T) {
	dir := filepath.Join("testdata", "release-assets")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 100 {
		t.Fatalf("only %d fixtures; the corpus is the point of this test", len(entries))
	}

	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			var resolved, unresolved []string
			for _, de := range entries {
				if de.IsDir() || !strings.HasSuffix(de.Name(), ".txt") {
					continue
				}
				tool := strings.TrimSuffix(de.Name(), ".txt")
				_, assets := fixtureAssets(t, filepath.Join(dir, de.Name()))
				if len(assets) == 0 {
					continue // no release published; nothing to choose from
				}
				choice, err := chooseReleaseAsset(assets, tool, arch)
				if err != nil {
					unresolved = append(unresolved, tool)
					continue
				}
				resolved = append(resolved, tool)
				// Whatever it picked must be something it would agree to
				// install, or the matcher contradicts its own first rule.
				if !releaseInstallableShape(choice.Asset) {
					t.Errorf("%s: chose %q, which is not an installable shape", tool, choice.Asset)
				}
				if releaseMovingName(choice.Asset) {
					t.Errorf("%s: chose %q, whose bytes move under a fixed name", tool, choice.Asset)
				}
				if hasAnyToken(choice.Asset, releaseForeignOS) {
					t.Errorf("%s: chose %q, which names another OS", tool, choice.Asset)
				}
				if hasAnyToken(choice.Asset, releaseForeignArch[arch]) {
					t.Errorf("%s: chose %q on %s, which names another architecture", tool, choice.Asset, arch)
				}
			}
			sort.Strings(unresolved)
			t.Logf("linux/%s: %d resolved, %d unresolved: %s",
				arch, len(resolved), len(unresolved), strings.Join(unresolved, " "))
			// A floor rather than an exact count: upstreams re-shape their
			// releases and the corpus is a snapshot. Well below what is
			// measured today, high enough that a broken rule cannot pass.
			const floor = 100
			if len(resolved) < floor {
				t.Errorf("resolved only %d of %d on linux/%s (< %d)", len(resolved), len(entries), arch, floor)
			}
		})
	}
}

// TestChooseReleaseAsset_UntaggedBinaryStaysEligible is the regression
// test for the ordering. A release can ship one bare linux binary with no
// OS or architecture token in its name, so the OS and architecture rules
// have nothing to match on it: they must let an untagged name THROUGH
// rather than requiring a positive match, or the only thing the release
// ships is rejected.
//
// The first draft protected this case by short-circuiting on a single
// remaining candidate instead. That is the wrong instrument, and the
// corpus said so: a lone candidate skipped the architecture test, so
// certstrap, hledger and janet, which publish amd64 only, installed their
// amd64 asset on arm64.
//
// The fixture deliberately holds no linux-TAGGED sibling. An earlier
// version listed `yt-dlp_linux.zip` beside the bare binary while claiming
// to test a release that ships only the latter, and the OS preference in
// releasePreferNativeOS then decided the case — correctly, but for a
// reason that left this property unmeasured. That preference has its own
// test; this one isolates eligibility.
func TestChooseReleaseAsset_UntaggedBinaryStaysEligible(t *testing.T) {
	assets := []string{
		"SHA2-256SUMS", "SHA2-256SUMS.sig", "SHA2-512SUMS",
		"yt-dlp", "yt-dlp.exe", "yt-dlp_macos",
	}
	for _, arch := range []string{"amd64", "arm64"} {
		got, err := chooseReleaseAsset(assets, "yt-dlp", arch)
		if err != nil {
			t.Fatalf("linux/%s: %v", arch, err)
		}
		if got.Asset != "yt-dlp" {
			t.Errorf("linux/%s: chose %q, want the bare linux binary %q", arch, got.Asset, "yt-dlp")
		}
	}

	// The other half of the same rule: an asset that names an architecture
	// EXPLICITLY must still be refused for the other one, even when it is
	// the only linux asset in the release.
	amd64Only := []string{"certstrap-darwin-amd64", "certstrap-linux-amd64", "certstrap-windows-amd64"}
	if got, err := chooseReleaseAsset(amd64Only, "certstrap", "amd64"); err != nil || got.Asset != "certstrap-linux-amd64" {
		t.Errorf("amd64: got %q, %v; want certstrap-linux-amd64", got.Asset, err)
	}
	if _, err := chooseReleaseAsset(amd64Only, "certstrap", "arm64"); err == nil {
		t.Error("an amd64-only release resolved on arm64")
	}
}

// TestReleaseInstallableShape_VersionDotsAreNotAnExtension covers a defect
// the corpus found in this matcher's first draft. mint publishes
// `mint-0.29.0-linux-x86_64`, and path.Ext reports its last dot-suffix as
// ".0-linux-x86_64", so testing for "no extension" that way made a bare
// binary read as metadata and refused the only linux asset in the release.
func TestReleaseInstallableShape_VersionDotsAreNotAnExtension(t *testing.T) {
	bare := []string{
		"mint-0.29.0-linux-x86_64",
		"tool-1.2.3-linux-amd64",
		"yt-dlp",
		"docker-compose-linux-x86_64",
	}
	for _, a := range bare {
		if !releaseInstallableShape(a) {
			t.Errorf("releaseInstallableShape(%q) = false; it is a bare binary", a)
		}
	}
	// A real extension is alphanumeric, which is the whole discriminator.
	if releaseTrailingExt("tool-0.29.0-linux-x86_64") != "" {
		t.Error("a version fragment was read as a file extension")
	}
	if got := releaseTrailingExt("tool.sha256"); got != "sha256" {
		t.Errorf("releaseTrailingExt(tool.sha256) = %q, want sha256", got)
	}
}

// TestChooseReleaseAsset_AcceptsSingleFileCompression covers the
// allow-list matching what the extractor can actually do. elm and workerd
// publish one gzipped binary rather than an archive, and extract.go has
// handled that shape all along, so omitting it made the matcher narrower
// than the engine for no reason.
func TestChooseReleaseAsset_AcceptsSingleFileCompression(t *testing.T) {
	assets := []string{
		"workerd-darwin-64.gz", "workerd-linux-64.gz",
		"workerd-linux-arm64.gz", "workerd-windows-64.gz",
	}
	for arch, want := range map[string]string{
		"amd64": "workerd-linux-64.gz",
		"arm64": "workerd-linux-arm64.gz",
	} {
		got, err := chooseReleaseAsset(assets, "workerd", arch)
		if err != nil {
			t.Fatalf("linux/%s: %v", arch, err)
		}
		if got.Asset != want {
			t.Errorf("linux/%s: chose %q, want %q", arch, got.Asset, want)
		}
	}
}

// TestReleaseMovingName covers what cannot be pinned, and what only looks
// that way. odin publishes odin-linux-amd64-dev-2026-08.tar.gz, a dated
// build whose bytes never change, so refusing every "-dev-" cost a
// repository for no gain.
func TestReleaseMovingName(t *testing.T) {
	for _, moving := range []string{
		"rustfs-linux-x86_64-latest.zip", "tool_latest.tar.gz",
		"tool-nightly-linux.tar.gz", "tool-edge.zip", "tool-canary.tar.gz",
	} {
		if !releaseMovingName(moving) {
			t.Errorf("releaseMovingName(%q) = false, want true", moving)
		}
	}
	for _, pinned := range []string{
		"odin-linux-amd64-dev-2026-08.tar.gz",
		"tool-v1.2.3-linux-amd64.tar.gz",
		"tool-linux-amd64-devel-1.0.tar.gz",
	} {
		if releaseMovingName(pinned) {
			t.Errorf("releaseMovingName(%q) = true; its bytes do not move", pinned)
		}
	}
}

// TestChooseReleaseAsset_ArchMatchingIsTokenBoundary covers the substring
// trap: "x64" appears inside "linux64", so a Contains test reads a name
// that mentions no architecture as naming amd64, and on arm64 it would
// install the wrong binary.
func TestChooseReleaseAsset_ArchMatchingIsTokenBoundary(t *testing.T) {
	if !hasAnyToken("tool-linux64.tar.gz", releaseArchTokens["amd64"]) {
		t.Error("linux64 is a legitimate amd64 spelling and should match as a token")
	}
	if hasAnyToken("tool-linux-aarch64.tar.gz", releaseArchTokens["amd64"]) {
		t.Error("an aarch64 asset matched the amd64 token set")
	}

	// The discriminating cases, all from the real corpus. Each contains an
	// architecture token as a SUBSTRING while naming a different platform,
	// and the OS filter cannot catch them either: in "winx64" the token
	// "win" is followed by a letter rather than a separator, and the same
	// is true of "osx" in "osx64". So a substring test would select a
	// Windows or macOS build as this host's amd64 asset.
	for _, foreign := range []string{
		"cf8-cli_8.18.4_winx64.zip", // cf
		"codeql-osx64.zip",          // codeql
		"neko-2.4.1-osx64.tar.gz",   // neko
	} {
		if hasAnyToken(foreign, releaseArchTokens["amd64"]) {
			t.Errorf("%q matched the amd64 token set; x64 appears only as a substring", foreign)
		}
	}
	// And a release of nothing but those must fail rather than install one.
	if _, err := chooseReleaseAsset([]string{"codeql-osx64.zip", "cf8-cli_8.18.4_winx64.zip"}, "codeql", "amd64"); err == nil {
		t.Error("a release of only macOS and Windows assets resolved on linux/amd64")
	}

	assets := []string{"tool-linux-x86_64.tar.gz", "tool-linux-aarch64.tar.gz"}
	for arch, want := range map[string]string{
		"amd64": "tool-linux-x86_64.tar.gz",
		"arm64": "tool-linux-aarch64.tar.gz",
	} {
		got, err := chooseReleaseAsset(assets, "tool", arch)
		if err != nil {
			t.Fatalf("linux/%s: %v", arch, err)
		}
		if got.Asset != want {
			t.Errorf("linux/%s: chose %q, want %q", arch, got.Asset, want)
		}
	}

	// The other direction: an ordinary word containing "arm" must not read
	// as an ARM asset, or a legitimate amd64 build gets refused.
	if hasAnyToken("alarm-tool-linux-x86_64.tar.gz", releaseForeignArch["amd64"]) {
		t.Error("the word alarm matched an ARM token")
	}
}

// TestChooseReleaseAsset_RejectsWhatCannotBePinned covers the moving-name
// rule. rustfs publishes rustfs-linux-x86_64-latest.zip, whose bytes
// change under a fixed name: pinning a version to it records a version
// while the content moves, so an update is invisible and a reinstall
// fetches something else.
func TestChooseReleaseAsset_RejectsWhatCannotBePinned(t *testing.T) {
	moving := []string{"rustfs-linux-x86_64-latest.zip", "rustfs-linux-aarch64-latest.zip"}
	if _, err := chooseReleaseAsset(moving, "rustfs", "amd64"); err == nil {
		t.Error("a release of only moving-name assets was accepted")
	}
	// A pinned sibling beside a moving one is still installable.
	mixed := append([]string{"rustfs-linux-x86_64-v1.2.3.zip"}, moving...)
	got, err := chooseReleaseAsset(mixed, "rustfs", "amd64")
	if err != nil {
		t.Fatalf("a pinned asset beside moving ones was refused: %v", err)
	}
	if got.Asset != "rustfs-linux-x86_64-v1.2.3.zip" {
		t.Errorf("chose %q, want the pinned asset", got.Asset)
	}
}

// TestChooseReleaseAsset_PrefersTheToolOverThingsShippedBeside is the
// tie-break regression. Shortest-name alone was measured picking a
// PKCS#11 library over the infisical CLI and restatectl over restate-cli.
func TestChooseReleaseAsset_PrefersTheToolOverThingsShippedBeside(t *testing.T) {
	cases := []struct {
		tool   string
		assets []string
		want   string
	}{
		{
			tool: "infisical",
			assets: []string{
				"infisical_1.2.3_linux_amd64.tar.gz",
				"cli_1.2.3_linux_amd64.tar.gz",
			},
			want: "infisical_1.2.3_linux_amd64.tar.gz",
		},
		{
			tool: "restate",
			assets: []string{
				"restatectl-x86_64-unknown-linux-musl.tar.xz",
				"restate-cli-x86_64-unknown-linux-musl.tar.xz",
			},
			want: "restate-cli-x86_64-unknown-linux-musl.tar.xz",
		},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			got, err := chooseReleaseAsset(tc.assets, tc.tool, "amd64")
			if err != nil {
				t.Fatal(err)
			}
			if got.Asset != tc.want {
				t.Errorf("chose %q, want %q", got.Asset, tc.want)
			}
		})
	}
}

// TestChooseReleaseAsset_PrefersGnuOverMusl pins the libc preference.
// Both consumer images are glibc, and no upstream prefers musl; an
// earlier draft did, on no evidence.
func TestChooseReleaseAsset_PrefersGnuOverMusl(t *testing.T) {
	assets := []string{
		"tool-x86_64-unknown-linux-musl.tar.gz",
		"tool-x86_64-unknown-linux-gnu.tar.gz",
	}
	got, err := chooseReleaseAsset(assets, "tool", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got.Asset, "gnu") {
		t.Errorf("chose %q, want the gnu build", got.Asset)
	}
	// musl alone is still installable.
	only := []string{"tool-x86_64-unknown-linux-musl.tar.gz"}
	if got, err := chooseReleaseAsset(only, "tool", "amd64"); err != nil || !strings.Contains(got.Asset, "musl") {
		t.Errorf("a musl-only release was refused: %q, %v", got.Asset, err)
	}
}

// TestReleaseInstallableShape covers the allow-list. Every rejected suffix
// below appears in the real corpus, which is why a deny-list was the wrong
// instrument: the supply-chain metadata formats keep arriving.
func TestReleaseInstallableShape(t *testing.T) {
	ok := []string{
		"tool-linux-amd64.tar.gz", "tool.tgz", "tool.tar.xz", "tool.zip",
		"yt-dlp", "docker-compose-linux-x86_64",
	}
	for _, a := range ok {
		if !releaseInstallableShape(a) {
			t.Errorf("releaseInstallableShape(%q) = false, want true", a)
		}
	}
	notOK := []string{
		"checksums.txt", "tool.sha256", "tool.sig", "tool.asc", "tool.minisig",
		"tool.deb", "tool.rpm", "tool.apk", "tool.msi", "tool.dmg", "tool.pkg",
		"tool.sbom.json", "tool.provenance.json", "tool.sigstore.json",
		"tool.intoto.jsonl", "tool.spdx.json", "tool.pem", "tool.AppImage",
	}
	for _, a := range notOK {
		if releaseInstallableShape(a) {
			t.Errorf("releaseInstallableShape(%q) = true, want false", a)
		}
	}
}

// TestReleaseChecksumFor covers both digest shapes and the honest absence
// of one. Measured over the corpus, a manifest covers 38 of 144
// repositories and per-asset siblings add 22, so most releases publish
// nothing to verify against and the row has to say so.
func TestReleaseChecksumFor(t *testing.T) {
	cases := []struct {
		name         string
		assets       []string
		chosen       string
		wantName     string
		wantManifest bool
	}{
		{
			name:         "per-asset sibling wins",
			assets:       []string{"tool-linux.tar.gz", "tool-linux.tar.gz.sha256", "checksums.txt"},
			chosen:       "tool-linux.tar.gz",
			wantName:     "tool-linux.tar.gz.sha256",
			wantManifest: false,
		},
		{
			name:         "manifest",
			assets:       []string{"tool-linux.tar.gz", "checksums.txt"},
			chosen:       "tool-linux.tar.gz",
			wantName:     "checksums.txt",
			wantManifest: true,
		},
		{
			name:         "goreleaser versioned manifest",
			assets:       []string{"cli_0.43.125_linux_amd64.tar.gz", "cli_0.43.125_checksums.txt"},
			chosen:       "cli_0.43.125_linux_amd64.tar.gz",
			wantName:     "cli_0.43.125_checksums.txt",
			wantManifest: true,
		},
		{
			name:     "nothing to verify against",
			assets:   []string{"tool-linux.tar.gz", "tool.sbom.json"},
			chosen:   "tool-linux.tar.gz",
			wantName: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name, isManifest := releaseChecksumFor(tc.assets, tc.chosen)
			if name != tc.wantName {
				t.Errorf("checksum asset = %q, want %q", name, tc.wantName)
			}
			if isManifest != tc.wantManifest {
				t.Errorf("isManifest = %v, want %v", isManifest, tc.wantManifest)
			}
		})
	}
}

// TestChooseReleaseAsset_FailsWithEveryCandidateNamed covers the failure
// message. A no-match is the expected outcome for some releases, and the
// remedy is reading what was there, so an opaque failure would be
// unactionable.
func TestChooseReleaseAsset_FailsWithEveryCandidateNamed(t *testing.T) {
	_, err := chooseReleaseAsset([]string{"tool.deb", "tool.rpm"}, "tool", "amd64")
	if err == nil {
		t.Fatal("a release of only package formats was accepted")
	}
	for _, want := range []string{"tool.deb", "tool.rpm"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not name %q: %v", want, err)
		}
	}
	if _, err := chooseReleaseAsset(nil, "tool", "amd64"); err == nil {
		t.Error("an empty release was accepted")
	}
}

// TestParseReleaseRef covers the source form. The host is required rather
// than defaulted to github, and that is deliberate: a gitlab source that
// lost its host would resolve against a github repository of the same
// name, so the failure would be a WRONG install rather than an error.
func TestParseReleaseRef(t *testing.T) {
	ok := map[string]releaseRef{
		"github/cli/cli":        {Host: "github", Owner: "cli", Repo: "cli"},
		"gitlab/gitlab-org/cli": {Host: "gitlab", Owner: "gitlab-org", Repo: "cli"},
		"github/docker/compose": {Host: "github", Owner: "docker", Repo: "compose"},
	}
	for ref, want := range ok {
		got, err := parseReleaseRef(ref)
		if err != nil {
			t.Errorf("parseReleaseRef(%q) = %v", ref, err)
			continue
		}
		if got != want {
			t.Errorf("parseReleaseRef(%q) = %+v, want %+v", ref, got, want)
		}
	}
	for _, bad := range []string{
		"cli/cli",             // no host: would silently mean github
		"bitbucket/owner/rep", // unknown host
		"github/cli",          // no repo
		"github//cli",         // no owner
		"github/cli/cli/extra",
		"",
	} {
		if _, err := parseReleaseRef(bad); err == nil {
			t.Errorf("parseReleaseRef(%q) was accepted", bad)
		}
	}
}

// TestReleaseDownloadURL pins the per-forge asset URL shapes.
func TestReleaseDownloadURL(t *testing.T) {
	gh := releaseDownloadURL(releaseRef{Host: "github", Owner: "docker", Repo: "compose"}, "v5.5.0", "docker-compose-linux-x86_64")
	if want := "https://github.com/docker/compose/releases/download/v5.5.0/docker-compose-linux-x86_64"; gh != want {
		t.Errorf("github URL = %q, want %q", gh, want)
	}
	gl := releaseDownloadURL(releaseRef{Host: "gitlab", Owner: "gitlab-org", Repo: "cli"}, "v1.2.3", "glab_1.2.3_linux_amd64.tar.gz")
	if want := "https://gitlab.com/gitlab-org/cli/-/releases/v1.2.3/downloads/glab_1.2.3_linux_amd64.tar.gz"; gl != want {
		t.Errorf("gitlab URL = %q, want %q", gl, want)
	}
}

// TestReleaseFormat maps asset names onto the extractor's own vocabulary.
// A format the extractor does not know would fail at extraction time
// rather than at selection, which is the wrong place to find out.
func TestReleaseFormat(t *testing.T) {
	cases := map[string]string{
		"tool.tar.gz":  "tar.gz",
		"tool.tgz":     "tar.gz",
		"tool.tar.xz":  "tar.xz",
		"tool.txz":     "tar.xz",
		"tool.tar.bz2": "tar.bz2",
		"tool.tar.zst": "tar.zst",
		"tool.tar":     "tar",
		"tool.zip":     "zip",
		"tool.gz":      "gz",
		"tool.xz":      "xz",
		"yt-dlp":       formatRaw,
		"tool-1.2.3":   formatRaw,
	}
	for asset, want := range cases {
		if got := releaseFormat(asset); got != want {
			t.Errorf("releaseFormat(%q) = %q, want %q", asset, got, want)
		}
	}
}

// TestReleaseFiles covers what gets published on PATH and where each
// executable is found inside an artifact. The default is the tool's own
// name; the registry's binary list replaces it, because a registry label
// is not always the name the tool is invoked by (`qdns` ships `q`).
func TestReleaseFiles(t *testing.T) {
	cases := []struct {
		name  string
		tool  string
		hints *ReleaseHints
		want  []AquaFile
	}{
		{name: "no hints", tool: "ripgrep", want: []AquaFile{{Name: "ripgrep"}}},
		{
			name: "bin names a different file", tool: "solidity",
			hints: &ReleaseHints{Bin: "solc"},
			want:  []AquaFile{{Name: "solidity", Src: "solc"}},
		},
		{
			name: "bin_path is a directory", tool: "kotlin",
			hints: &ReleaseHints{BinPath: "kotlinc/bin"},
			want:  []AquaFile{{Name: "kotlin", Src: "kotlinc/bin/kotlin"}},
		},
		{
			name: "bin_path plus bin", tool: "helm-diff",
			hints: &ReleaseHints{Bin: "diff", BinPath: "diff/bin"},
			want:  []AquaFile{{Name: "helm-diff", Src: "diff/bin/diff"}},
		},
		// The registry's own name for the tool is a label, not the
		// executable: publishing `qdns` would put a name on PATH that no
		// documentation for natesales/q mentions.
		{
			name: "bins replaces the tool name", tool: "qdns",
			hints: &ReleaseHints{Bins: []string{"q"}},
			want:  []AquaFile{{Name: "q"}},
		},
		{
			name: "bins publishes every executable", tool: "unison",
			hints: &ReleaseHints{Bins: []string{"ucm", "unison"}},
			want:  []AquaFile{{Name: "ucm"}, {Name: "unison"}},
		},
		// Bin describes the TOOL's executable, so it is scoped to the entry
		// carrying the tool's name — and when the published set does not
		// contain that name, as here, it never applies at all. solidity is
		// the real case: the registry names both, and the file the archive
		// holds is simply `solc`.
		{
			name: "bin does not reach a published sibling", tool: "solidity",
			hints: &ReleaseHints{Bins: []string{"solc"}, Bin: "solc"},
			want:  []AquaFile{{Name: "solc"}},
		},
		{
			name: "bin_path prefixes every executable", tool: "kotlin",
			hints: &ReleaseHints{Bins: []string{"kotlin", "kotlinc"}, BinPath: "kotlinc/bin"},
			want: []AquaFile{
				{Name: "kotlin", Src: "kotlinc/bin/kotlin"},
				{Name: "kotlinc", Src: "kotlinc/bin/kotlinc"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := releaseFiles(tc.tool, tc.hints)
			if !slices.Equal(got, tc.want) {
				t.Errorf("releaseFiles(%q, %+v) = %+v, want %+v", tc.tool, tc.hints, got, tc.want)
			}
		})
	}
}

// TestChooseReleaseAssetWithHints covers the one selection hint. The
// restate repository publishes restate-server, restate-cli and restatectl,
// which are three separate tools in the registry, and no file-name
// heuristic can attribute those assets: only the registry knows.
func TestChooseReleaseAssetWithHints(t *testing.T) {
	assets := []string{
		"restate-server-x86_64-unknown-linux-musl.tar.xz",
		"restate-cli-x86_64-unknown-linux-musl.tar.xz",
		"restatectl-x86_64-unknown-linux-musl.tar.xz",
	}
	cases := map[string]struct {
		tool  string
		match string
		want  string
	}{
		"server": {tool: "restate-server", match: "restate-server", want: "restate-server-x86_64-unknown-linux-musl.tar.xz"},
		"cli":    {tool: "restate", match: "restate-cli", want: "restate-cli-x86_64-unknown-linux-musl.tar.xz"},
		"ctl":    {tool: "restatectl", match: "restatectl", want: "restatectl-x86_64-unknown-linux-musl.tar.xz"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := chooseReleaseAssetWithHints(assets, tc.tool, "amd64", &ReleaseHints{Matching: tc.match})
			if err != nil {
				t.Fatal(err)
			}
			if got.Asset != tc.want {
				t.Errorf("chose %q, want %q", got.Asset, tc.want)
			}
		})
	}

	// A hint that matches nothing is ignored rather than fatal: the
	// registry and the release move independently, and a hint that stopped
	// matching is exactly the case the heuristic exists for.
	got, err := chooseReleaseAssetWithHints(assets, "restate", "amd64", &ReleaseHints{Matching: "no-such-thing"})
	if err != nil {
		t.Fatalf("a stale hint made the install fail: %v", err)
	}
	if got.Asset == "" {
		t.Error("a stale hint produced no choice")
	}
	// And nil hints behave exactly as the bare matcher.
	bare, _ := chooseReleaseAsset(assets, "restate", "amd64")
	withNil, _ := chooseReleaseAssetWithHints(assets, "restate", "amd64", nil)
	if bare.Asset != withNil.Asset {
		t.Errorf("nil hints changed the choice: %q vs %q", withNil.Asset, bare.Asset)
	}
}

// TestReleaseSpec_DiscoveredChecksumIsNotDeclared covers a distinction the
// install path depends on. ChecksumDeclared means "upstream promises a
// checksum", and its contract is that failing to obtain one must REFUSE
// the install. Here the digest source was discovered by looking at the
// asset list, so nobody promised anything: setting the flag would turn
// every upstream that drops its checksums file into a hard install failure
// for a tool that worked yesterday.
func TestReleaseSpec_DiscoveredChecksumIsNotDeclared(t *testing.T) {
	in := &installer{}
	rr := releaseRef{Host: "github", Owner: "docker", Repo: "compose"}

	withSums := []string{"docker-compose-linux-x86_64", "checksums.txt"}
	spec, err := in.releaseSpec(rr, "docker-compose", "v5.5.0", withSums, nil)
	if err != nil {
		t.Fatal(err)
	}
	if spec.ChecksumURL == "" {
		t.Error("a release publishing checksums.txt produced no checksum URL")
	}
	if spec.ChecksumDeclared {
		t.Error("a DISCOVERED checksum was recorded as declared; losing it would then refuse the install")
	}
	if spec.ChecksumAlg != "sha256" {
		t.Errorf("ChecksumAlg = %q, want sha256", spec.ChecksumAlg)
	}

	withoutSums := []string{"docker-compose-linux-x86_64"}
	spec, err = in.releaseSpec(rr, "docker-compose", "v5.5.0", withoutSums, nil)
	if err != nil {
		t.Fatal(err)
	}
	if spec.ChecksumURL != "" || spec.ChecksumDeclared {
		t.Errorf("a release with no digest source produced %+v", spec)
	}
}

// TestSearchInstallTree covers the fallback that makes a nested release
// archive installable. A release publishes no manifest of its contents, so
// the declared path is a guess and upstream's build decides whether it is
// right: pandoc ships its binary at pandoc-<version>/bin/pandoc, and
// before the search that was a hard install failure for the whole tool.
//
// The ranking has to be a TOTAL order. An install that resolves to a
// different file on a re-run is worse than one that fails, because the
// second is reported and the first is not.
func TestSearchInstallTree(t *testing.T) {
	cases := []struct {
		name    string
		files   []string
		plain   []string
		guess   string
		base    string
		want    string
		wantErr bool
	}{
		{
			name:  "the guess is where the file is",
			files: []string{"pandoc"},
			guess: "pandoc", base: "pandoc", want: "pandoc",
		},
		{
			name:  "nested under the archive top directory",
			files: []string{"pandoc-3.10.2/bin/pandoc", "pandoc-3.10.2/share/data.txt"},
			guess: "pandoc", base: "pandoc", want: "pandoc-3.10.2/bin/pandoc",
		},
		// Shallowest wins: a binary sits above its resources, never below
		// them, so a deeper same-named file is a bundled copy. The guess
		// is absent here, or the search would return it without ranking
		// anything.
		{
			name:  "the shallowest match wins",
			files: []string{"extras/nested/q", "dist/q"},
			guess: "q", base: "q", want: "dist/q",
		},
		// arch/ sorts before bin/, so this case fails if the bin rank is
		// dropped and lexicographic order decides.
		{
			name:  "a bin parent breaks a depth tie",
			files: []string{"arch/tool", "bin/tool"},
			guess: "tool", base: "tool", want: "bin/tool",
		},
		// An archive carrying both platforms must not resolve to the
		// darwin build on linux.
		{
			name:  "a foreign-OS path loses to a native one",
			files: []string{"darwin-amd64/tool", "linux-amd64/tool"},
			guess: "tool", base: "tool", want: "linux-amd64/tool",
		},
		// But it must not lose the ONLY candidate either: the filter
		// narrows when it can and abstains when it cannot.
		{
			name:  "a foreign-OS path still wins when it is all there is",
			files: []string{"macos/tool"},
			guess: "tool", base: "tool", want: "macos/tool",
		},
		// A directory can carry the tool's name (pandoc ships a
		// share/pandoc data tree), and here it is the SHALLOWER of the
		// two, so accepting one would win the ranking outright.
		{
			name:  "a directory of the right name is not the executable",
			files: []string{"pandoc/data.txt", "sub/pandoc"},
			guess: "pandoc", base: "pandoc", want: "sub/pandoc",
		},
		{
			name:  "nothing named that was extracted",
			plain: []string{"README.md", "LICENSE"},
			guess: "yr", base: "yr", wantErr: true,
		},
		// SwiftFormat's linux zip holds one file, `swiftformat_linux`, named
		// after the ASSET rather than the tool. One executable is no
		// ambiguity to resolve, so it is taken.
		{
			name:  "the artifact's only executable is taken",
			files: []string{"swiftformat_linux"}, plain: []string{"README.md"},
			guess: "swiftformat", base: "swiftformat", want: "swiftformat_linux",
		},
		// Two and it abstains: guessing which of several binaries the
		// caller meant is how the wrong tool ends up on PATH.
		{
			name:  "two executables and neither named right abstains",
			files: []string{"tool-a", "tool-b"},
			guess: "tool", base: "tool", wantErr: true,
		},
		// A non-executable of the right shape is not a program, and the
		// modes are upstream's own statement: tar and unzip preserve them.
		{
			name:  "a non-executable file is not the artifact's executable",
			plain: []string{"data.bin"},
			guess: "tool", base: "tool", wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			write := func(f string, mode os.FileMode) {
				p := filepath.Join(root, f)
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatalf("Setup: %v", err)
				}
				if err := os.WriteFile(p, []byte("x"), mode); err != nil {
					t.Fatalf("Setup: %v", err)
				}
			}
			// The execute bit is data here, not decoration: the fallback for
			// an unnamed binary reads it.
			for _, f := range tc.files {
				write(f, 0o755)
			}
			for _, f := range tc.plain {
				write(f, 0o644)
			}
			got, err := searchInstallTree(root, filepath.Join(root, tc.guess), tc.base)
			if (err != nil) != tc.wantErr {
				t.Fatalf("searchInstallTree(%v, %q) error = %v, wantErr %v",
					tc.files, tc.base, err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if want := filepath.Join(root, tc.want); got != want {
				t.Errorf("searchInstallTree(%v, %q) = %q, want %q", tc.files, tc.base, got, want)
			}
		})
	}
}

// TestChooseReleaseAsset_PrefersAnAssetNamingThisOS covers the narrowing
// that sits between foreign-OS rejection and the tie-break. Rejection
// removes the assets naming somebody ELSE's OS and leaves both the ones
// naming linux and the ones naming nothing; between those, a name that
// says linux is a build for linux, while a name that says nothing may be
// the sources.
func TestChooseReleaseAsset_PrefersAnAssetNamingThisOS(t *testing.T) {
	cases := map[string]struct {
		assets []string
		tool   string
		hints  *ReleaseHints
		// goarch is the host architecture the choice is made for. Empty
		// means amd64, so only a case that is ABOUT the other arch says so.
		goarch string
		want   string
	}{
		// ethereum/solidity publishes the compiler beside a source
		// archive, and it is the SOURCE whose stem matches the tool name,
		// so name affinity alone picks the tarball.
		"a source archive loses to a linux build": {
			assets: []string{"solc-macos", "solc-static-linux", "solc-windows.exe", "solidity_0.8.36.tar.gz"},
			tool:   "solidity", hints: &ReleaseHints{Bins: []string{"solc"}, Bin: "solc"},
			want: "solc-static-linux",
		},
		// nicklockwood/SwiftFormat's undecorated zip is the macOS build.
		"an undecorated archive loses to a linux one": {
			assets: []string{"swiftformat.zip", "swiftformat_linux.zip"},
			tool:   "swiftformat", want: "swiftformat_linux.zip",
		},
		// yt-dlp's bare `yt-dlp` is a Python zipapp; `yt-dlp_linux` is the
		// standalone binary, which is what a container without python3
		// needs.
		"a standalone linux binary beats an interpreter bundle": {
			assets: []string{"yt-dlp", "yt-dlp.exe", "yt-dlp.tar.gz", "yt-dlp_linux", "yt-dlp_macos"},
			tool:   "yt-dlp", want: "yt-dlp_linux",
		},
		// The preference ABSTAINS when nothing names the OS, which is the
		// common case: most releases name the platform in the architecture
		// token alone.
		"abstains when no asset names an OS": {
			assets: []string{"ripgrep-14.1.1-x86_64.tar.gz"},
			tool:   "ripgrep", want: "ripgrep-14.1.1-x86_64.tar.gz",
		},
		// gnu-over-musl runs FIRST, so the OS preference must not reverse
		// it: facebook/dotslash's musl build is the only one naming linux.
		"gnu wins before the OS preference is consulted": {
			assets: []string{"dotslash-linux-musl.x86_64.tar.gz", "dotslash-ubuntu-22.04.x86_64.tar.gz"},
			tool:   "dotslash", want: "dotslash-ubuntu-22.04.x86_64.tar.gz",
		},
		// The same entry point on the OTHER host architecture, because the
		// hints path reaches foreign-arch rejection before any preference
		// runs and BurntSushi/ripgrep ships one build per arch. Without a
		// case here the whole hints table asserted amd64 only.
		"foreign-arch rejection decides on arm64": {
			assets: []string{
				"ripgrep-14.1.1-x86_64-unknown-linux-musl.tar.gz",
				"ripgrep-14.1.1-aarch64-unknown-linux-gnu.tar.gz",
			},
			tool: "ripgrep", goarch: "arm64",
			want: "ripgrep-14.1.1-aarch64-unknown-linux-gnu.tar.gz",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			goarch := cmp.Or(tc.goarch, "amd64")
			got, err := chooseReleaseAssetWithHints(tc.assets, tc.tool, goarch, tc.hints)
			if err != nil {
				t.Fatalf("chooseReleaseAssetWithHints(%v, %q, %q) = %v", tc.assets, tc.tool, goarch, err)
			}
			if got.Asset != tc.want {
				t.Errorf("chooseReleaseAssetWithHints(%v, %q, %q) chose %q, want %q",
					tc.assets, tc.tool, goarch, got.Asset, tc.want)
			}
		})
	}
}

// TestChooseReleaseAsset_ScoresThePublishedBinaryNames covers the second
// half of name affinity. A registry name is a catalog label, and the asset
// is named after what upstream BUILT, so an asset can match one, the other
// or both — and when the two disagree the label wins, or a repository
// publishing several binaries hands over the wrong one.
func TestChooseReleaseAsset_ScoresThePublishedBinaryNames(t *testing.T) {
	cases := map[string]struct {
		assets []string
		tool   string
		hints  *ReleaseHints
		// goarch is the host architecture the choice is made for. Empty
		// means amd64, so only a case that is ABOUT the other arch says so.
		goarch string
		want   string
	}{
		// rancher/k3k publishes the CLI beside the server. Both score 3,
		// one on the label and one on the executable name.
		"the registry label outranks the executable name": {
			assets: []string{"k3k-linux-amd64", "k3kcli-linux-amd64"},
			tool:   "k3kcli", hints: &ReleaseHints{Bins: []string{"k3k"}, Bin: "k3k"},
			want: "k3kcli-linux-amd64",
		},
		// transifex/cli names its asset after the binary, so the label has
		// nothing to match and the executable name has to carry it.
		"the executable name carries it when the label matches nothing": {
			assets: []string{"tx-linux-amd64.tar.gz", "docs.tar.gz"},
			tool:   "transifex", hints: &ReleaseHints{Bins: []string{"tx"}},
			want: "tx-linux-amd64.tar.gz",
		},
		// And the other direction in the same corpus: babashka's binary is
		// `bb` while its asset is named after the tool.
		"the label carries it when the executable name matches nothing": {
			assets: []string{"babashka-1.13.219-linux-amd64.tar.gz", "bb-static.tar.gz"},
			tool:   "babashka", hints: &ReleaseHints{Bins: []string{"bb"}},
			want: "babashka-1.13.219-linux-amd64.tar.gz",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			goarch := cmp.Or(tc.goarch, "amd64")
			got, err := chooseReleaseAssetWithHints(tc.assets, tc.tool, goarch, tc.hints)
			if err != nil {
				t.Fatalf("chooseReleaseAssetWithHints(%v, %q, %q) = %v", tc.assets, tc.tool, goarch, err)
			}
			if got.Asset != tc.want {
				t.Errorf("chooseReleaseAssetWithHints(%v, %q, %q) chose %q, want %q",
					tc.assets, tc.tool, goarch, got.Asset, tc.want)
			}
		})
	}
}

// TestReleaseArchTokens_UnknownSpellingIsNotNeutral pins the reason the
// foreign-architecture list has a long tail. An unrecognised spelling
// leaves an asset NEUTRAL rather than rejected, and a neutral asset wins
// whenever nothing matches the host outright — so a gap in the list is not
// a missed rejection, it is a wrong install.
func TestReleaseArchTokens_UnknownSpellingIsNotNeutral(t *testing.T) {
	// protobuf-javascript's own release tooling writes aarch_64 and
	// x86_32. Before aarch_64 was a known arm64 spelling, an arm64 host
	// matched nothing, fell through to the neutral set and took the 32-bit
	// x86 build.
	assets := []string{
		"protobuf-javascript-4.0.2-linux-aarch_64.zip",
		"protobuf-javascript-4.0.2-linux-x86_32.zip",
		"protobuf-javascript-4.0.2-linux-x86_64.zip",
		"protobuf-javascript-4.0.2.tar.gz",
	}
	for arch, want := range map[string]string{
		"amd64": "protobuf-javascript-4.0.2-linux-x86_64.zip",
		"arm64": "protobuf-javascript-4.0.2-linux-aarch_64.zip",
	} {
		t.Run(arch, func(t *testing.T) {
			got, err := chooseReleaseAsset(assets, "protoc-gen-js", arch)
			if err != nil {
				t.Fatalf("chooseReleaseAsset(protoc-gen-js, %s) = %v", arch, err)
			}
			if got.Asset != want {
				t.Errorf("chooseReleaseAsset(protoc-gen-js, %s) chose %q, want %q", arch, got.Asset, want)
			}
		})
	}

	// A 32-bit ARM build is not a substitute for arm64: elm publishes
	// exactly one linux ARM asset and it is the 32-bit one, so arm64 has
	// nothing to install and must say so.
	elm := []string{"elm-0.19.2-linux-arm.gz", "elm-0.19.2-linux-x64.gz", "elm-0.19.2-mac-arm.gz"}
	if got, err := chooseReleaseAsset(elm, "elm", "arm64"); err == nil {
		t.Errorf("chooseReleaseAsset(elm, arm64) chose %q, want a refusal: linux-arm is 32-bit", got.Asset)
	}
	if got, err := chooseReleaseAsset(elm, "elm", "amd64"); err != nil || got.Asset != "elm-0.19.2-linux-x64.gz" {
		t.Errorf("chooseReleaseAsset(elm, amd64) = %q, %v, want elm-0.19.2-linux-x64.gz", got.Asset, err)
	}
}

// TestListReleaseAssets_CarriesTheGitHubCredential pins the fix for a
// defect the live check found. The GitHub anonymous rate limit is 60
// requests an hour for the whole PROCESS, and a release install spends two
// of them: one resolving the tag, one listing the assets. While only the
// version resolver held the token, the tag resolved and the listing came
// back HTTP 403 on a repository whose release was public — a failure that
// reads like a missing release.
//
// The second half is the fence: the credential must not travel to the
// download URL, which is a different origin and needs none.
func TestListReleaseAssets_CarriesTheGitHubCredential(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"assets":[{"name":"tool-linux-amd64"}]}`))
	}))
	defer srv.Close()

	tokens := &githubTokenCache{token: "s3cret", checked: time.Now()}
	in := &installer{client: srv.Client(), output: func(string) {}, tokens: tokens}

	// The API host is what earns the header, and the test server is not it,
	// so drive both cases through githubAuth directly: it is the predicate
	// that decides, and a test server cannot be api.github.com.
	if opts := githubAuth("https://api.github.com/repos/o/r/releases/tags/v1", tokens); len(opts) != 1 {
		t.Errorf("githubAuth(api.github.com) returned %d options, want 1", len(opts))
	}
	if opts := githubAuth("https://github.com/o/r/releases/download/v1/tool", tokens); opts != nil {
		t.Errorf("githubAuth(a download URL) returned %d options, want none: the token must not "+
			"travel to another origin", len(opts))
	}
	if opts := githubAuth("https://api.github.com/repos/o/r", &githubTokenCache{checked: time.Now()}); opts != nil {
		t.Errorf("githubAuth with no token returned %d options, want none", len(opts))
	}

	// And the listing itself decodes what the API returns.
	var doc struct {
		Assets []struct{ Name string } `json:"assets"`
	}
	if err := in.getJSON(t.Context(), srv.URL, &doc); err != nil {
		t.Fatalf("getJSON = %v", err)
	}
	if len(doc.Assets) != 1 || doc.Assets[0].Name != "tool-linux-amd64" {
		t.Errorf("getJSON decoded %+v, want one asset named tool-linux-amd64", doc.Assets)
	}
	if gotAuth != "" {
		t.Errorf("getJSON sent Authorization %q to a non-GitHub host, want none", gotAuth)
	}
}
