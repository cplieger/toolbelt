package toolbelt

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
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
// test for the ordering. yt-dlp publishes one bare linux binary with no
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
func TestChooseReleaseAsset_UntaggedBinaryStaysEligible(t *testing.T) {
	assets := []string{
		"SHA2-256SUMS", "SHA2-256SUMS.sig", "SHA2-512SUMS",
		"yt-dlp", "yt-dlp.exe", "yt-dlp_linux.zip", "yt-dlp_macos",
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
