package toolbelt

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// The release source installs a binary from a forge release, for tools
// mise knows about that aqua has no package for. Source form:
// "release:<host>/<owner>/<repo>", host github or gitlab.
//
// Which asset to download is a JUDGEMENT over file names (no
// machine-readable description exists) — best effort, picking one asset
// or failing naming every candidate seen. Kept honest by the fixture
// corpus (testdata/release-assets, all 147 affected repositories).

// releaseAssetExts is an allow-list of archive and bare-binary shapes.
// An allow-list rather than a deny-list: a deny-list provably misses
// what it has not seen (the corpus ships .sbom.json, .provenance.json,
// .sigstore.json, .minisig, .deb, .rpm, .pkg, .AppImage, .sha256
// siblings and more, growing with supply-chain tooling). Naming what IS
// installable does not.
var releaseAssetExts = []string{
	".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.bz2", ".tbz2", ".tar.zst", ".zip",
	// Single-file compression (one gzipped/xz'd binary, not an archive):
	// extract.go already handles both, so omitting them made the
	// allow-list narrower than the engine and refused elm and workerd.
	".gz", ".xz", ".bz2", ".zst",
}

// releaseMovingNames are name fragments marking an asset whose content
// changes under a fixed name — unpinnable, since a reinstall would
// silently fetch something else (rustfs-linux-x86_64-latest.zip).
// "-dev-" is deliberately NOT here: odin's dated
// odin-linux-amd64-dev-2026-08.tar.gz never changes, and refusing it
// cost that repository on both architectures for no gain.
var releaseMovingNames = []string{"-latest", "_latest", "-nightly", "_nightly", "-edge", "-canary"}

// releaseForeignOS names an OS that is not linux, to REJECT rather than
// select (a release naming no OS at all is common and must stay
// eligible). Carries CONCATENATED spellings (osx64, winx64, macosx)
// alongside plain ones — not redundancy: token matching needs a
// separator on both sides, so in "codeql-osx64.zip" neither "osx"
// (followed by a digit) nor "x64" (inside "osx64") matches, and a macOS
// build becomes eligible for a linux host without the concatenated form.
var releaseForeignOS = []string{
	"darwin", "macos", "macosx", "macosarm", "apple", "osx", "osx64", "osx86", "mac",
	"windows", "win", "win32", "win64", "winx64", "winx86", "msvc", "pc-windows",
	"freebsd", "netbsd", "openbsd", "solaris", "illumos", "android",
}

// releaseArchTokens are the spellings of each architecture, widest
// first (aqua's replacement table, plus protobuf's underscore form
// `aarch_64`). `arm8` is deliberately NOT here even though it means
// ARMv8: zhanhb's cidr-merger publishes arm5-arm8 AND arm64 for linux,
// and admitting the rarer spelling only moves the tie-break onto the
// shorter of two equally correct names; left unlisted it stays NEUTRAL.
var releaseArchTokens = map[string][]string{
	goarchAMD64: {"x86_64", "amd64", "x64", "64bit", "linux64"},
	goarchARM64: {"aarch64", "aarch_64", "arm64", "armv8"},
}

// releaseForeignArch are architecture tokens that rule an asset out for
// the host, keyed by GOARCH. The long tail is derived from the corpus:
// an unrecognised spelling makes an asset NEUTRAL rather than rejected,
// and a neutral asset wins when nothing matches outright — before
// `aarch_64` was listed, protobuf-javascript's arm64 host matched
// neither `linux-aarch_64` nor `linux-x86_32`, fell through to neutral,
// and selected the 32-bit build.
var releaseForeignArch = map[string][]string{
	goarchAMD64: {
		"aarch64", "aarch_64", "arm64", "armv8", "arm8", "armv7", "armv7a", "armv7hl", "armv6",
		"armv5", "arm7", "arm6", "arm5", "armeabi", "armhf", "arm",
		"i386", "i686", "386", "x86_32",
		"riscv64", "riscv64gc", "ppc64le", "ppcle_64", "s390x", "s390_64",
		"mips", "mips64", "mips64le", "mipsle", "loong64", "loongarch64",
	},
	goarchARM64: {
		"x86_64", "amd64", "x64", "x86_32",
		"armv7", "armv7a", "armv7hl", "armv6", "armv5", "arm7", "arm6", "arm5", "armeabi", "armhf", "arm",
		"i386", "i686", "386",
		"riscv64", "riscv64gc", "ppc64le", "ppcle_64", "s390x", "s390_64",
		"mips", "mips64", "mips64le", "mipsle", "loong64", "loongarch64",
	},
}

// releaseChecksumNames are the manifest file names a release publishes a
// digest list under. A per-asset "<asset>.sha256" sibling is looked for
// separately (see releaseChecksumFor).
var releaseChecksumNames = []string{
	"checksums.txt", "checksum.txt", "sha256sums.txt", "sha256sums",
	"sha256sum.txt", "sha2-256sums", "shasums256.txt", "checksums.sha256",
}

// assetChoice is what the matcher decided: the asset to download and,
// when the release publishes one, where its digest can be read.
type assetChoice struct {
	Asset string
	// ChecksumAsset is a digest source in the same release: either a
	// manifest listing many files, or a per-asset sibling. Empty means
	// the release publishes nothing to verify against, which the row
	// reports rather than hides.
	ChecksumAsset string
	// ChecksumIsManifest distinguishes the two shapes, because a manifest
	// needs the line for this asset picked out of it while a sibling is
	// the digest itself.
	ChecksumIsManifest bool
}

// chooseReleaseAsset picks one asset for goarch out of a release's file
// names, matching against every name the tool is known by: its registry
// name first, then the executables it publishes (see releasePickBest).
//
// The ORDER matters and was measured wrong twice: architecture must NOT
// come before the single-candidate rule, or a release shipping one
// untagged linux binary has no escape — lost 19 repositories on amd64
// and 23 on arm64 (yt-dlp, solidity among them). ubi's order (extension,
// single candidate, OS, architecture) recovers them.
func chooseReleaseAsset(assets []string, tool, goarch string) (assetChoice, error) {
	return chooseReleaseAssetNamed(assets, []string{tool}, goarch)
}

// chooseReleaseAssetNamed is chooseReleaseAsset with the full name set.
func chooseReleaseAssetNamed(assets, names []string, goarch string) (assetChoice, error) {
	if len(assets) == 0 {
		return assetChoice{}, errors.New("the release publishes no assets")
	}

	// 1. Installable shapes only, and nothing whose bytes move under a
	//    fixed name.
	cands := make([]string, 0, len(assets))
	for _, a := range assets {
		if releaseInstallableShape(a) && !releaseMovingName(a) {
			cands = append(cands, a)
		}
	}
	if len(cands) == 0 {
		return assetChoice{}, fmt.Errorf("no installable asset among %d files (%s)",
			len(assets), strings.Join(assets, ", "))
	}

	// 2. Reject what names another OS or another architecture. An asset
	//    naming NEITHER survives both steps — see chooseReleaseAsset's
	//    doc comment for why architecture cannot short-circuit instead.
	if os := releaseRejectForeignOS(cands); len(os) > 0 {
		cands = os
	} else {
		return assetChoice{}, fmt.Errorf("every installable asset names another OS (%s)",
			strings.Join(assets, ", "))
	}
	narrowed := releaseSelectArch(cands, goarch)
	if len(narrowed) == 0 {
		return assetChoice{}, fmt.Errorf("no asset for linux/%s among %s", goarch, strings.Join(cands, ", "))
	}
	cands = narrowed
	// gnu-over-musl runs FIRST: facebook/dotslash's musl build is the
	// only one naming linux, so preferring the OS token first would hand
	// it the win and reverse the gnu preference.
	if len(cands) > 1 {
		cands = releasePreferGnu(cands)
	}
	if len(cands) > 1 {
		cands = releasePreferNativeOS(cands)
	}

	choice := assetChoice{Asset: releasePickBest(cands, names)}
	choice.ChecksumAsset, choice.ChecksumIsManifest = releaseChecksumFor(assets, choice.Asset)
	return choice, nil
}

// releaseInstallableShape reports whether a file name is an archive or a
// bare binary this engine can install.
//
// A name with no recognised extension is treated as a bare binary, which
// is how the majority of Go and Rust releases ship. That is also why the
// rejection of everything else has to be explicit: a `.sbom.json` has no
// archive extension either.
func releaseInstallableShape(name string) bool {
	lower := strings.ToLower(name)
	for _, ext := range releaseAssetExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	// Otherwise it is a bare binary if it carries no file extension, and
	// "carries no extension" cannot be path.Ext: mint publishes
	// `mint-0.29.0-linux-x86_64`, whose last dot-suffix path.Ext reports
	// as ".0-linux-x86_64", so the version's own dots made a bare binary
	// read as metadata. A real extension is alphanumeric instead, which
	// separates `json`/`deb`/`sha256` from `0-linux-x86_64` with no list
	// of metadata formats needed.
	return releaseTrailingExt(lower) == ""
}

// releaseTrailingExt returns the trailing dot-separated segment when it
// looks like a file extension, i.e. when it is non-empty and entirely
// alphanumeric. Anything else (a version fragment, an architecture
// triple) is part of the name.
func releaseTrailingExt(lower string) string {
	i := strings.LastIndexByte(lower, '.')
	if i < 0 || i == len(lower)-1 {
		return ""
	}
	seg := lower[i+1:]
	for j := range len(seg) {
		c := seg[j]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return ""
		}
	}
	return seg
}

// releaseMovingName reports whether the asset's content changes under a
// fixed name, which makes it impossible to pin.
func releaseMovingName(name string) bool {
	lower := strings.ToLower(name)
	for _, frag := range releaseMovingNames {
		if strings.Contains(lower, frag) {
			return true
		}
	}
	return false
}

// releaseRejectForeignOS drops assets naming an OS that is not linux.
// An asset naming no OS at all is kept: plenty of releases publish a
// single linux binary with no platform in the name.
func releaseRejectForeignOS(cands []string) []string {
	out := make([]string, 0, len(cands))
	for _, a := range cands {
		if !hasAnyToken(a, releaseForeignOS) {
			out = append(out, a)
		}
	}
	return out
}

// releaseSelectArch narrows to the host architecture. Matching is on
// token BOUNDARIES, not substrings: `strings.Contains(name, "x64")`
// matches every `linux64` asset, silently selecting the wrong
// architecture on a name that never mentioned one. An asset naming no
// architecture survives (a release with one linux binary for both is
// common).
func releaseSelectArch(cands []string, goarch string) []string {
	want := releaseArchTokens[goarch]
	foreign := releaseForeignArch[goarch]
	var matched, neutral []string
	for _, a := range cands {
		switch {
		case hasAnyToken(a, want):
			matched = append(matched, a)
		case hasAnyToken(a, foreign):
			// Names another architecture: not for this host.
		default:
			neutral = append(neutral, a)
		}
	}
	if len(matched) > 0 {
		return matched
	}
	return neutral
}

// releasePreferGnu prefers a glibc build over a musl one.
//
// Both consumer images are Debian, so gnu is the native choice. An
// earlier draft preferred musl on the theory that a static binary always
// runs; that matched none of mise, aqua or ubi and had no evidence behind
// it. A musl asset is still accepted when it is the only one.
func releasePreferGnu(cands []string) []string {
	var gnu, other []string
	for _, a := range cands {
		lower := strings.ToLower(a)
		switch {
		case strings.Contains(lower, "musl"):
		case strings.Contains(lower, "gnu"), strings.Contains(lower, "glibc"):
			gnu = append(gnu, a)
		default:
			other = append(other, a)
		}
	}
	if len(gnu) > 0 {
		return gnu
	}
	if len(other) > 0 {
		return other
	}
	return cands
}

// releasePreferNativeOS narrows to the assets that name THIS OS, when
// any do. Foreign-OS rejection above cannot make this call: it leaves
// both the ones naming linux and the ones naming nothing, and a name
// that says nothing may be a source archive — ethereum/solidity
// publishes solc-static-linux beside solidity_<version>.tar.gz of the
// sources, whose stem happens to match the tool name.
//
// Abstains when nothing names the OS (the common case: most releases
// name the platform in the architecture token alone, or not at all).
func releasePreferNativeOS(cands []string) []string {
	var native []string
	for _, a := range cands {
		if hasToken(a, "linux") {
			native = append(native, a)
		}
	}
	if len(native) > 0 {
		return native
	}
	return cands
}

// releasePickBest breaks a remaining tie: name similarity first, then
// length. Length alone was measured picking wrong on real releases (a
// PKCS#11 library over the infisical CLI, restatectl over restate-cli);
// preferring the best-matching stem fixes it.
//
// Similarity is scored against EVERY name the tool is known by, best
// wins, list ORDER breaking a tie: `transifex` ships `tx-linux-…` and
// babashka's binary is `bb` while its asset is `babashka-…`, so neither
// the label nor the executable name alone can be scored.
//
// Label ranking first is what keeps rancher/k3k's `k3kcli-linux-amd64`
// (the CLI) apart from `k3k-linux-amd64` (the server): both score 3,
// one on the label and one on the executable name, and only the label's
// precedence picks the CLI the entry is actually for.
func releasePickBest(cands, names []string) string {
	best := cands[0]
	bestScore, bestName := releaseNameAffinity(best, names)
	for _, a := range cands[1:] {
		score, nameIdx := releaseNameAffinity(a, names)
		switch {
		case score > bestScore:
			best, bestScore, bestName = a, score, nameIdx
		case score < bestScore:
		case nameIdx < bestName:
			best, bestName = a, nameIdx
		case nameIdx > bestName:
		case len(a) < len(best):
			best = a
		case len(a) == len(best) && a < best:
			best = a
		}
	}
	return best
}

// releaseNameAffinity scores how much an asset name looks like it IS the
// named tool rather than something shipped beside it, taking the best
// score over every name the tool answers to. The second result is the
// index of the name that produced it, so a caller can prefer an earlier
// name at equal score.
func releaseNameAffinity(asset string, names []string) (score, nameIdx int) {
	stem := strings.ToLower(releaseStem(asset))
	nameIdx = len(names)
	for i, name := range names {
		if s := stemAffinity(stem, strings.ToLower(name)); s > score {
			score, nameIdx = s, i
		}
	}
	return score, nameIdx
}

// stemAffinity scores one asset stem against one lowercased name.
func stemAffinity(stem, t string) int {
	if t == "" {
		return 0
	}
	switch {
	case stem == t:
		return 4
	case strings.HasPrefix(stem, t+"-"), strings.HasPrefix(stem, t+"_"), strings.HasPrefix(stem, t+"."):
		return 3
	case strings.HasPrefix(stem, t):
		return 2
	case strings.Contains(stem, t):
		return 1
	}
	return 0
}

// releaseStem strips the recognised archive extension from an asset
// name. path.Ext is not enough: ".tar.gz" is two extensions.
func releaseStem(name string) string {
	lower := strings.ToLower(name)
	for _, ext := range releaseAssetExts {
		if strings.HasSuffix(lower, ext) {
			return name[:len(name)-len(ext)]
		}
	}
	return name
}

// releaseChecksumFor finds a digest source for the chosen asset: a
// per-asset sibling first (needs no parsing, cannot be confused with
// another asset's line), then a manifest. Roughly 60 of 147 releases
// can be verified at all; the rest install on the transport's word,
// reported per entry rather than hidden (see ToolStatus.Checksum).
func releaseChecksumFor(assets []string, chosen string) (name string, isManifest bool) {
	for _, suffix := range []string{".sha256", ".sha256sum", ".sha256.txt"} {
		want := chosen + suffix
		for _, a := range assets {
			if strings.EqualFold(a, want) {
				return a, false
			}
		}
	}
	for _, a := range assets {
		if slices.Contains(releaseChecksumNames, strings.ToLower(a)) {
			return a, true
		}
	}
	// A goreleaser-style manifest carrying the version in its name
	// (cli_0.43.125_checksums.txt).
	for _, a := range assets {
		lower := strings.ToLower(a)
		if strings.HasSuffix(lower, "_checksums.txt") || strings.HasSuffix(lower, "-checksums.txt") {
			return a, true
		}
	}
	return "", false
}

// hasAnyToken reports whether name contains any of the tokens as a whole
// token, bounded by a separator or the ends of the name. The boundary
// matters in both directions: a plain substring test matches "x64"
// inside "linux64", but splitting into fields is equally wrong (the
// separators include '_', so "mint-0.29.0-linux-x86_64" splits into x86
// and 64 and "x86_64" can never match) — that alone lost mint on both
// architectures.
func hasAnyToken(name string, tokens []string) bool {
	hay := strings.ToLower(releaseStem(name))
	for _, t := range tokens {
		if hasToken(hay, t) {
			return true
		}
	}
	return false
}

// hasToken reports whether hay contains token delimited by separators or
// string edges. hay and token are both lowercased already.
func hasToken(hay, token string) bool {
	for i := 0; ; {
		j := strings.Index(hay[i:], token)
		if j < 0 {
			return false
		}
		start := i + j
		end := start + len(token)
		if releaseBoundary(hay, start-1) && releaseBoundary(hay, end) {
			return true
		}
		i = start + 1
		if i >= len(hay) {
			return false
		}
	}
}

// releaseBoundary reports whether index i is outside the string or holds
// a separator, i.e. whether a token may end there.
func releaseBoundary(s string, i int) bool {
	if i < 0 || i >= len(s) {
		return true
	}
	switch s[i] {
	case '-', '_', '.', '+', '~', '/':
		return true
	}
	return false
}

// ReleaseHints are the install hints a registry entry carries for a
// release-backed tool, compiled into the catalog rather than guessed:
// the four fields (of 26 hint-bearing entries) that state something the
// heuristic cannot derive from a file name alone — which of several
// binaries in one repository is this tool, and where the executable
// sits inside the artifact.
//
// The registry's `asset_pattern` is deliberately NOT among them
// (least-mechanism, not omission): its 8 users write three different
// template dialects, and the heuristic already picks the right asset
// for all 8 against their real release file lists, so a template
// evaluator would buy nothing.
type ReleaseHints struct {
	// Matching narrows the candidate set by substring BEFORE the heuristic
	// runs. It is the one selection hint that matters: the restate
	// repository publishes restate-server, restate-cli and restatectl, and
	// these are three separate tools whose assets no file-name heuristic
	// can attribute.
	Matching string `json:"matching,omitempty"`
	// Bin and BinPath name the executable INSIDE the artifact: Bin a file
	// name that differs from the published one, BinPath a directory to
	// look in. helm-diff is the case both exist for — the archive holds
	// `diff/bin/diff` and the tool is published as `helm-diff`.
	Bin     string `json:"bin,omitempty"`
	BinPath string `json:"bin_path,omitempty"`
	// Bins are the names this tool publishes on PATH, carried only when
	// they differ from the tool's own name (40 of 158 entries) — a
	// release ships whatever upstream's build produced: `qdns` is the
	// registry's name for `natesales/q`, whose binary is `q`.
	//
	// A set rather than one name because 14 of those 40 publish several
	// (kotlin ships six kotlinc variants). An absent one is skipped
	// rather than fatal, since a stale list must still install what IS
	// there.
	Bins []string `json:"bins,omitempty"`
}

// The registry's `rename_exe` is deliberately NOT among these
// (least-mechanism): it names the name to PUBLISH, which the publish set
// already states across all 7 entries carrying one. Reading it as the
// name to look for INSIDE the artifact — the opposite of what it means —
// is a mistake that already shipped: it sent the swiftformat install
// looking for a file called `swiftformat` in an archive holding
// `swiftformat_linux`. The sole-executable fallback in searchInstallTree
// resolves that shape for every release, not just the 7 annotated ones.

// IsZero reports whether the hints carry nothing, so a catalog entry can
// omit the object entirely rather than emitting an empty one.
//
// Exported because the catalog COMPILER is the only caller: it decides per
// entry whether there is a hint worth writing, and duplicating the field
// list there is how a fifth hint gets added to one side and not the other.
func (h *ReleaseHints) IsZero() bool {
	return h == nil || (h.Matching == "" && h.Bin == "" && h.BinPath == "" && len(h.Bins) == 0)
}

// chooseReleaseAssetWithHints applies the selection hint before falling
// back to the heuristic, and hands the heuristic every name the tool
// answers to. A hint that narrows to something is authoritative; one
// that matches NOTHING is ignored rather than fatal, since the registry
// and the release move independently and a stopped-matching hint is
// exactly the case the heuristic exists for.
func chooseReleaseAssetWithHints(assets []string, tool, goarch string, hints *ReleaseHints) (assetChoice, error) {
	names := []string{tool}
	if hints != nil {
		if hints.Matching != "" {
			var kept []string
			want := strings.ToLower(hints.Matching)
			for _, a := range assets {
				if strings.Contains(strings.ToLower(a), want) {
					kept = append(kept, a)
				}
			}
			if len(kept) > 0 {
				assets = kept
			}
		}
		// The registry name goes FIRST and the binaries after it, so a
		// release naming both (babashka ships `babashka-<v>-linux-amd64`
		// and the binary `bb`) keeps the label's own score.
		names = append(names, hints.Bins...)
		if hints.Bin != "" {
			names = append(names, hints.Bin)
		}
	}
	return chooseReleaseAssetNamed(assets, names, goarch)
}
