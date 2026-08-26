package toolbelt

import (
	"fmt"
	"runtime"
	"strings"
)

// The release source installs a binary from a forge release, for the
// tools the mise registry knows about and the aqua registry has no
// package for. Source form: "release:<host>/<owner>/<repo>", where host
// is github or gitlab.
//
// The asset a release ships is not described anywhere machine-readable,
// so which file to download is a JUDGEMENT over the release's file
// names. That judgement is best effort and it says so: it either picks
// one asset or fails naming every candidate it saw, and nothing is
// recorded as installed until the binary runs and answers.
//
// This is deliberately a smaller heuristic than mise's scored
// five-factor selection or ubi's, and it makes no claim to parity. What
// keeps it honest is the fixture corpus: every one of the 147 affected
// repositories has its real release file list in
// testdata/release-assets, and the matcher's choice for each is
// asserted on both architectures. A repository it cannot resolve is a
// recorded expectation rather than a surprise in production.

// releaseAssetExts is an allow-list of archive and bare-binary shapes.
//
// An allow-list rather than a deny-list, because a deny-list provably
// misses what it has not seen. Measured over the corpus, releases ship
// .sbom.json, .provenance.json, .sigstore.json, .intoto.jsonl, .spdx.json,
// .minisig, .pem, .asc, .sig, .deb, .rpm, .apk, .msi, .dmg, .pkg, .snap,
// .AppImage and .sha256 siblings, and that list grows with the supply-chain
// tooling of the day. Naming what IS installable does not.
var releaseAssetExts = []string{
	".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.bz2", ".tbz2", ".tar.zst", ".zip",
	// Single-file compression, i.e. one gzipped or xz'd binary rather than
	// an archive. extract.go already handles both (its "gz" and "xz"
	// cases decompress to the bin name), so omitting them here made the
	// allow-list narrower than the engine: measured on the corpus, that
	// alone refused elm and workerd, which publish exactly this shape.
	".gz", ".xz", ".bz2", ".zst",
}

// releaseMovingNames are name fragments that mark an asset whose content
// changes under a fixed name.
//
// Such an asset cannot be pinned: the manifest would record a version
// while the bytes moved underneath it, so an update would be invisible
// and a reinstall would silently fetch something else. Measured in the
// corpus on rustfs, which publishes rustfs-linux-x86_64-latest.zip.
// "-dev-" is deliberately NOT here. It reads like a moving name and is
// not: odin publishes odin-linux-amd64-dev-2026-08.tar.gz, a dated build
// whose bytes never change, and refusing it cost that repository on both
// architectures for no gain.
var releaseMovingNames = []string{"-latest", "_latest", "-nightly", "_nightly", "-edge", "-canary"}

// releaseForeignOS names an OS that is not linux. These exist to REJECT
// rather than to select, which matters because a release naming no OS at
// all is common and must stay eligible.
//
// The list carries CONCATENATED spellings (osx64, winx64, macosx) as well
// as plain ones, and that is not redundancy. Token matching needs a
// separator or a string edge on both sides, so in "codeql-osx64.zip" the
// token "osx" is followed by a digit and does not match, while the
// architecture token "x64" sits inside "osx64" and does not match either:
// both filters miss the asset and a macOS build becomes eligible for a
// linux host. Derived from the corpus rather than guessed, these are the
// spellings that actually occur across the 147 releases.
var releaseForeignOS = []string{
	"darwin", "macos", "macosx", "macosarm", "apple", "osx", "osx64", "osx86", "mac",
	"windows", "win", "win32", "win64", "winx64", "winx86", "msvc", "pc-windows",
	"freebsd", "netbsd", "openbsd", "solaris", "illumos", "android",
}

// releaseArchTokens are the spellings of each architecture, widest
// first. aqua's own replacement table is the source for these.
var releaseArchTokens = map[string][]string{
	"amd64": {"x86_64", "amd64", "x64", "64bit", "linux64"},
	"arm64": {"aarch64", "arm64", "armv8"},
}

// releaseForeignArch are architecture tokens that rule an asset out for
// the host, keyed by the host's own GOARCH.
var releaseForeignArch = map[string][]string{
	"amd64": {"aarch64", "arm64", "armv7", "armv6", "armhf", "arm", "i386", "i686", "386", "riscv64", "ppc64le", "s390x", "mips", "loong64"},
	"arm64": {"x86_64", "amd64", "x64", "armv7", "armv6", "armhf", "i386", "i686", "386", "riscv64", "ppc64le", "s390x", "mips", "loong64"},
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
// names.
//
// The ORDER is the part that was measured wrong twice, so it is spelled
// out. Architecture must NOT come first: testing it before the
// single-candidate rule forecloses the escape for a release that ships
// one untagged linux binary, and measured over the corpus that lost 19
// repositories on amd64 and 23 on arm64, yt-dlp and solidity among them.
// ubi orders it extension, then single candidate, then OS, then
// architecture, and that recovers them.
func chooseReleaseAsset(assets []string, tool, goarch string) (assetChoice, error) {
	if len(assets) == 0 {
		return assetChoice{}, fmt.Errorf("the release publishes no assets")
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
	//    naming NEITHER survives both steps, and that is what makes the
	//    order work: a release shipping one untagged linux binary (yt-dlp
	//    ships exactly `yt-dlp`) has nothing for these rules to match, so
	//    testing them cannot reject it.
	//
	//    An earlier draft short-circuited on a single remaining candidate
	//    instead, to protect that case. Measured over the corpus it let an
	//    explicitly-amd64 asset install on arm64 for three repositories
	//    that publish amd64 only (certstrap, hledger, janet), because a
	//    lone candidate skipped the architecture test that would have
	//    refused it. Keeping the rules and letting untagged names through
	//    protects the same releases without that hole.
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
	if len(cands) > 1 {
		cands = releasePreferGnu(cands)
	}

	choice := assetChoice{Asset: releasePickBest(cands, tool)}
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
	// "carries no extension" cannot be path.Ext: measured on the corpus,
	// mint publishes `mint-0.29.0-linux-x86_64`, whose last dot-suffix
	// path.Ext reports as ".0-linux-x86_64", so the version's own dots
	// made a bare binary read as metadata.
	//
	// A real extension is alphanumeric. That is what separates `json`,
	// `deb`, `sig` and `sha256` from `0-linux-x86_64`, and it needs no
	// list of the metadata formats of the day.
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
	for j := 0; j < len(seg); j++ {
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

// releaseSelectArch narrows to the host architecture.
//
// Matching is on token BOUNDARIES, not substrings, and that is not
// pedantry: `strings.Contains(name, "x64")` matches every `linux64`
// asset, so a substring test silently selects an asset for the wrong
// architecture on a name that never mentioned one.
//
// An asset naming no architecture survives, since a release with one
// linux binary for both architectures is common.
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

// releasePickBest breaks a remaining tie.
//
// Name similarity first, then length. Length alone was measured picking
// wrong on real releases: a PKCS#11 library over the infisical CLI,
// restatectl over restate-cli, and a legacy gam build over the glibc2.39
// one. Preferring the asset whose stem best matches the tool name fixes
// all three, and length remains the tie-break under it.
func releasePickBest(cands []string, tool string) string {
	best := cands[0]
	bestScore := releaseNameAffinity(best, tool)
	for _, a := range cands[1:] {
		score := releaseNameAffinity(a, tool)
		switch {
		case score > bestScore:
			best, bestScore = a, score
		case score == bestScore && len(a) < len(best):
			best = a
		case score == bestScore && len(a) == len(best) && a < best:
			best = a
		}
	}
	return best
}

// releaseNameAffinity scores how much an asset name looks like it IS the
// named tool rather than something shipped beside it.
func releaseNameAffinity(asset, tool string) int {
	if tool == "" {
		return 0
	}
	stem := strings.ToLower(releaseStem(asset))
	t := strings.ToLower(tool)
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

// releaseChecksumFor finds a digest source for the chosen asset:
// a per-asset sibling first, then a manifest listing many files.
//
// A sibling is preferred because it needs no parsing and cannot be
// confused with another asset's line. Measured over the corpus, a
// manifest covers 38 of 144 repositories and per-asset siblings add 22
// more, so roughly 60 of 147 releases can be verified at all and the rest
// install on the transport's word. That is reported per entry rather than
// hidden (see ToolStatus.Checksum).
func releaseChecksumFor(assets []string, chosen string) (name string, isManifest bool) {
	for _, suffix := range []string{".sha256", ".sha256sum", ".sha256.txt"} {
		want := strings.ToLower(chosen + suffix)
		for _, a := range assets {
			if strings.ToLower(a) == want {
				return a, false
			}
		}
	}
	for _, a := range assets {
		lower := strings.ToLower(a)
		for _, cn := range releaseChecksumNames {
			if lower == cn {
				return a, true
			}
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
// token, bounded by a separator or the ends of the name.
//
// The boundary is what makes this correct rather than approximate, in
// both directions. A plain substring test matches "x64" inside "linux64",
// so a name mentioning no architecture would read as amd64. But splitting
// the name into fields is equally wrong: the separators include '_', so
// "mint-0.29.0-linux-x86_64" splits into x86 and 64 and the token
// "x86_64" can never match anything. Measured on the corpus, that alone
// lost mint on both architectures.
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

// hostArch is the architecture the matcher selects for. A variable so a
// test can assert both without a cross-compiled binary.
var hostArch = runtime.GOARCH
