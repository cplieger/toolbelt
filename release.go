package toolbelt

import (
	"fmt"
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
// first. aqua's own replacement table is the source for these, plus the
// underscore form protobuf's release tooling emits (`aarch_64`).
//
// `arm8` is deliberately NOT here even though it means ARMv8: zhanhb's
// cidr-merger publishes arm5, arm6, arm7, arm8 AND arm64 for linux, and
// admitting the rarer spelling as a match only moves the tie-break onto
// the shorter of two equally correct names. Left unlisted it stays
// NEUTRAL, so it remains eligible for a release that ships nothing else.
var releaseArchTokens = map[string][]string{
	"amd64": {"x86_64", "amd64", "x64", "64bit", "linux64"},
	"arm64": {"aarch64", "aarch_64", "arm64", "armv8"},
}

// releaseForeignArch are architecture tokens that rule an asset out for
// the host, keyed by the host's own GOARCH.
//
// The long tail is derived from the corpus, not guessed, and it is
// load-bearing for a reason worth stating: an unrecognised spelling makes
// an asset NEUTRAL rather than rejected, and a neutral asset wins whenever
// nothing matches the host outright. protobuf-javascript publishes
// `linux-aarch_64` and `linux-x86_32`; before `aarch_64` was a known arm64
// spelling, an arm64 host matched neither, fell through to neutral, and
// selected the 32-bit x86 build.
var releaseForeignArch = map[string][]string{
	"amd64": {
		"aarch64", "aarch_64", "arm64", "armv8", "arm8", "armv7", "armv7a", "armv7hl", "armv6",
		"armv5", "arm7", "arm6", "arm5", "armeabi", "armhf", "arm",
		"i386", "i686", "386", "x86_32",
		"riscv64", "riscv64gc", "ppc64le", "ppcle_64", "s390x", "s390_64",
		"mips", "mips64", "mips64le", "mipsle", "loong64", "loongarch64",
	},
	"arm64": {
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
// The ORDER is the part that was measured wrong twice, so it is spelled
// out. Architecture must NOT come first: testing it before the
// single-candidate rule forecloses the escape for a release that ships
// one untagged linux binary, and measured over the corpus that lost 19
// repositories on amd64 and 23 on arm64, yt-dlp and solidity among them.
// ubi orders it extension, then single candidate, then OS, then
// architecture, and that recovers them.
func chooseReleaseAsset(assets []string, tool, goarch string) (assetChoice, error) {
	return chooseReleaseAssetNamed(assets, []string{tool}, goarch)
}

// chooseReleaseAssetNamed is chooseReleaseAsset with the full name set.
func chooseReleaseAssetNamed(assets, names []string, goarch string) (assetChoice, error) {
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
	// gnu-over-musl runs FIRST. Both narrow among assets that are all
	// valid for this host, and the OS preference is the blunter of the two:
	// facebook/dotslash publishes `dotslash-linux-musl.x86_64.tar.gz`
	// beside `dotslash-ubuntu-22.04.x86_64.tar.gz`, and only the first
	// names linux, so preferring the OS token first would hand the musl
	// build the win and quietly reverse the gnu preference.
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

// releasePreferNativeOS narrows to the assets that name THIS OS, when any
// do.
//
// Foreign-OS rejection above cannot make this call: it removes the assets
// naming somebody else's OS and leaves both the ones naming linux and the
// ones naming nothing. Between those two, a name that says linux is a
// build for linux, while a name that says nothing may be a source archive
// — ethereum/solidity publishes solc-static-linux beside a
// solidity_<version>.tar.gz of the sources, and the source archive is the
// one whose stem matches the tool name.
//
// Abstains when nothing names the OS, which is the common case and the
// reason it is a preference rather than a filter: most releases name the
// platform in the architecture token alone, or not at all (yt-dlp ships
// exactly `yt-dlp`).
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

// releasePickBest breaks a remaining tie.
//
// Name similarity first, then length. Length alone was measured picking
// wrong on real releases: a PKCS#11 library over the infisical CLI,
// restatectl over restate-cli, and a legacy gam build over the glibc2.39
// one. Preferring the asset whose stem best matches the tool name fixes
// all three, and length remains the tie-break under it.
//
// Similarity is scored against EVERY name the tool is known by, best
// wins, and the ORDER of that list breaks a tie. A registry name is a
// catalog label and the asset is named after what upstream built:
// `transifex` ships `tx-linux-amd64.tar.gz`, `graphite` ships `gt-linux`,
// and scoring only the label gives those assets nothing to match. Both
// directions occur in one corpus — babashka's binary is `bb` and its asset
// is `babashka-…` — so neither name can be the only one scored.
//
// The label ranking first is what keeps rancher/k3k's two binaries apart:
// the tool is `k3kcli`, whose executable the registry calls `k3k`, and the
// release publishes `k3kcli-linux-amd64` (the CLI) beside
// `k3k-linux-amd64` (the server). Both score 3, one on the label and one
// on the executable name, and only the label's precedence picks the CLI
// the entry is actually for.
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

// ReleaseHints are the install hints a registry entry carries for a
// release-backed tool, compiled into the catalog rather than guessed.
//
// 26 of the affected registry entries ship at least one hint. These are
// the four that state something the heuristic cannot derive from a file
// name: which of several binaries in one repository is this tool, and
// where the executable sits inside the artifact.
//
// The registry's `asset_pattern` is deliberately NOT among them, and that
// is a least-mechanism call rather than an omission. Its 8 users write
// three different dialects (Tera `{{ arch(x64='amd64') }}`, mise's own
// `{amd64_arch}` braces, and shell globs), one of them carries a Tera
// `{% if %}` block, and consuming any of it means shipping a template
// evaluator this library declined for the 10 `http:` entries. Measured
// against every one of those repositories' real release file lists, the
// heuristic in release.go already picks the right asset for all 8, so the
// evaluator would buy nothing.
type ReleaseHints struct {
	// Matching narrows the candidate set by substring BEFORE the heuristic
	// runs. It is the one selection hint that matters: the restate
	// repository publishes restate-server, restate-cli and restatectl, and
	// these are three separate tools whose assets no file-name heuristic
	// can attribute.
	Matching string `json:"matching,omitempty"`
	// Bins are the names this tool publishes on PATH, carried only when
	// they are not just the tool's own name — 40 of the 158 release-backed
	// entries, and the single biggest correctness item in this struct. A
	// release ships whatever upstream's build produced: `qdns` is the
	// registry's name for `natesales/q`, whose binary is `q`, and `unison`
	// ships `ucm`. Without this the install links a name the artifact does
	// not contain.
	//
	// A set rather than one name because 14 of those 40 publish several
	// (kotlin ships six kotlinc variants). An absent one is skipped rather
	// than fatal: the registry and the release move independently, so a
	// list that has gone stale must still install what IS there.
	Bins []string `json:"bins,omitempty"`
	// Bin and BinPath name the executable INSIDE the artifact: Bin a file
	// name that differs from the published one, BinPath a directory to
	// look in. helm-diff is the case both exist for — the archive holds
	// `diff/bin/diff` and the tool is published as `helm-diff`.
	Bin     string `json:"bin,omitempty"`
	BinPath string `json:"bin_path,omitempty"`
}

// The registry's `rename_exe` is deliberately NOT among these, on the same
// least-mechanism grounds as asset_pattern and with the same measurement
// behind it. It names the name to PUBLISH, and across all 7 entries that
// carry one it states something the publish set already says: 4 repeat the
// tool's own name (swiftformat, tanzu, yt-dlp, helm-diff) and 3 repeat an
// entry in Bins (aws-amplify, oh-my-pi, podman). An earlier draft read it
// as the name to look for inside the artifact, which is the opposite of
// what it means, and that mistake is what sent the swiftformat install
// looking for a file called `swiftformat` in an archive holding
// `swiftformat_linux`. The sole-executable fallback in searchInstallTree
// is what actually resolves that shape, for every release rather than the
// 7 the registry annotated.

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
// answers to.
//
// A hint that narrows to something is authoritative: it is upstream's own
// statement about its own release. A hint that matches NOTHING is ignored
// rather than fatal, because the registry and the release move
// independently, and a hint that stopped matching is exactly the case the
// heuristic exists for.
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
