package toolbelt

import (
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/cplieger/httpx/v5"
	"github.com/cplieger/pathinside/v2"
)

// installer executes install/uninstall plans for every source kind.
// It is owned by the Engine and always invoked from the single job
// worker goroutine, so no internal locking is needed.
type installer struct {
	client *http.Client
	// output receives human-readable progress lines (wired to the
	// running job's ring buffer + the OnJobOutput callback).
	output func(line string)
	// log carries operator-facing lines that must outlive the job's
	// output ring: a refused install, an artifact installed without
	// checksum verification. Nil falls back to slog.Default().
	log *slog.Logger
	// aptIdx is the parsed Debian package list, used as the literal-name
	// oracle before any apt-get install (see installer.aptKnownName).
	// Nil, or not yet loaded, degrades to the expansion-character
	// fallback rather than to no check at all.
	aptIdx *aptIndex
	// tokens authenticates the release source's asset listing against the
	// GitHub API, the same credential the version resolver uses. Nil means
	// anonymous, which works until the 60/hour ceiling.
	tokens   *githubTokenCache
	toolsDir string
}

// Checksum outcomes recorded on ToolStatus.Checksum.
const (
	// checksumVerified: the definition declared a checksum source and
	// the downloaded artifact's digest matched it.
	checksumVerified = "verified"
	// checksumUnverified: the definition declared no checksum source,
	// so the artifact was installed on the transport's word alone.
	checksumUnverified = "unverified"
)

// The two architectures this engine installs for, spelled as GOARCH
// spells them. Named because they are a ROLE — the host architecture an
// asset must match — read by the asset matcher, the catalog's
// resolvability check and the manual-install ARCH_* environment. The
// same characters appearing inside an asset-token list are a different
// thing (a token upstream puts in a filename) and stay literal there.
const (
	goarchAMD64 = "amd64"
	goarchARM64 = "arm64"
)

// algSHA256 names the checksum algorithm a definition declares and a
// release's own checksum file tags its digests with.
const algSHA256 = "sha256"

// installOutcome is what one install produced: the bins the tool now
// owns in the bin dir, the package-manager-owned bins, and how the
// artifact's integrity was established (aqua artifacts only; empty for
// the ecosystem backends, which carry their own integrity checks).
type installOutcome struct {
	checksum string
	bins     []string
	pmBins   []string
	// apt marks an install whose artifacts this engine does not own: an
	// apt package lands in /usr, on the container layer, so it produces
	// no bins to link and nothing to remove on uninstall. Recorded so the
	// caller can tell "installed and owns nothing" from "installed
	// nothing", which are otherwise the same empty bin set.
	apt bool
}

// logger returns the operator-facing logger (slog.Default when unset).
func (in *installer) logger() *slog.Logger {
	if in.log == nil {
		return slog.Default()
	}
	return in.log
}

func (in *installer) binDir() string    { return filepath.Join(in.toolsDir, "bin") }
func (in *installer) optDir() string    { return filepath.Join(in.toolsDir, "opt") }
func (in *installer) npmDir() string    { return filepath.Join(in.toolsDir, "npm") }
func (in *installer) pythonDir() string { return filepath.Join(in.toolsDir, "python") }

// managedDirMode is the mode every directory the engine creates for
// itself is pinned to: traversable by anyone who can reach the tools
// tree, writable only by the uid the engine runs as.
const managedDirMode os.FileMode = 0o755

// ensureManagedDir creates dir and, when THIS call created it, verifies
// the filesystem stored managedDirMode rather than assuming it did:
// mkdir(2) takes the mode through the umask, and a group-write ACE or a
// setgid parent can both store a wider mode than requested. bin/ is why
// this matters — a group-writable bin/ lets any group member repoint a
// published PATH entry. Only a directory THIS call created is
// chmod'ed; a pre-existing one is left alone.
func ensureManagedDir(dir string) error {
	if err := os.MkdirAll(filepath.Dir(dir), managedDirMode); err != nil {
		return err
	}
	if mkErr := os.Mkdir(dir, managedDirMode); mkErr != nil {
		if !errors.Is(mkErr, os.ErrExist) {
			return mkErr
		}
		// Mirror os.MkdirAll's acceptance test: a name occupied by a
		// regular file still fails rather than reading as established.
		fi, statErr := os.Stat(dir)
		if statErr != nil {
			return statErr
		}
		if !fi.IsDir() {
			return fmt.Errorf("%s exists and is not a directory", dir)
		}
		return nil
	}
	return enforceDirMode(dir, managedDirMode)
}

// ensureManagedDirs establishes several levels, outermost first, so each
// gets its own verdict. The caller decides where engine ownership starts
// (ToolsDir stays a plain MkdirAll; opt/, opt/<tool>/, npm/, npm/bin/ are
// certified).
func ensureManagedDirs(dirs ...string) error {
	for _, dir := range dirs {
		if err := ensureManagedDir(dir); err != nil {
			return err
		}
	}
	return nil
}

func (in *installer) logf(format string, args ...any) {
	in.output(fmt.Sprintf(format, args...))
}

// maxArtifactSize caps tool downloads. Runtimes (Go toolchain, JRE) run
// ~200 MB; anything past this is a broken or hostile URL.
const maxArtifactSize = 1 << 30

// Transient suffixes inside a tool's opt dir: the extraction target
// before a publish, and the superseded tree kept during one. Neither is
// ever a retention candidate.
const (
	stagingSuffix = ".staging"
	backupSuffix  = ".old"
)

// DefaultKeepVersions is how many superseded versions of a tool the
// engine retains when Config.KeepVersions is unset: one, so a bad update
// always has a previous tree under <ToolsDir>/opt/<name>/ to fall back
// to instead of only a re-download.
const DefaultKeepVersions = 1

// downloadAttemptBudget bounds a single download attempt (the retry
// loop sits outside it).
const downloadAttemptBudget = 10 * time.Minute

// install dispatches one tool install and returns what it produced: the
// bins it now owns in the bin dir (symlinks/wrappers), the pm-owned
// bins, and the artifact's verification outcome. prevPM is the tool's
// previously recorded pm bin set (ownership survives updates).
func (in *installer) install(ctx context.Context, name string, t *Tool, aq *AquaPackage, prevPM []string) (installOutcome, error) {
	var out installOutcome
	var err error
	kind, ref, _ := strings.Cut(t.Source, ":")
	switch kind {
	case SourceAqua:
		out.bins, out.checksum, err = in.installAqua(ctx, name, t.Version, aq)
	case SourceNpm:
		out.pmBins, err = in.installNpm(ctx, ref, t.Version, prevPM)
	case SourcePip:
		out.pmBins, err = in.installPip(ctx, ref, t.Version, prevPM)
	case SourceCargo:
		out.bins, err = in.installCargo(ctx, ref, t.Version)
	case SourceGo:
		out.bins, err = in.installGo(ctx, ref, t.Version)
	case SourceRelease:
		out.bins, out.checksum, err = in.installRelease(ctx, name, ref, t.Version, t.Release)
	case SourceApt:
		out.apt = true
		err = in.installApt(ctx, ref)
	case SourceManual:
		out.bins, err = in.installManual(ctx, name, t)
	default:
		return installOutcome{}, fmt.Errorf("unknown source %q", t.Source)
	}
	if err != nil {
		return installOutcome{}, err
	}
	return out, nil
}

// --- aqua / http artifacts ---

// installFromSpec runs the download, verify, extract and link sequence
// over a resolved spec: download, checksum verify (mandatory when the
// definition declares a source), extract into a versioned opt dir,
// symlink declared files into bin. Shared by the aqua and release
// sources so the verify-then-swap ordering is not duplicated.
func (in *installer) installFromSpec(ctx context.Context, name, version string, spec *InstallSpec) (bins []string, checksum string, err error) {
	in.logf("downloading %s", spec.URL)

	tmp, err := os.MkdirTemp(in.toolsDir, ".dl-"+name+"-*")
	if err != nil {
		return nil, "", err
	}
	defer os.RemoveAll(tmp)

	artifact := filepath.Join(tmp, lastPathSegment(spec.URL))
	if derr := in.download(ctx, spec.URL, artifact); derr != nil {
		return nil, "", derr
	}
	checksum, err = in.verifyArtifact(ctx, name, version, artifact, spec)
	if err != nil {
		return nil, "", err
	}

	versDir, err := in.extractAndSwap(ctx, name, version, spec, artifact)
	if err != nil {
		return nil, "", err
	}
	bins, err = in.linkDeclaredFiles(versDir, spec.Files, spec.SearchFiles)
	if err != nil {
		return nil, "", err
	}
	in.logf("installed %s %s (%s)", name, version, strings.Join(bins, ", "))
	return bins, checksum, nil
}

func (in *installer) installAqua(ctx context.Context, name, version string, aq *AquaPackage) (bins []string, checksum string, err error) {
	if aq == nil {
		return nil, "", fmt.Errorf("no aqua definition for %s (catalog missing?)", name)
	}
	spec, err := aq.ResolveSpec(version)
	if err != nil {
		return nil, "", err
	}
	return in.installFromSpec(ctx, name, version, spec)
}

// verifyArtifact enforces the checksum invariant before the download is
// extracted or published, and reports how integrity was established. A
// declared checksum source that fails to resolve, fetch, parse or match
// REFUSES the install; a definition declaring none still installs, but
// logs the tool/version/URL at Warn so the gap is observable rather than
// inferred.
func (in *installer) verifyArtifact(ctx context.Context, name, version, artifact string, spec *InstallSpec) (string, error) {
	switch {
	case spec.ChecksumURL != "":
		if verr := in.verifyChecksum(ctx, artifact, spec); verr != nil {
			return "", in.refuseUnverified(name, version, spec.URL, verr)
		}
		in.logf("checksum verified (%s)", spec.ChecksumAlg)
		return checksumVerified, nil
	case spec.ChecksumDeclared:
		// Declared but unobtainable: resolution produced no source to
		// fetch. Never downgrade to an unverified install.
		return "", in.refuseUnverified(name, version, spec.URL,
			errors.New("the definition declares a checksum source but it resolved to no URL"))
	default:
		in.logger().Warn("toolbelt: installing UNVERIFIED artifact: the definition declares no checksum source",
			"tool", name, "version", version, "url", spec.URL)
		in.logf("WARNING: no checksum source declared for %s %s; installing UNVERIFIED from %s",
			name, version, spec.URL)
		return checksumUnverified, nil
	}
}

// refuseUnverified logs the refusal where an operator will see it and
// returns the error that fails the install.
func (in *installer) refuseUnverified(name, version, url string, cause error) error {
	in.logger().Error("toolbelt: REFUSING install: declared checksum not verified",
		"tool", name, "version", version, "url", url, "error", cause)
	in.logf("REFUSING to install %s %s: declared checksum not verified: %v", name, version, cause)
	return fmt.Errorf("refusing to install %s %s unverified: %w", name, version, cause)
}

// extractAndSwap extracts the artifact into a fresh staging dir and
// atomically swaps it into the versioned opt dir. The backup rename means
// a same-version reinstall has no window where the tool is deleted but
// not yet replaced. Durability: every extracted file and the staged
// directory's entry list are flushed before the publishing rename, and
// the parent directory's entry list is flushed after it; a barrier
// failure restores the previous version rather than leaving a tree the
// engine would prune around.
func (in *installer) extractAndSwap(ctx context.Context, name, version string, spec *InstallSpec, artifact string) (string, error) {
	// The version is a path component from here on, and only the sources
	// routed through this function have that constraint (see
	// versionpolicy.go). Asserting it here is what stops a wider
	// grammar's value reaching the join if another source is wired in.
	if !versionPathComponent(version) {
		return "", fmt.Errorf("refusing to install %s: version %q is not a path component", name, version)
	}
	versDir := filepath.Join(in.optDir(), name, version)
	staging := versDir + stagingSuffix
	if err := os.RemoveAll(staging); err != nil {
		return "", err
	}
	// The mode certified on staging carries across: the publish below is
	// a rename of this same inode.
	if err := ensureManagedDirs(in.optDir(), filepath.Join(in.optDir(), name), staging); err != nil {
		return "", err
	}
	binName := name
	if len(spec.Files) > 0 {
		binName = spec.Files[0].Name
	}
	if err := extractArtifact(ctx, artifact, spec.Format, staging, binName); err != nil {
		return "", err
	}
	if err := syncTree(staging); err != nil {
		return "", fmt.Errorf("flush staged install of %s %s: %w", name, version, err)
	}
	backup := versDir + backupSuffix
	if err := os.RemoveAll(backup); err != nil {
		return "", err
	}
	if _, err := os.Stat(versDir); err == nil {
		if err := os.Rename(versDir, backup); err != nil {
			return "", err
		}
	}
	if err := os.Rename(staging, versDir); err != nil {
		restoreBackup(versDir, backup)
		return "", err
	}
	if err := fsyncDir(filepath.Dir(versDir)); err != nil {
		// The rename is visible but not committed: undo it so the
		// previous version stays the live one and the install fails.
		_ = os.RemoveAll(versDir)
		restoreBackup(versDir, backup)
		return "", fmt.Errorf("commit install of %s %s: %w", name, version, err)
	}
	_ = os.RemoveAll(backup)
	return versDir, nil
}

// restoreBackup puts a superseded version tree back after a failed
// publish. Best-effort: the failure path already returns an error, and a
// missing backup simply means there was no previous version.
func restoreBackup(versDir, backup string) {
	if _, err := os.Stat(backup); err != nil {
		return
	}
	_ = os.Rename(backup, versDir)
}

// linkDeclaredFiles resolves and symlinks each declared binary from the
// install dir into the bin dir, returning the linked bin names. When
// search is set the declared paths are guesses and a miss falls back to
// finding the file in the tree (see InstallSpec.SearchFiles).
func (in *installer) linkDeclaredFiles(versDir string, files []AquaFile, search bool) ([]string, error) {
	// The install dir IS the confinement boundary for every declared
	// file, so the Root is constructed once here rather than at each
	// check: pathinside/v2 buys its misuse-resistance at the
	// construction site.
	installRoot := pathinside.Root(versDir)
	var bins []string
	for _, f := range files {
		src := cmp.Or(f.Src, f.Name)
		target, err := safeJoin(installRoot, src)
		if err != nil {
			return nil, err
		}
		if search {
			found, ferr := searchInstallTree(versDir, target, path.Base(src))
			if ferr != nil {
				// One name of a guessed set going missing is upstream's
				// business, not a failure of this install: a registry
				// list that outran the release still installs everything
				// the artifact does contain. The empty check below is
				// what keeps that from degrading into a silent no-op.
				in.logf("skipping %s: %v", f.Name, ferr)
				continue
			}
			target = found
		}
		resolved, err := resolveInsideInstall(installRoot, target, src)
		if err != nil {
			return nil, err
		}
		if err := in.linkBin(f.Name, resolved); err != nil {
			return nil, err
		}
		bins = append(bins, f.Name)
	}
	if len(bins) == 0 {
		// Reachable only through the search path, where a miss is
		// tolerated per name. An install that published nothing is a
		// failed install however many names it skipped, or the tool
		// would read as present with no way to run it.
		return nil, fmt.Errorf("the artifact contains none of the %d declared executables", len(files))
	}
	return bins, nil
}

// resolveInsideInstall resolves one declared file to a real path proven
// to sit inside the install dir, and leaves it executable. Symlinks are
// resolved BEFORE stat/chmod/link, because tar/unzip faithfully recreate
// symlink members even though they sanitize .. and absolute paths.
// Residual gap: containment is a name-based TOCTOU, since no inode
// identity carries into enforceExecutable's open or linkBin's publish.
func resolveInsideInstall(installRoot pathinside.Root, target, src string) (string, error) {
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		return "", fmt.Errorf("declared file %s missing after extract: %w", src, err)
	}
	if !insideStrictly(installRoot, resolved) {
		return "", fmt.Errorf("declared file %s escapes the install dir via symlink", src)
	}
	if err := enforceExecutable(resolved); err != nil {
		return "", err
	}
	return resolved, nil
}

// searchInstallTree resolves a GUESSED path: returns guess unchanged when
// a regular file is there, else finds the executable named base inside
// root, else falls back to the artifact's only executable — a FALLBACK
// so a matching guess is never re-litigated. Ranking is a total order
// (shallowest first, then a bin/ parent, then lexicographic) so a
// re-run cannot pick a different file; foreign-OS paths are dropped
// first, only when something is left to fall back to.
func searchInstallTree(root, guess, base string) (string, error) {
	// Regular file, not a directory: pandoc's archive carries a
	// share/pandoc data dir a name-only check would resolve to.
	if fi, err := os.Stat(guess); err == nil && fi.Mode().IsRegular() {
		return guess, nil
	}
	named, executable, err := walkInstallTree(root, base)
	if err != nil {
		return "", err
	}
	cands := named
	if len(cands) == 0 {
		// Nothing carries the name. An archive holding exactly ONE
		// executable has no ambiguity to resolve, and it is a common shape
		// precisely because the packager expected the consumer to rename
		// it: SwiftFormat's linux zip contains one file, `swiftformat_linux`,
		// named after the ASSET rather than the tool. Two or more and this
		// abstains, because guessing which of several binaries the caller
		// meant is how the wrong tool ends up on PATH.
		if len(executable) != 1 {
			return "", fmt.Errorf("%s is not in the artifact: no file named %s was extracted, "+
				"and it holds %d executables rather than one", base, base, len(executable))
		}
		cands = executable
	}
	if kept := rejectForeignOSPaths(root, cands); len(kept) > 0 {
		cands = kept
	}
	slices.SortFunc(cands, func(a, b string) int {
		if c := cmp.Compare(pathDepth(a), pathDepth(b)); c != 0 {
			return c
		}
		if c := cmp.Compare(binDirRank(b), binDirRank(a)); c != 0 {
			return c
		}
		return cmp.Compare(a, b)
	})
	return cands[0], nil
}

// walkInstallTree returns the regular files under root named base, and
// separately every regular file carrying an execute bit. tar and unzip
// both preserve archive modes, so the executable set is upstream's own
// statement about which members are programs.
func walkInstallTree(root, base string) (named, executable []string, err error) {
	// WalkDir does not follow symlinks, so a link planted by the archive
	// cannot walk the search out of the tree. The candidate still goes
	// through the caller's EvalSymlinks and containment checks.
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if d.Name() == base {
			named = append(named, p)
		}
		fi, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		if fi.Mode().Perm()&0o111 != 0 {
			executable = append(executable, p)
		}
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("search the install tree for %s: %w", base, err)
	}
	return named, executable, nil
}

// rejectForeignOSPaths drops candidates whose path inside root names an
// operating system that is not this one.
func rejectForeignOSPaths(root string, cands []string) []string {
	out := make([]string, 0, len(cands))
	for _, p := range cands {
		rel, err := filepath.Rel(root, p)
		if err != nil {
			rel = p
		}
		if !hasAnyToken(rel, releaseForeignOS) {
			out = append(out, p)
		}
	}
	return out
}

// pathDepth counts a path's separators, the sort's primary key.
func pathDepth(p string) int { return strings.Count(p, string(filepath.Separator)) }

// binDirRank scores a candidate whose parent directory is bin, the
// convention a nested archive follows when it has one.
func binDirRank(p string) int {
	if filepath.Base(filepath.Dir(p)) == "bin" {
		return 1
	}
	return 0
}

// download fetches url to dest with a size cap, retrying transient
// failures (a fresh attempt truncates and rewrites dest).
func (in *installer) download(ctx context.Context, rawURL, dest string) error {
	_, err := httpx.Do(ctx, func(ctx context.Context) (struct{}, error) {
		return struct{}{}, in.downloadOnce(ctx, rawURL, dest)
	}, httpx.WithMaxAttempts(2), httpx.WithLabel("download "+lastPathSegment(rawURL)))
	return err
}

func (in *installer) downloadOnce(ctx context.Context, rawURL, dest string) error {
	ctx, cancel := context.WithTimeout(ctx, downloadAttemptBudget)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return err
	}
	res, err := in.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return httpx.CheckHTTPStatus(res)
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(res.Body, maxArtifactSize+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n > maxArtifactSize {
		return httpx.Permanent(fmt.Errorf("artifact exceeds %d byte cap", int64(maxArtifactSize)))
	}
	in.logf("downloaded %s (%.1f MB)", filepath.Base(dest), float64(n)/1e6)
	return nil
}

// verifyChecksum fetches the checksum artifact and compares the
// download's digest. The checksum file may be a bare digest or the
// standard "digest  filename" list (sha256sum style).
func (in *installer) verifyChecksum(ctx context.Context, artifact string, spec *InstallSpec) error {
	body, err := httpx.GetBytes(ctx, in.client, spec.ChecksumURL,
		httpx.WithMaxAttempts(3), httpx.WithMaxBodyBytes(1<<20))
	if err != nil {
		return fmt.Errorf("fetch checksum: %w", err)
	}
	want := findChecksum(string(body), filepath.Base(artifact), spec.ChecksumAlg)
	if want == "" {
		return fmt.Errorf("checksum file has no entry for %s", filepath.Base(artifact))
	}

	var h hash.Hash
	switch spec.ChecksumAlg {
	case algSHA256:
		h = sha256.New()
	case "sha512":
		h = sha512.New()
	default:
		return fmt.Errorf("unsupported checksum algorithm %q", spec.ChecksumAlg)
	}
	f, err := os.Open(artifact)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("checksum mismatch: want %s, got %s", want, got)
	}
	return nil
}

// findChecksum extracts asset's digest for the given algorithm from a
// checksum file body: a bare digest, the coreutils "digest  name" table
// (binary mode prefixes name with *), or BSD "SHA512 (name) = digest".
// The algorithm is part of the match, since BSD files often list
// several per asset (mikefarah/yq's checksums-bsd) and digest-length
// filtering keeps a CRC32/MD5 line from being read as a sha512.
func findChecksum(body, asset, alg string) string {
	wantLen := map[string]int{algSHA256: 64, "sha512": 128}[alg]
	if wantLen == 0 {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(body), "\n")
	if len(lines) == 1 && isHexDigest(strings.TrimSpace(lines[0]), wantLen) {
		return strings.TrimSpace(lines[0]) // bare digest file
	}
	for _, line := range lines {
		if d := checksumFromLine(strings.Fields(line), asset, alg, wantLen); d != "" {
			return d
		}
	}
	return ""
}

// checksumFromLine matches one checksum-file line against asset+alg:
// BSD style ("SHA512 (name) = digest", tag dashed or not) or coreutils
// style ("digest  name", * prefix tolerated).
func checksumFromLine(fields []string, asset, alg string, wantLen int) string {
	if len(fields) < 2 {
		return ""
	}
	bsdTag := strings.ToUpper(alg)                           // SHA512
	bsdTagDashed := strings.ToUpper(alg[:3]) + "-" + alg[3:] // SHA-512
	if len(fields) == 4 && (fields[0] == bsdTag || fields[0] == bsdTagDashed) &&
		strings.Trim(fields[1], "()") == asset && isHexDigest(fields[3], wantLen) {
		return fields[3]
	}
	nameField := strings.TrimPrefix(fields[len(fields)-1], "*")
	if filepath.Base(nameField) == asset && isHexDigest(fields[0], wantLen) {
		return fields[0]
	}
	return ""
}

// isHexDigest reports whether s is exactly n hex characters.
func isHexDigest(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

// pruneOldVersions removes superseded versioned install dirs, keeping the
// current version plus the `keep` most recent previous ones (see
// retained) so a bad update has a fallback. Best-effort: a failure is
// logged and disk is left as-is.
func (in *installer) pruneOldVersions(name, current string, keep int) {
	root := filepath.Join(in.optDir(), name)
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, victim := range prunable(entries, current, keep) {
		if err := os.RemoveAll(filepath.Join(root, victim)); err != nil {
			in.logf("could not prune %s/%s: %v", name, victim, err)
			continue
		}
		in.logf("pruned old version %s/%s", name, victim)
	}
}

// prunable selects entries under a tool's opt root that go: never the
// current version, always transient .staging/.old residue, and the
// remaining superseded versions newest-first (mtime, name tiebreak)
// past the first `retained`.
func prunable(entries []os.DirEntry, current string, keep int) []string {
	type candidate struct {
		modTime time.Time
		name    string
	}
	var victims []string
	var supers []candidate
	for _, e := range entries {
		switch name := e.Name(); {
		case name == current:
		case strings.HasSuffix(name, stagingSuffix), strings.HasSuffix(name, backupSuffix):
			victims = append(victims, name)
		default:
			var mod time.Time
			if fi, err := e.Info(); err == nil {
				mod = fi.ModTime()
			}
			supers = append(supers, candidate{modTime: mod, name: name})
		}
	}
	slices.SortFunc(supers, func(a, b candidate) int {
		if !a.modTime.Equal(b.modTime) {
			return b.modTime.Compare(a.modTime)
		}
		return strings.Compare(b.name, a.name)
	})
	for _, c := range supers[min(retained(keep), len(supers)):] {
		victims = append(victims, c.name)
	}
	return victims
}

// retained normalizes a configured retention count: 0 (unset) means
// DefaultKeepVersions, and a negative value keeps none (the
// prune-everything-superseded behavior).
func retained(keep int) int {
	switch {
	case keep == 0:
		return DefaultKeepVersions
	case keep < 0:
		return 0
	default:
		return keep
	}
}

// linkBin force-replaces bin/<name> with a symlink to target and flushes
// the bin dir's entry list, so a published PATH entry survives a crash.
// A failed barrier restores the previous link: the install is failing, and
// the tool that was on PATH before must stay the one on PATH.
func (in *installer) linkBin(name, target string) error {
	if err := ensureManagedDir(in.binDir()); err != nil {
		return err
	}
	link := filepath.Join(in.binDir(), name)
	prev, hadPrev := os.Readlink(link)
	if err := os.RemoveAll(link); err != nil {
		return err
	}
	if err := os.Symlink(target, link); err != nil {
		return err
	}
	if err := fsyncDir(in.binDir()); err != nil {
		_ = os.Remove(link)
		if hadPrev == nil {
			_ = os.Symlink(prev, link)
		}
		return fmt.Errorf("commit bin link %s: %w", name, err)
	}
	return nil
}

// --- package-manager backends ---

// pmEnv builds the environment for package-manager subprocesses: the
// engine's bin dir leads PATH so freshly installed runtimes resolve.
func (in *installer) pmEnv() []string {
	env := os.Environ()
	pathValue := in.binDir() + string(os.PathListSeparator) + os.Getenv("PATH")
	out := env[:0]
	for _, e := range env {
		if strings.HasPrefix(e, "PATH=") {
			continue
		}
		out = append(out, e)
	}
	return append(out,
		"PATH="+pathValue,
		"GOBIN="+in.binDir(),
		"GOPATH="+filepath.Join(in.toolsDir, "go"),
		"NPM_CONFIG_PREFIX="+in.npmDir(),
		// uv tool install: per-tool venvs + launcher dir on the
		// persistent tools tree (the managed interpreter lands under
		// $HOME/.local/share/uv, which is also on the volume).
		"UV_TOOL_DIR="+filepath.Join(in.pythonDir(), "tools"),
		"UV_TOOL_BIN_DIR="+filepath.Join(in.pythonDir(), "bin"),
	)
}

// runPM runs a package-manager command, streaming its combined output
// line by line into the job log.
func (in *installer) runPM(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = in.pmEnv()
	return in.streamCmd(cmd, name)
}

func (in *installer) streamCmd(cmd *exec.Cmd, label string) error {
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	var pending strings.Builder
	for {
		n, rerr := pipe.Read(buf)
		if n > 0 {
			pending.WriteString(string(buf[:n]))
			in.drainLines(&pending)
		}
		if rerr != nil {
			break
		}
	}
	if tail := strings.TrimSpace(pending.String()); tail != "" {
		in.output(tail)
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("%s failed: %w", label, err)
	}
	return nil
}

// drainLines emits every complete (newline-terminated) line buffered in
// pending, leaving any trailing partial line behind for the next read.
func (in *installer) drainLines(pending *strings.Builder) {
	for {
		line, rest, found := strings.Cut(pending.String(), "\n")
		if !found {
			return
		}
		if trimmed := strings.TrimRight(line, "\r"); trimmed != "" {
			in.output(trimmed)
		}
		pending.Reset()
		pending.WriteString(rest)
	}
}

// binDiff snapshots dir before fn and returns entries added by fn.
func (in *installer) binDiff(dir string, fn func() error) ([]string, error) {
	before := map[string]bool{}
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			before[e.Name()] = true
		}
	}
	if err := fn(); err != nil {
		return nil, err
	}
	var added []string
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if !before[e.Name()] {
				added = append(added, e.Name())
			}
		}
	}
	slices.Sort(added)
	return added, nil
}

// installNpm installs one npm package globally under the engine's npm
// prefix and symlinks its new bins into the bin dir.
func (in *installer) installNpm(ctx context.Context, pkg, version string, prev []string) ([]string, error) {
	if err := ensureManagedDirs(in.npmDir(), filepath.Join(in.npmDir(), "bin")); err != nil {
		return nil, err
	}
	pmBin := filepath.Join(in.npmDir(), "bin")
	added, err := in.binDiff(pmBin, func() error {
		return in.runPM(ctx, "npm", "install", "-g", "--prefix", in.npmDir(), pkg+"@"+version)
	})
	if err != nil {
		return nil, err
	}
	return in.linkPMBins(pmBin, added, prev, pkg)
}

// installPip installs one PyPI CLI tool via `uv tool install` (the
// pipx-equivalent primitive: isolated per-tool venv, self-contained
// launcher). `uv pip install --prefix` was tried first and rejected —
// its launcher points at the managed interpreter without the prefix's
// site-packages, so every entry point dies with ModuleNotFoundError.
func (in *installer) installPip(ctx context.Context, pkg, version string, prev []string) ([]string, error) {
	if err := ensureManagedDirs(in.pythonDir(), filepath.Join(in.pythonDir(), "bin")); err != nil {
		return nil, err
	}
	pmBin := filepath.Join(in.pythonDir(), "bin")
	added, err := in.binDiff(pmBin, func() error {
		return in.runPM(ctx, "uv", "tool", "install", "--reinstall", pkg+"=="+version)
	})
	if err != nil {
		return nil, err
	}
	return in.linkPMBins(pmBin, added, prev, pkg)
}

// linkPMBins symlinks package-manager bin entries into the engine bin
// dir and returns the tool's owned bin set: the union of previously
// recorded bins still present in the pm dir and the diff's new names —
// a reinstall creates no new entries, so trusting the diff alone would
// clobber ownership of multi-bin packages (tsc + tsserver). Falls back
// to the package's conventional bin name for a first install that
// created nothing new.
func (in *installer) linkPMBins(pmBin string, added, prev []string, pkg string) ([]string, error) {
	owned := map[string]bool{}
	for _, b := range prev {
		if _, err := os.Stat(filepath.Join(pmBin, b)); err == nil {
			owned[b] = true
		}
	}
	for _, b := range added {
		owned[b] = true
	}
	if len(owned) == 0 {
		base := pkgBinName(pkg)
		if _, err := os.Stat(filepath.Join(pmBin, base)); err == nil {
			owned[base] = true
		}
	}
	out := make([]string, 0, len(owned))
	for b := range owned {
		if err := in.linkBin(b, filepath.Join(pmBin, b)); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	slices.Sort(out)
	return out, nil
}

// pkgBinName maps a package ref to its conventional bin name
// (@scope/name -> name).
func pkgBinName(pkg string) string {
	if _, name, found := strings.CutLast(pkg, "/"); found {
		return name
	}
	return pkg
}

// installCargo builds/installs a crate with binaries landing directly
// in the engine bin dir (cargo --root writes <root>/bin).
func (in *installer) installCargo(ctx context.Context, crate, version string) ([]string, error) {
	return in.binDiff(in.binDir(), func() error {
		return in.runPM(ctx, "cargo", "install", crate,
			"--version", strings.TrimPrefix(version, "v"), "--root", in.toolsDir)
	})
}

// installGo `go install`s a module with GOBIN pointed at the bin dir.
func (in *installer) installGo(ctx context.Context, module, version string) ([]string, error) {
	ver := version
	if !strings.HasPrefix(ver, "v") {
		ver = "v" + ver
	}
	return in.binDiff(in.binDir(), func() error {
		return in.runPM(ctx, "go", "install", module+"@"+ver)
	})
}

// installManual runs a user-provided shell command with the engine's
// path variables exported. The command is responsible for placing
// binaries in $BIN (or $OPT for larger trees).
func (in *installer) installManual(ctx context.Context, name string, t *Tool) ([]string, error) {
	if strings.TrimSpace(t.Install) == "" {
		return nil, fmt.Errorf("manual tool %s has no install command", name)
	}
	optDir := filepath.Join(in.optDir(), name)
	if err := ensureManagedDirs(in.optDir(), optDir); err != nil {
		return nil, err
	}
	added, err := in.binDiff(in.binDir(), func() error {
		return in.runShell(ctx, t.Install, t.Version, optDir)
	})
	if err != nil {
		return nil, err
	}
	probe := t.Probe
	if probe == "" {
		probe = name
	}
	if _, err := os.Stat(filepath.Join(in.binDir(), probe)); err != nil {
		return nil, fmt.Errorf("install command finished but %s is not in the bin dir", probe)
	}
	if !slices.Contains(added, probe) {
		added = append(added, probe)
	}
	return added, nil
}

// runShell executes a manual install/uninstall command under bash with
// the documented variables in the environment. The arch spellings
// cover the naming conventions upstream release artifacts actually use
// (self-documenting OR names: the value is the left side on amd64, the
// right side on arm64).
func (in *installer) runShell(ctx context.Context, command, version, optDir string) error {
	cmd := exec.CommandContext(ctx, "bash", "-c", command)
	arm := runtime.GOARCH == goarchARM64
	pick := func(amd, a64 string) string {
		if arm {
			return a64
		}
		return amd
	}
	cmd.Env = append(in.pmEnv(),
		"VERSION="+version,
		"VERSION_NOPFX="+strings.TrimPrefix(version, "v"),
		"BIN="+in.binDir(),
		"TOOLS="+in.toolsDir,
		"OPT="+optDir,
		"ARCH_AMD64_OR_ARM64="+pick(goarchAMD64, goarchARM64),
		"ARCH_X64_OR_ARM64="+pick("x64", goarchARM64),
		"ARCH_X86_64_OR_AARCH64="+pick("x86_64", "aarch64"),
		"ARCH_X64_OR_AARCH64="+pick("x64", "aarch64"),
		"ARCH_X86_64_OR_ARM64="+pick("x86_64", goarchARM64),
	)
	return in.streamCmd(cmd, "install command")
}

// --- uninstall ---

// uninstall removes a tool's engine-owned footprint: recorded bin
// symlinks, versioned opt dirs, and (for pm backends) the package
// itself. It never touches files the engine has no record of.
func (in *installer) uninstall(ctx context.Context, name string, t *Tool, st *ToolStatus) error {
	kind, ref, _ := strings.Cut(t.Source, ":")
	if kind == SourceApt {
		// Nothing recorded to undo (its files are in /usr, not this
		// engine's bin/opt), and removing the package could take an
		// image dependency with it. Dropping the entry stops it being
		// reinstalled; a container recreate removes the rest.
		in.logf("dropped the %s entry; the Debian package stays until the container is recreated (apt packages are not on the persistent volume)", name)
		return nil
	}
	switch kind {
	case SourceNpm:
		if err := in.runPM(ctx, "npm", "uninstall", "-g", "--prefix", in.npmDir(), ref); err != nil {
			in.logf("npm uninstall failed (continuing): %v", err)
		}
	case SourcePip:
		if err := in.runPM(ctx, "uv", "tool", "uninstall", ref); err != nil {
			in.logf("uv tool uninstall failed (continuing): %v", err)
		}
	case SourceManual:
		if strings.TrimSpace(t.Uninstall) != "" {
			if err := in.runShell(ctx, t.Uninstall, t.Version, filepath.Join(in.optDir(), name)); err != nil {
				in.logf("uninstall command failed (continuing): %v", err)
			}
		}
	}
	for _, b := range append(append([]string{}, st.Bins...), st.PMBins...) {
		link := filepath.Join(in.binDir(), b)
		if err := os.Remove(link); err == nil {
			in.logf("removed %s", b)
		}
	}
	if err := os.RemoveAll(filepath.Join(in.optDir(), name)); err != nil {
		return err
	}
	in.logf("uninstalled %s", name)
	return nil
}
