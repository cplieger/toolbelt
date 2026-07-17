package toolbelt

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/cplieger/httpx/v3"
)

// installer executes install/uninstall plans for every source kind.
// It is owned by the Engine and always invoked from the single job
// worker goroutine, so no internal locking is needed.
type installer struct {
	client *http.Client
	// output receives human-readable progress lines (wired to the
	// running job's ring buffer + the OnJobOutput callback).
	output   func(line string)
	toolsDir string
}

func (in *installer) binDir() string    { return filepath.Join(in.toolsDir, "bin") }
func (in *installer) optDir() string    { return filepath.Join(in.toolsDir, "opt") }
func (in *installer) npmDir() string    { return filepath.Join(in.toolsDir, "npm") }
func (in *installer) pythonDir() string { return filepath.Join(in.toolsDir, "python") }

func (in *installer) logf(format string, args ...any) {
	in.output(fmt.Sprintf(format, args...))
}

// maxArtifactSize caps tool downloads. Runtimes (Go toolchain, JRE) run
// ~200 MB; anything past this is a broken or hostile URL.
const maxArtifactSize = 1 << 30

// downloadAttemptBudget bounds a single download attempt (the retry
// loop sits outside it).
const downloadAttemptBudget = 10 * time.Minute

// install dispatches one tool install and returns the bins it now owns
// in the bin dir (symlinks/wrappers) plus pm-owned bins. prevPM is the
// tool's previously recorded pm bin set (ownership survives updates).
func (in *installer) install(ctx context.Context, name string, t *Tool, aq *AquaPackage, prevPM []string) (bins, pmBins []string, err error) {
	kind, ref, _ := strings.Cut(t.Source, ":")
	switch kind {
	case SourceAqua:
		bins, err = in.installAqua(ctx, name, t.Version, aq)
	case SourceNpm:
		pmBins, err = in.installNpm(ctx, ref, t.Version, prevPM)
	case SourcePip:
		pmBins, err = in.installPip(ctx, ref, t.Version, prevPM)
	case SourceCargo:
		bins, err = in.installCargo(ctx, ref, t.Version)
	case SourceGo:
		bins, err = in.installGo(ctx, ref, t.Version)
	case SourceManual:
		bins, err = in.installManual(ctx, name, t)
	default:
		return nil, nil, fmt.Errorf("unknown source %q", t.Source)
	}
	if err != nil {
		return nil, nil, err
	}
	// Write the entry's shims (extra wrapper scripts) last so they can
	// reference the just-installed binaries.
	for shim, cmdline := range t.Shims {
		if werr := in.writeShim(shim, cmdline); werr != nil {
			return nil, nil, werr
		}
		in.logf("shim: %s -> %s", shim, cmdline)
		bins = append(bins, shim)
	}
	return bins, pmBins, nil
}

// --- aqua / http artifacts ---

// installAqua downloads and places a binary artifact per the resolved
// aqua spec: download, checksum verify when the definition declares a
// source, extract into a versioned opt dir, symlink the declared files
// into bin.
func (in *installer) installAqua(ctx context.Context, name, version string, aq *AquaPackage) ([]string, error) {
	if aq == nil {
		return nil, fmt.Errorf("no aqua definition for %s (catalog missing?)", name)
	}
	spec, err := aq.ResolveSpec(version)
	if err != nil {
		return nil, err
	}
	in.logf("downloading %s", spec.URL)

	tmp, err := os.MkdirTemp(in.toolsDir, ".dl-"+name+"-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	artifact := filepath.Join(tmp, lastPathSegment(spec.URL))
	if derr := in.download(ctx, spec.URL, artifact); derr != nil {
		return nil, derr
	}
	if spec.ChecksumURL != "" {
		if verr := in.verifyChecksum(ctx, artifact, spec); verr != nil {
			return nil, verr
		}
		in.logf("checksum verified (%s)", spec.ChecksumAlg)
	} else {
		in.logf("no checksum source declared; installing unverified")
	}

	versDir, err := in.extractAndSwap(ctx, name, version, spec, artifact)
	if err != nil {
		return nil, err
	}
	bins, err := in.linkDeclaredFiles(versDir, spec.Files)
	if err != nil {
		return nil, err
	}

	// Prune superseded versions now that the new one is linked.
	in.pruneOldVersions(name, version)
	in.logf("installed %s %s (%s)", name, version, strings.Join(bins, ", "))
	return bins, nil
}

// extractAndSwap extracts the artifact into a fresh staging dir and
// atomically swaps it into the versioned opt dir. The backup rename
// means a same-version reinstall never has a window where the tool is
// deleted but the replacement rename hasn't happened.
func (in *installer) extractAndSwap(ctx context.Context, name, version string, spec *InstallSpec, artifact string) (string, error) {
	versDir := filepath.Join(in.optDir(), name, version)
	staging := versDir + ".staging"
	if err := os.RemoveAll(staging); err != nil {
		return "", err
	}
	if err := os.MkdirAll(staging, 0o755); err != nil {
		return "", err
	}
	binName := name
	if len(spec.Files) > 0 {
		binName = spec.Files[0].Name
	}
	if err := extractArtifact(ctx, artifact, spec.Format, staging, binName); err != nil {
		return "", err
	}
	backup := versDir + ".old"
	if err := os.RemoveAll(backup); err != nil {
		return "", err
	}
	if _, err := os.Stat(versDir); err == nil {
		if err := os.Rename(versDir, backup); err != nil {
			return "", err
		}
	}
	if err := os.Rename(staging, versDir); err != nil {
		if _, berr := os.Stat(backup); berr == nil {
			_ = os.Rename(backup, versDir) // restore on failure
		}
		return "", err
	}
	_ = os.RemoveAll(backup)
	return versDir, nil
}

// linkDeclaredFiles resolves and symlinks each declared binary from the
// install dir into the bin dir, returning the linked bin names.
func (in *installer) linkDeclaredFiles(versDir string, files []AquaFile) ([]string, error) {
	var bins []string
	for _, f := range files {
		src := f.Src
		if src == "" {
			src = f.Name
		}
		target, err := safeJoin(versDir, src)
		if err != nil {
			return nil, err
		}
		// Resolve symlinks BEFORE stat/chmod/link: tar and unzip
		// sanitize .. and absolute member paths (fail-closed on the
		// consumer images, verified), but they faithfully recreate
		// symlink members — a malicious archive could point the
		// declared file at a path outside the install tree, and a
		// follow-symlink chmod + a published bin/ link would escape
		// the sandbox.
		resolved, err := filepath.EvalSymlinks(target)
		if err != nil {
			return nil, fmt.Errorf("declared file %s missing after extract: %w", src, err)
		}
		if _, err := safeJoin(versDir, mustRel(versDir, resolved)); err != nil {
			return nil, fmt.Errorf("declared file %s escapes the install dir via symlink", src)
		}
		if err := os.Chmod(resolved, 0o755); err != nil {
			return nil, err
		}
		if err := in.linkBin(f.Name, resolved); err != nil {
			return nil, err
		}
		bins = append(bins, f.Name)
	}
	return bins, nil
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
	case "sha256":
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
// checksum file body. Real-world formats covered: a bare digest, the
// coreutils "digest  name" table (binary mode prefixes the name with
// *), and BSD style "SHA512 (name) = digest". The algorithm is part of
// the match: BSD files often list SEVERAL algorithms per asset
// (mikefarah/yq's checksums-bsd), and coreutils-style multi-hash
// tables put the name first — digest-length and tag filtering keep a
// CRC32/MD5 line from being returned as a sha512 (found the hard way
// on the borgcube migration; the mismatch failed closed, as designed,
// but with a misleading "want" value).
func findChecksum(body, asset, alg string) string {
	wantLen := map[string]int{"sha256": 64, "sha512": 128}[alg]
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

// pruneOldVersions removes superseded versioned install dirs, keeping
// only current. Best-effort.
func (in *installer) pruneOldVersions(name, current string) {
	root := filepath.Join(in.optDir(), name)
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.Name() == current {
			continue
		}
		if err := os.RemoveAll(filepath.Join(root, e.Name())); err == nil {
			in.logf("pruned old version %s/%s", name, e.Name())
		}
	}
}

// linkBin force-replaces bin/<name> with a symlink to target.
func (in *installer) linkBin(name, target string) error {
	if err := os.MkdirAll(in.binDir(), 0o755); err != nil {
		return err
	}
	link := filepath.Join(in.binDir(), name)
	if err := os.RemoveAll(link); err != nil {
		return err
	}
	return os.Symlink(target, link)
}

// writeShim creates a wrapper script in bin that execs cmdline.
func (in *installer) writeShim(name, cmdline string) error {
	if err := os.MkdirAll(in.binDir(), 0o755); err != nil {
		return err
	}
	body := fmt.Sprintf("#!/bin/sh\nexec %s \"$@\"\n", cmdline)
	path := filepath.Join(in.binDir(), filepath.Base(name))
	// Created 0o600; the Chmod grants exec (a shim must be runnable).
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = f.WriteString(body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Chmod(path, 0o755)
}

// --- package-manager backends ---

// pmEnv builds the environment for package-manager subprocesses: the
// engine's bin dir leads PATH so freshly installed runtimes resolve.
func (in *installer) pmEnv() []string {
	env := os.Environ()
	path := in.binDir() + string(os.PathListSeparator) + os.Getenv("PATH")
	out := env[:0]
	for _, e := range env {
		if strings.HasPrefix(e, "PATH=") {
			continue
		}
		out = append(out, e)
	}
	return append(out,
		"PATH="+path,
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
	if err := os.MkdirAll(filepath.Join(in.npmDir(), "bin"), 0o755); err != nil {
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

// installPip installs one PyPI CLI tool via `uv tool install` — the
// pipx-equivalent primitive: uv provisions a managed CPython when none
// exists on PATH, each tool gets an isolated venv under UV_TOOL_DIR,
// and the launchers uv drops in UV_TOOL_BIN_DIR are self-contained
// (venv-backed shebangs). A bare `uv pip install --prefix` was tried
// first and REJECTED: its launchers point at the managed interpreter
// without the prefix's site-packages, so every entry point dies with
// ModuleNotFoundError.
func (in *installer) installPip(ctx context.Context, pkg, version string, prev []string) ([]string, error) {
	if err := os.MkdirAll(filepath.Join(in.pythonDir(), "bin"), 0o755); err != nil {
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
// dir and returns the tool's owned bin set. The set is the union of
// the previously recorded bins that still exist in the pm dir and the
// diff's newly created names — a reinstall/update creates NO new
// entries (the launchers already exist), so trusting the diff alone
// would clobber ownership of multi-bin packages (typescript: tsc +
// tsserver) and make them read as uninstalled. Falls back to the
// package's conventional bin name for a first install that created
// nothing new.
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
	if i := strings.LastIndex(pkg, "/"); i >= 0 {
		return pkg[i+1:]
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
	if err := os.MkdirAll(optDir, 0o755); err != nil {
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
	arm := runtime.GOARCH == "arm64"
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
		"ARCH_AMD64_OR_ARM64="+pick("amd64", "arm64"),
		"ARCH_X64_OR_ARM64="+pick("x64", "arm64"),
		"ARCH_X86_64_OR_AARCH64="+pick("x86_64", "aarch64"),
		"ARCH_X64_OR_AARCH64="+pick("x64", "aarch64"),
		"ARCH_X86_64_OR_ARM64="+pick("x86_64", "arm64"),
	)
	return in.streamCmd(cmd, "install command")
}

// --- uninstall ---

// uninstall removes a tool's engine-owned footprint: recorded bin
// symlinks/shims, versioned opt dirs, and (for pm backends) the
// package itself. It never touches files the engine has no record of.
func (in *installer) uninstall(ctx context.Context, name string, t *Tool, st *ToolStatus) error {
	kind, ref, _ := strings.Cut(t.Source, ":")
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
	for shim := range t.Shims {
		_ = os.Remove(filepath.Join(in.binDir(), shim))
	}
	if err := os.RemoveAll(filepath.Join(in.optDir(), name)); err != nil {
		return err
	}
	in.logf("uninstalled %s", name)
	return nil
}
