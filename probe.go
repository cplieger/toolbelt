package toolbelt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cplieger/keyenc"
)

// probeTimeout bounds one probe execution: generous enough for a
// JVM-class tool's cold start on a loaded volume (the verdict is cached
// per binary, so this is paid once per install, not per read), short
// enough that a wedged tool cannot stall an inventory read.
// probeWaitDelay bounds the wait for a killed process's output pipes, so
// a child that outlives its parent cannot hang the probe either.
const (
	probeTimeout   = 10 * time.Second
	probeWaitDelay = 2 * time.Second
)

// probeOutputCap bounds how much of a probe's output is buffered. Version
// banners are bytes; a tool that ignores its arguments and streams must
// not be able to grow the engine's heap.
const probeOutputCap = 64 << 10

// exitCouldNotExecute is the one exit status that is NOT an answer: 127
// means the dynamic loader, shell, or shebang never ran `main` (missing
// shared library, unresolvable interpreter), so it carries no claim
// about the tool. Every other non-zero status is graded as an answer
// (a tool that rejects --version still proved it can execute).
// Measured cost of missing this distinction: a Node.js missing
// libatomic.so.1 probed clean and every npm tool behind it then failed
// naming the wrong tool.
const exitCouldNotExecute = 127

// defaultVersionArgs is what the probe runs when a definition declares
// no version-reporting shape. It is deliberately NOT an empty argument
// list: language servers (gopls, tsserver, pyright-langserver) start a
// server and block forever when run bare, whereas --version makes
// essentially every CLI exit, and a tool that does not support the flag
// still exits — which is all the exec-only probe asserts.
var defaultVersionArgs = []string{"--version"}

// Probe modes: what a probe actually established about an install.
const (
	// probeModeVersion: the tool ran and reported the recorded version
	// (the definition declared its version-reporting shape).
	probeModeVersion = "exec+version"
	// probeModeExec: the tool ran and answered, but no version shape is
	// declared, so the installed version itself stays unproven.
	probeModeExec = "exec"
	// probeModePresence: the recorded bin cannot be executed at all (not
	// a regular executable file), so only presence was checked. Logged,
	// never presented as verified.
	probeModePresence = "presence"
	// probeModePackage: an npm package that ships no bin, checked
	// against the version in its installed package.json.
	probeModePackage = "package"
)

// probeVerdict is what one probe established.
type probeVerdict struct {
	// Mode is the strongest check that actually ran (probeMode*).
	Mode string
	// Reason explains a failure or a downgrade, for the log line.
	Reason string
	// OK is the install-detection answer: true = installed, false =
	// reinstall.
	OK bool
}

// probeCache memoizes exec probes so Inventory, which a settings UI polls,
// does not spawn a subprocess per tool per call. Presence and a pip: venv's
// interpreter are re-checked on every probe, so a deleted file shows at once.
// The exec verdict is keyed by the probe target's fileIdentity, the recorded
// version, the declared version args and, for a pip: venv, its resolved
// interpreter's fileIdentity, so a reinstall, relink, version bump or
// interpreter change invalidates it without a TTL.
type probeCache struct {
	entries map[string]probeCacheEntry
	mu      sync.Mutex
}

type probeCacheEntry struct {
	fingerprint string
	verdict     probeVerdict
}

// lookup returns the cached verdict for name when it was recorded
// against the same fingerprint.
func (c *probeCache) lookup(name, fingerprint string) (probeVerdict, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[name]
	if !ok || e.fingerprint != fingerprint {
		return probeVerdict{}, false
	}
	return e.verdict, true
}

// store records a fresh verdict.
func (c *probeCache) store(name, fingerprint string, v probeVerdict) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[string]probeCacheEntry{}
	}
	c.entries[name] = probeCacheEntry{fingerprint: fingerprint, verdict: v}
}

// forget drops a tool's cached verdict (install, uninstall).
func (c *probeCache) forget(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, name)
}

// binDir is the single PATH dir the engine publishes into.
func (e *Engine) binDir() string { return binDir(e.toolsDir) }

// probeInstalled reports whether the tool is installed. The recorded bin
// must exist AND execute, and with declared version args the answer must
// contain the recorded version, so a truncated download, a wrong-arch
// binary, a dangling symlink, a dead venv interpreter, or the wrong version
// all read as NOT installed. A present non-executable file falls back to
// presence, at Warn; a file the OS refuses to start is not installed. An apt
// package, and an npm package that ships no bin, are proven by their
// package manager's record instead.
func (e *Engine) probeInstalled(name string, t *Tool, s *ToolStatus) bool {
	return e.probeTool(name, t, s).OK
}

func (e *Engine) probeTool(name string, t *Tool, s *ToolStatus) probeVerdict {
	kind, ref, _ := strings.Cut(t.Source, ":")
	if kind == SourceApt {
		return probeApt(ref)
	}
	var pkgReason string
	if kind == SourceNpm && len(s.Bins)+len(s.PMBins) == 0 {
		v, ok := e.probeNpmPackage(ref, s.InstalledVersion)
		if ok {
			return v
		}
		pkgReason = v.Reason
	}
	v := e.probeBins(name, t, s)
	if !v.OK && pkgReason != "" {
		v.Reason = pkgReason + "; " + v.Reason
	}
	return v
}

// probeBins executes the tool's probe bin, cached per tool and logged once
// per fingerprint change.
func (e *Engine) probeBins(name string, t *Tool, s *ToolStatus) probeVerdict {
	kind, ref, _ := strings.Cut(t.Source, ":")
	bins := recordedBins(name, t, s)
	for _, b := range bins {
		if _, err := os.Stat(filepath.Join(e.binDir(), b)); err != nil {
			return probeVerdict{OK: false, Mode: probeModePresence, Reason: "bin " + b + " is missing"}
		}
	}
	var interpreter string
	if kind == SourcePip {
		var failed probeVerdict
		var ok bool
		if interpreter, failed, ok = e.probePipInterpreter(ref); !ok {
			return failed
		}
	}
	target := filepath.Join(e.binDir(), probeBin(name, t, bins))
	args := t.VersionArgs
	if len(args) == 0 {
		args = defaultVersionArgs
	}
	want := s.InstalledVersion
	fingerprint, err := probeFingerprint(target, want, t.VersionArgs)
	if err != nil {
		return probeVerdict{OK: false, Mode: probeModePresence, Reason: "probe target unusable: " + err.Error()}
	}
	if interpreter != "" {
		fingerprint = keyenc.Join(fingerprint, interpreter)
	}
	if v, ok := e.probes.lookup(name, fingerprint); ok {
		return v
	}
	v := e.runProbe(target, args, want, len(t.VersionArgs) > 0)
	e.probes.store(name, fingerprint, v)
	e.logVerdict(name, v)
	return v
}

// probePipInterpreter checks a pip: venv's interpreter before its launcher
// runs. ok is false with the failed verdict when the interpreter is missing
// or unmanaged; otherwise identity is pipInterpreter's.
func (e *Engine) probePipInterpreter(ref string) (identity string, failed probeVerdict, ok bool) {
	identity, missing, foreign := pipInterpreter(e.toolsDir, ref)
	switch {
	case missing != "":
		return "", probeVerdict{
			OK: false, Mode: probeModePresence,
			Reason: "venv interpreter " + missing + " is missing",
		}, false
	case foreign != "":
		return "", probeVerdict{
			OK: false, Mode: probeModePresence,
			Reason: "venv interpreter " + foreign + " is outside " + pythonInterpreterDir(e.toolsDir),
		}, false
	}
	return identity, probeVerdict{}, true
}

// probeApt asks dpkg, because an apt package may ship no executable at
// all (libc6-dev) and its files sit in /usr, not the engine's bin dir.
// The verdict is deliberately NOT cached: unlike the other sources, an
// apt package can be removed from under the process by anyone with a
// container shell, and dpkg-query is a cheap local read.
func probeApt(pkg string) probeVerdict {
	if !AptAvailable() {
		return probeVerdict{OK: false, Mode: probeModePresence, Reason: "apt is unavailable on this host"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	st, err := aptQuery(ctx, pkg)
	if err != nil {
		return probeVerdict{OK: false, Mode: probeModePresence, Reason: err.Error()}
	}
	if !st.installed {
		return probeVerdict{OK: false, Mode: probeModePresence, Reason: "dpkg reports " + pkg + " is not installed"}
	}
	// The dpkg status IS the version, so this is the one source whose
	// probe verifies the answer without executing anything.
	return probeVerdict{OK: true, Mode: probeModeVersion, Reason: "dpkg reports " + pkg + " " + st.version}
}

// npmPackageCap bounds a package.json read; a real one is a few KiB.
const npmPackageCap = 1 << 20

// probeNpmPackage checks an npm package that ships no bin against the
// version in its installed package.json. ok is false when the bin probe
// must decide instead: the package declares a bin, or its package.json is
// missing or unreadable, which the verdict's Reason then names. The read
// goes through os.Root because npm refs are not validated, so a ".." ref
// must not reach outside node_modules. Like probeApt it is not cached: a
// file read notices a removal at once.
func (e *Engine) probeNpmPackage(ref, want string) (probeVerdict, bool) {
	unread := func(cause string) (probeVerdict, bool) {
		return probeVerdict{Reason: "the package.json of " + ref + " " + cause}, false
	}
	root, err := os.OpenRoot(npmModulesDir(e.toolsDir))
	if err != nil {
		return unread("cannot be read: " + err.Error())
	}
	defer func() { _ = root.Close() }()
	f, err := root.Open(filepath.Join(ref, "package.json"))
	if err != nil {
		return unread("cannot be read: " + err.Error())
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, npmPackageCap+1))
	switch {
	case err != nil:
		return unread("cannot be read: " + err.Error())
	case len(data) > npmPackageCap:
		return unread("exceeds " + strconv.Itoa(npmPackageCap) + " bytes")
	}
	// npm links a bin from "bin" (a path or a name-to-path map) or from
	// every file in "directories.bin":
	// https://docs.npmjs.com/cli/v11/configuring-npm/package-json#bin
	var pkg struct {
		Bin         any    `json:"bin"`
		Version     string `json:"version"`
		Directories struct {
			Bin string `json:"bin"`
		} `json:"directories"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return unread("is not valid JSON: " + err.Error())
	}
	if pkg.Version == "" {
		return unread("carries no version")
	}
	if declaresBin(pkg.Bin) || pkg.Directories.Bin != "" {
		return probeVerdict{}, false
	}
	if want != "" && strings.TrimPrefix(pkg.Version, "v") != strings.TrimPrefix(want, "v") {
		return probeVerdict{
			OK: false, Mode: probeModePackage,
			Reason: fmt.Sprintf("package.json reports %q, recorded version is %q", pkg.Version, want),
		}, true
	}
	return probeVerdict{OK: true, Mode: probeModePackage}, true
}

// pyvenvCap bounds a pyvenv.cfg read; uv writes a few lines.
const pyvenvCap = 64 << 10

// pipVenvSeparators are the runs PEP 503 folds to one "-"
// (https://packaging.python.org/en/latest/specifications/name-normalization/).
var pipVenvSeparators = regexp.MustCompile(`[-_.]+`)

// pipVenvName is the venv dir uv names after a pip: ref: the normalized
// package name, extras dropped.
func pipVenvName(ref string) string {
	name, _, _ := strings.Cut(ref, "[")
	return strings.ToLower(pipVenvSeparators.ReplaceAllString(name, "-"))
}

// pipInterpreter inspects the interpreter of the uv venv behind a pip: ref:
// the pyvenv.cfg home directory and the file bin/python resolves to. Both
// live outside the venv, so the launcher's fingerprint cannot see them
// change. missing names the first one gone; else foreign is the resolved
// interpreter when it lies outside pythonInterpreterDir, a tree the engine
// does not manage and so cannot keep alive; otherwise identity is the
// resolved interpreter's fileIdentity. All are empty when
// there is no pyvenv.cfg or a venv path leaves the tool dir.
func pipInterpreter(toolsDir, ref string) (identity, missing, foreign string) {
	toolDir := pythonToolDir(toolsDir)
	root, err := os.OpenRoot(toolDir)
	if err != nil {
		return "", "", ""
	}
	defer func() { _ = root.Close() }()
	venv := pipVenvName(ref)
	f, err := root.Open(filepath.Join(venv, "pyvenv.cfg"))
	if err != nil {
		return "", "", ""
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, pyvenvCap))
	if err != nil {
		return "", "", ""
	}
	if home := pyvenvHome(string(data)); home != "" {
		if _, statErr := os.Stat(home); errors.Is(statErr, fs.ErrNotExist) {
			return "", home, ""
		}
	}
	python := filepath.Join(venv, "bin", "python")
	full := filepath.Join(toolDir, python)
	// The root confines every component but the last, which uv links to an
	// interpreter outside the tool dir.
	if _, err = root.Lstat(python); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", full, ""
		}
		return "", "", ""
	}
	resolved, err := filepath.EvalSymlinks(full)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", full, ""
		}
		return "", "", ""
	}
	if !underDir(resolved, pythonInterpreterDir(toolsDir)) {
		return "", "", resolved
	}
	parts, err := fileIdentity(resolved)
	if err != nil {
		return "", "", ""
	}
	return keyenc.Join(parts...), "", ""
}

// fileIdentity is the stat identity of the file at resolved, as key parts.
// Device, inode and ctime catch a replacement that keeps mode, size and
// mtime (a rename over it, or a rewrite with its mtime put back): setting an
// mtime stamps ctime with the current time (utimensat(2)).
func fileIdentity(resolved string) ([]string, error) {
	fi, err := os.Stat(resolved)
	if err != nil {
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("stat %s: no device, inode or ctime", resolved)
	}
	return []string{
		resolved,
		fi.Mode().String(),
		strconv.FormatInt(fi.Size(), 10),
		strconv.FormatInt(fi.ModTime().UnixNano(), 10),
		strconv.FormatUint(st.Dev, 10),
		strconv.FormatUint(st.Ino, 10),
		strconv.FormatInt(st.Ctim.Nano(), 10),
	}, nil
}

// underDir reports whether the resolved path lies below dir, compared with
// dir's links resolved too.
func underDir(resolved, dir string) bool {
	if resolvedDir, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolvedDir
	}
	rel, err := filepath.Rel(dir, resolved)
	return err == nil && rel != "." && filepath.IsLocal(rel)
}

// pyvenvHome reads the home key, parsed as CPython's site module does
// (https://docs.python.org/3/library/site.html).
func pyvenvHome(cfg string) string {
	for line := range strings.Lines(cfg) {
		key, value, ok := strings.Cut(line, "=")
		if ok && strings.EqualFold(strings.TrimSpace(key), "home") {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func declaresBin(bin any) bool {
	switch b := bin.(type) {
	case string:
		return b != ""
	case map[string]any:
		return len(b) > 0
	}
	return false
}

// logVerdict reports a FRESH verdict (cache hits stay quiet, so a stable
// volume logs once per binary change, not once per inventory read).
func (e *Engine) logVerdict(name string, v probeVerdict) {
	switch {
	case !v.OK:
		e.log.Warn("toolbelt: install probe failed; tool will be reinstalled",
			"tool", name, "reason", v.Reason)
	case v.Mode == probeModePresence:
		e.log.Warn("toolbelt: install NOT verified by execution, presence only",
			"tool", name, "reason", v.Reason)
	default:
		e.log.Debug("toolbelt: install probe passed", "tool", name, "mode", v.Mode)
	}
}

// runProbe executes the probe target under a hard timeout and grades the
// answer. Exit status is not part of the grade except exit 127 (see
// exitCouldNotExecute). When the version shape is declared, the output
// must carry the recorded version.
func (e *Engine) runProbe(target string, args []string, want string, declared bool) probeVerdict {
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		return probeVerdict{OK: false, Mode: probeModePresence, Reason: "cannot resolve " + target}
	}
	fi, err := os.Stat(resolved)
	if err != nil {
		return probeVerdict{OK: false, Mode: probeModePresence, Reason: "cannot stat " + resolved}
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
		// Genuinely unprobeable: nothing to execute. Presence stands in,
		// and the caller logs that the install is unverified.
		return probeVerdict{OK: true, Mode: probeModePresence, Reason: resolved + " is not an executable file"}
	}
	out, runErr := e.execProbe(target, args)
	if runErr != nil {
		return probeVerdict{OK: false, Mode: probeModeExec, Reason: runErr.Error()}
	}
	if !declared || want == "" {
		return probeVerdict{OK: true, Mode: probeModeExec}
	}
	if !versionAnswered(out, want) {
		return probeVerdict{
			OK: false, Mode: probeModeVersion,
			Reason: fmt.Sprintf("reported %q, recorded version is %q", firstLine(out), want),
		}
	}
	return probeVerdict{OK: true, Mode: probeModeVersion}
}

// execProbe runs the probe command with the engine's PATH (so a
// launcher's `#!/usr/bin/env node` shebang resolves against the engine's
// own bin dir), no stdin, bounded output and a bounded lifetime. A
// non-zero exit is an answer, not an error; only a failure to execute or
// to finish in time is.
func (e *Engine) execProbe(target string, args []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, target, args...)
	cmd.Env = e.inst.pmEnv()
	cmd.WaitDelay = probeWaitDelay
	var out cappedBuffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if ctx.Err() != nil {
		return out.String(), fmt.Errorf("probe did not answer within %s", probeTimeout)
	}
	exit, isExit := errors.AsType[*exec.ExitError](err)
	if err != nil && !isExit {
		return out.String(), fmt.Errorf("cannot execute: %w", err)
	}
	// The loader's own diagnostic (stderr) is the only description of
	// why the binary would not run.
	if isExit && exit.ExitCode() == exitCouldNotExecute {
		return out.String(), fmt.Errorf("cannot execute: %s", probeFailureDetail(out.String()))
	}
	return out.String(), nil
}

// probeFailureDetail is the reportable head of a failed probe's output,
// falling back to the exit status when the tool said nothing at all.
func probeFailureDetail(out string) string {
	if line := firstLine(out); line != "" {
		return line
	}
	return "exit status " + strconv.Itoa(exitCouldNotExecute) + ", no output"
}

// recordedBins is the presence set: the tool's recorded bins, or the
// derived probe name before the first status write (so a pre-seeded
// volume still reads as installed when the binary is there and runs).
func recordedBins(name string, t *Tool, s *ToolStatus) []string {
	bins := append(append([]string{}, s.Bins...), s.PMBins...)
	if len(bins) > 0 {
		return bins
	}
	return []string{derivedProbeName(name, t)}
}

// probeBin picks the ONE bin to execute. Executing every recorded bin
// would spawn a subprocess per name for multi-bin packages (typescript:
// tsc + tsserver) on every probe, for no extra signal: the probe name is
// what the tool is identified by.
func probeBin(name string, t *Tool, bins []string) string {
	derived := derivedProbeName(name, t)
	if t.Probe != "" || len(bins) == 0 || slices.Contains(bins, derived) {
		return derived
	}
	return bins[0]
}

// derivedProbeName is the declared probe name, else the tool name's
// conventional bin name (@scope/pkg -> pkg).
func derivedProbeName(name string, t *Tool) string {
	if t.Probe != "" {
		return t.Probe
	}
	return pkgBinName(strings.TrimPrefix(name, "@"))
}

// probeFingerprint identifies what is about to be probed, so a cached
// verdict is only reused for the exact same binary, recorded version and
// probe shape. declaredArgs is the definition's list before defaulting:
// declaring the default ["--version"] runs the same argv but grades the
// version, so it must not reuse an undeclared verdict. Assembled with
// keyenc because the path, version and args can each hold a separator
// (["--version"] vs ["--","version"] must not share a joined form).
func probeFingerprint(target, want string, declaredArgs []string) (string, error) {
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		return "", err
	}
	parts, err := fileIdentity(resolved)
	if err != nil {
		return "", err
	}
	return keyenc.Join(append(parts, want, keyenc.Join(declaredArgs...))...), nil
}

// versionAnswered reports whether a probe's output claims the recorded
// version. Upstream banners are inconsistent about the v prefix and case
// ("jq-1.8.1", "go version go1.26.5", "v24.18.0"), so the version, any
// leading v trimmed, is found case-insensitively as a whole number: one
// inside a longer number (11.2.3 or 1.2.30 for 1.2.3) does not count, and
// text after it (a label, commit hash or platform) is not read, because
// the check catches a different binary and no suffix grammar is total.
func versionAnswered(out, want string) bool {
	needle := strings.ToLower(strings.TrimPrefix(want, "v"))
	if needle == "" {
		return true
	}
	hay := strings.ToLower(out)
	for from := 0; ; {
		i := strings.Index(hay[from:], needle)
		if i < 0 {
			return false
		}
		start := from + i
		end := start + len(needle)
		if !versionContinues(hay[:start], true) && !versionContinues(hay[end:], false) {
			return true
		}
		from = start + 1
	}
}

func versionContinues(side string, before bool) bool {
	digitAt := func(i int) bool { return i >= 0 && i < len(side) && side[i] >= '0' && side[i] <= '9' }
	if before {
		n := len(side)
		return digitAt(n-1) || n >= 2 && side[n-1] == '.' && digitAt(n-2)
	}
	return digitAt(0) || len(side) >= 2 && side[0] == '.' && digitAt(1)
}

// firstLine is the reportable head of a probe answer (bounded, so a
// chatty tool cannot flood a log line).
func firstLine(out string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
	if len(line) > 120 {
		return line[:120]
	}
	return line
}

// cappedBuffer collects at most probeOutputCap bytes and discards the
// rest, so an unbounded talker cannot grow the heap.
type cappedBuffer struct{ buf bytes.Buffer }

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := probeOutputCap - c.buf.Len(); room > 0 {
		c.buf.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}

func (c *cappedBuffer) String() string { return c.buf.String() }
