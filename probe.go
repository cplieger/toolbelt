package toolbelt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
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
)

// probeVerdict is what one probe established.
type probeVerdict struct {
	// Mode is the strongest check that actually ran (probeMode*).
	Mode string
	// Reason explains a failure or a downgrade, for the log line.
	Reason string
	// OK is the install-detection answer: true = installed, false =
	// reinstall. A failed probe is never fatal.
	OK bool
}

// probeCache memoizes exec probes so the read path (Inventory, which a
// settings UI polls) does not spawn a subprocess per tool per call.
//
// Presence is re-checked on every probe — it is a stat, and a deleted
// binary must be noticed immediately. Only the EXEC verdict is cached,
// keyed by a fingerprint of the probe target (resolved path, size,
// mtime), the recorded version, and the declared version args, so any
// reinstall, relink or version bump invalidates it without a TTL.
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
func (e *Engine) binDir() string { return filepath.Join(e.toolsDir, "bin") }

// probeInstalled reports whether the tool is installed. Presence of
// bin/<name> is necessary but not sufficient: every recorded bin (or the
// derived probe name before the first status write) must exist AND the
// tool's probe binary must answer when executed — and, when the
// definition declares its version-reporting shape (Tool.VersionArgs),
// the answer must contain the recorded version. A truncated download, a
// wrong-architecture binary, a dangling symlink into a pruned version
// dir, or a tool left at the wrong version therefore reads as NOT
// installed, which routes it to a reinstall; a failed probe is never
// fatal.
//
// A recorded bin the engine cannot execute at all (a data file a manual
// install script placed in bin/) falls back to presence only and says so
// at Warn rather than claiming the install was verified.
func (e *Engine) probeInstalled(name string, t *Tool, s *ToolStatus) bool {
	return e.probeTool(name, t, s).OK
}

// probeTool is probeInstalled's full verdict (mode + reason), cached per
// tool and logged once per fingerprint change.
func (e *Engine) probeTool(name string, t *Tool, s *ToolStatus) probeVerdict {
	bins := recordedBins(name, t, s)
	for _, b := range bins {
		if _, err := os.Stat(filepath.Join(e.binDir(), b)); err != nil {
			return probeVerdict{OK: false, Mode: probeModePresence, Reason: "bin " + b + " is missing"}
		}
	}
	target := filepath.Join(e.binDir(), probeBin(name, t, bins))
	args := t.VersionArgs
	if len(args) == 0 {
		args = defaultVersionArgs
	}
	want := s.InstalledVersion
	fingerprint, err := probeFingerprint(target, want, args)
	if err != nil {
		return probeVerdict{OK: false, Mode: probeModePresence, Reason: "probe target unusable: " + err.Error()}
	}
	if v, ok := e.probes.lookup(name, fingerprint); ok {
		return v
	}
	v := e.runProbe(target, args, want, len(t.VersionArgs) > 0)
	e.probes.store(name, fingerprint, v)
	e.logVerdict(name, v)
	return v
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
// answer. Exit status is deliberately not part of the grade: a tool that
// does not support --version still proves it can execute, which is what
// the exec-only probe claims. When the version shape is declared, the
// output must carry the recorded version.
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
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		return out.String(), fmt.Errorf("cannot execute: %w", err)
	}
	return out.String(), nil
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
// probe shape.
//
// The components are assembled with keyenc rather than concatenated, because
// two of them can contain a separator and they are not separated by anything
// that cannot: the resolved path is a filesystem path and the wanted version
// is a manifest string, so a path containing the separator shifts the split
// and one tool's fingerprint can be made to match another shape's. The arg
// list nests by composition for the same reason a space-joined list is not
// enough on its own: joining ["--version"] and ["--", "version"] to one string
// loses the element boundary, so two different probe invocations would share a
// verdict.
func probeFingerprint(target, want string, args []string) (string, error) {
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	return keyenc.Join(
		resolved,
		strconv.FormatInt(fi.Size(), 10),
		strconv.FormatInt(fi.ModTime().UnixNano(), 10),
		want,
		keyenc.Join(args...),
	), nil
}

// versionAnswered reports whether a probe's output claims the recorded
// version. Upstream banners are inconsistent about the v prefix and case
// ("jq-1.8.1", "go version go1.26.5", "v24.18.0"), so the comparison is
// a case-insensitive containment check on the version with any leading v
// trimmed from both sides.
func versionAnswered(out, want string) bool {
	needle := strings.ToLower(strings.TrimPrefix(want, "v"))
	if needle == "" {
		return true
	}
	return strings.Contains(strings.ToLower(out), needle)
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
