package toolbelt

import (
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/cplieger/go/pathinside"
	"github.com/cplieger/toolbelt/v3/internal/custody"
)

// Root integrity: an opt-in prerequisite check (Config.VerifyRootIntegrity).
// The install probe EXECUTES what it finds in the tool tree, and that
// bin dir goes first on PATH, so a managed root another account can write,
// or redirect, is a root-code-execution surface for a root process.
//
// REPORT-ONLY (repair belongs to the consumer's entrypoint); absence is
// not a finding (a fresh volume has almost none of these yet); a
// failing root deliberately cascades findings onto paths beneath it.

// RootIntegrityFinding is one managed root that failed the integrity
// check, and why.
type RootIntegrityFinding struct {
	// Path is the offending directory as the check inspected it:
	// ConfigDir, ToolsDir, or one of the directories beneath ToolsDir.
	Path string
	// Reason states the first thing that disqualified it, in operator
	// terms ("is a symlink", "is not under this process's exclusive
	// control: /tools, mode 0775, can be modified by gid 1001").
	Reason string
}

// RootIntegrityError is the ErrRootIntegrity shape that names every
// offending root. Compare with errors.Is(err, ErrRootIntegrity) to
// classify the failure; recover it with errors.As to read the individual
// findings (a consumer that warns and runs tool-less needs the detail; a
// consumer that treats the class as fatal does not).
type RootIntegrityError struct {
	// Findings is every offending path with its reason, sorted by path
	// then reason so the same bad volume always reports identically.
	Findings []RootIntegrityFinding
}

func (e *RootIntegrityError) Error() string {
	return "managed root failed the integrity check: " + strings.Join(findingLines(e.Findings), "; ")
}

// Is makes errors.Is(err, ErrRootIntegrity) match.
func (*RootIntegrityError) Is(target error) bool { return target == ErrRootIntegrity }

// findingLines renders one "<path> <reason>" line per finding. The
// message and the log field share it so an operator reading either sees
// the same text.
func findingLines(findings []RootIntegrityFinding) []string {
	lines := make([]string, 0, len(findings))
	for _, f := range findings {
		lines = append(lines, f.Path+" "+f.Reason)
	}
	return lines
}

// verifyRootIntegrity inspects the managed roots and, when any of them
// is unfit, logs the refusal where an operator will see it and returns
// the *RootIntegrityError naming every one. Nil means every root that
// exists is a real directory under the exclusive control of this process
// (custody.Trust.Verify) that still resolves inside the tool tree.
func verifyRootIntegrity(log *slog.Logger, configDir, toolsDir string, trust custody.Trust) error {
	findings := inspectRoots(configDir, toolsDir, trust)
	if len(findings) == 0 {
		return nil
	}
	log.Error("toolbelt: REFUSING to start: a managed root is not fit to execute from",
		"config_dir", configDir, "tools_dir", toolsDir,
		"finding_count", len(findings), "findings", strings.Join(findingLines(findings), "; "))
	return &RootIntegrityError{Findings: findings}
}

// inspectRoots judges every managed root, ConfigDir, ToolsDir and the
// managedDirs beneath it, and reports at most one finding per root: the first
// leg it fails. ConfigDir is exempt from the containment leg alone (it is
// legitimately outside ToolsDir).
func inspectRoots(configDir, toolsDir string, trust custody.Trust) []RootIntegrityFinding {
	var out []RootIntegrityFinding
	add := func(path, reason string) {
		if reason != "" {
			out = append(out, RootIntegrityFinding{Path: path, Reason: reason})
		}
	}
	configReason, _ := inspectRootDir(configDir, trust)
	add(configDir, configReason)
	toolsReason, toolsIsDir := inspectRootDir(toolsDir, trust)

	// Judged against the RESOLVED ToolsDir: a volume may sit behind a
	// symlinked ancestor (/config -> /mnt/config), and comparing against
	// the unresolved root would report every child as escaping.
	toolsRoot, contained := pathinside.Root(""), false
	if toolsIsDir {
		resolved, err := filepath.EvalSymlinks(toolsDir)
		if err != nil && toolsReason == "" {
			toolsReason = "cannot be resolved: " + err.Error()
		} else if err == nil {
			toolsRoot, contained = pathinside.Root(resolved), true
		}
	}
	add(toolsDir, toolsReason)

	for _, path := range managedDirs(toolsDir) {
		reason, isDir := inspectRootDir(path, trust)
		if reason == "" && isDir && contained {
			reason = inspectContainment(toolsRoot, path)
		}
		add(path, reason)
	}

	slices.SortFunc(out, func(a, b RootIntegrityFinding) int {
		if c := strings.Compare(a.Path, b.Path); c != 0 {
			return c
		}
		return strings.Compare(a.Reason, b.Reason)
	})
	return out
}

// inspectRootDir returns the first leg path fails ("" for none) and
// whether it is a real directory, which the containment leg needs. Lstat,
// so a root that is a symlink is refused, not followed; an unreadable root
// is not assumed clean. Writers are judged by principal, not mode bits:
// under a POSIX.1e list the group bits are its mask, so a mode test would
// refuse a writer TrustedUIDs declares.
func inspectRootDir(path string, trust custody.Trust) (string, bool) {
	fi, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// Nothing to judge: a fresh volume has almost none of these yet.
		return "", false
	case err != nil:
		return "cannot be inspected: " + err.Error(), false
	case fi.Mode()&os.ModeSymlink != 0:
		return "is a symlink", false
	case !fi.IsDir():
		return "is not a directory", false
	}
	if err := trust.Verify(path, true); err != nil {
		return "is " + err.Error(), true
	}
	return "", true
}

// inspectContainment resolves a real directory and confirms it is still
// inside the tool tree. The mode legs are name-level; this is the leg
// that catches a redirect through an intermediate symlink, which is how
// a launcher directory ends up somewhere the operator never granted.
//
// The tree travels as a pathinside.Root constructed once by inspectRoots,
// so the containment pair cannot be supplied transposed.
func inspectContainment(toolsRoot pathinside.Root, path string) string {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "cannot be resolved: " + err.Error()
	}
	if !toolsRoot.Contains(resolved) {
		return "resolves to " + resolved + ", outside the tool tree"
	}
	return ""
}
