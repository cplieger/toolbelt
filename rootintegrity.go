package toolbelt

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/cplieger/pathinside/v2"
)

// Root integrity: an opt-in prerequisite check on the directories the
// engine treats as its own (Config.VerifyRootIntegrity).
//
// Why it exists: the install probe EXECUTES what it finds in the tool
// tree (probeTool -> runProbe -> exec.CommandContext on
// <ToolsDir>/bin/<tool>), and the package-manager environment puts that
// same bin dir first on PATH, so even a shebang resolves inside the
// tree. On a consumer that runs as root over an operator-controlled
// persistent volume, a managed root that is a symlink into somewhere
// else, or one any group or other principal can write, is therefore a
// root-code-execution surface rather than a tidiness question.
//
// The check is REPORT-ONLY: it never chmods, creates, repairs or deletes
// anything. Tightening an operator's volume from inside a library would
// be a behavior change no consumer asked for, and repair belongs to the
// consumer's entrypoint, which knows whether the tree is disposable, and
// runs before the process it has to protect.
//
// Absence is not a finding. On a fresh volume most of these directories
// do not exist yet — New creates bin/ moments later, and npm/ and
// python/ only ever come into being when an ecosystem install runs — so
// a missing path is skipped rather than reported.
//
// A root that fails its own inspection can cascade findings onto the
// paths beneath it (a ToolsDir that is a regular file makes every child
// unreadable, a symlinked npm parent makes npm/bin resolve out of the
// tree). That is deliberate: every path is judged and reported, so the
// operator sees the whole surface rather than one line at a time.

// RootIntegrityFinding is one managed root that failed the integrity
// check, and why.
type RootIntegrityFinding struct {
	// Path is the offending directory as the check inspected it:
	// ConfigDir, ToolsDir, or one of the directories beneath ToolsDir.
	Path string
	// Reason states what disqualified it, in operator terms ("is a
	// symlink", "is group- or other-writable (mode 0775)").
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
func (e *RootIntegrityError) Is(target error) bool { return target == ErrRootIntegrity }

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
// exists is a real directory, writable by its owner alone, that still
// resolves inside the tool tree.
func verifyRootIntegrity(log *slog.Logger, configDir, toolsDir string) error {
	findings := inspectRoots(configDir, toolsDir)
	if len(findings) == 0 {
		return nil
	}
	log.Error("toolbelt: REFUSING to start: a managed root is not fit to execute from",
		"config_dir", configDir, "tools_dir", toolsDir,
		"finding_count", len(findings), "findings", strings.Join(findingLines(findings), "; "))
	return &RootIntegrityError{Findings: findings}
}

// inspectRoots judges every managed root: ConfigDir, then ToolsDir, then
// the directories beneath ToolsDir — the launcher dirs the probe and
// PATH reach into (bin, opt), and the ecosystem trees (npm, python) with
// their own bin dirs. The npm and python PARENTS are judged as well as
// their leaves: either parent can redirect the launcher directory
// beneath it, so checking only the leaves would miss the redirect.
//
// ConfigDir is exempt from the containment leg alone — it is
// legitimately outside ToolsDir — not from the symlink, type or mode
// legs.
func inspectRoots(configDir, toolsDir string) []RootIntegrityFinding {
	out, _ := inspectRootDir(configDir)
	toolsFindings, toolsIsDir := inspectRootDir(toolsDir)
	out = append(out, toolsFindings...)

	// Containment is judged against the RESOLVED ToolsDir, not the
	// configured string: an operator's volume legitimately sits behind a
	// symlinked ancestor (/config -> /mnt/config), and comparing the
	// resolved children against the unresolved root would report every
	// one of them as escaping. ToolsDir itself has already been refused
	// if IT is the symlink, so this resolves the ancestors only.
	//
	// This is the boundary the containment leg confines to, so it is
	// where the pathinside.Root is constructed.
	toolsRoot, contained := pathinside.Root(""), false
	if toolsIsDir {
		resolved, err := filepath.EvalSymlinks(toolsDir)
		if err != nil {
			out = append(out, RootIntegrityFinding{Path: toolsDir, Reason: "cannot be resolved: " + err.Error()})
		} else {
			toolsRoot, contained = pathinside.Root(resolved), true
		}
	}

	for _, path := range []string{
		filepath.Join(toolsDir, "bin"),
		filepath.Join(toolsDir, "opt"),
		filepath.Join(toolsDir, "npm"),
		filepath.Join(toolsDir, "npm", "bin"),
		filepath.Join(toolsDir, "python"),
		filepath.Join(toolsDir, "python", "bin"),
	} {
		findings, isDir := inspectRootDir(path)
		out = append(out, findings...)
		if isDir && contained {
			out = append(out, inspectContainment(toolsRoot, path)...)
		}
	}

	slices.SortFunc(out, func(a, b RootIntegrityFinding) int {
		if c := strings.Compare(a.Path, b.Path); c != 0 {
			return c
		}
		return strings.Compare(a.Reason, b.Reason)
	})
	return out
}

// inspectRootDir applies the per-path legs and reports whether the path
// is a real directory (which is what makes the containment leg
// meaningful for it).
//
// os.Lstat, never os.Stat: a root that IS a symlink must be refused, not
// followed. Every failure other than not-exist is a finding — an
// unreadable root is not assumed clean.
func inspectRootDir(path string) ([]RootIntegrityFinding, bool) {
	fi, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// Nothing to judge: a fresh volume has almost none of these yet.
		return nil, false
	case err != nil:
		return []RootIntegrityFinding{{Path: path, Reason: "cannot be inspected: " + err.Error()}}, false
	case fi.Mode()&os.ModeSymlink != 0:
		return []RootIntegrityFinding{{Path: path, Reason: "is a symlink"}}, false
	case !fi.IsDir():
		return []RootIntegrityFinding{{Path: path, Reason: "is not a directory"}}, false
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return []RootIntegrityFinding{{
			Path:   path,
			Reason: fmt.Sprintf("is group- or other-writable (mode %04o)", perm),
		}}, true
	}
	return nil, true
}

// inspectContainment resolves a real directory and confirms it is still
// inside the tool tree. The mode legs are name-level; this is the leg
// that catches a redirect through an intermediate symlink, which is how
// a launcher directory ends up somewhere the operator never granted.
//
// The tree travels as a pathinside.Root constructed once by inspectRoots,
// so the containment pair cannot be supplied transposed.
func inspectContainment(toolsRoot pathinside.Root, path string) []RootIntegrityFinding {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return []RootIntegrityFinding{{Path: path, Reason: "cannot be resolved: " + err.Error()}}
	}
	if !toolsRoot.Contains(resolved) {
		return []RootIntegrityFinding{{
			Path:   path,
			Reason: "resolves to " + resolved + ", outside the tool tree",
		}}
	}
	return nil
}
