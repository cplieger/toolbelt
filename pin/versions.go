//go:build linux

package pin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cplieger/toolbelt/v3/internal/retain"
)

// lastFieldOfFirstLine reads a version probe's answer: the last
// whitespace-separated field of the first line, and "" when there is none. It
// covers the `<name> <version>` and bare `<version>` shapes.
func lastFieldOfFirstLine(out string) string {
	line, _, _ := strings.Cut(out, "\n")
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

// selfContained reports whether path is an artifact that keeps working after the
// staging tree is removed: a REGULAR executable file, not a symlink. os.Stat
// follows links and a bare executable check is also true for a directory, so both
// are checked explicitly.
func selfContained(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return false
	}
	return fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}

// probeVersion asks an artifact for its version, bounded.
func (m *Manager) probeVersion(ctx context.Context, bin string) (string, error) {
	out, err := m.run(ctx, &command{
		Path:    bin,
		Env:     m.commandEnv(bin),
		Args:    m.cfg.ProbeArgs,
		Timeout: probeTimeout,
	})
	if err != nil {
		return "", err
	}
	version := lastFieldOfFirstLine(string(out))
	if version == "" {
		return "", fmt.Errorf("the version probe produced no parseable version at %s", bin)
	}
	return version, nil
}

// versionDirComplete reports whether a version directory is a completed install:
// the sentinel is a plain file naming exactly this version, and every required
// artifact inside is a self-contained executable. The sentinel is checked against
// the directory's own name, not the pin, so a retained predecessor reads as
// complete.
func (m *Manager) versionDirComplete(version string) bool {
	dir := m.versionDir(version)
	sentinel := filepath.Join(dir, sentinelName)
	fi, err := os.Lstat(sentinel)
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	// #nosec G304 -- sentinel is built from Root plus a directory entry name, and
	// it was just proved to be a regular file rather than a link.
	raw, err := os.ReadFile(sentinel)
	if err != nil || strings.TrimSpace(string(raw)) != version {
		return false
	}
	return selfContained(filepath.Join(dir, m.primary))
}

// activationStage names the check a version directory failed. It exists so selection and
// retention can share ONE set of checks while keeping their own severity and their own
// wording: the same refusal is an exclusion to one caller and a retention decision to the
// other, and those are not the same sentence.
type activationStage uint8

const (
	stageActivatable activationStage = iota // every check passed
	stageUntrusted
	stageWideEntry
	stageProbeFailed
	stageVersionMismatch
)

// activation is what [Manager.activatable] answers: the selection when a version directory
// would be activated, and otherwise the stage that refused it plus what that stage learned.
type activation struct {
	sel      selection
	verdict  error  // the custody verdict, read in the SAME lock acquisition as the trust answer
	err      error  // the version probe's error, when the probe is what failed
	dir      string // the version directory, once trust let it be computed
	bin      string // the primary artifact inside it, once the probe was reached
	entry    string // wideArtifact's offender: an entry name, or "." for the directory itself
	reason   string // why that entry is not provably private
	reported string // the version the probe answered
	stage    activationStage
}

// activatable answers the one question selection and retention both ask of a
// complete version directory: would this be activated? One predicate, so a check
// added to selection cannot silently miss retention, which prunes on this answer.
// trusted comes first because probeVersion EXECUTES the artifact: retention must
// not run a binary selection declined. It reports and does not log; the custody
// verdict travels along from the same lock acquisition (see [Manager.trusted]).
func (m *Manager) activatable(ctx context.Context, version string) activation {
	mayActivate, verdict := m.trusted(version)
	if !mayActivate {
		return activation{stage: stageUntrusted, verdict: verdict}
	}
	dir := m.versionDir(version)
	if entry, why := m.wideArtifact(dir); entry != "" {
		return activation{stage: stageWideEntry, verdict: verdict, dir: dir, entry: entry, reason: why}
	}
	bin := filepath.Join(dir, m.primary)
	got, err := m.probeVersion(ctx, bin)
	switch {
	case err != nil:
		return activation{stage: stageProbeFailed, verdict: verdict, dir: dir, bin: bin, err: err, reported: got}
	case got != version:
		return activation{stage: stageVersionMismatch, verdict: verdict, dir: dir, bin: bin, reported: got}
	}
	return activation{
		stage:   stageActivatable,
		verdict: verdict,
		dir:     dir,
		bin:     bin,
		sel:     selection{version: version, dir: dir, bin: bin},
	}
}

// predecessorRole classifies one complete predecessor through
// [Manager.activatable], and logs why when it is not a fallback. An untrusted
// directory under a CLEAN verdict is this deployment's own earlier install, which
// no process will ever activate (installed is per-process), so it is prunable;
// under a REFUSED verdict it may be another principal's install, so it is immune.
// A replaced artifact is prunable: it can never serve and its sentinel is false.
func (m *Manager) predecessorRole(ctx context.Context, version string) retain.Role {
	a := m.activatable(ctx, version)
	switch a.stage {
	case stageUntrusted:
		if a.verdict == nil {
			m.log.Info("pruning a version directory no process can activate: this process did not install it and the tree is declared untrusted, so it is neither a fallback nor evidence",
				"package", m.cfg.Name, "version", version)
			return retain.Prunable
		}
		m.log.Warn("not counting a version directory towards retention, and not deleting it: custody refused the tree, so this directory may be another principal's install",
			"package", m.cfg.Name, "version", version, "verdict", a.verdict)
		return retain.Immune
	case stageWideEntry:
		m.log.Warn("not counting a version directory towards retention: selection would refuse it because an entry is not provably private to this process",
			"package", m.cfg.Name, "version", version, "offender", a.entry, "reason", a.reason)
		return retain.Immune
	case stageProbeFailed:
		m.log.Warn("not counting a version directory towards retention: it would not survive selection's version probe",
			"package", m.cfg.Name, "version", version, "error", a.err)
		return retain.Immune
	case stageVersionMismatch:
		m.log.Error("pruning a version directory: its artifact reports a different version than the directory and sentinel claim, so the install was replaced or tampered with",
			"package", m.cfg.Name, "version", version, "reported", a.reported, "path", a.bin)
		return retain.Prunable
	}
	return retain.Fallback
}

// completeVersions lists the completed version directories in retain.Order:
// most recently activated first, by the directory's mtime.
func (m *Manager) completeVersions() []retain.Entry {
	entries, err := os.ReadDir(m.versionsDir)
	if err != nil {
		return nil
	}
	out := make([]retain.Entry, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		// Dot-prefixed entries are staging trees, never versions.
		if !e.IsDir() || strings.HasPrefix(name, ".") {
			continue
		}
		if !m.versionDirComplete(name) {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, retain.Entry{Name: name, Activated: fi.ModTime()})
	}
	return retain.Order(out)
}

// trusted reports whether a version directory may be activated. A sentinel is a
// forgeable plain file, so without custody of the tree nothing found there is
// activated, not even what this process installed earlier. Under
// [Config.Untrusted], whatever the measured verdict, only a version this process
// published from a verified archive is: that proves a publish, not unchanged
// bytes, which is the strongest claim available there. The verdict is returned
// from the same lock acquisition, so a log line cannot describe a decision that
// was never made.
func (m *Manager) trusted(version string) (mayActivate bool, verdict error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case m.custodyErr != nil:
		// The verdict says this process does not control the tree and the caller has
		// not accepted that. Nothing here is evidence, INCLUDING what this process
		// installed earlier: that fact proves a publish at some past instant, not the
		// bytes at this one, and in a writable tree the directory or the artifact can
		// be renamed between the checks and the exec. Readiness is withheld rather
		// than granted on a claim the library cannot make.
		return false, m.custodyErr
	case m.cfg.Untrusted:
		// The caller declared the tree untrustworthy on its own knowledge: only a
		// version this process published from a verified archive.
		return m.installed[version], nil
	}
	return true, m.custodyErr
}

// wideArtifact returns the first entry in dir that is not provably private to
// this process and why, or "" when everything is; "." is the directory itself.
// Every top-level entry counts, not only the primary: PathEntry puts the whole
// directory on PATH, where an entry beside the primary resolves by bare name.
// The reason travels with the name because an entry somebody can
// write and one whose access list could not be read are fixed differently.
func (m *Manager) wideArtifact(dir string) (name, reason string) {
	euid := os.Geteuid()
	if why, private := m.trust.EntryPrivate(dir, euid); !private {
		return ".", why
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ".", "could not be listed: " + err.Error()
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if why, private := m.trust.EntryPrivate(filepath.Join(dir, e.Name()), euid); !private {
			return e.Name(), why
		}
	}
	return "", ""
}

// selectActive picks the version to run: the pin when it is activatable, else the
// most recently activated other complete version, else none. A sentinel is not
// proof: each candidate's primary artifact must answer the version its directory
// claims, and one that does not is removed, so the pin reinstalls and no false
// sentinel stays behind. The checks live in [Manager.activatable]; the wording
// and severity stay here.
func (m *Manager) selectActive(ctx context.Context) (selection, bool) {
	for _, version := range preferPin(m.completeVersions(), m.cfg.Version) {
		a := m.activatable(ctx, version)
		if a.stage == stageUntrusted {
			m.log.Warn("ignoring an existing version directory because this process does not exclusively control the installation tree; only a freshly verified install may be activated",
				"package", m.cfg.Name, "version", version, "reason", a.verdict, "untrusted", m.cfg.Untrusted)
			continue
		}
		if m.cfg.Untrusted {
			m.log.Error("activating a version on degraded evidence: Config.Untrusted declares this tree shared, so all that is known is that this process published this version from a verified archive earlier, not that its artifact is unchanged since",
				"package", m.cfg.Name, "version", version, "reason", a.verdict)
		}
		switch a.stage {
		case stageWideEntry:
			if a.entry == "." {
				m.log.Error("excluding a version directory: the directory itself is not provably private to this process, so any entry in it can be replaced whatever its own mode says",
					"package", m.cfg.Name, "version", version, "dir", a.dir, "reason", a.reason)
			} else {
				m.log.Error("excluding a version directory: an entry in it is not provably private to this process, so it is a file this process may execute and cannot vouch for",
					"package", m.cfg.Name, "version", version, "entry", a.entry, "reason", a.reason)
			}
			continue
		case stageProbeFailed:
			m.log.Warn("excluding a version directory: its artifact did not answer the version probe",
				"package", m.cfg.Name, "version", version, "path", a.bin, "error", a.err)
			continue
		case stageVersionMismatch:
			m.log.Error("removing a version directory: its artifact reports a different version than the directory and sentinel claim, so the install was replaced or tampered with",
				"package", m.cfg.Name, "version", version, "reported", a.reported,
				"path", a.bin)
			// activatable probes only under a clean custody verdict, so this is a
			// delete mayMutateTree allows.
			m.removeUnderRoot([]string{version})
			continue
		}
		return a.sel, true
	}
	return selection{}, false
}

// preferPin returns the entries' names with pin first (when present) and the
// rest in the given order, so the pinned version is always tried first.
func preferPin(entries []retain.Entry, pin string) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Name == pin {
			out = append(out, e.Name)
		}
	}
	for _, e := range entries {
		if e.Name != pin {
			out = append(out, e.Name)
		}
	}
	return out
}

// pruneSuperseded removes the version directories retain.Victims names, then
// syncs the installation root so the removals are durable. Failures warn: disk
// hygiene must not brick a start. A predecessor counts towards the one kept
// only when it would survive selection (see predecessorRole), and one selection
// refuses for a state this library did not create is spared as evidence, except
// a replaced artifact, which is pruned.
func (m *Manager) pruneSuperseded(ctx context.Context, active string) {
	victims := retain.Victims(m.completeVersions(), active, retainPredecessors, func(name string) retain.Role {
		return m.predecessorRole(ctx, name)
	})
	if len(victims) == 0 {
		return
	}
	removed := m.removeUnderRoot(victims)
	if removed == 0 {
		return
	}
	m.log.Info("pruned superseded versions",
		"package", m.cfg.Name, "removed", removed, "active", active, "retain", retainPredecessors)
	if err := m.fsync(m.versionsDir); err != nil {
		m.log.Warn("failed to sync the installation root after pruning",
			"package", m.cfg.Name, "error", err)
	}
}

// prunePartials removes incomplete version directories and orphan staging trees.
// It runs before selection so a partial directory is never a candidate, and it
// runs while no staging tree of this manager exists: Ensure holds opSem and
// creates its stage later.
//
// Its caller runs it only when Manager.mayMutateTree allows.
func (m *Manager) prunePartials() {
	entries, err := os.ReadDir(m.versionsDir)
	if err != nil {
		return
	}
	victims := make([]string, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		switch {
		case strings.HasPrefix(name, stagePrefix):
			victims = append(victims, name)
		case !e.IsDir(), strings.HasPrefix(name, "."):
			continue
		case !m.versionDirComplete(name):
			victims = append(victims, name)
		}
	}
	if removed := m.removeUnderRoot(victims); removed > 0 {
		m.log.Info("removed incomplete install directories",
			"package", m.cfg.Name, "removed", removed)
	}
}

// removeUnderRoot deletes the named entries through an os.Root confined to the
// installation root, so a symlinked or otherwise redirected entry cannot make a
// delete escape the tree. It returns how many were removed.
func (m *Manager) removeUnderRoot(names []string) int {
	if len(names) == 0 {
		return 0
	}
	root, err := os.OpenRoot(m.versionsDir)
	if err != nil {
		m.log.Warn("failed to open the installation root for pruning",
			"package", m.cfg.Name, "error", err)
		return 0
	}
	defer root.Close()
	removed := 0
	for _, name := range names {
		if err := root.RemoveAll(name); err != nil {
			m.log.Warn("failed to remove an install directory",
				"package", m.cfg.Name, "entry", name, "error", err)
			continue
		}
		removed++
	}
	return removed
}
