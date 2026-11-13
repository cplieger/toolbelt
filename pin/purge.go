//go:build linux

package pin

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// purgeTarget is one entry the sweep may remove: its path relative to Root and
// the shape the previous installer left there. The shape is a gate: the link
// directory is co-owned, and another installer's symlink at the same name is
// not this sweep's to delete.
type purgeTarget struct {
	// path is relative to Root.
	path string
	// dir marks a target the previous installer created as a directory; every
	// other target must be a regular file.
	dir bool
}

// validate rejects a purge whose paths could escape Root. Every target is deleted
// through an os.Root confined to Root, but refusing a traversal at construction
// reports the profile's mistake instead of silently sweeping nothing.
func (p *Purge) validate(linkDir string) error {
	if err := p.validateTargets(); err != nil {
		return err
	}
	if len(p.Names) > 0 && linkDir == "" {
		return fmt.Errorf("pin: Purge.Names sweeps entries under LinkDir, which is empty, so name %q has no directory to be swept from", p.Names[0])
	}
	if p.StagePrefix != "" && !strings.HasPrefix(p.StagePrefix, ".") {
		return fmt.Errorf("pin: Purge.StagePrefix %q must start with a dot, so a version scan cannot reach what it matches", p.StagePrefix)
	}
	if p.Marker != "" {
		switch {
		case !strings.HasPrefix(p.Marker, "."):
			return fmt.Errorf("pin: Purge.Marker %q must start with a dot, so no version scan can mistake it for a version", p.Marker)
		case strings.ContainsRune(p.Marker, '/'), strings.ContainsRune(p.Marker, filepath.Separator):
			return fmt.Errorf("pin: Purge.Marker %q must be a single path component directly under Root", p.Marker)
		case p.Marker == "." || p.Marker == "..":
			return fmt.Errorf("pin: Purge.Marker must not be %q", p.Marker)
		}
	}
	return nil
}

// purgeOnce runs the sweep at most once per process AND at most once per volume.
// The in-process latch stops a retry or rescan re-walking the co-owned directory;
// the on-disk marker is what stops a start that has nothing left to migrate from
// walking it at all.
func (m *Manager) purgeOnce() {
	if m.cfg.Purge == nil {
		return
	}
	m.mu.Lock()
	already := m.purged
	m.purged = true
	m.mu.Unlock()
	if already {
		return
	}
	if m.purgeRecorded() {
		m.log.Debug("skipping the one-shot purge: it is already recorded as complete on this volume",
			"package", m.cfg.Name, "marker", m.cfg.Purge.Marker)
		return
	}
	m.purge()
}

// purge deletes the previous installer's layout (the named artifacts, the named
// entries under LinkDir, every orphan staging tree) and nothing else, each only
// when it has the shape that installer left. Each step is an independent
// RemoveAll, so the sweep is idempotent and interruption-safe. Failures warn and
// continue, but withhold the completion marker so the next start retries.
func (m *Manager) purge() {
	root, err := os.OpenRoot(m.cfg.Root)
	if err != nil {
		// A missing root means there is nothing to purge; anything else is worth
		// a line.
		if !os.IsNotExist(err) {
			m.log.Warn("failed to open the root to purge a previous installer's layout",
				"package", m.cfg.Name, "error", err)
		}
		return
	}
	defer root.Close()

	removed, failed := 0, 0
	for _, t := range m.purgeTargets(root) {
		present, matches := purgeShapeMatches(root, t)
		switch {
		case !present:
			continue
		case !matches && m.ownsLinkAt(root, t.path):
			m.log.Debug("not purging this manager's own convenience symlink; the link publication owns it",
				"package", m.cfg.Name, "entry", t.path)
		case !matches:
			m.log.Warn("refusing to remove an entry the previous layout never had this shape at; it belongs to another owner of this tree and that owner's state still claims it",
				"package", m.cfg.Name, "entry", t.path, "want_shape", shapeName(t.dir))
		default:
			// RemoveAll through the root confines the delete to this tree: a
			// symlinked artifact cannot redirect it at whatever sits next door.
			if err := root.RemoveAll(t.path); err != nil {
				failed++
				m.log.Warn("failed to remove an artifact of the previous layout; it is inert, so the start continues",
					"package", m.cfg.Name, "entry", t.path, "error", err)
				continue
			}
			removed++
		}
	}
	if removed == 0 {
		m.log.Debug("no previous layout to purge", "package", m.cfg.Name)
	} else {
		m.log.Info("purged a previous installer's layout; the pinned version is installed fresh into its own version directory",
			"package", m.cfg.Name, "removed", removed)
	}
	if failed > 0 {
		m.log.Warn("not recording the purge as complete: some artifacts could not be removed, so the next start retries the sweep",
			"package", m.cfg.Name, "failed", failed)
		return
	}
	m.recordPurge()
}

// purgeTargets assembles the sweep's fixed target list. There is no scan of the
// co-owned link directory: only the names the profile declared are considered, so
// nothing another owner put there is ever a candidate.
func (m *Manager) purgeTargets(root *os.Root) []purgeTarget {
	p := m.cfg.Purge
	out := make([]purgeTarget, 0, len(p.Artifacts)+len(p.Names)+4)
	for _, path := range p.Artifacts {
		out = append(out, purgeTarget{path: path})
	}
	for _, name := range p.Names {
		out = append(out, purgeTarget{path: filepath.Join(m.cfg.LinkDir, name)})
	}
	return append(out, orphanStages(root, p.StagePrefix)...)
}

// purgeShapeMatches reports whether anything is at t.path, and whether it has the
// shape the previous installer left there. Lstat, never Stat: a symlink at a swept
// path is precisely the foreign artifact this gate exists to spare, so it must not
// be resolved to whatever it points at.
func purgeShapeMatches(root *os.Root, t purgeTarget) (present, matches bool) {
	fi, err := root.Lstat(t.path)
	if err != nil {
		return false, false
	}
	if t.dir {
		return true, fi.IsDir()
	}
	return true, fi.Mode().IsRegular()
}

// ownsLinkAt reports whether path holds this manager's own link for the artifact
// of its base name. A former link dir can sit where a Purge target names a file.
func (m *Manager) ownsLinkAt(root *os.Root, path string) bool {
	name := filepath.Base(path)
	_, own := m.linkSlot(root, filepath.Dir(path), name, name)
	return own
}

// shapeName names a target's expected shape for the refusal log line.
func shapeName(dir bool) string {
	if dir {
		return "directory"
	}
	return "regular file"
}

// orphanStages lists orphan staging trees directly under Root. The prefix is
// dot-leading, so it cannot match the installation root that now sits in the same
// directory, and an empty prefix matches nothing rather than everything.
func orphanStages(root *os.Root, prefix string) []purgeTarget {
	if prefix == "" {
		return nil
	}
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return nil
	}
	out := make([]purgeTarget, 0, len(entries))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) {
			out = append(out, purgeTarget{path: e.Name(), dir: true})
		}
	}
	return out
}

// purgeRecorded reports whether the completion marker is on the volume. A
// non-regular file at that path is NOT a marker: the sweep would rather run again
// (it is idempotent) than skip on evidence it did not write. An empty Marker means
// the profile asked for the sweep on every start.
func (m *Manager) purgeRecorded() bool {
	if m.cfg.Purge.Marker == "" {
		return false
	}
	fi, err := os.Lstat(filepath.Join(m.cfg.Root, m.cfg.Purge.Marker))
	return err == nil && fi.Mode().IsRegular()
}

// recordPurge writes the completion marker durably. A failure only warns: the
// only consequence is that the next start repeats a sweep which is by then a
// no-op on every path it looks at.
func (m *Manager) recordPurge() {
	if m.cfg.Purge.Marker == "" {
		return
	}
	path := filepath.Join(m.cfg.Root, m.cfg.Purge.Marker)
	stamp := m.now().UTC().Format("2006-01-02T15:04:05Z") + "\n"
	if err := m.writeFileDurably(m.cfg.Purge.Marker, []byte(stamp), fileMode); err != nil {
		m.log.Warn("failed to record that the purge completed; the sweep repeats on the next start, which is a no-op on a swept volume",
			"package", m.cfg.Name, "path", path, "error", err)
		return
	}
	m.log.Debug("recorded the purge as complete", "package", m.cfg.Name, "path", path)
}

// publishConvenienceLinks republishes <Root>/<LinkDir>/<Name> into sel's directory
// and retracts every other link this manager owns there and every link it owns in
// FormerLinkDirs, so no link dangles once the old version is pruned.
// Non-authoritative: every failure only warns.
// Link directories are commonly co-owned, so only an empty slot or this manager's
// own link is replaced or removed ([Manager.ownsLink]). Every step goes through an
// [os.Root] on Root: with LinkDir a symlink out of Root, an unconfined publish was
// measured landing outside Root.
func (m *Manager) publishConvenienceLinks(sel selection) {
	if m.cfg.LinkDir == "" && len(m.cfg.FormerLinkDirs) == 0 {
		return
	}
	root, err := os.OpenRoot(m.cfg.Root)
	if err != nil {
		m.log.Warn("failed to open the root to publish the convenience symlinks",
			"package", m.cfg.Name, "root", m.cfg.Root, "error", err)
		return
	}
	defer root.Close()
	var linkDirInfo fs.FileInfo
	if m.cfg.LinkDir != "" {
		m.publishInLinkDir(root, sel)
		if fi, err := root.Stat(m.cfg.LinkDir); err == nil {
			linkDirInfo = fi
		}
	}
	for _, dir := range m.cfg.FormerLinkDirs {
		if aliasesDir(root, dir, linkDirInfo) {
			m.log.Debug("not retracting the convenience symlinks in a former link dir that resolves to LinkDir",
				"package", m.cfg.Name, "path", filepath.Join(m.cfg.Root, dir))
			continue
		}
		m.retractFormerLinks(root, dir)
	}
}

// aliasesDir reports whether dir resolves through root to the directory info
// describes. It catches the symlink spellings New's lexical check cannot see,
// where retracting dir would remove the primary's link just published in LinkDir.
func aliasesDir(root *os.Root, dir string, info fs.FileInfo) bool {
	if info == nil {
		return false
	}
	fi, err := root.Stat(dir)
	return err == nil && os.SameFile(fi, info)
}

// publishInLinkDir points the primary's link in LinkDir at sel and retracts the
// strays beside it.
func (m *Manager) publishInLinkDir(root *os.Root, sel selection) {
	linkDir := filepath.Join(m.cfg.Root, m.cfg.LinkDir)
	if err := root.MkdirAll(m.cfg.LinkDir, dirMode); err != nil {
		m.log.Warn("failed to create the link dir for the convenience symlinks",
			"package", m.cfg.Name, "path", linkDir, "error", err)
		return
	}
	// Selection proved the primary is a self-contained executable.
	changed := m.publishLink(root, m.primary, filepath.Join(sel.dir, m.primary))
	changed = m.retractStrayLinks(root) || changed
	if !changed {
		return
	}
	if err := m.fsync(linkDir); err != nil {
		m.log.Warn("failed to sync the link dir after republishing the convenience symlinks",
			"package", m.cfg.Name, "error", err)
	}
}

// retractFormerLinks retracts every link this manager owns in dir, the primary's
// included, and every staged link a crash left there. A missing dir has nothing
// to retract.
func (m *Manager) retractFormerLinks(root *os.Root, dir string) {
	changed, err := m.retractOwnLinks(root, dir, false)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	path := filepath.Join(m.cfg.Root, dir)
	if err != nil {
		m.log.Warn("failed to list a former link dir to retract its convenience symlinks",
			"package", m.cfg.Name, "path", path, "error", err)
		return
	}
	if !changed {
		return
	}
	if err := m.fsync(path); err != nil {
		m.log.Warn("failed to sync a former link dir after retracting its convenience symlinks",
			"package", m.cfg.Name, "path", path, "error", err)
	}
}

// publishLink points <LinkDir>/<name> at target and reports whether it changed the
// link directory. An entry this manager does not own is left as it is.
func (m *Manager) publishLink(root *os.Root, name, target string) bool {
	link := filepath.Join(m.cfg.LinkDir, name)
	if free, own := m.linkSlot(root, m.cfg.LinkDir, name, name); !free && !own {
		m.log.Warn("not publishing a convenience symlink: another owner of the link dir holds an entry at its name",
			"package", m.cfg.Name, "path", filepath.Join(m.cfg.Root, link))
		return false
	}
	tmp := filepath.Join(m.cfg.LinkDir, stagedLinkName(name))
	_ = root.Remove(tmp)
	// The TARGET is deliberately not root-relative. os.Root resolves the name being
	// created, never the text a symlink is given, and the text has to stay the
	// absolute version-directory path an operator's shell will resolve.
	if err := root.Symlink(target, tmp); err != nil {
		m.log.Warn("failed to stage a convenience symlink",
			"package", m.cfg.Name, "path", filepath.Join(m.cfg.Root, tmp), "error", err)
		return false
	}
	if err := m.rename(root, tmp, link); err != nil {
		_ = root.Remove(tmp)
		m.log.Warn("failed to publish a convenience symlink; the bare name will not resolve, the primary path is unaffected",
			"package", m.cfg.Name, "path", filepath.Join(m.cfg.Root, link), "error", err)
		return false
	}
	m.log.Debug("published a convenience symlink",
		"package", m.cfg.Name, "path", filepath.Join(m.cfg.Root, link), "target", target)
	return true
}

// retractStrayLinks retracts every link this manager owns in LinkDir under another
// name than the primary's, and every staged link a crash left, and reports whether it
// changed the link directory.
func (m *Manager) retractStrayLinks(root *os.Root) bool {
	changed, err := m.retractOwnLinks(root, m.cfg.LinkDir, true)
	if err != nil {
		m.log.Warn("failed to list the link dir to retract stale convenience symlinks",
			"package", m.cfg.Name, "path", filepath.Join(m.cfg.Root, m.cfg.LinkDir), "error", err)
	}
	return changed
}

// retractOwnLinks retracts every link this manager owns in dir and every staged link
// a crash left there, sparing the primary's own link when keepPrimary is set, and
// reports whether it changed dir. Ownership is read off each entry rather than the
// configuration: a link an earlier installer published for a sidecar the release has
// since dropped would dangle once retention prunes its version.
func (m *Manager) retractOwnLinks(root *os.Root, dir string, keepPrimary bool) (bool, error) {
	entries, err := listLinkDir(root, dir)
	if err != nil {
		return false, err
	}
	changed := false
	for _, e := range entries {
		if e.Type()&fs.ModeSymlink == 0 {
			continue
		}
		// publishLink renames or removes its staged link before returning, so one found
		// here is a crash remnant whatever its artifact's status.
		artifact, staged := stagedLinkArtifact(e.Name())
		if keepPrimary && !staged && artifact == m.primary {
			continue
		}
		changed = m.retractLink(root, dir, e.Name(), artifact) || changed
	}
	return changed, nil
}

// listLinkDir lists a link dir through root.Open rather than root.FS: io/fs accepts
// only fs.ValidPath names, which refuses spellings validation admits ("bin/", "./bin")
// and the other link operations resolve.
func listLinkDir(root *os.Root, dir string) ([]fs.DirEntry, error) {
	f, err := root.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.ReadDir(-1)
}

// stagedLinkSuffix ends the name [Manager.publishLink] stages a link under before
// renaming it into place.
const stagedLinkSuffix = ".newlink"

// stagedLinkName is the name the link for artifact is staged under. The dot prefix
// keeps it out of a plain listing.
func stagedLinkName(artifact string) string { return "." + artifact + stagedLinkSuffix }

// stagedLinkArtifact maps an entry name in a link dir to the artifact its link would
// carry, and reports whether the entry is a staged name from [stagedLinkName].
func stagedLinkArtifact(entry string) (artifact string, staged bool) {
	rest, dotted := strings.CutPrefix(entry, ".")
	if inner, ok := strings.CutSuffix(rest, stagedLinkSuffix); dotted && ok {
		return inner, true
	}
	return entry, false
}

// retractLink removes this manager's own link for artifact at <dir>/<entry> and
// reports whether it changed dir. Anything else at that name is left alone.
func (m *Manager) retractLink(root *os.Root, dir, entry, artifact string) bool {
	if _, own := m.linkSlot(root, dir, entry, artifact); !own {
		return false
	}
	link := filepath.Join(dir, entry)
	if err := root.Remove(link); err != nil {
		m.log.Warn("failed to retract a convenience symlink; it may dangle",
			"package", m.cfg.Name, "path", filepath.Join(m.cfg.Root, link), "error", err)
		return false
	}
	m.log.Debug("retracted a convenience symlink",
		"package", m.cfg.Name, "path", filepath.Join(m.cfg.Root, link))
	return true
}

// linkSlot reports whether <dir>/<entry> is free, and whether what is there is this
// manager's own link for artifact. Lstat, never Stat: a foreign symlink must be
// judged as itself, not as whatever it points at. A slot that cannot be read is
// neither.
func (m *Manager) linkSlot(root *os.Root, dir, entry, artifact string) (free, own bool) {
	link := filepath.Join(dir, entry)
	fi, err := root.Lstat(link)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return true, false
	case err != nil, fi.Mode()&fs.ModeSymlink == 0:
		return false, false
	}
	text, err := root.Readlink(link)
	return false, err == nil && m.ownsLink(artifact, text)
}

// ownsLink reports whether a symlink for artifact name with this text has the shape
// [Manager.publishConvenienceLinks] writes: the path of an artifact of that same name
// directly inside a directory of this installation root. The shape is the ownership
// record, so nothing else is persisted, and a dangling link into a pruned version is
// still recognised and so still retracted. The test runs on the cleaned text, since
// filepath.Base and filepath.Dir skip a trailing separator rather than a component,
// and refuses a ".." element, which resolves through a symlinked directory to
// somewhere other than its lexical meaning.
func (m *Manager) ownsLink(name, text string) bool {
	if slices.Contains(strings.Split(text, string(filepath.Separator)), "..") {
		return false
	}
	clean := filepath.Clean(text)
	return filepath.Base(clean) == name && filepath.Dir(filepath.Dir(clean)) == m.versionsDir
}

// validateTargets checks each named deletion target.
func (p *Purge) validateTargets() error {
	for i, path := range p.Artifacts {
		if path == "" {
			return fmt.Errorf("pin: Purge.Artifacts[%d] is required", i)
		}
		if err := validateRelPath(fmt.Sprintf("Purge.Artifacts[%d]", i), path); err != nil {
			return err
		}
	}
	for i, name := range p.Names {
		if err := validateComponent(fmt.Sprintf("Purge.Names[%d]", i), name); err != nil {
			return err
		}
	}
	return nil
}
