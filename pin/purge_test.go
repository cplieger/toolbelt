//go:build linux

package pin

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The layout a previous installer of this package is imagined to have left behind.
// Every one of these facts is INJECTED: the library carries no knowledge of any
// consumer's migration history, which is why Purge is a parameter rather than
// behaviour.
const (
	legacyStagePrefix = ".toolkit-stage."
	legacyMarker      = ".toolkit-legacy-purged"
)

func legacyArtifacts() []string {
	return []string{
		".toolkit-update-in-progress",
		".toolkit-installed",
		".toolkit-ready",
		testLinkDir + "/.toolkit.prev",
		testLinkDir + "/.toolkit.prev.absent",
	}
}

func legacyNames() []string {
	return []string{toolName, toolSidecar, toolExtra}
}

// testPurge is the full injected sweep the tests drive.
func testPurge() *Purge {
	return &Purge{
		Artifacts:   legacyArtifacts(),
		Names:       legacyNames(),
		StagePrefix: legacyStagePrefix,
		Marker:      legacyMarker,
	}
}

// legacyFixture plants the whole previous layout, every entry in the SHAPE the old
// installer left it in (regular files, and a directory for the staging tree), which
// is what the sweep requires before it removes anything. It returns every path it
// created, relative to Root.
func legacyFixture(t *testing.T, root string) []string {
	t.Helper()
	for _, d := range []string{
		filepath.Join(root, testLinkDir),
		filepath.Join(root, legacyStagePrefix+"abc123"),
	} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("MkdirAll(%s): %v", d, err)
		}
	}
	files := legacyArtifacts()
	for _, name := range legacyNames() {
		files = append(files, testLinkDir+"/"+name)
	}
	files = append(files, legacyStagePrefix+"abc123/leftover")
	for _, rel := range files {
		p := filepath.Join(root, rel)
		if err := os.WriteFile(p, []byte("legacy\n"), 0o600); err != nil {
			t.Fatalf("WriteFile(%s): %v", p, err)
		}
	}
	return files
}

// TestPurgeDeletesTheWholeInjectedLayout pins the sweep: every declared artifact,
// every declared name under LinkDir, and every orphan staging tree goes -- and the
// co-owned link directory itself does not.
func TestPurgeDeletesTheWholeInjectedLayout(t *testing.T) {
	env := newFakeEnv(t)
	files := legacyFixture(t, env.root)
	m := env.manager(func(c *Config) { c.Purge = testPurge() })

	m.purge()

	for _, rel := range files {
		if exists(filepath.Join(env.root, rel)) {
			t.Errorf("%s survived the purge", rel)
		}
	}
	if exists(filepath.Join(env.root, legacyStagePrefix+"abc123")) {
		t.Error("the orphan staging tree survived the purge")
	}
	if !exists(filepath.Join(env.root, testLinkDir)) {
		t.Error("the purge removed the link directory, which another owner may co-own")
	}
	if !exists(filepath.Join(env.root, legacyMarker)) {
		t.Error("the completion marker was not recorded after a clean sweep")
	}
}

// TestPurgeRefusesAnEntryOfTheWrongShape pins the shape gate, which is what makes the
// sweep safe in a co-owned directory: another installer publishes a SYMLINK at
// exactly one of these names, and the old installer of this package never did, so a
// symlink there is somebody else's live pointer.
func TestPurgeRefusesAnEntryOfTheWrongShape(t *testing.T) {
	tests := map[string]struct {
		plant func(t *testing.T, root string) string
	}{
		"a symlink where a regular file is expected": {
			plant: func(t *testing.T, root string) string {
				other := filepath.Join(root, "other-owner-tree")
				if err := os.MkdirAll(other, 0o755); err != nil {
					t.Fatalf("MkdirAll: %v", err)
				}
				link := filepath.Join(root, testLinkDir, toolName)
				if err := os.Symlink(other, link); err != nil {
					t.Fatalf("Symlink: %v", err)
				}
				return link
			},
		},
		"a directory where a regular file is expected": {
			plant: func(t *testing.T, root string) string {
				dir := filepath.Join(root, testLinkDir, toolSidecar)
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatalf("MkdirAll: %v", err)
				}
				return dir
			},
		},
		"a regular file where a staging directory is expected": {
			plant: func(t *testing.T, root string) string {
				p := filepath.Join(root, legacyStagePrefix+"notadir")
				if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
				return p
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			env := newFakeEnv(t)
			if err := os.MkdirAll(filepath.Join(env.root, testLinkDir), 0o755); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			spared := tc.plant(t, env.root)
			m := env.manager(func(c *Config) { c.Purge = testPurge() })

			m.purge()

			if !exists(spared) {
				t.Errorf("the sweep removed %s, whose shape the previous layout never had there", spared)
			}
		})
	}
}

// TestPurgeIsIdempotentAndSurvivesInterruption pins the two properties a start-time
// delete sequence needs. Every step is an independent RemoveAll of a fixed path, so a
// second run is a no-op and a run that starts from a half-swept volume finishes the
// job.
func TestPurgeIsIdempotentAndSurvivesInterruption(t *testing.T) {
	t.Run("idempotent", func(t *testing.T) {
		env := newFakeEnv(t)
		files := legacyFixture(t, env.root)
		m := env.manager(func(c *Config) { c.Purge = testPurge() })

		m.purge()
		m.purge()
		m.purge()

		for _, rel := range files {
			if exists(filepath.Join(env.root, rel)) {
				t.Errorf("%s survived repeated purges", rel)
			}
		}
	})

	t.Run("no previous layout at all", func(t *testing.T) {
		env := newFakeEnv(t)
		m := env.manager(func(c *Config) { c.Purge = testPurge() })
		m.purge() // a swept volume: every step is a no-op
		if !exists(filepath.Join(env.root, legacyMarker)) {
			t.Error("a no-op sweep did not record completion")
		}
	})

	t.Run("resumes from a partially swept volume", func(t *testing.T) {
		env := newFakeEnv(t)
		files := legacyFixture(t, env.root)
		// Simulate a kill mid-sequence: a prefix of the deletes already ran.
		for _, rel := range []string{testLinkDir + "/" + toolName, ".toolkit-installed", ".toolkit-ready"} {
			if err := os.RemoveAll(filepath.Join(env.root, rel)); err != nil {
				t.Fatalf("RemoveAll(%s): %v", rel, err)
			}
		}
		m := env.manager(func(c *Config) { c.Purge = testPurge() })

		m.purge()

		for _, rel := range files {
			if exists(filepath.Join(env.root, rel)) {
				t.Errorf("%s survived the resumed purge", rel)
			}
		}
	})
}

// TestPurgeMarkerMakesTheSweepRunOncePerVolume pins the marker's two jobs: a recorded
// marker skips the sweep entirely, and a marker that is not a regular file is not
// evidence this manager wrote it, so the sweep runs again rather than trusting it.
func TestPurgeMarkerMakesTheSweepRunOncePerVolume(t *testing.T) {
	t.Run("a recorded marker skips the sweep", func(t *testing.T) {
		env := newFakeEnv(t)
		legacyFixture(t, env.root)
		if err := os.WriteFile(filepath.Join(env.root, legacyMarker), []byte("done\n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		m := env.manager(func(c *Config) { c.Purge = testPurge() })

		m.purgeOnce()

		if !exists(filepath.Join(env.root, ".toolkit-installed")) {
			t.Error("the sweep ran although the volume records it as complete")
		}
	})

	t.Run("a non-regular marker is not evidence", func(t *testing.T) {
		env := newFakeEnv(t)
		legacyFixture(t, env.root)
		if err := os.MkdirAll(filepath.Join(env.root, legacyMarker), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		m := env.manager(func(c *Config) { c.Purge = testPurge() })

		m.purgeOnce()

		if exists(filepath.Join(env.root, ".toolkit-installed")) {
			t.Error("the sweep skipped on a marker it did not write")
		}
	})

	t.Run("an empty Marker sweeps on every start", func(t *testing.T) {
		env := newFakeEnv(t)
		legacyFixture(t, env.root)
		p := testPurge()
		p.Marker = ""
		m := env.manager(func(c *Config) { c.Purge = p })

		if m.purgeRecorded() {
			t.Error("purgeRecorded reported a marker although none is configured")
		}
		m.purge()
		if exists(filepath.Join(env.root, ".toolkit-installed")) {
			t.Error("the sweep did not run with no marker configured")
		}
		for _, e := range mustReadDir(t, env.root) {
			if strings.HasPrefix(e, ".toolkit-legacy") {
				t.Errorf("a marker %q was written although none is configured", e)
			}
		}
	})
}

// TestPurgeWithdrawsTheMarkerWhenSomethingCouldNotBeRemoved pins that the sweep never
// records a job it did not finish: an undeletable artifact leaves the marker unwritten
// so the next start retries.
//
// The only portable way to make a delete fail is to remove the permission to unlink,
// which root does not obey, so the case is skipped when the suite runs privileged. CI
// runs unprivileged, which is where this assertion earns its place.
func TestPurgeWithdrawsTheMarkerWhenSomethingCouldNotBeRemoved(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: a read-only parent directory does not stop an unlink")
	}
	env := newFakeEnv(t)
	legacyFixture(t, env.root)
	// A non-empty directory whose own mode forbids unlinking its child.
	locked := filepath.Join(env.root, legacyStagePrefix+"locked")
	if err := os.MkdirAll(filepath.Join(locked, "child"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Chmod(locked, 0o500); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	m := env.manager(func(c *Config) { c.Purge = testPurge() })

	m.purge()

	if exists(filepath.Join(env.root, legacyMarker)) {
		t.Error("the purge recorded completion although an artifact could not be removed")
	}
}

// TestPurgeRefusesTheRootItself pins the worst thing a mis-declared profile could ask
// for. "." passes the relative-path validation, so the shape gate is what stops the
// sweep from deleting the installation root: the root is not a regular file.
func TestPurgeRefusesTheRootItself(t *testing.T) {
	env := newFakeEnv(t)
	legacyFixture(t, env.root)
	m := env.manager(func(c *Config) {
		c.Purge = &Purge{Artifacts: []string{"."}, Marker: legacyMarker}
	})

	m.purge()

	if !exists(env.root) {
		t.Fatal("the sweep removed the installation root")
	}
	if !exists(filepath.Join(env.root, testLinkDir)) {
		t.Error("the sweep removed the root's contents")
	}
}

// TestNilPurgeSweepsNothing pins the off switch: with no Purge configured the sweep
// does not run at all, and nothing a previous installer left is touched.
func TestNilPurgeSweepsNothing(t *testing.T) {
	env := newFakeEnv(t)
	files := legacyFixture(t, env.root)
	m := env.manager()

	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	// The legacy files at the artifact names included: the convenience links replace
	// only an empty slot or the manager's own link.
	for _, rel := range files {
		if fi, err := os.Lstat(filepath.Join(env.root, rel)); err != nil || !fi.Mode().IsRegular() {
			t.Errorf("%s was removed or replaced although no Purge is configured", rel)
		}
	}
	for _, e := range mustReadDir(t, env.root) {
		if strings.Contains(e, "legacy-purged") {
			t.Errorf("a purge marker %q was written although no Purge is configured", e)
		}
	}
}

// TestPurgeRunsOncePerProcess pins that the sweep is latched: a retry or a rescan
// does not sweep again, and the convenience link published at a swept name survives.
func TestPurgeRunsOncePerProcess(t *testing.T) {
	env := newFakeEnv(t)
	m := env.manager(func(c *Config) { c.Purge = testPurge() })

	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	link := filepath.Join(env.root, testLinkDir, toolName)
	if !exists(link) {
		t.Fatal("the convenience symlink was not published")
	}
	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	if !exists(link) {
		t.Error("a second Ensure purged the convenience symlink it had just published")
	}
}

// TestConvenienceLinkPointsAtTheActiveArtifact pins the operator path: the link is
// republished as a symlink at the active version's artifact, so a bare-name lookup
// keeps resolving after the version-addressed move.
func TestConvenienceLinkPointsAtTheActiveArtifact(t *testing.T) {
	env := newFakeEnv(t)
	m := env.manager()

	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	link := filepath.Join(env.root, testLinkDir, toolName)
	fi, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("Lstat(%s): %v", link, err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("%s is not a symlink (mode %v)", link, fi.Mode())
	}
	target, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("Readlink: %v", err)
	}
	if target != m.Path() {
		t.Errorf("symlink target = %q, want the active artifact %q", target, m.Path())
	}
	// No temp link may be left behind by the atomic publish.
	if exists(filepath.Join(env.root, testLinkDir, "."+toolName+".newlink")) {
		t.Error("the staged temp link survived publication")
	}
}

// TestEmptyLinkDirPublishesNoLink pins the off switch by ABSENCE: with no LinkDir the
// directory is never created and the install is ready anyway, because the link was
// never an input to anything.
func TestEmptyLinkDirPublishesNoLink(t *testing.T) {
	env := newFakeEnv(t)
	m := env.manager(func(c *Config) { c.LinkDir = "" })

	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if ready, why := m.Ready(); !ready {
		t.Errorf("Ready() = false (%s), want true", why)
	}
	if exists(filepath.Join(env.root, testLinkDir)) {
		t.Error("a link directory was created although LinkDir is empty")
	}
	for _, e := range mustReadDir(t, env.root) {
		if e == toolName {
			t.Error("a bare artifact name was published under Root although LinkDir is empty")
		}
	}
}

// TestConvenienceLinkIsNeverConsultedForReadiness pins the other half: the link is
// CONVENIENCE ONLY. A failed publish, a dangling link, and a link replaced by a plain
// file must all leave readiness and Path untouched, because the manager never reads
// it.
func TestConvenienceLinkIsNeverConsultedForReadiness(t *testing.T) {
	t.Run("a failed publish does not withhold readiness", func(t *testing.T) {
		env := newFakeEnv(t)
		link := filepath.Join(env.root, testLinkDir, toolName)
		env.onRename = failRenameTo(link)
		m := env.manager()

		if err := m.Ensure(t.Context()); err != nil {
			t.Fatalf("Ensure error = %v, want nil: a convenience-link failure must not fail the install", err)
		}
		if ready, why := m.Ready(); !ready {
			t.Errorf("Ready() = false (%s), want true despite the link failure", why)
		}
		if exists(link) {
			t.Error("the link exists although its publish rename failed")
		}
		// And the failed publish leaves no debris in a directory this package does not
		// own: the staged temp is removed on the failure path too, or a co-owner's
		// directory collects one per start.
		if exists(filepath.Join(env.root, testLinkDir, "."+toolName+".newlink")) {
			t.Error("the staged temp link survived the failed publish")
		}
	})

	t.Run("a sabotaged link does not affect a rescan", func(t *testing.T) {
		env := newFakeEnv(t)
		m := env.manager()
		if err := m.Ensure(t.Context()); err != nil {
			t.Fatalf("Ensure: %v", err)
		}
		want := m.Path()
		link := filepath.Join(env.root, testLinkDir, toolName)
		if err := os.Remove(link); err != nil {
			t.Fatalf("Remove: %v", err)
		}
		if err := os.Symlink(filepath.Join(env.root, "nowhere"), link); err != nil {
			t.Fatalf("Symlink: %v", err)
		}

		ok, err := m.Rescan(t.Context())
		if !ok || err != nil {
			t.Fatalf("Rescan = (%v, %v), want (true, nil)", ok, err)
		}
		if ready, why := m.Ready(); !ready {
			t.Errorf("Ready() = false (%s), want true: the link is not an integrity input", why)
		}
		if got := m.Path(); got != want {
			t.Errorf("Path() = %q, want the version-directory path %q", got, want)
		}
	})
}

// TestPurgeSweepsEveryDeclaredLinkName pins the Names half of the sweep on its own.
// A consumer migrating away from a layout that only ever published bare names declares
// no artifacts at all, and every name it does declare has to be swept from LinkDir —
// the list is the whole of what the sweep is entitled to touch there, so a name left
// behind is a stale bare command an operator's shell keeps finding.
//
// The artifact names get the manager's own symlinks after the sweep, so the check is
// that no legacy regular file survives at any name, not that every name is empty. A
// legacy file the sweep missed also blocks the link, because it is not the manager's.
func TestPurgeSweepsEveryDeclaredLinkName(t *testing.T) {
	names := []string{toolName, toolSidecar, toolExtra, "toolkit-old", "toolkit-legacy", "toolkit-ancient"}
	env := newFakeEnv(t)
	linkDir := filepath.Join(env.root, testLinkDir)
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", linkDir, err)
	}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(linkDir, name), []byte("legacy\n"), 0o600); err != nil {
			t.Fatalf("WriteFile(%s): %v", name, err)
		}
	}
	m := env.manager(func(c *Config) { c.Purge = &Purge{Names: names, Marker: legacyMarker} })

	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	for _, name := range names {
		if fi, err := os.Lstat(filepath.Join(linkDir, name)); err == nil && fi.Mode().IsRegular() {
			t.Errorf("%s survived the sweep although the profile declared it", name)
		}
	}
}

// TestPurgeRecordsWhatItRemoved pins the sweep's own audit line. The purge is the one
// destructive act this library performs on a volume it did not create, and the count it
// reports is all an operator gets to reconcile against: a sweep that removed something
// says so at Info, and a volume with nothing to migrate stays quiet.
func TestPurgeRecordsWhatItRemoved(t *testing.T) {
	logs := captureLogs(t)
	env := newFakeEnv(t)
	planted := legacyFixture(t, env.root)
	m := env.manager(func(c *Config) { c.Purge = testPurge() })

	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	got := logs.at(slog.LevelInfo, "removed")
	if len(got) != 1 {
		t.Fatalf("Info records carrying a removal count = %d, want 1: the sweep's record of what it deleted", len(got))
	}
	// Every planted path except the one the fixture leaves absent, plus the staging tree
	// its leftover sits in.
	if want := "9"; got[0].attrs["removed"] != want {
		t.Errorf("removed = %q, want %q from the %d planted paths", got[0].attrs["removed"], want, len(planted))
	}
}

// TestPurgeMarkerFailureWarnsAndLeavesTheSweepDone pins the marker's failure posture.
// Losing the marker only costs a repeated sweep, which is a no-op on a swept volume, so
// it must not fail the start — but it has to be visible, or a volume that sweeps on
// every start looks like a library that cannot count.
func TestPurgeMarkerFailureWarnsAndLeavesTheSweepDone(t *testing.T) {
	logs := captureLogs(t)
	env := newFakeEnv(t)
	legacyFixture(t, env.root)
	marker := filepath.Join(env.root, legacyMarker)
	env.onRename = failRenameTo(marker)
	m := env.manager(func(c *Config) { c.Purge = testPurge() })

	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure error = %v, want nil: the completion marker is not on the readiness path", err)
	}
	if exists(marker) {
		t.Fatal("the marker exists although its write failed, so this fixture proves nothing")
	}
	got := logs.at(slog.LevelWarn, "path")
	if len(got) != 1 || got[0].attrs["path"] != marker {
		t.Errorf("Warn records naming a path = %v, want one naming %s", got, marker)
	}
}

// TestConvenienceLinkSyncFailureWarns pins the last step of the convenience publish.
// The link is already in place by then, so an unsynced parent costs only the link's
// survival across a crash — a warning, never a withheld verdict, and never silence.
func TestConvenienceLinkSyncFailureWarns(t *testing.T) {
	logs := captureLogs(t)
	env := newFakeEnv(t)
	linkDir := filepath.Join(env.root, testLinkDir)
	env.onSync = func(path string) error {
		if path == linkDir {
			return errors.New("injected sync failure")
		}
		return nil
	}
	m := env.manager()

	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure error = %v, want nil: the convenience link is never an integrity input", err)
	}
	if ready, why := m.Ready(); !ready {
		t.Errorf("Ready() = false (%s), want true", why)
	}
	if got := logs.at(slog.LevelWarn, "error"); len(got) != 1 {
		t.Errorf("Warn records carrying an error = %d, want 1 for the unsynced link directory; got %v",
			len(got), logs.messages(slog.LevelWarn))
	}
}

func mustReadDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", dir, err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// TestConvenienceLinkPublishStaysUnderRoot pins the link publish inside Root.
//
// LinkDir is the one tree this package writes into that nothing has proved anything
// about: the custody walk judges the installation root and the ancestors above it,
// and LinkDir is a SIBLING of that root, so it is never on the chain. The README
// says a directory holding a convenience link is commonly co-owned, and the purge
// already confines its DELETES there for exactly that reason — so a plant at that
// name is a shape to expect, not an exotic one.
//
// Before the confinement this published the symlink outside Root entirely,
// contradicting the package's own claim that Root is the only tree it writes.
func TestConvenienceLinkPublishStaysUnderRoot(t *testing.T) {
	env := newFakeEnv(t)
	outside := filepath.Join(filepath.Dir(env.root), "outside")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatalf("MkdirAll the directory outside Root: %v", err)
	}
	if err := os.MkdirAll(env.root, 0o755); err != nil {
		t.Fatalf("MkdirAll Root: %v", err)
	}
	// Another owner of the tree puts a pointer out of Root at the link directory's
	// name, which sticky permits: it restricts removal and renaming, never CREATE.
	if err := os.Symlink(outside, filepath.Join(env.root, testLinkDir)); err != nil {
		t.Fatalf("Symlink the link dir out of Root: %v", err)
	}

	m := env.manager()
	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	if entries := mustReadDir(t, outside); len(entries) != 0 {
		t.Errorf("the publish wrote %v outside Root, want nothing", entries)
	}
	// And the failure is a warning, not a withheld verdict: the link is not an
	// integrity input, so an unpublishable one must not cost readiness.
	if ready, why := m.Ready(); !ready {
		t.Errorf("Ready() = false (%s), want true: the convenience link is never an integrity input", why)
	}
	if got, want := m.Path(), filepath.Join(env.versionDir(pinnedVersion), toolName); got != want {
		t.Errorf("Path() = %q, want %q", got, want)
	}
}

// TestPurgeMarkerWriteStaysUnderRoot pins the durable write inside Root.
//
// The marker and the state record are the two files this package writes DIRECTLY
// under Root, through a temp name in the same directory. Root reaches the custody
// walk as an ANCESTOR of the installation root, so a sticky one passes the check
// while still letting another principal create entries in it — and the temp name is
// derivable from the profile. Before the confinement, os.WriteFile followed a
// symlink planted at that name: measured, a file outside Root was truncated and
// overwritten, and the marker path was left as a symlink pointing at it.
func TestPurgeMarkerWriteStaysUnderRoot(t *testing.T) {
	env := newFakeEnv(t)
	outside := filepath.Join(filepath.Dir(env.root), "outside")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatalf("MkdirAll the directory outside Root: %v", err)
	}
	if err := os.MkdirAll(env.root, 0o755); err != nil {
		t.Fatalf("MkdirAll Root: %v", err)
	}
	victim := filepath.Join(outside, "victim")
	const want = "ORIGINAL\n"
	if err := os.WriteFile(victim, []byte(want), 0o600); err != nil {
		t.Fatalf("seed the file outside Root: %v", err)
	}
	for _, name := range []string{"." + legacyMarker + ".tmp", "." + toolName + stateSuffix + ".tmp"} {
		if err := os.Symlink(victim, filepath.Join(env.root, name)); err != nil {
			t.Fatalf("Symlink %s at the temp name: %v", name, err)
		}
	}

	m := env.manager(func(c *Config) { c.Purge = &Purge{Marker: legacyMarker} })
	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	got, err := os.ReadFile(victim)
	switch {
	case err != nil:
		t.Fatalf("the file outside Root is gone: %v", err)
	case string(got) != want:
		t.Errorf("the file outside Root now holds %q, want it untouched at %q", string(got), want)
	}
}

// readLink returns the text of the symlink at path, failing the test when path is
// anything else.
func readLink(t *testing.T, path string) string {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat(%s): %v", path, err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("%s is not a symlink (mode %v)", path, fi.Mode())
	}
	text, err := os.Readlink(path)
	if err != nil {
		t.Fatalf("Readlink(%s): %v", path, err)
	}
	return text
}

// TestConvenienceLinksCoverEveryInstalledArtifact pins the link set: the primary,
// every required artifact and every optional one the version holds each get a link
// into the active version directory, because a primary that re-execs a sidecar by
// bare name finds it only if the sidecar resolves from the same directory. An
// optional artifact the archive did not provide gets no link at all, never a
// dangling one.
func TestConvenienceLinksCoverEveryInstalledArtifact(t *testing.T) {
	t.Run("every artifact the version holds", func(t *testing.T) {
		env := newFakeEnv(t)
		m := env.manager()
		if err := m.Ensure(t.Context()); err != nil {
			t.Fatalf("Ensure: %v", err)
		}
		for _, name := range []string{toolName, toolSidecar, toolExtra} {
			link := filepath.Join(env.root, testLinkDir, name)
			if got, want := readLink(t, link), filepath.Join(env.versionDir(pinnedVersion), name); got != want {
				t.Errorf("%s -> %q, want %q", name, got, want)
			}
			if exists(filepath.Join(env.root, testLinkDir, "."+name+".newlink")) {
				t.Errorf("the staged temp link for %s survived publication", name)
			}
		}
	})

	t.Run("an optional artifact the archive lacks", func(t *testing.T) {
		env := newFakeEnv(t)
		delete(env.produces, toolExtra)
		m := env.manager()
		if err := m.Ensure(t.Context()); err != nil {
			t.Fatalf("Ensure: %v", err)
		}
		if exists(filepath.Join(env.root, testLinkDir, toolExtra)) {
			t.Errorf("a link was published for %s, which the active version does not hold", toolExtra)
		}
		if got, want := readLink(t, filepath.Join(env.root, testLinkDir, toolSidecar)), filepath.Join(env.versionDir(pinnedVersion), toolSidecar); got != want {
			t.Errorf("%s -> %q, want %q", toolSidecar, got, want)
		}
	})
}

// TestConvenienceLinksFollowAVersionSwitch pins the set across an activation that
// changes what the version holds: every link moves to the new version, and the link
// of an optional artifact the new version dropped is retracted rather than left
// pointing at the old one, where it would dangle once retention prunes it.
func TestConvenienceLinksFollowAVersionSwitch(t *testing.T) {
	const nextVersion = "2.14.3"
	env := newFakeEnv(t)
	if err := env.manager().Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure %s: %v", pinnedVersion, err)
	}
	if !exists(filepath.Join(env.root, testLinkDir, toolExtra)) {
		t.Fatalf("no %s link after the first activation, so this fixture proves nothing", toolExtra)
	}
	env.placeVersion(nextVersion, toolName, toolSidecar)

	m := env.manager(func(c *Config) { c.Version = nextVersion })
	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure %s: %v", nextVersion, err)
	}
	if got := m.Version(); got != nextVersion {
		t.Fatalf("active version = %q, want %q", got, nextVersion)
	}

	for _, name := range []string{toolName, toolSidecar} {
		if got, want := readLink(t, filepath.Join(env.root, testLinkDir, name)), filepath.Join(env.versionDir(nextVersion), name); got != want {
			t.Errorf("%s -> %q, want %q", name, got, want)
		}
	}
	if _, err := os.Lstat(filepath.Join(env.root, testLinkDir, toolExtra)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Lstat(%s) error = %v, want not-exist: the new version ships no %s", toolExtra, err, toolExtra)
	}
}

// TestConvenienceLinksRetractADanglingOwnedLink pins that ownership is read from the
// link text and never from its target: a link of this manager's shape into a version
// directory retention already pruned is still its own, so it is removed when the
// active version lacks that artifact.
func TestConvenienceLinksRetractADanglingOwnedLink(t *testing.T) {
	env := newFakeEnv(t)
	delete(env.produces, toolExtra)
	linkDir := filepath.Join(env.root, testLinkDir)
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	pruned := filepath.Join(env.versionDir("2.0.0"), toolExtra)
	if exists(pruned) {
		t.Fatalf("%s exists, so the planted link would not dangle", pruned)
	}
	link := filepath.Join(linkDir, toolExtra)
	if err := os.Symlink(pruned, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	if err := env.manager().Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if _, err := os.Lstat(link); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Lstat(%s) error = %v, want not-exist: a dangling link of this manager's shape must be retracted", toolExtra, err)
	}
}

// TestConvenienceLinksLeaveAForeignEntryAlone pins the ownership rule in the
// co-owned link directory, through the purge and the republish together. Another
// installer's entry at one of the artifact names, or anywhere else there, is neither
// replaced when the active version holds that artifact nor retracted when it does
// not: only an empty slot or a link of this manager's own shape is ever touched.
func TestConvenienceLinksLeaveAForeignEntryAlone(t *testing.T) {
	foreign := map[string]func(env *fakeEnv) string{
		"a link into another tool tree": func(env *fakeEnv) string {
			return filepath.Join(env.root, "opt", toolExtra, "1.0.0", toolExtra)
		},
		"a link into this tree at another artifact": func(env *fakeEnv) string {
			return filepath.Join(env.versionDir(pinnedVersion), toolName)
		},
		"a relative link": func(*fakeEnv) string {
			return filepath.Join("..", toolName+versionsSuffix, pinnedVersion, toolExtra)
		},
	}
	for name, targetOf := range foreign {
		for _, holds := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s, version holds it %v", name, holds), func(t *testing.T) {
				env := newFakeEnv(t)
				if !holds {
					delete(env.produces, toolExtra)
				}
				linkDir := filepath.Join(env.root, testLinkDir)
				if err := os.MkdirAll(linkDir, 0o755); err != nil {
					t.Fatalf("MkdirAll: %v", err)
				}
				planted := map[string]string{
					toolExtra:   targetOf(env),
					"othertool": filepath.Join(env.root, "opt", "othertool", "2.0.0", "othertool"),
				}
				for link, target := range planted {
					if err := os.Symlink(target, filepath.Join(linkDir, link)); err != nil {
						t.Fatalf("Symlink(%s): %v", link, err)
					}
				}
				m := env.manager(func(c *Config) { c.Purge = testPurge() })

				if err := m.Ensure(t.Context()); err != nil {
					t.Fatalf("Ensure: %v", err)
				}
				if _, err := m.Rescan(t.Context()); err != nil {
					t.Fatalf("Rescan: %v", err)
				}
				for link, want := range planted {
					if got := readLink(t, filepath.Join(linkDir, link)); got != want {
						t.Errorf("foreign %s -> %q, want it untouched at %q", link, got, want)
					}
				}
				if got, want := readLink(t, filepath.Join(linkDir, toolSidecar)), filepath.Join(env.versionDir(pinnedVersion), toolSidecar); got != want {
					t.Errorf("%s -> %q, want %q: a foreign entry must not stop the rest of the set", toolSidecar, got, want)
				}
			})
		}
	}
}
