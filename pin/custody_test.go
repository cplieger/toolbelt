//go:build linux

package pin

import (
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cplieger/toolbelt/v3/internal/custody"
)

// custodyRefusal is the words every custody refusal carries.
const custodyRefusal = "not under this process's exclusive control"

// refusedForCustody reports whether err is a custody refusal.
func refusedForCustody(err error) bool {
	return err != nil && strings.Contains(err.Error(), custodyRefusal)
}

// TestEnsureDeletesNothingInATreeItRefuses pins that a refused tree is read-only
// for the whole operation: the legacy purge, the partial sweep and the state
// record are writes under Root, and running any of them in a tree the manager
// refuses would claim the authority the refusal disclaims. Both shapes are
// covered: the versions directory exists, and it does not yet, where the verdict
// judges its nearest existing ancestor.
func TestEnsureDeletesNothingInATreeItRefuses(t *testing.T) {
	t.Run("the versions directory exists", func(t *testing.T) {
		env := newFakeEnv(t)
		partial := env.placePartial("1.0.0")
		if err := os.Chmod(env.root, 0o777); err != nil {
			t.Fatalf("chmod the install root: %v", err)
		}
		if err := env.manager().Ensure(t.Context()); !refusedForCustody(err) {
			t.Fatalf("Ensure error = %v, want the custody refusal", err)
		}
		if !exists(partial) {
			t.Errorf("Ensure deleted %s inside a tree it refused", partial)
		}
		if exists(env.statePath()) {
			t.Errorf("Ensure wrote %s inside a tree it refused", env.statePath())
		}
	})

	t.Run("the versions directory does not exist yet", func(t *testing.T) {
		env := newFakeEnv(t)
		legacy := filepath.Join(env.root, testLinkDir, toolName)
		if err := os.MkdirAll(filepath.Dir(legacy), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := writeFakeBinary(legacy, "0.9.0"); err != nil {
			t.Fatalf("writeFakeBinary: %v", err)
		}
		if err := os.Chmod(env.root, 0o777); err != nil {
			t.Fatalf("chmod the install root: %v", err)
		}
		m := env.manager(func(c *Config) { c.Purge = &Purge{Names: []string{toolName}} })
		if err := m.Ensure(t.Context()); !refusedForCustody(err) {
			t.Fatalf("Ensure error = %v, want the custody refusal", err)
		}
		if !exists(legacy) {
			t.Errorf("the legacy purge deleted %s in a tree the manager refused", legacy)
		}
		if exists(env.statePath()) {
			t.Errorf("Ensure wrote %s inside a tree it refused", env.statePath())
		}
	})
}

// TestEnsureRefusesAStickyInstallationRoot pins the difference between the
// installation root and its ancestors. Sticky restricts removal and renaming,
// never creation: on an ancestor that protects our own entry, but anyone able to
// create entries in the root can plant a complete-looking version directory.
func TestEnsureRefusesAStickyInstallationRoot(t *testing.T) {
	env := newFakeEnv(t)
	env.placeVersion(pinnedVersion)
	if err := os.Chmod(env.versionsRoot(), 0o777|os.ModeSticky); err != nil {
		t.Fatalf("chmod the installation root sticky and world-writable: %v", err)
	}
	err := custody.Trust{}.Verify(env.versionsRoot(), true)
	if !refusedForCustody(err) || !strings.Contains(err.Error(), "sticky") {
		t.Fatalf("Verify = %v, want a refusal that says why the sticky bit is not enough", err)
	}

	m := env.manager()
	if err := m.Ensure(t.Context()); !refusedForCustody(err) {
		t.Fatalf("Ensure error = %v, want the custody refusal", err)
	}
	if ready, _ := m.Ready(); ready {
		t.Error("Ready() = true through a sticky world-writable installation root")
	}
}

// TestFirstStartOnAStickySharedParentRunsTheOneShotPurge pins that the verdict on a
// first start judges the nearest existing directory as an ancestor. That directory
// ends the chain while the versions directory does not exist, and judged as the
// installation root a /tmp-shaped (1777) parent would refuse the one start on
// which the one-shot purge can still run.
func TestFirstStartOnAStickySharedParentRunsTheOneShotPurge(t *testing.T) {
	env := newFakeEnv(t)
	legacyFixture(t, env.root)
	legacyArtifact := filepath.Join(env.root, ".toolkit-installed")
	if err := os.Chmod(env.root, os.ModeSticky|0o777); err != nil {
		t.Fatalf("chmod the shared parent: %v", err)
	}
	if exists(env.versionsRoot()) {
		t.Fatal("the installation root already exists, so this is not a first start")
	}
	if err := (custody.Trust{}).Verify(env.root, true); !refusedForCustody(err) {
		t.Fatalf("Verify(leafIsRoot) = %v, want a refusal: the installation root is never exempted", err)
	}
	if err := (custody.Trust{}).Verify(env.root, false); err != nil {
		t.Fatalf("Verify(ancestor) = %v, want nil: a sticky ancestor is exempt from the write question", err)
	}

	m := env.manager(func(c *Config) { c.Purge = testPurge() })
	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if err := m.custodyVerdict(); err != nil {
		t.Errorf("custodyVerdict = %v, want nil on the first start", err)
	}
	if exists(legacyArtifact) {
		t.Error("the legacy artifact survived the first start, so the one-shot purge did not run")
	}
	if !exists(filepath.Join(env.root, legacyMarker)) {
		t.Error("the purge marker was not recorded on the first start")
	}
}

// TestNewWiresTheDeclaredIdentities pins that Config.TrustedUIDs reaches the
// manager's trust set, read off the resolved set so it gates at any privilege:
// the end-to-end witness below needs root to hand the tree to another uid.
func TestNewWiresTheDeclaredIdentities(t *testing.T) {
	m := newFakeEnv(t).manager(func(c *Config) { c.TrustedUIDs = []int{3000} })
	if !slices.Equal(m.trust.UIDs, []int{3000}) {
		t.Fatalf("m.trust.UIDs = %v, want the declared [3000]", m.trust.UIDs)
	}
}

// TestDeclaringTheOwnerKeepsCustodyAndAvoidsAReinstall pins what TrustedUIDs is for:
// a tree another, already privileged user owns is refused until that user is
// declared, and once declared custody holds, so a restart reuses the install
// instead of downloading it again.
func TestDeclaringTheOwnerKeepsCustodyAndAvoidsAReinstall(t *testing.T) {
	const owner = 65501
	if os.Geteuid() != 0 {
		t.Skip("handing the tree to another uid needs root")
	}
	setup := func(t *testing.T) *fakeEnv {
		t.Helper()
		env := newFakeEnv(t)
		if err := os.Chown(env.root, owner, -1); err != nil {
			t.Fatalf("chown the install root: %v", err)
		}
		return env
	}

	t.Run("refused when nothing is declared", func(t *testing.T) {
		m := setup(t).manager()
		err := m.Ensure(t.Context())
		if !refusedForCustody(err) || !strings.Contains(err.Error(), "uid 65501") || !strings.Contains(err.Error(), "TrustedUIDs") {
			t.Fatalf("Ensure error = %v, want a refusal naming uid %d and TrustedUIDs", err, owner)
		}
	})

	t.Run("declared: custody holds and a restart reuses the install", func(t *testing.T) {
		env := setup(t)
		trust := func(c *Config) { c.TrustedUIDs = []int{owner} }
		m := env.manager(trust)
		if err := m.Ensure(t.Context()); err != nil {
			t.Fatalf("Ensure with the owner declared: %v", err)
		}
		if ready, why := m.Ready(); !ready {
			t.Fatalf("Ready() = false (%s)", why)
		}
		first := env.fetchCount()
		if err := env.manager(trust).Ensure(t.Context()); err != nil {
			t.Fatalf("Ensure after a restart: %v", err)
		}
		if got := env.fetchCount(); got != first {
			t.Errorf("fetches went from %d to %d across a restart, want no reinstall", first, got)
		}
	})
}

// widenStaged makes env change the staged artifact as the staged probe runs, the
// last moment before the move judges it.
func widenStaged(env *fakeEnv, widen func(path string) error) {
	env.onProbe = func(bin string) ([]byte, error) {
		if strings.Contains(bin, stagePrefix) {
			if err := widen(bin); err != nil {
				return nil, err
			}
		}
		return env.probeAnswer(bin)
	}
}

// TestMoveArtifactRefusesToPublishAWritableArtifact pins the artifact rule at the
// move, the last point at which what the archive or the filesystem made of the
// artifact can be refused: publish renames this inode into place. The refusal
// points at TrustedUIDs only for an owner, never for a group, which no
// declaration covers.
func TestMoveArtifactRefusesToPublishAWritableArtifact(t *testing.T) {
	const refusal = "will not publish an artifact it executes that it cannot prove is private"
	t.Run("writable by its group", func(t *testing.T) {
		env := newFakeEnv(t)
		widenStaged(env, func(path string) error { return os.Chmod(path, 0o775) })
		err := env.manager().Ensure(t.Context())
		if err == nil || !strings.Contains(err.Error(), refusal) || !strings.Contains(err.Error(), "is writable by") {
			t.Fatalf("Ensure error = %v, want the move's refusal naming the writer", err)
		}
		if strings.Contains(err.Error(), "TrustedUIDs") {
			t.Errorf("Ensure error = %v points at TrustedUIDs for a group", err)
		}
		if dirs := env.versionDirs(); len(dirs) != 0 {
			t.Errorf("installation root holds %v, want nothing published", dirs)
		}
	})
	t.Run("owned by another user", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("handing the artifact to another uid needs root")
		}
		env := newFakeEnv(t)
		widenStaged(env, func(path string) error { return os.Chown(path, 4242, -1) })
		err := env.manager().Ensure(t.Context())
		if err == nil || !strings.Contains(err.Error(), refusal) || !strings.Contains(err.Error(), "is owned by uid 4242") {
			t.Fatalf("Ensure error = %v, want the move's refusal naming the owner", err)
		}
		if !strings.Contains(err.Error(), "TrustedUIDs") {
			t.Errorf("Ensure error = %v, want it to point at TrustedUIDs for a user", err)
		}
	})
}

// widenAtSentinelSync makes env run widen on the staged sentinel when it is
// synced, after the move and before assemble judges the staged directory.
func widenAtSentinelSync(env *fakeEnv, widen func(sentinel string) error) {
	env.onSync = func(path string) error {
		if filepath.Base(path) == sentinelName && strings.Contains(path, stagePrefix) {
			return widen(path)
		}
		return nil
	}
}

// TestPublishRefusesAVersionDirectoryTheFilesystemWidened pins assemble's gate on
// the two entries it creates itself. A filesystem may store a wider mode than
// requested (an inherited NFSv4 ACE on OpenZFS), and a published directory
// selection refuses would make every start reinstall while reporting success.
func TestPublishRefusesAVersionDirectoryTheFilesystemWidened(t *testing.T) {
	env := newFakeEnv(t)
	widenAtSentinelSync(env, func(sentinel string) error { return os.Chmod(filepath.Dir(sentinel), 0o777) })
	err := env.manager().Ensure(t.Context())
	if !refusedForCustody(err) || !strings.Contains(err.Error(), "because the directory itself is writable by") {
		t.Fatalf("Ensure error = %v, want assemble's refusal of the version directory", err)
	}
	if dirs := env.versionDirs(); len(dirs) != 0 {
		t.Errorf("installation root holds %v, want nothing published", dirs)
	}
}

// TestPublishRefusesAWidenedSentinel pins the same gate on the sentinel, which
// says the directory is complete: a principal who can rewrite it can mark a
// half-populated directory ready.
func TestPublishRefusesAWidenedSentinel(t *testing.T) {
	env := newFakeEnv(t)
	widenAtSentinelSync(env, func(sentinel string) error { return os.Chmod(sentinel, 0o606) })
	err := env.manager().Ensure(t.Context())
	if !refusedForCustody(err) || !strings.Contains(err.Error(), "an entry in it ("+sentinelName+") is writable by") {
		t.Fatalf("Ensure error = %v, want assemble's refusal naming the sentinel", err)
	}
	if dirs := env.versionDirs(); len(dirs) != 0 {
		t.Errorf("installation root holds %v, want nothing published", dirs)
	}
}

// TestRescanRefusesATreeThatLostCustody pins that Rescan judges custody itself: a
// tree re-permissioned after a clean start is refused, and the version this
// process installed there is no longer activated.
func TestRescanRefusesATreeThatLostCustody(t *testing.T) {
	env := newFakeEnv(t)
	m := env.manager()
	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if err := os.Chmod(env.root, 0o777); err != nil {
		t.Fatalf("chmod the install root: %v", err)
	}
	ok, err := m.Rescan(t.Context())
	if ok || !refusedForCustody(err) {
		t.Fatalf("Rescan = (%v, %v), want (false, the custody refusal)", ok, err)
	}
	if ready, why := m.Ready(); ready || why != ReasonUnavailable {
		t.Errorf("Ready() = (%v, %v), want (false, %v)", ready, why, ReasonUnavailable)
	}
}

// TestARefusedTreeExecutesNoPlacedVersion pins that trust is judged before any
// probe: selection and retention never run a binary from a directory in a tree
// custody refused, through Ensure or through Rescan.
func TestARefusedTreeExecutesNoPlacedVersion(t *testing.T) {
	env := newFakeEnv(t)
	planted := env.placeVersion(prevVersion)
	if err := os.Chmod(env.root, 0o777); err != nil {
		t.Fatalf("chmod the install root: %v", err)
	}
	m := env.manager()
	if err := m.Ensure(t.Context()); !refusedForCustody(err) {
		t.Fatalf("Ensure error = %v, want the custody refusal", err)
	}
	if _, err := m.Rescan(t.Context()); !refusedForCustody(err) {
		t.Fatalf("Rescan error = %v, want the custody refusal", err)
	}
	if got := env.countCalls("probe " + filepath.Join(planted, toolName)); got != 0 {
		t.Errorf("the placed artifact was executed %d times in a tree custody refused", got)
	}
}

// TestFinishDoesNotMutateATreeWhoseVerdictFlippedMidOperation pins the writes
// finish makes, the links and their stray sweep, against a verdict that flips
// during the operation: clean at the start, so selection succeeds, then refused
// by the install's own check, so finish runs with a selection in a tree it may
// not change.
func TestFinishDoesNotMutateATreeWhoseVerdictFlippedMidOperation(t *testing.T) {
	env := newFakeEnv(t)
	env.placeVersion("1.0.0")
	flipped := false
	env.onProbe = func(bin string) ([]byte, error) {
		if !flipped {
			flipped = true
			if err := os.Chmod(env.root, 0o777); err != nil {
				return nil, err
			}
		}
		return env.probeAnswer(bin)
	}
	stray := filepath.Join(env.root, testLinkDir, "toolkit-legacy")
	if err := os.MkdirAll(filepath.Dir(stray), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Symlink(filepath.Join(env.versionDir("0.8.0"), "toolkit-legacy"), stray); err != nil {
		t.Fatalf("Symlink(%s): %v", stray, err)
	}
	m := env.manager()

	if err := m.Ensure(t.Context()); !refusedForCustody(err) {
		t.Fatalf("Ensure error = %v, want the install's custody refusal", err)
	}
	if m.custodyVerdict() == nil {
		t.Fatal("the fixture did not flip the verdict")
	}
	if got := m.Version(); got != "1.0.0" {
		t.Fatalf("Version() = %q, want the selection made before the flip", got)
	}
	if exists(filepath.Join(env.root, testLinkDir, toolName)) {
		t.Error("the convenience link was published in a tree the operation refused to change")
	}
	if !exists(stray) {
		t.Error("the stray-link sweep retracted a link in a tree the operation refused to change")
	}
	if exists(env.statePath()) {
		t.Error("the state record was written in a tree the operation refused to change")
	}
}

// TestAnUncontrolledTreeIsWarnedAbout pins the verdict's log line, the only place
// an operator learns that a sentinel in this tree is no longer evidence, and its
// absence on a clean tree. 0707 grants everyone write and the group nothing, so
// the tree is shared whatever uid or gid runs the test.
func TestAnUncontrolledTreeIsWarnedAbout(t *testing.T) {
	logs := captureLogs(t)
	env := newFakeEnv(t)
	if err := os.MkdirAll(env.versionsRoot(), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Chmod(env.versionsRoot(), 0o707); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	shared := env.manager()
	shared.checkCustody()
	if shared.custodyVerdict() == nil {
		t.Fatal("custodyVerdict is nil on a tree everyone can write")
	}
	if got := logs.at(slog.LevelWarn, "root"); len(got) != 1 || got[0].attrs["root"] != env.versionsRoot() {
		t.Fatalf("Warn records naming the installation root = %v, want one naming %s", got, env.versionsRoot())
	}

	clean := newFakeEnv(t)
	if err := os.MkdirAll(clean.versionsRoot(), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	private := clean.manager()
	private.checkCustody()
	if err := private.custodyVerdict(); err != nil {
		t.Fatalf("custodyVerdict = %v, want nil on a private tree", err)
	}
	if got := logs.at(slog.LevelWarn, "root"); len(got) != 1 {
		t.Errorf("Warn records naming the installation root = %v, want none added by a private tree", got)
	}
}
