//go:build linux

package pin

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/toolbelt/v3/internal/retain"
)

// TestVersionDirCompleteRejectsEveryIncompleteShape pins what "complete" means. The
// sentinel is the ONLY thing that separates a finished install from a directory an
// interrupted one left behind, and it is checked against the directory's own name so
// a retained predecessor still reads as complete.
func TestVersionDirCompleteRejectsEveryIncompleteShape(t *testing.T) {
	tests := map[string]struct {
		setup func(t *testing.T, dir string)
		want  bool
	}{
		"complete set": {
			setup: func(t *testing.T, dir string) {
				writeSet(t, dir, pinnedVersion, toolName)
				writeSentinelFile(t, dir, pinnedVersion)
			},
			want: true,
		},
		"artifacts but no sentinel (interrupted install)": {
			setup: func(t *testing.T, dir string) {
				writeSet(t, dir, pinnedVersion, toolName)
			},
		},
		"sentinel names another version": {
			setup: func(t *testing.T, dir string) {
				writeSet(t, dir, pinnedVersion, toolName)
				writeSentinelFile(t, dir, prevVersion)
			},
		},
		"missing primary artifact": {
			setup: func(t *testing.T, dir string) {
				writeSet(t, dir, pinnedVersion, toolSidecar)
				writeSentinelFile(t, dir, pinnedVersion)
			},
		},
		"primary artifact is a symlink": {
			setup: func(t *testing.T, dir string) {
				target := filepath.Join(t.TempDir(), "elsewhere")
				if err := writeFakeBinary(target, pinnedVersion); err != nil {
					t.Fatalf("writeFakeBinary: %v", err)
				}
				if err := os.Symlink(target, filepath.Join(dir, toolName)); err != nil {
					t.Fatalf("Symlink: %v", err)
				}
				writeSentinelFile(t, dir, pinnedVersion)
			},
		},
		"primary artifact is not executable": {
			setup: func(t *testing.T, dir string) {
				if err := os.WriteFile(filepath.Join(dir, toolName), []byte("x"), 0o600); err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
				writeSentinelFile(t, dir, pinnedVersion)
			},
		},
		"sentinel is a symlink": {
			setup: func(t *testing.T, dir string) {
				writeSet(t, dir, pinnedVersion, toolName)
				other := filepath.Join(t.TempDir(), "sentinel")
				if err := os.WriteFile(other, []byte(pinnedVersion+"\n"), 0o600); err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
				if err := os.Symlink(other, filepath.Join(dir, sentinelName)); err != nil {
					t.Fatalf("Symlink: %v", err)
				}
			},
		},
		"sentinel is a directory": {
			setup: func(t *testing.T, dir string) {
				writeSet(t, dir, pinnedVersion, toolName)
				if err := os.MkdirAll(filepath.Join(dir, sentinelName), 0o755); err != nil {
					t.Fatalf("MkdirAll: %v", err)
				}
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			env := newFakeEnv(t)
			m := env.manager()
			dir := env.versionDir(pinnedVersion)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			tc.setup(t, dir)
			if got := m.versionDirComplete(pinnedVersion); got != tc.want {
				t.Errorf("versionDirComplete = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestSelectActiveIgnoresPartialDirectories pins that a partially written version
// directory is never a selection candidate: it is not complete, so selection skips
// it and falls back to the complete predecessor.
func TestSelectActiveIgnoresPartialDirectories(t *testing.T) {
	env := newFakeEnv(t)
	env.placePartial(pinnedVersion)
	env.placeVersion(prevVersion)
	m := env.manager()

	sel, ok := m.selectActive(t.Context())
	if !ok {
		t.Fatal("selectActive found nothing, want the complete predecessor")
	}
	if sel.version != prevVersion {
		t.Errorf("selected %q, want %q -- a directory with no sentinel must not be selected", sel.version, prevVersion)
	}
}

// TestEnsurePrunesPartialsBeforeSelecting pins that Ensure removes a partial
// directory rather than leaving it to be re-probed forever, and that the staging
// trees of a previous crashed run go with it.
func TestEnsurePrunesPartialsBeforeSelecting(t *testing.T) {
	env := newFakeEnv(t)
	env.placePartial(oldVersion)
	orphan := filepath.Join(env.versionsRoot(), stagePrefix+"crashed")
	if err := os.MkdirAll(filepath.Join(orphan, "home"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	m := env.manager()

	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if exists(env.versionDir(oldVersion)) {
		t.Error("the partial version directory survived Ensure")
	}
	if exists(orphan) {
		t.Error("the orphan staging tree survived Ensure")
	}
}

// TestSelectActiveExcludesAReplacedArtifactUnderAnIntactSentinel pins that a
// directory name plus a sentinel is not proof. The selected candidate is probed and
// must answer with the version its own directory claims, so an artifact replaced on
// the volume while the sentinel stayed intact is excluded -- falling back to another
// complete version and leaving the pin unsatisfied so the caller reinstalls.
func TestSelectActiveExcludesAReplacedArtifactUnderAnIntactSentinel(t *testing.T) {
	t.Run("excluded and the fallback serves when reinstall is impossible", func(t *testing.T) {
		env := newFakeEnv(t)
		tampered := env.placeVersion(pinnedVersion)
		env.placeVersion(prevVersion)
		// The sentinel still names the pin; only the artifact was swapped.
		if err := writeFakeBinary(filepath.Join(tampered, toolName), "6.6.6"); err != nil {
			t.Fatalf("writeFakeBinary: %v", err)
		}
		env.archiveLacksArtifacts = true
		m := env.manager()

		if err := m.Ensure(t.Context()); err == nil {
			t.Fatal("Ensure returned nil although the pin was replaced and reinstall failed")
		}
		if got := m.PathEntry(); got != env.versionDir(prevVersion) {
			t.Errorf("PathEntry() = %q, want the untampered predecessor %q", got, env.versionDir(prevVersion))
		}
		if ready, why := m.Ready(); !ready {
			t.Errorf("Ready() = false (%s), want true on the predecessor", why)
		}
	})

	t.Run("triggers a reinstall that replaces the tampered directory", func(t *testing.T) {
		env := newFakeEnv(t)
		tampered := env.placeVersion(pinnedVersion)
		if err := writeFakeBinary(filepath.Join(tampered, toolName), "6.6.6"); err != nil {
			t.Fatalf("writeFakeBinary: %v", err)
		}
		m := env.manager()

		if err := m.Ensure(t.Context()); err != nil {
			t.Fatalf("Ensure: %v", err)
		}
		if env.fetchCount() != 1 {
			t.Errorf("fetches = %d, want 1 -- a version-probe mismatch must trigger a reinstall", env.fetchCount())
		}
		out, err := env.probeAnswer(filepath.Join(tampered, toolName))
		if err != nil {
			t.Fatalf("probeAnswer: %v", err)
		}
		if got := lastFieldOfFirstLine(string(out)); got != pinnedVersion {
			t.Errorf("reinstalled artifact reports %q, want %q", got, pinnedVersion)
		}
		if ready, why := m.Ready(); !ready {
			t.Errorf("Ready() = false (%s), want true after the reinstall", why)
		}
	})
}

// TestEnsureRefusesATreeWithoutCustody pins that a pre-existing directory in a
// tree another principal can write is never activated, and that nothing is
// fetched into such a tree: the install refuses before a byte is downloaded.
func TestEnsureRefusesATreeWithoutCustody(t *testing.T) {
	env := newFakeEnv(t)
	env.placeVersion(pinnedVersion)
	if err := os.Chmod(env.root, 0o777); err != nil {
		t.Fatalf("chmod the install root: %v", err)
	}
	m := env.manager()

	err := m.Ensure(t.Context())
	if err == nil || !strings.Contains(err.Error(), "not under this process's exclusive control") {
		t.Fatalf("Ensure error = %v, want the custody refusal", err)
	}
	if _, ok := m.selectActive(t.Context()); ok {
		t.Fatal("selectActive accepted a pre-existing directory in a tree without custody")
	}
	if env.fetchCount() != 0 {
		t.Errorf("fetches = %d, want 0: nothing is downloaded into a tree without custody", env.fetchCount())
	}
	if ready, _ := m.Ready(); ready {
		t.Error("Ready() = true in a tree without custody")
	}
}

// TestEnsurePrunesToTheRetention pins retention through Ensure: on a start that
// already has the pin, one predecessor survives and everything older is removed.
// The placed directories share an activation time, so retain.Order falls back to
// version precedence and keeps the newest predecessor.
func TestEnsurePrunesToTheRetention(t *testing.T) {
	env := newFakeEnv(t)
	for _, v := range []string{pinnedVersion, prevVersion, oldVersion, "2.13.0"} {
		dir := env.placeVersion(v)
		at := time.Unix(1_700_000_000, 0)
		if err := os.Chtimes(dir, at, at); err != nil {
			t.Fatalf("Chtimes(%s): %v", dir, err)
		}
	}
	m := env.manager()

	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	got := slices.Sorted(slices.Values(env.versionDirs()))
	want := slices.Sorted(slices.Values([]string{pinnedVersion, prevVersion}))
	if !slices.Equal(got, want) {
		t.Errorf("version directories = %v, want %v", got, want)
	}
	// A prune is a directory-entry removal, so the installation root's own entry
	// list has to reach stable storage.
	if syncs := env.countCalls("fsync " + env.versionsRoot()); syncs != 1 {
		t.Errorf("fsyncs of %s = %d, want 1 once the prune removed something", env.versionsRoot(), syncs)
	}
}

// TestEnsureFailedInstallPrunesNothing pins that a failed install never touches the
// fallback set. The versions on the volume are exactly what makes the failure
// survivable, so pruning runs only after a successful publish.
func TestEnsureFailedInstallPrunesNothing(t *testing.T) {
	env := newFakeEnv(t)
	env.placeVersion(prevVersion)
	env.placeVersion(oldVersion)
	env.archiveLacksArtifacts = true
	m := env.manager()

	if err := m.Ensure(t.Context()); err == nil {
		t.Fatal("Ensure returned nil although the archive held no artifact")
	}
	got := slices.Sorted(slices.Values(env.versionDirs()))
	want := slices.Sorted(slices.Values([]string{oldVersion, prevVersion}))
	if !slices.Equal(got, want) {
		t.Errorf("version directories = %v, want %v -- a failed install must prune nothing", got, want)
	}
}

// TestLastFieldOfFirstLine pins the default probe parse: the last
// whitespace-separated field of the first line, so extra banner or trailing lines
// cannot change the answer.
func TestLastFieldOfFirstLine(t *testing.T) {
	tests := map[string]string{
		"toolkit 2.14.2\n":                     "2.14.2",
		"toolkit 2.14.2":                       "2.14.2",
		"toolkit 2.14.2\nextra 9.9.9\n":        "2.14.2",
		"  toolkit   2.14.2  \n":               "2.14.2",
		"2.14.2\n":                             "2.14.2",
		"":                                     "",
		"\n":                                   "",
		"   \n":                                "",
		"\ntoolkit 2.14.2\n":                   "",
		"toolkit version 2.14.2 (build abc)\n": "abc)",
	}
	for out, want := range tests {
		t.Run(strings.ReplaceAll(out, "\n", "\\n"), func(t *testing.T) {
			if got := lastFieldOfFirstLine(out); got != want {
				t.Errorf("lastFieldOfFirstLine(%q) = %q, want %q", out, got, want)
			}
		})
	}
}

// FuzzLastFieldOfFirstLine pins the default parser's invariants on arbitrary probe
// output: it never panics, the result is always a field of the FIRST line, and it
// never contains whitespace. A parsed version is compared against a directory name
// and a sentinel, so a parse that could return whitespace or a later line's content
// would be a real integrity problem.
func FuzzLastFieldOfFirstLine(f *testing.F) {
	for _, seed := range []string{
		"toolkit 2.14.2\n", "", "\n\n\n", "   ", "toolkit\t2.14.2\r\n",
		"a b c\nd e f\n", "2.14.2", "\x00 \x00", strings.Repeat("x ", 500),
		"../../etc/passwd", "v1 v2 ..", "\u00a0 1.0",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, out string) {
		got := lastFieldOfFirstLine(out)
		if got == "" {
			return
		}
		if strings.ContainsAny(got, " \t\r\n\v\f") {
			t.Fatalf("lastFieldOfFirstLine(%q) = %q, which contains whitespace", out, got)
		}
		first, _, _ := strings.Cut(out, "\n")
		if !slices.Contains(strings.Fields(first), got) {
			t.Fatalf("lastFieldOfFirstLine(%q) = %q, which is not a field of the first line %q", out, got, first)
		}
	})
}

// TestSelectActiveExcludesAnUnparseableVersionAnswer pins that an artifact whose
// probe output carries no version is excluded rather than trusted. An empty parse
// must never be treated as "matches the directory name", because that would let a
// broken or replaced artifact activate.
func TestSelectActiveExcludesAnUnparseableVersionAnswer(t *testing.T) {
	tests := map[string]struct {
		out string
		err error
	}{
		"empty output":       {out: ""},
		"blank output":       {out: "   \n"},
		"probe failed":       {err: errors.New("timed out")},
		"leading blank line": {out: "\ntoolkit " + pinnedVersion + "\n"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			env := newFakeEnv(t)
			env.placeVersion(pinnedVersion)
			env.onProbe = func(string) ([]byte, error) { return []byte(tc.out), tc.err }
			m := env.manager()

			if sel, ok := m.selectActive(t.Context()); ok {
				t.Errorf("selectActive accepted %q (selected %q)", tc.out, sel.version)
			}
		})
	}
}

// TestSelfContainedRejectsEverythingButARegularExecutable pins the one predicate
// that decides whether an artifact survives the staging cleanup.
func TestSelfContainedRejectsEverythingButARegularExecutable(t *testing.T) {
	dir := t.TempDir()
	regularExec := filepath.Join(dir, "ok")
	if err := writeFakeBinary(regularExec, pinnedVersion); err != nil {
		t.Fatalf("writeFakeBinary: %v", err)
	}
	notExec := filepath.Join(dir, "plain")
	if err := os.WriteFile(notExec, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(regularExec, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	subdir := filepath.Join(dir, "sub")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	tests := map[string]struct {
		path string
		want bool
	}{
		"regular executable":           {path: regularExec, want: true},
		"regular but not executable":   {path: notExec},
		"symlink to a good executable": {path: link},
		"directory with the exec bit":  {path: subdir},
		"absent":                       {path: filepath.Join(dir, "nope")},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := selfContained(tc.path); got != tc.want {
				t.Errorf("selfContained(%s) = %v, want %v", name, got, tc.want)
			}
		})
	}
}

// TestRemoveUnderRootCannotEscapeTheInstallationRoot pins the confinement on every
// delete this package performs: a symlinked entry under the root must not redirect a
// removal at whatever sits outside it.
func TestRemoveUnderRootCannotEscapeTheInstallationRoot(t *testing.T) {
	env := newFakeEnv(t)
	m := env.manager()
	if err := os.MkdirAll(env.versionsRoot(), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	outside := filepath.Join(env.root, "precious")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	victim := filepath.Join(outside, "file")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(env.versionsRoot(), "escape")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	m.removeUnderRoot([]string{"escape"})

	if !exists(victim) {
		t.Error("a delete followed a symlink out of the installation root")
	}
}

// TestWideArtifactNamesTheSymlinkItRefuses is the same rule one level up, where selection
// and publication actually ask it: a symlink planted in a version directory is a top-level
// entry PathEntry exposes, so it is refused by name with a reason the operator can read.
func TestWideArtifactNamesTheSymlinkItRefuses(t *testing.T) {
	env := newFakeEnv(t)
	dir := env.placeVersion(pinnedVersion)
	m := env.manager()
	if entry, reason := m.wideArtifact(dir); entry != "" {
		t.Fatalf("wideArtifact = (%q, %q) on a clean directory, want no offender", entry, reason)
	}

	if err := os.Symlink(filepath.Join(dir, toolName), filepath.Join(dir, "planted")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	entry, reason := m.wideArtifact(dir)
	if entry != "planted" {
		t.Errorf("wideArtifact = %q, want the planted link: it sits on PATH like every other entry there", entry)
	}
	if !strings.Contains(reason, "symlink") {
		t.Errorf("wideArtifact reason = %q, want one naming the symlink", reason)
	}
}

// TestSelectionAndRetentionAgreeOnEveryRefusal is the coupling test for the shared
// predicate. Retention counts a version towards the retained set only when
// selection would activate it; with two copies of the checks, a check added to
// selection alone would let retention delete the fallback selection keeps, exactly
// when the fallback is needed. The property is agreement, so the test asserts
// agreement rather than either answer.
func TestSelectionAndRetentionAgreeOnEveryRefusal(t *testing.T) {
	tests := map[string]struct {
		setup       func(t *testing.T, env *fakeEnv, dir string)
		mutate      func(c *Config)
		activatable bool
	}{
		"a clean directory": {
			setup:       func(*testing.T, *fakeEnv, string) {},
			activatable: true,
		},
		"an entry another principal can write": {
			setup: func(t *testing.T, _ *fakeEnv, dir string) {
				t.Helper()
				if err := os.Chmod(filepath.Join(dir, toolName), 0o777); err != nil {
					t.Fatalf("chmod the artifact: %v", err)
				}
			},
		},
		"a symlink planted in the directory": {
			setup: func(t *testing.T, _ *fakeEnv, dir string) {
				t.Helper()
				if err := os.Symlink(filepath.Join(dir, toolName), filepath.Join(dir, "planted")); err != nil {
					t.Fatalf("Symlink: %v", err)
				}
			},
		},
		"an artifact reporting another version": {
			setup: func(t *testing.T, _ *fakeEnv, dir string) {
				t.Helper()
				if err := writeFakeBinary(filepath.Join(dir, toolName), "1.0.0"); err != nil {
					t.Fatalf("writeFakeBinary: %v", err)
				}
			},
		},
		"a tree the caller declared untrusted": {
			setup:  func(*testing.T, *fakeEnv, string) {},
			mutate: func(c *Config) { c.Untrusted = true },
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			env := newFakeEnv(t)
			dir := env.placeVersion(pinnedVersion)
			tc.setup(t, env, dir)
			mutate := []func(*Config){}
			if tc.mutate != nil {
				mutate = append(mutate, tc.mutate)
			}
			m := env.manager(mutate...)
			m.checkCustody()

			// Retention first: selection removes a replaced artifact's directory.
			retained := m.predecessorRole(t.Context(), pinnedVersion) == retain.Fallback
			sel, selected := m.selectActive(t.Context())
			if selected != retained {
				t.Errorf("selectActive = %v but predecessorRole-is-fallback = %v for the same directory; retention promises the answers agree, and a retained version selection refuses is not a fallback",
					selected, retained)
			}
			if selected != tc.activatable {
				t.Errorf("selectActive selected %q (%v), want activatable = %v", sel.version, selected, tc.activatable)
			}
		})
	}
}

// TestSelectActiveNamesTheWideVersionDirectoryItExcludes pins which of the two
// exclusions an operator is told about, because the remedy is not the same. A version
// DIRECTORY another principal can write means every artifact in it can be replaced
// whatever the artifacts' own modes say; a single wide ENTRY is one file to fix. Naming
// the wrong one sends the operator to chmod a file that was never the problem.
func TestSelectActiveNamesTheWideVersionDirectoryItExcludes(t *testing.T) {
	logs := captureLogs(t)
	env := newFakeEnv(t)
	dir := env.placeVersion(pinnedVersion)
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod the version directory: %v", err)
	}
	m := env.manager()
	m.checkCustody()

	if _, ok := m.selectActive(t.Context()); ok {
		t.Fatal("selectActive accepted a version directory another principal can write")
	}
	if got := logs.at(slog.LevelError, "dir"); len(got) != 1 || got[0].attrs["dir"] != dir {
		t.Errorf("Error records naming a directory = %v, want one naming %s", got, dir)
	}
	if got := logs.at(slog.LevelError, "entry"); len(got) != 0 {
		t.Errorf("Error records naming an entry = %v, want none: the directory itself is what was refused", got)
	}
}

// TestThePartialSweepReportsOnlyWhatItRemoved pins the sweep's audit line and its
// silence. Removing an incomplete install directory is a delete on a volume the operator
// owns, so the count is reported — and a start with nothing to sweep says nothing,
// because a line claiming a sweep that removed nothing is the noise that hides the one
// that did something.
func TestThePartialSweepReportsOnlyWhatItRemoved(t *testing.T) {
	logs := captureLogs(t)

	// A volume whose installation root holds nothing but a complete version: the sweep
	// looks at it, finds no victim, and says nothing.
	clean := newFakeEnv(t)
	clean.placeVersion(pinnedVersion)
	if err := clean.manager().Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure on a volume with nothing to sweep: %v", err)
	}
	if got := logs.at(slog.LevelInfo, "removed"); len(got) != 0 {
		t.Fatalf("Info records carrying a removal count = %v, want none when nothing was swept", got)
	}

	env := newFakeEnv(t)
	env.placePartial(oldVersion)
	orphan := filepath.Join(env.versionsRoot(), stagePrefix+"crashed")
	if err := os.MkdirAll(filepath.Join(orphan, "home"), 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", orphan, err)
	}
	if err := env.manager().Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	got := logs.at(slog.LevelInfo, "removed")
	if len(got) != 1 {
		t.Fatalf("Info records carrying a removal count = %v, want 1 after the sweep removed two directories", got)
	}
	if want := "2"; got[0].attrs["removed"] != want {
		t.Errorf("removed = %q, want %q: the partial directory and the orphan staging tree", got[0].attrs["removed"], want)
	}
}

// TestPruneSyncFailureWarns pins the last step of a prune. The directories are already
// gone by then, so an unsynced installation root costs only that a crash can bring their
// entries back — a warning rather than a failure, since the prune is hygiene and the
// active version is unaffected.
func TestPruneSyncFailureWarns(t *testing.T) {
	logs := captureLogs(t)
	env := newFakeEnv(t)
	for _, v := range []string{pinnedVersion, prevVersion, oldVersion} {
		env.placeVersion(v)
	}
	env.onSync = func(path string) error {
		if path == env.versionsRoot() {
			return errors.New("injected sync failure")
		}
		return nil
	}
	m := env.manager()

	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure error = %v, want nil: a prune that cannot be synced is still a prune", err)
	}
	if exists(env.versionDir(oldVersion)) {
		t.Fatal("the superseded version survived, so this fixture never reached the sync")
	}
	if got := logs.at(slog.LevelWarn, "error"); len(got) != 1 {
		t.Errorf("Warn records carrying an error = %d, want 1 for the unsynced installation root; got %v",
			len(got), logs.messages(slog.LevelWarn))
	}
}

// TestTrustedAnswersWithTheVerdictThatProducedIt pins that the decision and the reason for
// it come from ONE acquisition of the state lock.
//
// selectActive reports both in a single log record. Asking twice — the predicate, then the
// verdict — meant a verdict that changed between the two acquisitions produced a record
// whose reason belonged to a decision nothing had made, which is the worst kind of
// diagnostic: authoritative and wrong.
func TestTrustedAnswersWithTheVerdictThatProducedIt(t *testing.T) {
	env := newFakeEnv(t)
	env.placeVersion(pinnedVersion)
	clean := env.manager()
	clean.checkCustody()
	if mayActivate, verdict := clean.trusted(pinnedVersion); !mayActivate || verdict != nil {
		t.Errorf("trusted on a private tree = (%v, %v), want (true, nil)", mayActivate, verdict)
	}

	if err := os.Chmod(env.root, 0o777); err != nil {
		t.Fatalf("chmod the install root: %v", err)
	}
	m := env.manager()
	m.checkCustody()

	mayActivate, verdict := m.trusted(pinnedVersion)
	if mayActivate {
		t.Fatal("trusted accepted a planted version in a tree this process does not control")
	}
	if verdict == nil || !strings.Contains(verdict.Error(), "not under this process's exclusive control") {
		t.Errorf("trusted verdict = %v, want the custody verdict that refused it", verdict)
	}
	if verdict != m.custodyVerdict() {
		t.Errorf("trusted verdict = %v, custodyVerdict = %v: the answer and its reason must be the same read", verdict, m.custodyVerdict())
	}
}

func writeSet(t *testing.T, dir, version string, names ...string) {
	t.Helper()
	for _, n := range names {
		if err := writeFakeBinary(filepath.Join(dir, n), version); err != nil {
			t.Fatalf("writeFakeBinary(%s): %v", n, err)
		}
	}
}

func writeSentinelFile(t *testing.T, dir, version string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, sentinelName), []byte(version+"\n"), 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
}

// TestRetentionBoundsAnUntrustedTree pins that a tree of directories this process
// did not install still has a bounded size. Such a directory is not activatable;
// were it immune, nothing would prune it and the tree would grow by one version per
// pin bump. The bound comes from the prunable set having no immunity, never from a
// non-activatable directory counting against retainPredecessors: that would keep a
// corrupt newer directory and prune the good older one, just when the pin failed.
func TestRetentionBoundsAnUntrustedTree(t *testing.T) {
	env := newFakeEnv(t)
	// Three predecessors this process did not install, plus the pin it did.
	for _, v := range []string{"1.0.0", "1.1.0", "1.2.0"} {
		env.placeVersion(v)
	}
	env.placeVersion(pinnedVersion)
	m := env.manager(func(c *Config) { c.Untrusted = true })
	m.checkCustody()
	if verdict := m.custodyVerdict(); verdict != nil {
		t.Fatalf("the fixture needs a CLEAN custody verdict so Untrusted is the sole reason, got %v", verdict)
	}

	victims := retain.Victims(m.completeVersions(), pinnedVersion, retainPredecessors, func(name string) retain.Role {
		return m.predecessorRole(t.Context(), name)
	})
	for _, v := range []string{"1.0.0", "1.1.0", "1.2.0"} {
		if !slices.Contains(victims, v) {
			t.Errorf("%s survived pruning; the tree is still unbounded", v)
		}
	}
	if slices.Contains(victims, pinnedVersion) {
		t.Errorf("the active version %s was pruned", pinnedVersion)
	}
}

// TestRetentionSparesAStrangersInstallWhenCustodyRefused is the other half of
// the same split, and why it turns on the verdict rather than the flag: a tree
// custody refused provably has a writer this library cannot account for, so a
// complete directory in it may be another principal's, and it is immune.
func TestRetentionSparesAStrangersInstallWhenCustodyRefused(t *testing.T) {
	env := newFakeEnv(t)
	env.placeVersion("1.0.0")
	env.placeVersion(pinnedVersion)
	if err := os.Chmod(env.root, 0o777); err != nil {
		t.Fatal(err)
	}
	m := env.manager()
	m.checkCustody()
	if m.custodyVerdict() == nil {
		t.Skip("this filesystem did not make the widened tree fail custody; the split cannot be exercised")
	}
	if got := m.predecessorRole(t.Context(), "1.0.0"); got != retain.Immune {
		t.Errorf("predecessorRole(1.0.0) = %v, want Immune: a stranger's install must not be deleted", got)
	}
	if m.mayMutateTree() {
		t.Error("mayMutateTree() = true under a refused verdict, so a prune could run")
	}
}

// TestReactivationRecordsTheActivationAndRetainsByIt pins R8 with R7: moving the
// pin back to an older version on the volume makes that directory the most
// recently activated, and retention then keeps the version that was active just
// before, not the higher one by version precedence.
func TestReactivationRecordsTheActivationAndRetainsByIt(t *testing.T) {
	env := newFakeEnv(t)
	// prevVersion was activated last, though pinnedVersion is the higher version.
	for i, v := range []string{oldVersion, pinnedVersion, prevVersion} {
		dir := env.placeVersion(v)
		at := time.Unix(1_600_000_000+int64(i)*60, 0)
		if err := os.Chtimes(dir, at, at); err != nil {
			t.Fatalf("Chtimes(%s): %v", dir, err)
		}
	}
	m := env.manager(func(c *Config) { c.Version = oldVersion })

	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if got := m.Version(); got != oldVersion {
		t.Fatalf("Version() = %q, want the re-pinned %q", got, oldVersion)
	}
	fi, err := os.Stat(env.versionDir(oldVersion))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if want := m.now(); !fi.ModTime().Equal(want) {
		t.Errorf("mtime of the activated directory = %v, want the activation time %v", fi.ModTime(), want)
	}
	got := slices.Sorted(slices.Values(env.versionDirs()))
	want := slices.Sorted(slices.Values([]string{oldVersion, prevVersion}))
	if !slices.Equal(got, want) {
		t.Errorf("version directories = %v, want %v (the re-activated one and the one active before it)", got, want)
	}
}

// replacedVersion is what a replaced artifact answers in the mismatch tests: a
// newer release written over a pinned directory, the way a vendor's self-updater
// renames its download over the running path.
const replacedVersion = "2.15.0"

// placeReplaced places a complete version directory whose artifact answers
// replacedVersion while its name and sentinel still claim version.
func (e *fakeEnv) placeReplaced(version string) string {
	e.t.Helper()
	dir := e.placeVersion(version)
	if err := writeFakeBinary(filepath.Join(dir, e.release.Name), replacedVersion); err != nil {
		e.t.Fatalf("writeFakeBinary: %v", err)
	}
	return dir
}

// mismatchReports returns the records at level that report version's artifact
// answering replacedVersion.
func mismatchReports(logs *logRecorder, level slog.Level, version string) []logRecord {
	var out []logRecord
	for _, r := range logs.at(level, "reported") {
		if r.attrs["version"] == version && r.attrs["reported"] == replacedVersion {
			out = append(out, r)
		}
	}
	return out
}

// assertMismatchLoggedOnce pins the operator's view of one replaced directory:
// one Error naming it and the version its artifact answered, and no Warn
// repeating it from retention.
func assertMismatchLoggedOnce(t *testing.T, logs *logRecorder, version string) {
	t.Helper()
	if got := mismatchReports(logs, slog.LevelError, version); len(got) != 1 {
		t.Errorf("Error records reporting %s's artifact as %s = %v, want exactly one", version, replacedVersion, got)
	}
	if got := mismatchReports(logs, slog.LevelWarn, version); len(got) != 0 {
		t.Errorf("Warn records reporting %s's artifact as %s = %v, want none beside the Error", version, replacedVersion, got)
	}
}

// TestRetentionPrunesAPredecessorWhoseArtifactAnswersAnotherVersion pins that a
// replaced predecessor is deleted rather than spared. It can never serve, its
// sentinel claims a version its artifact is not, and sparing it kept such
// directories on the volume forever, each one a full install.
func TestRetentionPrunesAPredecessorWhoseArtifactAnswersAnotherVersion(t *testing.T) {
	logs := captureLogs(t)
	env := newFakeEnv(t)
	env.placeVersion(pinnedVersion)
	env.placeReplaced(prevVersion)
	env.placeVersion(oldVersion)
	m := env.manager()

	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if exists(env.versionDir(prevVersion)) {
		t.Errorf("the replaced predecessor %s survived retention, so its false %s stays on the volume", prevVersion, sentinelName)
	}
	if !exists(env.versionDir(oldVersion)) {
		t.Errorf("the working predecessor %s was pruned; it is the one fallback retention keeps", oldVersion)
	}
	if got := m.Version(); got != pinnedVersion {
		t.Errorf("Version() = %q, want the pin %q", got, pinnedVersion)
	}
	assertMismatchLoggedOnce(t, logs, prevVersion)
}

// TestAReplacedPinIsRemovedWhenItCannotBeReinstalled pins the failed-install
// half: the predecessor serves, and the replaced pin directory goes rather than
// waiting, with its false sentinel, for an install that may never succeed.
func TestAReplacedPinIsRemovedWhenItCannotBeReinstalled(t *testing.T) {
	logs := captureLogs(t)
	env := newFakeEnv(t)
	env.placeReplaced(pinnedVersion)
	env.placeVersion(prevVersion)
	env.onFetch = func(io.Writer) error { return errors.New("injected fetch failure") }
	m := env.manager()

	if err := m.Ensure(t.Context()); err == nil {
		t.Fatal("Ensure returned nil although the pin could not be reinstalled")
	}
	if got := m.Version(); got != prevVersion {
		t.Errorf("Version() = %q, want the working predecessor %q", got, prevVersion)
	}
	if exists(env.versionDir(pinnedVersion)) {
		t.Errorf("the replaced pin directory survived, so its %s still claims %s", sentinelName, pinnedVersion)
	}
	assertMismatchLoggedOnce(t, logs, pinnedVersion)
}

// TestAReplacedPinIsReinstalledFromTheVerifiedArchive pins the success half:
// the pin directory is rebuilt from the digest-verified download, so what is on
// the volume afterwards answers the version its sentinel claims.
func TestAReplacedPinIsReinstalledFromTheVerifiedArchive(t *testing.T) {
	logs := captureLogs(t)
	env := newFakeEnv(t)
	dir := env.placeReplaced(pinnedVersion)
	env.placeVersion(prevVersion)
	m := env.manager()

	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if got := env.fetchCount(); got != 1 {
		t.Errorf("fetches = %d, want 1 reinstall of the pin", got)
	}
	if got := m.Version(); got != pinnedVersion {
		t.Errorf("Version() = %q, want the reinstalled pin %q", got, pinnedVersion)
	}
	out, err := env.probeAnswer(filepath.Join(dir, toolName))
	if err != nil {
		t.Fatalf("probeAnswer: %v", err)
	}
	if got := lastFieldOfFirstLine(string(out)); got != pinnedVersion {
		t.Errorf("the pin directory's artifact answers %q after the reinstall, want %q", got, pinnedVersion)
	}
	if !exists(env.versionDir(prevVersion)) {
		t.Errorf("the working predecessor %s was pruned", prevVersion)
	}
	assertMismatchLoggedOnce(t, logs, pinnedVersion)
}

// TestRescanRemovesAReplacedPin pins the no-download path: a rescan cannot
// reinstall, so it serves the predecessor and removes the replaced pin
// directory, reporting it once.
func TestRescanRemovesAReplacedPin(t *testing.T) {
	logs := captureLogs(t)
	env := newFakeEnv(t)
	env.placeReplaced(pinnedVersion)
	env.placeVersion(prevVersion)
	m := env.manager()

	ok, err := m.Rescan(t.Context())
	if err != nil || !ok {
		t.Fatalf("Rescan = (%v, %v), want (true, nil) on the predecessor", ok, err)
	}
	if got := m.Version(); got != prevVersion {
		t.Errorf("Version() = %q, want the working predecessor %q", got, prevVersion)
	}
	if exists(env.versionDir(pinnedVersion)) {
		t.Errorf("the replaced pin directory survived the rescan, so its %s still claims %s", sentinelName, pinnedVersion)
	}
	if got := env.fetchCount(); got != 0 {
		t.Errorf("fetches = %d, want none: a rescan only re-derives from disk", got)
	}
	assertMismatchLoggedOnce(t, logs, pinnedVersion)
}
