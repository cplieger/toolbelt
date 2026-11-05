package pin

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
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
				writeSet(t, dir, pinnedVersion, toolName, toolSidecar)
				writeSentinelFile(t, dir, pinnedVersion)
			},
			want: true,
		},
		"artifacts but no sentinel (interrupted install)": {
			setup: func(t *testing.T, dir string) {
				writeSet(t, dir, pinnedVersion, toolName, toolSidecar)
			},
		},
		"sentinel names another version": {
			setup: func(t *testing.T, dir string) {
				writeSet(t, dir, pinnedVersion, toolName, toolSidecar)
				writeSentinelFile(t, dir, prevVersion)
			},
		},
		"missing required sidecar": {
			setup: func(t *testing.T, dir string) {
				writeSet(t, dir, pinnedVersion, toolName)
				writeSentinelFile(t, dir, pinnedVersion)
			},
		},
		"missing primary artifact": {
			setup: func(t *testing.T, dir string) {
				writeSet(t, dir, pinnedVersion, toolSidecar)
				writeSentinelFile(t, dir, pinnedVersion)
			},
		},
		"required artifact is a symlink": {
			setup: func(t *testing.T, dir string) {
				writeSet(t, dir, pinnedVersion, toolName)
				target := filepath.Join(t.TempDir(), "elsewhere")
				if err := writeFakeBinary(target, pinnedVersion); err != nil {
					t.Fatalf("writeFakeBinary: %v", err)
				}
				if err := os.Symlink(target, filepath.Join(dir, toolSidecar)); err != nil {
					t.Fatalf("Symlink: %v", err)
				}
				writeSentinelFile(t, dir, pinnedVersion)
			},
		},
		"required artifact is not executable": {
			setup: func(t *testing.T, dir string) {
				writeSet(t, dir, pinnedVersion, toolName)
				if err := os.WriteFile(filepath.Join(dir, toolSidecar), []byte("x"), 0o600); err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
				writeSentinelFile(t, dir, pinnedVersion)
			},
		},
		"sentinel is a symlink": {
			setup: func(t *testing.T, dir string) {
				writeSet(t, dir, pinnedVersion, toolName, toolSidecar)
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
				writeSet(t, dir, pinnedVersion, toolName, toolSidecar)
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
		env.installerFails = true
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
		if got := LastFieldOfFirstLine(string(out)); got != pinnedVersion {
			t.Errorf("reinstalled artifact reports %q, want %q", got, pinnedVersion)
		}
		if ready, why := m.Ready(); !ready {
			t.Errorf("Ready() = false (%s), want true after the reinstall", why)
		}
	})
}

// TestSelectActiveIgnoresExistingDirectoriesWithoutCustody pins the contract a
// tree without custody gets: a sentinel is a plain file and therefore trivially
// forgeable, unlike a digest, so a pre-existing version directory may not be
// activated -- only one this process installed from a verified archive.
//
// The trigger is the MEASURED verdict rather than the Untrusted flag. Untrusted
// waives the refusal to install into such a tree; it is not a declaration that the
// tree is bad, because a caller cannot be expected to know its volume carries an
// inherited ACL. So the fixture makes the root genuinely writable by others and
// then waives the install refusal, which is the real deployment this covers.
func TestSelectActiveIgnoresExistingDirectoriesWithoutCustody(t *testing.T) {
	env := newFakeEnv(t)
	env.placeVersion(pinnedVersion)
	if err := os.Chmod(env.root, 0o777); err != nil {
		t.Fatalf("chmod the install root: %v", err)
	}
	m := env.manager(func(c *Config) { c.InstallWithoutCustody = true })
	m.checkCustody()

	if _, ok := m.selectActive(t.Context()); ok {
		t.Fatal("selectActive accepted a pre-existing directory in a tree without custody")
	}
	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if env.fetchCount() != 1 {
		t.Errorf("fetches = %d, want 1 -- a tree without custody must force a digest-verified reinstall", env.fetchCount())
	}
	if ready, why := m.Ready(); !ready {
		t.Errorf("Ready() = false (%s), want true after the verified reinstall", why)
	}
}

// TestRetainedAndPrunedVersions pins the retention invariant as a unit across every
// Retain value, including the axis no consumer exercises today (anything other than
// one). Retention is what makes a bad activation recoverable without a rollback
// journal, so it is asserted directly rather than only through Ensure.
func TestRetainedAndPrunedVersions(t *testing.T) {
	tests := map[string]struct {
		complete   []string
		active     string
		retain     int
		wantKeep   []string
		wantPruned []string
	}{
		"retain one: active plus predecessor": {
			complete:   []string{"2.14.2", "2.14.1", "2.14.0", "2.13.9"},
			active:     "2.14.2",
			retain:     1,
			wantKeep:   []string{"2.14.2", "2.14.1"},
			wantPruned: []string{"2.14.0", "2.13.9"},
		},
		"retain two keeps two predecessors": {
			complete:   []string{"2.14.2", "2.14.1", "2.14.0", "2.13.9"},
			active:     "2.14.2",
			retain:     2,
			wantKeep:   []string{"2.14.2", "2.14.1", "2.14.0"},
			wantPruned: []string{"2.13.9"},
		},
		"retain three keeps every predecessor there is": {
			complete:   []string{"2.14.2", "2.14.1", "2.14.0", "2.13.9"},
			active:     "2.14.2",
			retain:     3,
			wantKeep:   []string{"2.14.2", "2.14.1", "2.14.0", "2.13.9"},
			wantPruned: []string{},
		},
		"retain zero keeps only the active version": {
			complete:   []string{"2.14.2", "2.14.1", "2.14.0"},
			active:     "2.14.2",
			retain:     0,
			wantKeep:   []string{"2.14.2"},
			wantPruned: []string{"2.14.1", "2.14.0"},
		},
		"a negative retain is treated as zero": {
			complete:   []string{"2.14.2", "2.14.1"},
			active:     "2.14.2",
			retain:     -3,
			wantKeep:   []string{"2.14.2"},
			wantPruned: []string{"2.14.1"},
		},
		"the predecessor is never pruned when the fallback is active": {
			complete:   []string{"2.14.1", "2.14.0"},
			active:     "2.14.1",
			retain:     1,
			wantKeep:   []string{"2.14.1", "2.14.0"},
			wantPruned: []string{},
		},
		"only the active version present": {
			complete:   []string{"2.14.2"},
			active:     "2.14.2",
			retain:     1,
			wantKeep:   []string{"2.14.2"},
			wantPruned: []string{},
		},
		"a version newer than the active one is pruned (the pin moved down)": {
			complete:   []string{"2.15.0", "2.14.2", "2.14.1"},
			active:     "2.14.2",
			retain:     1,
			wantKeep:   []string{"2.14.2", "2.14.1"},
			wantPruned: []string{"2.15.0"},
		},
		"a newer version is pruned even at a high retain": {
			complete:   []string{"3.0.0", "2.15.0", "2.14.2", "2.14.1"},
			active:     "2.14.2",
			retain:     5,
			wantKeep:   []string{"2.14.2", "2.14.1"},
			wantPruned: []string{"3.0.0", "2.15.0"},
		},
		"numeric ordering, not lexical": {
			complete:   []string{"2.14.2", "2.9.9", "2.10.0"},
			active:     "2.14.2",
			retain:     1,
			wantKeep:   []string{"2.14.2", "2.10.0"},
			wantPruned: []string{"2.9.9"},
		},
		"nothing is pruned when no version is active": {
			complete:   []string{"2.14.2", "2.14.1", "2.14.0"},
			active:     "",
			retain:     1,
			wantKeep:   nil,
			wantPruned: nil,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// The two halves of retention, composed the way pruneSuperseded
			// composes them: the pure lexical candidate list, then the spare set,
			// then the victims. The usability half needs a filesystem and a
			// subprocess, so it is covered by the Ensure-level tests instead; here
			// every candidate is treated as usable, which is the healthy tree.
			var keep []string
			if tc.active != "" {
				candidates := predecessorCandidates(tc.complete, tc.active)
				retain := max(tc.retain, 0)
				keep = append([]string{tc.active}, candidates[:min(retain, len(candidates))]...)
			}
			got := slices.Sorted(slices.Values(keep))
			want := slices.Sorted(slices.Values(tc.wantKeep))
			if !slices.Equal(got, want) {
				t.Errorf("retained = %v, want %v", got, want)
			}
			var pruned []string
			if tc.active != "" {
				pruned = victimsOf(tc.complete, keep, nil)
			}
			prunedSorted := slices.Sorted(slices.Values(pruned))
			wantPruned := slices.Sorted(slices.Values(tc.wantPruned))
			if !slices.Equal(prunedSorted, wantPruned) {
				t.Errorf("victimsOf = %v, want %v", prunedSorted, wantPruned)
			}
			keep, pruned = got, prunedSorted
			for _, v := range pruned {
				if slices.Contains(keep, v) {
					t.Errorf("%q is both retained and pruned", v)
				}
			}
		})
	}
}

// TestEnsurePrunesToTheConfiguredRetention pins the invariant through Ensure, at the
// default retention and at a higher one: on a start that already has the pin, the
// retained predecessors survive and everything older is removed.
func TestEnsurePrunesToTheConfiguredRetention(t *testing.T) {
	tests := map[string]struct {
		retain int
		want   []string
	}{
		"default retention keeps one predecessor": {retain: 0, want: []string{pinnedVersion, prevVersion}},
		"retention of two keeps two":              {retain: 2, want: []string{pinnedVersion, prevVersion, oldVersion}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			env := newFakeEnv(t)
			for _, v := range []string{pinnedVersion, prevVersion, oldVersion, "2.13.0"} {
				env.placeVersion(v)
			}
			m := env.manager(func(c *Config) { c.Retain = tc.retain })

			if err := m.Ensure(t.Context()); err != nil {
				t.Fatalf("Ensure: %v", err)
			}
			got := slices.Sorted(slices.Values(env.versionDirs()))
			want := slices.Sorted(slices.Values(tc.want))
			if !slices.Equal(got, want) {
				t.Errorf("version directories = %v, want %v", got, want)
			}
			// A prune is a directory-entry removal, so the installation root's own
			// entry list has to reach stable storage: an unsynced prune can come back
			// after a crash as a version directory this sweep already decided against.
			if syncs := env.countCalls("fsync " + env.versionsRoot()); syncs != 1 {
				t.Errorf("fsyncs of %s = %d, want 1 once the prune removed something", env.versionsRoot(), syncs)
			}
		})
	}
}

// TestEnsureFailedInstallPrunesNothing pins that a failed install never touches the
// fallback set. The versions on the volume are exactly what makes the failure
// survivable, so pruning runs only after a successful publish.
func TestEnsureFailedInstallPrunesNothing(t *testing.T) {
	env := newFakeEnv(t)
	env.placeVersion(prevVersion)
	env.placeVersion(oldVersion)
	env.installerFails = true
	m := env.manager()

	if err := m.Ensure(t.Context()); err == nil {
		t.Fatal("Ensure returned nil although the installer produced nothing")
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
			if got := LastFieldOfFirstLine(out); got != want {
				t.Errorf("LastFieldOfFirstLine(%q) = %q, want %q", out, got, want)
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
		got := LastFieldOfFirstLine(out)
		if got == "" {
			return
		}
		if strings.ContainsAny(got, " \t\r\n\v\f") {
			t.Fatalf("LastFieldOfFirstLine(%q) = %q, which contains whitespace", out, got)
		}
		first, _, _ := strings.Cut(out, "\n")
		if !slices.Contains(strings.Fields(first), got) {
			t.Fatalf("LastFieldOfFirstLine(%q) = %q, which is not a field of the first line %q", out, got, first)
		}
	})
}

// TestCompareVersionsOrdersNumerically pins that version ordering is numeric per
// segment, because the retained-predecessor invariant is defined by "the newest
// version below the active one".
func TestCompareVersionsOrdersNumerically(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"2.14.2", "2.14.1", 1},
		{"2.14.1", "2.14.2", -1},
		{"2.14.2", "2.14.2", 0},
		{"2.10.0", "2.9.9", 1},
		{"2.14", "2.14.0", 0},
		{"2.14.1", "2.14", 1},
		{"2.14.2", "not-a-version", -1},
		{"10.0.0", "9.99.99", 1},
	}
	for _, tc := range tests {
		got := compareVersions(tc.a, tc.b)
		if (got > 0) != (tc.want > 0) || (got < 0) != (tc.want < 0) {
			t.Errorf("compareVersions(%q, %q) = %d, want sign of %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestSortVersionsDescIsDeterministic pins that the newest-first ordering the
// selection and retention both read is total, including for entries that are not
// versions at all.
func TestSortVersionsDescIsDeterministic(t *testing.T) {
	in := []string{"2.9.9", "zzz", "2.14.2", "2.10.0", "2.14.2"}
	first := slices.Clone(in)
	sortVersionsDesc(first)
	second := slices.Clone(in)
	slices.Reverse(second)
	sortVersionsDesc(second)
	if !slices.Equal(first, second) {
		t.Errorf("sortVersionsDesc is input-order dependent: %v vs %v", first, second)
	}
	if first[0] != "zzz" && compareVersions(first[0], first[1]) < 0 {
		t.Errorf("sortVersionsDesc did not order newest first: %v", first)
	}
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

// TestEntryPrivateRefusesAnEntryOwnedByAnotherIdentity is the only coverage the ownership
// half of the artifact rule has, and entryPrivate gates activation of every version
// directory: dropping this check let a binary owned by a stranger be executed as root,
// because its owner may rewrite it whatever the mode says.
//
// The identity doing the asking is a parameter, as it is on [checkSymlink], so the rule gates
// at any privilege: no fixture an unprivileged process can create belongs to anybody else,
// and a rule that read its identity from the ambient process would be pinned only where
// privilege exists — the root-only-green shape that once left the trusted-writer knobs
// disconnected with CI green.
func TestEntryPrivateRefusesAnEntryOwnedByAnotherIdentity(t *testing.T) {
	const stranger = 4242

	env := newFakeEnv(t)
	path := filepath.Join(t.TempDir(), "artifact")
	if err := os.WriteFile(path, []byte("x"), 0o700); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if os.Geteuid() == 0 {
		// Root's own files are trusted whatever euid is asked about, so as root the
		// fixture has to belong to somebody else — which root is the one identity able to
		// arrange.
		if err := os.Chown(path, stranger, -1); err != nil {
			t.Fatalf("chown the fixture to uid %d: %v", stranger, err)
		}
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("the filesystem reported no ownership information for the fixture")
	}
	owner := int(stat.Uid)
	if owner == 0 {
		t.Fatalf("the fixture is owned by root, which is trusted whoever asks, so this test would prove nothing")
	}
	// Neither the owner nor root: an identity for which the fixture is somebody else's.
	other := owner + 1

	m := env.manager()
	if _, private := m.entryPrivate(path, false, owner); !private {
		t.Fatalf("entryPrivate refused an entry owned by the identity running the check, so the fixture is wrong")
	}
	if reason, private := m.entryPrivate(path, false, other); private {
		t.Errorf("entryPrivate accepted an entry owned by uid %d when asked as uid %d; that user can rewrite a binary this package executes", owner, other)
	} else if want := fmt.Sprintf("is owned by uid %d", owner); reason != want {
		t.Errorf("entryPrivate reason = %q, want %q: the operator has to be told which identity owns it", reason, want)
	}
	declared := env.manager(func(c *Config) { c.TrustedUIDs = []int{owner} })
	if _, private := declared.entryPrivate(path, false, other); !private {
		t.Errorf("entryPrivate refused uid %d after the caller declared it, which is the whole point of the declaration", owner)
	}
}

// TestEntryPrivateFailsClosedWhenTheListCannotBeRead pins the direction of the one error
// entryPrivate cannot resolve, AND the words it reports it in. An access-control list it
// could not evaluate is not proof there is nothing to find, and this predicate's answer
// decides whether a version directory is activated, so "I could not look" must never come
// back as "there was nothing there".
//
// The wording half is the operator's half, and it is the reason this predicate returns a
// diagnosis rather than a bool. ErrACLUnreadable and ErrACLDialectUnsupported exist to
// separate "could not be evaluated" from "a stranger can write", so a refusal that reports
// the second for the first sends the operator to chmod a mode that is already correct while
// the real obstacle — a dialect, a seccomp filter denying getxattr, an I/O error — goes
// unmentioned.
func TestEntryPrivateFailsClosedWhenTheListCannotBeRead(t *testing.T) {
	env := newFakeEnv(t)
	m := env.manager()
	euid := os.Geteuid()
	path := filepath.Join(t.TempDir(), "artifact")
	if err := os.WriteFile(path, []byte("x"), 0o700); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, private := m.entryPrivate(path, false, euid); !private {
		t.Fatalf("entryPrivate refused a private fixture, so this test would prove nothing")
	}

	old := getxattrFn
	getxattrFn = func(string, string, []byte) (int, error) { return 0, syscall.EIO }
	defer func() { getxattrFn = old }()

	reason, private := m.entryPrivate(path, false, euid)
	if private {
		t.Fatal("entryPrivate accepted an entry whose access-control list it could not read")
	}
	if !strings.Contains(reason, "could not be evaluated") {
		t.Errorf("entryPrivate reason = %q, want one saying the list could not be evaluated", reason)
	}
	if strings.Contains(reason, "writable") {
		t.Errorf("entryPrivate reason = %q: nobody was found writable here, and reporting one sends the operator to fix a mode that is already correct", reason)
	}
}

// TestEntryPrivateRefusesASymlinkAsASymlink pins the one refusal whose diagnosis the
// operator cannot act on if it is reported by mode.
//
// A symlink's own mode is 0777 on every Linux system and grants nothing. Judged by that
// mode it reports an entry everyone can write, and chmod cannot fix it: chmod follows the
// link to its target, so the operator changes a different object and the exclusion stays.
// checkSymlink states this rule for the path walk; this is the copy that has to agree, and
// it also closes a fail-OPEN window — Getxattr follows the link, so a link whose TARGET
// carries a POSIX.1e list was judged by the target's list under the link's own stat.
func TestEntryPrivateRefusesASymlinkAsASymlink(t *testing.T) {
	env := newFakeEnv(t)
	m := env.manager()
	dir := t.TempDir()
	target := filepath.Join(dir, "artifact")
	if err := os.WriteFile(target, []byte("x"), 0o700); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	reason, private := m.entryPrivate(link, false, os.Geteuid())
	if private {
		t.Fatal("entryPrivate accepted a symlink; this package executes what is in a version directory, and a link is not that file")
	}
	if !strings.Contains(reason, "symlink") {
		t.Errorf("entryPrivate reason = %q, want one naming it a symlink: reported by mode the operator is told everyone can write it, and chmod on a link follows to its target", reason)
	}
	if strings.Contains(reason, "writable") {
		t.Errorf("entryPrivate reason = %q: a link's 0777 mode is not a grant, and reporting it as one is an exclusion nobody can clear", reason)
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
// predicate, and it is the whole reason there is one.
//
// Retention's claim about itself is that it counts a version towards the retained set only
// when selection would activate it. Nothing enforced that claim while the two ran their own
// copies of the same three checks: a fourth check added to selection would have silently
// missed retention, which prunes on this answer and would then have deleted the fallback
// selection would have kept — in exactly the situation the fallback exists for. The
// property is agreement, so the test asserts agreement rather than either answer.
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

			sel, selected := m.selectActive(t.Context())
			retained := m.predecessorRole(t.Context(), pinnedVersion) == roleFallback
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
	if !errors.Is(verdict, ErrNoCustody) {
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

// TestRetentionBoundsAnUntrustedTree is the defect Config.Untrusted used to document as
// a limitation: a directory this process did not install is not activatable, so it went
// into the immune set and NOTHING pruned it. keep never filled, every predecessor was
// immune, and the tree grew one version per pin bump forever — ~240 MB a time for a
// package the size of the ones this library installs.
//
// The bound must come from the prunable set having no immunity, NEVER from letting a
// non-activatable directory count against Retain: that shape keeps a corrupt newer
// directory while pruning the good older one, exactly when the pin has already failed.
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

	keep, immune := m.usablePredecessors(t.Context(), m.completeVersions(), pinnedVersion, m.cfg.Retain)

	if len(keep) != 0 {
		t.Errorf("keep = %v, want empty: no foreign directory may spend a fallback slot", keep)
	}
	if len(immune) != 0 {
		t.Errorf("immune = %v, want empty: with custody clean these are this deployment's own dead installs, not evidence and not a stranger's", immune)
	}
	victims := victimsOf(m.completeVersions(), []string{pinnedVersion}, immune)
	for _, v := range []string{"1.0.0", "1.1.0", "1.2.0"} {
		if !slices.Contains(victims, v) {
			t.Errorf("%s survived pruning; the tree is still unbounded", v)
		}
	}
	if slices.Contains(victims, pinnedVersion) {
		t.Errorf("the active version %s was pruned", pinnedVersion)
	}
}

// TestRetentionSparesAStrangersInstallWhenCustodyRefused is the other half of the same
// split, and the reason it turns on the VERDICT rather than on which flag was set. A
// waived bad verdict means the tree provably has a writer this library cannot account
// for, so a complete directory in it may be another principal's — deleting a stranger's
// files is not a disk-hygiene decision this library gets to make.
func TestRetentionSparesAStrangersInstallWhenCustodyRefused(t *testing.T) {
	env := newFakeEnv(t)
	env.placeVersion("1.0.0")
	env.placeVersion(pinnedVersion)
	// Make custody refuse, and accept it, which is what a consumer with nothing
	// precise to say about its volume does.
	if err := os.Chmod(env.root, 0o777); err != nil {
		t.Fatal(err)
	}
	m := env.manager(func(c *Config) { c.InstallWithoutCustody = true })
	m.checkCustody()
	if m.custodyVerdict() == nil {
		t.Skip("this filesystem did not make the widened tree fail custody; the split cannot be exercised")
	}

	keep, immune := m.usablePredecessors(t.Context(), m.completeVersions(), pinnedVersion, m.cfg.Retain)

	if len(keep) != 0 {
		t.Errorf("keep = %v, want empty: an unverifiable directory is not a fallback", keep)
	}
	if !slices.Contains(immune, "1.0.0") {
		t.Errorf("immune = %v, want it to hold 1.0.0: a stranger's install must not be deleted", immune)
	}
	if slices.Contains(victimsOf(m.completeVersions(), []string{pinnedVersion}, immune), "1.0.0") {
		t.Error("a directory that may be another principal's was pruned")
	}
}
