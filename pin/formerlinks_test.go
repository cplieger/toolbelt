//go:build linux

package pin

import (
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// formerLinkDir is where an earlier deployment of the test profile published its
// links, before it moved them to testLinkDir.
const formerLinkDir = "old-bin"

// newFormerEnv is the primary env with formerLinkDir created and plant run in it.
func newFormerEnv(t *testing.T, plant func(env *fakeEnv, dir string)) (*fakeEnv, string) {
	t.Helper()
	env := newFakeEnv(t)
	dir := filepath.Join(env.root, formerLinkDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", dir, err)
	}
	plant(env, dir)
	return env, dir
}

// symlinkAt creates link with text, failing the test on error.
func symlinkAt(t *testing.T, text, link string) {
	t.Helper()
	if err := os.Symlink(text, link); err != nil {
		t.Fatalf("Symlink(%s): %v", link, err)
	}
}

// withFormer names formerLinkDir as a former link dir.
func withFormer(c *Config) { c.FormerLinkDirs = []string{formerLinkDir} }

// TestFormerLinkDirsRetractTheManagersOwnLinks pins the retraction: every link in a
// former link dir with the shape this manager publishes goes, the primary's name
// included and dangling or not, because nothing else retracts it once LinkDir has
// moved.
func TestFormerLinkDirsRetractTheManagersOwnLinks(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Config)
		entry  string
		text   func(env *fakeEnv) string
	}{
		"the primary's link": {
			mutate: withFormer,
			entry:  toolName,
			text:   func(env *fakeEnv) string { return filepath.Join(env.versionDir(prevVersion), toolName) },
		},
		"a sidecar's link": {
			mutate: withFormer,
			entry:  toolSidecar,
			text:   func(env *fakeEnv) string { return filepath.Join(env.versionDir(prevVersion), toolSidecar) },
		},
		"a link into a pruned version": {
			mutate: withFormer,
			entry:  toolName,
			text:   func(env *fakeEnv) string { return filepath.Join(env.versionDir("0.1.0"), toolName) },
		},
		"a crash-left staged link": {
			mutate: withFormer,
			entry:  stagedLinkName(toolName),
			text:   func(env *fakeEnv) string { return filepath.Join(env.versionDir(prevVersion), toolName) },
		},
		"the primary's link with LinkDir empty": {
			mutate: func(c *Config) { c.LinkDir = ""; withFormer(c) },
			entry:  toolName,
			text:   func(env *fakeEnv) string { return filepath.Join(env.versionDir(prevVersion), toolName) },
		},
		"the primary's link with the dir spelled ./old-bin/": {
			mutate: func(c *Config) { c.FormerLinkDirs = []string{"./" + formerLinkDir + "/"} },
			entry:  toolName,
			text:   func(env *fakeEnv) string { return filepath.Join(env.versionDir(prevVersion), toolName) },
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var link string
			env, dir := newFormerEnv(t, func(env *fakeEnv, dir string) {
				link = filepath.Join(dir, tc.entry)
				symlinkAt(t, tc.text(env), link)
			})
			if err := env.manager(tc.mutate).Ensure(t.Context()); err != nil {
				t.Fatalf("Ensure: %v", err)
			}
			if _, err := os.Lstat(link); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("Lstat(%s) error = %v, want not-exist: it is this manager's link in a former link dir", link, err)
			}
			if got := env.countCalls("fsync " + dir); got != 1 {
				t.Errorf("fsync of %s ran %d times, want 1 after the retraction changed it", dir, got)
			}
		})
	}
}

// TestFormerLinkDirsLeaveForeignEntriesAlone pins the ownership gate: in a former
// link dir only this manager's shape is retracted, and a manager-shaped link in a
// directory nobody named is not looked at.
func TestFormerLinkDirsLeaveForeignEntriesAlone(t *testing.T) {
	const userFile = "a user's own toolkit\n"
	sep := string(filepath.Separator)
	planted := map[string]string{}
	env, dir := newFormerEnv(t, func(env *fakeEnv, dir string) {
		planted[toolSidecar] = filepath.Join(env.root, "opt", toolName, prevVersion, toolSidecar)
		planted["toolkit-old"] = filepath.Join(env.versionDir(prevVersion), toolName)
		planted[toolAlias] = filepath.Join("/opt", "elsewhere", toolName+versionsSuffix, prevVersion, toolAlias)
		// Concatenated, not Joined, which would clean the ".." away.
		planted[toolExtra] = env.versionDir(prevVersion) + sep + ".." + sep + prevVersion + sep + toolExtra
		for name, text := range planted {
			symlinkAt(t, text, filepath.Join(dir, name))
		}
		if err := os.WriteFile(filepath.Join(dir, toolName), []byte(userFile), 0o755); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	})
	unnamed := filepath.Join(env.root, "other-bin", toolName)
	if err := os.MkdirAll(filepath.Dir(unnamed), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	unnamedText := filepath.Join(env.versionDir(prevVersion), toolName)
	symlinkAt(t, unnamedText, unnamed)

	if err := env.manager(withFormer).Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	for name, want := range planted {
		if got := readLink(t, filepath.Join(dir, name)); got != want {
			t.Errorf("foreign %s -> %q, want it untouched at %q", name, got, want)
		}
	}
	got, err := os.ReadFile(filepath.Join(dir, toolName))
	if fi, lerr := os.Lstat(filepath.Join(dir, toolName)); lerr != nil || !fi.Mode().IsRegular() || err != nil || string(got) != userFile {
		t.Errorf("the user's regular file %s = %q (%v, %v), want it untouched", toolName, got, lerr, err)
	}
	if got := readLink(t, unnamed); got != unnamedText {
		t.Errorf("%s -> %q, want it untouched at %q: its directory is not a former link dir", unnamed, got, unnamedText)
	}
	if got := env.countCalls("fsync " + dir); got != 0 {
		t.Errorf("fsync of %s ran %d times, want none when nothing changed", dir, got)
	}
}

// TestFormerLinkDirsRespectTheCustodyVerdict pins that the retraction is a write
// under the same gate as the links: a tree custody refuses, from the start or
// after a mid-operation flip, keeps its former links.
func TestFormerLinkDirsRespectTheCustodyVerdict(t *testing.T) {
	plantOwn := func(link *string) func(env *fakeEnv, dir string) {
		return func(env *fakeEnv, dir string) {
			*link = filepath.Join(dir, toolName)
			symlinkAt(t, filepath.Join(env.versionDir("0.1.0"), toolName), *link)
		}
	}
	t.Run("refused from the start", func(t *testing.T) {
		var link string
		env, _ := newFormerEnv(t, plantOwn(&link))
		if err := os.Chmod(env.root, 0o777); err != nil {
			t.Fatalf("chmod the install root: %v", err)
		}
		if err := env.manager(withFormer).Ensure(t.Context()); !refusedForCustody(err) {
			t.Fatalf("Ensure error = %v, want the custody refusal", err)
		}
		if !exists(link) {
			t.Errorf("Ensure retracted %s inside a tree it refused", link)
		}
	})
	t.Run("refused mid-operation", func(t *testing.T) {
		var link string
		env, _ := newFormerEnv(t, plantOwn(&link))
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
		m := env.manager(withFormer)
		if err := m.Ensure(t.Context()); !refusedForCustody(err) {
			t.Fatalf("Ensure error = %v, want the install's custody refusal", err)
		}
		if m.Version() != "1.0.0" {
			t.Fatalf("Version() = %q, want the selection made before the flip", m.Version())
		}
		if !exists(link) {
			t.Errorf("finish retracted %s in a tree the operation refused to change", link)
		}
	})
}

// TestFormerLinkDirsStayInsideRoot pins the confinement: a former link dir that
// resolves out of Root is not swept, and says so, while one that does not exist
// is silently nothing to do.
func TestFormerLinkDirsStayInsideRoot(t *testing.T) {
	t.Run("a former link dir resolving out of Root is not swept", func(t *testing.T) {
		logs := captureLogs(t)
		var outside, text string
		env, dir := newFormerEnv(t, func(env *fakeEnv, dir string) {
			outside = filepath.Join(filepath.Dir(env.root), "outside")
			if err := os.Rename(dir, outside); err != nil {
				t.Fatalf("Rename: %v", err)
			}
			symlinkAt(t, outside, dir)
			text = filepath.Join(env.versionDir("0.1.0"), toolName)
			symlinkAt(t, text, filepath.Join(outside, toolName))
		})
		if err := env.manager(withFormer).Ensure(t.Context()); err != nil {
			t.Fatalf("Ensure: %v", err)
		}
		if got := readLink(t, filepath.Join(outside, toolName)); got != text {
			t.Errorf("%s outside Root -> %q, want it untouched at %q", toolName, got, text)
		}
		if !warnedAbout(logs, dir) {
			t.Errorf("no warning names %s, want one saying the former link dir could not be listed", dir)
		}
	})
	t.Run("a missing former link dir is nothing to do", func(t *testing.T) {
		logs := captureLogs(t)
		env := newFakeEnv(t)
		if err := env.manager(withFormer).Ensure(t.Context()); err != nil {
			t.Fatalf("Ensure: %v", err)
		}
		if dir := filepath.Join(env.root, formerLinkDir); warnedAbout(logs, dir) {
			t.Errorf("a warning names the missing %s, want silence", dir)
		}
	})
}

// TestFormerLinkDirsSkipADirAliasingLinkDir pins that a former link dir resolving
// to LinkDir through a symlink, in either direction, keeps the primary's link that
// the same activation just published there.
func TestFormerLinkDirsSkipADirAliasingLinkDir(t *testing.T) {
	cases := map[string]struct{ real, alias string }{
		"the former dir is a symlink to LinkDir": {real: testLinkDir, alias: formerLinkDir},
		"LinkDir is a symlink to the former dir": {real: formerLinkDir, alias: testLinkDir},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			env := newFakeEnv(t)
			if err := os.MkdirAll(filepath.Join(env.root, tc.real), 0o755); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			symlinkAt(t, tc.real, filepath.Join(env.root, tc.alias))
			m := env.manager(withFormer)
			if err := m.Ensure(t.Context()); err != nil {
				t.Fatalf("Ensure: %v", err)
			}
			link := filepath.Join(env.root, testLinkDir, toolName)
			if got, err := os.Readlink(link); err != nil || got != m.Path() {
				t.Errorf("Readlink(%s) = %q, %v, want the active artifact %q", link, got, err, m.Path())
			}
		})
	}
}

// TestFormerLinkDirsPurgeLeavesTheManagersOwnLink pins that a purge target holding
// this manager's own link in a former link dir is not refused as another owner's
// entry, and the retraction still removes it.
func TestFormerLinkDirsPurgeLeavesTheManagersOwnLink(t *testing.T) {
	logs := captureLogs(t)
	target := filepath.Join(formerLinkDir, toolName)
	env, dir := newFormerEnv(t, func(env *fakeEnv, dir string) {
		symlinkAt(t, filepath.Join(env.versionDir("0.1.0"), toolName), filepath.Join(dir, toolName))
	})
	m := env.manager(func(c *Config) {
		withFormer(c)
		c.Purge = &Purge{Artifacts: []string{target}}
	})
	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	for _, r := range logs.at(slog.LevelWarn, "entry") {
		if r.attrs["entry"] == target {
			t.Errorf("purge warned %q about %s, want no refusal: it is this manager's own link", r.msg, target)
		}
	}
	if link := filepath.Join(dir, toolName); exists(link) {
		t.Errorf("%s survived, want it retracted from the former link dir", link)
	}
}

// warnedAbout reports whether a warning carried path as its "path" attribute.
func warnedAbout(logs *logRecorder, path string) bool {
	for _, r := range logs.at(slog.LevelWarn, "path") {
		if strings.TrimSuffix(r.attrs["path"], "/") == path {
			return true
		}
	}
	return false
}
