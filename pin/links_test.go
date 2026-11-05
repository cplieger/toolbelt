//go:build linux

package pin

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A release that ships five binaries at one version and only its primary at the
// next, the shape of a sidecar set an earlier installer linked and pin installs
// none of.
const (
	shrinkWideVersion   = "2.37.1"
	shrinkNarrowVersion = "3.0.0"
	shrinkArtifactDir   = "toolkit/bin"
	toolExtra           = "toolkit-term"
	toolAlias           = "tk"
	toolAliasChat       = "tkchat"
)

// shrinkRelease is the primary profile with its own ArtifactDir.
func shrinkRelease() Config {
	r := toolRelease()
	r.ArtifactDir = shrinkArtifactDir
	return r
}

// newShrinkEnv is a volume an earlier installer left with the five-binary release
// active: its version directory complete and a link to each binary in LinkDir.
// plant runs first, and a name it fills gets no link.
func newShrinkEnv(t *testing.T, plant func(env *fakeEnv, linkDir string)) *fakeEnv {
	t.Helper()
	env := newEnv(t, shrinkRelease(), nil)
	linkDir := filepath.Join(env.root, testLinkDir)
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", linkDir, err)
	}
	if plant != nil {
		plant(env, linkDir)
	}
	dir := env.placeVersion(shrinkWideVersion, toolName, toolSidecar, toolExtra, toolAlias, toolAliasChat)
	for _, name := range []string{toolName, toolSidecar, toolExtra, toolAlias, toolAliasChat} {
		link := filepath.Join(linkDir, name)
		if _, err := os.Lstat(link); err == nil {
			continue
		}
		if err := os.Symlink(filepath.Join(dir, name), link); err != nil {
			t.Fatalf("Symlink(%s): %v", link, err)
		}
	}
	return env
}

// shrinkTo pins env to the one-binary release and runs Ensure on it.
func shrinkTo(t *testing.T, env *fakeEnv, mutate ...func(*Config)) error {
	t.Helper()
	archive := buildZip(t, map[string]zipEntry{
		shrinkArtifactDir + "/" + toolName: {body: fakeBinaryBody(shrinkNarrowVersion), mode: 0o755},
	})
	env.useArchive(archive)
	mutate = append([]func(*Config){func(c *Config) { c.Version = shrinkNarrowVersion }}, mutate...)
	return env.manager(mutate...).Ensure(t.Context())
}

// TestConvenienceLinksRetractWhatADroppedReleaseNoLongerShips pins retraction on
// ownership rather than on configured names. pin links only the primary, and the
// links an earlier installer published for four sidecars into this tree must go:
// left in place they dangle once retention prunes their version. An entry of
// another shape, at one of those names or anywhere else, is never touched.
func TestConvenienceLinksRetractWhatADroppedReleaseNoLongerShips(t *testing.T) {
	t.Run("own links of dropped artifacts are retracted", func(t *testing.T) {
		env := newShrinkEnv(t, nil)
		linkDir := filepath.Join(env.root, testLinkDir)
		dropped := []string{toolSidecar, toolExtra, toolAlias, toolAliasChat}

		if err := shrinkTo(t, env); err != nil {
			t.Fatalf("Ensure %s: %v", shrinkNarrowVersion, err)
		}
		if got, want := readLink(t, filepath.Join(linkDir, toolName)), filepath.Join(env.versionDir(shrinkNarrowVersion), toolName); got != want {
			t.Errorf("%s -> %q, want %q", toolName, got, want)
		}
		for _, name := range dropped {
			if _, err := os.Lstat(filepath.Join(linkDir, name)); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("Lstat(%s) error = %v, want not-exist: %s ships no %s", name, err, shrinkNarrowVersion, name)
			}
		}
	})

	// Config validation accepts these spellings of the same directory, and every other
	// link operation resolves them, so the retraction must too.
	for form, spelled := range map[string]string{
		"a trailing slash": testLinkDir + "/",
		"a dot prefix":     "./" + testLinkDir,
	} {
		t.Run("own links are retracted with LinkDir spelled with "+form, func(t *testing.T) {
			env := newShrinkEnv(t, nil)
			linkDir := filepath.Join(env.root, testLinkDir)

			if err := shrinkTo(t, env, func(c *Config) { c.LinkDir = spelled }); err != nil {
				t.Fatalf("Ensure %s: %v", shrinkNarrowVersion, err)
			}
			for _, name := range []string{toolSidecar, toolExtra, toolAlias, toolAliasChat} {
				if _, err := os.Lstat(filepath.Join(linkDir, name)); !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("Lstat(%s) error = %v, want not-exist: %s ships no %s", name, err, shrinkNarrowVersion, name)
				}
			}
		})
	}

	t.Run("an own link that already dangles is retracted", func(t *testing.T) {
		env := newShrinkEnv(t, nil)
		linkDir := filepath.Join(env.root, testLinkDir)
		const pruned = "toolkit-legacy"
		dangling := filepath.Join(linkDir, pruned)
		if err := os.Symlink(filepath.Join(env.versionsRoot(), "1.0.0", pruned), dangling); err != nil {
			t.Fatalf("Symlink(%s): %v", dangling, err)
		}

		if err := shrinkTo(t, env); err != nil {
			t.Fatalf("Ensure %s: %v", shrinkNarrowVersion, err)
		}
		if _, err := os.Lstat(dangling); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Lstat(%s) error = %v, want not-exist: it points into a version retention already pruned", dangling, err)
		}
	})

	t.Run("foreign entries are left alone", func(t *testing.T) {
		const userFile = "a user's own tk\n"
		otherTarget := filepath.Join("/opt", "other", toolAliasChat)
		elsewhereTarget := filepath.Join("/opt", "elsewhere", toolName+versionsSuffix, shrinkWideVersion, toolExtra)
		var renamedTarget string
		env := newShrinkEnv(t, func(env *fakeEnv, linkDir string) {
			if err := os.WriteFile(filepath.Join(linkDir, toolAlias), []byte(userFile), 0o755); err != nil {
				t.Fatalf("WriteFile(%s): %v", toolAlias, err)
			}
			if err := os.Symlink(otherTarget, filepath.Join(linkDir, toolAliasChat)); err != nil {
				t.Fatalf("Symlink(%s): %v", toolAliasChat, err)
			}
			// Into this manager's own tree, but at a name its links never carry.
			renamedTarget = filepath.Join(env.versionDir(shrinkWideVersion), toolName)
			if err := os.Symlink(renamedTarget, filepath.Join(linkDir, "toolkit-old")); err != nil {
				t.Fatalf("Symlink(toolkit-old): %v", err)
			}
			// This manager's shape at its own name, but under another root's versions directory.
			if err := os.Symlink(elsewhereTarget, filepath.Join(linkDir, toolExtra)); err != nil {
				t.Fatalf("Symlink(%s): %v", toolExtra, err)
			}
		})
		linkDir := filepath.Join(env.root, testLinkDir)

		if err := shrinkTo(t, env); err != nil {
			t.Fatalf("Ensure %s: %v", shrinkNarrowVersion, err)
		}
		got, err := os.ReadFile(filepath.Join(linkDir, toolAlias))
		switch fi, lerr := os.Lstat(filepath.Join(linkDir, toolAlias)); {
		case lerr != nil:
			t.Errorf("the user's regular file %s is gone: %v", toolAlias, lerr)
		case !fi.Mode().IsRegular() || err != nil || string(got) != userFile:
			t.Errorf("the user's %s is now mode %v holding %q (%v), want the regular file %q", toolAlias, fi.Mode(), got, err, userFile)
		}
		for name, want := range map[string]string{
			toolAliasChat: otherTarget,
			"toolkit-old": renamedTarget,
			toolExtra:     elsewhereTarget,
		} {
			if got := readLink(t, filepath.Join(linkDir, name)); got != want {
				t.Errorf("foreign %s -> %q, want it untouched at %q", name, got, want)
			}
		}
		if _, err := os.Lstat(filepath.Join(linkDir, toolSidecar)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Lstat(%s) error = %v, want not-exist: a foreign neighbour must not stop the retraction", toolSidecar, err)
		}
	})

	t.Run("link text is judged by the path it names, not its spelling", func(t *testing.T) {
		env := newShrinkEnv(t, nil)
		linkDir := filepath.Join(env.root, testLinkDir)
		// via is a symlinked directory, so the ".." after it climbs out of the place the
		// text appears to name.
		via := filepath.Join(filepath.Dir(env.root), "via")
		if err := os.Symlink(filepath.Join(t.TempDir(), "deep"), via); err != nil {
			t.Fatalf("Symlink(%s): %v", via, err)
		}
		sep := string(filepath.Separator)
		climb := strings.Join([]string{
			via, "..", filepath.Base(env.root), filepath.Base(env.versionsRoot()), shrinkWideVersion, toolExtra,
		}, sep)
		planted := map[string]string{
			toolName:    env.versionsRoot() + sep + toolName + sep,
			toolSidecar: env.versionsRoot() + sep + toolSidecar + sep,
			toolExtra:   climb,
			toolAlias:   env.versionDir(shrinkWideVersion) + sep + toolAlias + sep,
		}
		for name, text := range planted {
			link := filepath.Join(linkDir, name)
			if err := os.Remove(link); err != nil {
				t.Fatalf("Remove(%s): %v", link, err)
			}
			if err := os.Symlink(text, link); err != nil {
				t.Fatalf("Symlink(%s): %v", link, err)
			}
		}

		if err := shrinkTo(t, env); err != nil {
			t.Fatalf("Ensure %s: %v", shrinkNarrowVersion, err)
		}
		for _, name := range []string{toolName, toolSidecar, toolExtra} {
			if got, err := os.Readlink(filepath.Join(linkDir, name)); err != nil || got != planted[name] {
				t.Errorf("foreign %s -> %q (%v), want it untouched at %q", name, got, err, planted[name])
			}
		}
		if _, err := os.Lstat(filepath.Join(linkDir, toolAlias)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Lstat(%s) error = %v, want not-exist: a trailing separator still names this tree's %s", toolAlias, err, shrinkWideVersion)
		}
	})

	t.Run("a crash-left staged link of a dropped artifact is retracted", func(t *testing.T) {
		env := newShrinkEnv(t, nil)
		linkDir := filepath.Join(env.root, testLinkDir)
		staged := filepath.Join(linkDir, "."+toolExtra+".newlink")
		if err := os.Symlink(filepath.Join(env.versionDir(shrinkWideVersion), toolExtra), staged); err != nil {
			t.Fatalf("Symlink(%s): %v", staged, err)
		}

		if err := shrinkTo(t, env); err != nil {
			t.Fatalf("Ensure %s: %v", shrinkNarrowVersion, err)
		}
		if _, err := os.Lstat(staged); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Lstat(%s) error = %v, want not-exist: no later publish reuses that temp name", staged, err)
		}
	})

	t.Run("a foreign symlink at a staged-link name is left alone", func(t *testing.T) {
		env := newShrinkEnv(t, nil)
		linkDir := filepath.Join(env.root, testLinkDir)
		staged := filepath.Join(linkDir, "."+toolExtra+".newlink")
		foreign := filepath.Join("/opt", "other", toolExtra)
		if err := os.Symlink(foreign, staged); err != nil {
			t.Fatalf("Symlink(%s): %v", staged, err)
		}

		if err := shrinkTo(t, env); err != nil {
			t.Fatalf("Ensure %s: %v", shrinkNarrowVersion, err)
		}
		if got := readLink(t, staged); got != foreign {
			t.Errorf("foreign %s -> %q, want it untouched at %q", staged, got, foreign)
		}
	})

	t.Run("a link dir resolving out of Root is not swept", func(t *testing.T) {
		env := newShrinkEnv(t, nil)
		linkDir := filepath.Join(env.root, testLinkDir)
		outside := filepath.Join(filepath.Dir(env.root), "outside")
		if err := os.Rename(linkDir, outside); err != nil {
			t.Fatalf("Rename(%s, %s): %v", linkDir, outside, err)
		}
		if err := os.Symlink(outside, linkDir); err != nil {
			t.Fatalf("Symlink the link dir out of Root: %v", err)
		}

		if err := shrinkTo(t, env); err != nil {
			t.Fatalf("Ensure %s: %v", shrinkNarrowVersion, err)
		}
		if got, want := readLink(t, filepath.Join(outside, toolSidecar)), filepath.Join(env.versionDir(shrinkWideVersion), toolSidecar); got != want {
			t.Errorf("%s outside Root -> %q, want it untouched at %q", toolSidecar, got, want)
		}
	})
}
