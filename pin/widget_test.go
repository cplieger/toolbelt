//go:build linux

package pin

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// A SECOND, deliberately different profile, driven end to end: a tar.gz archive
// rather than a zip, different architecture tokens and URL shape, a two-word
// version probe, a helper executable beside the primary, and no convenience
// link and no purge. It proves the library does not depend on the
// shape its consumers happen to share.
const (
	widgetName     = "widget"
	widgetHelper   = "widget-helper"
	widgetProbeOne = "version"
	widgetGate     = "autoupdate"
)

// widgetRelease is the synthetic profile.
func widgetRelease() Config {
	return Config{
		Name:        widgetName,
		URLTemplate: "https://widgets.invalid/dl/{arch}/widget_{version}.tar.gz",
		ArchTokens:  map[string]string{"amd64": "linux-64", "arm64": "linux-arm"},
		ArtifactDir: "dist/bin",
		ProbeArgs:   []string{widgetProbeOne},
		Assertions:  []Assertion{{Name: widgetGate, Args: []string{"config", "set", widgetGate, "off"}, Required: true}},
	}
}

// buildTarGz builds a real gzipped tar in memory.
func buildTarGz(t *testing.T, entries map[string]zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for n := range entries {
			if !yield(n) {
				return
			}
		}
	}) {
		e := entries[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: int64(e.mode), Size: int64(len(e.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatalf("tar header %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(e.body)); err != nil {
			t.Fatalf("tar body %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// widgetArchive holds the primary and a helper under the profile's ArtifactDir,
// plus other content. Only the primary is published.
func widgetArchive(t *testing.T, version string) []byte {
	t.Helper()
	return buildTarGz(t, map[string]zipEntry{
		"dist/bin/" + widgetName:   {body: fakeBinaryBody(version), mode: 0o755},
		"dist/bin/" + widgetHelper: {body: fakeBinaryBody(version), mode: 0o755},
		"dist/bin/notes.txt":       {body: "not an artifact\n", mode: 0o644},
		"dist/share/widget.png":    {body: "asset\n", mode: 0o644},
	})
}

// newWidgetEnv wires an env to the synthetic profile.
func newWidgetEnv(t *testing.T) *fakeEnv {
	t.Helper()
	env := newEnv(t, widgetRelease(), widgetArchive(t, pinnedVersion))
	env.probeAnswerFor = func(v string) string { return fmt.Sprintf("%s version %s\n", widgetName, v) }
	return env
}

// widgetManager builds a manager for the widget profile: no link dir, no purge.
func widgetManager(env *fakeEnv, mutate ...func(*Config)) *Manager {
	base := func(c *Config) {
		c.LinkDir = ""
		c.Purge = nil
	}
	return env.manager(append([]func(*Config){base}, mutate...)...)
}

// TestWidgetProfileInstallsEndToEnd is the synthetic profile's happy path: every
// parameter the real consumers do not vary, varied at once, driven through the same
// lifecycle.
func TestWidgetProfileInstallsEndToEnd(t *testing.T) {
	env := newWidgetEnv(t)
	m := widgetManager(env)

	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	// The URL shape and the architecture token come from this profile, not the
	// primary one.
	wantURL := "https://widgets.invalid/dl/linux-64/widget_" + pinnedVersion + ".tar.gz"
	if env.countCalls("fetch "+wantURL) != 1 {
		t.Errorf("calls = %v, want one fetch of %q", env.called(), wantURL)
	}
	// The versions root and the state file are keyed on the package NAME.
	dir := filepath.Join(env.root, widgetName+versionsSuffix, pinnedVersion)
	if got := m.PathEntry(); got != dir {
		t.Errorf("PathEntry() = %q, want %q", got, dir)
	}
	if !exists(filepath.Join(env.root, widgetName+stateSuffix)) {
		t.Errorf("the state record was not written at %s", widgetName+stateSuffix)
	}
	if got, want := m.Path(), filepath.Join(dir, widgetName); got != want {
		t.Errorf("Path() = %q, want %q", got, want)
	}
	// The primary artifact is published; nothing else from the archive is.
	got := slices.Sorted(slices.Values(mustReadDir(t, dir)))
	want := []string{sentinelName, widgetName}
	if !slices.Equal(got, want) {
		t.Errorf("version directory holds %v, want %v", got, want)
	}
	if env.countCalls("probe "+filepath.Join(dir, widgetName)) == 0 {
		t.Errorf("the primary artifact was never probed: %v", env.called())
	}
	if env.countCalls("assert config set "+widgetGate+" off") == 0 {
		t.Errorf("the profile's required assertion never ran: %v", env.called())
	}
	// The off switches are asserted by absence.
	if exists(filepath.Join(env.root, testLinkDir)) {
		t.Error("a link directory was created although LinkDir is empty")
	}
	if ready, why := m.Ready(); !ready {
		t.Errorf("Ready() = false (%s), want true", why)
	}
}

// TestWidgetProfileExcludesAVersionTheProbeDenies pins that the probe answer
// gates activation: an artifact naming another version is excluded.
func TestWidgetProfileExcludesAVersionTheProbeDenies(t *testing.T) {
	env := newWidgetEnv(t)
	env.placeVersion(pinnedVersion)
	env.onProbe = func(string) ([]byte, error) { return []byte("widget version 0.0.1\n"), nil }
	m := widgetManager(env)
	if _, ok := m.selectActive(t.Context()); ok {
		t.Error("selectActive accepted an artifact reporting a version its directory does not claim")
	}
}

// TestWidgetProfileRefusesAnArchiveWithoutItsArtifact pins that an archive whose
// primary artifact is absent, misplaced or not executable publishes nothing,
// whatever else it holds.
func TestWidgetProfileRefusesAnArchiveWithoutItsArtifact(t *testing.T) {
	tests := map[string]map[string]zipEntry{
		"primary missing": {
			"dist/bin/" + widgetHelper: {body: fakeBinaryBody(pinnedVersion), mode: 0o755},
		},
		"artifact in the wrong directory": {
			"bin/" + widgetName:   {body: fakeBinaryBody(pinnedVersion), mode: 0o755},
			"bin/" + widgetHelper: {body: fakeBinaryBody(pinnedVersion), mode: 0o755},
		},
		"artifact not executable": {
			"dist/bin/" + widgetName:   {body: fakeBinaryBody(pinnedVersion), mode: 0o644},
			"dist/bin/" + widgetHelper: {body: fakeBinaryBody(pinnedVersion), mode: 0o644},
		},
	}
	for name, entries := range tests {
		t.Run(name, func(t *testing.T) {
			env := newWidgetEnv(t)
			env.setArchive(buildTarGz(t, entries))
			m := widgetManager(env)

			if err := m.Ensure(t.Context()); err == nil {
				t.Fatal("Ensure returned nil although the archive holds no usable artifact")
			}
			if exists(filepath.Join(env.root, widgetName+versionsSuffix, pinnedVersion)) {
				t.Error("a version directory was published without its artifact")
			}
			if ready, _ := m.Ready(); ready {
				t.Error("Ready() = true with no complete install")
			}
		})
	}
}

// TestWidgetProfileKeepsTheMostRecentlyActivatedPredecessor pins retention on
// activation time rather than version order: of three predecessors, the one
// activated last is kept even though another has a higher version.
func TestWidgetProfileKeepsTheMostRecentlyActivatedPredecessor(t *testing.T) {
	env := newWidgetEnv(t)
	base := time.Now().Add(-time.Hour)
	for i, v := range []string{prevVersion, "2.13.0", oldVersion} {
		dir := env.placeVersion(v)
		at := base.Add(time.Duration(i) * time.Minute)
		if err := os.Chtimes(dir, at, at); err != nil {
			t.Fatalf("Chtimes(%s): %v", dir, err)
		}
	}
	m := widgetManager(env)

	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	root := filepath.Join(env.root, widgetName+versionsSuffix)
	got := slices.Sorted(slices.Values(nonHidden(mustReadDir(t, root))))
	want := slices.Sorted(slices.Values([]string{pinnedVersion, oldVersion}))
	if !slices.Equal(got, want) {
		t.Errorf("version directories = %v, want %v (active plus the last activated)", got, want)
	}
}

// TestWidgetProfileFallsBackToAPredecessor pins that the fallback posture is not a
// property of the primary profile: with the download broken, a complete predecessor
// keeps the widget install ready.
func TestWidgetProfileFallsBackToAPredecessor(t *testing.T) {
	env := newWidgetEnv(t)
	prev := env.placeVersion(prevVersion)
	env.onFetch = func(io.Writer) error { return errors.New("network unreachable") }
	m := widgetManager(env)

	if err := m.Ensure(t.Context()); err == nil {
		t.Fatal("Ensure returned nil although the download failed")
	}
	if ready, why := m.Ready(); !ready {
		t.Errorf("Ready() = false (%s), want true on the retained predecessor", why)
	}
	if got, want := m.Path(), filepath.Join(prev, widgetName); got != want {
		t.Errorf("Path() = %q, want %q", got, want)
	}
	if got := m.Version(); got != prevVersion {
		t.Errorf("Version() = %q, want the fallback %q", got, prevVersion)
	}
}

// TestTwoProfilesShareOneRootWithoutColliding pins the consequence of keying every
// path on Config.Name: two different packages installed under the same Root keep
// separate version trees, separate state records and separate active versions.
func TestTwoProfilesShareOneRootWithoutColliding(t *testing.T) {
	primary := newFakeEnv(t)
	widget := newWidgetEnv(t)
	widget.root = primary.root // one shared installation root

	first := primary.manager()
	second := widgetManager(widget)

	if err := first.Ensure(t.Context()); err != nil {
		t.Fatalf("primary Ensure: %v", err)
	}
	if err := second.Ensure(t.Context()); err != nil {
		t.Fatalf("widget Ensure: %v", err)
	}

	if ready, why := first.Ready(); !ready {
		t.Errorf("primary Ready() = false (%s)", why)
	}
	if ready, why := second.Ready(); !ready {
		t.Errorf("widget Ready() = false (%s)", why)
	}
	if first.PathEntry() == second.PathEntry() {
		t.Errorf("both managers activated %q; the version trees must not collide", first.PathEntry())
	}
	for _, name := range []string{
		toolName + versionsSuffix, toolName + stateSuffix,
		widgetName + versionsSuffix, widgetName + stateSuffix,
	} {
		if !exists(filepath.Join(primary.root, name)) {
			t.Errorf("%s is missing from the shared root", name)
		}
	}
	// The second manager's prune must not have touched the first's tree.
	if !exists(filepath.Join(first.PathEntry(), toolName)) {
		t.Error("the widget install pruned the primary package's active version")
	}
}

// nonHidden drops the dot-prefixed entries a directory listing may carry.
func nonHidden(entries []string) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if !strings.HasPrefix(e, ".") {
			out = append(out, e)
		}
	}
	return out
}
