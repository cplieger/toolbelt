package pin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A SECOND, deliberately different profile, driven end to end.
//
// The library's real consumers all install the same shape of release, so every
// parameter they do not vary would otherwise ship exercised by nothing. This
// synthetic "widget" package varies all of them at once and in the opposite
// direction from the primary test profile:
//
//   - no in-archive installer: the archive already holds the artifacts
//   - a package NAME that differs from its primary ARTIFACT name
//   - different architecture tokens, and a different URL shape
//   - a JSON version probe, so ParseVersion is not the default
//   - TWO required artifacts, no optional ones
//   - no convenience link, no purge, and a retention of two
//
// What it does not prove is that a real second upstream publishes archives in this
// shape. It proves the library does not depend on the shape its consumers happen to
// share.
const (
	widgetName     = "widget"
	widgetBinary   = "widget-cli"
	widgetHelper   = "widget-helper"
	widgetProbeOne = "version"
	widgetProbeTwo = "--json"
	widgetGate     = "autoupdate"
)

// widgetRelease is the synthetic profile.
func widgetRelease() Release {
	return Release{
		Name:        widgetName,
		Binary:      widgetBinary,
		URLTemplate: "https://widgets.invalid/dl/{arch}/widget_{version}.zip",
		ArchTokens:  map[string]string{"amd64": "linux-64", "arm64": "linux-arm"},
		ArtifactDir: "dist/bin",
		ProbeArgs:   []string{widgetProbeOne, widgetProbeTwo},
		// No Installer: the archive ships the artifacts. No Notice: the package
		// is not proprietary.
		ParseVersion: parseJSONVersion,
		Mandatory:    []Assertion{{Name: widgetGate, Args: []string{"config", "set", widgetGate, "off"}}},
	}
}

// parseJSONVersion is the widget profile's parser: the probe prints a JSON object.
// It must never panic on arbitrary bytes, because the probe's output is whatever an
// artifact on the volume chose to print.
func parseJSONVersion(out string) string {
	var doc struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return ""
	}
	return doc.Version
}

// widgetArchive is an archive that already holds both artifacts under the profile's
// ArtifactDir, plus content that must NOT be published.
func widgetArchive(t *testing.T, version string) []byte {
	t.Helper()
	return buildZip(t, map[string]zipEntry{
		"dist/bin/" + widgetBinary: {body: fakeBinaryBody(version), mode: 0o755},
		"dist/bin/" + widgetHelper: {body: fakeBinaryBody(version), mode: 0o755},
		"dist/bin/notes.txt":       {body: "not an artifact\n", mode: 0o644},
		"dist/share/widget.png":    {body: "asset\n", mode: 0o644},
	})
}

// newWidgetEnv wires an env to the synthetic profile.
func newWidgetEnv(t *testing.T) *fakeEnv {
	t.Helper()
	env := newEnv(t, widgetRelease(), widgetArchive(t, pinnedVersion), []string{widgetHelper}, nil)
	env.probeAnswerFor = func(v string) string {
		return fmt.Sprintf("{\"name\":%q,\"version\":%q}\n", widgetName, v)
	}
	return env
}

// widgetManager builds a manager for the widget profile with the axes this profile
// exercises: no link dir, no purge, retention of two.
func widgetManager(env *fakeEnv, mutate ...func(*Config)) *Manager {
	base := func(c *Config) {
		c.LinkDir = ""
		c.Purge = nil
		c.Retain = 2
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
	wantURL := "https://widgets.invalid/dl/linux-64/widget_" + pinnedVersion + ".zip"
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
	// Path is the ARTIFACT, whose name differs from the package's.
	if got, want := m.Path(), filepath.Join(dir, widgetBinary); got != want {
		t.Errorf("Path() = %q, want %q", got, want)
	}
	// Both required artifacts are published; nothing else from the archive is.
	got := slices.Sorted(slices.Values(mustReadDir(t, dir)))
	want := slices.Sorted(slices.Values([]string{sentinelName, widgetBinary, widgetHelper}))
	if !slices.Equal(got, want) {
		t.Errorf("version directory holds %v, want %v", got, want)
	}
	// No subprocess but the probe and the assertion ran: there is no installer.
	if env.countCalls("installer") != 0 {
		t.Errorf("an installer ran although the profile declares none: %v", env.called())
	}
	if env.countCalls("probe "+filepath.Join(dir, widgetBinary)) == 0 {
		t.Errorf("the primary artifact was never probed: %v", env.called())
	}
	if env.countCalls("assert config set "+widgetGate+" off") == 0 {
		t.Errorf("the profile's mandatory assertion never ran: %v", env.called())
	}
	// The off switches are asserted by absence.
	if exists(filepath.Join(env.root, testLinkDir)) {
		t.Error("a link directory was created although LinkDir is empty")
	}
	if ready, why := m.Ready(); !ready {
		t.Errorf("Ready() = false (%s), want true", why)
	}
}

// TestWidgetProfileUsesItsOwnVersionParser pins that the JSON probe answer is what
// gates activation for this profile: the default last-field parser would read the
// whole JSON object's tail, so a wrong parser must not silently pass.
func TestWidgetProfileUsesItsOwnVersionParser(t *testing.T) {
	env := newWidgetEnv(t)
	m := widgetManager(env)
	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	answer := fmt.Sprintf("{\"name\":%q,\"version\":%q}\n", widgetName, pinnedVersion)
	if got := parseJSONVersion(answer); got != pinnedVersion {
		t.Fatalf("the profile's parser returned %q for %q", got, answer)
	}
	if got := LastFieldOfFirstLine(answer); got == pinnedVersion {
		t.Fatal("the default parser also reads this shape, so the test proves nothing about ParseVersion")
	}

	t.Run("a probe answer the parser cannot read excludes the version", func(t *testing.T) {
		env := newWidgetEnv(t)
		env.onProbe = func(string) ([]byte, error) { return []byte("widget " + pinnedVersion + "\n"), nil }
		m := widgetManager(env)
		if _, ok := m.selectActive(t.Context()); ok {
			t.Error("selectActive accepted output the profile's parser cannot read")
		}
	})

	t.Run("a parseable answer naming another version is excluded", func(t *testing.T) {
		env := newWidgetEnv(t)
		env.placeVersion(pinnedVersion, widgetBinary, widgetHelper)
		env.onProbe = func(string) ([]byte, error) { return []byte(`{"version":"0.0.1"}`), nil }
		m := widgetManager(env)
		if _, ok := m.selectActive(t.Context()); ok {
			t.Error("selectActive accepted an artifact reporting a version its directory does not claim")
		}
	})
}

// TestWidgetProfileRequiredSetIsBothArtifacts pins the required set for a profile
// whose helper is not optional: an archive missing the helper publishes nothing, and
// an archive missing the primary artifact likewise.
func TestWidgetProfileRequiredSetIsBothArtifacts(t *testing.T) {
	tests := map[string]map[string]zipEntry{
		"helper missing": {
			"dist/bin/" + widgetBinary: {body: fakeBinaryBody(pinnedVersion), mode: 0o755},
		},
		"primary missing": {
			"dist/bin/" + widgetHelper: {body: fakeBinaryBody(pinnedVersion), mode: 0o755},
		},
		"artifacts in the wrong directory": {
			"bin/" + widgetBinary: {body: fakeBinaryBody(pinnedVersion), mode: 0o755},
			"bin/" + widgetHelper: {body: fakeBinaryBody(pinnedVersion), mode: 0o755},
		},
		"artifacts not executable": {
			"dist/bin/" + widgetBinary: {body: fakeBinaryBody(pinnedVersion), mode: 0o644},
			"dist/bin/" + widgetHelper: {body: fakeBinaryBody(pinnedVersion), mode: 0o644},
		},
	}
	for name, entries := range tests {
		t.Run(name, func(t *testing.T) {
			env := newWidgetEnv(t)
			env.archive = buildZip(t, entries)
			env.digest = digestOf(env.archive)
			m := widgetManager(env)

			if err := m.Ensure(t.Context()); err == nil {
				t.Fatal("Ensure returned nil although a required artifact is absent")
			}
			if exists(filepath.Join(env.root, widgetName+versionsSuffix, pinnedVersion)) {
				t.Error("a version directory was published without its full required set")
			}
			if ready, _ := m.Ready(); ready {
				t.Error("Ready() = true with no complete install")
			}
		})
	}
}

// TestWidgetProfileRetainsTwoPredecessors pins the retention axis end to end on the
// profile that sets it: three versions on the volume, the active one plus two kept,
// the fourth pruned.
func TestWidgetProfileRetainsTwoPredecessors(t *testing.T) {
	env := newWidgetEnv(t)
	for _, v := range []string{prevVersion, oldVersion, "2.13.0"} {
		env.placeVersion(v, widgetBinary, widgetHelper)
	}
	m := widgetManager(env)

	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	root := filepath.Join(env.root, widgetName+versionsSuffix)
	got := slices.Sorted(slices.Values(nonHidden(mustReadDir(t, root))))
	want := slices.Sorted(slices.Values([]string{pinnedVersion, prevVersion, oldVersion}))
	if !slices.Equal(got, want) {
		t.Errorf("version directories = %v, want %v (active plus two predecessors)", got, want)
	}
}

// TestWidgetProfileFallsBackToAPredecessor pins that the fallback posture is not a
// property of the primary profile: with the download broken, a complete predecessor
// keeps the widget install ready.
func TestWidgetProfileFallsBackToAPredecessor(t *testing.T) {
	env := newWidgetEnv(t)
	prev := env.placeVersion(prevVersion, widgetBinary, widgetHelper)
	env.onFetch = func(io.Writer) error { return errors.New("network unreachable") }
	m := widgetManager(env)

	if err := m.Ensure(t.Context()); err == nil {
		t.Fatal("Ensure returned nil although the download failed")
	}
	if ready, why := m.Ready(); !ready {
		t.Errorf("Ready() = false (%s), want true on the retained predecessor", why)
	}
	if got, want := m.Path(), filepath.Join(prev, widgetBinary); got != want {
		t.Errorf("Path() = %q, want %q", got, want)
	}
	if state, ok := m.Active(); !ok || state.ActiveVersion != prevVersion || state.LastError == "" {
		t.Errorf("State = %+v (active=%v), want the fallback recorded with its error", state, ok)
	}
}

// TestTwoProfilesShareOneRootWithoutColliding pins the consequence of keying every
// path on Release.Name: two different packages installed under the same Root keep
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
