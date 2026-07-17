package toolbelt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// failingTransport errors every request: any network touch fails the
// test that installed it.
type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("network touched in an offline-only path")
}

func offlineClient() *http.Client { return &http.Client{Transport: failingTransport{}} }

// manualEntry returns a trivially installable manual tool definition.
func manualEntry(name string) Tool {
	return Tool{
		Source: SourceManual, Version: "1",
		Install: fmt.Sprintf(`printf x > "$BIN/%s" && chmod 755 "$BIN/%s"`, name, name),
	}
}

func TestDisable_UninstallsAndKeepsTemplate(t *testing.T) {
	e := newTestEngine(t, nil)
	addManual(t, e, "tool", nil)

	on := true
	jv, err := e.Patch("tool", PatchRequest{Disabled: &on})
	if err != nil || jv == nil {
		t.Fatalf("disable patch: job=%v err=%v", jv, err)
	}
	if final := waitJob(t, e, jv.ID); final.State != JobDone {
		t.Fatalf("disable job = %+v tail=%v", final, final.OutputTail)
	}
	// Footprint gone, template kept, state dropped.
	if _, err := os.Stat(filepath.Join(e.toolsDir, "bin", "tool")); !os.IsNotExist(err) {
		t.Fatal("binary survived disable")
	}
	m, _ := e.store.Manifest()
	tl, ok := m.Tools["tool"]
	if !ok || !tl.Disabled {
		t.Fatalf("template lost or not disabled: %+v", m.Tools)
	}
	if _, owned := e.store.State().Tools["tool"]; owned {
		t.Fatal("state not dropped on disable")
	}
	inv, _ := e.Inventory()
	if inv.Tools[0].Installed || !inv.Tools[0].Disabled {
		t.Fatalf("inventory row = %+v", inv.Tools[0])
	}
}

func TestInstall_RefusesDisabled(t *testing.T) {
	e := newTestEngine(t, nil)
	err := e.store.MutateManifest(func(m *Manifest) error {
		tl := manualEntry("x")
		tl.Disabled = true
		m.Tools["x"] = tl
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Install("x"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("install disabled = %v, want ErrDisabled", err)
	}
}

func TestPatch_EnableInstalls(t *testing.T) {
	e := newTestEngine(t, nil)
	err := e.store.MutateManifest(func(m *Manifest) error {
		tl := manualEntry("x")
		tl.Disabled = true
		m.Tools["x"] = tl
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	off := false
	jv, err := e.Patch("x", PatchRequest{Disabled: &off})
	if err != nil || jv == nil {
		t.Fatalf("enable patch: job=%v err=%v", jv, err)
	}
	if final := waitJob(t, e, jv.ID); final.State != JobDone {
		t.Fatalf("enable job = %+v tail=%v", final, final.OutputTail)
	}
	if _, err := os.Stat(filepath.Join(e.toolsDir, "bin", "x")); err != nil {
		t.Fatal("enable did not install")
	}
}

func TestPatch_DisableDependentsRefusedThenForced(t *testing.T) {
	e := newTestEngine(t, nil)
	addManual(t, e, "base", nil)
	addManual(t, e, "dep", []string{"base"})

	on := true
	_, err := e.Patch("base", PatchRequest{Disabled: &on})
	var depErr *DependentsError
	if !errors.As(err, &depErr) || !errors.Is(err, ErrHasDependents) {
		t.Fatalf("disable with dependents = %v, want DependentsError", err)
	}
	if len(depErr.Dependents) != 1 || depErr.Dependents[0] != "dep" {
		t.Fatalf("dependents = %v", depErr.Dependents)
	}

	jv, err := e.Patch("base", PatchRequest{Disabled: &on, Force: true})
	if err != nil || jv == nil {
		t.Fatalf("forced disable: job=%v err=%v", jv, err)
	}
	if final := waitJob(t, e, jv.ID); final.State != JobDone {
		t.Fatalf("forced disable job = %+v", final)
	}
}

func TestRemove_DisabledDependentDoesNotBlock(t *testing.T) {
	e := newTestEngine(t, nil)
	addManual(t, e, "base", nil)
	err := e.store.MutateManifest(func(m *Manifest) error {
		tl := manualEntry("dep")
		tl.Requires = []string{"base"}
		tl.Disabled = true
		m.Tools["dep"] = tl
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	jv, deps, err := e.Remove("base", false)
	if err != nil {
		t.Fatalf("remove with only a disabled dependent = %v (deps %v)", err, deps)
	}
	waitJob(t, e, jv.ID)
}

func TestReconcile_ConvergesBothWays(t *testing.T) {
	e := newTestEngine(t, nil)
	// installed-then-disabled tool + enabled-but-missing tool.
	addManual(t, e, "extra", nil)
	err := e.store.MutateManifest(func(m *Manifest) error {
		tl := m.Tools["extra"]
		tl.Disabled = true
		m.Tools["extra"] = tl
		m.Tools["missing"] = manualEntry("missing")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	jv, err := e.Reconcile(ReconcileMissing)
	if err != nil || jv == nil {
		t.Fatalf("reconcile: job=%v err=%v", jv, err)
	}
	if final := waitJob(t, e, jv.ID); final.State != JobDone {
		t.Fatalf("reconcile job = %+v tail=%v", final, final.OutputTail)
	}
	if _, err := os.Stat(filepath.Join(e.toolsDir, "bin", "extra")); !os.IsNotExist(err) {
		t.Fatal("disabled tool's binary survived reconcile")
	}
	if _, err := os.Stat(filepath.Join(e.toolsDir, "bin", "missing")); err != nil {
		t.Fatal("missing tool not installed by reconcile")
	}
}

func TestReconcile_EmptyManifestNoJob(t *testing.T) {
	e := newTestEngine(t, nil)
	jv, err := e.Reconcile(ReconcileMissing)
	if err != nil || jv != nil {
		t.Fatalf("empty reconcile: job=%v err=%v", jv, err)
	}
}

func TestReconcile_ConvergedIsOffline(t *testing.T) {
	// A converged manifest must reconcile with ZERO network: the engine
	// gets a failing transport, so any fetch fails the job.
	e := newTestEngineClient(t, nil, offlineClient(), nil)
	addManual(t, e, "tool", nil) // manual installs touch no network

	jv, err := e.Reconcile(ReconcileMissing)
	if err != nil || jv == nil {
		t.Fatalf("reconcile: job=%v err=%v", jv, err)
	}
	final := waitJob(t, e, jv.ID)
	if final.State != JobDone {
		t.Fatalf("converged offline reconcile = %+v tail=%v", final, final.OutputTail)
	}
	if len(final.OutputTail) == 0 || !strings.Contains(strings.Join(final.OutputTail, "\n"), "converged") {
		t.Fatalf("expected converged output, got %v", final.OutputTail)
	}
}

func TestReconcileFull_EnqueuesUpdatePass(t *testing.T) {
	e := newTestEngine(t, nil)
	addManual(t, e, "tool", nil)
	jv, err := e.Reconcile(ReconcileFull)
	if err != nil || jv == nil {
		t.Fatal(err)
	}
	waitJob(t, e, jv.ID)
	// The follow-up update job ran too (manual tools skip updates, so
	// it completes as an up-to-date no-op).
	_, recent := e.Jobs()
	kinds := map[string]bool{}
	for _, r := range recent {
		kinds[r.Kind] = true
	}
	if !kinds[JobKindReconcile] || !kinds[JobKindUpdate] {
		t.Fatalf("recent kinds = %v, want reconcile + update", kinds)
	}
}

func TestHydration_SparseEntryFromCatalog(t *testing.T) {
	cat := &Catalog{Entries: map[string]CatalogEntry{
		"x": {
			Name: "x", Source: SourceManual, Version: "1.0.0",
			Install: `printf x > "$BIN/x" && chmod 755 "$BIN/x"`, Probe: "x",
			Shims: map[string]string{"x-alias": "x --serve"},
		},
	}}
	e := newTestEngine(t, cat)
	// A name-only hand edit, as a wtk config-file user would write.
	err := e.store.MutateManifest(func(m *Manifest) error {
		m.Tools["x"] = Tool{}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	jv, err := e.Reconcile(ReconcileMissing)
	if err != nil {
		t.Fatal(err)
	}
	if final := waitJob(t, e, jv.ID); final.State != JobDone {
		t.Fatalf("reconcile = %+v tail=%v", final, final.OutputTail)
	}
	m, _ := e.store.Manifest()
	tl := m.Tools["x"]
	if tl.Source != SourceManual || tl.Version != "1.0.0" || tl.Shims["x-alias"] == "" {
		t.Fatalf("hydration did not persist catalog fields: %+v", tl)
	}
	if _, err := os.Stat(filepath.Join(e.toolsDir, "bin", "x-alias")); err != nil {
		t.Fatal("catalog shim not written")
	}
}

func TestHydration_LegacyBinaryDoesNotWedge(t *testing.T) {
	// A migration volume: an unmanaged binary already sits in bin/ under
	// the tool's probe name. The sparse entry must still hydrate its
	// source (hydration runs BEFORE the probe-based plan), so the
	// update path has a source to resolve instead of wedging on "".
	cat := &Catalog{Entries: map[string]CatalogEntry{
		"legacy": {
			Name: "legacy", Source: SourceManual, Version: "2.0.0",
			Install: `printf y > "$BIN/legacy" && chmod 755 "$BIN/legacy"`, Probe: "legacy",
		},
	}}
	e := newTestEngine(t, cat)
	if err := os.WriteFile(filepath.Join(e.toolsDir, "bin", "legacy"), []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := e.store.MutateManifest(func(m *Manifest) error {
		m.Tools["legacy"] = Tool{}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	jv, err := e.Reconcile(ReconcileMissing)
	if err != nil {
		t.Fatal(err)
	}
	if final := waitJob(t, e, jv.ID); final.State != JobDone {
		t.Fatalf("reconcile = %+v", final)
	}
	m, _ := e.store.Manifest()
	if m.Tools["legacy"].Source == "" {
		t.Fatal("legacy entry left source-less (the wedge)")
	}
	// The unmanaged binary satisfied the probe: reconcile leaves it.
	if data, _ := os.ReadFile(filepath.Join(e.toolsDir, "bin", "legacy")); string(data) != "old" {
		t.Fatal("reconcile overwrote an unmanaged binary")
	}
	// An explicit install takes ownership.
	ij, err := e.Install("legacy")
	if err != nil {
		t.Fatal(err)
	}
	if final := waitJob(t, e, ij.ID); final.State != JobDone {
		t.Fatalf("explicit install = %+v tail=%v", final, final.OutputTail)
	}
	if got := e.store.State().Tools["legacy"].InstalledVersion; got != "2.0.0" {
		t.Fatalf("ownership not established: %q", got)
	}
}

func TestHydration_UnknownNameFailsNamed(t *testing.T) {
	e := newTestEngine(t, nil) // empty catalog
	err := e.store.MutateManifest(func(m *Manifest) error {
		m.Tools["mystery"] = Tool{}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	jv, err := e.Reconcile(ReconcileMissing)
	if err != nil {
		t.Fatal(err)
	}
	final := waitJob(t, e, jv.ID)
	if final.State != JobFailed || !strings.Contains(final.Error, "not in the catalog") {
		t.Fatalf("job = %+v, want named catalog error", final)
	}
}

func TestHydration_DisabledStaysOffline(t *testing.T) {
	// Disabled templates hydrate static fields only — no version
	// resolution, no network (failing transport proves it).
	cat := &Catalog{Entries: map[string]CatalogEntry{
		"tmpl": {Name: "tmpl", Source: "npm:tmpl"}, // npm source would need network for latest
	}}
	e := newTestEngineClient(t, cat, offlineClient(), nil)
	err := e.store.MutateManifest(func(m *Manifest) error {
		m.Tools["tmpl"] = Tool{Disabled: true}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	jv, err := e.Reconcile(ReconcileMissing)
	if err != nil {
		t.Fatal(err)
	}
	if final := waitJob(t, e, jv.ID); final.State != JobDone {
		t.Fatalf("reconcile with disabled sparse entry = %+v", final)
	}
	m, _ := e.store.Manifest()
	tl := m.Tools["tmpl"]
	if tl.Source != "npm:tmpl" {
		t.Fatalf("static hydration missing: %+v", tl)
	}
	if tl.Version != "" {
		t.Fatalf("disabled template resolved a version (network?): %q", tl.Version)
	}
}

func TestInstallOrder_DisabledDependencyRefused(t *testing.T) {
	e := newTestEngine(t, nil)
	err := e.store.MutateManifest(func(m *Manifest) error {
		base := manualEntry("base")
		base.Disabled = true
		m.Tools["base"] = base
		dep := manualEntry("dep")
		dep.Requires = []string{"base"}
		m.Tools["dep"] = dep
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	m, _ := e.store.Manifest()
	_, err = e.installOrder(context.Background(), m, []string{"dep"})
	if err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("installOrder through disabled dep = %v, want refusal", err)
	}
}

func TestManifest_CommentRoundTrip(t *testing.T) {
	dir := t.TempDir()
	seed := &Manifest{
		Version: ManifestVersion,
		Comment: []string{"line one", "line two"},
		Tools:   map[string]Tool{"gopls": {Disabled: true}},
	}
	st := newStore(dir, seed, slog.Default())
	if err := st.initFiles(); err != nil {
		t.Fatal(err)
	}
	// A mutation must preserve the comment.
	err := st.MutateManifest(func(m *Manifest) error {
		m.Tools["extra"] = Tool{Source: SourceManual, Version: "1", Install: "true"}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "tools.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["_comment"]; !ok {
		t.Fatalf("_comment dropped on rewrite: %s", raw)
	}
	m, _ := st.Manifest()
	if len(m.Comment) != 2 || !m.Tools["gopls"].Disabled {
		t.Fatalf("roundtrip = %+v", m)
	}
}

func TestSeed_FreshVolumeAndV1Backup(t *testing.T) {
	t.Run("fresh volume", func(t *testing.T) {
		dir := t.TempDir()
		st := newStore(dir, DefaultSeed(), slog.Default())
		if err := st.initFiles(); err != nil {
			t.Fatal(err)
		}
		m, err := st.Manifest()
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"gopls", "tsc-native", "pyrefly", "gh"} {
			tl, ok := m.Tools[name]
			if !ok || !tl.Disabled {
				t.Errorf("seed template %s missing or enabled: %+v", name, tl)
			}
		}
		if len(m.Comment) == 0 {
			t.Error("seed comment missing")
		}
	})
	t.Run("v1 backup gets seed not empty", func(t *testing.T) {
		dir := t.TempDir()
		v1 := `{"lsp":{"gopls":{"enabled":true}}}`
		if err := os.WriteFile(filepath.Join(dir, "tools.json"), []byte(v1), 0o644); err != nil {
			t.Fatal(err)
		}
		st := newStore(dir, DefaultSeed(), slog.Default())
		if err := st.initFiles(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(dir, "tools.json.v1.bak")); err != nil {
			t.Fatal("v1 backup missing")
		}
		m, _ := st.Manifest()
		if len(m.Tools) != 4 {
			t.Fatalf("v1 replacement should be the seed, got %d tools", len(m.Tools))
		}
	})
	t.Run("nil seed stays empty", func(t *testing.T) {
		dir := t.TempDir()
		st := newStore(dir, nil, slog.Default())
		if err := st.initFiles(); err != nil {
			t.Fatal(err)
		}
		m, _ := st.Manifest()
		if len(m.Tools) != 0 {
			t.Fatalf("nil seed produced tools: %+v", m.Tools)
		}
	})
}

func TestDefaultSeed_ReturnsFreshCopies(t *testing.T) {
	a := DefaultSeed()
	a.Tools["gopls"] = Tool{Disabled: false, Source: "mutated"}
	a.Comment[0] = "mutated"
	b := DefaultSeed()
	if b.Tools["gopls"].Source == "mutated" || b.Comment[0] == "mutated" {
		t.Fatal("DefaultSeed shares state across calls")
	}
}

func TestEnsureInstalled_EnablesDisabledTemplate(t *testing.T) {
	e := newTestEngine(t, nil)
	err := e.store.MutateManifest(func(m *Manifest) error {
		tl := manualEntry("gh")
		tl.Disabled = true
		m.Tools["gh"] = tl
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := e.EnsureInstalled(ctx, "gh"); err != nil {
		t.Fatalf("EnsureInstalled disabled template: %v", err)
	}
	m, _ := e.store.Manifest()
	if m.Tools["gh"].Disabled {
		t.Fatal("template still disabled after EnsureInstalled")
	}
	if _, err := os.Stat(filepath.Join(e.toolsDir, "bin", "gh")); err != nil {
		t.Fatal("tool not installed")
	}
}

func TestInventory_UnmanagedBinaryDoesNotMarkDisabledInstalled(t *testing.T) {
	e := newTestEngine(t, nil)
	err := e.store.MutateManifest(func(m *Manifest) error {
		m.Tools["tool"] = Tool{Disabled: true}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// An unmanaged same-name file exists in bin.
	if err := os.WriteFile(filepath.Join(e.toolsDir, "bin", "tool"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	inv, _ := e.Inventory()
	if inv.Tools[0].Installed {
		t.Fatal("unmanaged binary marked a disabled template installed")
	}
}

func TestVerifyCatalog(t *testing.T) {
	cat := &Catalog{Entries: map[string]CatalogEntry{
		"good-manual": {Name: "good-manual", Source: SourceManual, Install: "true"},
		"bad-manual":  {Name: "bad-manual", Source: SourceManual},
		"no-source":   {Name: "no-source"},
		"good-aqua": {
			Name: "good-aqua", Source: "aqua:o/r",
			Aqua: &AquaPackage{Type: aquaTypeGitHubRelease, RepoOwner: "o", RepoName: "r", Asset: "r_{{.Version}}.tar.gz"},
		},
		"aqua-no-def": {Name: "aqua-no-def", Source: "aqua:o/r"},
		"aqua-amd-only": {
			Name: "aqua-amd-only", Source: "aqua:o/r",
			Aqua: &AquaPackage{Type: aquaTypeGitHubRelease, RepoOwner: "o", RepoName: "r", Asset: "a", SupportedEnvs: []string{"linux/amd64"}},
		},
		"aqua-bad-template": {
			Name: "aqua-bad-template", Source: "aqua:o/r",
			Aqua: &AquaPackage{Type: aquaTypeGitHubRelease, RepoOwner: "o", RepoName: "r", Asset: "{{.Broken"},
		},
		"good-npm": {Name: "good-npm", Source: "npm:x"},
	}}
	cases := []struct {
		name   string
		fails  bool
		reason string
	}{
		{"good-manual", false, ""},
		{"good-aqua", false, ""},
		{"good-npm", false, ""},
		{"missing-entirely", true, "not in the catalog"},
		{"no-source", true, "no source"},
		{"bad-manual", true, "install command"},
		{"aqua-no-def", true, "embedded definition"},
		{"aqua-amd-only", true, "linux/arm64"},
		{"aqua-bad-template", true, "template"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			errs := VerifyCatalog(cat, []string{tc.name})
			if tc.fails {
				if len(errs) != 1 || !strings.Contains(errs[0].Error(), tc.reason) {
					t.Fatalf("VerifyCatalog(%s) = %v, want error containing %q", tc.name, errs, tc.reason)
				}
				return
			}
			if len(errs) != 0 {
				t.Fatalf("VerifyCatalog(%s) = %v, want clean", tc.name, errs)
			}
		})
	}
}
