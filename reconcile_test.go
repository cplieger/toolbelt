package toolbelt

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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
		Install: binStub(name),
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
	m, _ := e.store.LoadManifest()
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
	depErr, isDependents := errors.AsType[*DependentsError](err)
	if !isDependents || !errors.Is(err, ErrHasDependents) {
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
	jv, deps, err := e.Remove("base")
	if err != nil || len(deps) != 0 {
		t.Fatalf("remove with only a disabled dependent = %v (deps %v), want success naming none", err, deps)
	}
	if final := waitJob(t, e, jv.ID); final.State != JobDone || !slices.Equal(final.Names, []string{"base"}) {
		t.Errorf("remove job = %s %v, want done over [base]", final.State, final.Names)
	}
	m, err := e.store.LoadManifest()
	if err != nil {
		t.Fatal(err)
	}
	if row, ok := m.Tools["dep"]; !ok || !row.Disabled {
		t.Errorf("dep row = %+v (present %v), want the disabled template kept", row, ok)
	}
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

	jv, enqueued, err := e.Reconcile(ReconcileMissing)
	if err != nil || !enqueued {
		t.Fatalf("reconcile: job=%v enqueued=%v err=%v", jv, enqueued, err)
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

// TestReconcile_RebuildsAVenvOnAnotherPythonRequest: a pip: row whose venv
// was built for another Python request than the manifest's is not converged,
// though its version matches and its launcher runs, so a hand-edited python
// field reaches the venv (uv tool install --python).
func TestReconcile_RebuildsAVenvOnAnotherPythonRequest(t *testing.T) {
	argv := fakeUV(t)
	e := pipEngine(t, "3.14")
	writeStub(t, e, "x", "echo x 1.0.0")
	if err := e.store.setToolStatus("x", func(s *ToolStatus) {
		s.InstalledVersion = "1.0.0"
		s.Python = "3.13"
		s.PMBins = []string{"x"}
	}); err != nil {
		t.Fatal(err)
	}

	jv, enqueued, err := e.Reconcile(ReconcileMissing)
	if err != nil || !enqueued {
		t.Fatalf("reconcile: job=%v enqueued=%v err=%v", jv, enqueued, err)
	}
	if final := waitJob(t, e, jv.ID); final.State != JobDone {
		t.Fatalf("reconcile job = %s, want done (tail %v)", final.State, final.OutputTail)
	}
	if got, want := readArgv(t, argv), []string{"tool install --reinstall --python 3.14 x==1.0.0"}; !slices.Equal(got, want) {
		t.Errorf("uv argv = %q, want %q", got, want)
	}
	if got := e.store.State().Tools["x"].Python; got != "3.14" {
		t.Errorf("recorded python = %q, want 3.14", got)
	}

	jv, _, err = e.Reconcile(ReconcileMissing)
	if err != nil {
		t.Fatal(err)
	}
	if out := strings.Join(waitJob(t, e, jv.ID).OutputTail, "\n"); !strings.Contains(out, "everything converged") {
		t.Errorf("second reconcile output = %q, want everything converged", out)
	}
}

// TestReconcile_InstallsTheVersionTheManifestNowNames: a hand edit of an
// installed row's version is a request Reconcile applies, so tools.json and
// tools-state.json agree once it reports converged.
func TestReconcile_InstallsTheVersionTheManifestNowNames(t *testing.T) {
	e := newTestEngine(t, nil)
	addManual(t, e, "tool", nil)
	err := e.store.MutateManifest(func(m *Manifest) error {
		tl := m.Tools["tool"]
		tl.Version = "2"
		m.Tools["tool"] = tl
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	jv, enqueued, err := e.Reconcile(ReconcileMissing)
	if err != nil || !enqueued {
		t.Fatalf("reconcile: job=%v enqueued=%v err=%v", jv, enqueued, err)
	}
	if final := waitJob(t, e, jv.ID); final.State != JobDone {
		t.Fatalf("reconcile job = %s, want done (tail %v)", final.State, final.OutputTail)
	}
	if got := e.store.State().Tools["tool"].InstalledVersion; got != "2" {
		t.Errorf("installed version = %q, want 2", got)
	}
	out, err := exec.Command(filepath.Join(e.toolsDir, "bin", "tool")).Output()
	if err != nil || strings.TrimSpace(string(out)) != "tool 2" {
		t.Errorf("installed binary prints %q (%v), want tool 2", out, err)
	}

	jv, _, err = e.Reconcile(ReconcileMissing)
	if err != nil {
		t.Fatal(err)
	}
	if out := strings.Join(waitJob(t, e, jv.ID).OutputTail, "\n"); !strings.Contains(out, "everything converged") {
		t.Errorf("second reconcile output = %q, want everything converged", out)
	}
}

// TestReconcile_SparseRowIsOfflineWhenInstalled: an empty manifest version
// means the latest, which is resolved only by an install, so an installed
// sparse row is converged and Reconcile asks no version source.
func TestReconcile_SparseRowIsOfflineWhenInstalled(t *testing.T) {
	e := newTestEngineClient(t, nil, offlineClient(), nil)
	addManual(t, e, "tool", nil)
	err := e.store.MutateManifest(func(m *Manifest) error {
		tl := m.Tools["tool"]
		tl.Version = ""
		m.Tools["tool"] = tl
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	jv, _, err := e.Reconcile(ReconcileMissing)
	if err != nil {
		t.Fatal(err)
	}
	final := waitJob(t, e, jv.ID)
	if out := strings.Join(final.OutputTail, "\n"); final.State != JobDone || !strings.Contains(out, "everything converged") {
		t.Errorf("reconcile = %s %q, want done and everything converged", final.State, out)
	}
}

func TestReconcile_EmptyManifestNoJob(t *testing.T) {
	e := newTestEngine(t, nil)
	// The C15 no-job answer: enqueued false, a nil job and a NIL error,
	// so a caller cannot mistake a fresh volume for a failure — nor reach
	// the job without reading the flag that says there isn't one.
	jv, enqueued, err := e.Reconcile(ReconcileMissing)
	if err != nil {
		t.Errorf("empty reconcile err = %v, want nil", err)
	}
	if enqueued {
		t.Errorf("empty reconcile enqueued = true, want false")
	}
	if jv != nil {
		t.Errorf("empty reconcile job = %+v, want nil", jv)
	}
}

func TestReconcile_ConvergedIsOffline(t *testing.T) {
	// A converged manifest must reconcile with ZERO network: the engine
	// gets a failing transport, so any fetch fails the job.
	e := newTestEngineClient(t, nil, offlineClient(), nil)
	addManual(t, e, "tool", nil) // manual installs touch no network

	jv, enqueued, err := e.Reconcile(ReconcileMissing)
	if err != nil || !enqueued {
		t.Fatalf("reconcile: job=%v enqueued=%v err=%v", jv, enqueued, err)
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
	jv, enqueued, err := e.Reconcile(ReconcileFull)
	if err != nil || !enqueued {
		t.Fatalf("reconcile full: job=%v enqueued=%v err=%v", jv, enqueued, err)
	}
	waitJob(t, e, jv.ID)
	// The follow-up update job completes as an up-to-date no-op (manual
	// tools skip updates), but Reconcile hands back only the reconcile
	// job, so there is no ID to wait on: poll until the update job
	// reaches recent history instead of reading it once, which raced the
	// worker on a loaded runner.
	deadline := time.Now().Add(15 * time.Second)
	for {
		_, recent := e.Jobs()
		kinds := map[string]bool{}
		for _, r := range recent {
			kinds[r.Kind] = true
		}
		if kinds[JobKindReconcile] && kinds[JobKindUpdate] {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("recent kinds = %v, want reconcile + update", kinds)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestHydration_SparseEntryFromCatalog(t *testing.T) {
	cat := &Catalog{Entries: map[string]CatalogEntry{
		"x": {
			Name: "x", Source: SourceManual, Version: "1.0.0",
			Install: binStub("x"), Probe: "x",
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
	jv, enqueued, err := e.Reconcile(ReconcileMissing)
	if err != nil || !enqueued {
		t.Fatalf("reconcile: job=%v enqueued=%v err=%v", jv, enqueued, err)
	}
	if final := waitJob(t, e, jv.ID); final.State != JobDone {
		t.Fatalf("reconcile = %+v tail=%v", final, final.OutputTail)
	}
	m, _ := e.store.LoadManifest()
	tl := m.Tools["x"]
	if tl.Source != SourceManual || tl.Version != "1.0.0" {
		t.Fatalf("hydration did not persist catalog fields: %+v", tl)
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
			Install: binStub("legacy"), Probe: "legacy",
		},
	}}
	e := newTestEngine(t, cat)
	// The pre-existing binary is a real program: it answers the probe, so
	// the reconciler has no reason to touch it.
	legacyBin := filepath.Join(e.toolsDir, "bin", "legacy")
	if err := os.WriteFile(legacyBin, []byte("#!/bin/sh\necho old\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := e.store.MutateManifest(func(m *Manifest) error {
		m.Tools["legacy"] = Tool{}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	jv, enqueued, err := e.Reconcile(ReconcileMissing)
	if err != nil || !enqueued {
		t.Fatalf("reconcile: job=%v enqueued=%v err=%v", jv, enqueued, err)
	}
	if final := waitJob(t, e, jv.ID); final.State != JobDone {
		t.Fatalf("reconcile = %+v", final)
	}
	m, _ := e.store.LoadManifest()
	if m.Tools["legacy"].Source == "" {
		t.Fatal("legacy entry left source-less (the wedge)")
	}
	// The unmanaged binary satisfied the probe: reconcile leaves it.
	if data, _ := os.ReadFile(legacyBin); !strings.Contains(string(data), "echo old") {
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
	jv, enqueued, err := e.Reconcile(ReconcileMissing)
	if err != nil || !enqueued {
		t.Fatalf("reconcile: job=%v enqueued=%v err=%v", jv, enqueued, err)
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
	jv, enqueued, err := e.Reconcile(ReconcileMissing)
	if err != nil || !enqueued {
		t.Fatalf("reconcile: job=%v enqueued=%v err=%v", jv, enqueued, err)
	}
	if final := waitJob(t, e, jv.ID); final.State != JobDone {
		t.Fatalf("reconcile with disabled sparse entry = %+v", final)
	}
	m, _ := e.store.LoadManifest()
	tl := m.Tools["tmpl"]
	if tl.Source != "npm:tmpl" {
		t.Fatalf("static hydration missing: %+v", tl)
	}
	if tl.Version != "" {
		t.Fatalf("disabled template resolved a version (network?): %q", tl.Version)
	}
}

func TestInstallOrder_DisabledDependencyEnabled(t *testing.T) {
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
	m, _ := e.store.LoadManifest()
	plan := e.installOrder(t.Context(), m, []string{"dep"})
	if len(plan.unplanned) != 0 {
		t.Fatalf("installOrder through disabled dep: unplanned %v, want the dep enabled", plan.unplanned)
	}
	if got := plan.ordered; len(got) != 2 || got[0] != "base" || got[1] != "dep" {
		t.Fatalf("ordered = %v, want [base dep]", got)
	}
	if got := plan.enabled; len(got) != 1 || got[0] != "base" {
		t.Fatalf("enabled = %v, want [base]", got)
	}
	// The enable is PERSISTED, not merely applied to the plan's copy: a
	// dependency the plan installs while the manifest still calls it
	// disabled would be uninstalled again by the next reconcile.
	m2, _ := e.store.LoadManifest()
	if m2.Tools["base"].Disabled {
		t.Fatal("base still disabled in the manifest after the plan enabled it")
	}
}

// A tool named DIRECTLY stays refused-by-omission: install is
// policy-neutral, so enabling rides Patch. Only the dependency edge
// carries the implicit enable.
func TestInstallOrder_DisabledRootIsNotEnabled(t *testing.T) {
	e := newTestEngine(t, nil)
	err := e.store.MutateManifest(func(m *Manifest) error {
		base := manualEntry("base")
		base.Disabled = true
		m.Tools["base"] = base
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	m, _ := e.store.LoadManifest()
	plan := e.installOrder(t.Context(), m, []string{"base"})
	if len(plan.unplanned) != 0 {
		t.Fatalf("installOrder(base) unplanned = %v, want none", plan.unplanned)
	}
	if len(plan.enabled) != 0 {
		t.Fatalf("enabled = %v, want none for a directly named tool", plan.enabled)
	}
	m2, _ := e.store.LoadManifest()
	if !m2.Tools["base"].Disabled {
		t.Fatal("a directly named disabled tool was enabled by the plan")
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
	m, _ := st.LoadManifest()
	if len(m.Comment) != 2 || !m.Tools["gopls"].Disabled {
		t.Fatalf("roundtrip = %+v", m)
	}
}

func TestSeed_InitFiles(t *testing.T) {
	t.Run("fresh volume", func(t *testing.T) {
		dir := t.TempDir()
		st := newStore(dir, DefaultSeed(), slog.Default())
		if err := st.initFiles(); err != nil {
			t.Fatal(err)
		}
		m, err := st.LoadManifest()
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"gopls", "pyright", "rust-analyzer", "typescript-language-server"}
		if got := slices.Sorted(maps.Keys(m.Tools)); !slices.Equal(got, want) {
			t.Errorf("seed templates = %v, want exactly %v (no forge CLI is seeded)", got, want)
		}
		for _, name := range want {
			if tl := m.Tools[name]; !tl.Disabled {
				t.Errorf("seed template %s is enabled: %+v", name, tl)
			}
		}
		if len(m.Comment) == 0 {
			t.Error("seed comment missing")
		}
	})
	t.Run("wrong-version manifest is an error, file untouched", func(t *testing.T) {
		dir := t.TempDir()
		retired := `{"lsp":{"gopls":{"enabled":true}}}`
		if err := os.WriteFile(filepath.Join(dir, "tools.json"), []byte(retired), 0o644); err != nil {
			t.Fatal(err)
		}
		st := newStore(dir, DefaultSeed(), slog.Default())
		if err := st.initFiles(); err == nil {
			t.Fatal("initFiles accepted a versionless manifest")
		}
		raw, err := os.ReadFile(filepath.Join(dir, "tools.json"))
		if err != nil || string(raw) != retired {
			t.Fatalf("manifest rewritten on refusal: %s (%v)", raw, err)
		}
	})
	t.Run("unparseable manifest is an error", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "tools.json"), []byte("{nope"), 0o644); err != nil {
			t.Fatal(err)
		}
		st := newStore(dir, DefaultSeed(), slog.Default())
		if err := st.initFiles(); err == nil {
			t.Fatal("initFiles accepted an unparseable manifest")
		}
	})
	t.Run("nil seed stays empty", func(t *testing.T) {
		dir := t.TempDir()
		st := newStore(dir, nil, slog.Default())
		if err := st.initFiles(); err != nil {
			t.Fatal(err)
		}
		m, _ := st.LoadManifest()
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
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	if err := e.EnsureInstalled(ctx, "gh"); err != nil {
		t.Fatalf("EnsureInstalled disabled template: %v", err)
	}
	m, _ := e.store.LoadManifest()
	if m.Tools["gh"].Disabled {
		t.Fatal("template still disabled after EnsureInstalled")
	}
	if _, err := os.Stat(filepath.Join(e.toolsDir, "bin", "gh")); err != nil {
		t.Fatal("tool not installed")
	}
}

// TestEnsureInstalled_InstallsTheVersionTheManifestNowNames: a caller that
// needs the tool now gets the version the manifest names, as Reconcile would.
func TestEnsureInstalled_InstallsTheVersionTheManifestNowNames(t *testing.T) {
	e := newTestEngine(t, nil)
	addManual(t, e, "tool", nil)
	err := e.store.MutateManifest(func(m *Manifest) error {
		tl := m.Tools["tool"]
		tl.Version = "2"
		m.Tools["tool"] = tl
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	if err := e.EnsureInstalled(ctx, "tool"); err != nil {
		t.Fatalf("EnsureInstalled: %v", err)
	}
	if got := e.store.State().Tools["tool"].InstalledVersion; got != "2" {
		t.Errorf("installed version = %q, want 2", got)
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

// TestFindChecksum pins the three real-world checksum-file formats and
// the algorithm-aware matching that keeps a multi-algorithm BSD table
// (mikefarah/yq's checksums-bsd lists MD5 through SHA-512 per asset)
// from returning the wrong column's digest.
func TestFindChecksum(t *testing.T) {
	sha256hex := strings.Repeat("ab", 32)
	sha512hex := strings.Repeat("cd", 64)
	cases := []struct {
		name  string
		body  string
		asset string
		alg   string
		want  string
	}{
		{"bare digest", sha256hex + "\n", "x.tar.gz", "sha256", sha256hex},
		// Verification compares case-insensitively, so an upper-case digest
		// file must be read rather than fail closed as unverifiable.
		{"upper-case digest", strings.Repeat("AF", 32) + "  x.tar.gz\n", "x.tar.gz", "sha256", strings.Repeat("AF", 32)},
		{"bare digest wrong length for alg", sha256hex + "\n", "x.tar.gz", "sha512", ""},
		{"coreutils table", sha256hex + "  x.tar.gz\nffff  other.tar.gz\n", "x.tar.gz", "sha256", sha256hex},
		{"coreutils binary-mode star", sha256hex + " *x.tar.gz\n", "x.tar.gz", "sha256", sha256hex},
		{"bsd sha512", "SHA512 (x.tar.gz) = " + sha512hex + "\n", "x.tar.gz", "sha512", sha512hex},
		{"bsd dashed tag", "SHA-512 (x.tar.gz) = " + sha512hex + "\n", "x.tar.gz", "sha512", sha512hex},
		{
			// The yq shape: several algorithms for the same asset; the
			// sha512 line must win over MD5/SHA1/CRC32 rows.
			"bsd multi-algorithm picks the requested one",
			"MD5 (x.tar.gz) = 0123456789abcdef0123456789abcdef\n" +
				"SHA1 (x.tar.gz) = 0123456789abcdef0123456789abcdef01234567\n" +
				"SHA512 (x.tar.gz) = " + sha512hex + "\n",
			"x.tar.gz", "sha512", sha512hex,
		},
		{
			// Name-first multi-hash table (yq's plain `checksums`): no
			// column is length+position safe to attribute, so no match —
			// fail closed rather than guess.
			"name-first multi-hash table refuses",
			"x.tar.gz  df32907e  0123456789abcdef0123456789abcdef\n",
			"x.tar.gz", "sha256", "",
		},
		{"unknown algorithm refuses", sha256hex + "  x.tar.gz\n", "x.tar.gz", "md5", ""},
		{"asset not listed", sha256hex + "  other.tar.gz\n", "x.tar.gz", "sha256", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := findChecksum(tc.body, tc.asset, tc.alg); got != tc.want {
				t.Fatalf("findChecksum(%s, %s) = %q, want %q", tc.asset, tc.alg, got, tc.want)
			}
		})
	}
}

// TestReconcile_SweepsOrphanedState pins the Remove crash-window
// cleanup: an engine-owned footprint whose manifest row is gone (crash
// between Remove's manifest write and its uninstall job) is swept by
// the next reconcile instead of surviving forever.
func TestReconcile_SweepsOrphanedState(t *testing.T) {
	e := newTestEngine(t, nil)
	addManual(t, e, "orphan", nil)
	if _, err := os.Stat(filepath.Join(e.toolsDir, "bin", "orphan")); err != nil {
		t.Fatalf("precondition: orphan not installed: %v", err)
	}
	err := e.store.MutateManifest(func(m *Manifest) error {
		delete(m.Tools, "orphan")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	jv, enqueued, err := e.Reconcile(ReconcileMissing)
	if err != nil || !enqueued {
		t.Fatalf("reconcile: job=%v enqueued=%v err=%v", jv, enqueued, err)
	}
	if final := waitJob(t, e, jv.ID); final.State != JobDone {
		t.Fatalf("reconcile job = %+v tail=%v", final, final.OutputTail)
	}
	if _, err := os.Stat(filepath.Join(e.toolsDir, "bin", "orphan")); !os.IsNotExist(err) {
		t.Fatal("orphaned binary not swept from bin/")
	}
	if st := e.store.State(); len(st.Tools["orphan"].Bins) > 0 || st.Tools["orphan"].InstalledVersion != "" {
		t.Fatalf("orphaned state row survived the sweep: %+v", st.Tools["orphan"])
	}
}

// depCatalog offers "dep" as a manual catalog entry, so an install plan can
// adopt it offline.
func depCatalog() *Catalog {
	return &Catalog{Entries: map[string]CatalogEntry{
		"dep": {Name: "dep", Source: SourceManual, Version: "1", Install: binStub("dep"), Probe: "dep"},
	}}
}

// editManifest applies a hand edit to tools.json.
func editManifest(t *testing.T, e *Engine, edit func(m *Manifest)) {
	t.Helper()
	if err := e.store.MutateManifest(func(m *Manifest) error { edit(m); return nil }); err != nil {
		t.Fatal(err)
	}
}

// requireInstalled checks that name has an enabled manifest row, a state
// record at version 1 and its binary in bin/.
func requireInstalled(t *testing.T, e *Engine, name string) {
	t.Helper()
	m, err := e.store.LoadManifest()
	if err != nil {
		t.Fatal(err)
	}
	if row, ok := m.Tools[name]; !ok || row.Disabled {
		t.Errorf("%s manifest row = %+v (present %v), want enabled", name, row, ok)
	}
	if got := e.store.State().Tools[name].InstalledVersion; got != "1" {
		t.Errorf("%s installed version = %q, want 1", name, got)
	}
	if _, err := os.Stat(filepath.Join(e.toolsDir, "bin", name)); err != nil {
		t.Errorf("%s binary: %v", name, err)
	}
}

// TestPatch_RequiresOnAnInstalledRowInstallsTheDependency: a requirement
// added to an installed, enabled row is a request for the dependency, so the
// Patch queues the install that adopts or enables it.
func TestPatch_RequiresOnAnInstalledRowInstallsTheDependency(t *testing.T) {
	for _, tc := range []struct {
		seed func(m *Manifest)
		name string
	}{
		{name: "absent dependency"},
		{name: "disabled template", seed: func(m *Manifest) {
			d := manualEntry("dep")
			d.Disabled = true
			m.Tools["dep"] = d
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEngineClient(t, depCatalog(), offlineClient(), nil)
			addManual(t, e, "tool", nil)
			if tc.seed != nil {
				editManifest(t, e, tc.seed)
			}
			req := []string{"dep"}
			jv, err := e.Patch("tool", PatchRequest{Requires: &req})
			if err != nil || jv == nil {
				t.Fatalf("patch requires: job=%v err=%v, want a job", jv, err)
			}
			if final := waitJob(t, e, jv.ID); final.State != JobDone {
				t.Fatalf("patch job = %s (tail %v)", final.State, final.OutputTail)
			}
			requireInstalled(t, e, "dep")
			requireInstalled(t, e, "tool")
		})
	}
}

// TestPatch_SatisfiedRequiresQueuesNothing: naming an enabled dependency, or
// dropping a requirement, asks for nothing the disk lacks.
func TestPatch_SatisfiedRequiresQueuesNothing(t *testing.T) {
	e := newTestEngineClient(t, nil, offlineClient(), nil)
	addManual(t, e, "dep", nil)
	addManual(t, e, "tool", nil)
	for _, req := range [][]string{{"dep"}, {}} {
		jv, err := e.Patch("tool", PatchRequest{Requires: &req})
		if err != nil || jv != nil {
			t.Errorf("patch requires %v: job=%v err=%v, want neither", req, jv, err)
		}
	}
}

// TestPatch_RequiresOnADisabledTemplateQueuesNothing: a disabled template
// has no install obligation, so naming a dependency it lacks adopts nothing
// until the template is enabled.
func TestPatch_RequiresOnADisabledTemplateQueuesNothing(t *testing.T) {
	e := newTestEngineClient(t, depCatalog(), offlineClient(), nil)
	addManual(t, e, "tool", nil)
	editManifest(t, e, func(m *Manifest) {
		tl := m.Tools["tool"]
		tl.Disabled = true
		m.Tools["tool"] = tl
	})
	req := []string{"dep"}
	jv, err := e.Patch("tool", PatchRequest{Requires: &req})
	if err != nil || jv != nil {
		t.Errorf("patch requires: job=%v err=%v, want neither", jv, err)
		if jv != nil {
			waitJob(t, e, jv.ID)
		}
	}
	m, err := e.store.LoadManifest()
	if err != nil {
		t.Fatal(err)
	}
	if row, ok := m.Tools["dep"]; ok {
		t.Errorf("dep manifest row = %+v, want none", row)
	}
	if got := m.Tools["tool"].Requires; !slices.Equal(got, req) {
		t.Errorf("tool requires = %v, want %v", got, req)
	}
}

// TestReconcile_InstallsAnUnsatisfiedDependency: a hand-edited requirement
// with no manifest row is installed by Reconcile, which then converges.
func TestReconcile_InstallsAnUnsatisfiedDependency(t *testing.T) {
	e := newTestEngineClient(t, depCatalog(), offlineClient(), nil)
	addManual(t, e, "tool", nil)
	editManifest(t, e, func(m *Manifest) {
		tl := m.Tools["tool"]
		tl.Requires = []string{"dep"}
		m.Tools["tool"] = tl
	})
	if final := reconcileJob(t, e); final.State != JobDone {
		t.Fatalf("reconcile = %s (tail %v)", final.State, final.OutputTail)
	}
	requireInstalled(t, e, "dep")
	if out := strings.Join(reconcileJob(t, e).OutputTail, "\n"); !strings.Contains(out, "everything converged") {
		t.Errorf("second reconcile output = %q, want everything converged", out)
	}
}

// TestForcedCascade_ReconcileAddsNothingBack: a forced remove or disable of
// base in base <- mid <- top takes top too, so no enabled row needs what went
// and the next Reconcile, which could adopt base and mid from the catalog,
// adds nothing back.
func TestForcedCascade_ReconcileAddsNothingBack(t *testing.T) {
	chain := []string{"base", "mid", "top"}
	on := true
	for _, tc := range []struct {
		cascade func(e *Engine) (*Job, error)
		name    string
	}{
		{name: "remove", cascade: func(e *Engine) (*Job, error) {
			jv, _, err := e.RemoveWithDependents("base")
			return jv, err
		}},
		{name: "disable", cascade: func(e *Engine) (*Job, error) {
			return e.Patch("base", PatchRequest{Disabled: &on, Force: true})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cat := &Catalog{Entries: map[string]CatalogEntry{}}
			for _, n := range chain[:2] {
				cat.Entries[n] = CatalogEntry{Name: n, Source: SourceManual, Version: "1", Install: binStub(n), Probe: n}
			}
			e := newTestEngineClient(t, cat, offlineClient(), nil)
			addManual(t, e, "base", nil)
			addManual(t, e, "mid", []string{"base"})
			addManual(t, e, "top", []string{"mid"})
			// A bystander keeps the manifest non-empty, so Reconcile runs.
			addManual(t, e, "side", nil)
			jv, err := tc.cascade(e)
			if err != nil {
				t.Fatal(err)
			}
			if final := waitJob(t, e, jv.ID); final.State != JobDone || !slices.Equal(final.Names, chain) {
				t.Errorf("cascade job = %s %v, want done over %v", final.State, final.Names, chain)
			}
			final := reconcileJob(t, e)
			if out := strings.Join(final.OutputTail, "\n"); final.State != JobDone || !strings.Contains(out, "everything converged") {
				t.Errorf("reconcile = %s %q, want done and everything converged", final.State, out)
			}
			m, err := e.store.LoadManifest()
			if err != nil {
				t.Fatal(err)
			}
			for _, n := range chain {
				if row, ok := m.Tools[n]; ok && !row.Disabled {
					t.Errorf("%s is enabled after the cascade and a Reconcile", n)
				}
				if _, err := os.Stat(filepath.Join(e.toolsDir, "bin", n)); !os.IsNotExist(err) {
					t.Errorf("%s binary is installed after the cascade and a Reconcile", n)
				}
			}
		})
	}
}

// TestForcedCascade_CrossesADisabledOrCatalogOnlyRow: in base <- mid <- top
// with mid disabled (hydrated or still source-less), or absent with a catalog
// entry, Reconcile's install plan enables or adopts mid for the enabled top
// and then restores base. So the refusal and the inventory name top, a forced
// remove or disable takes it, and the next Reconcile adds nothing back.
func TestForcedCascade_CrossesADisabledOrCatalogOnlyRow(t *testing.T) {
	on := true
	for _, mid := range []struct {
		row  func() (Tool, bool)
		name string
	}{
		{name: "disabled mid", row: func() (Tool, bool) {
			tl := manualEntry("mid")
			tl.Requires = []string{"base"}
			tl.Disabled = true
			return tl, true
		}},
		{name: "source-less disabled mid", row: func() (Tool, bool) { return Tool{Disabled: true}, true }},
		{name: "catalog-only mid", row: func() (Tool, bool) { return Tool{}, false }},
	} {
		for _, tc := range []struct {
			cascade func(e *Engine) (*Job, error)
			name    string
		}{
			{name: "remove", cascade: func(e *Engine) (*Job, error) {
				jv, _, err := e.RemoveWithDependents("base")
				return jv, err
			}},
			{name: "disable", cascade: func(e *Engine) (*Job, error) {
				return e.Patch("base", PatchRequest{Disabled: &on, Force: true})
			}},
		} {
			t.Run(mid.name+" "+tc.name, func(t *testing.T) {
				cat := &Catalog{Entries: map[string]CatalogEntry{
					"base": {Name: "base", Source: SourceManual, Version: "1", Install: binStub("base"), Probe: "base"},
					"mid":  {Name: "mid", Source: SourceManual, Version: "1", Install: binStub("mid"), Probe: "mid", Requires: []string{"base"}},
				}}
				e := newTestEngineClient(t, cat, offlineClient(), nil)
				addManual(t, e, "base", nil)
				addManual(t, e, "top", nil)
				// A bystander keeps the manifest non-empty, so Reconcile runs.
				addManual(t, e, "side", nil)
				// After the installs, which hydrate a source-less row.
				editManifest(t, e, func(m *Manifest) {
					top := m.Tools["top"]
					top.Requires = []string{"mid"}
					m.Tools["top"] = top
					if row, ok := mid.row(); ok {
						m.Tools["mid"] = row
					}
				})
				want := []string{"top"}
				if row := inventoryRow(t, e, "base"); !slices.Equal(row.Dependents, want) {
					t.Errorf("inventory dependents of base = %v, want %v", row.Dependents, want)
				}
				if _, deps, err := e.Remove("base"); err == nil {
					t.Fatalf("Remove(base) succeeded (dependents %v), want DependentsError naming %v", deps, want)
				} else if de, ok := errors.AsType[*DependentsError](err); !ok || !slices.Equal(de.Dependents, want) {
					t.Errorf("Remove(base) = %v, want DependentsError naming %v", err, want)
				}
				jv, err := tc.cascade(e)
				if err != nil {
					t.Fatal(err)
				}
				if final := waitJob(t, e, jv.ID); final.State != JobDone || !slices.Equal(final.Names, []string{"base", "top"}) {
					t.Errorf("cascade job = %s %v, want done over [base top]", final.State, final.Names)
				}
				final := reconcileJob(t, e)
				if out := strings.Join(final.OutputTail, "\n"); final.State != JobDone || !strings.Contains(out, "everything converged") {
					t.Errorf("reconcile = %s %q, want done and everything converged", final.State, out)
				}
				m, err := e.store.LoadManifest()
				if err != nil {
					t.Fatal(err)
				}
				for _, n := range []string{"base", "mid", "top"} {
					if row, ok := m.Tools[n]; ok && !row.Disabled {
						t.Errorf("%s is enabled after the cascade and a Reconcile", n)
					}
					if _, err := os.Stat(filepath.Join(e.toolsDir, "bin", n)); !os.IsNotExist(err) {
						t.Errorf("%s binary is installed after the cascade and a Reconcile", n)
					}
				}
			})
		}
	}
}

// TestReconcile_DisabledOwnedDependencyIsEnabledNotUninstalled: a disabled
// row an enabled row needs, directly or through another disabled row, is
// enabled by the install plan, so Reconcile does not uninstall it first.
func TestReconcile_DisabledOwnedDependencyIsEnabledNotUninstalled(t *testing.T) {
	for _, tc := range []struct {
		name     string
		disabled []string
	}{
		{name: "direct", disabled: []string{"dep"}},
		{name: "through a disabled dependency", disabled: []string{"dep", "mid"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEngineClient(t, nil, offlineClient(), nil)
			addManual(t, e, "dep", nil)
			addManual(t, e, "mid", []string{"dep"})
			addManual(t, e, "tool", []string{"mid"})
			editManifest(t, e, func(m *Manifest) {
				for _, n := range tc.disabled {
					tl := m.Tools[n]
					tl.Disabled = true
					m.Tools[n] = tl
				}
			})
			final := reconcileJob(t, e)
			out := strings.Join(final.OutputTail, "\n")
			if final.State != JobDone || strings.Contains(out, "uninstalling disabled tools") {
				t.Errorf("reconcile = %s %q, want done with no uninstall", final.State, out)
			}
			for _, n := range tc.disabled {
				requireInstalled(t, e, n)
			}
		})
	}
}

// TestReconcile_KeepsWhatAnAdoptedDependencyNeeds: a dependency the install
// plan adopts from the catalog brings its own edges, so a disabled, owned row
// one of them names is enabled by that plan rather than uninstalled first.
func TestReconcile_KeepsWhatAnAdoptedDependencyNeeds(t *testing.T) {
	for _, tc := range []struct {
		entry CatalogEntry
		name  string
	}{
		{name: "requires", entry: CatalogEntry{
			Name: "lsp", Source: SourceManual, Version: "1", Install: binStub("lsp"), Probe: "lsp", Requires: []string{"node"},
		}},
		{name: "source backend", entry: CatalogEntry{Name: "lsp", Source: "npm:lsp", Version: "1.0.0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := t.TempDir()
			npm := "#!/bin/sh\nd=\"$NPM_CONFIG_PREFIX/lib/node_modules/lsp\"\n" +
				"mkdir -p \"$d\" && printf '{\"name\":\"lsp\",\"version\":\"1.0.0\"}' > \"$d/package.json\"\n"
			if err := os.WriteFile(filepath.Join(fake, "npm"), []byte(npm), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", fake+string(os.PathListSeparator)+os.Getenv("PATH"))
			cat := &Catalog{
				Entries:  map[string]CatalogEntry{"lsp": tc.entry},
				Backends: map[string]string{SourceNpm: "node"},
			}
			e := newTestEngineClient(t, cat, offlineClient(), nil)
			addManual(t, e, "node", nil)
			addManual(t, e, "tool", nil)
			editManifest(t, e, func(m *Manifest) {
				n := m.Tools["node"]
				n.Disabled = true
				m.Tools["node"] = n
				tl := m.Tools["tool"]
				tl.Requires = []string{"lsp"}
				m.Tools["tool"] = tl
			})
			final := reconcileJob(t, e)
			out := strings.Join(final.OutputTail, "\n")
			if final.State != JobDone || strings.Contains(out, "uninstalling disabled tools") {
				t.Errorf("reconcile = %s %q, want done with no uninstall", final.State, out)
			}
			requireInstalled(t, e, "node")
			if got := e.store.State().Tools["lsp"].InstalledVersion; got != tc.entry.Version {
				t.Errorf("lsp installed version = %q, want %s", got, tc.entry.Version)
			}
		})
	}
}

// TestReconcile_KeepsTheOrphanedStateOfANeededDependency: an owned state row
// with no manifest row, for a dependency the install plan is about to adopt,
// is the adopted row's install, so Reconcile does not sweep it first.
func TestReconcile_KeepsTheOrphanedStateOfANeededDependency(t *testing.T) {
	e := newTestEngineClient(t, depCatalog(), offlineClient(), nil)
	addManual(t, e, "tool", nil)
	addManual(t, e, "dep", nil)
	editManifest(t, e, func(m *Manifest) {
		delete(m.Tools, "dep")
		tl := m.Tools["tool"]
		tl.Requires = []string{"dep"}
		m.Tools["tool"] = tl
	})
	final := reconcileJob(t, e)
	out := strings.Join(final.OutputTail, "\n")
	if final.State != JobDone || strings.Contains(out, "sweeping orphaned install state") {
		t.Errorf("reconcile = %s %q, want done with no sweep", final.State, out)
	}
	requireInstalled(t, e, "dep")
}

// TestReconcile_UnresolvableDependencyFailsTheDependent: a requirement no
// catalog entry resolves fails the job naming it, and leaves the installed
// dependent in place.
func TestReconcile_UnresolvableDependencyFailsTheDependent(t *testing.T) {
	e := newTestEngineClient(t, nil, offlineClient(), nil)
	addManual(t, e, "tool", nil)
	editManifest(t, e, func(m *Manifest) {
		tl := m.Tools["tool"]
		tl.Requires = []string{"ghost"}
		m.Tools["tool"] = tl
	})
	final := reconcileJob(t, e)
	if final.State != JobFailed || !strings.Contains(final.Error, `dependency "ghost" failed`) {
		t.Errorf("reconcile = %s %q, want failed naming dependency ghost", final.State, final.Error)
	}
	requireInstalled(t, e, "tool")
	if got := e.store.State().Tools["tool"].LastError; !strings.Contains(got, `dependency "ghost" failed`) {
		t.Errorf("tool last error = %q, want the dependency failure", got)
	}
}

// TestEnsureInstalled_InstallsTheMissingDependencyOfAnInstalledTool: an
// installed tool whose dependency is a disabled template is not ready, so
// EnsureInstalled enables and installs the dependency.
func TestEnsureInstalled_InstallsTheMissingDependencyOfAnInstalledTool(t *testing.T) {
	e := newTestEngineClient(t, nil, offlineClient(), nil)
	addManual(t, e, "tool", nil)
	editManifest(t, e, func(m *Manifest) {
		tl := m.Tools["tool"]
		tl.Requires = []string{"dep"}
		m.Tools["tool"] = tl
		d := manualEntry("dep")
		d.Disabled = true
		m.Tools["dep"] = d
	})
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	if err := e.EnsureInstalled(ctx, "tool"); err != nil {
		t.Fatalf("EnsureInstalled: %v", err)
	}
	requireInstalled(t, e, "dep")
}

// TestEnsureInstalled_ReinstallsAnEnabledDependencyWhoseBinaryIsGone: an
// installed tool is not ready while an enabled dependency, named in requires
// or implied by its source's backend, has lost its binary, so EnsureInstalled
// reinstalls the dependency as Reconcile would.
func TestEnsureInstalled_ReinstallsAnEnabledDependencyWhoseBinaryIsGone(t *testing.T) {
	const pkg = "pkg"
	for _, tc := range []struct {
		seed func(t *testing.T, e *Engine)
		name string
		dep  string
	}{
		{name: "requires", dep: "dep", seed: func(t *testing.T, e *Engine) {
			addManual(t, e, "dep", nil)
			addManual(t, e, pkg, []string{"dep"})
		}},
		{name: "source backend", dep: "node", seed: func(t *testing.T, e *Engine) {
			addManual(t, e, "node", nil)
			editManifest(t, e, func(m *Manifest) { m.Tools[pkg] = Tool{Source: "npm:" + pkg, Version: "1.0.0"} })
			if err := e.store.setToolStatus(pkg, func(s *ToolStatus) { s.InstalledVersion = "1.0.0" }); err != nil {
				t.Fatal(err)
			}
			writeNpmPackage(t, e, pkg, `{"name":"pkg","version":"1.0.0"}`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// npm fails if anything reruns it: the npm row itself is installed.
			fake := t.TempDir()
			if err := os.WriteFile(filepath.Join(fake, "npm"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", fake+string(os.PathListSeparator)+os.Getenv("PATH"))
			cat := &Catalog{Entries: map[string]CatalogEntry{}, Backends: map[string]string{SourceNpm: "node"}}
			e := newTestEngineClient(t, cat, offlineClient(), nil)
			tc.seed(t, e)
			if err := os.Remove(filepath.Join(e.toolsDir, "bin", tc.dep)); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			if err := e.EnsureInstalled(ctx, pkg); err != nil {
				t.Fatalf("EnsureInstalled: %v", err)
			}
			requireInstalled(t, e, tc.dep)
		})
	}
}

// TestEnsureInstalled_ReadsASourceLessRowAsHydrated: a runnable source-less
// row is ready only as Reconcile would leave it after hydration, so
// EnsureInstalled installs what the catalog entry's requires, its source's
// backend or its default version call for before returning.
func TestEnsureInstalled_ReadsASourceLessRowAsHydrated(t *testing.T) {
	const tool = "tool"
	for _, tc := range []struct {
		entries  map[string]CatalogEntry
		seed     func(t *testing.T, e *Engine)
		name     string
		want     string
		recorded string
	}{
		{name: "catalog requires", want: "dep", entries: map[string]CatalogEntry{
			tool:  {Name: tool, Source: SourceManual, Version: "1", Install: binStub(tool), Probe: tool, Requires: []string{"dep"}},
			"dep": depCatalog().Entries["dep"],
		}},
		{name: "source backend", want: "node", recorded: "1.0.0", entries: map[string]CatalogEntry{
			tool:   {Name: tool, Source: "npm:" + tool, Version: "1.0.0"},
			"node": {Name: "node", Source: SourceManual, Version: "1", Install: binStub("node"), Probe: "node"},
		}, seed: func(t *testing.T, e *Engine) {
			writeNpmPackage(t, e, tool, `{"name":"tool","version":"1.0.0"}`)
		}},
		{name: "catalog version", want: tool, recorded: "0.9", entries: map[string]CatalogEntry{
			tool: {Name: tool, Source: SourceManual, Version: "1", Install: binStub(tool), Probe: tool},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// npm fails if anything runs it. In the source-backend case the
			// npm row is already installed; the other cases use no npm.
			fake := t.TempDir()
			if err := os.WriteFile(filepath.Join(fake, "npm"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", fake+string(os.PathListSeparator)+os.Getenv("PATH"))
			cat := &Catalog{Entries: tc.entries, Backends: map[string]string{SourceNpm: "node"}}
			e := newTestEngineClient(t, cat, offlineClient(), nil)
			if err := os.WriteFile(filepath.Join(e.toolsDir, "bin", tool), []byte("#!/bin/sh\necho old\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			editManifest(t, e, func(m *Manifest) { m.Tools[tool] = Tool{} })
			if tc.recorded != "" {
				if err := e.store.setToolStatus(tool, func(s *ToolStatus) { s.InstalledVersion = tc.recorded }); err != nil {
					t.Fatal(err)
				}
			}
			if tc.seed != nil {
				tc.seed(t, e)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			if err := e.EnsureInstalled(ctx, tool); err != nil {
				t.Fatalf("EnsureInstalled: %v", err)
			}
			requireInstalled(t, e, tc.want)
		})
	}
}

// TestEnsureInstalled_ConvergedToolLeavesTheManifestFile: a ready tool needs
// no manifest write, so EnsureInstalled does not replace tools.json.
func TestEnsureInstalled_ConvergedToolLeavesTheManifestFile(t *testing.T) {
	e := newTestEngineClient(t, depCatalog(), offlineClient(), nil)
	addManual(t, e, "tool", nil)
	before, err := os.Stat(e.store.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.EnsureInstalled(t.Context(), "tool"); err != nil {
		t.Fatalf("EnsureInstalled: %v", err)
	}
	after, err := os.Stat(e.store.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Error("tools.json was replaced, want the converged call to write nothing")
	}
}

// reconcileJob runs one ReconcileMissing job to its end.
func reconcileJob(t *testing.T, e *Engine) *Job {
	t.Helper()
	jv, enqueued, err := e.Reconcile(ReconcileMissing)
	if err != nil || !enqueued {
		t.Fatalf("reconcile: job=%v enqueued=%v err=%v", jv, enqueued, err)
	}
	return waitJob(t, e, jv.ID)
}
