package toolbelt

import (
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
)

// adoptableCatalog knows each name as an offline, installable manual tool,
// so planning can adopt it without touching the network.
func adoptableCatalog(names ...string) *Catalog {
	cat := &Catalog{Entries: map[string]CatalogEntry{}}
	for _, n := range names {
		cat.Entries[n] = CatalogEntry{
			Name: n, Source: SourceManual, Version: "1",
			Install: binStub(n), Probe: n,
		}
	}
	return cat
}

func seedManifest(t *testing.T, e *Engine, tools map[string]Tool) {
	t.Helper()
	err := e.store.MutateManifest(func(m *Manifest) error {
		maps.Copy(m.Tools, tools)
		return nil
	})
	if err != nil {
		t.Fatalf("Setup: seed manifest: %v", err)
	}
}

func requiring(name string, deps ...string) Tool {
	t := manualEntry(name)
	t.Requires = deps
	return t
}

func disabledEntry(name string) Tool {
	t := manualEntry(name)
	t.Disabled = true
	return t
}

func runInstallJob(t *testing.T, e *Engine, names ...string) *Job {
	t.Helper()
	job, err := e.queue.Enqueue(JobKindInstall, names)
	if err != nil {
		t.Fatalf("Setup: enqueue install %v: %v", names, err)
	}
	return waitJob(t, e, job.ID)
}

func loadManifest(t *testing.T, e *Engine) *Manifest {
	t.Helper()
	m, err := e.store.LoadManifest()
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	return m
}

func outputMentions(j *Job, s string) bool {
	return slices.ContainsFunc(j.OutputTail, func(line string) bool { return strings.Contains(line, s) })
}

func TestInstall_FailedRootLeavesNoAdoptedSibling(t *testing.T) {
	e := newTestEngine(t, adoptableCatalog("d"))
	seedManifest(t, e, map[string]Tool{"r": requiring("r", "d", "e")})

	final := runInstallJob(t, e, "r")

	if final.State != JobFailed {
		t.Errorf("install [r] job state = %s, want failed", final.State)
	}
	if d, ok := loadManifest(t, e).Tools["d"]; ok {
		t.Errorf("install [r] with unresolvable e left d in tools.json as %+v, want no row", d)
	}
	if got := inventoryByName(t, e)["r"].LastError; !strings.Contains(got, `dependency "e" failed`) {
		t.Errorf("install [r]: r last_error = %q, want it to say dependency \"e\" failed", got)
	}
}

func TestInstall_FailedRootLeavesSiblingTemplateDisabled(t *testing.T) {
	e := newTestEngine(t, nil)
	seedManifest(t, e, map[string]Tool{
		"d": disabledEntry("d"),
		"r": requiring("r", "d", "e"),
	})

	final := runInstallJob(t, e, "r")

	if final.State != JobFailed {
		t.Errorf("install [r] job state = %s, want failed", final.State)
	}
	if !loadManifest(t, e).Tools["d"].Disabled {
		t.Error("install [r] with unresolvable e enabled template d, want it still disabled")
	}
	if outputMentions(final, "enabling d") {
		t.Errorf("install [r] job log = %q, want no enable reported for d", final.OutputTail)
	}
}

func TestInstall_FailedRootLeavesTemplateOnItsPathDisabled(t *testing.T) {
	e := unresolvableNodeEngine(t)
	pyright := loadManifest(t, e).Tools["pyright"]
	pyright.Disabled = true
	seedManifest(t, e, map[string]Tool{
		"pyright": pyright,
		"tsls":    requiring("tsls", "pyright"),
	})

	final := runInstallJob(t, e, "tsls")

	if final.State != JobFailed {
		t.Errorf("install [tsls] job state = %s, want failed", final.State)
	}
	if !loadManifest(t, e).Tools["pyright"].Disabled {
		t.Error("install [tsls] with unresolvable node enabled template pyright, want it still disabled")
	}
	byName := inventoryByName(t, e)
	if got := byName["tsls"].LastError; !strings.Contains(got, `dependency "node" failed`) {
		t.Errorf("install [tsls]: tsls last_error = %q, want it to say dependency \"node\" failed", got)
	}
	if got := byName["pyright"].LastError; got != "" {
		t.Errorf("install [tsls]: pyright last_error = %q, want none on a template the failed plan left disabled", got)
	}
}

// A dependency two roots share must not ride the failed root's plan into
// the next root's: the next root has to adopt it for itself, or it installs
// a tool tools.json has no row for.
func TestInstall_FailedRootDoesNotStrandSharedNewDependency(t *testing.T) {
	for name, order := range map[string][]string{
		"failingRootFirst": {"a", "b"},
		"failingRootLast":  {"b", "a"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newTestEngine(t, adoptableCatalog("d"))
			seedManifest(t, e, map[string]Tool{
				"a": requiring("a", "d", "x"),
				"b": requiring("b", "d"),
			})

			final := runInstallJob(t, e, order...)

			if final.State != JobFailed {
				t.Errorf("install %v job state = %s, want failed", order, final.State)
			}
			m := loadManifest(t, e)
			if _, ok := m.Tools["d"]; !ok {
				t.Errorf("install %v: d has no tools.json row, want b's plan to have adopted it", order)
			}
			byName := inventoryByName(t, e)
			for _, n := range []string{"d", "b"} {
				if !byName[n].Installed {
					t.Errorf("install %v: %s installed = false (last_error %q), want true", order, n, byName[n].LastError)
				}
			}
			if got := byName["a"].LastError; !strings.Contains(got, `dependency "x" failed`) {
				t.Errorf("install %v: a last_error = %q, want it to say dependency \"x\" failed", order, got)
			}
			for n, st := range e.store.State().Tools {
				if _, ok := m.Tools[n]; st.InstalledVersion != "" && !ok {
					t.Errorf("install %v: %s installed at %q with no tools.json row", order, n, st.InstalledVersion)
				}
			}
		})
	}
}

func TestInstall_FailedRootLeavesPreexistingDependencyUntouched(t *testing.T) {
	e := newTestEngine(t, nil)
	seedManifest(t, e, map[string]Tool{
		"d":    manualEntry("d"),
		"user": requiring("user", "d"),
	})
	if final := runInstallJob(t, e, "user"); final.State != JobDone {
		t.Fatalf("Setup: install [user] = %+v tail=%v", final, final.OutputTail)
	}
	before, err := json.Marshal(loadManifest(t, e).Tools["d"])
	if err != nil {
		t.Fatalf("Setup: marshal d: %v", err)
	}
	beforeState := e.store.State().Tools["d"]
	seedManifest(t, e, map[string]Tool{"r": requiring("r", "d", "e")})

	if final := runInstallJob(t, e, "r"); final.State != JobFailed {
		t.Errorf("install [r] job state = %s, want failed", final.State)
	}

	after, err := json.Marshal(loadManifest(t, e).Tools["d"])
	if err != nil {
		t.Fatalf("marshal d: %v", err)
	}
	if string(after) != string(before) {
		t.Errorf("install [r] changed d's tools.json row to %s, want %s", after, before)
	}
	st := e.store.State().Tools["d"]
	if st.LastError != "" {
		t.Errorf("install [r] wrote last_error %q onto d, want none: d is not on the failed path", st.LastError)
	}
	if st.InstalledVersion != beforeState.InstalledVersion {
		t.Errorf("install [r] moved d's installed version to %q, want %q", st.InstalledVersion, beforeState.InstalledVersion)
	}
}

// The installOrder tests below change tools.json after the plan's
// manifest is loaded, which is the window a hand edit lands in and one no
// job-level test can time.
func TestInstallOrder_ExistingRowWinsOverStagedAdoption(t *testing.T) {
	cat := adoptableCatalog("d")
	entry := cat.Entries["d"]
	entry.Version = "2"
	cat.Entries["d"] = entry
	e := newTestEngine(t, cat)
	seedManifest(t, e, map[string]Tool{"r": requiring("r", "d")})
	m := loadManifest(t, e)
	seedManifest(t, e, map[string]Tool{"d": manualEntry("d")})

	p := e.installOrder(t.Context(), m, []string{"r"})

	if len(p.unplanned) != 0 {
		t.Fatalf("installOrder([r]) unplanned = %+v, want none", p.unplanned)
	}
	if got := loadManifest(t, e).Tools["d"].Version; got != "1" {
		t.Errorf("installOrder([r]) wrote d at version %q to tools.json, want the existing row's %q", got, "1")
	}
	if got := m.Tools["d"].Version; got != "1" {
		t.Errorf("installOrder([r]) left the plan seeing d at version %q, want tools.json's %q", got, "1")
	}
}

func TestInstallOrder_VanishedTemplateFailsTheWholeRoot(t *testing.T) {
	e := newTestEngine(t, adoptableCatalog("d"))
	seedManifest(t, e, map[string]Tool{
		"gone": disabledEntry("gone"),
		"r":    requiring("r", "d", "gone"),
	})
	m := loadManifest(t, e)
	if err := e.store.MutateManifest(func(mm *Manifest) error {
		delete(mm.Tools, "gone")
		return nil
	}); err != nil {
		t.Fatalf("Setup: remove gone: %v", err)
	}

	p := e.installOrder(t.Context(), m, []string{"r"})

	if len(p.unplanned) != 1 || !errors.Is(p.unplanned[0].err, ErrNotFound) {
		t.Fatalf("installOrder([r]) unplanned = %+v, want r alone failing with ErrNotFound", p.unplanned)
	}
	_, _ = e.recordUnplanned(m, p.unplanned, func(string) {})
	if _, ok := loadManifest(t, e).Tools["d"]; ok {
		t.Error("installOrder([r]) that failed on a vanished template still wrote adoption d to tools.json")
	}
	if _, ok := m.Tools["d"]; ok || len(p.enabled) != 0 || len(p.ordered) != 0 {
		t.Errorf("installOrder([r]) that failed left d in the plan manifest (%v), enabled %v, ordered %v; want none",
			ok, p.enabled, p.ordered)
	}
	if got, want := inventoryByName(t, e)["r"].LastError, `dependency "gone" failed: tool not found`; got != want {
		t.Errorf("installOrder([r]) on a vanished template: r last_error = %q, want %q", got, want)
	}
}

func TestInstallOrder_VanishedTemplateFailsEveryCommittedRowOnItsPath(t *testing.T) {
	e := newTestEngine(t, adoptableCatalog("d"))
	seedManifest(t, e, map[string]Tool{
		"gone": disabledEntry("gone"),
		"mid":  requiring("mid", "d", "gone"),
		"r":    requiring("r", "mid"),
	})
	m := loadManifest(t, e)
	if err := e.store.MutateManifest(func(mm *Manifest) error {
		delete(mm.Tools, "gone")
		return nil
	}); err != nil {
		t.Fatalf("Setup: remove gone: %v", err)
	}

	p := e.installOrder(t.Context(), m, []string{"r"})
	_, _ = e.recordUnplanned(m, p.unplanned, func(string) {})

	byName := inventoryByName(t, e)
	want := `dependency "gone" failed: tool not found`
	for _, n := range []string{"r", "mid"} {
		if got := byName[n].LastError; got != want {
			t.Errorf("installOrder([r]) on a vanished template under mid: %s last_error = %q, want %q", n, got, want)
		}
	}
	for _, n := range []string{"d", "gone"} {
		if st, ok := e.store.State().Tools[n]; ok {
			t.Errorf("installOrder([r]) on a vanished template under mid: wrote status %+v for %s, want none: it has no tools.json row", st, n)
		}
	}
}

func TestInstallOrder_VanishedTemplateLeavesNoStatusOnAncestorDeletedWithIt(t *testing.T) {
	e := newTestEngine(t, adoptableCatalog("d"))
	seedManifest(t, e, map[string]Tool{
		"gone": disabledEntry("gone"),
		"mid":  requiring("mid", "d", "gone"),
		"r":    requiring("r", "mid"),
	})
	m := loadManifest(t, e)
	if err := e.store.MutateManifest(func(mm *Manifest) error {
		delete(mm.Tools, "gone")
		delete(mm.Tools, "mid")
		return nil
	}); err != nil {
		t.Fatalf("Setup: remove gone and mid: %v", err)
	}

	p := e.installOrder(t.Context(), m, []string{"r"})
	_, _ = e.recordUnplanned(m, p.unplanned, func(string) {})

	if got, want := inventoryByName(t, e)["r"].LastError, `dependency "gone" failed: tool not found`; got != want {
		t.Errorf("installOrder([r]) after one edit removed mid and gone: r last_error = %q, want %q", got, want)
	}
	for _, n := range []string{"mid", "gone", "d"} {
		if st, ok := e.store.State().Tools[n]; ok {
			t.Errorf("installOrder([r]) after one edit removed mid and gone: wrote status %+v for %s, want none: it has no tools.json row", st, n)
		}
	}
}

func TestInstallOrder_VanishedTemplateLeavesNoStatusOnTemplateOnItsPath(t *testing.T) {
	e := newTestEngine(t, nil)
	tmpl := requiring("tmpl", "gone")
	tmpl.Disabled = true
	seedManifest(t, e, map[string]Tool{
		"gone": disabledEntry("gone"),
		"tmpl": tmpl,
		"r":    requiring("r", "tmpl"),
	})
	m := loadManifest(t, e)
	if err := e.store.MutateManifest(func(mm *Manifest) error {
		delete(mm.Tools, "gone")
		return nil
	}); err != nil {
		t.Fatalf("Setup: remove gone: %v", err)
	}

	p := e.installOrder(t.Context(), m, []string{"r"})
	_, _ = e.recordUnplanned(m, p.unplanned, func(string) {})

	if got, want := inventoryByName(t, e)["r"].LastError, `dependency "gone" failed: tool not found`; got != want {
		t.Errorf("installOrder([r]) on a vanished template under tmpl: r last_error = %q, want %q", got, want)
	}
	if !loadManifest(t, e).Tools["tmpl"].Disabled {
		t.Error("installOrder([r]) on a vanished template under tmpl enabled tmpl, want it still disabled")
	}
	if got := inventoryByName(t, e)["tmpl"].LastError; got != "" {
		t.Errorf("installOrder([r]) on a vanished template under tmpl: tmpl last_error = %q, want none on a template the failed plan left disabled", got)
	}
}

func TestInstall_PlannedRootPersistsItsStagedDependencies(t *testing.T) {
	e := newTestEngine(t, adoptableCatalog("d"))
	seedManifest(t, e, map[string]Tool{
		"tmpl": disabledEntry("tmpl"),
		"r":    requiring("r", "d", "tmpl"),
	})

	final := runInstallJob(t, e, "r")

	if final.State != JobDone {
		t.Fatalf("install [r] = %+v tail=%v, want done", final, final.OutputTail)
	}
	m := loadManifest(t, e)
	if _, ok := m.Tools["d"]; !ok {
		t.Error("install [r]: d has no tools.json row, want it adopted")
	}
	if m.Tools["tmpl"].Disabled {
		t.Error("install [r]: tmpl still disabled, want it enabled as r's dependency")
	}
	if !outputMentions(final, "enabling tmpl, required by r") {
		t.Errorf("install [r] job log = %q, want it to report tmpl enabled for r", final.OutputTail)
	}
	byName := inventoryByName(t, e)
	for _, n := range []string{"d", "tmpl", "r"} {
		if !byName[n].Installed {
			t.Errorf("install [r]: %s installed = false (last_error %q), want true", n, byName[n].LastError)
		}
	}
}
