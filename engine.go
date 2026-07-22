package toolbelt

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// Sentinel errors. Compare with errors.Is; *DependentsError additionally
// carries the dependent names (errors.As).
var (
	// ErrNotFound marks an operation on a tool the manifest doesn't have.
	ErrNotFound = errors.New("tool not found")
	// ErrHasDependents marks a refused remove/disable: enabled entries
	// still require the tool (directly or as an implied backend).
	ErrHasDependents = errors.New("tool has dependents")
	// ErrDisabled marks an install attempt on a disabled template.
	// Enabling is an explicit state change (Patch Disabled=false), never
	// a side effect of a retry.
	ErrDisabled = errors.New("tool is disabled")
	// ErrUnknownJob marks a Wait on a job id the queue no longer knows:
	// never enqueued, or its terminal view was evicted by the history
	// cap. Without it a Wait on an evicted id would poll to ctx
	// deadline.
	ErrUnknownJob = errors.New("unknown job")
)

// DependentsError is the ErrHasDependents shape that names the enabled
// entries blocking a remove/disable.
type DependentsError struct {
	Dependents []string
}

func (e *DependentsError) Error() string {
	return fmt.Sprintf("tool has dependents: %s", strings.Join(e.Dependents, ", "))
}

// Is makes errors.Is(err, ErrHasDependents) match.
func (e *DependentsError) Is(target error) bool { return target == ErrHasDependents }

// backendDeps maps a source kind to the tool that must be installed
// first for the backend to function at all.
var backendDeps = map[string]string{
	SourceNpm:   "node",
	SourcePip:   "uv",
	SourceCargo: "rust",
	SourceGo:    "go",
}

// --- read side ---

// Inventory assembles the full read-side snapshot: every manifest entry
// joined with install state, the system group, and the active job.
func (e *Engine) Inventory() (*Inventory, error) {
	m, err := e.store.Manifest()
	if err != nil {
		return nil, err
	}
	st := e.store.State()
	installing := e.queue.InstallingSet()

	res := &Inventory{Tools: []ToolInfo{}, System: e.systemTools(), Job: e.queue.Active()}
	names := make([]string, 0, len(m.Tools))
	for n := range m.Tools {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		t := m.Tools[n]
		s := st.Tools[n]
		res.Tools = append(res.Tools, e.toolInfo(n, &t, &s, installing[n]))
	}
	return res, nil
}

// toolInfo builds one inventory row.
func (e *Engine) toolInfo(name string, t *Tool, s *ToolStatus, installing bool) ToolInfo {
	v := ToolInfo{
		Name:             name,
		Source:           t.Source,
		Version:          t.Version,
		Pin:              t.Pin,
		Disabled:         t.Disabled,
		Requires:         t.Requires,
		Description:      t.Description,
		Origin:           t.Origin,
		Installed:        e.installedFor(name, t, s),
		InstalledVersion: s.InstalledVersion,
		Installing:       installing,
		LastError:        s.LastError,
	}
	if cat, ok := e.cat().Lookup(name); ok {
		v.Lsp = cat.Lsp
	}
	if latest := e.versions.Cached(t.Source); latest != "" && latest != t.Version {
		v.Latest = latest
	}
	return v
}

// installedFor is the row-level installed flag. Enabled entries use the
// probe (recorded bins, falling back to the derived probe name so
// pre-seeded volumes read as installed); disabled templates count as
// installed only while the engine still owns a footprint (an unmanaged
// same-name binary must not make a template look installed).
func (e *Engine) installedFor(name string, t *Tool, s *ToolStatus) bool {
	if t.Disabled {
		return s.owned()
	}
	return e.probeInstalled(name, t, s)
}

// probeInstalled checks the tool's bin presence: every recorded bin
// (or the derived probe name before first status write) resolves in
// the bin dir.
func (e *Engine) probeInstalled(name string, t *Tool, s *ToolStatus) bool {
	bins := append(append([]string{}, s.Bins...), s.PMBins...)
	if len(bins) == 0 {
		// No recorded bins (never installed by this engine): fall back
		// to the derived probe name so pre-seeded volumes still read
		// as installed when the binary exists.
		probe := t.Probe
		if probe == "" {
			probe = pkgBinName(strings.TrimPrefix(name, "@"))
		}
		bins = []string{probe}
	}
	for _, b := range bins {
		if _, err := os.Stat(filepath.Join(e.toolsDir, "bin", b)); err != nil {
			return false
		}
	}
	return true
}

func (e *Engine) systemTools() []SystemTool {
	out := make([]SystemTool, 0, len(e.system))
	for _, b := range e.system {
		_, err := exec.LookPath(b)
		out = append(out, SystemTool{Name: b, Installed: err == nil})
	}
	return out
}

// Search queries the catalog (empty query = featured set), hiding
// entries already in the manifest.
func (e *Engine) Search(query string) []CatalogEntry {
	hits := e.cat().Search(query)
	m, err := e.store.Manifest()
	if err != nil {
		e.log.Warn("toolbelt: search: manifest unreadable, results unfiltered", "error", err)
		return hits
	}
	out := hits[:0]
	for i := range hits {
		if _, exists := m.Tools[hits[i].Name]; !exists {
			out = append(out, hits[i])
		}
	}
	return out
}

// Jobs returns the active job (with output tail) and recent history.
func (e *Engine) Jobs() (active *Job, recent []*Job) { return e.queue.Snapshot() }

// CancelJob aborts a queued or running job.
func (e *Engine) CancelJob(id string) bool { return e.queue.Cancel(id) }

// Wait blocks until the job reaches a terminal state and returns its
// final view.
func (e *Engine) Wait(ctx context.Context, jobID string) (*Job, error) {
	return e.queue.Wait(ctx, jobID)
}

// --- write side ---

// AddRequest is the Add call's body: intent for a new tool. Every field
// except Name is optional when the catalog knows the name.
type AddRequest struct {
	Name        string   `json:"name"`
	Source      string   `json:"source,omitempty"`  // optional when the catalog knows the name
	Version     string   `json:"version,omitempty"` // optional: resolve latest
	Description string   `json:"description,omitempty"`
	Origin      string   `json:"origin,omitempty"`
	Install     string   `json:"install,omitempty"`
	Uninstall   string   `json:"uninstall,omitempty"`
	Probe       string   `json:"probe,omitempty"`
	Requires    []string `json:"requires,omitempty"`
	Pin         bool     `json:"pin,omitempty"`
	// Disabled adds the entry as a template: recorded, not installed,
	// no job enqueued (Add then returns a nil Job).
	Disabled bool `json:"disabled,omitempty"`
}

// Add records a new tool in the manifest and, unless the request marks
// it disabled, enqueues its install. Present-and-enabled is the default
// intent: adding means "have this installed".
func (e *Engine) Add(ctx context.Context, req *AddRequest) (*Job, error) {
	name := strings.TrimSpace(req.Name)
	if !validToolName(name) {
		return nil, errors.New("invalid tool name")
	}
	t, err := e.resolveNewTool(ctx, name, req)
	if err != nil {
		return nil, err
	}
	err = e.store.MutateManifest(func(m *Manifest) error {
		if _, exists := m.Tools[name]; exists {
			return fmt.Errorf("tool %q already exists", name)
		}
		m.Tools[name] = t
		return nil
	})
	if err != nil {
		return nil, err
	}
	if t.Disabled {
		return nil, nil
	}
	jv, err := e.queue.Enqueue(JobKindInstall, []string{name})
	if err != nil {
		// Queue full: undo the manifest row so a rejected add doesn't
		// leave phantom intent with no install job.
		if rollback := e.store.MutateManifest(func(m *Manifest) error {
			delete(m.Tools, name)
			return nil
		}); rollback != nil {
			e.log.Error("toolbelt: add rollback failed", "error", rollback)
		}
		return nil, err
	}
	return jv, nil
}

// resolveNewTool merges the request with catalog knowledge and, for
// enabled adds, resolves a concrete version. Disabled templates stay
// fully offline (their version hydrates at enable time).
func (e *Engine) resolveNewTool(ctx context.Context, name string, req *AddRequest) (Tool, error) {
	t := Tool{
		Source:      strings.TrimSpace(req.Source),
		Version:     strings.TrimSpace(req.Version),
		Pin:         req.Pin,
		Disabled:    req.Disabled,
		Requires:    req.Requires,
		Description: strings.TrimSpace(req.Description),
		Origin:      req.Origin,
		Install:     strings.TrimSpace(req.Install),
		Uninstall:   strings.TrimSpace(req.Uninstall),
		Probe:       strings.TrimSpace(req.Probe),
	}
	if cat, ok := e.cat().Lookup(name); ok {
		mergeCatalogDefaults(&t, &cat)
	}
	if t.Disabled {
		// Template: no source requirement, no network. Hydration
		// completes it when it is enabled.
		if t.Version != "" && !validVersionString(t.Version) {
			return t, errors.New("invalid version string")
		}
		return t, nil
	}
	if t.Source == "" {
		return t, fmt.Errorf("unknown tool %q: pick a source (npm:/pip:/cargo:/go:/aqua:/manual)", name)
	}
	if err := validateSource(t.Source, t.Install); err != nil {
		return t, err
	}
	if t.Version == "" {
		latest, err := e.versions.Latest(ctx, t.Source, e.aquaDef(t.Source))
		if err != nil {
			return t, fmt.Errorf("resolve latest version: %w", err)
		}
		t.Version = latest
	}
	if !validVersionString(t.Version) {
		return t, errors.New("invalid version string")
	}
	return t, nil
}

// mergeCatalogDefaults fills unset fields of t from the catalog entry.
// Fields other than the source are inherited only when the sources
// agree, so a user's explicit source override never pulls in a
// mismatched definition.
func mergeCatalogDefaults(t *Tool, cat *CatalogEntry) {
	if t.Source == "" {
		t.Source = cat.Source
	}
	if t.Source != cat.Source {
		return
	}
	if t.Description == "" {
		t.Description = cat.Description
	}
	if t.Requires == nil {
		t.Requires = cat.Requires
	}
	if t.Install == "" {
		t.Install = cat.Install
	}
	if t.Uninstall == "" {
		t.Uninstall = cat.Uninstall
	}
	if t.Probe == "" {
		t.Probe = cat.Probe
	}
	if t.Version == "" {
		t.Version = cat.Version
	}
}

// PatchRequest edits an existing tool. Pointer fields distinguish
// "absent" from zero values. Disabled is the enable/disable toggle:
// false→true uninstalls the engine-owned footprint and keeps the
// template; true→false installs.
type PatchRequest struct {
	Version     *string   `json:"version,omitempty"`
	Pin         *bool     `json:"pin,omitempty"`
	Disabled    *bool     `json:"disabled,omitempty"`
	Description *string   `json:"description,omitempty"`
	Requires    *[]string `json:"requires,omitempty"`
	Install     *string   `json:"install,omitempty"`
	Uninstall   *string   `json:"uninstall,omitempty"`
	// Force permits disabling a tool that enabled entries require,
	// cascading the disable to those dependents (one level, mirroring
	// Remove's force cascade).
	Force bool `json:"force,omitempty"`
}

// patchOutcome records what a Patch mutation changed (for job selection
// and rollback).
type patchOutcome struct {
	prevVersion     string
	cascaded        []string
	versionChanged  bool
	disabledChanged bool
	nowDisabled     bool
}

// Patch merges fields into an existing tool and enqueues the follow-up
// job the transition needs: enable → install (when missing), disable →
// footprint uninstall (template kept), version change on an enabled
// tool → reinstall. Returns nil when no job is needed.
func (e *Engine) Patch(name string, req PatchRequest) (*Job, error) {
	if req.Version != nil && !validVersionString(*req.Version) {
		return nil, errors.New("invalid version string")
	}
	var out patchOutcome
	err := e.store.MutateManifest(func(m *Manifest) error {
		return patchManifest(m, name, &req, &out)
	})
	if err != nil {
		return nil, err
	}
	return e.patchJob(name, &out)
}

// patchManifest applies one PatchRequest to the manifest: the dependent
// refusal (or, with Force, the one-level disable cascade mirroring
// Remove's force) plus the field overlay. Records what changed in out.
func patchManifest(m *Manifest, name string, req *PatchRequest, out *patchOutcome) error {
	t, ok := m.Tools[name]
	if !ok {
		return ErrNotFound
	}
	var deps []string
	if req.Disabled != nil && *req.Disabled && !t.Disabled {
		deps = enabledDependents(m, name)
		if len(deps) > 0 && !req.Force {
			return &DependentsError{Dependents: deps}
		}
	}
	*out = applyPatch(&t, req)
	m.Tools[name] = t
	// A forced disable cascades to the enabled dependents (one level,
	// mirroring Remove's force): a dependent left enabled would declare
	// intent against a disabled prerequisite.
	if out.disabledChanged && out.nowDisabled && req.Force {
		for _, d := range deps {
			dt := m.Tools[d]
			dt.Disabled = true
			m.Tools[d] = dt
			out.cascaded = append(out.cascaded, d)
		}
	}
	return nil
}

// applyPatch overlays the request's set fields onto t, reporting the
// transitions (for job selection and rollback).
func applyPatch(t *Tool, req *PatchRequest) patchOutcome {
	var out patchOutcome
	if req.Version != nil && *req.Version != t.Version {
		out.prevVersion = t.Version
		t.Version = *req.Version
		out.versionChanged = true
	}
	if req.Disabled != nil && *req.Disabled != t.Disabled {
		t.Disabled = *req.Disabled
		out.disabledChanged = true
	}
	out.nowDisabled = t.Disabled
	if req.Pin != nil {
		t.Pin = *req.Pin
	}
	if req.Description != nil {
		t.Description = *req.Description
	}
	if req.Requires != nil {
		t.Requires = *req.Requires
	}
	if req.Install != nil {
		t.Install = *req.Install
	}
	if req.Uninstall != nil {
		t.Uninstall = *req.Uninstall
	}
	return out
}

// patchJob enqueues the job a patch outcome requires, rolling the
// manifest back when the queue refuses it.
func (e *Engine) patchJob(name string, out *patchOutcome) (*Job, error) {
	switch {
	case out.disabledChanged && out.nowDisabled:
		names := append([]string{name}, out.cascaded...)
		jv, err := e.queue.Enqueue(JobKindDisable, names)
		if err != nil {
			for _, n := range names {
				e.rollbackPatch(n, func(t *Tool) { t.Disabled = false })
			}
			return nil, err
		}
		return jv, nil
	case out.disabledChanged && !out.nowDisabled:
		jv, err := e.queue.Enqueue(JobKindInstall, []string{name})
		if err != nil {
			e.rollbackPatch(name, func(t *Tool) { t.Disabled = true })
			return nil, err
		}
		return jv, nil
	case out.versionChanged && !out.nowDisabled:
		jv, err := e.queue.Enqueue(JobKindInstall, []string{name})
		if err != nil {
			prev := out.prevVersion
			e.rollbackPatch(name, func(t *Tool) { t.Version = prev })
			return nil, err
		}
		return jv, nil
	default:
		return nil, nil
	}
}

// rollbackPatch reverts one field after a rejected enqueue so the
// manifest never claims a state no job will realize.
func (e *Engine) rollbackPatch(name string, undo func(*Tool)) {
	if err := e.store.MutateManifest(func(m *Manifest) error {
		if t, ok := m.Tools[name]; ok {
			undo(&t)
			m.Tools[name] = t
		}
		return nil
	}); err != nil {
		e.log.Error("toolbelt: patch rollback failed", "tool", name, "error", err)
	}
}

// enabledDependents lists the ENABLED manifest entries that require
// name, directly (Requires) or as the implied backend of their source
// kind. Disabled templates never block; hydration re-adopts their
// dependencies when they are enabled.
func enabledDependents(m *Manifest, name string) []string {
	var out []string
	for other := range m.Tools {
		t := m.Tools[other]
		if other == name || t.Disabled {
			continue
		}
		if slices.Contains(t.Requires, name) {
			out = append(out, other)
			continue
		}
		kind, _, _ := strings.Cut(t.Source, ":")
		if backendDeps[kind] == name {
			out = append(out, other)
		}
	}
	sort.Strings(out)
	return out
}

// Install re-enqueues an install for an existing, enabled tool (retry /
// install-missing). Installing a disabled template is refused with
// ErrDisabled: install is policy-neutral, enabling rides Patch.
func (e *Engine) Install(name string) (*Job, error) {
	m, err := e.store.Manifest()
	if err != nil {
		return nil, err
	}
	t, ok := m.Tools[name]
	if !ok {
		return nil, ErrNotFound
	}
	if t.Disabled {
		return nil, ErrDisabled
	}
	return e.queue.Enqueue(JobKindInstall, []string{name})
}

// Update enqueues an update job over every unpinned, enabled tool (or
// the given names).
func (e *Engine) Update(names ...string) (*Job, error) {
	return e.queue.Enqueue(JobKindUpdate, names)
}

// Remove uninstalls a tool and deletes its template. Without force, a
// tool that enabled entries require is refused and the dependents are
// returned. The removed manifest entries travel on the uninstall job so
// source-specific cleanup (npm/pip uninstalls, manual uninstall
// commands) still knows the sources after the manifest rows are gone.
func (e *Engine) Remove(name string, force bool) (*Job, []string, error) {
	var dependents []string
	removed := map[string]Tool{}
	err := e.store.MutateManifest(func(m *Manifest) error {
		return removeFromManifest(m, name, force, &dependents, removed)
	})
	if err != nil {
		return nil, dependents, err
	}
	names := make([]string, 0, len(removed))
	for n := range removed {
		names = append(names, n)
	}
	sort.Strings(names)
	jv, err := e.queue.EnqueueRemoval(names, removed)
	if err != nil {
		e.rollbackRemoval(removed)
		return nil, dependents, err
	}
	return jv, dependents, nil
}

// removeFromManifest deletes name (and, with force, its enabled
// dependents) from m, recording the removed entries. It refuses with
// *DependentsError when enabled entries require name and force is
// false.
func removeFromManifest(m *Manifest, name string, force bool, dependents *[]string, removed map[string]Tool) error {
	t, ok := m.Tools[name]
	if !ok {
		return ErrNotFound
	}
	*dependents = enabledDependents(m, name)
	if len(*dependents) > 0 && !force {
		return &DependentsError{Dependents: *dependents}
	}
	removed[name] = t
	delete(m.Tools, name)
	if force {
		for _, d := range *dependents {
			removed[d] = m.Tools[d]
			delete(m.Tools, d)
		}
	}
	return nil
}

// rollbackRemoval restores manifest rows after a rejected uninstall job
// so intent and on-disk reality don't diverge (the tool is still
// installed on disk).
func (e *Engine) rollbackRemoval(removed map[string]Tool) {
	rollback := e.store.MutateManifest(func(m *Manifest) error {
		for n := range removed {
			if _, exists := m.Tools[n]; !exists {
				m.Tools[n] = removed[n]
			}
		}
		return nil
	})
	if rollback != nil {
		e.log.Error("toolbelt: remove rollback failed", "error", rollback)
	}
}

// Reconcile enqueues the convergence job: install missing enabled
// entries, uninstall the engine-owned footprint of disabled ones and
// of orphaned state rows (a manifest row deleted without its uninstall
// job completing). ReconcileFull additionally enqueues an update pass
// over unpinned entries. Returns (nil, nil) when the manifest is empty
// and no state row exists (nothing to converge). The returned job is
// the reconcile job; Wait on it to gate consumer readiness (session
// creation, UI states).
func (e *Engine) Reconcile(mode ReconcileMode) (*Job, error) {
	m, err := e.store.Manifest()
	if err != nil {
		return nil, err
	}
	if len(m.Tools) == 0 && len(e.store.State().Tools) == 0 {
		return nil, nil
	}
	jv, err := e.queue.Enqueue(JobKindReconcile, nil)
	if err != nil {
		return nil, err
	}
	if mode == ReconcileFull {
		if _, uerr := e.queue.Enqueue(JobKindUpdate, nil); uerr != nil {
			e.log.Warn("toolbelt: reconcile update pass not enqueued", "error", uerr)
		}
	}
	return jv, nil
}

// EnsureInstalled synchronously guarantees a tool: present in the
// manifest (created from the catalog when missing), enabled, installed,
// and on PATH. This is the programmatic "a product action needs this
// binary now" path (a forge login installing gh, an MCP flow installing
// node); unlike Install it DOES enable a disabled template, because the
// user explicitly invoked the feature that needs the tool.
func (e *Engine) EnsureInstalled(ctx context.Context, name string) error {
	m, err := e.store.Manifest()
	if err != nil {
		return err
	}
	t, inManifest := m.Tools[name]
	status := e.store.State().Tools[name]
	if inManifest && !t.Disabled && e.probeInstalled(name, &t, &status) {
		return nil
	}
	jv, err := e.ensureJob(ctx, name, &t, inManifest)
	if err != nil {
		return err
	}
	final, err := e.queue.Wait(ctx, jv.ID)
	if err != nil {
		return err
	}
	if final.State != JobDone {
		return fmt.Errorf("install %s: %s", name, orDefault(final.Error, final.State))
	}
	return nil
}

// ensureJob picks the mutation EnsureInstalled needs: enable a disabled
// template, retry an existing entry, or add from the catalog.
func (e *Engine) ensureJob(ctx context.Context, name string, t *Tool, inManifest bool) (*Job, error) {
	if inManifest && t.Disabled {
		f := false
		jv, err := e.Patch(name, PatchRequest{Disabled: &f})
		if err != nil {
			return nil, err
		}
		if jv != nil {
			return jv, nil
		}
		// Already installed at enable time: no job was needed.
		return nil, errors.New("enable produced no install job")
	}
	if inManifest {
		return e.Install(name)
	}
	return e.Add(ctx, &AddRequest{Name: name})
}

func orDefault(s, def string) string {
	if s != "" {
		return s
	}
	return def
}

// --- job execution ---

// executeJob runs one dequeued job on the worker goroutine. Install,
// update, and reconcile jobs hydrate catalog knowledge first (under the
// store lock, before any probe or planning — ordering is load-bearing:
// a legacy unmanaged binary satisfying the probe would otherwise leave
// a sparse entry source-less and wedge the update path).
func (e *Engine) executeJob(ctx context.Context, j *job, output func(string)) error {
	e.inst.output = output
	defer func() { e.inst.output = func(string) {} }()
	switch j.kind {
	case JobKindInstall, JobKindUpdate, JobKindReconcile:
		if err := e.hydrateStatic(); err != nil {
			return err
		}
	}
	switch j.kind {
	case JobKindInstall:
		return e.runInstall(ctx, j.names, output)
	case JobKindUninstall:
		return e.runUninstall(ctx, j)
	case JobKindDisable:
		return e.runDisable(ctx, j.names, output)
	case JobKindUpdate:
		return e.runUpdate(ctx, j.names, output)
	case JobKindReconcile:
		return e.runReconcile(ctx, output)
	case JobKindCatalogRefresh:
		// No hydration first: the refresh REPLACES the knowledge
		// hydration reads. Sparse entries pick up the fresh catalog on
		// their next install/update/reconcile job.
		return e.runCatalogRefresh(ctx, output)
	default:
		return fmt.Errorf("unknown job kind %q", j.kind)
	}
}

// hydrateStatic completes sparse manifest entries from the catalog:
// every entry with no source gets the catalog's static fields merged
// and persisted (source, requires, install/uninstall/probe,
// description, default version). Purely offline — version resolution
// for actively-installed tools happens per-tool in installTool. Names
// the catalog doesn't know stay sparse; they fail their own install
// with a named error rather than failing the whole job here.
func (e *Engine) hydrateStatic() error {
	return e.store.MutateManifest(func(m *Manifest) error {
		for name := range m.Tools {
			t := m.Tools[name]
			if t.Source != "" {
				continue
			}
			cat, ok := e.cat().Lookup(name)
			if !ok {
				continue
			}
			mergeCatalogDefaults(&t, &cat)
			m.Tools[name] = t
		}
		return nil
	})
}

// runInstall installs the named tools plus any missing dependencies,
// dependencies first.
func (e *Engine) runInstall(ctx context.Context, names []string, output func(string)) error {
	m, err := e.store.Manifest()
	if err != nil {
		return err
	}
	ordered, err := e.installOrder(ctx, m, names)
	if err != nil {
		return err
	}
	var failed []string
	var firstErr error
	for _, n := range ordered {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := e.installTool(ctx, n, output); err != nil {
			failed = append(failed, n)
			if firstErr == nil {
				firstErr = err
			}
			output(fmt.Sprintf("ERROR %s: %v", n, err))
			// A failed dependency dooms its dependents; carry on so
			// unrelated names in the same job still install.
		}
	}
	switch len(failed) {
	case 0:
		return nil
	case 1:
		return fmt.Errorf("%s: %w", failed[0], firstErr)
	default:
		return fmt.Errorf("failed: %s", strings.Join(failed, ", "))
	}
}

// installOrder expands names with backend deps + Requires (creating
// manifest entries from the catalog for missing deps) and returns them
// dependency-first.
func (e *Engine) installOrder(ctx context.Context, m *Manifest, names []string) ([]string, error) {
	p := &installPlan{e: e, m: m, seen: map[string]bool{}}
	for _, n := range names {
		if err := p.visit(ctx, n, nil); err != nil {
			return nil, err
		}
	}
	return p.ordered, nil
}

// installPlan carries the shared state of the dependency-first DFS
// installOrder runs.
type installPlan struct {
	e       *Engine
	m       *Manifest
	seen    map[string]bool
	ordered []string
}

// visit walks a tool's dependencies depth-first, appending each to the
// plan's order after its deps. A tool already on the stack is a cycle;
// a disabled dependency is a refusal (the user explicitly disabled it,
// and installing through it would silently override that policy).
func (p *installPlan) visit(ctx context.Context, n string, stack []string) error {
	if p.seen[n] {
		return nil
	}
	if slices.Contains(stack, n) {
		return fmt.Errorf("requires cycle through %q", n)
	}
	t, ok := p.m.Tools[n]
	if !ok {
		adopted, err := p.e.adoptDependency(ctx, p.m, n)
		if err != nil {
			return err
		}
		t = adopted
	}
	if t.Disabled && len(stack) > 0 {
		return fmt.Errorf("dependency %q is disabled; enable it first", n)
	}
	stack = append(stack, n)
	for _, dep := range p.e.depsOf(n, &t) {
		if err := p.visit(ctx, dep, stack); err != nil {
			return err
		}
	}
	p.seen[n] = true
	p.ordered = append(p.ordered, n)
	return nil
}

// adoptDependency pulls a not-yet-manifested dependency into the
// manifest from the catalog at its latest version.
func (e *Engine) adoptDependency(ctx context.Context, m *Manifest, n string) (Tool, error) {
	nt, err := e.resolveNewTool(ctx, n, &AddRequest{Name: n})
	if err != nil {
		return Tool{}, fmt.Errorf("dependency %q: %w", n, err)
	}
	if err := e.store.MutateManifest(func(mm *Manifest) error {
		if _, exists := mm.Tools[n]; !exists {
			mm.Tools[n] = nt
		}
		return nil
	}); err != nil {
		return Tool{}, err
	}
	m.Tools[n] = nt
	return nt, nil
}

// depsOf merges backend-implied deps with the entry's Requires.
func (e *Engine) depsOf(name string, t *Tool) []string {
	var deps []string
	kind, _, _ := strings.Cut(t.Source, ":")
	if d, ok := backendDeps[kind]; ok && d != name {
		deps = append(deps, d)
	}
	for _, r := range t.Requires {
		if r != name && !slices.Contains(deps, r) {
			deps = append(deps, r)
		}
	}
	return deps
}

// installTool installs one tool when not already at its manifest
// version, recording status either way. A sparse entry resolves its
// version to latest here (and persists it); an entry the catalog
// couldn't hydrate fails with a named error.
func (e *Engine) installTool(ctx context.Context, name string, output func(string)) error {
	m, err := e.store.Manifest()
	if err != nil {
		return err
	}
	t, ok := m.Tools[name]
	if !ok {
		return ErrNotFound
	}
	if t.Disabled {
		output(fmt.Sprintf("%s is disabled; skipping", name))
		return nil
	}
	if t.Source == "" {
		return fmt.Errorf("no install knowledge for %q: not in the catalog and no source given", name)
	}
	if t.Version == "" {
		latest, verr := e.versions.Latest(ctx, t.Source, e.aquaDef(t.Source))
		if verr != nil {
			return fmt.Errorf("resolve latest version: %w", verr)
		}
		if perr := e.persistVersion(name, latest); perr != nil {
			return perr
		}
		t.Version = latest
	}
	st := e.store.State().Tools[name]
	if st.InstalledVersion == t.Version && e.probeInstalled(name, &t, &st) {
		output(fmt.Sprintf("%s %s already installed", name, t.Version))
		return nil
	}
	output(fmt.Sprintf("installing %s %s (%s)", name, t.Version, t.Source))
	bins, pmBins, err := e.inst.install(ctx, name, &t, e.aquaDef(t.Source), st.PMBins)
	if err != nil {
		e.store.setToolStatus(name, func(s *ToolStatus) { s.LastError = err.Error() })
		return err
	}
	e.store.setToolStatus(name, func(s *ToolStatus) {
		s.InstalledVersion = t.Version
		s.Bins = bins
		s.PMBins = pmBins
		s.LastError = ""
	})
	return nil
}

// persistVersion records a freshly resolved version on the manifest
// entry (keeping intent inspectable and update diffs meaningful).
func (e *Engine) persistVersion(name, version string) error {
	return e.store.MutateManifest(func(m *Manifest) error {
		if t, ok := m.Tools[name]; ok && t.Version == "" {
			t.Version = version
			m.Tools[name] = t
		}
		return nil
	})
}

// runUninstall removes the named tools' installs. The job carries the
// removed manifest entries (Remove deletes them before enqueueing), so
// source-specific cleanup — npm/pip package removal, manual uninstall
// commands — runs with the real Tool definition.
func (e *Engine) runUninstall(ctx context.Context, j *job) error {
	st := e.store.State()
	for _, n := range j.names {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		e.inst.output(fmt.Sprintf("uninstalling %s", n))
		t, ok := j.removed[n]
		if !ok {
			// No definition available (shouldn't happen): bin/opt
			// cleanup still covers the user-visible footprint.
			t = Tool{Source: SourceManual}
		}
		status := st.Tools[n]
		if err := e.inst.uninstall(ctx, n, &t, &status); err != nil {
			return err
		}
		e.store.dropToolStatus(n)
	}
	return nil
}

// runDisable uninstalls the engine-owned footprint of tools whose
// template stays in the manifest (the Patch disable transition and the
// reconciler's disabled-but-installed case). A tool with no recorded
// engine state has nothing owned to remove — unmanaged same-name files
// are deliberately left alone.
func (e *Engine) runDisable(ctx context.Context, names []string, output func(string)) error {
	m, err := e.store.Manifest()
	if err != nil {
		return err
	}
	st := e.store.State()
	for _, n := range names {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		status := st.Tools[n]
		if !status.owned() {
			output(fmt.Sprintf("%s has no engine-owned install; template kept", n))
			continue
		}
		t, ok := m.Tools[n]
		if !ok {
			t = Tool{Source: SourceManual}
		}
		output(fmt.Sprintf("disabling %s (uninstalling, template kept)", n))
		if err := e.inst.uninstall(ctx, n, &t, &status); err != nil {
			return err
		}
		e.store.dropToolStatus(n)
	}
	return nil
}

// runUpdate refreshes latest-version data and reinstalls outdated,
// unpinned, enabled tools (or the explicit names).
func (e *Engine) runUpdate(ctx context.Context, names []string, output func(string)) error {
	m, err := e.store.Manifest()
	if err != nil {
		return err
	}
	targets := names
	if len(targets) == 0 {
		for n := range m.Tools {
			targets = append(targets, n)
		}
		sort.Strings(targets)
	}
	explicit := len(names) > 0
	var bumped []string
	for _, n := range targets {
		did, err := e.updateOne(ctx, m, n, explicit, output)
		if err != nil {
			return err
		}
		if did {
			bumped = append(bumped, n)
		}
	}
	if len(bumped) == 0 {
		output("everything up to date")
		return nil
	}
	return e.runInstall(ctx, bumped, output)
}

// updateOne checks one tool for a newer upstream version and records the
// bump in the manifest, reporting whether it changed. Disabled templates
// stay offline; pinned tools are skipped unless explicitly named; manual
// tools have no upstream source.
func (e *Engine) updateOne(ctx context.Context, m *Manifest, n string, explicit bool, output func(string)) (bool, error) {
	t, ok := m.Tools[n]
	if !ok {
		return false, nil
	}
	if t.Disabled {
		return false, nil
	}
	if t.Pin && !explicit {
		output(fmt.Sprintf("%s pinned at %s, skipping", n, t.Version))
		return false, nil
	}
	if t.Source == SourceManual || t.Source == "" {
		return false, nil
	}
	latest, err := e.versions.Latest(ctx, t.Source, e.aquaDef(t.Source))
	if err != nil {
		output(fmt.Sprintf("%s: version check failed: %v", n, err))
		return false, nil
	}
	if latest == t.Version {
		return false, nil
	}
	// Validate the frozen definition can actually resolve the candidate
	// BEFORE persisting the bump: registry drift between the upstream
	// tag list and the baked aqua definition would otherwise pin the
	// manifest to an uninstallable version (a persistent failed job
	// until an image rebuild or a hand edit). Skipping keeps the old
	// version working.
	if aq := e.aquaDef(t.Source); aq != nil {
		if _, rerr := aq.ResolveSpec(latest); rerr != nil {
			output(fmt.Sprintf("%s: %s not resolvable by the baked definition, keeping %s: %v",
				n, latest, t.Version, rerr))
			return false, nil
		}
	}
	output(fmt.Sprintf("%s: %s -> %s", n, t.Version, latest))
	if err := e.store.MutateManifest(func(mm *Manifest) error {
		cur, ok := mm.Tools[n]
		if !ok {
			return nil
		}
		cur.Version = latest
		mm.Tools[n] = cur
		return nil
	}); err != nil {
		return false, err
	}
	return true, nil
}

// runReconcile converges disk state to manifest intent, both ways:
// orphaned state rows are swept, disabled-but-owned footprints are
// uninstalled (freeing names), then missing enabled entries install.
// Zero network when converged.
func (e *Engine) runReconcile(ctx context.Context, output func(string)) error {
	m, err := e.store.Manifest()
	if err != nil {
		return err
	}
	missing, extras, orphans := e.reconcilePlan(m)
	if len(missing) == 0 && len(extras) == 0 && len(orphans) == 0 {
		output("everything converged")
		return nil
	}
	if err := e.sweepOrphans(ctx, orphans, output); err != nil {
		return err
	}
	if len(extras) > 0 {
		output(fmt.Sprintf("uninstalling disabled tools: %s", strings.Join(extras, ", ")))
		if err := e.runDisable(ctx, extras, output); err != nil {
			return err
		}
	}
	if len(missing) > 0 {
		output(fmt.Sprintf("installing missing tools: %s", strings.Join(missing, ", ")))
		if err := e.runInstall(ctx, missing, output); err != nil {
			return err
		}
	}
	return nil
}

// reconcilePlan classifies the manifest and state rows into the
// reconcile work sets: enabled-but-missing installs, disabled-but-owned
// footprints, and orphaned state rows (owned footprint, no manifest
// row).
func (e *Engine) reconcilePlan(m *Manifest) (missing, extras, orphans []string) {
	st := e.store.State()
	for n := range m.Tools {
		t := m.Tools[n]
		status := st.Tools[n]
		switch {
		case t.Disabled && status.owned():
			extras = append(extras, n)
		case !t.Disabled && !e.probeInstalled(n, &t, &status):
			missing = append(missing, n)
		}
	}
	for n := range st.Tools {
		status := st.Tools[n]
		if _, inManifest := m.Tools[n]; !inManifest && status.owned() {
			orphans = append(orphans, n)
		}
	}
	sort.Strings(missing)
	sort.Strings(extras)
	sort.Strings(orphans)
	return missing, extras, orphans
}

// sweepOrphans uninstalls engine-owned footprints whose manifest row is
// gone — the residue of a crash between Remove's manifest write and its
// uninstall job. The real Tool definition died with the manifest row,
// so cleanup runs with the manual-source fallback (recorded bins and
// the opt dir are removed; a package-manager tree may remain, bounded
// to engine-owned dirs).
func (e *Engine) sweepOrphans(ctx context.Context, orphans []string, output func(string)) error {
	for _, n := range orphans {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		output(fmt.Sprintf("sweeping orphaned install state: %s", n))
		status := e.store.State().Tools[n]
		t := Tool{Source: SourceManual}
		if err := e.inst.uninstall(ctx, n, &t, &status); err != nil {
			return err
		}
		e.store.dropToolStatus(n)
	}
	return nil
}

// aquaDef returns the catalog's aqua definition for an aqua: source.
func (e *Engine) aquaDef(source string) *AquaPackage {
	kind, ref, _ := strings.Cut(source, ":")
	if kind != SourceAqua {
		return nil
	}
	c := e.cat()
	for k := range c.Entries {
		if c.Entries[k].Source == source && c.Entries[k].Aqua != nil {
			return c.Entries[k].Aqua
		}
	}
	// Fallback: synthesize a plain github_release definition so an
	// aqua ref outside the catalog still resolves the common shape.
	owner, repo, ok := strings.Cut(ref, "/")
	if !ok {
		return nil
	}
	return &AquaPackage{Type: aquaTypeGitHubRelease, RepoOwner: owner, RepoName: repo}
}

// validToolName gates manifest keys: the name is a display/manifest key,
// so keep it boring. A slash is legal only in exactly the npm scoped
// form `@scope/name` with non-empty halves (rejects `@/x`, `@x/`,
// `x/y`, `@a/b/c`).
func validToolName(name string) bool {
	if name == "" || len(name) > 80 {
		return false
	}
	if !validSlashForm(name) {
		return false
	}
	for _, r := range name {
		if !validToolNameRune(r) {
			return false
		}
	}
	return true
}

// validSlashForm allows a slash only in the exact npm scoped form
// `@scope/name` with non-empty halves.
func validSlashForm(name string) bool {
	i := strings.IndexByte(name, '/')
	if i < 0 {
		return true
	}
	return strings.HasPrefix(name, "@") && i >= 2 && i != len(name)-1 &&
		strings.Count(name, "/") == 1
}

// validToolNameRune reports whether r is an allowed tool-name character.
func validToolNameRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	case r == '.' || r == '-' || r == '_' || r == '+' || r == '@' || r == '/':
		return true
	default:
		return false
	}
}

// validateSource sanity-checks a source string.
func validateSource(source, install string) error {
	if source == SourceManual {
		if strings.TrimSpace(install) == "" {
			return errors.New("manual tools need an install command")
		}
		return nil
	}
	kind, ref, ok := strings.Cut(source, ":")
	if !ok || ref == "" {
		return errors.New("source must be <kind>:<ref> or manual")
	}
	switch kind {
	case SourceAqua:
		if !strings.Contains(ref, "/") {
			return errors.New("aqua source must be aqua:owner/repo")
		}
	case SourceNpm, SourcePip, SourceCargo, SourceGo:
	default:
		return fmt.Errorf("unknown source kind %q", kind)
	}
	return nil
}
