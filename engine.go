package toolbelt

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"runtime"
	"slices"
	"strings"
	"time"
)

// Sentinel errors. Compare with errors.Is; *DependentsError additionally
// carries the dependent names and *RootIntegrityError the offending roots
// (errors.As).
var (
	// ErrNotFound marks an operation on a tool the manifest doesn't have.
	ErrNotFound = errors.New("tool not found")
	// ErrHasDependents marks a refused remove/disable: enabled entries
	// still require the tool (directly or as an implied backend).
	ErrHasDependents = errors.New("tool has dependents")
	// ErrEssential marks a refused remove: the consumer's bundled-tools
	// file declares this tool necessary (CatalogEntry.Essential).
	// Disabling it is still allowed — see that field for why only deletion
	// is refused.
	ErrEssential = errors.New("tool is essential to this application")
	// ErrDisabled marks an install attempt on a disabled template.
	// Enabling is an explicit state change (Patch Disabled=false), never
	// a side effect of a retry.
	ErrDisabled = errors.New("tool is disabled")
	// ErrUnknownJob marks a Wait on a job id the queue no longer knows:
	// never enqueued, or its terminal view was evicted by the history
	// cap. Without it a Wait on an evicted id would poll to ctx
	// deadline.
	ErrUnknownJob = errors.New("unknown job")
	// ErrRootIntegrity marks a New refused by the opt-in root-integrity
	// check (Config.VerifyRootIntegrity): a managed root is a symlink,
	// is not a directory, is group- or other-writable, cannot be
	// inspected, or resolves outside the tool tree. *RootIntegrityError
	// names each one.
	ErrRootIntegrity = errors.New("managed root failed the integrity check")
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

// defaultBackends maps a source kind to the tool that must be installed
// first for the backend to function at all.
//
// It is the FALLBACK, not the authority: the answer belongs to the
// catalog (Catalog.Backends), because which entry provides npm is a fact
// about the catalog's contents while knowing how to run npm is the
// engine's. This copy exists so a catalog compiled before that field
// existed, or one that names only some kinds, still resolves a backend.
var defaultBackends = map[string]string{
	SourceNpm:   "node",
	SourcePip:   "uv",
	SourceCargo: "rust",
	SourceGo:    "go",
}

// backendFor names the tool a source kind needs installed first, the
// catalog's answer taking precedence over defaultBackends per KIND rather
// than wholesale — a catalog that names one kind must not silently drop
// the rest.
func backendFor(backends map[string]string, kind string) (string, bool) {
	if d, ok := backends[kind]; ok {
		// An empty value is how a catalog says this kind needs no backend
		// at all, which a missing key cannot express while a default
		// exists.
		return d, d != ""
	}
	d, ok := defaultBackends[kind]
	return d, ok
}

// DefaultBackends returns the source-kind-to-backend-tool map a compiled
// catalog should carry: npm needs node, pip needs uv, cargo needs rust,
// go needs go.
//
// Exported for the catalog compiler, which stamps it into every artifact
// so the answer travels as DATA rather than living only in this package's
// source. A consumer that provides a different backend edits the field
// in its own bundled-tools file; nothing has to reach a Go map.
// Returns a fresh copy on every call.
func DefaultBackends() map[string]string {
	return maps.Clone(defaultBackends)
}

// --- read side ---

// Inventory assembles the full read-side snapshot: every manifest entry
// joined with install state, the system group, and the active job.
func (e *Engine) Inventory() (*Inventory, error) {
	m, err := e.store.LoadManifest()
	if err != nil {
		return nil, err
	}
	st := e.store.State()
	installing := e.queue.InstallingSet()

	res := &Inventory{Tools: []ToolInfo{}, System: e.systemTools(), Job: e.queue.Active()}
	// Discovered packages exclude anything the manifest holds, whatever its
	// source: a name in Tools is already rendered there, and a package that
	// appeared in both groups would offer a delete control in one and not the
	// other for the same thing.
	res.AptPackages = e.discoveredApt(m)
	dependents := dependentsIndex(m, e.backends())
	names := make([]string, 0, len(m.Tools))
	for n := range m.Tools {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		t := m.Tools[n]
		s := st.Tools[n]
		res.Tools = append(res.Tools, e.toolInfo(n, &t, &s, installing[n], dependents[n]))
	}
	return res, nil
}

// toolInfo builds one inventory row.
func (e *Engine) toolInfo(name string, t *Tool, s *ToolStatus, installing bool, dependents []string) ToolInfo {
	v := ToolInfo{
		Name:             name,
		Source:           t.Source,
		Version:          t.Version,
		Pin:              t.Pin,
		Disabled:         t.Disabled,
		Requires:         t.Requires,
		Dependents:       dependents,
		Description:      t.Description,
		Origin:           t.Origin,
		Installed:        e.installedFor(name, t, s),
		InstalledVersion: s.InstalledVersion,
		Installing:       installing,
		LastError:        s.LastError,
	}
	if cat, ok := e.cat().Lookup(name); ok {
		v.Lsp = cat.Lsp
		v.Essential = cat.Essential
	}
	// The checksum answer describes an artifact that is present, so it
	// travels only with an installed row: a status surviving a wiped
	// volume would otherwise report "verified" about a binary that is
	// gone.
	if v.Installed {
		v.Checksum = s.Checksum
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

// probeInstalled lives in probe.go: presence plus a bounded execution
// of the tool, and a version match when the definition declares one.

func (e *Engine) systemTools() []SystemTool {
	out := make([]SystemTool, 0, len(e.system))
	for _, b := range e.system {
		out = append(out, SystemTool{Name: b, Installed: hasSystemBin(b)})
	}
	return out
}

// SearchCounts is one query answered from every corpus the engine
// searches, each block cut to its cap beside the count it had before
// the cut. A block is cut iff its Matched count exceeds its length;
// nothing else reports a cut.
//
// The catalog entries alias the catalog: do not mutate their slice fields
// (see [CatalogEntry]).
type SearchCounts struct {
	// AptState says WHY the package list did or did not answer; see
	// [AptState]. AptAvailable is the same verdict narrowed to a bool.
	// It leads the struct because govet's fieldalignment wants the
	// smaller pointer-bearing field ahead of the slices.
	AptState AptState
	// Installable is what [Engine.Search] returns: catalog entries with
	// an install source, minus those already in the manifest.
	Installable []CatalogEntry
	// Unavailable is what [Engine.SearchUnavailable] returns.
	Unavailable []CatalogEntry
	// Apt is what [Engine.SearchApt] returns; empty when AptAvailable is
	// false.
	Apt []AptHit
	// InstallableMatched is how many entries Installable would hold had
	// nothing cut it.
	InstallableMatched int
	// UnavailableMatched is how many entries Unavailable would hold had
	// nothing cut it.
	UnavailableMatched int
	// AptMatched is how many packages Apt would hold had nothing cut it.
	AptMatched int
	// AptAvailable is the bool [Engine.SearchApt] returns: false means
	// the package list could not be consulted, which a consumer must
	// render differently from an empty Apt.
	AptAvailable bool
}

// SearchWithCounts answers one query from every corpus at once. It is
// what a consumer building one reply calls, so the per-package work behind
// Apt (see aptHitsWithCandidate) runs once per request; [Engine.Search],
// [Engine.SearchUnavailable] and [Engine.SearchApt] are its projections.
func (e *Engine) SearchWithCounts(query string) SearchCounts {
	var sc SearchCounts
	sc.Installable, sc.InstallableMatched = e.searchInstallable(query)
	sc.Unavailable, sc.UnavailableMatched = e.searchUnavailable(query)
	sc.Apt, sc.AptMatched, sc.AptState = e.searchApt(query)
	sc.AptAvailable = sc.AptState == AptStateAvailable
	return sc
}

// Search queries the catalog (empty query = featured set), hiding
// entries already in the manifest.
//
// The returned entries alias the catalog: do not mutate their slice fields
// (see [CatalogEntry]).
func (e *Engine) Search(query string) []CatalogEntry {
	hits, _ := e.searchInstallable(query)
	return hits
}

func (e *Engine) searchInstallable(query string) (hits []CatalogEntry, matched int) {
	return cutSearch(e.filterInstalled(e.cat().Search(query)))
}

// SearchUnavailable ranks the catalog entries no install source exists
// for (see [Catalog.Unavailable]), filtered like Search so a name the
// user already has by some other route is not offered as uninstallable.
//
// The returned entries alias the catalog: do not mutate their slice fields
// (see [CatalogEntry]).
func (e *Engine) SearchUnavailable(query string) []CatalogEntry {
	hits, _ := e.searchUnavailable(query)
	return hits
}

func (e *Engine) searchUnavailable(query string) (hits []CatalogEntry, matched int) {
	return cutSearch(e.filterInstalled(e.cat().SearchUnavailable(query)))
}

// cutSearch caps a filtered block at searchLimit and reports how many
// rows it held before the cap. It runs AFTER filterInstalled so the count
// and the rows describe one population: a cut taken before the filter
// would count a row the filter then drops, and report a cut on a reply
// that carries every row the user can see.
func cutSearch(hits []CatalogEntry) (cut []CatalogEntry, matched int) {
	matched = len(hits)
	return hits[:min(matched, searchLimit)], matched
}

// filterInstalled drops hits already present in the manifest. An
// unreadable manifest returns the hits unfiltered rather than nothing: a
// search that silently goes empty is worse than one that offers a tool
// the user already has, and the Add path refuses a duplicate anyway.
//
// It filters in place over the caller's slice, which aliases nothing the
// catalog owns because Search allocated it.
func (e *Engine) filterInstalled(hits []CatalogEntry) []CatalogEntry {
	if len(hits) == 0 {
		return hits
	}
	m, err := e.store.LoadManifest()
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

// SearchApt ranks Debian packages against a query.
//
// ok=false means no package list is available. A consumer must render
// that differently from an empty result, because "apt search is
// unavailable" and "no package matches" look identical and mean opposite
// things. Which of the two reasons it was is [AptState], on
// [SearchCounts]; a consumer that tells a reader anything about apt wants
// that rather than this bool.
//
// The first call triggers a background refresh and returns whatever is
// loaded, which on a cold engine is nothing. That is deliberate: a search
// request must not block on a network round trip, and the refresh is
// lazy precisely so a headless consumer that never searches never pays
// for the index at all.
func (e *Engine) SearchApt(query string) ([]AptHit, bool) {
	hits, _, state := e.searchApt(query)
	return hits, state == AptStateAvailable
}

// AptState says what one search could learn from the Debian package
// corpus. It splits the false half of the bool [Engine.SearchApt]
// returns, which covers two facts that mean opposite things to a reader:
// a host where apt cannot be used at all, and a host whose index has not
// been read yet.
//
// The zero value states nothing, so a consumer decoding a reply from an
// engine that predates this falls back to the bool.
type AptState string

// The states, ordered by how much the corpus can ever say. There is no
// name for the zero value: no search returns it, and it exists on the
// wire only as the absence a consumer reads from an older engine.
const (
	// AptStateUnavailable means apt is not usable here (see
	// [AptAvailable]), so no search will answer from the corpus.
	AptStateUnavailable AptState = "unavailable"
	// AptStateIndexing means apt is usable and no package index is
	// loaded. The first search starts the load and answers without it, so
	// a later search answers from the corpus — a consumer says it is
	// checking rather than asserting an absence it cannot support.
	AptStateIndexing AptState = "indexing"
	// AptStateAvailable means the corpus answered this query, so an empty
	// Apt block means nothing matched.
	AptStateAvailable AptState = "available"
)

func (e *Engine) searchApt(query string) (hits []AptHit, matched int, state AptState) {
	if !AptAvailable() {
		return nil, 0, AptStateUnavailable
	}
	if e.aptIdx.stale() {
		e.aptIdx.refresh()
	}
	hits, matched, consulted := e.aptIdx.Search(query)
	if !consulted {
		return nil, 0, AptStateIndexing
	}
	return e.aptHitsWithCandidate(hits), matched, AptStateAvailable
}

// aptHitsWithCandidate fills in the version apt would install, for the
// capped result set only.
//
// It is resolved here rather than in the index because it costs one
// apt-cache invocation per package: over 68,799 packages that would be
// absurd, over the eight a search returns it is what lets a user see that
// the catalog offers 14.1.1 while Debian offers 14.1.0-1 and choose
// knowingly. A package whose candidate cannot be read keeps an empty
// version rather than dropping out of the results.
func (e *Engine) aptHitsWithCandidate(hits []AptHit) []AptHit {
	if len(hits) == 0 {
		return hits
	}
	ctx, cancel := context.WithTimeout(context.Background(), aptCandidateBudget)
	defer cancel()
	for i := range hits {
		// Validated with the same grammar the install path applies, so
		// the two readers of one apt-cache candidate cannot disagree
		// about whether it is a version. They did: search displayed
		// openssh-client's epoch candidate that Add then refused.
		if v, err := e.inst.aptCandidate(ctx, hits[i].Name); err == nil && validVersion(SourceApt, v) {
			hits[i].Candidate = v
		}
	}
	return hits
}

// aptCandidateBudget bounds the whole candidate-resolution pass over one
// capped result set. apt-cache is a local index read, so this is a
// runaway guard rather than a working budget.
const aptCandidateBudget = 10 * time.Second

// releaseTagResolvable reports whether a candidate tag actually publishes
// an asset this host can install, without downloading anything.
//
// It is the release source's half of the pre-persist check: the manifest
// must never record a version whose release has nothing for us, because
// the recorded version is what every later install and probe reads.
func (e *Engine) releaseTagResolvable(ctx context.Context, name, ref, tag string, hints *ReleaseHints) error {
	rr, err := parseReleaseRef(ref)
	if err != nil {
		return err
	}
	assets, err := e.inst.listReleaseAssets(ctx, rr, tag)
	if err != nil {
		return err
	}
	_, err = chooseReleaseAssetWithHints(assets, name, runtime.GOARCH, hints)
	return err
}

// Jobs returns the active job (with output tail) and recent history.
func (e *Engine) Jobs() (active *Job, recent []*Job) { return e.queue.Snapshot() }

// CancelJob aborts a queued or running job. The cancellation is
// attributed to the caller: the job's CancelCause reports CancelCaller,
// distinguishing a deliberate cancel (this call, including the httpapi
// cancel route) from the CancelShutdown cancellations Close produces.
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
		if t.Version != "" && !validVersion(t.Source, t.Version) {
			return t, versionRejected(t.Source, t.Version)
		}
		return t, nil
	}
	if t.Source == "" {
		return t, e.noSourceError(name)
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
	if !validVersion(t.Source, t.Version) {
		return t, versionRejected(t.Source, t.Version)
	}
	return t, nil
}

// noSourceError explains an add for which neither the caller nor the
// catalog supplied a source.
//
// The catalog may KNOW this tool and have no way to install it (mise
// core:/vfox:/conda: backends). Saying "unknown tool" there is false and
// sends the user looking for a typo, so name the reason instead. A caller
// who supplies its own source never reaches this: it is only asked when
// the catalog was the only available knowledge, which is what keeps a
// hand-authored manual entry for one of these names working.
func (e *Engine) noSourceError(name string) error {
	u, ok := e.cat().Unavailable[name]
	switch {
	case !ok:
		return fmt.Errorf("unknown tool %q: pick a source from npm:, pip:, cargo:, go:, aqua: or manual", name)
	case u.Reason != "":
		return fmt.Errorf("%q has no install source in the catalog, which gives the reason %q. Install it in a shell, or add it with an explicit source", name, u.Reason)
	default:
		return fmt.Errorf("%q has no install source in the catalog. Install it in a shell, or add it with an explicit source", name)
	}
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
	// Clone the two slice fields. Everything else hydrated here is a string,
	// but these cross from the catalog — held in an atomic.Pointer and swapped
	// whole on refresh, so every reader shares one copy — into a manifest row,
	// which IS mutated (Add, Patch, remove). Sharing the backing array would
	// make a future append or sort on a row rewrite what every other reader of
	// the live catalog sees. Today's writers all REPLACE the slice rather than
	// writing through it, so this closes the next edit rather than a live bug.
	if t.Requires == nil {
		t.Requires = slices.Clone(cat.Requires)
	}
	if t.VersionArgs == nil {
		t.VersionArgs = slices.Clone(cat.VersionArgs)
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
	if t.Release == nil {
		t.Release = cat.Release
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
	// RemoveWithDependents).
	Force bool `json:"force,omitempty"`
}

// patchOutcome records what a Patch mutation changed (for job selection
// and rollback).
type patchOutcome struct {
	prevVersion     string
	source          string
	cascaded        []string
	versionChanged  bool
	disabledChanged bool
	nowDisabled     bool
	// pinChanged and nowPinned carry a pin transition out to Patch, which
	// is where the dpkg-level hold is applied. The mutation itself cannot
	// do it: patchManifest runs inside the manifest lock and holding a
	// package is a subprocess.
	pinChanged bool
	nowPinned  bool
}

// Patch merges fields into an existing tool and enqueues the follow-up
// job the transition needs: enable → install (when missing), disable →
// footprint uninstall (template kept), version change on an enabled
// tool → reinstall. Returns nil when no job is needed.
func (e *Engine) Patch(name string, req PatchRequest) (*Job, error) {
	var out patchOutcome
	err := e.store.MutateManifest(func(m *Manifest) error {
		return patchManifest(m, name, &req, &out, e.backends())
	})
	if err != nil {
		return nil, err
	}
	e.applyAptHold(name, &out)
	return e.patchJob(name, &out)
}

// applyAptHold makes a pin REAL for an apt package by asking dpkg to hold
// it, and releases the hold when the pin comes off.
//
// Without it a pin is bookkeeping only. Manifest-level pinning already
// stops this engine bumping the row (updateOne skips a pinned tool), but
// apt upgrades a package as a DEPENDENCY of some other install, so a
// pinned package could move underneath a pin that reported it frozen and
// nothing would record the change. `apt-mark hold` is the only mechanism
// apt itself respects.
//
// Best-effort on purpose, and it fires only on a transition. The pin is
// already persisted by the time this runs, so a failure must not undo the
// user's stated intent — it warns and leaves the manifest-level pin in
// force, which is strictly what the pin meant before this existed.
func (e *Engine) applyAptHold(name string, out *patchOutcome) {
	pkg, ok := strings.CutPrefix(out.source, SourceApt+":")
	if !ok || !out.pinChanged || !AptAvailable() {
		return
	}
	if err := e.inst.aptSetHold(context.Background(), pkg, out.nowPinned); err != nil {
		e.log.Warn("toolbelt: apt hold not applied; the pin holds in the manifest only",
			"tool", name, "package", pkg, "hold", out.nowPinned, "error", err)
	}
}

// patchManifest applies one PatchRequest to the manifest: the dependent
// refusal (or, with Force, the one-level disable cascade mirroring
// RemoveWithDependents) plus the field overlay. Records what changed in out.
func patchManifest(m *Manifest, name string, req *PatchRequest, out *patchOutcome, backends map[string]string) error {
	t, ok := m.Tools[name]
	if !ok {
		return ErrNotFound
	}
	// The version check runs here rather than in Patch because the
	// grammar it must apply depends on this row's source, and the refusal
	// precedes every mutation below.
	if req.Version != nil && !validVersion(t.Source, *req.Version) {
		return versionRejected(t.Source, *req.Version)
	}
	var deps []string
	if req.Disabled != nil && *req.Disabled && !t.Disabled {
		deps = enabledDependents(m, name, backends)
		if len(deps) > 0 && !req.Force {
			return &DependentsError{Dependents: deps}
		}
	}
	*out = applyPatch(&t, req)
	m.Tools[name] = t
	// A forced disable cascades to the enabled dependents (one level,
	// mirroring RemoveWithDependents): a dependent left enabled would
	// declare intent against a disabled prerequisite.
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
		out.pinChanged = *req.Pin != t.Pin
		t.Pin = *req.Pin
	}
	out.nowPinned = t.Pin
	// Carried so Patch can tell an apt row from any other kind without
	// re-reading the manifest outside its lock.
	out.source = t.Source
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
func enabledDependents(m *Manifest, name string, backends map[string]string) []string {
	var out []string
	for other := range m.Tools {
		t := m.Tools[other]
		if other == name || t.Disabled {
			continue
		}
		if dependsOn(&t, other, name, backends) {
			out = append(out, other)
		}
	}
	slices.Sort(out)
	return out
}

// dependentsIndex is enabledDependents for every name at once, in one
// pass over the manifest rather than one pass per row. Inventory renders
// every tool, so the per-name form would make the read quadratic in the
// manifest size for an answer the same walk already produces.
func dependentsIndex(m *Manifest, backends map[string]string) map[string][]string {
	out := map[string][]string{}
	for other := range m.Tools {
		t := m.Tools[other]
		if t.Disabled {
			continue
		}
		for _, dep := range depsOf(other, &t, backends) {
			out[dep] = append(out[dep], other)
		}
	}
	for dep := range out {
		slices.Sort(out[dep])
	}
	return out
}

// dependsOn reports whether tool `other` requires `name`. It reads the
// edge set from depsOf, the one place that decides what a dependency
// edge is, so the refusal and the inventory's advisory answer cannot
// disagree about one.
func dependsOn(t *Tool, other, name string, backends map[string]string) bool {
	return slices.Contains(depsOf(other, t, backends), name)
}

// Install re-enqueues an install for an existing, enabled tool (retry /
// install-missing). Installing a disabled template is refused with
// ErrDisabled: install is policy-neutral, enabling rides Patch.
func (e *Engine) Install(name string) (*Job, error) {
	m, err := e.store.LoadManifest()
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

// Remove uninstalls a tool and deletes its template. A tool that enabled
// entries require is REFUSED with *DependentsError, and the dependents
// are returned so a caller can name them; RemoveWithDependents is the
// cascading sibling that removes them too. The removed manifest entries
// travel on the uninstall job so source-specific cleanup (npm/pip
// uninstalls, manual uninstall commands) still knows the sources after
// the manifest rows are gone.
//
// Two methods rather than one force flag, on the os.Remove /
// os.RemoveAll precedent: at a call site `Remove(name, true)` said
// nothing about what the second argument widened, and the wider
// operation deletes OTHER tools the caller never named.
func (e *Engine) Remove(name string) (*Job, []string, error) {
	return e.remove(name, false)
}

// RemoveWithDependents uninstalls a tool together with every enabled
// entry that requires it, deleting all their templates; the returned job
// carries every removed name and dependents reports which rode along.
//
// The cascade is ONE LEVEL: the direct requirers of name. With A
// requiring B and B requiring name, this removes name and B and leaves A
// enabled against a gone dependency — removing A too is the caller's
// decision. Prefer Remove unless the caller has already established
// that removing the dependents is intended; nothing here re-checks that.
func (e *Engine) RemoveWithDependents(name string) (*Job, []string, error) {
	return e.remove(name, true)
}

// remove is the shared body. cascade is the one behavioural difference
// between the two exported methods, and it is unexported precisely so no
// caller has to read a bare boolean at a call site.
func (e *Engine) remove(name string, cascade bool) (*Job, []string, error) {
	var dependents []string
	removed := map[string]Tool{}
	err := e.store.MutateManifest(func(m *Manifest) error {
		return removeFromManifest(m, name, cascade, &dependents, removed, e.removeKnowledge())
	})
	if err != nil {
		return nil, dependents, err
	}
	names := make([]string, 0, len(removed))
	for n := range removed {
		names = append(names, n)
	}
	slices.Sort(names)
	jv, err := e.queue.EnqueueRemoval(names, removed)
	if err != nil {
		e.rollbackRemoval(removed)
		return nil, dependents, err
	}
	return jv, dependents, nil
}

// removeKnowledge is the CATALOG-derived input a removal needs: what
// counts as a dependency edge, and which names the product declares
// essential. Bundled because both answers come from the same live catalog
// and must be read once per call — a swap partway through a cascade would
// otherwise change the rules mid-decision.
type removeKnowledge struct {
	backends  map[string]string
	essential func(name string) bool
}

// removeKnowledge snapshots the live catalog for one removal.
//
// Essential is read HERE rather than from the manifest row, and that is
// the point: it is the bundle's live answer, so a product that stops
// depending on a tool releases it immediately instead of waiting for
// something to re-resolve the row.
func (e *Engine) removeKnowledge() removeKnowledge {
	c := e.cat()
	return removeKnowledge{
		backends: e.backends(),
		essential: func(name string) bool {
			if c == nil {
				return false
			}
			cat, ok := c.Lookup(name)
			return ok && cat.Essential
		},
	}
}

// removeFromManifest deletes name (and, with cascade, its enabled
// dependents) from m, recording the removed entries. It refuses with
// *DependentsError when enabled entries require name and cascade is
// false.
func removeFromManifest(m *Manifest, name string, cascade bool, dependents *[]string, removed map[string]Tool, rc removeKnowledge) error {
	t, ok := m.Tools[name]
	if !ok {
		return ErrNotFound
	}
	// Before the dependents check, so the answer does not depend on
	// whether anything happens to require it, and so RemoveWithDependents
	// cannot delete it as somebody else's collateral.
	if rc.essential(name) {
		return fmt.Errorf("%w: %s", ErrEssential, name)
	}
	*dependents = enabledDependents(m, name, rc.backends)
	if len(*dependents) > 0 && !cascade {
		return &DependentsError{Dependents: *dependents}
	}
	// A cascade must not take an essential row down with it. Refusing the
	// whole call is the honest answer: the caller asked for a set, and
	// removing part of it would leave the user believing the rest went too.
	if cascade {
		for _, d := range *dependents {
			if rc.essential(d) {
				return fmt.Errorf("%w: %s, which requires %s", ErrEssential, d, name)
			}
		}
	}
	removed[name] = t
	delete(m.Tools, name)
	if cascade {
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

// Reconcile enqueues the convergence job: install missing enabled entries,
// uninstall the engine-owned footprint of disabled ones and of orphaned
// state rows. ReconcileFull also enqueues an update pass over unpinned
// entries. A queued reconcile is returned rather than duplicated and a full
// queue never refuses one, so err means a manifest read failure or shutdown.
//
// enqueued is false, with a nil job and a nil error, when the manifest is
// empty and no state row exists; a readiness gate branches on enqueued first.
func (e *Engine) Reconcile(mode ReconcileMode) (jv *Job, enqueued bool, err error) {
	m, err := e.store.LoadManifest()
	if err != nil {
		return nil, false, err
	}
	if len(m.Tools) == 0 && len(e.store.State().Tools) == 0 {
		return nil, false, nil
	}
	jv, err = e.queue.Enqueue(JobKindReconcile, nil)
	if err != nil {
		return nil, false, err
	}
	if mode == ReconcileFull {
		if _, uerr := e.queue.Enqueue(JobKindUpdate, nil); uerr != nil {
			e.log.Warn("toolbelt: reconcile update pass not enqueued", "error", uerr)
		}
	}
	return jv, true, nil
}

// EnsureInstalled synchronously guarantees a tool: present in the
// manifest (created from the catalog when missing), enabled, installed,
// and on PATH. This is the programmatic "a product action needs this
// binary now" path (a forge login installing gh, an MCP flow installing
// node); unlike Install it DOES enable a disabled template, because the
// user explicitly invoked the feature that needs the tool.
func (e *Engine) EnsureInstalled(ctx context.Context, name string) error {
	m, err := e.store.LoadManifest()
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
		if cause := final.Err(); cause != nil {
			return fmt.Errorf("install %s: %w", name, cause)
		}
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
		return e.runInstall(ctx, j, j.names, output)
	case JobKindUninstall:
		return e.runUninstall(ctx, j)
	case JobKindDisable:
		return e.runDisable(ctx, j.names, output)
	case JobKindUpdate:
		return e.runUpdate(ctx, j, output)
	case JobKindReconcile:
		return e.runReconcile(ctx, j, output)
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
// dependencies first. The resolved plan is published on the job before
// the first install starts, so a consumer polling the inventory sees
// every tool the job will touch as installing rather than discovering
// dependency rows one at a time, each looking idle.
func (e *Engine) runInstall(ctx context.Context, j *job, names []string, output func(string)) error {
	m, err := e.store.LoadManifest()
	if err != nil {
		return err
	}
	p := e.installOrder(ctx, m, names)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	e.queue.setCovers(j, p.ordered)
	for _, n := range p.enabled {
		output(fmt.Sprintf("enabling %s, required by %s", n, strings.Join(names, ", ")))
	}
	fails := e.recordUnplanned(m, p.unplanned, output)
	blockers := installBlockers{}
	// Resolved once for the whole plan: a catalog swap mid-job must not
	// change what counts as a dependency edge partway through.
	backends := e.backends()
	for _, n := range p.ordered {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if cause, blocked := blockers.cause(m, n, backends); blocked {
			e.recordBlocked(n, cause, output)
			blockers[n] = cause
			continue
		}
		if err := e.installTool(ctx, n, output); err != nil {
			fails.add(n, err)
			blockers[n] = blocker{err: err}
			output(fmt.Sprintf("ERROR %s: %v", n, err))
		}
	}
	return fails.err()
}

// installError is the tools an install job could not install, each with
// its cause, in order.
type installError struct {
	names []string
	errs  []error
}

func (f *installError) add(name string, err error) {
	f.names = append(f.names, name)
	f.errs = append(f.errs, err)
}

// err is the job's error: nil, one tool's cause, or every cause behind the
// name list, so errors.As reaches any of them.
func (f *installError) err() error {
	switch len(f.names) {
	case 0:
		return nil
	case 1:
		return fmt.Errorf("%s: %w", f.names[0], f.errs[0])
	default:
		return f
	}
}

func (f *installError) Error() string { return "failed: " + strings.Join(f.names, ", ") }

func (f *installError) Unwrap() []error { return f.errs }

func (e *Engine) recordUnplanned(m *Manifest, unplanned []planFailure, output func(string)) *installError {
	fails := &installError{}
	for _, u := range unplanned {
		fails.add(u.name, u.err)
		output(fmt.Sprintf("ERROR %s: %v", u.name, u.err))
		rows := u.stranded
		if !slices.Contains(rows, u.name) {
			rows = append(rows, u.name)
		}
		for _, n := range rows {
			if _, ok := m.Tools[n]; !ok {
				continue
			}
			if serr := e.recordFailure(n, u.err); serr != nil {
				e.log.Error("toolbelt: planning error not recorded", "tool", n, "error", serr)
			}
		}
	}
	return fails
}

type dependencyError struct {
	err  error
	name string
}

func (e *dependencyError) Error() string {
	return fmt.Sprintf("dependency %q failed: %v", e.name, e.err)
}

func (e *dependencyError) Unwrap() error { return e.err }

type installBlockers map[string]blocker

// blocker is one tool the job could not install. root names the dependency
// that stopped it, empty for a tool that failed on its own; err is the root
// failure's cause either way, so a blocked row can carry it.
type blocker struct {
	err  error
	root string
}

// cause names the tool that makes installing n pointless — a dependency
// that failed in this job, or the ROOT failure behind a dependency that
// was itself blocked. The plan is dependency-first, so one pass
// propagates a failure through the whole chain behind it.
//
// Attempting a doomed dependent would make it blame itself: with node
// unable to run, pyright fails with `npm failed: exit status 127`.
func (b installBlockers) cause(m *Manifest, n string, backends map[string]string) (blocker, bool) {
	t, ok := m.Tools[n]
	if !ok {
		return blocker{}, false
	}
	for _, dep := range depsOf(n, &t, backends) {
		stop, stopped := b[dep]
		if !stopped {
			continue
		}
		if stop.root != "" {
			return stop, true
		}
		return blocker{root: dep, err: stop.err}, true
	}
	return blocker{}, false
}

// recordBlocked reports a tool the job skipped and puts the reason on its
// status row, so the row names the tool that actually broke instead of
// keeping whatever error a previous attempt left there.
func (e *Engine) recordBlocked(name string, cause blocker, output func(string)) {
	output(fmt.Sprintf("%s: skipped, %s failed", name, cause.root))
	if serr := e.recordFailure(name, &dependencyError{name: cause.root, err: cause.err}); serr != nil {
		e.log.Error("toolbelt: blocked reason not recorded", "tool", name, "error", serr)
	}
}

// systemPackagesFirst moves apt: roots ahead of the rest, each group in its
// incoming order. A native build (cgo, node-gyp, a pip sdist) compiles against
// system packages it declares no edge to: apt installs without Recommends, so
// gcc arrives without libc6-dev's headers, and Go enables cgo whenever a C
// compiler is on PATH (https://pkg.go.dev/cmd/cgo).
func systemPackagesFirst(m *Manifest, names []string) []string {
	apt := make([]string, 0, len(names))
	var rest []string
	for _, n := range names {
		if sourceKind(m.Tools[n].Source) == SourceApt {
			apt = append(apt, n)
		} else {
			rest = append(rest, n)
		}
	}
	return append(apt, rest...)
}

// installOrder expands names with backend deps + Requires (adopting missing
// deps from the catalog, enabling disabled ones) and returns them
// dependency-first, apt roots before the others (systemPackagesFirst),
// updating m to match tools.json. Each root plans on its own and is
// all-or-nothing: its adoptions and enables are staged, then committed to
// tools.json and m in one write only when its whole chain plans. A failed root
// lands in unplanned with its staging and order entries discarded, so a later
// root adopts a shared new dependency itself and the other roots still install.
func (e *Engine) installOrder(ctx context.Context, m *Manifest, names []string) *installPlan {
	p := &installPlan{e: e, m: m, seen: map[string]bool{}}
	for _, n := range systemPackagesFirst(m, names) {
		mark := len(p.ordered)
		p.stage = rootStage{tools: map[string]Tool{}, via: map[string][]string{}}
		err := p.visit(ctx, n, nil)
		if err == nil {
			err = p.commit()
		}
		if err != nil {
			for _, planned := range p.ordered[mark:] {
				delete(p.seen, planned)
			}
			p.ordered = p.ordered[:mark]
			p.unplanned = append(p.unplanned, planFailure{name: n, err: err, stranded: p.stranded})
		}
		p.stranded = nil
	}
	return p
}

// installPlan carries the shared state of the dependency-first DFS
// installOrder runs. m holds only committed entries; the root being
// walked sees its own staged ones through lookup.
type installPlan struct {
	e       *Engine
	m       *Manifest
	seen    map[string]bool
	ordered []string
	// enabled records the disabled templates this plan switched on as
	// obligatory dependencies, for the job log. Committed roots only.
	enabled   []string
	unplanned []planFailure
	stranded  []string
	stage     rootStage
}

type rootStage struct {
	tools map[string]Tool
	// via is each staged enable's ancestor path, so a commit that fails on
	// the enable can strand the same rows a planning failure there would.
	via     map[string][]string
	adopted []string
	enabled []string
}

type planFailure struct {
	err  error
	name string
	// stranded is the failed path's committed tools whose dependency could
	// not be planned. Staged entries are absent: nothing of them persists.
	stranded []string
}

func (p *installPlan) lookup(n string) (Tool, bool) {
	if t, ok := p.stage.tools[n]; ok {
		return t, true
	}
	t, ok := p.m.Tools[n]
	return t, ok
}

// commit writes the root's staged changes in one manifest mutation and
// copies the rows as written into m. An adoption yields to a row that
// appeared on disk meanwhile; an enable whose row vanished fails the root,
// strands the committed rows on its path, and the aborted mutation writes
// nothing.
func (p *installPlan) commit() error {
	s := &p.stage
	if len(s.tools) == 0 {
		return nil
	}
	written := make(map[string]Tool, len(s.tools))
	err := p.e.store.MutateManifest(func(mm *Manifest) error {
		if vanished := s.apply(mm); vanished != "" {
			p.stranded = append(p.stranded, s.committedPath(mm, vanished)...)
			return &dependencyError{name: vanished, err: ErrNotFound}
		}
		for n := range s.tools {
			written[n] = mm.Tools[n]
		}
		return nil
	})
	if err != nil {
		return err
	}
	maps.Copy(p.m.Tools, written)
	p.enabled = append(p.enabled, s.enabled...)
	return nil
}

// apply must run inside an abortable manifest mutation: a missing enable
// can follow adoptions it already wrote into mm.
func (s *rootStage) apply(mm *Manifest) (vanished string) {
	for _, n := range s.adopted {
		if _, exists := mm.Tools[n]; !exists {
			mm.Tools[n] = s.tools[n]
		}
	}
	for _, n := range s.enabled {
		t, ok := mm.Tools[n]
		if !ok {
			return n
		}
		t.Disabled = false
		mm.Tools[n] = t
	}
	return ""
}

// committedPath is the vanished enable's ancestors that still have a row
// in mm. It reads mm, not the plan's manifest, because the same hand edit
// can delete an ancestor, and a status row needs a manifest row.
func (s *rootStage) committedPath(mm *Manifest, vanished string) []string {
	var rows []string
	for _, a := range s.via[vanished] {
		_, staged := s.tools[a]
		if _, onDisk := mm.Tools[a]; onDisk && !staged {
			rows = append(rows, a)
		}
	}
	return rows
}

// visit walks a tool's dependencies depth-first, appending each to the
// plan's order after its deps. A tool already on the stack is a cycle.
//
// A DISABLED dependency is ENABLED rather than refused: asking for a
// tool is asking for what it cannot run without (typescript-language-server
// with no typescript is a launcher with nothing to launch). The enable is
// staged like an adoption (installOrder owns when it persists), and mirrors
// the force-disable cascade's edge walk in the other direction.
func (p *installPlan) visit(ctx context.Context, n string, stack []string) error {
	if p.seen[n] {
		return nil
	}
	if slices.Contains(stack, n) {
		return fmt.Errorf("requires cycle through %q", n)
	}
	t, err := p.entry(ctx, n, stack)
	if err != nil {
		return err
	}
	stack = append(stack, n)
	for _, dep := range depsOf(n, &t, p.e.backends()) {
		if err := p.visit(ctx, dep, stack); err != nil {
			if _, staged := p.stage.tools[n]; !staged {
				p.stranded = append(p.stranded, n)
			}
			return err
		}
	}
	p.seen[n] = true
	p.ordered = append(p.ordered, n)
	return nil
}

func (p *installPlan) entry(ctx context.Context, n string, stack []string) (Tool, error) {
	t, ok := p.lookup(n)
	if !ok {
		nt, err := p.e.resolveNewTool(ctx, n, &AddRequest{Name: n})
		if err != nil {
			return Tool{}, &dependencyError{name: n, err: err}
		}
		t = nt
		p.stage.tools[n] = t
		p.stage.adopted = append(p.stage.adopted, n)
	}
	if t.Disabled && len(stack) > 0 {
		t.Disabled = false
		p.stage.tools[n] = t
		p.stage.enabled = append(p.stage.enabled, n)
		p.stage.via[n] = slices.Clone(stack)
	}
	return t, nil
}

// depsOf merges backend-implied deps with the entry's Requires. It is
// the ONE definition of a dependency edge: the install plan walks it, the
// remove/disable refusal derives its dependents from it, and so does the
// inventory's advisory dependents field, so none of the three can hold a
// different idea of what depends on what. Self-references are dropped
// (an entry named after its own backend, e.g. the `go` entry itself).
func depsOf(name string, t *Tool, backends map[string]string) []string {
	var deps []string
	kind, _, _ := strings.Cut(t.Source, ":")
	if d, ok := backendFor(backends, kind); ok && d != name {
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
//
// The status write is the install's COMMIT POINT: superseded versions are
// pruned only after the new tree and its state record are both durable,
// so a crash (or a full disk) can never leave a pruned previous version
// next to a state file that was never written. verifyInstalled sits
// between the two, so a binary that cannot run fails the install with
// the predecessor still on disk.
func (e *Engine) installTool(ctx context.Context, name string, output func(string)) error {
	t, err := e.resolveInstallTarget(ctx, name, output)
	if err != nil || t == nil {
		return err
	}
	st := e.store.State().Tools[name]
	if st.InstalledVersion == t.Version && e.probeInstalled(name, t, &st) {
		output(fmt.Sprintf("%s %s already installed", name, t.Version))
		return nil
	}
	output(fmt.Sprintf("installing %s %s from %s", name, t.Version, t.Source))
	res, err := e.inst.install(ctx, name, t, e.aquaDef(t.Source), &st)
	if err != nil {
		if serr := e.recordFailure(name, err); serr != nil {
			e.log.Error("toolbelt: install error not recorded", "tool", name, "error", serr)
		}
		return err
	}
	if serr := e.commitInstall(name, t, res); serr != nil {
		return serr
	}
	if verr := e.verifyInstalled(name, t, output); verr != nil {
		return verr
	}
	e.pruneSuperseded(name, t)
	return nil
}

// resolveInstallTarget prepares the entry installTool is about to act on:
// it reads the manifest row, refuses one the catalog could not hydrate,
// and resolves (and persists) a sparse entry's version. A nil Tool with a
// nil error means there is nothing to install — a disabled template,
// which is a no-op rather than a failure, so a reconcile pass carrying
// one does not fail the whole job.
func (e *Engine) resolveInstallTarget(ctx context.Context, name string, output func(string)) (*Tool, error) {
	m, err := e.store.LoadManifest()
	if err != nil {
		return nil, err
	}
	t, ok := m.Tools[name]
	if !ok {
		return nil, ErrNotFound
	}
	if t.Disabled {
		output(fmt.Sprintf("%s is disabled, so it was skipped", name))
		return nil, nil
	}
	if t.Source == "" {
		return nil, fmt.Errorf("no install knowledge exists for %q because it is not in the catalog and no source was given", name)
	}
	if t.Version != "" {
		return &t, nil
	}
	latest, err := e.versions.Latest(ctx, t.Source, e.aquaDef(t.Source))
	if err != nil {
		return nil, fmt.Errorf("resolve latest version: %w", err)
	}
	if err := e.persistVersion(name, latest); err != nil {
		return nil, err
	}
	t.Version = latest
	return &t, nil
}

// commitInstall records what landed. This write is the install's COMMIT
// POINT, so a failure here fails the job with the PREVIOUS state intact
// and nothing pruned, and a retry converges.
func (e *Engine) commitInstall(name string, t *Tool, res installOutcome) error {
	if err := e.store.setToolStatus(name, func(s *ToolStatus) {
		s.InstalledVersion = t.Version
		s.Bins = res.bins
		s.PMBins = res.pmBins
		s.Checksum = res.checksum
		s.LastError = ""
	}); err != nil {
		return fmt.Errorf("record install state for %s: %w", name, err)
	}
	e.probes.forget(name)
	// An apt install changes the host's package set, and it changes it for
	// DEPENDENCIES too, so the discovered list has to be re-derived rather
	// than adjusted for the one name. Invalidated here rather than on a
	// timer: this is the moment a reader is looking, and it is the only
	// moment the answer can have changed.
	if res.apt && e.aptSeen != nil {
		e.aptSeen.Invalidate()
	}
	return nil
}

// verifyInstalled probes what the install just published and refuses to
// let a binary the OS will not run stand as a completed install. It runs
// AFTER the status write (durability unchanged) and BEFORE pruning, so a
// failed verification leaves the retained predecessor as the fallback.
//
// Only CannotExec fails the install; a version-banner mismatch is
// reported and tolerated as a knowledge gap rather than evidence the
// tool is broken. The probe verdict is cached by binary fingerprint, so
// the inventory read that follows reuses it instead of re-spawning.
func (e *Engine) verifyInstalled(name string, t *Tool, output func(string)) error {
	st := e.store.State().Tools[name]
	v := e.probeTool(name, t, &st)
	switch {
	case v.CannotExec:
		err := fmt.Errorf("installed %s but it cannot run: %s", t.Version, v.Reason)
		output(fmt.Sprintf("ERROR %s: %v", name, err))
		if serr := e.recordFailure(name, err); serr != nil {
			e.log.Error("toolbelt: verification failure not recorded", "tool", name, "error", serr)
		}
		return err
	case !v.OK:
		output(fmt.Sprintf("The %s install was not verified. %s", name, v.Reason))
	}
	return nil
}

// recordFailure stores an install failure on the tool's status row.
func (e *Engine) recordFailure(name string, cause error) error {
	return e.store.setToolStatus(name, func(s *ToolStatus) { s.LastError = cause.Error() })
}

// pruneSuperseded applies the retention policy to a tool's versioned
// install trees, after its new version is durably recorded. Only aqua
// sources publish versioned trees; the other backends own a single
// unversioned dir that must never be swept.
func (e *Engine) pruneSuperseded(name string, t *Tool) {
	if kind, _, _ := strings.Cut(t.Source, ":"); kind != SourceAqua {
		return
	}
	e.inst.pruneOldVersions(name, t.Version, e.keepVersions)
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
		if err := e.store.dropToolStatus(n); err != nil {
			return fmt.Errorf("drop install state for %s: %w", n, err)
		}
		e.probes.forget(n)
	}
	return nil
}

// runDisable uninstalls the engine-owned footprint of tools whose
// template stays in the manifest (the Patch disable transition and the
// reconciler's disabled-but-installed case). A tool with no recorded
// engine state has nothing owned to remove — unmanaged same-name files
// are deliberately left alone.
func (e *Engine) runDisable(ctx context.Context, names []string, output func(string)) error {
	m, err := e.store.LoadManifest()
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
			output(fmt.Sprintf("%s has no engine-owned install, so the template was kept", n))
			continue
		}
		t, ok := m.Tools[n]
		if !ok {
			t = Tool{Source: SourceManual}
		}
		output(fmt.Sprintf("disabling %s, uninstalling it and keeping the template", n))
		if err := e.inst.uninstall(ctx, n, &t, &status); err != nil {
			return err
		}
		if err := e.store.dropToolStatus(n); err != nil {
			return fmt.Errorf("drop install state for %s: %w", n, err)
		}
		e.probes.forget(n)
	}
	return nil
}

// runUpdate refreshes latest-version data and reinstalls outdated,
// unpinned, enabled tools (or the explicit names).
func (e *Engine) runUpdate(ctx context.Context, j *job, output func(string)) error {
	m, err := e.store.LoadManifest()
	if err != nil {
		return err
	}
	names := j.names
	targets := names
	if len(targets) == 0 {
		for n := range m.Tools {
			targets = append(targets, n)
		}
		slices.Sort(targets)
	}
	bumped, limited, err := e.checkUpdates(ctx, m, targets, len(names) > 0, output)
	if err != nil {
		return err
	}
	if len(bumped) == 0 {
		if limited != nil {
			return limited
		}
		output("everything up to date")
		return nil
	}
	if err := e.runInstall(ctx, j, bumped, output); err != nil {
		if limited != nil {
			return errors.Join(err, limited)
		}
		return err
	}
	return limited
}

// checkUpdates runs updateOne over targets, returning the bumped names and
// the first rate-limited version check. That limit does not stop the walk:
// the job still checks and installs the rest, then fails on it rather than
// reporting the tool up to date.
func (e *Engine) checkUpdates(ctx context.Context, m *Manifest, targets []string, explicit bool, output func(string)) (bumped []string, limited, err error) {
	for _, n := range targets {
		did, err := e.updateOne(ctx, m, n, explicit, output)
		switch {
		case errors.Is(err, ErrGitHubRateLimited):
			if limited == nil {
				limited = fmt.Errorf("%s: version check: %w", n, err)
			}
		case err != nil:
			return nil, nil, err
		case did:
			bumped = append(bumped, n)
		}
	}
	return bumped, limited, nil
}

// updateOne checks one tool for a newer upstream version and records the
// bump in the manifest, reporting whether it changed. Disabled templates
// stay offline; pinned tools are skipped unless explicitly named; manual
// tools have no upstream source. A failed version check is skipped, except
// a GitHub rate limit, which it returns.
func (e *Engine) updateOne(ctx context.Context, m *Manifest, n string, explicit bool, output func(string)) (bool, error) {
	t, ok := m.Tools[n]
	if !ok || t.Disabled || t.Source == SourceManual || t.Source == "" {
		return false, nil
	}
	if t.Pin && !explicit {
		output(fmt.Sprintf("%s pinned at %s, skipping", n, t.Version))
		return false, nil
	}
	latest, err := e.versions.Latest(ctx, t.Source, e.aquaDef(t.Source))
	if err != nil {
		output(fmt.Sprintf("%s: version check failed: %v", n, err))
		if errors.Is(err, ErrGitHubRateLimited) {
			return false, err
		}
		return false, nil
	}
	if latest == t.Version {
		return false, nil
	}
	if reason := e.candidateUninstallable(ctx, n, &t, latest); reason != "" {
		output(reason)
		return false, nil
	}
	output(fmt.Sprintf("updating %s from %s to %s", n, t.Version, latest))
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

// candidateUninstallable reports why a newer version must not be written
// into the manifest, or "" when it may be. Both checks run BEFORE the
// bump is persisted, because a manifest pinned to an uninstallable
// version is a persistent failed job until an image rebuild or a hand
// edit, while skipping keeps the working version installed.
//
// The aqua half covers registry drift between the upstream tag list and
// the baked definition. The release half covers an upstream that renames
// its assets between releases, and it is not optional either: the new tag
// would be written and then fail to install on every run afterwards, with
// the working version already overwritten. It costs one asset listing.
func (e *Engine) candidateUninstallable(ctx context.Context, n string, t *Tool, latest string) string {
	if aq := e.aquaDef(t.Source); aq != nil {
		if _, err := aq.ResolveSpec(latest); err != nil {
			return fmt.Sprintf("%s: %s not resolvable by the baked definition, keeping %s: %v",
				n, latest, t.Version, err)
		}
	}
	if kind, ref, _ := strings.Cut(t.Source, ":"); kind == SourceRelease {
		if err := e.releaseTagResolvable(ctx, n, ref, latest, t.Release); err != nil {
			return fmt.Sprintf("%s: %s has no installable asset, keeping %s: %v",
				n, latest, t.Version, err)
		}
	}
	return ""
}

// runReconcile converges disk state to manifest intent, both ways:
// orphaned state rows are swept, disabled-but-owned footprints are
// uninstalled (freeing names), then missing enabled entries install.
// Zero network when converged.
func (e *Engine) runReconcile(ctx context.Context, j *job, output func(string)) error {
	m, err := e.store.LoadManifest()
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
		if err := e.runInstall(ctx, j, missing, output); err != nil {
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
	slices.Sort(missing)
	slices.Sort(extras)
	slices.Sort(orphans)
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
		if err := e.store.dropToolStatus(n); err != nil {
			return fmt.Errorf("drop orphaned install state for %s: %w", n, err)
		}
		e.probes.forget(n)
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
	if !validNameComponents(name) {
		return false
	}
	for _, r := range name {
		if !validToolNameRune(r) {
			return false
		}
	}
	return true
}

// validNameComponents requires every slash-separated part of the name to
// be a usable single path component: not empty, not "." and not "..".
//
// The name is joined onto the opt dir (`opt/<name>/<version>`) and
// uninstall hands the join to os.RemoveAll, so a dot component aims that
// removal outside the tool's own directory. Only an EXACT dot component
// is traversal — "tool.v2", "..extras" and "..." stay valid, which a
// leading-dot or contains-".." test would wrongly refuse. Splitting on
// '/' alone is safe because validToolNameRune admits no other separator.
func validNameComponents(name string) bool {
	for part := range strings.SplitSeq(name, "/") {
		if part == "" || part == "." || part == ".." {
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
	case SourceRelease:
		if _, rerr := parseReleaseRef(ref); rerr != nil {
			return rerr
		}
	case SourceApt:
		// The grammar gate, applied at the door. Everything downstream
		// treats the ref as a literal package name, so this is where a
		// token that apt would read as an option, a version pin, an
		// architecture qualifier or a removal is refused.
		if !aptValidName(ref) {
			return fmt.Errorf("apt source must be apt:<package> with a valid Debian package name, got %q", ref)
		}
	case SourceNpm, SourcePip, SourceCargo, SourceGo:
	default:
		return fmt.Errorf("unknown source kind %q", kind)
	}
	return nil
}

// discoveredApt lists installed apt packages the manifest does not hold.
//
// Filtered against the manifest by NAME rather than by source, because an apt
// package can also be the thing a manual or release entry installed under the
// same name, and one thing must not appear in two inventory groups: the Tools
// row carries a delete control and this group carries none, so a reader would
// see the same package as both managed and not.
func (e *Engine) discoveredApt(m *Manifest) []AptPackage {
	if e.aptSeen == nil {
		return nil
	}
	all := e.aptSeen.List(context.Background())
	if len(all) == 0 {
		return nil
	}
	out := make([]AptPackage, 0, len(all))
	for _, p := range all {
		if _, managed := m.Tools[p.Name]; !managed {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
