package toolbelt

// Library-owned result shapes. These are the Engine's Go return types
// and, unchanged, the JSON wire shapes of the httpapi projection —
// consumers that generate client types (wiregen) alias them.

// Job states.
const (
	JobQueued    = "queued"
	JobRunning   = "running"
	JobDone      = "done"
	JobFailed    = "failed"
	JobCancelled = "cancelled"
)

// CancelCause identifies WHO cancelled a job. The cause is known inside
// the engine at every cancellation site, and it is the distinction a
// consumer needs to decide whether a cancellation deserves an alert: a
// shutdown cancellation is routine (the process is going down and the
// engine cancels what it was running), a caller cancellation is a
// deliberate act. Without it both arrive as a bare JobCancelled and the
// consumer has to invent its own shutdown flag.
//
// Meaningful only for a job whose State is JobCancelled — a job that
// finished, failed, or timed out always carries CancelUnknown, even if a
// cancellation was requested and lost the race.
type CancelCause string

const (
	// CancelUnknown is the zero value: no cause was recorded. A
	// cancelled job carrying it was stopped through a path that names no
	// cause. Deliberately NOT equal to CancelShutdown or CancelCaller,
	// so a cancellation path added later cannot be silently read as
	// either one.
	CancelUnknown CancelCause = ""
	// CancelShutdown is cancellation initiated by Engine.Close: the
	// running job's context is cancelled and queued jobs are drained
	// because the engine is shutting down. Routine.
	CancelShutdown CancelCause = "shutdown"
	// CancelCaller is cancellation initiated through Engine.CancelJob —
	// the httpapi POST {prefix}/jobs/{id}/cancel route, or product code
	// calling it directly. Deliberate.
	CancelCaller CancelCause = "caller"
)

// String renders a cause for logs, naming the zero value instead of
// printing an empty string.
func (c CancelCause) String() string {
	if c == CancelUnknown {
		return "unknown"
	}
	return string(c)
}

// Job kinds.
const (
	JobKindInstall        = "install"
	JobKindUninstall      = "uninstall" // Remove: footprint removed, entry deleted
	JobKindDisable        = "disable"   // Patch disabled:true: footprint removed, entry kept
	JobKindUpdate         = "update"
	JobKindReconcile      = "reconcile"       // converge disk to intent (install missing + disable extras)
	JobKindCatalogRefresh = "catalog-refresh" // fetch + verify + swap the published catalog
)

// Job is one queued/running/finished unit of engine work.
type Job struct {
	ID    string   `json:"id"`
	Kind  string   `json:"kind"`
	State string   `json:"state"`
	Error string   `json:"error,omitempty"`
	Names []string `json:"names,omitempty"`
	// CancelCause names who cancelled the job (State JobCancelled only).
	// Additive on the wire: omitted whenever the cause is unknown, so a
	// consumer that ignores the field sees exactly the payload it saw
	// before — JobCancelled keeps its meaning and value.
	CancelCause CancelCause `json:"cancel_cause,omitempty"`
	// OutputTail carries the job's most recent output lines; populated
	// by Jobs() snapshots only (live output streams via the
	// Config.OnJobOutput callback).
	OutputTail []string `json:"output_tail,omitempty"`
	// Timestamps are Unix milliseconds.
	CreatedAt int64 `json:"created_at"`
	StartedAt int64 `json:"started_at,omitempty"`
	EndedAt   int64 `json:"ended_at,omitempty"`
}

// ToolInfo is one tool row in Inventory: the manifest entry joined with
// the engine's install state.
type ToolInfo struct {
	Name             string   `json:"name"`
	Source           string   `json:"source,omitempty"`
	Version          string   `json:"version,omitempty"`
	Description      string   `json:"description,omitempty"`
	Origin           string   `json:"origin,omitempty"`
	InstalledVersion string   `json:"installed_version,omitempty"`
	Latest           string   `json:"latest,omitempty"`
	LastError        string   `json:"last_error,omitempty"`
	Requires         []string `json:"requires,omitempty"`
	Pin              bool     `json:"pin,omitempty"`
	Disabled         bool     `json:"disabled,omitempty"`
	// Lsp marks a language-server entry (catalog knowledge); consumers
	// use it for the no-LSP-enabled warning and UI badges.
	Lsp        bool `json:"lsp,omitempty"`
	Installed  bool `json:"installed"`
	Installing bool `json:"installing"`
}

// SystemTool is one image-baked binary surfaced read-only (Config.System).
type SystemTool struct {
	Name      string `json:"name"`
	Installed bool   `json:"installed"`
}

// Inventory is the full read-side snapshot: every manifest entry joined
// with state, the system group, and the active job.
type Inventory struct {
	Job    *Job         `json:"job,omitempty"`
	Tools  []ToolInfo   `json:"tools"`
	System []SystemTool `json:"system"`
}

// ReconcileMode selects how much a Reconcile job does.
type ReconcileMode int

const (
	// ReconcileMissing converges intent without network: installs
	// missing enabled entries, uninstalls the engine-owned footprint of
	// disabled ones. Zero fetches when already converged.
	ReconcileMissing ReconcileMode = iota
	// ReconcileFull is ReconcileMissing plus an update pass over
	// unpinned entries (enqueued as a separate update job).
	ReconcileFull
)

// CatalogInfo reports the live catalog's provenance and freshness (the
// Engine.CatalogInfo return and the httpapi GET catalog body).
type CatalogInfo struct {
	// Refs are the upstream registry refs the catalog was compiled
	// from; Generated its compile timestamp (RFC 3339 UTC). Both are
	// informational pass-throughs of the catalog document.
	Refs      map[string]string `json:"refs,omitempty"`
	Generated string            `json:"generated,omitempty"`
	// Source is where the live catalog came from: baked (the image
	// file), cached (the refresh cache, reloaded at boot), remote
	// (fetched this process lifetime), or none (degraded, no catalog).
	Source string `json:"source"`
	// URL is the configured refresh source (empty when refresh is not
	// configured).
	URL string `json:"url,omitempty"`
	// LastError is the most recent refresh failure ("" after a
	// successful refresh).
	LastError string `json:"last_error,omitempty"`
	Entries   int    `json:"entries"`
	// FetchedAt is the last successful refresh (Unix milliseconds; 0
	// before the first).
	FetchedAt int64 `json:"fetched_at,omitempty"`
	// Scheduled reports whether the engine-owned background refresh
	// loop is running.
	Scheduled bool `json:"scheduled"`
}
