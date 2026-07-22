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
