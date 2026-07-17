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
	JobKindInstall   = "install"
	JobKindUninstall = "uninstall" // Remove: footprint removed, entry deleted
	JobKindDisable   = "disable"   // Patch disabled:true: footprint removed, entry kept
	JobKindUpdate    = "update"
	JobKindReconcile = "reconcile" // converge disk to intent (install missing + disable extras)
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
	Shims            map[string]string `json:"shims,omitempty"`
	Name             string            `json:"name"`
	Source           string            `json:"source,omitempty"`
	Version          string            `json:"version,omitempty"`
	Description      string            `json:"description,omitempty"`
	Origin           string            `json:"origin,omitempty"`
	InstalledVersion string            `json:"installed_version,omitempty"`
	Latest           string            `json:"latest,omitempty"`
	LastError        string            `json:"last_error,omitempty"`
	Requires         []string          `json:"requires,omitempty"`
	Pin              bool              `json:"pin,omitempty"`
	Disabled         bool              `json:"disabled,omitempty"`
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
