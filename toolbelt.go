// Package toolbelt provisions developer tools onto a persistent volume,
// declaratively. A manifest (tools.json) records intent: which tools, at
// which versions, enabled or disabled. A compiled catalog carries install
// knowledge (sources, artifact templates, checksum locations,
// dependencies). The Engine reconciles installed state against intent
// through a single-flight job queue: enabled-but-missing tools are
// installed, disabled-but-installed tools are uninstalled (their template
// kept), unmanaged files are never touched.
//
// Data files (all under the consumer's persistent config volume):
//
//	<ConfigDir>/tools.json       — the manifest: user intent. Toolbelt is
//	                               the only writer, but out-of-band hand
//	                               edits are supported by design (the file
//	                               is re-read on every operation).
//	<ConfigDir>/tools-state.json — engine-owned machine state (installed
//	                               version, owned bin names, last error).
//	<ToolsDir>/opt/<name>/<ver>/ — versioned install trees.
//	<ToolsDir>/bin               — the single PATH dir (symlinks).
//
// The catalog (CatalogPath, compiled at image build by cmd/toolcatalog) is
// read-only environment data; a missing catalog degrades to manual and
// ecosystem sources only, and entries that need catalog knowledge fail
// their jobs with a named error.
//
// Install sources: aqua-registry artifact definitions (with upstream
// checksum verification when the definition declares a source), npm, pip
// (via uv), cargo, go install, and a manual bash escape hatch. No external
// package-manager binary ships with the library; ecosystem backends are
// themselves installable tools (npm needs node, pip needs uv, ...), and
// the engine adopts those backend dependencies automatically.
package toolbelt

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cplieger/ssrf/v3"
)

// Source prefixes for Tool.Source. A source is "<kind>:<ref>" except
// SourceManual which stands alone.
const (
	SourceAqua   = "aqua"   // aqua:owner/repo — evaluated aqua-registry definition
	SourceNpm    = "npm"    // npm:package
	SourcePip    = "pip"    // pip:package (installed via uv)
	SourceCargo  = "cargo"  // cargo:crate
	SourceGo     = "go"     // go:module/path
	SourceManual = "manual" // user-provided install command
)

// ManifestVersion is the manifest schema version this engine reads and
// writes — the only version it accepts. A manifest with any other
// version (or one that fails to parse) is an error at engine start.
const ManifestVersion = 2

// Config wires an Engine. ConfigDir and ToolsDir are required.
type Config struct {
	// OnJobChanged, when non-nil, receives every job state transition
	// (queued, running, done, failed, cancelled). Views carry no output
	// tail; stream output via OnJobOutput or poll Jobs().
	OnJobChanged func(*Job)
	// OnJobOutput, when non-nil, receives coalesced batches of a running
	// job's output lines (~150 ms cadence).
	OnJobOutput func(jobID string, lines []string)
	// Logger receives engine-level log lines. Nil means slog.Default().
	Logger *slog.Logger
	// Seed is the manifest written when none exists (fresh volume).
	// Nil seeds an empty manifest. See DefaultSeed.
	Seed *Manifest
	// ConfigDir holds tools.json + tools-state.json (the persistent
	// config volume root).
	ConfigDir string
	// ToolsDir is the install tree root (bin/, opt/, npm/, python/).
	ToolsDir string
	// CatalogPath is the compiled catalog baked into the consumer's
	// image (optional; missing = degraded search + named install errors
	// for catalog-dependent entries). With Refresh configured this is
	// the first-boot/offline fallback: a valid refresh cache under
	// ConfigDir takes precedence at construction.
	CatalogPath string
	// Refresh, when non-nil, enables runtime catalog refresh: the
	// engine fetches the published catalog at Refresh.URL (on the
	// engine-owned schedule when Interval is positive, and on demand
	// via RefreshCatalog), verifies it against Refresh.Require, caches
	// it under ConfigDir, and swaps it in atomically. The last good
	// catalog stands on any failure. Nil keeps the baked catalog
	// static for the process lifetime (the pre-refresh behavior).
	Refresh *CatalogRefresh
	// CatalogOverlays are consumer overlay JSON files (see
	// ApplyOverlay) applied in order to every catalog the engine
	// loads: the baked file, the refresh cache, and each fetched
	// refresh. This keeps app-specific display patches independent of
	// the published artifact. Entries added by a runtime overlay must
	// embed any aqua definition inline (there is no registry checkout
	// to resolve from at runtime).
	CatalogOverlays []string
	// System names image-baked binaries surfaced read-only in
	// Inventory's System group (informational; not managed).
	System []string
}

// Engine is the tools subsystem: the single owner of the manifest and
// install tree, the job queue, and the catalog. Construct with New.
//
// The manifest store's single-writer guarantee is an in-process lock:
// every other process (a CLI, an agent) must go through the consumer's
// server rather than linking toolbelt against the same data dirs.
type Engine struct {
	store *store
	// catalog is the live catalog, swapped atomically by the refresh
	// job. Readers take a snapshot via cat() and never see a partial
	// swap; a snapshot taken before a swap stays internally consistent
	// for the duration of that operation.
	catalog         atomic.Pointer[Catalog]
	refresh         *CatalogRefresh
	stopRefresh     context.CancelFunc
	client          *http.Client
	queue           *jobQueue
	inst            *installer
	versions        *versionResolver
	log             *slog.Logger
	catalogOverlays []string
	system          []string
	configDir       string
	toolsDir        string
	catState        catalogState
	refreshWG       sync.WaitGroup
}

// cat returns the current catalog snapshot.
func (e *Engine) cat() *Catalog { return e.catalog.Load() }

// urlPolicyTransport validates every request URL (including redirect
// hops re-entering RoundTrip) against the SSRF URL policy before the
// underlying transport dials.
type urlPolicyTransport struct {
	next   http.RoundTripper
	policy ssrf.URLPolicy
}

func (t urlPolicyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.policy.Validate(req.URL.String()); err != nil {
		return nil, err
	}
	return t.next.RoundTrip(req)
}

// newEngineClient builds the engine's outbound HTTP client. Downloads
// and version checks go to registry-defined public URLs: validate every
// initial target and redirect before SafeTransport enforces public
// resolved and connected IPs at the dial boundary. Extracted so the
// composition (URL policy + redirect policy + hardened transport) has
// offline test coverage; the dial-time behavior stays covered by the
// ssrf library's own suite.
func newEngineClient() *http.Client {
	return &http.Client{
		Transport: urlPolicyTransport{
			next:   ssrf.SafeTransport(ssrf.WithAllowedPorts(443)),
			policy: ssrf.NewURLPolicy(),
		},
		CheckRedirect: ssrf.SafeRedirectPolicy(nil),
		// Per-attempt bound: retry loops (httpx.GetBytes / httpx.Do) sit
		// OUTSIDE client.Do, so this caps one attempt, not the sequence.
		Timeout: 15 * time.Minute,
	}
}

// New constructs and starts an Engine: initializes the manifest files
// (seeding when absent; a manifest of any other schema version is an
// error) and launches the job worker.
func New(cfg *Config) (*Engine, error) {
	if cfg.ConfigDir == "" || cfg.ToolsDir == "" {
		return nil, errors.New("toolbelt: ConfigDir and ToolsDir are required")
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	st := newStore(cfg.ConfigDir, cfg.Seed, log)
	if err := st.initFiles(); err != nil {
		return nil, fmt.Errorf("toolbelt: init manifest: %w", err)
	}
	client := newEngineClient()
	e := &Engine{
		store:           st,
		refresh:         cfg.Refresh,
		catalogOverlays: cfg.CatalogOverlays,
		client:          client,
		versions:        newVersionResolver(client),
		log:             log,
		configDir:       cfg.ConfigDir,
		toolsDir:        cfg.ToolsDir,
		system:          cfg.System,
	}
	e.initCatalog(cfg)
	e.queue = newJobQueue(cfg.OnJobChanged, cfg.OnJobOutput, log, e.executeJob)
	e.inst = &installer{toolsDir: cfg.ToolsDir, client: client, output: func(string) {}}
	if err := os.MkdirAll(filepath.Join(cfg.ToolsDir, "bin"), 0o755); err != nil {
		return nil, err
	}
	e.startCatalogSchedule()
	return e, nil
}

// Close stops the catalog-refresh schedule, then the job worker
// (cancelling any running job).
func (e *Engine) Close() {
	if e.stopRefresh != nil {
		e.stopRefresh()
	}
	e.refreshWG.Wait()
	e.queue.Close()
}

// DefaultSeed returns the shared starter manifest: the officially
// supported language servers for Go, TypeScript, and Python plus the
// GitHub CLI, all disabled. Nothing downloads until an entry is
// enabled; install knowledge (source, dependencies, version) hydrates
// from the catalog at enable time. Backend runtimes (node, go) and
// required packages (typescript) are deliberately NOT seeded: the
// engine auto-adopts missing dependencies at install time, whereas a
// seeded-but-disabled dependency REFUSES dependent installs
// ("dependency X is disabled; enable it first" — a disabled entry is
// user policy). Returns a fresh copy on every call.
func DefaultSeed() *Manifest {
	return &Manifest{
		Version: ManifestVersion,
		Comment: []string{
			"Tool templates. Entries with \"disabled\": true are preinstalled examples:",
			"enable one to install it (set \"disabled\": false, or use the tools API/UI),",
			"then restart or trigger a reconcile. Add more tools by name; install",
			"knowledge (source, dependencies, version) comes from the built-in",
			"catalog.",
		},
		Tools: map[string]Tool{
			"gopls":                      {Disabled: true},
			"typescript-language-server": {Disabled: true},
			"pyright":                    {Disabled: true},
			"gh":                         {Disabled: true},
		},
	}
}
