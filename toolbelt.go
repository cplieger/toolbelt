// Package toolbelt provisions developer tools onto a persistent volume,
// declaratively. A manifest (tools.json) records intent; a compiled
// catalog carries install knowledge; the Engine reconciles installed
// state against intent through a single-flight job queue, never
// touching unmanaged files.
//
//	<ConfigDir>/tools.json       — user intent, re-read every operation.
//	<ConfigDir>/tools-state.json — engine-owned machine state.
//	<ToolsDir>/opt/<name>/<ver>/ — versioned install trees.
//	<ToolsDir>/bin               — the single PATH dir (symlinks).
//
// CatalogPath (compiled by cmd/toolcatalog) is read-only; a missing
// catalog degrades to manual and ecosystem sources only. Install
// sources: aqua-registry, npm, pip (via uv), cargo, go install, and a
// manual bash escape hatch.
package toolbelt

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cplieger/ssrf/v4"
)

// Source prefixes for Tool.Source. A source is "<kind>:<ref>" except
// SourceManual which stands alone.
const (
	SourceAqua    = "aqua"    // aqua:owner/repo — evaluated aqua-registry definition
	SourceNpm     = "npm"     // npm:package
	SourcePip     = "pip"     // pip:package (installed via uv)
	SourceCargo   = "cargo"   // cargo:crate
	SourceGo      = "go"      // go:module/path
	SourceApt     = "apt"     // apt:package — Debian package, container layer
	SourceRelease = "release" // release:<github|gitlab>/owner/repo — forge release asset
	SourceManual  = "manual"  // user-provided install command
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
	// Refresh, when non-nil, enables runtime catalog refresh: fetches
	// the published catalog at Refresh.URL (on the engine-owned
	// schedule, or on demand via RefreshCatalog), verifies it against
	// Refresh.Require, caches it under ConfigDir, and swaps it in
	// atomically. The last good catalog stands on any failure. Nil
	// keeps the baked catalog static for the process lifetime.
	Refresh *CatalogRefresh
	// CatalogOverlays are consumer overlay JSON files (see
	// ApplyOverlay) applied to every catalog the engine loads, keeping
	// app-specific display patches independent of the published
	// artifact. A runtime overlay must embed any aqua definition inline
	// — there is no registry checkout to resolve from at runtime.
	CatalogOverlays []string
	// System names image-baked binaries surfaced read-only in
	// Inventory's System group (informational; not managed).
	System []string
	// KeepVersions is how many SUPERSEDED versions of a tool to retain
	// under <ToolsDir>/opt/<name>/ (the current version is always kept),
	// so a bad update can be rolled back. 0 means DefaultKeepVersions; a
	// negative value keeps none.
	KeepVersions int
	// VerifyRootIntegrity makes New REFUSE to construct an Engine over
	// managed roots it cannot safely execute from (see rootintegrity.go).
	// Off by default; turn it on when the tool tree lives on an
	// operator-controlled volume and the process runs privileged. A
	// failure returns ErrRootIntegrity as a *RootIntegrityError
	// (errors.As), logged at Error before New returns.
	VerifyRootIntegrity bool
}

// Engine is the tools subsystem: the single owner of the manifest and
// install tree, the job queue, and the catalog. Construct with New.
//
// The manifest store's single-writer guarantee is an in-process lock:
// every other process (a CLI, an agent) must go through the consumer's
// server rather than linking toolbelt against the same data dirs.
type Engine struct {
	// aptSeen lists installed apt packages with no manifest row: what the
	// image asked for and what a user or an agent installed in the shell.
	// Read-only, cached, invalidated when this engine runs an apt job.
	aptSeen *aptDiscovery
	store   *store
	// catalog is the live catalog, swapped atomically by the refresh
	// job. Readers take a snapshot via cat() and never see a partial
	// swap; a snapshot taken before a swap stays internally consistent
	// for the duration of that operation.
	catalog atomic.Pointer[Catalog]
	// aptIdx is the Debian package list: the apt search corpus and the
	// literal-name oracle the install gate consults. Lazily refreshed by
	// the first search that asks for apt results, never at boot (see
	// aptIndex).
	aptIdx          *aptIndex
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
	// probes memoizes install probes: presence is always re-checked, the
	// execution verdict is cached per binary fingerprint.
	probes    probeCache
	catState  catalogState
	refreshWG sync.WaitGroup
	// keepVersions mirrors Config.KeepVersions (0 = DefaultKeepVersions).
	keepVersions int
}

// cat returns the current catalog snapshot.
func (e *Engine) cat() *Catalog { return e.catalog.Load() }

// backends is the source-kind-to-backend-tool map the dependency edge
// reads, taken from the loaded catalog. Nil is fine: backendFor falls
// back per kind, so an engine with no catalog at all still adopts the
// standard backends.
func (e *Engine) backends() map[string]string {
	c := e.cat()
	if c == nil {
		return nil
	}
	return c.Backends
}

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
//
// With Config.VerifyRootIntegrity set, the managed roots are inspected
// FIRST — before any file is written or directory created — and an
// unfit root refuses construction with ErrRootIntegrity. New is the
// seam on purpose: Inventory and EnsureInstalled probe synchronously
// too, so gating only the reconcile queue would leave those paths open.
func New(cfg *Config) (*Engine, error) {
	if cfg.ConfigDir == "" || cfg.ToolsDir == "" {
		return nil, errors.New("toolbelt: ConfigDir and ToolsDir are required")
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	// Before newStore: st.initFiles() writes tools.json and CREATES
	// ConfigDir, so a check placed after it would be judging a directory
	// this library just made. Before the bin/ creation further down, which
	// resolves every ancestor component by name (only the leaf mkdir refuses
	// a symlink). And before newJobQueue, whose worker goroutine an error
	// returned afterwards would leak (the caller gets a nil Engine and can
	// never Close it).
	if cfg.VerifyRootIntegrity {
		if err := verifyRootIntegrity(log, cfg.ConfigDir, cfg.ToolsDir); err != nil {
			return nil, fmt.Errorf("toolbelt: %w", err)
		}
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
		log:             log,
		configDir:       cfg.ConfigDir,
		toolsDir:        cfg.ToolsDir,
		system:          cfg.System,
		keepVersions:    cfg.KeepVersions,
	}
	e.initCatalog(cfg)
	e.queue = newJobQueue(cfg.OnJobChanged, cfg.OnJobOutput, log, e.executeJob)
	// One index, shared by the three things that need a package list: the
	// search corpus, the installer's literal-name oracle, and the version
	// resolver's apt-cache read. Constructed before both so neither can
	// hold a nil one.
	e.aptIdx = newAptIndex(log)
	e.aptSeen = &aptDiscovery{}
	// One token cache too, for the same reason: the version resolver and
	// the release installer each spend a GitHub API call per install, and
	// the anonymous rate limit is per PROCESS, not per caller.
	tokens := &githubTokenCache{}
	e.versions = newVersionResolver(client, e.aptIdx, tokens)
	e.inst = &installer{
		toolsDir: cfg.ToolsDir,
		client:   client,
		log:      log,
		output:   func(string) {},
		aptIdx:   e.aptIdx,
		tokens:   tokens,
	}
	// ensureManagedDir, not MkdirAll: this is where bin/ is normally BORN,
	// so it is the only place the mode the filesystem stored for it can
	// still be certified. linkBin re-establishes the same directory later
	// and enforces there too, but by then this call has already created it,
	// so leaving this one unverified would make that enforcement dead code
	// in every flow that goes through New.
	if err := ensureManagedDir(filepath.Join(cfg.ToolsDir, "bin")); err != nil {
		return nil, err
	}
	e.startCatalogSchedule()
	return e, nil
}

// Close stops the catalog-refresh schedule, then the job worker
// (cancelling any running job and draining the queued ones). Every job
// it cancels reports CancelShutdown as its CancelCause, so a consumer
// can tell an ordinary shutdown from an operator's deliberate cancel.
func (e *Engine) Close() {
	if e.stopRefresh != nil {
		e.stopRefresh()
	}
	e.refreshWG.Wait()
	e.queue.Close()
}

// DefaultSeed returns the shared starter manifest: the officially
// supported language servers for Go, TypeScript, and Python plus the
// GitHub CLI, all disabled. Nothing downloads until enabled; install
// knowledge hydrates from the catalog at enable time.
//
// Backend runtimes and required packages are deliberately NOT seeded:
// the engine adopts a missing dependency at install time, so a seeded
// row would only be a second place for its version to drift. Returns a
// fresh copy on every call.
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
			"rust-analyzer":              {Disabled: true},
			"gh":                         {Disabled: true},
		},
	}
}
