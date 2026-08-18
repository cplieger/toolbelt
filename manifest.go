package toolbelt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/cplieger/atomicfile/v3"
)

// Tool is one manifest entry: the user's intent for a single tool.
// Every field except the map key (the tool name) is optional; empty
// Source/Version/Requires hydrate from the catalog when the tool is
// installed or updated.
type Tool struct {
	// Source locates the install definition: "aqua:cli/cli",
	// "npm:pyright", "pip:x", "cargo:x", "go:golang.org/x/tools/gopls",
	// or "manual". Empty = hydrate from the catalog.
	Source string `json:"source,omitempty"`
	// Version is the concrete upstream version, exactly as upstream
	// tags it (may or may not carry a leading v). Never a range.
	// Empty = resolve latest when the tool is actively installed.
	Version string `json:"version,omitempty"`
	// Description is display text (catalog-provided or user-written).
	Description string `json:"description,omitempty"`
	// Origin records provenance for linked entries, e.g. "mcp:<name>"
	// for a tool created from an MCP add flow.
	Origin string `json:"origin,omitempty"`
	// Install is the shell command for Source == "manual". It runs via
	// bash with VERSION, BIN, TOOLS, OPT and ARCH_* in the environment.
	Install string `json:"install,omitempty"`
	// Uninstall optionally overrides cleanup for Source == "manual".
	Uninstall string `json:"uninstall,omitempty"`
	// Probe is the bin name whose presence marks the tool installed
	// (manual installs only; other sources derive it). Defaults to the
	// tool name.
	Probe string `json:"probe,omitempty"`
	// Requires lists other manifest/catalog tool names that must be
	// installed before (or alongside) this one, e.g. jdtls -> java.
	// Backend-level needs (npm->node, pip->uv, cargo->rust, go->go)
	// are implied and need not be listed.
	Requires []string `json:"requires,omitempty"`
	// VersionArgs are the arguments that make this tool print its
	// version, e.g. ["--version"] or ["version"]. Declaring them makes
	// the install probe verify the ANSWER: the tool is executed and its
	// output must contain the recorded version, so a binary that is
	// present but is the wrong version counts as not installed and is
	// reinstalled. Empty means the probe runs the tool with --version
	// and only requires that it answers at all (the version stays
	// unproven). Hydrated from the catalog when unset.
	VersionArgs []string `json:"version_args,omitempty"`
	// Pin freezes the version: update runs skip this tool.
	Pin bool `json:"pin,omitempty"`
	// Disabled marks the entry a template: recorded intent whose
	// install is explicitly bypassed. The reconciler uninstalls a
	// disabled tool's engine-owned footprint and keeps the entry.
	// Absent (false) means enabled — presence in the manifest is
	// intent to have the tool installed.
	Disabled bool `json:"disabled,omitempty"`
}

// Manifest is the tools.json document (schema ManifestVersion).
type Manifest struct {
	Tools map[string]Tool `json:"tools"`
	// Comment is a single reserved documentation key preserved across
	// engine rewrites (seed how-to text). Other unknown JSON keys are
	// NOT preserved; the manifest is not a general round-tripping
	// document.
	Comment []string `json:"_comment,omitempty"`
	Version int      `json:"version"`
}

// ToolStatus is the engine-owned per-tool machine state.
type ToolStatus struct {
	// UpdatedAt is when this status last changed.
	UpdatedAt time.Time `json:"updated_at"`
	// InstalledVersion is the version last installed successfully.
	InstalledVersion string `json:"installed_version,omitempty"`
	// LastError is the failure message of the most recent install
	// attempt; cleared on success.
	LastError string `json:"last_error,omitempty"`
	// Checksum records how the installed artifact's integrity was
	// established: "verified" (the definition declared a checksum
	// source and the digest matched) or "unverified" (it declared
	// none). Empty for sources without artifact checksums (npm, pip,
	// cargo, go, manual). This is the durable answer to "was this tool
	// installed unverified?".
	Checksum string `json:"checksum,omitempty"`
	// Bins are the names this tool owns in the bin dir (symlinks),
	// removed on uninstall.
	Bins []string `json:"bins,omitempty"`
	// PMBins are package-manager bin names discovered by diffing the
	// pm's bin dir (npm/pip), symlinked into the bin dir.
	PMBins []string `json:"pm_bins,omitempty"`
}

// owned reports whether the engine has recorded install state for the
// tool — the gate for uninstalling anything. Unmanaged files (same
// name, never installed by this engine) are never touched.
func (s *ToolStatus) owned() bool {
	return s.InstalledVersion != "" || len(s.Bins) > 0 || len(s.PMBins) > 0
}

// State is the tools-state.json document.
type State struct {
	Tools map[string]ToolStatus `json:"tools"`
}

// store owns tools.json (user intent) and tools-state.json (machine
// state). It is the ONLY writer of both files; every read-modify-write
// runs under mu. Files are re-read on each access so an out-of-band
// hand edit of the manifest is picked up on the next operation.
type store struct {
	seed         *Manifest
	log          *slog.Logger
	manifestPath string
	statePath    string
	mu           sync.Mutex
}

func newStore(configDir string, seed *Manifest, log *slog.Logger) *store {
	return &store{
		seed:         seed,
		log:          log,
		manifestPath: filepath.Join(configDir, "tools.json"),
		statePath:    filepath.Join(configDir, "tools-state.json"),
	}
}

// initFiles writes the seed when no manifest exists. Any existing file
// must already be schema ManifestVersion: an unparseable or
// wrong-version manifest is an error (the engine refuses to guess at
// or rewrite user intent), surfaced from New. Called once at engine
// start.
func (s *store) initFiles() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.readManifestLocked()
	if errors.Is(err, fs.ErrNotExist) {
		return s.writeManifestLocked(s.seedManifest())
	}
	return err
}

// seedManifest returns a deep copy of the configured seed (or an empty
// manifest) so later mutations never write through into Config.Seed.
func (s *store) seedManifest() *Manifest {
	if s.seed == nil {
		return &Manifest{Version: ManifestVersion, Tools: map[string]Tool{}}
	}
	cp := &Manifest{
		Version: ManifestVersion,
		Comment: append([]string{}, s.seed.Comment...),
		Tools:   make(map[string]Tool, len(s.seed.Tools)),
	}
	maps.Copy(cp.Tools, s.seed.Tools)
	return cp
}

// readManifestLocked parses tools.json. A file whose version is not
// ManifestVersion yields an error. Caller holds mu.
func (s *store) readManifestLocked() (*Manifest, error) {
	data, err := os.ReadFile(s.manifestPath)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", s.manifestPath, err)
	}
	if m.Version != ManifestVersion {
		return &m, fmt.Errorf("%s: manifest version %d (want %d)", s.manifestPath, m.Version, ManifestVersion)
	}
	if m.Tools == nil {
		m.Tools = map[string]Tool{}
	}
	// tools.json is hand-editable and re-read per operation, so a key
	// here has not necessarily been through Add's validation — and the
	// key IS a path component: it is joined onto the opt dir and the
	// join is handed to os.RemoveAll on uninstall. Validate on the way
	// in, at the one place every read path goes through, rather than
	// trusting the file. Refusing the document (like the version check
	// above) beats dropping the entry: the engine reports intent it
	// cannot use instead of silently rewriting it.
	for _, name := range slices.Sorted(maps.Keys(m.Tools)) {
		if !validToolName(name) {
			return nil, fmt.Errorf("%s: invalid tool name %q", s.manifestPath, name)
		}
	}
	return &m, nil
}

func (s *store) writeManifestLocked(m *Manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	durable, err := atomicWrite(s.manifestPath, append(data, '\n'))
	if err != nil {
		return err
	}
	if !durable {
		// Intent is recoverable (the file is user-editable and re-read
		// per operation), so a non-durable manifest commit is reported
		// rather than failed — unlike the state file below, which gates
		// pruning and must never claim more than it can stand behind.
		s.log.Warn("toolbelt: manifest write not durable", "path", s.manifestPath, "error", errNotDurable)
	}
	return nil
}

// atomicWrite publishes one engine-owned JSON file and reports whether
// the commit reached stable storage. It is a package var so durability
// tests can inject a failing write (ENOSPC) and a non-durable commit at
// the state-write barrier.
var atomicWrite = realAtomicWrite

// realAtomicWrite is the production writer: atomicfile runs the full
// protocol (write temp, fsync it, rename, fsync the parent directory), and
// Durable is false when the parent-directory barrier failed after the
// rename.
func realAtomicWrite(path string, data []byte) (durable bool, err error) {
	res, err := atomicfile.WriteFile(context.Background(), path, data,
		atomicfile.WithMode(0o644), atomicfile.WithMkdirMode(0o755))
	return res.Durable, err
}

// LoadManifest reads the manifest file under the store lock and returns a
// copy of the parsed result (Tool values are copied by value; callers must
// not mutate maps/slices inside them). It is a verb because it costs real
// work per call — the lock, a file read and a JSON decode — and a caller
// that treated it as a field access would pay for all three in a loop
// (go-rulebook C21). Named for the file it loads, beside MutateManifest.
func (s *store) LoadManifest() (*Manifest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.readManifestLocked()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &Manifest{Version: ManifestVersion, Tools: map[string]Tool{}}, nil
		}
		return nil, err
	}
	return m, nil
}

// MutateManifest applies fn to the parsed manifest and persists the
// result atomically, all under the store lock. fn returning an error
// aborts without writing.
func (s *store) MutateManifest(fn func(*Manifest) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.readManifestLocked()
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		m = &Manifest{Version: ManifestVersion, Tools: map[string]Tool{}}
	}
	if err := fn(m); err != nil {
		return err
	}
	return s.writeManifestLocked(m)
}

// State returns the current machine state (missing file = empty state).
func (s *store) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readStateLocked()
}

func (s *store) readStateLocked() State {
	st := State{Tools: map[string]ToolStatus{}}
	data, err := os.ReadFile(s.statePath)
	if err != nil {
		return st
	}
	if err := json.Unmarshal(data, &st); err != nil {
		s.log.Warn("toolbelt: state file unreadable, resetting", "error", err)
		return State{Tools: map[string]ToolStatus{}}
	}
	if st.Tools == nil {
		st.Tools = map[string]ToolStatus{}
	}
	return st
}

// MutateState applies fn to the machine state and persists it durably.
// The state file is the engine's record of what is installed, and an
// install's commit point: it gates pruning superseded versions, so a
// write that failed — or landed without reaching stable storage — is an
// ERROR the caller must fail on, not a warning. Failing here leaves the
// previous state file intact (atomicfile publishes by rename).
func (s *store) MutateState(fn func(*State)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.readStateLocked()
	fn(&st)
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	durable, err := atomicWrite(s.statePath, append(data, '\n'))
	if err != nil {
		return fmt.Errorf("write %s: %w", s.statePath, err)
	}
	if !durable {
		return fmt.Errorf("write %s: %w", s.statePath, errNotDurable)
	}
	return nil
}

// setToolStatus records a status update for one tool.
func (s *store) setToolStatus(name string, fn func(*ToolStatus)) error {
	return s.MutateState(func(st *State) {
		cur := st.Tools[name]
		fn(&cur)
		cur.UpdatedAt = time.Now().UTC()
		st.Tools[name] = cur
	})
}

// dropToolStatus removes a tool's machine state entirely (uninstall).
func (s *store) dropToolStatus(name string) error {
	return s.MutateState(func(st *State) {
		delete(st.Tools, name)
	})
}
