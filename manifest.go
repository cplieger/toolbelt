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
	"sync"
	"time"

	"github.com/cplieger/atomicfile/v2"
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
	return &m, nil
}

func (s *store) writeManifestLocked(m *Manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	_, err = atomicfile.WriteFile(context.Background(), s.manifestPath, append(data, '\n'),
		atomicfile.WithMode(0o644), atomicfile.WithMkdirMode(0o755))
	return err
}

// Manifest returns a copy of the current manifest (Tool values are
// copied by value; callers must not mutate maps/slices inside them).
func (s *store) Manifest() (*Manifest, error) {
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

// MutateState applies fn to the machine state and persists it. State
// write failures are logged, not fatal — state is reconstructible.
func (s *store) MutateState(fn func(*State)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.readStateLocked()
	fn(&st)
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		s.log.Error("toolbelt: marshal state", "error", err)
		return
	}
	if _, err := atomicfile.WriteFile(context.Background(), s.statePath, append(data, '\n'),
		atomicfile.WithMode(0o644), atomicfile.WithMkdirMode(0o755)); err != nil {
		s.log.Error("toolbelt: write state", "error", err)
	}
}

// setToolStatus records a status update for one tool.
func (s *store) setToolStatus(name string, fn func(*ToolStatus)) {
	s.MutateState(func(st *State) {
		cur := st.Tools[name]
		fn(&cur)
		cur.UpdatedAt = time.Now().UTC()
		st.Tools[name] = cur
	})
}

// dropToolStatus removes a tool's machine state entirely (uninstall).
func (s *store) dropToolStatus(name string) {
	s.MutateState(func(st *State) {
		delete(st.Tools, name)
	})
}
