package toolbelt

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
)

// CatalogEntry is one tool in the compiled catalog: the mise-registry
// name/description joined with the preferred install source and, for
// aqua sources, the embedded aqua package definition. Overlay entries
// (curated) may add requires/manual install commands and the lsp
// marker.
// Its slice fields (Aliases, Requires, VersionArgs) and its Aqua pointer ALIAS
// the catalog they were read from. A Catalog is swapped whole behind an
// atomic.Pointer and never edited in place, so every reader shares one copy and
// none of them may write to it: mutating a returned entry's slice corrupts the
// catalog for every other caller. Copy what you intend to change — see
// mergeCatalogDefaults, which clones before hydrating a mutable manifest row.
type CatalogEntry struct {
	Aqua        *AquaPackage `json:"aqua,omitempty"`
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	Source      string       `json:"source"`
	// Version is the default pinned version for entries without an
	// upstream version source (manual installs).
	Version   string   `json:"version,omitempty"`
	Install   string   `json:"install,omitempty"`   // manual-source entries
	Uninstall string   `json:"uninstall,omitempty"` // manual-source entries
	Probe     string   `json:"probe,omitempty"`     // manual-source entries
	Aliases   []string `json:"aliases,omitempty"`
	Requires  []string `json:"requires,omitempty"`
	// VersionArgs declares the tool's version-reporting shape, e.g.
	// ["--version"] or ["version"]. Hydrated onto manifest entries, it
	// upgrades the install probe from "the binary runs" to "the binary
	// reports the recorded version" (see Tool.VersionArgs).
	VersionArgs []string `json:"version_args,omitempty"`
	Featured    bool     `json:"featured,omitempty"`
	// Lsp marks language-server entries; drives the consumers'
	// no-LSP-enabled warning and UI badges.
	Lsp bool `json:"lsp,omitempty"`
	// Reason is set only on Catalog.Unavailable entries: the registry
	// backend the compiler could not use, e.g. "core:python" or
	// "vfox:mise-plugins/vfox-postgres". It is the whole explanation a
	// consumer can show for a tool it knows about and cannot install.
	Reason string `json:"reason,omitempty"`
	// Release carries the registry's install hints for a release-backed
	// entry (see ReleaseHints). Absent for every other source.
	Release *ReleaseHints `json:"release,omitempty"`
}

// Catalog is the compiled tool-catalog.json document.
type Catalog struct {
	// Refs records the upstream registry refs this catalog was
	// compiled from (informational).
	Refs map[string]string `json:"refs,omitempty"`
	// Licenses carries the upstream registries' license texts, keyed by
	// registry name (mise, aqua-registry). The compiled catalog embeds
	// data derived from both (MIT), and MIT requires the copyright +
	// permission notice to travel with copies — embedding the texts
	// makes every copy (baked, cached, fetched) self-contained.
	Licenses map[string]string       `json:"licenses,omitempty"`
	Entries  map[string]CatalogEntry `json:"entries"`
	// Unavailable holds registry entries for which no install source
	// exists at all: tools this catalog knows about and cannot install
	// (mise core:, vfox:, conda:, gem:, spm: backends, and aqua package
	// types the runtime evaluator does not cover). Each carries a Reason.
	//
	// Deliberately a SEPARATE map rather than a state field on Entries.
	// The compiled catalog is published to a stable URL and fetched at
	// runtime by engines of any age, so a sourceless row inside Entries
	// would reach an older engine's Search, hydrate an empty Source
	// through mergeCatalogDefaults, and fail Add on a row its UI had
	// offered. An unknown top-level key is ignored wholesale instead, so
	// an old engine behaves exactly as it does today. It also keeps the
	// Entries floor in cmd/toolcatalog meaningful: a registry that
	// compiles nothing cannot pad the count with skipped rows.
	//
	// The two key sets are disjoint (asserted at compile time), and
	// membership is architecture-INDEPENDENT: "no source exists" is a
	// fact about the registry, whereas "this release has no asset for
	// your arch" is a runtime answer belonging to the install job.
	Unavailable map[string]CatalogEntry `json:"unavailable,omitempty"`
	// aliases indexes alias -> entry name, built once at load so
	// Lookup doesn't scan ~700 entries per aliased miss on hot
	// inventory paths. Nil (a literal-constructed catalog) falls back
	// to the linear scan.
	aliases map[string]string
	// Generated is the compile timestamp (RFC 3339 UTC), stamped by
	// cmd/toolcatalog (informational).
	Generated string `json:"generated,omitempty"`
}

// parseCatalog unmarshals a compiled catalog document and builds the
// alias index. Nil entries normalize to an empty map (a degraded but
// usable catalog); a syntactically broken document errors.
func parseCatalog(data []byte) (*Catalog, error) {
	var c Catalog
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	if c.Entries == nil {
		c.Entries = map[string]CatalogEntry{}
	}
	if c.Unavailable == nil {
		c.Unavailable = map[string]CatalogEntry{}
	}
	c.aliases = buildAliasIndex(c.Entries)
	return &c, nil
}

// loadCatalogFile reads and parses one compiled catalog file.
func loadCatalogFile(path string) (*Catalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseCatalog(data)
}

// loadCatalog reads the compiled tool catalog baked into the image. A
// missing or unreadable catalog degrades gracefully: search returns
// nothing, manual/ecosystem sources still install, and entries that
// need catalog knowledge fail their jobs with a named error.
func loadCatalog(path string, log *slog.Logger) *Catalog {
	empty := &Catalog{Entries: map[string]CatalogEntry{}, Unavailable: map[string]CatalogEntry{}}
	if path == "" {
		return empty
	}
	c, err := loadCatalogFile(path)
	if err != nil {
		log.Warn("toolbelt: catalog unavailable", "path", path, "error", err)
		return empty
	}
	log.Info("toolbelt: catalog loaded", "entries", len(c.Entries))
	return c
}

// buildAliasIndex maps every alias to its entry name.
func buildAliasIndex(entries map[string]CatalogEntry) map[string]string {
	idx := make(map[string]string)
	for name := range entries {
		for _, a := range entries[name].Aliases {
			idx[a] = name
		}
	}
	return idx
}

// Lookup finds a catalog entry by name or alias.
//
// The returned entry aliases the catalog: do not mutate its slice fields (see
// [CatalogEntry]).
func (c *Catalog) Lookup(name string) (CatalogEntry, bool) {
	if e, ok := c.Entries[name]; ok {
		return e, true
	}
	if c.aliases != nil {
		if n, ok := c.aliases[name]; ok {
			return c.Entries[n], true
		}
		return CatalogEntry{}, false
	}
	for k := range c.Entries {
		if slices.Contains(c.Entries[k].Aliases, name) {
			return c.Entries[k], true
		}
	}
	return CatalogEntry{}, false
}

// searchLimit caps catalog search responses.
const searchLimit = 25

// Search ranks catalog entries against a query: exact name, name
// prefix, alias, name substring, then description substring. Empty
// query returns the featured set.
//
// The returned entries alias the catalog: do not mutate their slice fields
// (see [CatalogEntry]).
func (c *Catalog) Search(query string) []CatalogEntry {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return c.Featured()
	}
	return rankEntries(c.Entries, q)
}

// SearchUnavailable ranks the entries no install source exists for
// (see [Catalog.Unavailable]) with the same scoring Search uses, so a
// consumer can tell a user that a tool is known and why it cannot be
// installed instead of showing an empty result. An empty query returns
// nothing: the unavailable set has no featured members and listing 200
// uninstallable tools is not a browse surface.
//
// The returned entries alias the catalog: do not mutate their slice fields
// (see [CatalogEntry]).
func (c *Catalog) SearchUnavailable(query string) []CatalogEntry {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return nil
	}
	return rankEntries(c.Unavailable, q)
}

// rankEntries scores one entry map against a lowercased query and
// returns the best searchLimit matches.
//
// Ties break on NAME LENGTH before name, and that is load-bearing rather
// than cosmetic. Every prefix match scores the same, so with a
// name-ascending tie-break alone a short exact-ish name loses to every
// alphabetically-earlier longer one that shares its prefix. Measured
// over Debian trixie's 68,799 package names, `python3` ranked 909th of
// 6,607 hits for the query "python" (behind python-acme-doc and 907
// siblings) and `nodejs` ranked 1,701st for "node"; with the length
// tie-break they rank 1st and 3rd. The catalog's own corpus benefits the
// same way, so the fix belongs here and not in a per-corpus wrapper.
func rankEntries(entries map[string]CatalogEntry, q string) []CatalogEntry {
	type scored struct {
		e     CatalogEntry
		score int
	}
	var hits []scored
	for name := range entries {
		e := entries[name]
		score := matchScore(name, &e, q)
		if score == 0 {
			continue
		}
		hits = append(hits, scored{e, score})
	}
	slices.SortStableFunc(hits, func(a, b scored) int {
		// score descending, then name length ascending, then name ascending.
		return cmp.Or(
			cmp.Compare(b.score, a.score),
			cmp.Compare(len(a.e.Name), len(b.e.Name)),
			cmp.Compare(a.e.Name, b.e.Name),
		)
	})
	lim := min(len(hits), searchLimit)
	out := make([]CatalogEntry, 0, lim)
	for i := range hits[:lim] {
		out = append(out, hits[i].e)
	}
	return out
}

func matchScore(name string, e *CatalogEntry, q string) int {
	ln := strings.ToLower(name)
	switch {
	case ln == q:
		return 100
	case strings.HasPrefix(ln, q):
		return 80
	}
	for _, a := range e.Aliases {
		la := strings.ToLower(a)
		if la == q {
			return 90
		}
		if strings.HasPrefix(la, q) {
			return 70
		}
	}
	if strings.Contains(ln, q) {
		return 50
	}
	if strings.Contains(strings.ToLower(e.Description), q) {
		return 20
	}
	return 0
}

// Featured returns the curated starter set (empty-state content),
// sorted by name.
//
// The returned entries alias the catalog: do not mutate their slice fields
// (see [CatalogEntry]).
func (c *Catalog) Featured() []CatalogEntry {
	var out []CatalogEntry
	for k := range c.Entries {
		if c.Entries[k].Featured {
			out = append(out, c.Entries[k])
		}
	}
	slices.SortFunc(out, func(a, b CatalogEntry) int { return cmp.Compare(a.Name, b.Name) })
	if len(out) > searchLimit {
		out = out[:searchLimit]
	}
	return out
}

// ParseRequireList extracts tool names from a requirements list: one
// name per line, # comments and blank lines ignored — the shape
// required-tools.txt files use across the fleet (cmd/toolcatalog verify
// reads the same format). Shared here so consumers embedding their list
// for CatalogRefresh.Require parse it identically to the build gate.
func ParseRequireList(raw string) []string {
	var names []string
	for line := range strings.SplitSeq(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		names = append(names, line)
	}
	return names
}

// VerifyCatalog checks that every required name resolves in the catalog
// to install knowledge the engine can act on, offline: a non-empty
// source; for aqua sources an embedded definition that parses its
// templates and claims linux support on both amd64 and arm64; for
// manual sources an install command. One error per failing name; nil
// means the catalog satisfies the requirement set. Consumers run this
// at image build (cmd/toolcatalog verify) over their required names so
// a registry drift fails the build instead of a boot job.
func VerifyCatalog(c *Catalog, require []string) []error {
	var errs []error
	for _, name := range require {
		if err := verifyEntry(c, name); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}
	return errs
}

func verifyEntry(c *Catalog, name string) error {
	e, ok := c.Lookup(name)
	if !ok {
		// A required name that compiled into Unavailable is a REQUIREMENT
		// failure, not a missing name, and saying so is the difference
		// between "the registry renamed it" and "the registry stopped
		// giving us a way to install it". Without this branch the floor
		// gate weakens silently the moment a required tool's backend
		// changes upstream.
		if u, uok := c.Unavailable[name]; uok {
			if u.Reason != "" {
				return fmt.Errorf("no install source (%s)", u.Reason)
			}
			return errors.New("no install source")
		}
		return errors.New("not in the catalog")
	}
	if e.Source == "" {
		return errors.New("catalog entry has no source")
	}
	kind, _, _ := strings.Cut(e.Source, ":")
	switch kind {
	case "aqua":
		if e.Aqua == nil {
			return errors.New("aqua source without an embedded definition")
		}
		for _, arch := range []string{"amd64", "arm64"} {
			if !e.Aqua.SupportsLinux(arch) {
				return fmt.Errorf("definition does not support linux/%s", arch)
			}
		}
		if err := e.Aqua.CheckTemplates(); err != nil {
			return err
		}
	case "manual":
		if strings.TrimSpace(e.Install) == "" {
			return errors.New("manual source without an install command")
		}
	}
	return nil
}

// overlayDoc is an overlay document: entries keyed by tool name. An
// entry with a source replaces/creates the whole catalog entry; an
// entry without one patches display fields (featured, lsp, description,
// requires, probe) onto the compiled entry.
type overlayDoc struct {
	Entries map[string]CatalogEntry `json:"entries"`
}

// ApplyOverlay merges one overlay JSON document into the catalog.
// Shared by cmd/toolcatalog (compile time: base + app overlays) and the
// engine's catalog load/refresh pipeline (runtime: consumer overlay
// files re-applied over every fetched catalog, so display patches
// survive refreshes).
//
// resolveAqua, when non-nil, loads an aqua install definition for a
// source-bearing `aqua:` entry that does not embed one — the compile
// case, where cmd/toolcatalog passes a registry-checkout loader. At
// runtime there is no registry checkout: pass nil, and source-bearing
// aqua entries must carry their definition inline (display-field
// patches, the common runtime overlay, need no definition at all).
func ApplyOverlay(c *Catalog, data []byte, resolveAqua func(ref string) (*AquaPackage, error)) error {
	var ov overlayDoc
	if err := json.Unmarshal(data, &ov); err != nil {
		return err
	}
	return applyOverlayDoc(c, ov, resolveAqua)
}

// applyOverlayDoc is ApplyOverlay's core over a parsed document.
func applyOverlayDoc(c *Catalog, ov overlayDoc, resolveAqua func(ref string) (*AquaPackage, error)) error {
	for name := range ov.Entries {
		patch := ov.Entries[name]
		if patch.Source == "" {
			// A display patch targets whichever map holds the name. An
			// unavailable entry is patchable too: its description is what a
			// consumer shows beside the reason, and refusing here would make
			// an overlay's currency depend on whether the registry happened
			// to compile that tool this week.
			if cur, ok := c.Entries[name]; ok {
				mergeOverlayEntry(&cur, &patch)
				c.Entries[name] = cur
				continue
			}
			cur, ok := c.Unavailable[name]
			if !ok {
				return fmt.Errorf("overlay patches unknown tool %q", name)
			}
			mergeOverlayEntry(&cur, &patch)
			c.Unavailable[name] = cur
			continue
		}
		if err := overlayReplaceEntry(name, &patch, resolveAqua); err != nil {
			return err
		}
		c.Entries[name] = patch
		// An overlay supplying a source is exactly how a tool the compiler
		// skipped becomes installable (node, go, java, rust and glab are all
		// mise core:/gitlab: drops that overlays.json revives). Without this
		// delete, all five sit in BOTH maps: the invariants pass for each row
		// on its own, Search offers the installable one, SearchUnavailable
		// simultaneously reports it as having no installer, and the two
		// answers disagree with no way for a consumer to tell which is true.
		delete(c.Unavailable, name)
	}
	// Overlay entries may add names and aliases; rebuild the index.
	c.aliases = buildAliasIndex(c.Entries)
	return nil
}

// overlayReplaceEntry finalizes a source-bearing overlay entry in
// place: stamps the name and resolves a bare aqua: source into an
// embedded definition via the hook (compile time) or refuses (runtime,
// nil hook).
func overlayReplaceEntry(name string, patch *CatalogEntry, resolveAqua func(ref string) (*AquaPackage, error)) error {
	patch.Name = name
	ref, isAqua := strings.CutPrefix(patch.Source, "aqua:")
	if !isAqua || patch.Aqua != nil {
		return nil
	}
	if resolveAqua == nil {
		return fmt.Errorf("overlay %q: aqua source without an embedded definition", name)
	}
	aq, err := resolveAqua(ref)
	if err != nil {
		return fmt.Errorf("overlay %q: %w", name, err)
	}
	patch.Aqua = aq
	return nil
}

// mergeOverlayEntry patches display fields of a compiled entry.
func mergeOverlayEntry(cur, patch *CatalogEntry) {
	if patch.Featured {
		cur.Featured = true
	}
	if patch.Lsp {
		cur.Lsp = true
	}
	if patch.Description != "" {
		cur.Description = patch.Description
	}
	if patch.Requires != nil {
		cur.Requires = patch.Requires
	}
	if patch.Probe != "" {
		cur.Probe = patch.Probe
	}
}
