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
	Aqua *AquaPackage `json:"aqua,omitempty"`
	// Release carries the registry's install hints for a release-backed
	// entry (see ReleaseHints). Absent for every other source.
	Release *ReleaseHints `json:"release,omitempty"`
	// Reason is set only on Catalog.Unavailable entries: the registry
	// backend the compiler could not use, e.g. "core:python" or
	// "vfox:mise-plugins/vfox-postgres". It is the whole explanation a
	// consumer can show for a tool it knows about and cannot install.
	Reason      string `json:"reason,omitempty"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Source      string `json:"source"`
	// Version is the default pinned version for entries without an
	// upstream version source (manual installs).
	Version   string   `json:"version,omitempty"`
	Install   string   `json:"install,omitempty"`   // manual-source entries
	Uninstall string   `json:"uninstall,omitempty"` // manual-source entries
	Probe     string   `json:"probe,omitempty"`     // manual-source entries
	Aliases   []string `json:"aliases,omitempty"`
	// VersionArgs declares the tool's version-reporting shape, e.g.
	// ["--version"] or ["version"]. Hydrated onto manifest entries, it
	// upgrades the install probe from "the binary runs" to "the binary
	// reports the recorded version" (see Tool.VersionArgs).
	VersionArgs []string `json:"version_args,omitempty"`
	Requires    []string `json:"requires,omitempty"`
	Featured    bool     `json:"featured,omitempty"`
	// Lsp marks language-server entries; drives the consumers'
	// no-LSP-enabled warning and UI badges.
	Lsp bool `json:"lsp,omitempty"`
	// Essential marks a tool the PRODUCT depends on: removing it breaks a
	// feature the user did not ask to lose. The engine refuses to remove
	// such a row (ErrEssential) and a consumer groups it apart from the
	// tools a user chose, with no delete control.
	//
	// It is declared by a consumer's BUNDLED TOOLS file, never by registry
	// data, because "vibekit cannot do forge auth without gh" is a fact
	// about vibekit and not about gh. The reference carries none of these.
	//
	// The companion flag is Featured, and together they are the two
	// reasons a product bundles a tool at all: Essential means NECESSARY
	// (a feature breaks without it) and Featured means RECOMMENDED
	// (surfaced first, removable like anything else).
	//
	// It is not a lock on the version (Pin) and not a lock on the
	// installed state: an essential tool can still be updated, and it can
	// still be DISABLED, which is the escape hatch for a user who wants it
	// gone without breaking the manifest's shape. Only deletion is
	// refused, because deletion is the operation the product cannot
	// recover from silently — the row carrying the install knowledge is
	// what disappears.
	Essential bool `json:"essential,omitempty"`
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
	// Backends names the tool each source kind needs installed before it
	// can install anything: npm needs node, pip needs uv, and so on. The
	// engine adopts the named tool as a dependency (see backendFor).
	//
	// It is DATA rather than a map in the engine because it is a fact
	// about the catalog, not about the mechanism. The engine knows how to
	// run npm; which catalog entry provides npm is the catalog's answer,
	// and a consumer that bundles a different provider says so
	// here instead of patching a Go map it cannot reach. An absent or
	// partial map falls back to defaultBackends, so a catalog compiled
	// before this field existed keeps working.
	Backends map[string]string `json:"backends,omitempty"`
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
// returns the best searchLimit matches. Scoring and ordering are
// [Match] and [CompareRank], shared with the Debian package corpus.
func rankEntries(entries map[string]CatalogEntry, q string) []CatalogEntry {
	type scored struct {
		e     CatalogEntry
		score int
	}
	var hits []scored
	for name := range entries {
		e := entries[name]
		_, score := Match(name, e.Aliases, e.Description, q)
		if score == 0 {
			continue
		}
		hits = append(hits, scored{e, score})
	}
	slices.SortStableFunc(hits, func(a, b scored) int {
		return CompareRank(Rank{Name: a.e.Name, Score: a.score}, Rank{Name: b.e.Name, Score: b.score})
	})
	lim := min(len(hits), searchLimit)
	out := make([]CatalogEntry, 0, lim)
	for i := range hits[:lim] {
		out = append(out, hits[i].e)
	}
	return out
}

// MatchKind names WHICH field a search query hit. It is the one ranking
// fact a client cannot re-derive: aliases do not travel on the wire, so
// from the outside a hit on `rg` is indistinguishable from a description
// match on ripgrep's summary.
//
// It exists because a description hit is both the weakest kind and by far
// the most numerous — "python" appears in the description of every tool
// written in Python — so a consumer that groups, labels or filters results
// needs to tell it from the rest.
type MatchKind string

// The kinds, ordered by how strongly they answer the query.
const (
	// MatchNone is the zero value: the query hit nothing, or there was
	// no query to hit anything with.
	MatchNone MatchKind = ""
	// MatchName is a hit on the entry's own name.
	MatchName MatchKind = "name"
	// MatchAlias is a hit on one of the entry's aliases.
	MatchAlias MatchKind = "alias"
	// MatchDescription is a hit on the description only.
	MatchDescription MatchKind = "description"
)

// Match reports how query hits an entry, and how strongly, on one scale
// every corpus this package searches shares.
//
// ONE function rather than one per corpus. The catalog and the Debian
// package list carried byte-identical tier tables that differed only in
// that a package has no aliases, and two copies of a ranking rule is how
// a merged response ends up ordered by neither of them. Pass a nil alias
// slice for a corpus that has none.
//
// Score 0 means no match and pairs with MatchNone; every other score is
// strictly ordered, so a caller merging two corpora sorts on it directly
// (see [CompareRank]). An empty query scores 0: it selects the featured
// set rather than matching anything, and that set carries its own order.
func Match(name string, aliases []string, description, query string) (kind MatchKind, score int) {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return MatchNone, 0
	}
	ln := strings.ToLower(name)
	switch {
	case ln == q:
		return MatchName, 100
	case strings.HasPrefix(ln, q):
		return MatchName, 80
	}
	for _, a := range aliases {
		la := strings.ToLower(a)
		if la == q {
			return MatchAlias, 90
		}
		if strings.HasPrefix(la, q) {
			return MatchAlias, 70
		}
	}
	if strings.Contains(ln, q) {
		return MatchName, 50
	}
	if strings.Contains(strings.ToLower(description), q) {
		return MatchDescription, 20
	}
	return MatchNone, 0
}

// Rank is a scored hit's ordering key: what [CompareRank] needs and
// nothing else, so the same comparison serves corpora with different hit
// types.
type Rank struct {
	Name  string
	Score int
}

// CompareRank orders two scored hits: score descending, then name length
// ascending, then name ascending.
//
// Exported because THREE corpora order by it — the catalog, the Debian
// package list, and the merged response a consumer renders — and a merged
// list sorted by a different rule than the two lists feeding it is sorted
// by neither.
//
// The length tie-break is load-bearing rather than cosmetic. Every prefix
// match scores alike, so with a name-ascending tie-break alone a short
// near-exact name loses to every alphabetically-earlier longer one that
// shares its prefix. Measured over Debian trixie's 68,799 package names,
// `python3` ranked 909th of 6,607 hits for "python" (behind
// python-acme-doc and 907 siblings) and `nodejs` ranked 1,701st for
// "node"; with the length tie-break they rank 1st and 3rd.
func CompareRank(a, b Rank) int {
	return cmp.Or(
		cmp.Compare(b.Score, a.Score),
		cmp.Compare(len(a.Name), len(b.Name)),
		cmp.Compare(a.Name, b.Name),
	)
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
		return missingEntryReason(c, name)
	}
	if e.Source == "" {
		return errors.New("catalog entry has no source")
	}
	kind, _, _ := strings.Cut(e.Source, ":")
	switch kind {
	case "aqua":
		return verifyAquaEntry(&e)
	case "manual":
		if strings.TrimSpace(e.Install) == "" {
			return errors.New("manual source without an install command")
		}
	}
	return nil
}

// missingEntryReason explains a name Lookup did not answer for.
//
// A required name that compiled into Unavailable is a REQUIREMENT
// failure, not a missing name, and saying so is the difference between
// "the registry renamed it" and "the registry stopped giving us a way to
// install it". Without that distinction the floor gate weakens silently
// the moment a required tool's backend changes upstream.
func missingEntryReason(c *Catalog, name string) error {
	u, ok := c.Unavailable[name]
	switch {
	case !ok:
		return errors.New("not in the catalog")
	case u.Reason != "":
		return fmt.Errorf("no install source (%s)", u.Reason)
	default:
		return errors.New("no install source")
	}
}

// verifyAquaEntry checks the half of an entry only an aqua source has:
// an embedded definition that resolves on both architectures and whose
// templates parse.
func verifyAquaEntry(e *CatalogEntry) error {
	if e.Aqua == nil {
		return errors.New("aqua source without an embedded definition")
	}
	for _, arch := range []string{goarchAMD64, goarchARM64} {
		if !e.Aqua.SupportsLinux(arch) {
			return fmt.Errorf("definition does not support linux/%s", arch)
		}
	}
	return e.Aqua.CheckTemplates()
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
