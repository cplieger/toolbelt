package toolbelt

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"sort"
	"strings"
)

// CatalogEntry is one tool in the compiled catalog: the mise-registry
// name/description joined with the preferred install source and, for
// aqua sources, the embedded aqua package definition. Overlay entries
// (curated) may add requires/shims/manual install commands and the lsp
// marker.
type CatalogEntry struct {
	Shims       map[string]string `json:"shims,omitempty"`
	Aqua        *AquaPackage      `json:"aqua,omitempty"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Source      string            `json:"source"`
	// Version is the default pinned version for entries without an
	// upstream version source (manual installs).
	Version   string   `json:"version,omitempty"`
	Install   string   `json:"install,omitempty"`   // manual-source entries
	Uninstall string   `json:"uninstall,omitempty"` // manual-source entries
	Probe     string   `json:"probe,omitempty"`     // manual-source entries
	Aliases   []string `json:"aliases,omitempty"`
	Requires  []string `json:"requires,omitempty"`
	Featured  bool     `json:"featured,omitempty"`
	// Lsp marks language-server entries; drives the consumers'
	// no-LSP-enabled warning and UI badges.
	Lsp bool `json:"lsp,omitempty"`
}

// Catalog is the compiled tool-catalog.json document.
type Catalog struct {
	// Refs records the upstream registry refs this catalog was
	// compiled from (informational).
	Refs    map[string]string       `json:"refs,omitempty"`
	Entries map[string]CatalogEntry `json:"entries"`
}

// loadCatalog reads the compiled tool catalog baked into the image. A
// missing or unreadable catalog degrades gracefully: search returns
// nothing, manual/ecosystem sources still install, and entries that
// need catalog knowledge fail their jobs with a named error.
func loadCatalog(path string, log *slog.Logger) *Catalog {
	empty := &Catalog{Entries: map[string]CatalogEntry{}}
	if path == "" {
		return empty
	}
	data, err := os.ReadFile(path)
	if err != nil {
		log.Warn("toolbelt: catalog unavailable", "path", path, "error", err)
		return empty
	}
	var c Catalog
	if err := json.Unmarshal(data, &c); err != nil {
		log.Error("toolbelt: catalog unreadable", "path", path, "error", err)
		return empty
	}
	if c.Entries == nil {
		c.Entries = map[string]CatalogEntry{}
	}
	log.Info("toolbelt: catalog loaded", "entries", len(c.Entries))
	return &c
}

// Lookup finds a catalog entry by name or alias.
func (c *Catalog) Lookup(name string) (CatalogEntry, bool) {
	if e, ok := c.Entries[name]; ok {
		return e, true
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
func (c *Catalog) Search(query string) []CatalogEntry {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return c.Featured()
	}
	type scored struct {
		e     CatalogEntry
		score int
	}
	var hits []scored
	for name := range c.Entries {
		e := c.Entries[name]
		score := matchScore(name, &e, q)
		if score == 0 {
			continue
		}
		hits = append(hits, scored{e, score})
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].score != hits[j].score {
			return hits[i].score > hits[j].score
		}
		return hits[i].e.Name < hits[j].e.Name
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
func (c *Catalog) Featured() []CatalogEntry {
	var out []CatalogEntry
	for k := range c.Entries {
		if c.Entries[k].Featured {
			out = append(out, c.Entries[k])
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if len(out) > searchLimit {
		out = out[:searchLimit]
	}
	return out
}

// VerifyCatalog checks that every required name resolves in the catalog
// to install knowledge the engine can act on, offline: a non-empty
// source; for aqua sources an embedded definition that parses its
// templates and claims linux support on both amd64 and arm64; for
// manual sources an install command. One error per failing name; nil
// means the catalog satisfies the requirement set. Consumers run this
// at image build (cmd/toolcatalog verify) over their seed + migration
// names so a registry drift fails the build instead of a boot job.
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
