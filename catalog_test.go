package toolbelt

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// TestLookup_ResolvesAliasesWithoutAnIndex covers the catalog shape a
// consumer builds by hand (an overlay-only or test catalog, whose alias
// index is nil because nothing parsed it): the linear fallback is the only
// thing standing between such a catalog and every aliased name reading as
// unknown.
func TestLookup_ResolvesAliasesWithoutAnIndex(t *testing.T) {
	c := &Catalog{Entries: map[string]CatalogEntry{
		"ripgrep": {Name: "ripgrep", Source: "aqua:BurntSushi/ripgrep", Aliases: []string{"rg"}},
	}}
	cases := []struct {
		query string
		want  string // the entry name, empty for a miss
	}{
		{query: "ripgrep", want: "ripgrep"},
		{query: "rg", want: "ripgrep"},
		{query: "nope", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			got, ok := c.Lookup(tc.query)
			if ok != (tc.want != "") {
				t.Fatalf("Lookup(%q) found = %v, want %v", tc.query, ok, tc.want != "")
			}
			if got.Name != tc.want {
				t.Errorf("Lookup(%q) = %q, want %q", tc.query, got.Name, tc.want)
			}
		})
	}
}

// TestSearch_RanksExactNameOverPrefixOverAlias pins the ranking ladder
// the empty-state UI is ordered by, and the floor under it: a query that
// matches no field of an entry must not return that entry at all. An
// alias that merely EXISTS is not a match, so scoring one as if it were
// puts unrelated tools above the tool the user typed.
func TestSearch_RanksExactNameOverPrefixOverAlias(t *testing.T) {
	c := &Catalog{Entries: map[string]CatalogEntry{
		"widget":    {Name: "widget", Aliases: []string{"wg"}},
		"widgetize": {Name: "widgetize", Aliases: []string{"wz"}},
		"gadget":    {Name: "gadget", Aliases: []string{"widget-compat"}},
		"sprocket":  {Name: "sprocket", Aliases: []string{"sp"}, Description: "turns a widget"},
	}}
	cases := []struct {
		query string
		want  []string
	}{
		// name exact (100), name prefix (80), alias prefix (70),
		// description substring (20).
		{query: "widget", want: []string{"widget", "widgetize", "gadget", "sprocket"}},
		{query: "wz", want: []string{"widgetize"}},
		{query: "unrelated", want: nil},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			hits := c.Search(tc.query)
			var got []string
			for i := range hits {
				got = append(got, hits[i].Name)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("Search(%q) = %v, want %v", tc.query, got, tc.want)
			}
		})
	}
}

// TestRankEntries_BreaksTiesOnNameLength pins the tie-break that decides
// whether a search is usable on a large corpus. Every prefix match scores
// alike, so with a name-ascending tie-break alone the shortest and most
// likely answer loses to every alphabetically-earlier sibling sharing its
// prefix. Measured on Debian trixie's 68,799 package names before the fix,
// `python3` ranked 909th of 6,607 hits for "python" and `nodejs` 1,701st
// for "node". The corpus here is the shape of that failure, not its size.
func TestRankEntries_BreaksTiesOnNameLength(t *testing.T) {
	entries := map[string]CatalogEntry{
		"python3":         {Name: "python3"},
		"python-acme-doc": {Name: "python-acme-doc"},
		"python-attrs":    {Name: "python-attrs"},
		"python3-venv":    {Name: "python3-venv"},
	}
	got := rankEntries(entries, "python")
	if len(got) != 4 {
		t.Fatalf("rankEntries(python) returned %d entries, want 4", len(got))
	}
	if got[0].Name != "python3" {
		names := make([]string, 0, len(got))
		for i := range got {
			names = append(names, got[i].Name)
		}
		t.Errorf("rankEntries(python) first = %q, want %q (order: %v)", got[0].Name, "python3", names)
	}
	// An exact match still outranks every prefix match, length regardless.
	entries["py"] = CatalogEntry{Name: "py"}
	if got := rankEntries(entries, "python"); got[0].Name != "python3" {
		t.Errorf("a shorter non-matching name displaced the prefix winner: got %q", got[0].Name)
	}
	if got := rankEntries(entries, "py"); got[0].Name != "py" {
		t.Errorf("rankEntries(py) first = %q, want the exact match %q", got[0].Name, "py")
	}
}

// TestSearchUnavailable_ReportsKnownToolsWithNoInstaller covers the whole
// point of the second map: a tool the catalog knows about and cannot
// install must be findable, so a consumer can say why instead of
// returning nothing. Search must NOT see it, or an older code path would
// offer an install that cannot run.
func TestSearchUnavailable_ReportsKnownToolsWithNoInstaller(t *testing.T) {
	c := &Catalog{
		Entries: map[string]CatalogEntry{
			"pyright": {Name: "pyright", Source: "npm:pyright", Description: "Python LSP"},
		},
		Unavailable: map[string]CatalogEntry{
			"python": {Name: "python", Description: "python language", Reason: "core:python"},
		},
	}
	if got := c.Search("python"); len(got) != 1 || got[0].Name != "pyright" {
		t.Errorf("Search leaked or lost an entry: %+v", got)
	}
	got := c.SearchUnavailable("python")
	if len(got) != 1 || got[0].Name != "python" {
		t.Fatalf("SearchUnavailable(python) = %+v, want the python entry", got)
	}
	if got[0].Reason != "core:python" {
		t.Errorf("SearchUnavailable dropped the reason: got %q", got[0].Reason)
	}
	// An empty query is not a browse surface for uninstallable tools.
	if got := c.SearchUnavailable(""); got != nil {
		t.Errorf("SearchUnavailable(\"\") = %+v, want nil", got)
	}
}

// TestUnavailableIsInvisibleToAnOlderEngine is the compatibility test the
// separate map exists to pass. The published catalog is fetched at runtime
// by engines of any age, so this decodes a document carrying `unavailable`
// into a struct that has no such field, exactly as a predecessor binary
// would, and asserts every reader behaves as it does today. If this test
// ever needs relaxing, the rows have moved somewhere an old engine reads
// and the compatibility argument is void.
func TestUnavailableIsInvisibleToAnOlderEngine(t *testing.T) {
	const doc = `{"entries":{"ripgrep":{"name":"ripgrep","source":"aqua:BurntSushi/ripgrep"}},` +
		`"unavailable":{"python":{"name":"python","reason":"core:python"}}}`

	// The predecessor's view: same package, same parser, no Unavailable.
	type oldEntry struct {
		Name   string `json:"name"`
		Source string `json:"source"`
	}
	var old struct {
		Entries map[string]oldEntry `json:"entries"`
	}
	if err := json.Unmarshal([]byte(doc), &old); err != nil {
		t.Fatalf("an older engine could not parse the catalog at all: %v", err)
	}
	if len(old.Entries) != 1 {
		t.Fatalf("older engine sees %d entries, want 1", len(old.Entries))
	}
	if _, leaked := old.Entries["python"]; leaked {
		t.Fatal("an unavailable entry reached Entries, which is the break this map exists to avoid")
	}

	// The current engine's view: the row is present, and only where it belongs.
	c, err := parseCatalog([]byte(doc))
	if err != nil {
		t.Fatalf("parseCatalog: %v", err)
	}
	if _, ok := c.Lookup("python"); ok {
		t.Error("Lookup resolved an unavailable name; Add would then try to install it")
	}
	if len(c.Featured()) != 0 {
		t.Error("an unavailable entry reached the featured set")
	}
	if errs := VerifyCatalog(c, []string{"python"}); len(errs) != 1 {
		t.Fatalf("VerifyCatalog accepted an unavailable required name: %v", errs)
	} else if !strings.Contains(errs[0].Error(), "core:python") {
		t.Errorf("VerifyCatalog error does not name the reason: %v", errs[0])
	}
}

// TestApplyOverlay_EvictsARevivedNameFromUnavailable covers the one way a
// name can reach both maps: the compiler skips a tool for an unsupported
// backend and an overlay then supplies a source for it. node, go, java,
// rust and glab are all in that position on the live registries. Left in
// both, Search offers an install while SearchUnavailable simultaneously
// reports there is none.
func TestApplyOverlay_EvictsARevivedNameFromUnavailable(t *testing.T) {
	c := &Catalog{
		Entries: map[string]CatalogEntry{},
		Unavailable: map[string]CatalogEntry{
			"go":     {Name: "go", Reason: "core:go", Description: "Go language"},
			"python": {Name: "python", Reason: "core:python"},
		},
	}
	ov := []byte(`{"entries":{"go":{"source":"aqua:golang/go","featured":true}}}`)
	if err := ApplyOverlay(c, ov, func(string) (*AquaPackage, error) {
		return &AquaPackage{Type: "github_release"}, nil
	}); err != nil {
		t.Fatalf("ApplyOverlay: %v", err)
	}
	if _, still := c.Unavailable["go"]; still {
		t.Error("an overlay-revived name stayed in Unavailable")
	}
	if e, ok := c.Entries["go"]; !ok || e.Source != "aqua:golang/go" {
		t.Errorf("overlay did not create the installable entry: %+v", e)
	}
	if _, ok := c.Unavailable["python"]; !ok {
		t.Error("eviction removed an unrelated unavailable entry")
	}
}

// TestApplyOverlay_PatchesAnUnavailableDescription covers the display-patch
// path against the other map. An overlay's description is what a consumer
// shows beside the reason, so refusing here would make an overlay's
// currency depend on whether the registry happened to compile that tool.
func TestApplyOverlay_PatchesAnUnavailableDescription(t *testing.T) {
	c := &Catalog{
		Entries:     map[string]CatalogEntry{},
		Unavailable: map[string]CatalogEntry{"python": {Name: "python", Reason: "core:python"}},
	}
	if err := ApplyOverlay(c, []byte(`{"entries":{"python":{"description":"install it in a shell"}}}`), nil); err != nil {
		t.Fatalf("ApplyOverlay: %v", err)
	}
	if got := c.Unavailable["python"].Description; got != "install it in a shell" {
		t.Errorf("description = %q, want the patched text", got)
	}
	if c.Unavailable["python"].Reason != "core:python" {
		t.Error("a display patch overwrote the reason")
	}
	if err := ApplyOverlay(c, []byte(`{"entries":{"nope":{"description":"x"}}}`), nil); err == nil {
		t.Error("a patch against a name in neither map was accepted")
	}
}
