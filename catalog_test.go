package toolbelt

import (
	"slices"
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
