package toolbelt

import (
	"fmt"
	"log/slog"
	"slices"
	"testing"
)

// probeCatalog builds a catalog whose every entry matches the query
// "zqx" by name prefix: installable entries zqx-01.., unavailable entries
// zqx-u01.. (the featured flag marks every installable entry so the empty
// query reaches the same rows through Featured).
func probeCatalog(installable, unavailable int, featured bool) *Catalog {
	c := &Catalog{Entries: map[string]CatalogEntry{}, Unavailable: map[string]CatalogEntry{}}
	for i := 1; i <= installable; i++ {
		name := fmt.Sprintf("zqx-%02d", i)
		c.Entries[name] = CatalogEntry{Name: name, Source: "npm:" + name, Featured: featured}
	}
	for i := 1; i <= unavailable; i++ {
		name := fmt.Sprintf("zqx-u%02d", i)
		c.Unavailable[name] = CatalogEntry{Name: name, Reason: "core:" + name}
	}
	return c
}

// newSearchEngine is newTestEngine with a package index attached, which
// the full constructor always does and SearchWithCounts reads.
func newSearchEngine(t *testing.T, cat *Catalog, installed ...string) *Engine {
	t.Helper()
	e := newTestEngine(t, cat)
	e.aptIdx = newAptIndex(slog.Default())
	err := e.store.MutateManifest(func(m *Manifest) error {
		for _, name := range installed {
			m.Tools[name] = Tool{Source: "npm:" + name, Version: "1.0.0"}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func entryNames(entries []CatalogEntry) []string {
	names := make([]string, 0, len(entries))
	for i := range entries {
		names = append(names, entries[i].Name)
	}
	return names
}

// TestSearchWithCounts_CountsAfterTheFilterBeforeTheCut pins the order of
// the two operations on each catalog block: the manifest filter runs
// first, the count is taken, then the cap cuts. Counted before the
// filter, a catalog of 25 matches with one installed would report 25
// against 24 rows and claim a cut that removed nothing; cut before the
// filter, 27 matches with one installed would answer 24 rows with a cap
// of 25.
func TestSearchWithCounts_CountsAfterTheFilterBeforeTheCut(t *testing.T) {
	type want struct {
		installable, installableMatched int
		unavailable, unavailableMatched int
	}
	cases := []struct {
		name      string
		catalog   *Catalog
		installed []string
		query     string
		want      want
	}{
		{
			name:      "cap_reached_only_after_the_filter",
			catalog:   probeCatalog(25, 0, false),
			installed: []string{"zqx-01"},
			query:     "zqx",
			want:      want{installable: 24, installableMatched: 24},
		},
		{
			name:      "cut_after_the_filter",
			catalog:   probeCatalog(27, 0, false),
			installed: []string{"zqx-01"},
			query:     "zqx",
			want:      want{installable: 25, installableMatched: 26},
		},
		{
			name:    "unavailable_block_cut",
			catalog: probeCatalog(0, 26, false),
			query:   "zqx",
			want:    want{unavailable: 25, unavailableMatched: 26},
		},
		{
			name:      "featured_set_cut_after_the_filter",
			catalog:   probeCatalog(27, 0, true),
			installed: []string{"zqx-01"},
			query:     "",
			want:      want{installable: 25, installableMatched: 26},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newSearchEngine(t, tc.catalog, tc.installed...)
			sc := e.SearchWithCounts(tc.query)
			got := want{
				installable:        len(sc.Installable),
				installableMatched: sc.InstallableMatched,
				unavailable:        len(sc.Unavailable),
				unavailableMatched: sc.UnavailableMatched,
			}
			if got != tc.want {
				t.Errorf("SearchWithCounts(%q) = %+v, want %+v", tc.query, got, tc.want)
			}
			for _, name := range tc.installed {
				if slices.Contains(entryNames(sc.Installable), name) {
					t.Errorf("SearchWithCounts(%q).Installable offers %q, which the manifest already holds", tc.query, name)
				}
			}
		})
	}
}

// TestSearch_ListExportsProjectSearchWithCounts pins the catalog list
// exports to the blocks of SearchWithCounts: a consumer reading either
// surface sees the same rows, cap included. The apt projection is not
// compared here because a background index refresh can land between two
// calls on a host with apt, and the answer it changes is legitimate.
func TestSearch_ListExportsProjectSearchWithCounts(t *testing.T) {
	e := newSearchEngine(t, probeCatalog(27, 26, false), "zqx-01")
	sc := e.SearchWithCounts("zqx")
	if got, want := entryNames(e.Search("zqx")), entryNames(sc.Installable); !slices.Equal(got, want) {
		t.Errorf("Search(zqx) = %v, want SearchWithCounts(zqx).Installable %v", got, want)
	}
	if got, want := entryNames(e.SearchUnavailable("zqx")), entryNames(sc.Unavailable); !slices.Equal(got, want) {
		t.Errorf("SearchUnavailable(zqx) = %v, want SearchWithCounts(zqx).Unavailable %v", got, want)
	}
}
