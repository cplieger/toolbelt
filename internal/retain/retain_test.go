package retain

import (
	"slices"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func names(entries []Entry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name)
	}
	return out
}

// The order R7.1 states: newest activation first; equal times by version
// precedence, descending, unparseable names after parseable ones; then names.
func TestOrder(t *testing.T) {
	tests := []struct {
		name    string
		entries []Entry
		want    []string
	}{
		{"newest activation first, whatever the version", []Entry{
			{Name: "3.0.0", Activated: now.Add(-48 * time.Hour)}, {Name: "1.0.0", Activated: now}, {Name: "2.0.0", Activated: now.Add(-time.Hour)},
		}, []string{"1.0.0", "2.0.0", "3.0.0"}},
		{"a release above its prerelease", []Entry{{Name: "3.0.0-rc.1", Activated: now}, {Name: "3.0.0", Activated: now}}, []string{"3.0.0", "3.0.0-rc.1"}},
		{"numeric segments compare as numbers", []Entry{{Name: "2.9.0", Activated: now}, {Name: "2.14.2", Activated: now}}, []string{"2.14.2", "2.9.0"}},
		{"a v prefix is a version", []Entry{{Name: "v1.2.0", Activated: now}, {Name: "v1.10.0", Activated: now}}, []string{"v1.10.0", "v1.2.0"}},
		{"unparseable names after parseable ones", []Entry{{Name: "latest", Activated: now}, {Name: "1.0.0", Activated: now}, {Name: "nightly", Activated: now}}, []string{"1.0.0", "nightly", "latest"}},
		{"equal precedence falls to the names", []Entry{{Name: "1.0", Activated: now}, {Name: "1.0.0", Activated: now}}, []string{"1.0.0", "1.0"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := slices.Clone(tt.entries)
			if got := names(Order(tt.entries)); !slices.Equal(got, tt.want) {
				t.Errorf("Order = %v, want %v", got, tt.want)
			}
			if !slices.Equal(tt.entries, in) {
				t.Errorf("Order changed its argument to %v", tt.entries)
			}
		})
	}
}

func TestKeep(t *testing.T) {
	for _, tt := range []struct{ in, want int }{{0, 1}, {-1, 0}, {-7, 0}, {1, 1}, {3, 3}} {
		if got := Keep(tt.in); got != tt.want {
			t.Errorf("Keep(%d) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func fallback(string) Role { return Fallback }

// R7.5, toolbelt's downgrade case: v3 active, v1 activated an hour ago and v2
// two days ago, keep 1, so v1 stays and v2 goes.
func TestVictims_aDowngradeKeepsTheMostRecentlyActivated(t *testing.T) {
	entries := []Entry{{Name: "v3.0.0", Activated: now}, {Name: "v1.0.0", Activated: now.Add(-time.Hour)}, {Name: "v2.0.0", Activated: now.Add(-48 * time.Hour)}}
	if got := Victims(entries, "v3.0.0", 1, fallback); !slices.Equal(got, []string{"v2.0.0"}) {
		t.Errorf("Victims = %v, want [v2.0.0]", got)
	}
}

func TestVictims_keepCounts(t *testing.T) {
	entries := []Entry{{Name: "4", Activated: now}, {Name: "3", Activated: now.Add(-time.Hour)}, {Name: "2", Activated: now.Add(-2 * time.Hour)}, {Name: "1", Activated: now.Add(-3 * time.Hour)}}
	for _, tt := range []struct {
		keep int
		want []string
	}{
		{0, []string{"2", "1"}},
		{1, []string{"2", "1"}},
		{2, []string{"1"}},
		{5, nil},
		{-1, []string{"3", "2", "1"}},
	} {
		if got := Victims(entries, "4", tt.keep, fallback); !slices.Equal(got, tt.want) {
			t.Errorf("Victims(keep %d) = %v, want %v", tt.keep, got, tt.want)
		}
	}
}

// The active version is never a victim, wherever its activation time ranks it.
func TestVictims_neverTheActiveVersion(t *testing.T) {
	entries := []Entry{{Name: "2.0.0", Activated: now}, {Name: "1.0.0", Activated: now.Add(-time.Hour)}}
	if got := Victims(entries, "1.0.0", -1, fallback); !slices.Equal(got, []string{"2.0.0"}) {
		t.Errorf("Victims = %v, want [2.0.0]", got)
	}
}

// With nothing active nothing serves, so nothing is pruned.
func TestVictims_nothingWithoutAnActiveVersion(t *testing.T) {
	entries := []Entry{{Name: "2.0.0", Activated: now}, {Name: "1.0.0", Activated: now.Add(-time.Hour)}}
	if got := Victims(entries, "", -1, fallback); got != nil {
		t.Errorf("Victims = %v, want none", got)
	}
}

// The classifier is asked in order, only until keep fallbacks are found: it may
// run a subprocess.
func TestVictims_asksTheClassifierOnlyUntilKeepIsMet(t *testing.T) {
	entries := []Entry{{Name: "4", Activated: now}, {Name: "3", Activated: now.Add(-time.Hour)}, {Name: "2", Activated: now.Add(-2 * time.Hour)}, {Name: "1", Activated: now.Add(-3 * time.Hour)}}
	var asked []string
	role := func(name string) Role {
		asked = append(asked, name)
		return Fallback
	}
	if got := Victims(entries, "4", 1, role); !slices.Equal(got, []string{"2", "1"}) {
		t.Errorf("Victims = %v, want [2 1]", got)
	}
	if !slices.Equal(asked, []string{"3"}) {
		t.Errorf("asked %v, want [3]", asked)
	}
	asked = nil
	Victims(entries, "4", -1, role)
	if asked != nil {
		t.Errorf("keep -1 asked %v, want nothing", asked)
	}
}

// pinstall's roles, restated for recency: an immune predecessor is spared without
// spending the slot, a prunable one goes without spending it, and the usable one
// behind them is the one kept.
func TestVictims_rolesSpendNoSlot(t *testing.T) {
	entries := []Entry{
		{Name: "5", Activated: now},
		{Name: "4", Activated: now.Add(-time.Hour)},
		{Name: "3", Activated: now.Add(-2 * time.Hour)},
		{Name: "2", Activated: now.Add(-3 * time.Hour)},
		{Name: "1", Activated: now.Add(-4 * time.Hour)},
	}
	roles := map[string]Role{"4": Immune, "3": Prunable, "2": Fallback, "1": Fallback}
	var asked []string
	role := func(name string) Role {
		asked = append(asked, name)
		return roles[name]
	}
	if got := Victims(entries, "5", 1, role); !slices.Equal(got, []string{"3", "1"}) {
		t.Errorf("Victims = %v, want [3 1]", got)
	}
	if !slices.Equal(asked, []string{"4", "3", "2"}) {
		t.Errorf("asked %v, want [4 3 2]", asked)
	}
}

// Once keep fallbacks are found, a later predecessor goes without being asked,
// an unactivatable one included.
func TestVictims_pastTheBudgetNothingIsAsked(t *testing.T) {
	entries := []Entry{{Name: "3", Activated: now}, {Name: "2", Activated: now.Add(-time.Hour)}, {Name: "1", Activated: now.Add(-2 * time.Hour)}}
	role := func(name string) Role {
		if name == "1" {
			t.Errorf("asked about %s past the budget", name)
		}
		return Fallback
	}
	if got := Victims(entries, "3", 1, role); !slices.Equal(got, []string{"1"}) {
		t.Errorf("Victims = %v, want [1]", got)
	}
}
