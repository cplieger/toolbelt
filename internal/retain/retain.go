// Package retain is the install engine's retention rule and version-directory
// order: keep the active version and the keep most recently activated
// predecessors that could serve.
package retain

import (
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/go-version"
)

// Entry is one version directory: its name and when it was last activated,
// which its caller reads from the directory's mtime.
type Entry struct {
	Activated time.Time
	Name      string
}

// Role is what retention does with a predecessor the caller has classified.
type Role uint8

const (
	// Fallback could serve, so it counts against keep.
	Fallback Role = iota
	// Immune cannot serve and is not the caller's to delete; it is spared
	// without spending a slot.
	Immune
	// Prunable cannot serve and is not evidence; it goes without spending a
	// slot.
	Prunable
)

// Order returns entries most recently activated first. Equal times order by
// version precedence, descending, with names that are not versions after the
// ones that are, then by name, descending. entries is not changed.
func Order(entries []Entry) []Entry {
	out := slices.Clone(entries)
	slices.SortStableFunc(out, compare)
	return out
}

func compare(a, b Entry) int {
	if c := b.Activated.Compare(a.Activated); c != 0 {
		return c
	}
	av, aerr := version.NewVersion(a.Name)
	bv, berr := version.NewVersion(b.Name)
	switch {
	case aerr == nil && berr == nil:
		if c := bv.Compare(av); c != 0 {
			return c
		}
	case aerr == nil:
		return -1
	case berr == nil:
		return 1
	}
	return strings.Compare(b.Name, a.Name)
}

// Keep is the number of predecessors a configured count keeps: 0 means 1, and
// a negative count keeps none.
func Keep(n int) int {
	switch {
	case n == 0:
		return 1
	case n < 0:
		return 0
	}
	return n
}

// Victims returns, in [Order], the entries to delete: every one but active and
// the first Keep(keep) predecessors role calls Fallback. role is asked in
// order and only until those are found, because it may run the version; a
// predecessor it calls Immune is spared, and one it calls Prunable goes. With
// active empty nothing serves, so nothing is a victim.
func Victims(entries []Entry, active string, keep int, role func(name string) Role) []string {
	if active == "" {
		return nil
	}
	want := Keep(keep)
	kept := 0
	var victims []string
	for _, e := range Order(entries) {
		if e.Name == active {
			continue
		}
		if kept >= want {
			victims = append(victims, e.Name)
			continue
		}
		switch role(e.Name) {
		case Fallback:
			kept++
		case Immune:
		case Prunable:
			victims = append(victims, e.Name)
		}
	}
	return victims
}
