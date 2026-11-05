//go:build linux

package pin

import (
	"math"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestParseIdentities(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		raw      string
		want     []int
		rejected int
	}{
		{name: "empty", raw: "", want: nil},
		{name: "whitespace only", raw: "   \t ", want: nil},
		{name: "one", raw: "1000", want: []int{1000}},
		{name: "several", raw: "1000,1001,1002", want: []int{1000, 1001, 1002}},
		{name: "padded entries", raw: " 1000 , 1001 ", want: []int{1000, 1001}},

		// A separator declaring no identity is not a mistake worth counting.
		{name: "lone separator", raw: ",", want: nil},
		{name: "doubled separator", raw: "1000,,1001", want: []int{1000, 1001}},
		{name: "leading separator", raw: ",1000", want: []int{1000}},
		{name: "trailing separator", raw: "1000,", want: []int{1000}},

		// The four refusals.
		{name: "not a number", raw: "root", want: nil, rejected: 1},
		{name: "zero grants nothing", raw: "0", want: nil, rejected: 1},
		{name: "negative is not an identity", raw: "-1", want: nil, rejected: 1},
		{name: "float", raw: "1000.5", want: nil, rejected: 1},
		{name: "hex", raw: "0x3e8", want: nil, rejected: 1},
		{name: "opaque credential shaped", raw: "tok-AAAAAAAAAAAAAAAAAAAA", want: nil, rejected: 1},
		{name: "counts each refusal", raw: "root,0,-1", want: nil, rejected: 3},
		{name: "keeps the good ones", raw: "1000,nope,1001", want: []int{1000, 1001}, rejected: 1},

		// Shapes Atoi accepts, pinned deliberately so a change of mind is visible.
		{name: "explicit plus", raw: "+1000", want: []int{1000}},
		{name: "leading zeroes are decimal", raw: "007", want: []int{7}},
		{name: "max int", raw: strconv.Itoa(math.MaxInt), want: []int{math.MaxInt}},
		{name: "one past max int overflows", raw: "9223372036854775808", want: nil, rejected: 1},

		// Dedupe is numeric, not textual: these two entries differ as strings.
		{name: "duplicate", raw: "1000,1000", want: []int{1000}},
		{name: "duplicate arrives padded", raw: "1000, 1000 ", want: []int{1000}},
		{name: "duplicate spelled differently", raw: "1000,+1000", want: []int{1000}},

		// First-seen order survives both a duplicate and a refusal mid-list.
		{name: "order with a duplicate", raw: "1002,1000,1002,1001", want: []int{1002, 1000, 1001}},
		{name: "order with a refusal", raw: "1002,bad,1000", want: []int{1002, 1000}, rejected: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ids, rejected := ParseIdentities(tc.raw)
			if !slices.Equal(ids, tc.want) {
				t.Errorf("ParseIdentities(%q) ids = %v, want %v", tc.raw, ids, tc.want)
			}
			if rejected != tc.rejected {
				t.Errorf("ParseIdentities(%q) rejected = %d, want %d", tc.raw, rejected, tc.rejected)
			}
		})
	}
}

// TestParseIdentitiesKeepsRejectedTextOut is the reason the signature returns a count rather
// than the entries it refused: the rejected text is the operator's own input, and a compose
// interpolation mistake can make it a credential. Nothing derived from it may leave here.
func TestParseIdentitiesKeepsRejectedTextOut(t *testing.T) {
	t.Parallel()
	// Stands in for a value an operator wired to the variable by mistake. Deliberately not a
	// realistic vendor token, and deliberately not bound to an identifier a secret scanner
	// reads as a credential: the property under test is that non-numeric text does not
	// survive parsing, which any opaque value exercises.
	const rejectedEntry = "wrong-value-0123456789"
	ids, rejected := ParseIdentities("1000," + rejectedEntry + ",1001")
	if rejected != 1 {
		t.Fatalf("rejected = %d, want 1", rejected)
	}
	if !slices.Equal(ids, []int{1000, 1001}) {
		t.Fatalf("ids = %v, want [1000 1001]", ids)
	}
	// The only channel out of this function besides the count is the id slice, so the
	// property is checkable: no accepted id may render as any part of the rejected text.
	for _, id := range ids {
		if strings.Contains(rejectedEntry, strconv.Itoa(id)) {
			t.Errorf("id %d appears inside the rejected entry, which must not survive parsing", id)
		}
	}
}

// TestParseIdentitiesFeedsBothTrustFields pins the naming decision: the same list shape is
// what both trust fields take, which is why this is not called ParseTrustedUIDs.
func TestParseIdentitiesFeedsBothTrustFields(t *testing.T) {
	t.Parallel()
	ids, rejected := ParseIdentities("3000,4000")
	if rejected != 0 {
		t.Fatalf("rejected = %d, want 0", rejected)
	}
	cfg := Config{TrustedUIDs: ids, TrustedGIDs: ids}
	if !slices.Equal(cfg.TrustedUIDs, []int{3000, 4000}) {
		t.Errorf("TrustedUIDs = %v, want [3000 4000]", cfg.TrustedUIDs)
	}
	if !slices.Equal(cfg.TrustedGIDs, []int{3000, 4000}) {
		t.Errorf("TrustedGIDs = %v, want [3000 4000]", cfg.TrustedGIDs)
	}
}

func FuzzParseIdentities(f *testing.F) {
	for _, seed := range []string{"", ",", "1000", "1000,1001", " 1000 , 0 ,-1", "root", "+7", "007"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		ids, rejected := ParseIdentities(raw)
		if rejected < 0 {
			t.Fatalf("rejected = %d, must never be negative", rejected)
		}
		seen := make(map[int]bool, len(ids))
		for _, id := range ids {
			if id <= 0 {
				t.Fatalf("ParseIdentities(%q) returned %d; zero and negatives are never identities", raw, id)
			}
			if seen[id] {
				t.Fatalf("ParseIdentities(%q) returned %d twice; the result must be a set", raw, id)
			}
			seen[id] = true
		}
		// Every accepted id must be spelled by some field of the input, so the parser can
		// never invent an identity the operator did not write.
		for _, id := range ids {
			found := false
			for field := range strings.SplitSeq(raw, ",") {
				if parsed, err := strconv.Atoi(strings.TrimSpace(field)); err == nil && parsed == id {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("ParseIdentities(%q) returned %d, which no field of the input spells", raw, id)
			}
		}
	})
}
