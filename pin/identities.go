//go:build linux

package pin

import (
	"strconv"
	"strings"
)

// ParseIdentities parses a comma-separated list of numeric identities into the shape
// [Config.TrustedUIDs] and [Config.TrustedGIDs] take, and reports how many entries it
// refused.
//
// It exists because every consumer that installs through this library faces the same
// question about the same volume, and each was answering it with its own copy of the same
// twenty lines. The rule those copies encode is this package's, not the application's: what
// a uid means here, why zero grants nothing, and which values are not identities at all are
// all consequences of [Config.TrustedUIDs]'s contract, so they belong beside it rather than
// in each caller.
//
// It does NOT read the environment and it does NOT log, and both halves of that are
// deliberate. The caller owns the variable name, because a knob is spelled by the
// application that documents it; and the caller owns every word an operator reads, because
// the diagnosis is written against that name and its own README. This package logs plenty
// elsewhere, so the silence here is a division of labour rather than a house style.
//
// What is returned is a COUNT of refusals, never the refused text, and that is the part a
// caller must not work around. A malformed entry is the operator's own input, and a compose
// interpolation mistake can put a credential on any variable — `TRUSTED_UIDS: ${SOME_TOKEN}`
// is one typo away from an environment that looks fine. Echoing the rejected value would
// then leave a durable, queryable copy of a secret in the log store (CWE-532), which is also
// why [strconv.Atoi]'s own error is dropped rather than wrapped: a [strconv.NumError]
// carries the text that must not travel. A count is the most a caller can report and still
// be safe, and it is enough to say "some of what you wrote did not land".
//
// The refusals, all four of them:
//
//   - Text that is not a number at all.
//   - Zero, because root is trusted unconditionally, so naming it grants nothing and is
//     more likely a placeholder that expanded to an empty value.
//   - Any negative value, which is not an identity.
//   - Nothing else. A blank between separators is SKIPPED rather than counted: a doubled or
//     trailing comma declares no identity, so it is neither a grant nor a mistake worth a
//     diagnostic.
//
// Duplicates collapse and first-seen order is kept, so what reaches the library is a set
// rather than a transcript of the operator's typing.
//
// The name is not ParseTrustedUIDs, because whether these identities are TRUSTED is the
// caller's assertion — made by passing the result to one of those two fields — and the same
// list shape feeds both. A uid-specific name handed to [Config.TrustedGIDs] would read as a
// bug at every call site that does the correct thing.
func ParseIdentities(raw string) (ids []int, rejected int) {
	if strings.TrimSpace(raw) == "" {
		return nil, 0
	}
	seen := make(map[int]bool)
	for field := range strings.SplitSeq(raw, ",") {
		entry := strings.TrimSpace(field)
		if entry == "" {
			continue
		}
		id, err := strconv.Atoi(entry)
		if err != nil || id <= 0 {
			rejected++
			continue
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	return ids, rejected
}
