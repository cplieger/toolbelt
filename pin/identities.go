//go:build linux

package pin

import (
	"strconv"
	"strings"
)

// ParseIdentities parses a comma-separated list of numeric uids for
// [Config.TrustedUIDs] and reports how many entries it refused: text that is
// not a number, zero (root is always trusted, so it is more likely an empty
// placeholder) and negatives. Blanks are skipped and duplicates collapse. It
// returns a count, never the refused text, because a misinterpolated variable
// can put a credential there (CWE-532).
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
