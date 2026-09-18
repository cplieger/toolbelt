package toolbelt

import (
	"path/filepath"
	"strings"
)

// pathComponent reports whether s can be joined onto a directory as one
// path element: neither the directory itself nor its parent, no separator
// of either convention, and nothing filepath.Base would rewrite.
func pathComponent(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, `/\`) && s == filepath.Base(s)
}
