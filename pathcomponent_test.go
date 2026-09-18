package toolbelt

import "testing"

// TestPathComponent pins the one rule both joins depend on: the version
// that becomes opt/<name>/<version> and the declared file name that becomes
// bin/<name>. A backslash is refused even though Linux would accept it as a
// file name, because the value came from a registry, never from this host.
func TestPathComponent(t *testing.T) {
	cases := map[string]struct {
		in   string
		want bool
	}{
		"empty":       {"", false},
		"dot":         {".", false},
		"dotdot":      {"..", false},
		"slash":       {"a/b", false},
		"backslash":   {`a\b`, false},
		"absolute":    {"/a", false},
		"traversal":   {"../../etc", false},
		"plain":       {"a", true},
		"dotted":      {"a.b", true},
		"dash":        {"-", true},
		"space":       {"a b", true},
		"tag":         {"v1.2.3", true},
		"plus":        {"jdk-21.0.5+11", true},
		"debianEpoch": {"1:10.0p1", true},
	}
	for desc, tc := range cases {
		t.Run(desc, func(t *testing.T) {
			if got := pathComponent(tc.in); got != tc.want {
				t.Errorf("pathComponent(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
