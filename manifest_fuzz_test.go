package toolbelt

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// An accepted manifest names only single path components and survives the store's re-encoding.
func FuzzParseManifest(f *testing.F) {
	f.Add([]byte(`{"version":2,"tools":{"jq":{"source":"aqua:jqlang/jq","version":"1.8.1","pin":true}}}`))
	f.Add([]byte(`{"version":2}`))
	f.Add([]byte(`{"version":2,"tools":null,"_comment":["seed"]}`))
	f.Add([]byte(`{"version":2,"tools":{"openssh-client":{"source":"apt:openssh-client","version":"1:10.0p1-7+deb13u4"}}}`))
	f.Add([]byte(`{"version":2,"tools":{"@scope/name":{"source":"npm:@scope/name","requires":[]}}}`))
	f.Add([]byte(`{"version":2,"tools":{"x":{"source":"manual","install":"true","disabled":true}}}`))
	f.Add([]byte(`{"version":2,"tools":{`))
	f.Add([]byte(`{"version":1,"tools":{}}`))
	f.Add([]byte(`{"version":2,"tools":{"..":{"source":"manual"}}}`))
	f.Add([]byte(`{"version":2,"tools":{"a/b":{}}}`))
	f.Add([]byte(`{"version":2,"tools":{"jq":{"source":"aqua:jqlang/jq","version":"../x"}}}`))
	f.Add([]byte(`{"version":2,"tools":{"jq":{"version":".."}}}`))
	f.Add([]byte(`{"version":2,"tools":{"too\u0142":{}}}`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := ParseManifest(data)
		if err != nil {
			if m != nil {
				t.Fatalf("ParseManifest(%q) = %+v, %v; want a nil manifest with the error", data, m, err)
			}
			return
		}
		if m.Version != ManifestVersion {
			t.Fatalf("ParseManifest(%q).Version = %d, want %d", data, m.Version, ManifestVersion)
		}
		if m.Tools == nil {
			t.Fatalf("ParseManifest(%q).Tools = nil, want a non-nil map", data)
		}
		const root = "/opt"
		for name, tool := range m.Tools {
			if !validToolName(name) {
				t.Fatalf("ParseManifest(%q) accepted tool name %q, which Add refuses", data, name)
			}
			if joined := filepath.Join(root, name); joined != root+"/"+name {
				t.Fatalf("ParseManifest(%q) accepted tool name %q, which escapes its join: %q", data, name, joined)
			}
			if tool.Version == "" {
				continue
			}
			if !validVersion(tool.Source, tool.Version) {
				t.Fatalf("ParseManifest(%q) accepted %s version %q, which its source grammar refuses", data, name, tool.Version)
			}
			if strings.Contains(tool.Version, "/") || tool.Version == "." || tool.Version == ".." {
				t.Fatalf("ParseManifest(%q) accepted %s version %q, which is not a single path component", data, name, tool.Version)
			}
		}

		encoded, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("json.Marshal(ParseManifest(%q)) error = %v", data, err)
		}
		again, err := ParseManifest(encoded)
		if err != nil {
			t.Fatalf("ParseManifest(%q) accepted, but refuses its own encoding %q: %v", data, encoded, err)
		}
		reencoded, err := json.Marshal(again)
		if err != nil {
			t.Fatalf("json.Marshal(re-parsed %q) error = %v", encoded, err)
		}
		if !bytes.Equal(encoded, reencoded) {
			t.Fatalf("ParseManifest round-trip of %q drifted:\n first: %s\nsecond: %s", data, encoded, reencoded)
		}
	})
}
