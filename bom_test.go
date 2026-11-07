package toolbelt

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// utf8BOM is the byte-order mark some editors (Windows Notepad among them)
// write at the start of a file saved as UTF-8.
const utf8BOM = "\xef\xbb\xbf"

// TestHandEditedJSON_AcceptsALeadingBOM pins the three readers of files a
// user or consumer edits by hand: a BOM is not JSON, so encoding/json refuses
// it, but the document behind it is valid.
func TestHandEditedJSON_AcceptsALeadingBOM(t *testing.T) {
	t.Run("tools.json", func(t *testing.T) {
		doc := fmt.Sprintf(`%s{"version":%d,"tools":{"jq":{"source":"aqua:jqlang/jq","version":"1.8.1"}}}`, utf8BOM, ManifestVersion)
		m, err := ParseManifest([]byte(doc))
		if err != nil {
			t.Fatalf("ParseManifest(BOM + valid) error = %v, want nil", err)
		}
		if m.Tools["jq"].Version != "1.8.1" {
			t.Errorf("ParseManifest(BOM + valid).Tools[jq] = %+v", m.Tools["jq"])
		}
	})
	t.Run("overlay bytes", func(t *testing.T) {
		c := &Catalog{Entries: map[string]CatalogEntry{"tool-a": {Name: "tool-a", Source: "npm:tool-a"}}}
		if err := ApplyOverlay(c, []byte(utf8BOM+`{"entries":{"tool-a":{"description":"new"}}}`), nil); err != nil {
			t.Fatalf("ApplyOverlay(BOM + valid) error = %v, want nil", err)
		}
		if c.Entries["tool-a"].Description != "new" {
			t.Errorf("description = %q, want new", c.Entries["tool-a"].Description)
		}
	})
	t.Run("overlay file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "overlay.json")
		if err := os.WriteFile(path, []byte(utf8BOM+`{"entries":{"tool-a":{"description":"new"}}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		ov, err := readOverlayDoc(path)
		if err != nil {
			t.Fatalf("readOverlayDoc(BOM + valid) error = %v, want nil", err)
		}
		if len(ov.Entries) != 1 {
			t.Errorf("entries = %d, want 1", len(ov.Entries))
		}
	})
}

// TestHandEditedJSON_RefusesABOMElsewhere checks that only one leading mark is
// dropped: a second one, or one after whitespace, is still not JSON.
func TestHandEditedJSON_RefusesABOMElsewhere(t *testing.T) {
	for name, prefix := range map[string]string{"two marks": utf8BOM + utf8BOM, "after a space": " " + utf8BOM} {
		doc := fmt.Sprintf(`%s{"version":%d,"tools":{}}`, prefix, ManifestVersion)
		if _, err := ParseManifest([]byte(doc)); err == nil {
			t.Errorf("ParseManifest(%s) error = nil, want a parse error", name)
		}
	}
}
