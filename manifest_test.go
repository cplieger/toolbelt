package toolbelt

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseManifest_AcceptsAValidDocument(t *testing.T) {
	doc := fmt.Sprintf(`{"version":%d,"tools":{"jq":{"source":"aqua:jqlang/jq","version":"1.8.1","pin":true}}}`, ManifestVersion)
	m, err := ParseManifest([]byte(doc))
	if err != nil {
		t.Fatalf("ParseManifest(valid) error = %v, want nil", err)
	}
	if got := m.Tools["jq"]; got.Version != "1.8.1" || !got.Pin {
		t.Errorf("ParseManifest(valid).Tools[jq] = %+v, want version 1.8.1 pinned", got)
	}
}

func TestParseManifest_EmptyToolsIsAnEmptyMap(t *testing.T) {
	m, err := ParseManifest(fmt.Appendf(nil, `{"version":%d}`, ManifestVersion))
	if err != nil {
		t.Fatalf("ParseManifest(no tools) error = %v, want nil", err)
	}
	if m.Tools == nil {
		t.Error("ParseManifest(no tools).Tools = nil, want an empty map")
	}
}

func TestParseManifest_RefusesWhatNewRefuses(t *testing.T) {
	cases := []struct {
		name, doc, want string
	}{
		{name: "malformed", doc: `{"version":2,"tools":{`, want: "parse:"},
		{name: "wrong_version", doc: `{"version":1,"tools":{}}`, want: "manifest version 1"},
		{name: "traversing_key", doc: fmt.Sprintf(`{"version":%d,"tools":{"..":{"source":"manual"}}}`, ManifestVersion), want: "invalid tool name"},
		{name: "path_in_version", doc: fmt.Sprintf(`{"version":%d,"tools":{"jq":{"source":"aqua:jqlang/jq","version":"../x"}}}`, ManifestVersion), want: "jq:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseManifest([]byte(tc.doc))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ParseManifest(%s) error = %v, want one containing %q", tc.doc, err, tc.want)
			}
			dir := t.TempDir()
			if werr := os.WriteFile(filepath.Join(dir, "tools.json"), []byte(tc.doc), 0o600); werr != nil {
				t.Fatal(werr)
			}
			if _, nerr := New(&Config{ConfigDir: dir, ToolsDir: filepath.Join(dir, "tools")}); nerr == nil {
				t.Errorf("New accepted %s, which ParseManifest refuses", tc.doc)
			}
		})
	}
}

// The python grammar is a bare version only, on a pip: or source-less row:
// uv also accepts paths and executable names
// (https://docs.astral.sh/uv/concepts/python-versions/#requesting-a-version),
// which would build a venv outside the managed interpreters.
func TestParseManifest_AcceptsAPythonRequest(t *testing.T) {
	cases := map[string]string{
		"minor version on pip": `{"source":"pip:yamllint","python":"3.14"}`,
		"patch version on pip": `{"source":"pip:yamllint","python":"3.14.2"}`,
		"major only on pip":    `{"source":"pip:yamllint","python":"3"}`,
		"source-less template": `{"disabled":true,"python":"3.14"}`,
	}
	for name, tool := range cases {
		t.Run(name, func(t *testing.T) {
			doc := fmt.Sprintf(`{"version":%d,"tools":{"t":%s}}`, ManifestVersion, tool)

			m, err := ParseManifest([]byte(doc))
			if err != nil {
				t.Fatalf("ParseManifest(%s) error = %v, want nil", doc, err)
			}
			if m.Tools["t"].Python == "" {
				t.Errorf("ParseManifest(%s) dropped the python request", doc)
			}
		})
	}
}

func TestParseManifest_RefusesABadPythonRequest(t *testing.T) {
	cases := []struct {
		name, tool, want string
	}{
		{name: "absolute path", tool: `{"source":"pip:yamllint","python":"/usr/bin/python3"}`, want: `python "/usr/bin/python3" is not a version`},
		{name: "executable name", tool: `{"source":"pip:yamllint","python":"python3"}`, want: `python "python3" is not a version`},
		{name: "trailing option", tool: `{"source":"pip:yamllint","python":"3.14 --x"}`, want: "is not a version"},
		{name: "traversal", tool: `{"source":"pip:yamllint","python":"../3"}`, want: "is not a version"},
		{name: "implementation prefix", tool: `{"source":"pip:yamllint","python":"cpython3.14"}`, want: "is not a version"},
		{name: "npm source", tool: `{"source":"npm:pyright","python":"3.14"}`, want: `python applies only to pip: sources, not "npm:pyright"`},
		{name: "manual source", tool: `{"source":"manual","python":"3.14"}`, want: "python applies only to pip: sources"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := fmt.Sprintf(`{"version":%d,"tools":{"t":%s}}`, ManifestVersion, tc.tool)

			_, err := ParseManifest([]byte(doc))

			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("ParseManifest(%s) error = %v, want one containing %q", doc, err, tc.want)
			}
		})
	}
}
