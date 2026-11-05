package main

import (
	"os"
	"path/filepath"
	"testing"
)

// writeAquaDef writes ref's registry.yaml under a fresh aqua directory.
func writeAquaDef(t *testing.T, ref, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, filepath.FromSlash(ref), "registry.yaml")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestResolveBackendCore pins which core: failures leave the tool unavailable
// and which fail the build: a missing or unevaluable package is a skip, while
// a registry file that does not parse is drift the build must report.
func TestResolveBackendCore(t *testing.T) {
	ref := coreBackendAqua["node"]
	if ref == "" {
		t.Fatal(`coreBackendAqua has no "node" entry; pick another core tool for this test`)
	}
	for _, tc := range []struct {
		name, body string
		wantSkip   bool
	}{
		{name: "missing package", wantSkip: true},
		{name: "unevaluable type", body: "packages:\n  - type: go_install\n", wantSkip: true},
		{name: "syntax error", body: "packages: [\n", wantSkip: false},
		{name: "wrong type", body: "packages: notalist\n", wantSkip: false},
		{name: "no packages", body: "packages: []\n", wantSkip: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.body != "" {
				dir = writeAquaDef(t, ref, tc.body)
			}
			_, _, err := resolveBackend(dir, "core:node")
			if err == nil {
				t.Fatal("resolveBackend(core:node) = nil error, want one")
			}
			if skip, _ := backendSkip("core:node", err); skip != tc.wantSkip {
				t.Errorf("resolveBackend(core:node) = %v, backendSkip = %v, want %v", err, skip, tc.wantSkip)
			}
		})
	}
}
