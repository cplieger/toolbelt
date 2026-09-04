package toolbelt

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidVersion(t *testing.T) {
	cases := []struct {
		desc    string
		source  string
		version string
		want    bool
	}{
		// The reported failure: Debian spells openssh-client's version
		// with an epoch, and the engine refused to add it.
		{"apt epoch", "apt:openssh-client", "1:10.0p1-7+deb13u4", true},
		{"apt no epoch", "apt:nano", "8.4-1+deb13u1", true},
		{"apt tilde prerelease", "apt:foo", "1.2~rc1-1", true},
		{"apt multi-digit epoch", "apt:foo", "12:1.0-1", true},
		{"apt colon without an epoch", "apt:foo", "1.0:2-1", false},
		{"apt shell metacharacter", "apt:foo", "1.0; rm -rf /", false},

		// A tag lands in a path component and a bash variable, so its
		// alphabet stays the narrow one.
		{"aqua tag", "aqua:cli/cli", "v2.96.0", true},
		{"release tag with a plus", "release:github/adoptium/temurin21-binaries", "jdk-21.0.5+11", true},
		{"go pseudo-version", "go:golang.org/x/tools/gopls", "v0.0.0-20260101120000-abcdef123456", true},
		{"npm prerelease", "npm:pyright", "1.0.0-beta.1", true},
		{"tag rejects an epoch", "aqua:cli/cli", "1:2.0", false},
		{"tag rejects a tilde", "aqua:cli/cli", "1.2~rc1", false},
		{"tag rejects a path separator", "aqua:cli/cli", "v1/../../etc", false},
		{"tag rejects dot-dot", "aqua:cli/cli", "..", false},
		{"tag rejects a leading dash", "aqua:cli/cli", "-rf", false},
		{"manual tag", SourceManual, "2025-01-06", true},
		{"manual rejects a substitution", SourceManual, "$(evil)", false},

		// PyPI publishes an epoch too, with a different separator.
		{"pip epoch", "pip:ruff", "1!2.0.post1", true},
		{"pip underscore", "pip:ruff", "1.0_1", true},
		{"pip rejects a colon", "pip:ruff", "1:2.0", false},

		// A source-less row is inert, so the union applies.
		{"no source takes the union", "", "1:10.0p1-7+deb13u4", true},
		{"no source still refuses a space", "", "a b", false},

		{"empty version", "aqua:cli/cli", "", false},
		{"at the length cap", "aqua:cli/cli", strings.Repeat("a", maxVersionLen), true},
		{"over the length cap", "aqua:cli/cli", strings.Repeat("a", maxVersionLen+1), false},
		{"over the cap under Debian too", "apt:foo", strings.Repeat("1", maxVersionLen+1), false},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			if got := validVersion(c.source, c.version); got != c.want {
				t.Errorf("validVersion(%q, %q) = %v, want %v", c.source, c.version, got, c.want)
			}
		})
	}
}

// TestVersionRejectedNamesTheGrammar pins the diagnostic, because the
// message is the whole reason the policy is per-source: "contains illegal
// characters" sent a reader looking for a typo in a version Debian had
// spelled correctly.
func TestVersionRejectedNamesTheGrammar(t *testing.T) {
	cases := []struct{ source, want string }{
		{"apt:openssh-client", "Debian version"},
		{"pip:ruff", "PEP 440"},
		{"aqua:cli/cli", "release tag"},
		{"", "legal version string"},
	}
	for _, c := range cases {
		err := versionRejected(c.source, "bad value")
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("versionRejected(%q, …) = %v, want it to name %q", c.source, err, c.want)
		}
		if err == nil || !strings.Contains(err.Error(), `"bad value"`) {
			t.Errorf("versionRejected(%q, …) = %v, want it to quote the value", c.source, err)
		}
	}
}

func TestVersionPathComponent(t *testing.T) {
	good := []string{"v1.2.3", "jdk-21.0.5+11", "1:10.0p1"}
	for _, v := range good {
		if !versionPathComponent(v) {
			t.Errorf("versionPathComponent(%q) = false, want true", v)
		}
	}
	bad := []string{"", ".", "..", "a/b", `a\b`, "../../etc"}
	for _, v := range bad {
		if versionPathComponent(v) {
			t.Errorf("versionPathComponent(%q) = true, want false", v)
		}
	}
}

// TestSourceVersionGrammarIsTotal fails when a Source* constant is added
// without deciding its version alphabet. The constants are read out of
// the package's own source rather than listed here, because a list in a
// test cannot notice a ninth constant — which is the failure this table
// exists to prevent.
func TestSourceVersionGrammarIsTotal(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the package directory: %v", err)
	}
	fset := token.NewFileSet()
	var found int
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, entry.Name(), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, id := range vs.Names {
					if !strings.HasPrefix(id.Name, "Source") {
						continue
					}
					found++
					checkGrammarFor(t, id.Name)
				}
			}
		}
	}
	if found < 8 {
		t.Fatalf("found %d Source* constants, want at least the 8 documented source kinds — is the parse reaching toolbelt.go?", found)
	}
}

// checkGrammarFor asserts one source constant has a usable grammar. It
// resolves the constant's VALUE (the wire kind) from the exported name so
// the parse above does not have to evaluate the const block.
func checkGrammarFor(t *testing.T, constName string) {
	t.Helper()
	kinds := map[string]string{
		"SourceAqua":    SourceAqua,
		"SourceNpm":     SourceNpm,
		"SourcePip":     SourcePip,
		"SourceCargo":   SourceCargo,
		"SourceGo":      SourceGo,
		"SourceApt":     SourceApt,
		"SourceRelease": SourceRelease,
		"SourceManual":  SourceManual,
	}
	kind, known := kinds[constName]
	if !known {
		t.Errorf("%s is a new source constant: add it to this test and to sourceVersionGrammar", constName)
		return
	}
	g, ok := sourceVersionGrammar[kind]
	if !ok {
		t.Errorf("source kind %q (%s) has no entry in sourceVersionGrammar", kind, constName)
		return
	}
	if g == grammarUnknown {
		t.Errorf("source kind %q (%s) maps to grammarUnknown", kind, constName)
		return
	}
	if versionPatterns[g] == nil {
		t.Errorf("source kind %q (%s) names grammar %d, which has no pattern", kind, constName, g)
	}
}

// TestStore_VersionOnTheReadPath covers the half Add and Patch cannot
// reach. tools.json is hand-editable and re-read per operation, so a
// version that never went through either was the only one nothing
// checked — and under grammarTag it becomes a path component. Both
// directions are pinned, because a read-path check that over-tightens
// bricks the boot it was added to protect.
func TestStore_VersionOnTheReadPath(t *testing.T) {
	cases := []struct {
		desc, source, version string
		load                  bool
	}{
		{"an apt epoch loads", "apt:openssh-client", "1:10.0p1-7+deb13u4", true},
		{"a tag loads", "aqua:cli/cli", "v2.96.0", true},
		{"an epoch on a tag source is refused", "aqua:cli/cli", "1:2.0", false},
		{"a traversing version is refused", "aqua:cli/cli", "../../etc", false},
		{"a bare dot-dot version is refused", "aqua:cli/cli", "..", false},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			dir := t.TempDir()
			doc := fmt.Sprintf(`{"version":%d,"tools":{"tool":{"source":%q,"version":%q}}}`,
				ManifestVersion, c.source, c.version)
			if err := os.WriteFile(filepath.Join(dir, "tools.json"), []byte(doc), 0o644); err != nil {
				t.Fatal(err)
			}
			m, err := newStore(dir, nil, slog.Default()).LoadManifest()
			if c.load {
				if err != nil {
					t.Fatalf("LoadManifest() refused %s %q: %v", c.source, c.version, err)
				}
				if got := m.Tools["tool"].Version; got != c.version {
					t.Errorf("loaded version = %q, want %q", got, c.version)
				}
				return
			}
			if err == nil {
				t.Fatalf("LoadManifest() accepted %s %q: %+v", c.source, c.version, m)
			}
			if !strings.Contains(err.Error(), c.version) {
				t.Errorf("error %q does not name the refused version", err)
			}
		})
	}
}
