// Command toolcatalog compiles a toolbelt tool catalog from registry
// data, and verifies a compiled catalog against a consumer's required
// tool set.
//
// compile (the default) joins the mise registry (name -> preferred
// install backends, descriptions, aliases; MIT, github.com/jdx/mise
// /registry) with the aqua registry (per-package binary install
// definitions; MIT, github.com/aquaproj/aqua-registry /pkgs) and one or
// more overlay files (curated entries: LSP servers, runtimes, manual
// definitions), emitting one tool-catalog.json an Engine loads
// read-only. The base overlay set (overlays.json, embedded in the
// binary) applies first unless -no-base-overlays; consumers layer
// app-specific overlays with repeated -overlay flags.
//
// Runs at image build time (the Dockerfile downloads both registry
// tarballs at Renovate-pinned refs):
//
//	go run github.com/cplieger/toolbelt/v2/cmd/toolcatalog@<tag> \
//	    -mise <mise-repo>/registry \
//	    -aqua <aqua-registry-repo>/pkgs \
//	    -overlay overlays.json [-overlay app-overlays.json] \
//	    -refs mise=<ref>,aqua=<ref> \
//	    -out tool-catalog.json
//
// verify asserts every name in a requirements file (one per line, #
// comments) resolves in the compiled catalog to actionable install
// knowledge (offline checks: source present; aqua definitions embedded,
// template-parseable, linux amd64+arm64 support; manual entries carry
// an install command). A gap exits non-zero so the image build fails
// instead of a boot job:
//
//	go run github.com/cplieger/toolbelt/v2/cmd/toolcatalog@<tag> \
//	    verify -catalog tool-catalog.json -require required-tools.txt
//
// An ordinary command in the root module: it shares the engine's
// catalog and aqua schema types by construction (one version stream, no
// compiler/engine skew), and Go's module graph pruning keeps its
// registry-parsing dependencies (TOML, YAML) out of consumer builds.
package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/cplieger/toolbelt/v2"
	"go.yaml.in/yaml/v3"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "verify" {
		runVerify(os.Args[2:])
		return
	}
	runCompile(os.Args[1:])
}

// multiFlag collects repeated -overlay values.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

//go:embed overlays.json
var baseOverlays []byte

func runCompile(args []string) {
	fl := flag.NewFlagSet("compile", flag.ExitOnError)
	miseDir := fl.String("mise", "", "path to the mise registry dir (registry/*.toml)")
	aquaDir := fl.String("aqua", "", "path to the aqua-registry pkgs dir")
	var overlays multiFlag
	fl.Var(&overlays, "overlay", "overlay JSON path (repeatable; applied after the base set)")
	noBase := fl.Bool("no-base-overlays", false, "skip the embedded base overlay set (runtimes, forge CLIs, language servers)")
	refsFlag := fl.String("refs", "", "comma-separated name=ref pairs recorded in the catalog")
	outPath := fl.String("out", "tool-catalog.json", "output path")
	_ = fl.Parse(args)
	if *miseDir == "" || *aquaDir == "" {
		log.Fatal("toolcatalog: -mise and -aqua are required")
	}

	catalog := &toolbelt.Catalog{
		Refs:      parseRefs(*refsFlag),
		Generated: time.Now().UTC().Format(time.RFC3339),
		Licenses:  loadRegistryLicenses(*miseDir, *aquaDir),
		Entries:   map[string]toolbelt.CatalogEntry{},
	}
	stats := compileMiseEntries(catalog, *miseDir, *aquaDir)

	resolver := func(ref string) (*toolbelt.AquaPackage, error) { return loadAquaDef(*aquaDir, ref) }
	if !*noBase {
		if err := toolbelt.ApplyOverlay(catalog, baseOverlays, resolver); err != nil {
			log.Fatalf("toolcatalog: base overlays: %v", err)
		}
	}
	for _, ov := range overlays {
		data, err := os.ReadFile(ov)
		if err != nil {
			log.Fatalf("toolcatalog: overlay %s: %v", ov, err)
		}
		if err := toolbelt.ApplyOverlay(catalog, data, resolver); err != nil {
			log.Fatalf("toolcatalog: overlay %s: %v", ov, err)
		}
	}

	checkCatalogInvariants(catalog)
	writeCatalog(catalog, *outPath, stats)
}

// loadRegistryLicenses reads both registries' LICENSE files (at the
// checkout root, one level above the -mise registry dir / -aqua pkgs
// dir). The compiled catalog embeds data derived from both registries
// (MIT), and MIT requires the copyright + permission notice to travel
// with copies — embedding the texts makes every downstream copy of the
// catalog self-contained. Missing license files fail the compile: a
// silent omission would ship a non-compliant artifact.
func loadRegistryLicenses(miseDir, aquaDir string) map[string]string {
	out := map[string]string{}
	for name, dir := range map[string]string{"mise": miseDir, "aqua-registry": aquaDir} {
		data, err := os.ReadFile(filepath.Join(filepath.Dir(filepath.Clean(dir)), "LICENSE"))
		if err != nil {
			log.Fatalf("toolcatalog: %s LICENSE: %v (MIT notices must travel with the compiled catalog)", name, err)
		}
		out[name] = string(data)
	}
	return out
}

func runVerify(args []string) {
	fl := flag.NewFlagSet("verify", flag.ExitOnError)
	catalogPath := fl.String("catalog", "tool-catalog.json", "compiled catalog to verify")
	requirePath := fl.String("require", "", "requirements file (one tool name per line, # comments)")
	_ = fl.Parse(args)
	if *requirePath == "" {
		log.Fatal("toolcatalog verify: -require is required")
	}
	catalog := readCatalog(*catalogPath)
	names := readRequirements(*requirePath)
	if errs := toolbelt.VerifyCatalog(catalog, names); len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintf(os.Stderr, "toolcatalog verify: %v\n", e)
		}
		os.Exit(1)
	}
	fmt.Printf("toolcatalog verify: %d required tools resolve in %s (%d entries)\n",
		len(names), *catalogPath, len(catalog.Entries))
}

func readCatalog(path string) *toolbelt.Catalog {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("toolcatalog verify: read catalog: %v", err)
	}
	var c toolbelt.Catalog
	if err := json.Unmarshal(data, &c); err != nil {
		log.Fatalf("toolcatalog verify: parse catalog: %v", err)
	}
	if c.Entries == nil {
		log.Fatal("toolcatalog verify: catalog has no entries")
	}
	return &c
}

func readRequirements(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("toolcatalog verify: read requirements: %v", err)
	}
	var names []string
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		names = append(names, line)
	}
	if len(names) == 0 {
		log.Fatal("toolcatalog verify: requirements file lists no tools")
	}
	return names
}

// compileStats counts the outcome of a catalog compile run.
type compileStats struct{ tools, aquaBacked, skipped int }

// compileMiseEntries walks the mise registry, compiling each usable
// tool into the catalog and returning the run's counts.
func compileMiseEntries(catalog *toolbelt.Catalog, miseDir, aquaDir string) compileStats {
	var stats compileStats
	entries, err := os.ReadDir(miseDir)
	if err != nil {
		log.Fatalf("toolcatalog: read mise registry: %v", err)
	}
	for _, de := range entries {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".toml") {
			continue
		}
		name := strings.TrimSuffix(de.Name(), ".toml")
		entry, ok, cerr := compileEntry(miseDir, aquaDir, name)
		if cerr != nil {
			log.Fatalf("toolcatalog: %s: %v", name, cerr)
		}
		if !ok {
			stats.skipped++
			continue
		}
		catalog.Entries[name] = entry
		stats.tools++
		if strings.HasPrefix(entry.Source, "aqua:") {
			stats.aquaBacked++
		}
	}
	return stats
}

// checkCatalogInvariants fails the build if the compiled catalog is
// implausibly small or a featured entry lacks a source.
func checkCatalogInvariants(catalog *toolbelt.Catalog) {
	// Build invariants: a Renovate ref bump that guts the catalog must
	// fail loudly, not ship. Floor chosen well under the current ~700
	// but far above any plausible healthy shrink.
	const minEntries = 400
	if len(catalog.Entries) < minEntries {
		log.Fatalf("toolcatalog: only %d entries compiled (< %d) — registry format drift?",
			len(catalog.Entries), minEntries)
	}
	for name := range catalog.Entries {
		e := catalog.Entries[name]
		if e.Featured && e.Source == "" {
			log.Fatalf("toolcatalog: featured entry %q has no source", name)
		}
	}
}

// writeCatalog marshals the catalog to outPath and prints a summary.
func writeCatalog(catalog *toolbelt.Catalog, outPath string, stats compileStats) {
	data, err := json.Marshal(catalog)
	if err != nil {
		log.Fatalf("toolcatalog: marshal: %v", err)
	}
	if err := os.WriteFile(outPath, data, 0o600); err != nil {
		log.Fatalf("toolcatalog: write: %v", err)
	}
	fmt.Printf("toolcatalog: %d tools (%d aqua-backed, %d skipped) -> %s (%d KB)\n",
		stats.tools, stats.aquaBacked, stats.skipped, outPath, len(data)/1024)
}

func parseRefs(s string) map[string]string {
	refs := map[string]string{}
	for pair := range strings.SplitSeq(s, ",") {
		if k, v, ok := strings.Cut(strings.TrimSpace(pair), "="); ok {
			refs[k] = v
		}
	}
	return refs
}

// miseTool is the subset of a mise registry/<name>.toml we consume.
// The backends array holds strings or tables ({backend = "...", os =
// [...]}), so it decodes as []any and is coerced below.
type miseTool struct {
	Backends    []any    `toml:"backends"`
	Description string   `toml:"description"`
	Aliases     []string `toml:"aliases"`
	OS          []string `toml:"os"`
}

// compileEntry builds one catalog entry from a mise registry file,
// resolving the first backend the engine supports. ok=false means the
// tool has no usable backend (or is not for linux) and is skipped.
func compileEntry(miseDir, aquaDir, name string) (toolbelt.CatalogEntry, bool, error) {
	var mt miseTool
	if _, err := toml.DecodeFile(filepath.Join(miseDir, name+".toml"), &mt); err != nil {
		return toolbelt.CatalogEntry{}, false, err
	}
	if len(mt.OS) > 0 && !slices.Contains(mt.OS, "linux") {
		return toolbelt.CatalogEntry{}, false, nil
	}
	entry := toolbelt.CatalogEntry{
		Name:        name,
		Description: strings.TrimSpace(mt.Description),
		Aliases:     mt.Aliases,
	}
	for _, raw := range mt.Backends {
		backend := backendString(raw)
		if backend == "" {
			continue
		}
		source, aq, err := resolveBackend(aquaDir, backend)
		if errors.Is(err, errUnsupported) {
			continue // deliberately unsupported backend kind/type
		}
		if errors.Is(err, fs.ErrNotExist) {
			// The mise entry references an aqua package the pinned
			// aqua-registry ref doesn't have (the two registries move
			// independently). Skip this backend, try the next.
			continue
		}
		if err != nil {
			// Unreadable/unparseable definition = registry format
			// drift. FAIL the build so a Renovate ref bump can't ship
			// a silently shrunken catalog.
			return toolbelt.CatalogEntry{}, false, fmt.Errorf("backend %s: %w", backend, err)
		}
		entry.Source = source
		entry.Aqua = aq
		if entry.Description == "" && aq != nil {
			entry.Description = firstLine(aq.Description)
		}
		return entry, true, nil
	}
	return toolbelt.CatalogEntry{}, false, nil
}

// backendString extracts the backend spec from a string or table form.
// Tables appear both inline ({backend = "..."}) and as [[backends]]
// entries ({full = "...", platforms = [...]}).
func backendString(raw any) string {
	switch v := raw.(type) {
	case string:
		return v
	case map[string]any:
		return backendFromMap(v)
	default:
		return ""
	}
}

// backendFromMap extracts the backend spec from a table-form entry,
// returning "" when the entry restricts itself to non-linux platforms.
func backendFromMap(v map[string]any) string {
	s, _ := v["backend"].(string)
	if s == "" {
		s, _ = v["full"].(string)
	}
	for _, key := range []string{"os", "platforms"} {
		if !platformListAllowsLinux(v[key]) {
			return ""
		}
	}
	return s
}

// platformListAllowsLinux reports whether a table's os/platforms list
// permits linux. An absent or empty list means no restriction.
func platformListAllowsLinux(raw any) bool {
	list, ok := raw.([]any)
	if !ok || len(list) == 0 {
		return true
	}
	return slices.Contains(list, any("linux"))
}

// errUnsupported marks a backend/definition the compiler deliberately
// does not compile (unsupported kind or aqua package type). Distinct
// from hard errors: a YAML parse failure or unreadable file is format
// drift and must FAIL the build, not silently shrink the catalog.
var errUnsupported = errors.New("unsupported")

// resolveBackend maps a mise backend spec onto an engine source. aqua
// backends must have a parseable, linux-supported definition in the
// aqua registry checkout; ecosystem backends pass through.
func resolveBackend(aquaDir, backend string) (string, *toolbelt.AquaPackage, error) {
	kind, ref, ok := strings.Cut(backend, ":")
	if !ok {
		return "", nil, errUnsupported
	}
	// Strip mise backend options ("ubi:owner/repo[exe=x]").
	if i := strings.IndexByte(ref, '['); i >= 0 {
		ref = ref[:i]
	}
	switch kind {
	case "aqua":
		aq, err := loadAquaDef(aquaDir, ref)
		if err != nil {
			return "", nil, err
		}
		return "aqua:" + ref, aq, nil
	case "npm":
		return "npm:" + ref, nil, nil
	case "pipx":
		return "pip:" + ref, nil, nil
	case "cargo":
		return "cargo:" + ref, nil, nil
	case "go":
		return "go:" + ref, nil, nil
	default:
		// core:*, ubi:*, asdf:*, vfox:*, gem:*, dotnet:*, spm:* are
		// not supported natively; core runtimes arrive via overlays.
		return "", nil, errUnsupported
	}
}

// loadAquaDef parses pkgs/<ref>/registry.yaml and keeps definitions the
// runtime evaluator supports on linux.
func loadAquaDef(aquaDir, ref string) (*toolbelt.AquaPackage, error) {
	data, err := os.ReadFile(filepath.Join(aquaDir, filepath.FromSlash(ref), "registry.yaml"))
	if err != nil {
		return nil, err
	}
	var doc struct {
		Packages []toolbelt.AquaPackage `yaml:"packages"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if len(doc.Packages) == 0 {
		return nil, fmt.Errorf("no packages in %s", ref)
	}
	p := doc.Packages[0]
	switch p.Type {
	case "github_release", "http", "github_content":
	default:
		// A real registry type (go_install, cargo, github_archive, …)
		// the runtime evaluator doesn't cover — deliberate skip, not
		// drift.
		return nil, fmt.Errorf("%w: aqua type %q", errUnsupported, p.Type)
	}
	// The description travels on the catalog entry, not the def.
	p.Description = ""
	return &p, nil
}

// Overlay application (document shape, replace-vs-patch semantics, and
// the aqua-definition resolution hook) lives in the root module as
// toolbelt.ApplyOverlay, shared with the engine's runtime catalog
// refresh; this command passes a registry-checkout resolver so overlay
// entries with bare aqua: sources gain their embedded definitions.

func firstLine(s string) string {
	first, _, _ := strings.Cut(s, "\n")
	return strings.TrimSpace(first)
}
