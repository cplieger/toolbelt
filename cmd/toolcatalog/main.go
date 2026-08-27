// Command toolcatalog compiles a toolbelt tool catalog from registry
// data, and verifies a compiled catalog against a consumer's required
// tool set.
//
// compile (the default) joins the mise registry (name -> preferred
// install backends, descriptions, aliases; MIT, github.com/jdx/mise
// /registry) with the aqua registry (per-package binary install
// definitions; MIT, github.com/aquaproj/aqua-registry /pkgs), emitting
// one tool-catalog.json an Engine loads read-only.
//
// What it emits is a REFERENCE: everything the registries can express,
// translated, with no opinion about which tools matter. It carries no
// curated entry set of its own — an earlier version embedded one, which
// put a product's tool list, its featured flags and its UI copy inside a
// shared artifact.
//
// A product's own BUNDLED TOOLS — the ones it needs to function and the
// ones it recommends, including any the registries do not carry — are
// its file to own, not a layer over this one. It reaches the engine
// through Config.CatalogOverlays at runtime, or through -overlay here for
// a consumer that compiles its own catalog.
//
// Runs at image build time (the Dockerfile downloads both registry
// tarballs at Renovate-pinned refs):
//
//	go run github.com/cplieger/toolbelt/v3/cmd/toolcatalog@<tag> \
//	    -mise <mise-repo>/registry \
//	    -aqua <aqua-registry-repo>/pkgs \
//	    [-overlay bundled-tools.json] \
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
//	go run github.com/cplieger/toolbelt/v3/cmd/toolcatalog@<tag> \
//	    verify -catalog tool-catalog.json -require required-tools.txt \
//	        [-overlay bundled-tools.json]
//
// A consumer passes its own bundled-tools file to verify, so the gate
// judges the catalog its engine will actually hold rather than the
// reference alone.
//
// An ordinary command in the root module: it shares the engine's
// catalog and aqua schema types by construction (one version stream, no
// compiler/engine skew), and Go's module graph pruning keeps its
// registry-parsing dependencies (TOML, YAML) out of consumer builds.
package main

import (
	"cmp"
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
	"github.com/cplieger/toolbelt/v3"
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

func runCompile(args []string) {
	fl := flag.NewFlagSet("compile", flag.ExitOnError)
	miseDir := fl.String("mise", "", "path to the mise registry dir (registry/*.toml)")
	aquaDir := fl.String("aqua", "", "path to the aqua-registry pkgs dir")
	var overlays multiFlag
	fl.Var(&overlays, "overlay", "bundled-tools JSON path (repeatable; merged in order over the registry data)")
	refsFlag := fl.String("refs", "", "comma-separated name=ref pairs recorded in the catalog")
	outPath := fl.String("out", "tool-catalog.json", "output path")
	_ = fl.Parse(args)
	if *miseDir == "" || *aquaDir == "" {
		log.Fatal("toolcatalog: -mise and -aqua are required")
	}

	catalog := &toolbelt.Catalog{
		Refs:        parseRefs(*refsFlag),
		Generated:   time.Now().UTC().Format(time.RFC3339),
		Licenses:    loadRegistryLicenses(*miseDir, *aquaDir),
		Entries:     map[string]toolbelt.CatalogEntry{},
		Unavailable: map[string]toolbelt.CatalogEntry{},
		Backends:    toolbelt.DefaultBackends(),
	}
	stats := compileMiseEntries(catalog, *miseDir, *aquaDir)

	resolver := func(ref string) (*toolbelt.AquaPackage, error) { return loadAquaDef(*aquaDir, ref) }
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
	var overlays multiFlag
	fl.Var(&overlays, "overlay", "bundled-tools JSON to merge before verifying (repeatable)")
	_ = fl.Parse(args)
	if *requirePath == "" {
		log.Fatal("toolcatalog verify: -require is required")
	}
	catalog := readCatalog(*catalogPath)
	// Applied with a NIL aqua resolver, which is exactly what the engine
	// does at runtime: this gate has to judge the catalog the engine will
	// actually hold, and a bundled tool carrying a bare aqua: source fails
	// HERE rather than at a consumer's boot.
	//
	// Without this, a consumer whose required set includes one of its own
	// bundled tools had to either drop it from the gate or move it into the
	// shared artifact. The first loses the check; the second is how a
	// product's tool list ends up in a general catalog.
	for _, ov := range overlays {
		data, err := os.ReadFile(ov)
		if err != nil {
			log.Fatalf("toolcatalog verify: bundled tools %s: %v", ov, err)
		}
		if err := toolbelt.ApplyOverlay(catalog, data, nil); err != nil {
			log.Fatalf("toolcatalog verify: bundled tools %s: %v", ov, err)
		}
	}
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
type compileStats struct{ tools, aquaBacked, unavailable, foreign int }

// compileMiseEntries walks the mise registry, compiling each usable
// tool into the catalog and recording the rest.
//
// A tool with no usable backend is NOT discarded: it lands in
// catalog.Unavailable with the backend that defeated it, so a consumer
// can answer "we know this tool and cannot install it" instead of
// returning nothing for a name the user can see in the registry. Only
// entries that are not for linux at all are dropped outright, since
// nothing here could ever install them.
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
		entry, outcome, cerr := compileEntry(miseDir, aquaDir, name)
		if cerr != nil {
			log.Fatalf("toolcatalog: %s: %v", name, cerr)
		}
		switch outcome.kind {
		case outcomeCompiled:
			catalog.Entries[name] = entry
			stats.tools++
			if strings.HasPrefix(entry.Source, "aqua:") {
				stats.aquaBacked++
			}
		case outcomeUnavailable:
			entry.Reason = outcome.reason
			catalog.Unavailable[name] = entry
			stats.unavailable++
		case outcomeForeign:
			stats.foreign++
		}
	}
	return stats
}

// checkCatalogInvariants fails the build if the compiled catalog is
// implausibly small or self-contradictory.
func checkCatalogInvariants(catalog *toolbelt.Catalog) {
	// Build invariants: a Renovate ref bump that guts the catalog must
	// fail loudly, not ship. Floor chosen well under the current ~720
	// but far above any plausible healthy shrink.
	const minEntries = 400
	if len(catalog.Entries) < minEntries {
		log.Fatalf("toolcatalog: only %d installable entries compiled (< %d): registry format drift?",
			len(catalog.Entries), minEntries)
	}
	// The other direction is a real failure too, and it is the one a naive
	// reading misses: if the compiler suddenly resolves everything, the
	// likelier cause is that backend classification broke and every entry
	// fell into one bucket. ~200 tools have no install source on any
	// healthy day.
	if len(catalog.Backends) == 0 {
		log.Fatal("toolcatalog: catalog carries no backends map: the engine would fall back " +
			"to its built-in defaults, which is the coupling this field exists to remove")
	}
	const minUnavailable = 50
	if len(catalog.Unavailable) < minUnavailable {
		log.Fatalf("toolcatalog: only %d unavailable entries recorded (< %d): backend classification drift?",
			len(catalog.Unavailable), minUnavailable)
	}
	for name := range catalog.Entries {
		e := catalog.Entries[name]
		if e.Source == "" {
			log.Fatalf("toolcatalog: installable entry %q has no source", name)
		}
		// Disjointness. An overlay supplying a source for a skipped tool
		// must evict it from the other map (ApplyOverlay does); a name in
		// both makes Search and SearchUnavailable disagree about one tool
		// with no way for a consumer to tell which answer is true.
		if _, dup := catalog.Unavailable[name]; dup {
			log.Fatalf("toolcatalog: %q is in both entries and unavailable", name)
		}
	}
	for name := range catalog.Unavailable {
		u := catalog.Unavailable[name]
		if u.Source != "" {
			log.Fatalf("toolcatalog: unavailable entry %q carries source %q", name, u.Source)
		}
		if u.Reason == "" {
			log.Fatalf("toolcatalog: unavailable entry %q carries no reason", name)
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
	fmt.Printf("toolcatalog: %d tools (%d aqua-backed), %d unavailable, %d non-linux -> %s (%d KB)\n",
		stats.tools, stats.aquaBacked, stats.unavailable, stats.foreign, outPath, len(data)/1024)
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
	Bins        []string `toml:"bins"`
}

// outcomeKind is what compileEntry decided about one registry entry.
type outcomeKind int

const (
	outcomeCompiled    outcomeKind = iota // a supported backend resolved
	outcomeUnavailable                    // linux-capable, no supported backend
	outcomeForeign                        // not for linux at all
)

// outcome pairs the decision with the backend that produced it. reason
// is set only for outcomeUnavailable and is the string a consumer shows.
type outcome struct {
	reason string
	kind   outcomeKind
}

// linuxCapable reports whether a mise entry's `os` list admits linux.
//
// Matching is by PREFIX, not equality: the registry writes both `linux`
// and platform-qualified forms such as `linux-x64`, and an equality test
// drops the qualified ones as foreign. Measured on mise c2a0cb9,
// `android-cli` is dropped that way while declaring linux support. An
// absent or empty list means no restriction.
func linuxCapable(list []string) bool {
	if len(list) == 0 {
		return true
	}
	for _, v := range list {
		if v == "linux" || strings.HasPrefix(v, "linux-") {
			return true
		}
	}
	return false
}

// compileEntry builds one catalog entry from a mise registry file,
// resolving the first backend the engine supports. The outcome says
// whether it compiled, is linux-capable with no usable backend (the
// caller records it as unavailable, carrying the returned reason), or is
// not for linux at all.
//
// The returned entry is populated in every case except a hard error, so
// an unavailable tool still carries its description and aliases.
func compileEntry(miseDir, aquaDir, name string) (toolbelt.CatalogEntry, outcome, error) {
	var mt miseTool
	if _, err := toml.DecodeFile(filepath.Join(miseDir, name+".toml"), &mt); err != nil {
		return toolbelt.CatalogEntry{}, outcome{}, err
	}
	if !linuxCapable(mt.OS) {
		return toolbelt.CatalogEntry{}, outcome{kind: outcomeForeign}, nil
	}
	entry := toolbelt.CatalogEntry{
		Name:        name,
		Description: strings.TrimSpace(mt.Description),
		Aliases:     mt.Aliases,
	}
	// The first backend that names a reason is the one reported: it is the
	// registry's own preference, so it is the answer to "why can this not
	// be installed" that matches what a user reads upstream.
	var firstReason string
	for _, raw := range mt.Backends {
		backend := backendString(raw)
		if backend == "" {
			firstReason = cmp.Or(firstReason, "no linux platform")
			continue
		}
		source, aq, err := resolveBackend(aquaDir, backend)
		if skip, reason := backendSkip(backend, err); skip {
			firstReason = cmp.Or(firstReason, reason)
			continue
		}
		if err != nil {
			// Unreadable/unparseable definition = registry format
			// drift. FAIL the build so a Renovate ref bump can't ship
			// a silently shrunken catalog.
			return toolbelt.CatalogEntry{}, outcome{}, fmt.Errorf("backend %s: %w", backend, err)
		}
		entry.Source = source
		entry.Aqua = aq
		if strings.HasPrefix(source, toolbelt.SourceRelease+":") {
			entry.Release = releaseHints(name, mt.Bins, backendOptions(raw))
		}
		if entry.Description == "" && aq != nil {
			entry.Description = firstLine(aq.Description)
		}
		return entry, outcome{kind: outcomeCompiled}, nil
	}
	return entry, outcome{
		kind:   outcomeUnavailable,
		reason: cmp.Or(firstReason, "no backends declared"),
	}, nil
}

// backendSkip separates the two resolve failures that mean "try the next
// backend" from the one that means the registry's format has drifted.
// The reason it returns is what a consumer reads as the explanation for
// an unavailable tool, so it names the backend rather than the error.
func backendSkip(backend string, err error) (skip bool, reason string) {
	switch {
	case errors.Is(err, errUnsupported):
		// A deliberately unsupported backend kind or type.
		return true, backend
	case errors.Is(err, fs.ErrNotExist):
		// The mise entry references an aqua package the pinned
		// aqua-registry ref doesn't have (the two registries move
		// independently).
		return true, backend + " (not in the pinned aqua registry)"
	default:
		return false, ""
	}
}

// backendOptions returns a table-form backend's options map, or nil for
// the string form which carries none.
func backendOptions(raw any) map[string]any {
	if v, ok := raw.(map[string]any); ok {
		if o, ok := v["options"].(map[string]any); ok {
			return o
		}
	}
	return nil
}

// releaseHints reads the install hints a registry entry carries for a
// release-backed tool.
//
// Two sources, because the registry keeps them apart: the binary SET is a
// top-level `bins` field describing the tool, and the file-location hints
// are options on the github/gitlab backend. Only the four the engine acts
// on (see toolbelt.ReleaseHints): what this tool puts on PATH, which of
// several binaries in one repository it is, and where the executable sits
// inside the artifact. The registry's asset_pattern and rename_exe are
// deliberately not read; both decisions and their evidence are documented
// on the ReleaseHints type.
func releaseHints(name string, bins []string, opts map[string]any) *toolbelt.ReleaseHints {
	str := func(k string) string {
		if opts == nil {
			return ""
		}
		v, _ := opts[k].(string)
		return strings.TrimSpace(v)
	}
	h := &toolbelt.ReleaseHints{
		Matching: str("matching"),
		Bins:     releaseBins(name, bins),
		Bin:      str("bin"),
		BinPath:  str("bin_path"),
	}
	if h.IsZero() {
		return nil
	}
	return h
}

// releaseBins normalizes the registry's binary list, returning nil when it
// says nothing the installer does not already assume.
//
// The default IS the tool's own name, so carrying `bins = ["jq"]` for jq
// would put 112 redundant lists in the catalog. What survives is the 40
// entries where the published names genuinely differ.
func releaseBins(name string, bins []string) []string {
	out := make([]string, 0, len(bins))
	for _, b := range bins {
		if b = strings.TrimSpace(b); b != "" {
			out = append(out, b)
		}
	}
	if len(out) == 0 || slices.Equal(out, []string{name}) {
		return nil
	}
	// Sorted so the catalog is byte-stable across registry edits that only
	// reorder the list, and deduplicated because a repeated name would
	// publish the same symlink twice.
	slices.Sort(out)
	return slices.Compact(out)
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

// coreBackendAqua translates mise's `core:` backends — its own built-in
// installers, which this compiler does not implement — onto the aqua
// package that installs THE SAME TOOL.
//
// This is registry TRANSLATION, not curation, and it belongs here for the
// same reason the `github:` and `gitlab:` arms do: the registry states
// which tool an entry is, and the compiler's whole job is to express that
// in a source this engine can install from. An earlier design discarded
// every `core:` backend and had a hand-written overlay revive the four
// that mattered, which put a product's tool list inside a general
// artifact and left the reason in a code comment.
//
// Measured against the pinned registries, mise declares 13 `core:` tools
// and only these 5 have an aqua package for the same thing. The other 8
// stay unavailable with their backend as the reason, which is what a
// consumer needs to read to know it must supply them itself.
//
// Two near-misses are deliberately absent, because "aqua has a package
// whose name matches" is not the test:
//
//   - python. mise means CPython; aqua's `astral-sh/uv` is a different
//     tool that merely happens to be this engine's pip backend, and it
//     already reaches the catalog as its own registry entry. Translating
//     would hand somebody who asked for python an entry that installs uv.
//   - rust. aqua's `rust-lang/rustup` installs the `rustup-init` binary,
//     not a toolchain, so the entry would land with no `cargo` on PATH —
//     and `cargo:` sources adopt `rust` expecting exactly that. A wrong
//     translation is worse here than an honest gap: the tool would read
//     as installed and the backend would still be missing.
//
// So of the four backends this engine's source kinds adopt, node and go
// arrive by translation, uv arrives as its own registry entry, and rust
// is a gap a consumer bundles itself.
var coreBackendAqua = map[string]string{
	"bun":  "oven-sh/bun",
	"deno": "denoland/deno",
	"go":   "golang/go",
	"node": "nodejs/node",
	"zig":  "ziglang/zig",
}

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
	case "core":
		// A core tool aqua does not package stays unavailable, reported
		// with its backend so the reason names what could not be read.
		aquaRef, ok := coreBackendAqua[ref]
		if !ok {
			return "", nil, errUnsupported
		}
		aq, err := loadAquaDef(aquaDir, aquaRef)
		if err != nil {
			// The translation table names a package the pinned aqua
			// registry does not carry, or carries in a shape the runtime
			// cannot evaluate. Not fatal: the tool is simply unavailable,
			// exactly as it was before the table existed.
			return "", nil, errUnsupported
		}
		return "aqua:" + aquaRef, aq, nil
	case "github":
		// mise's github backend (formerly ubi) installs a release asset,
		// which is what the release source does. The registry names the
		// repository and nothing else about the asset, so the choice is the
		// matcher's; see release.go.
		return toolbelt.SourceRelease + ":github/" + ref, nil, nil
	case "gitlab":
		return toolbelt.SourceRelease + ":gitlab/" + ref, nil, nil
	case "npm":
		return "npm:" + ref, nil, nil
	case "pipx":
		return "pip:" + ref, nil, nil
	case "cargo":
		return "cargo:" + ref, nil, nil
	case "go":
		return "go:" + ref, nil, nil
	default:
		// asdf:*, vfox:*, conda:*, gem:*, dotnet:*, spm:* are not
		// supported natively and are recorded as unavailable with their
		// backend as the reason.
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
