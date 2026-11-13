package toolbelt

import (
	"archive/tar"
	"cmp"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTestEngine builds an Engine wired to a temp config/tools dir, a
// plain HTTP client (httptest servers live on 127.0.0.1, which the
// production SSRF transport rightly blocks), and an optional catalog.
func newTestEngine(t *testing.T, cat *Catalog) *Engine {
	t.Helper()
	return newTestEngineClient(t, cat, http.DefaultClient, nil)
}

// newTestEngineClient is newTestEngine with the HTTP client and seed
// injectable (failing transports for offline assertions, seeds for
// init tests).
func newTestEngineClient(t *testing.T, cat *Catalog, client *http.Client, seed *Manifest) *Engine {
	t.Helper()
	dir := t.TempDir()
	st := newStore(dir, seed, slog.Default())
	if err := st.initFiles(); err != nil {
		t.Fatal(err)
	}
	if cat == nil {
		cat = &Catalog{Entries: map[string]CatalogEntry{}}
	}
	toolsDir := filepath.Join(dir, "tools")
	if err := os.MkdirAll(filepath.Join(toolsDir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	e := &Engine{
		store:     st,
		client:    client,
		versions:  newTestVersionResolver(client),
		log:       slog.Default(),
		configDir: dir,
		toolsDir:  toolsDir,
	}
	e.catalog.Store(cat)
	e.inst = &installer{toolsDir: toolsDir, client: client, output: func(string) {}}
	e.queue = newJobQueue(nil, nil, slog.Default(), e.executeJob)
	t.Cleanup(e.Close)
	return e
}

// waitJob polls until the job reaches a terminal state.
func waitJob(t *testing.T, e *Engine, id string) *Job {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	v, err := e.queue.Wait(ctx, id)
	if err != nil {
		t.Fatalf("wait job %s: %v", id, err)
	}
	return v
}

// binStub is a manual install command that writes a RUNNABLE stub for
// name into $BIN, reporting the version being installed. The install
// probe executes what it finds in bin/, so a fixture has to be a real
// (if trivial) program — a file whose only property is existing reads as
// not installed, exactly as a truncated download would.
func binStub(name string) string {
	return fmt.Sprintf(`printf "#!/bin/sh\necho %s $VERSION\n" > "$BIN/%s" && chmod 755 "$BIN/%s"`,
		name, name, name)
}

// addManual creates and installs a trivial manual tool.
func addManual(t *testing.T, e *Engine, name string, requires []string) {
	t.Helper()
	job, err := e.Add(t.Context(), &AddRequest{
		Name: name, Source: SourceManual, Version: "1", Requires: requires,
		Install: binStub(name),
	})
	if err != nil {
		t.Fatal(err)
	}
	final := waitJob(t, e, job.ID)
	if final.State != JobDone {
		t.Fatalf("install %s = %+v tail=%v", name, final, final.OutputTail)
	}
}

func TestNew_RefusesRetiredManifest(t *testing.T) {
	dir := t.TempDir()
	retired := `{"runtimes":{"node":{"enabled":false,"version":"v26.5.0"}}}`
	if err := os.WriteFile(filepath.Join(dir, "tools.json"), []byte(retired), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := New(&Config{ConfigDir: dir, ToolsDir: filepath.Join(dir, "tools")})
	if err == nil || !strings.Contains(err.Error(), "manifest version") {
		t.Errorf("New accepted a retired-format manifest: %v", err)
	}
}

// TestStore_RefusesTraversingManifestKey covers the read path, which is the
// half Add's validation cannot reach: tools.json is hand-editable and re-read
// per operation, so a key that never went through Add reaches the installer
// unchecked. A ".." key resolves opt/<name> to the opt tree's PARENT, and
// uninstall hands that join to os.RemoveAll.
//
// The whole document is refused rather than the one entry dropped, matching
// the version check above: the engine reports what it cannot use instead of
// silently editing user intent.
func TestStore_RefusesTraversingManifestKey(t *testing.T) {
	for _, name := range []string{"..", ".", "@a/..", "a b"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			doc := fmt.Sprintf(`{"version":%d,"tools":{%q:{"source":"manual","install":"true"}}}`, ManifestVersion, name)
			if err := os.WriteFile(filepath.Join(dir, "tools.json"), []byte(doc), 0o644); err != nil {
				t.Fatal(err)
			}
			st := newStore(dir, nil, slog.Default())
			m, err := st.LoadManifest()
			if err == nil {
				t.Errorf("LoadManifest() accepted tool name %q: %+v", name, m)
			}
			if !strings.Contains(err.Error(), "invalid tool name") {
				t.Errorf("error %q does not name the invalid key", err)
			}
			if _, err := New(&Config{ConfigDir: dir, ToolsDir: filepath.Join(dir, "tools")}); err == nil {
				t.Errorf("New accepted a manifest holding tool name %q", name)
			}
		})
	}
}

// TestStore_AcceptsDottedManifestKey is the guard against over-tightening the
// read path: a dot is a legal name character, so a hand-written entry whose
// name merely CONTAINS dots must still load.
func TestStore_AcceptsDottedManifestKey(t *testing.T) {
	dir := t.TempDir()
	doc := fmt.Sprintf(`{"version":%d,"tools":{"tool.v2":{"source":"manual","install":"true"},"..extras":{"source":"manual","install":"true"}}}`, ManifestVersion)
	if err := os.WriteFile(filepath.Join(dir, "tools.json"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := newStore(dir, nil, slog.Default()).LoadManifest()
	if err != nil {
		t.Fatalf("LoadManifest() refused a legitimate dotted name: %v", err)
	}
	for _, name := range []string{"tool.v2", "..extras"} {
		if _, ok := m.Tools[name]; !ok {
			t.Errorf("entry %q was dropped: %+v", name, m.Tools)
		}
	}
}

func TestStore_MutateRoundtrip(t *testing.T) {
	st := newStore(t.TempDir(), nil, slog.Default())
	if err := st.initFiles(); err != nil {
		t.Fatal(err)
	}
	err := st.MutateManifest(func(m *Manifest) error {
		m.Tools["jq"] = Tool{Source: "aqua:jqlang/jq", Version: "1.8.1"}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := st.LoadManifest()
	if err != nil {
		t.Fatal(err)
	}
	if m.Tools["jq"].Version != "1.8.1" {
		t.Errorf("roundtrip lost data: %+v", m.Tools)
	}
	st.setToolStatus("jq", func(s *ToolStatus) {
		s.InstalledVersion = "1.8.1"
		s.Bins = []string{"jq"}
	})
	if got := st.State().Tools["jq"].InstalledVersion; got != "1.8.1" {
		t.Errorf("state roundtrip = %q", got)
	}
	st.dropToolStatus("jq")
	if _, ok := st.State().Tools["jq"]; ok {
		t.Error("dropToolStatus left entry")
	}
}

func TestAdd_ManualInstallRuns(t *testing.T) {
	e := newTestEngine(t, nil)
	addManual(t, e, "hello", nil)
	inv, err := e.Inventory()
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Tools) != 1 || !inv.Tools[0].Installed || inv.Tools[0].InstalledVersion != "1" {
		t.Errorf("inventory = %+v", inv.Tools)
	}
}

func TestAdd_ManualProbeMissingFails(t *testing.T) {
	e := newTestEngine(t, nil)
	logs := captureLogs(e)
	job, err := e.Add(t.Context(), &AddRequest{
		Name:    "ghost",
		Source:  SourceManual,
		Version: "1.0.0",
		Install: "true", // succeeds but installs nothing
	})
	if err != nil {
		t.Fatal(err)
	}
	final := waitJob(t, e, job.ID)
	if final.State != JobFailed {
		t.Errorf("job state = %s, want failed", final.State)
	}
	inv, _ := e.Inventory()
	if inv.Tools[0].LastError == "" {
		t.Error("expected last_error recorded")
	}
	// The reason WAS recorded, so the engine must not also report that it
	// could not record it: an operator greps the logs for the failure and
	// the two statements contradict each other.
	if logs.has("not recorded") {
		t.Errorf("the recorded failure was reported as unrecordable: %v", logs.lines)
	}
}

// TestInstall_UnrunnableBinaryFailsTheInstall pins the verification
// gate. An install command can succeed and still leave a binary the OS
// will not run — a missing shared library, a wrong-architecture image, a
// truncated download — and recording that as installed is what turns one
// broken runtime into a cascade of failures naming the wrong tools.
//
// The measured instance: a node whose libatomic.so.1 was absent was
// recorded at its version, so every npm-sourced tool behind it reported
// `npm failed: exit status 127` about ITSELF while node's row read clean.
func TestInstall_UnrunnableBinaryFailsTheInstall(t *testing.T) {
	e := newTestEngine(t, nil)
	logs := captureLogs(e)
	job, err := e.Add(t.Context(), &AddRequest{
		Name: "broken", Source: SourceManual, Version: "1.0.0",
		Install: `printf '#!/bin/sh\necho "broken: error while loading shared libraries: libfake.so.1" >&2\nexit 127\n' > "$BIN/broken" && chmod 755 "$BIN/broken"`,
	})
	if err != nil {
		t.Fatal(err)
	}
	final := waitJob(t, e, job.ID)
	if final.State != JobFailed {
		t.Errorf("job state = %s, want failed (tail %v)", final.State, final.OutputTail)
	}
	if !strings.Contains(final.Error, "cannot execute") {
		t.Errorf("job error = %q, want it to say the tool cannot execute", final.Error)
	}
	inv, _ := e.Inventory()
	row := inv.Tools[0]
	if row.Installed {
		t.Error("a binary that cannot run reads as installed")
	}
	// The recorded reason must name the CAUSE, not just the exit status:
	// the loader's own message is the only thing that says which library
	// is missing, and it only exists on the probe's stderr.
	if !strings.Contains(row.LastError, "libfake.so.1") {
		t.Errorf("last_error = %q, want the loader's own diagnostic", row.LastError)
	}
	// The verdict WAS recorded on the row above, so the engine must not
	// also report that it could not record it.
	if logs.has("not recorded") {
		t.Errorf("the recorded verdict was reported as unrecordable: %v", logs.lines)
	}
}

// TestInstall_LibraryOnlyNpmPackageIsAlreadyInstalled pins convergence for an
// npm package that ships no bin (a preset or shared config): its installed
// package.json is the proof, so neither an install nor a reconcile reruns npm,
// and the inventory reads it as installed.
func TestInstall_LibraryOnlyNpmPackageIsAlreadyInstalled(t *testing.T) {
	const pkg = "@size-limit/preset-app"
	fake := t.TempDir()
	marker := filepath.Join(fake, "npm-ran")
	if err := os.WriteFile(filepath.Join(fake, "npm"),
		[]byte("#!/bin/sh\ntouch "+marker+"\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fake+string(os.PathListSeparator)+os.Getenv("PATH"))
	e := newTestEngine(t, &Catalog{Entries: map[string]CatalogEntry{}, Backends: map[string]string{SourceNpm: ""}})
	if err := e.store.MutateManifest(func(m *Manifest) error {
		m.Tools[pkg] = Tool{Source: "npm:" + pkg, Version: "14.3.0"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.store.setToolStatus(pkg, func(s *ToolStatus) { s.InstalledVersion = "14.3.0" }); err != nil {
		t.Fatal(err)
	}
	writeNpmPackage(t, e, pkg, `{"name":"@size-limit/preset-app","version":"14.3.0"}`)

	job, err := e.Install(pkg)
	if err != nil {
		t.Fatal(err)
	}
	final := waitJob(t, e, job.ID)
	if final.State != JobDone {
		t.Errorf("install job = %s, want done (tail %v)", final.State, final.OutputTail)
	}
	if out := strings.Join(final.OutputTail, "\n"); !strings.Contains(out, pkg+" 14.3.0 already installed") {
		t.Errorf("install output = %q, want it to report the package already installed", out)
	}
	if out := reconcileOutput(t, e); strings.Contains(out, "installing missing tools") {
		t.Errorf("reconcile output = %q, want nothing missing", out)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("npm ran for a package that is already installed")
	}
	if row := inventoryByName(t, e)[pkg]; !row.Installed {
		t.Errorf("inventory row = %+v, want installed", row)
	}
}

// TestInstall_NoBinNpmPackageProofDecidesTheJob pins that an npm install
// exiting 0 ends done only when the installed package.json proves the
// requested version, the same proof the inventory reads, so a done job is
// never followed by a reconcile that reruns npm.
func TestInstall_NoBinNpmPackageProofDecidesTheJob(t *testing.T) {
	const pkg = "stylelint-config-standard"
	cases := []struct {
		name       string
		manifest   string // written by the fake npm; empty writes no package.json
		wantDone   bool
		wantReason string
	}{
		{name: "requested version installed", manifest: `{"name":"stylelint-config-standard","version":"1.0.0"}`, wantDone: true},
		{name: "another version left in place", manifest: `{"name":"stylelint-config-standard","version":"0.9.0"}`, wantReason: `"0.9.0"`},
		{name: "no package.json", wantReason: "package.json"},
		{name: "malformed package.json", manifest: `{"version":`, wantReason: "package.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEngine(t, &Catalog{Entries: map[string]CatalogEntry{}, Backends: map[string]string{SourceNpm: ""}})
			captureLogs(e)
			dir := filepath.Join(e.toolsDir, "npm", "lib", "node_modules", pkg)
			script := "#!/bin/sh\nexit 0\n"
			if tc.manifest != "" {
				script = fmt.Sprintf("#!/bin/sh\nmkdir -p '%s' && printf '%%s' '%s' > '%s/package.json'\n", dir, tc.manifest, dir)
			}
			fake := t.TempDir()
			if err := os.WriteFile(filepath.Join(fake, "npm"), []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", fake+string(os.PathListSeparator)+os.Getenv("PATH"))
			if err := e.store.MutateManifest(func(m *Manifest) error {
				m.Tools[pkg] = Tool{Source: "npm:" + pkg, Version: "1.0.0"}
				return nil
			}); err != nil {
				t.Fatal(err)
			}

			job, err := e.Install(pkg)
			if err != nil {
				t.Fatal(err)
			}
			final := waitJob(t, e, job.ID)

			row := inventoryByName(t, e)[pkg]
			if tc.wantDone {
				if final.State != JobDone || !row.Installed {
					t.Errorf("job = %s (%q), installed = %v; want done and installed", final.State, final.Error, row.Installed)
				}
				return
			}
			if final.State != JobFailed {
				t.Errorf("job state = %s, want failed (tail %v)", final.State, final.OutputTail)
			}
			if !strings.Contains(final.Error, tc.wantReason) || !strings.Contains(row.LastError, tc.wantReason) {
				t.Errorf("job error = %q, last_error = %q, want both to carry %q", final.Error, row.LastError, tc.wantReason)
			}
			if row.Installed {
				t.Error("the package reads as installed")
			}
		})
	}
}

// TestInstall_ProbeVerdictDecidesThePipJob pins that an install whose venv
// uv built on an interpreter outside the managed dir fails, as the inventory
// reads that venv as not installed.
func TestInstall_ProbeVerdictDecidesThePipJob(t *testing.T) {
	foreign := newInterpreterHome(t, t.TempDir())
	dir := t.TempDir()
	script := "#!/bin/sh\n" +
		"mkdir -p \"$UV_TOOL_DIR/x/bin\"\n" +
		"echo \"home = " + foreign + "\" > \"$UV_TOOL_DIR/x/pyvenv.cfg\"\n" +
		"ln -sf \"" + foreign + "/python3\" \"$UV_TOOL_DIR/x/bin/python\"\n" +
		"printf '#!/bin/sh\\necho x 1.0.0\\n' > \"$UV_TOOL_BIN_DIR/x\"\n" +
		"chmod +x \"$UV_TOOL_BIN_DIR/x\"\n"
	if err := os.WriteFile(filepath.Join(dir, "uv"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	e := pipEngine(t, "")
	captureLogs(e)

	job, err := e.Install("x")
	if err != nil {
		t.Fatal(err)
	}

	final := waitJob(t, e, job.ID)
	if final.State != JobFailed {
		t.Errorf("install job = %s, want failed (tail %v)", final.State, final.OutputTail)
	}
	if row := inventoryRow(t, e, "x"); row.Installed || !strings.Contains(row.LastError, "is outside") {
		t.Errorf("inventory row = %+v, want not installed with the probe's reason", row)
	}
}

// TestInstall_VersionBannerMismatchFailsTheInstall pins that a bin answering
// its declared version_args with another version fails the install, as the
// inventory reads it as not installed and Reconcile would install it again.
func TestInstall_VersionBannerMismatchFailsTheInstall(t *testing.T) {
	e := newTestEngine(t, nil)
	captureLogs(e)
	job, err := e.Add(t.Context(), &AddRequest{
		Name: "banner", Source: SourceManual, Version: "1.0.0", VersionArgs: []string{"--version"},
		Install: `printf '#!/bin/sh\necho banner 9.9.9\n' > "$BIN/banner" && chmod 755 "$BIN/banner"`,
	})
	if err != nil {
		t.Fatal(err)
	}

	final := waitJob(t, e, job.ID)
	if final.State != JobFailed || !strings.Contains(final.Error, "9.9.9") {
		t.Errorf("job = %s (%q), want failed naming the reported version", final.State, final.Error)
	}
	if row := inventoryRow(t, e, "banner"); row.Installed || !strings.Contains(row.LastError, "9.9.9") {
		t.Errorf("inventory row = %+v, want not installed with the probe's reason", row)
	}
}

// TestInstall_EnablesAnObligatoryDependency pins the dependency cascade:
// asking for a tool is asking for what it cannot run without. The
// refusal this replaced was a dead end — the dependent's install failed
// and the user had to find and toggle a row they never asked about.
func TestInstall_EnablesAnObligatoryDependency(t *testing.T) {
	e := newTestEngine(t, nil)
	err := e.store.MutateManifest(func(m *Manifest) error {
		base := manualEntry("base")
		base.Disabled = true
		m.Tools["base"] = base
		dep := manualEntry("dep")
		dep.Requires = []string{"base"}
		dep.Disabled = true
		m.Tools["dep"] = dep
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	enabled := false
	job, err := e.Patch("dep", PatchRequest{Disabled: &enabled})
	if err != nil {
		t.Fatal(err)
	}
	final := waitJob(t, e, job.ID)
	if final.State != JobDone {
		t.Errorf("job = %+v tail=%v", final, final.OutputTail)
	}
	inv, _ := e.Inventory()
	byName := map[string]ToolInfo{}
	for _, row := range inv.Tools {
		byName[row.Name] = row
	}
	for _, n := range []string{"base", "dep"} {
		if byName[n].Disabled {
			t.Errorf("%s still disabled", n)
		}
		if !byName[n].Installed {
			t.Errorf("%s not installed", n)
		}
	}
	// Visible, not silent: the job log says which row was switched on
	// and what asked for it.
	var announced bool
	for _, line := range final.OutputTail {
		if strings.Contains(line, "enabling base") {
			announced = true
		}
	}
	if !announced {
		t.Errorf("the auto-enable was not reported in the job log: %v", final.OutputTail)
	}
}

// TestInstallingFlag_CoversDependencies pins the per-row installing flag
// against the PLAN rather than the request. A dependency the user never
// named is adopted or enabled by the job that needs it, so a flag derived
// from the requested names leaves that row rendering as an idle
// not-installed entry for the whole time its install is running — which
// is what "go and typescript appeared, but as disabled" was.
func TestInstallingFlag_CoversDependencies(t *testing.T) {
	e := newTestEngine(t, nil)
	err := e.store.MutateManifest(func(m *Manifest) error {
		m.Tools["base"] = Tool{
			Source: SourceManual, Version: "1", Disabled: true,
			// Slow on purpose: the fixture has to hold the dependency's
			// install open long enough for a read to observe it.
			Install: "sleep 2 && " + binStub("base"),
		}
		dep := manualEntry("dep")
		dep.Requires = []string{"base"}
		dep.Disabled = true
		m.Tools["dep"] = dep
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	enabled := false
	job, err := e.Patch("dep", PatchRequest{Disabled: &enabled})
	if err != nil {
		t.Fatal(err)
	}
	// Deadline-bounded poll: fails closed with the rows it saw, so it
	// cannot flake into a false pass the way a bare sleep would.
	deadline := time.Now().Add(15 * time.Second)
	for {
		inv, ierr := e.Inventory()
		if ierr != nil {
			t.Fatal(ierr)
		}
		var base ToolInfo
		for _, row := range inv.Tools {
			if row.Name == "base" {
				base = row
			}
		}
		if base.Installing {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("base never reported installing; rows = %+v", inv.Tools)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if final := waitJob(t, e, job.ID); final.State != JobDone {
		t.Errorf("job = %+v tail=%v", final, final.OutputTail)
	}
}

// TestInstallPlan_PublishesWhileTheJobRuns pins the publication, not just
// the flag. A consumer refetches the inventory when a job change is
// published, and the plan is resolved AFTER the queued -> running
// transition, so with no publication of its own the adopted and
// newly-enabled rows stay invisible until the job ends — for a cold
// runtime, the whole download.
func TestInstallPlan_PublishesWhileTheJobRuns(t *testing.T) {
	e := newTestEngine(t, nil)
	var mu sync.Mutex
	var running int
	// The callback runs under the queue lock, so it may only record.
	// Reading the inventory from here would re-enter that lock.
	e.queue.Close()
	e.queue = newJobQueue(func(j *Job) {
		if j.State != JobRunning {
			return
		}
		mu.Lock()
		running++
		mu.Unlock()
	}, nil, slog.Default(), e.executeJob)

	err := e.store.MutateManifest(func(m *Manifest) error {
		base := manualEntry("base")
		base.Disabled = true
		m.Tools["base"] = base
		dep := manualEntry("dep")
		dep.Requires = []string{"base"}
		dep.Disabled = true
		m.Tools["dep"] = dep
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	enabled := false
	job, err := e.Patch("dep", PatchRequest{Disabled: &enabled})
	if err != nil {
		t.Fatal(err)
	}
	if final := waitJob(t, e, job.ID); final.State != JobDone {
		t.Errorf("job = %+v tail=%v", final, final.OutputTail)
	}
	mu.Lock()
	got := running
	mu.Unlock()
	// One for the transition into running, one for the resolved plan.
	if got < 2 {
		t.Errorf("running-state publications = %d, want the transition plus the plan", got)
	}
}

// TestInstall_DoomedDependentIsBlockedNotBlamed pins the attribution.
// With a backend runtime that cannot run, attempting the tools behind it
// made each one report a fault about ITSELF: the measured shipping case
// was node unable to load libatomic.so.1 while pyright, typescript and
// typescript-language-server each said `npm failed: exit status 127`.
func TestInstall_DoomedDependentIsBlockedNotBlamed(t *testing.T) {
	// A "runtime" that installs successfully and then cannot run, and
	// two tools that declare it as a requirement.
	e := newTestEngine(t, nil)
	logs := captureLogs(e)
	err := e.store.MutateManifest(func(m *Manifest) error {
		m.Tools["runtime"] = Tool{
			Source: SourceManual, Version: "1",
			Install: `printf '#!/bin/sh\nexit 127\n' > "$BIN/runtime" && chmod 755 "$BIN/runtime"`,
		}
		for _, n := range []string{"leaf", "middle"} {
			t := manualEntry(n)
			t.Requires = []string{"runtime"}
			m.Tools[n] = t
		}
		// A tool behind the blocked one: the failure must propagate, and
		// the reason must name the ROOT rather than the middle link.
		tail := manualEntry("tail")
		tail.Requires = []string{"middle"}
		m.Tools["tail"] = tail
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	job, err := e.Install("tail")
	if err != nil {
		t.Fatal(err)
	}
	final := waitJob(t, e, job.ID)
	if final.State != JobFailed {
		t.Errorf("job state = %s, want failed", final.State)
	}
	// The job's own error names the tool that broke, not its victims.
	if !strings.Contains(final.Error, "runtime") {
		t.Errorf("job error = %q, want it to name runtime", final.Error)
	}
	inv, _ := e.Inventory()
	byName := map[string]ToolInfo{}
	for _, row := range inv.Tools {
		byName[row.Name] = row
	}
	// Both victims name the root cause and neither claims a fault of its
	// own. "tail" is two edges away, so this also pins the propagation.
	for _, n := range []string{"middle", "tail"} {
		if got := byName[n].LastError; !strings.Contains(got, `dependency "runtime" failed: `) {
			t.Errorf("%s last_error = %q, want it to say dependency \"runtime\" failed with its cause", n, got)
		}
	}
	// An unrelated name in the same plan is not collateral damage.
	if byName["leaf"].Name != "" && byName["leaf"].Installed {
		t.Error("leaf was installed despite sharing the broken runtime")
	}
	// Every blocked reason above landed on its row, so the engine must not
	// also report that it could not record one.
	if logs.has("not recorded") {
		t.Errorf("a recorded blocked reason was reported as unrecordable: %v", logs.lines)
	}
}

// TestInstall_UnrelatedToolsStillInstall keeps the block narrow: only the
// chain behind the failure is skipped, never a sibling that shares the
// job but not the dependency.
func TestInstall_UnrelatedToolsStillInstall(t *testing.T) {
	e := newTestEngine(t, nil)
	err := e.store.MutateManifest(func(m *Manifest) error {
		m.Tools["runtime"] = Tool{
			Source: SourceManual, Version: "1",
			Install: `printf '#!/bin/sh\nexit 127\n' > "$BIN/runtime" && chmod 755 "$BIN/runtime"`,
		}
		doomed := manualEntry("doomed")
		doomed.Requires = []string{"runtime"}
		m.Tools["doomed"] = doomed
		m.Tools["fine"] = manualEntry("fine")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	job, err := e.queue.Enqueue(JobKindInstall, []string{"doomed", "fine"})
	if err != nil {
		t.Fatal(err)
	}
	if final := waitJob(t, e, job.ID); final.State != JobFailed {
		t.Errorf("job state = %s, want failed", final.State)
	}
	inv, _ := e.Inventory()
	for _, row := range inv.Tools {
		if row.Name == "fine" && !row.Installed {
			t.Errorf("fine was not installed: %q", row.LastError)
		}
	}
}

func unresolvableNodeEngine(t *testing.T) *Engine {
	t.Helper()
	cat := &Catalog{Entries: map[string]CatalogEntry{
		"node": {Name: "node", Source: "aqua:nodejs/node"},
	}}
	e := newTestEngineClient(t, cat, offlineClient(), nil)
	err := e.store.MutateManifest(func(m *Manifest) error {
		m.Tools["pyright"] = Tool{Source: "npm:pyright", Version: "1.0.0"}
		m.Tools["fine"] = manualEntry("fine")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func inventoryByName(t *testing.T, e *Engine) map[string]ToolInfo {
	t.Helper()
	inv, err := e.Inventory()
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]ToolInfo{}
	for _, row := range inv.Tools {
		byName[row.Name] = row
	}
	return byName
}

func TestInstall_UnresolvableDependencyFailsTheDependentRow(t *testing.T) {
	e := unresolvableNodeEngine(t)

	job, err := e.Install("pyright")
	if err != nil {
		t.Fatal(err)
	}
	final := waitJob(t, e, job.ID)
	if final.State != JobFailed {
		t.Errorf("Install(pyright) job state = %s, want failed", final.State)
	}
	if !strings.Contains(final.Error, `dependency "node" failed`) {
		t.Errorf("Install(pyright) job error = %q, want it to say dependency \"node\" failed", final.Error)
	}
	row := inventoryByName(t, e)["pyright"]
	if row.Installed {
		t.Error("pyright reported installed without its backend")
	}
	for _, want := range []string{`dependency "node" failed`, "resolve latest version", "network touched"} {
		if !strings.Contains(row.LastError, want) {
			t.Errorf("pyright last_error = %q, want it to contain %q", row.LastError, want)
		}
	}
}

func TestInstall_UnplannableDependencyFailsEveryRowOnItsPath(t *testing.T) {
	e := unresolvableNodeEngine(t)
	err := e.store.MutateManifest(func(m *Manifest) error {
		root := manualEntry("tsls")
		root.Requires = []string{"pyright"}
		m.Tools["tsls"] = root
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	job, err := e.Install("tsls")
	if err != nil {
		t.Fatal(err)
	}
	if final := waitJob(t, e, job.ID); final.State != JobFailed {
		t.Errorf("Install(tsls) job state = %s, want failed", final.State)
	}
	byName := inventoryByName(t, e)
	for _, name := range []string{"tsls", "pyright"} {
		if got := byName[name].LastError; !strings.Contains(got, `dependency "node" failed`) {
			t.Errorf("%s last_error = %q, want it to say dependency \"node\" failed", name, got)
		}
	}
}

func TestInstall_UnplannableRootDoesNotSinkSiblings(t *testing.T) {
	e := unresolvableNodeEngine(t)

	job, err := e.queue.Enqueue(JobKindInstall, []string{"pyright", "fine"})
	if err != nil {
		t.Fatal(err)
	}
	if final := waitJob(t, e, job.ID); final.State != JobFailed {
		t.Errorf("install [pyright fine] job state = %s, want failed", final.State)
	}
	byName := inventoryByName(t, e)
	if !byName["fine"].Installed {
		t.Errorf("fine was not installed: last_error %q", byName["fine"].LastError)
	}
	if got := byName["pyright"].LastError; !strings.Contains(got, `dependency "node" failed`) {
		t.Errorf("pyright last_error = %q, want it to say dependency \"node\" failed", got)
	}
}

// TestInventory_ReportsDependents pins the advisory field a consumer
// needs to ask the disable question BEFORE sending a request the engine
// refuses. Both edge kinds count: a declared Requires and the backend a
// source kind implies.
func TestInventory_ReportsDependents(t *testing.T) {
	e := newTestEngine(t, nil)
	err := e.store.MutateManifest(func(m *Manifest) error {
		m.Tools["node"] = manualEntry("node")
		m.Tools["typescript"] = Tool{Source: "npm:typescript", Version: "1"}
		m.Tools["tsls"] = Tool{Source: "npm:tsls", Version: "1", Requires: []string{"typescript"}}
		off := manualEntry("off")
		off.Disabled = true
		off.Requires = []string{"typescript"}
		m.Tools["off"] = off
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := e.Inventory()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, row := range inv.Tools {
		got[row.Name] = row.Dependents
	}
	// node is the implied backend of both npm entries; typescript is a
	// declared requirement of tsls. The DISABLED entry contributes
	// nothing, because it cannot be what is holding the tool.
	if want := []string{"tsls", "typescript"}; !slices.Equal(got["node"], want) {
		t.Errorf("node dependents = %v, want %v", got["node"], want)
	}
	if want := []string{"tsls"}; !slices.Equal(got["typescript"], want) {
		t.Errorf("typescript dependents = %v, want %v", got["typescript"], want)
	}
	if len(got["tsls"]) != 0 {
		t.Errorf("tsls dependents = %v, want none", got["tsls"])
	}
	// The refusal and the advisory field must name the same set, or a
	// consumer's pre-check disagrees with the answer it gets.
	m, _ := e.store.LoadManifest()
	if want := enabledDependents(m, dependentsIndex(m, e.cat()), "node"); !slices.Equal(got["node"], want) {
		t.Errorf("inventory dependents %v disagree with the refusal's %v", got["node"], want)
	}
}

func TestAdd_Validation(t *testing.T) {
	e := newTestEngine(t, nil)
	cases := map[string]AddRequest{
		"a name that is not a tool name":                {Name: "bad name!", Source: SourceManual, Version: "1", Install: "true"},
		"an unrecognised source scheme":                 {Name: "x", Source: "weird:ref", Version: "1"},
		"a manual source with no install command":       {Name: "x", Source: SourceManual, Version: "1"},
		"a version carrying a shell command":            {Name: "x", Source: "npm:pkg", Version: "1; rm -rf /"},
		"a name in neither the request nor the catalog": {Name: "unknown-tool-with-no-source-or-catalog", Version: "1"},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			if job, err := e.Add(t.Context(), &req); err == nil {
				t.Errorf("Add(%+v) = job %v, want a validation error", req, job)
			}
		})
	}
}

func TestAdd_DuplicateRejected(t *testing.T) {
	e := newTestEngine(t, nil)
	req := AddRequest{
		Name: "dup", Source: SourceManual, Version: "1",
		Install: binStub("dup"),
	}
	if _, err := e.Add(t.Context(), &req); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Add(t.Context(), &req); err == nil {
		t.Fatal("duplicate add should fail")
	}
}

func TestPatch_PinSyncAndVersionJob(t *testing.T) {
	e := newTestEngine(t, nil)
	job, err := e.Add(t.Context(), &AddRequest{
		Name: "t", Source: SourceManual, Version: "1.0.0",
		Install: binStub("t"), Probe: "t",
	})
	if err != nil {
		t.Fatal(err)
	}
	waitJob(t, e, job.ID)

	pin := true
	jv, err := e.Patch("t", PatchRequest{Pin: &pin})
	if err != nil || jv != nil {
		t.Errorf("pin patch: job=%v err=%v", jv, err)
	}
	m, _ := e.store.LoadManifest()
	if !m.Tools["t"].Pin {
		t.Error("pin not persisted")
	}

	v2 := "2.0.0"
	jv, err = e.Patch("t", PatchRequest{Version: &v2})
	if err != nil || jv == nil {
		t.Fatalf("version patch: job=%v err=%v", jv, err)
	}
	final := waitJob(t, e, jv.ID)
	if final.State != JobDone {
		t.Errorf("reinstall job = %+v", final)
	}
	if got := e.store.State().Tools["t"].InstalledVersion; got != "2.0.0" {
		t.Errorf("installed_version = %q, want 2.0.0", got)
	}

	if _, err := e.Patch("missing", PatchRequest{Pin: &pin}); !errors.Is(err, ErrNotFound) {
		t.Errorf("patch missing = %v, want ErrNotFound", err)
	}
}

func TestRemove_DependentsConflict(t *testing.T) {
	e := newTestEngine(t, nil)
	addManual(t, e, "base", nil)
	addManual(t, e, "dep", []string{"base"})

	_, deps, err := e.Remove("base")
	if !errors.Is(err, ErrHasDependents) {
		t.Errorf("err = %v, want ErrHasDependents", err)
	}
	if len(deps) != 1 || deps[0] != "dep" {
		t.Errorf("dependents = %v", deps)
	}

	jv, _, err := e.RemoveWithDependents("base")
	if err != nil {
		t.Fatal(err)
	}
	final := waitJob(t, e, jv.ID)
	if final.State != JobDone {
		t.Errorf("uninstall job = %+v", final)
	}
	m, _ := e.store.LoadManifest()
	if len(m.Tools) != 0 {
		t.Errorf("cascade left tools: %+v", m.Tools)
	}
	if _, err := os.Stat(filepath.Join(e.toolsDir, "bin", "base")); !os.IsNotExist(err) {
		t.Error("base bin not removed")
	}
}

func TestRemoveWithDependents_CascadesThroughTheChain(t *testing.T) {
	// base <- mid <- top. top requires base only through mid, and the
	// two-node case in TestRemove_DependentsConflict cannot tell a one-level
	// cascade from a transitive one; this can.
	e := newTestEngine(t, nil)
	addManual(t, e, "base", nil)
	addManual(t, e, "mid", []string{"base"})
	addManual(t, e, "top", []string{"mid"})

	jv, deps, err := e.RemoveWithDependents("base")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(deps, []string{"mid", "top"}) {
		t.Errorf("dependents = %v, want [mid top]: every enabled row that needs base rides along", deps)
	}
	if !slices.Equal(jv.Names, []string{"base", "mid", "top"}) {
		t.Errorf("job names = %v, want [base mid top]", jv.Names)
	}
	if final := waitJob(t, e, jv.ID); final.State != JobDone {
		t.Fatalf("uninstall job = %+v tail=%v", final, final.OutputTail)
	}
	m, err := e.store.LoadManifest()
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Tools) != 0 {
		t.Errorf("cascade left rows: %v", slices.Sorted(maps.Keys(m.Tools)))
	}
	for _, bin := range []string{"base", "mid", "top"} {
		if _, err := os.Stat(filepath.Join(e.toolsDir, "bin", bin)); !os.IsNotExist(err) {
			t.Errorf("%s binary not uninstalled by the cascade", bin)
		}
	}
}

// TestCascade_EveryEnabledDependentIsNamed: the inventory row and the
// refusal a confirm dialog shows name the same chain the forced call would
// take, for remove and disable, and a cycle back to the named tool ends the
// walk.
func TestCascade_EveryEnabledDependentIsNamed(t *testing.T) {
	e := newTestEngine(t, nil)
	addManual(t, e, "base", nil)
	addManual(t, e, "mid", []string{"base"})
	addManual(t, e, "top", []string{"mid"})
	addManual(t, e, "side", nil)
	if err := e.store.MutateManifest(func(m *Manifest) error {
		b := m.Tools["base"]
		b.Requires = []string{"top"}
		m.Tools["base"] = b
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	want := []string{"mid", "top"}
	if row := inventoryRow(t, e, "base"); !slices.Equal(row.Dependents, want) {
		t.Errorf("inventory dependents of base = %v, want %v", row.Dependents, want)
	}
	_, deps, err := e.Remove("base")
	if de, ok := errors.AsType[*DependentsError](err); !ok || !slices.Equal(de.Dependents, want) || !slices.Equal(deps, want) {
		t.Errorf("Remove(base) = %v (dependents %v), want DependentsError naming %v", err, deps, want)
	}
	on := true
	_, err = e.Patch("base", PatchRequest{Disabled: &on})
	if de, ok := errors.AsType[*DependentsError](err); !ok || !slices.Equal(de.Dependents, want) {
		t.Errorf("Patch(base, disabled) = %v, want DependentsError naming %v", err, want)
	}
}

// TestRemoveWithDependents_EssentialDeepInTheChainRefusesTheCall: an
// essential row two levels up would go with the cascade, so nothing goes,
// whether the row between is enabled or disabled (the install plan enables a
// disabled one for top).
func TestRemoveWithDependents_EssentialDeepInTheChainRefusesTheCall(t *testing.T) {
	for _, tc := range []struct {
		name        string
		midDisabled bool
	}{{name: "enabled mid"}, {name: "disabled mid", midDisabled: true}} {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEngine(t, nil)
			addManual(t, e, "base", nil)
			addManual(t, e, "mid", []string{"base"})
			addManual(t, e, "top", []string{"mid"})
			editManifest(t, e, func(m *Manifest) {
				mid := m.Tools["mid"]
				mid.Disabled = tc.midDisabled
				m.Tools["mid"] = mid
			})
			e.catalog.Store(&Catalog{Entries: map[string]CatalogEntry{
				"top": {Name: "top", Source: SourceManual, Essential: true},
			}})
			if _, _, err := e.RemoveWithDependents("base"); !errors.Is(err, ErrEssential) || !strings.Contains(err.Error(), "top") {
				t.Errorf("RemoveWithDependents(base) = %v, want ErrEssential naming top", err)
			}
			m, err := e.store.LoadManifest()
			if err != nil {
				t.Fatal(err)
			}
			if len(m.Tools) != 3 || m.Tools["mid"].Disabled != tc.midDisabled {
				t.Errorf("refused cascade changed the manifest: %v (mid disabled %v)", slices.Sorted(maps.Keys(m.Tools)), m.Tools["mid"].Disabled)
			}
		})
	}
}

func TestInstallOrder_BackendDepFromCatalog(t *testing.T) {
	// npm-sourced tool pulls node from the catalog automatically.
	cat := &Catalog{Entries: map[string]CatalogEntry{
		"node": {
			Name: "node", Source: SourceManual, Version: "1.0.0",
			Install: binStub("node"), Probe: "node",
		},
	}}
	e := newTestEngine(t, cat)
	err := e.store.MutateManifest(func(m *Manifest) error {
		m.Tools["pyright"] = Tool{Source: "npm:pyright", Version: "1.0.0"}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	m, _ := e.store.LoadManifest()
	plan := e.installOrder(t.Context(), m, []string{"pyright"})
	if len(plan.unplanned) != 0 {
		t.Fatalf("installOrder(pyright) unplanned = %v, want none", plan.unplanned)
	}
	ordered := plan.ordered
	if len(ordered) != 2 || ordered[0] != "node" || ordered[1] != "pyright" {
		t.Errorf("ordered = %v, want [node pyright]", ordered)
	}
	// The dep was adopted into the manifest.
	m2, _ := e.store.LoadManifest()
	if _, ok := m2.Tools["node"]; !ok {
		t.Error("node not adopted into manifest")
	}
}

func TestInstallOrder_CycleDetected(t *testing.T) {
	e := newTestEngine(t, nil)
	err := e.store.MutateManifest(func(m *Manifest) error {
		m.Tools["a"] = Tool{Source: SourceManual, Version: "1", Install: "true", Requires: []string{"b"}}
		m.Tools["b"] = Tool{Source: SourceManual, Version: "1", Install: "true", Requires: []string{"a"}}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	m, _ := e.store.LoadManifest()
	plan := e.installOrder(t.Context(), m, []string{"a"})
	if len(plan.unplanned) != 1 || plan.unplanned[0].name != "a" ||
		!strings.Contains(plan.unplanned[0].err.Error(), "cycle") {
		t.Errorf("installOrder(a) unplanned = %v, want the cycle recorded against a", plan.unplanned)
	}
	if len(plan.ordered) != 0 {
		t.Errorf("installOrder(a) ordered = %v, want nothing from the cyclic chain", plan.ordered)
	}
}

// TestInstallAqua_EndToEnd exercises the full artifact path: download a
// tar.gz from a local server, verify its sha256 against a checksums
// file, extract, link the declared binary, prune an older version.
func TestInstallAqua_EndToEnd(t *testing.T) {
	// Build a tar.gz holding mytool-1.2.0/bin/mytool.
	var tarball strings.Builder
	gz := gzip.NewWriter(&nopWriteCloser{&tarball})
	tw := tar.NewWriter(gz)
	content := []byte("#!/bin/sh\necho mytool\n")
	if err := tw.WriteHeader(&tar.Header{
		Name: "mytool-1.2.0/bin/mytool", Mode: 0o755, Size: int64(len(content)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	artifact := tarball.String()
	sum := sha256.Sum256([]byte(artifact))
	checksums := hex.EncodeToString(sum[:]) + "  mytool_1.2.0_linux_" + runtime.GOARCH + ".tar.gz\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".tar.gz"):
			_, _ = w.Write([]byte(artifact))
		case strings.HasSuffix(r.URL.Path, "checksums.txt"):
			_, _ = w.Write([]byte(checksums))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	aq := &AquaPackage{
		Type: "http", RepoOwner: "o", RepoName: "mytool",
		URL:    srv.URL + "/mytool_{{trimV .Version}}_{{.OS}}_{{.Arch}}.{{.Format}}",
		Format: "tar.gz",
		Files:  []AquaFile{{Name: "mytool", Src: "mytool-{{trimV .Version}}/bin/mytool"}},
		Checksum: &AquaChecksum{
			Type: "http", URL: srv.URL + "/checksums.txt", Algorithm: "sha256",
		},
	}
	cat := &Catalog{Entries: map[string]CatalogEntry{
		"mytool": {Name: "mytool", Source: "aqua:o/mytool", Aqua: aq},
	}}
	e := newTestEngine(t, cat)

	// Two superseded versions: retention keeps the newest one (a bad
	// update needs a tree to fall back to) and prunes the rest.
	older := filepath.Join(e.toolsDir, "opt", "mytool", "v1.0.0")
	old := filepath.Join(e.toolsDir, "opt", "mytool", "v1.1.0")
	for _, dir := range []string{older, old} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	stale := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(older, stale, stale); err != nil {
		t.Fatal(err)
	}

	job, err := e.Add(t.Context(), &AddRequest{Name: "mytool", Version: "v1.2.0"})
	if err != nil {
		t.Fatal(err)
	}
	final := waitJob(t, e, job.ID)
	if final.State != JobDone {
		t.Fatalf("job = %+v tail=%v", final, final.OutputTail)
	}

	link := filepath.Join(e.toolsDir, "bin", "mytool")
	target, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("bin link: %v", err)
	}
	if want := filepath.Join(e.toolsDir, "opt", "mytool", "v1.2.0", "mytool-1.2.0", "bin", "mytool"); target != want {
		t.Errorf("link target = %s, want %s", target, want)
	}
	if _, err := os.Stat(old); err != nil {
		t.Errorf("previous version not retained for rollback: %v", err)
	}
	if _, err := os.Stat(older); !os.IsNotExist(err) {
		t.Error("version beyond the retention window not pruned")
	}
	st := e.store.State().Tools["mytool"]
	if st.InstalledVersion != "v1.2.0" || len(st.Bins) != 1 {
		t.Errorf("state = %+v", st)
	}
	if st.Checksum != checksumVerified {
		t.Errorf("state checksum = %q, want %q", st.Checksum, checksumVerified)
	}
}

// TestInstallAqua_ChecksumMismatch ensures a bad digest aborts before
// anything is linked.
func TestInstallAqua_ChecksumMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "checksums.txt") {
			_, _ = w.Write([]byte(strings.Repeat("0", 64) + "  tool_1.0.0_linux_" + runtime.GOARCH + ".raw\n"))
			return
		}
		_, _ = w.Write([]byte("binary-bytes"))
	}))
	defer srv.Close()

	aq := &AquaPackage{
		Type: "http", RepoOwner: "o", RepoName: "tool",
		URL:      srv.URL + "/tool_{{trimV .Version}}_{{.OS}}_{{.Arch}}.raw",
		Format:   "raw",
		Files:    []AquaFile{{Name: "tool"}},
		Checksum: &AquaChecksum{Type: "http", URL: srv.URL + "/checksums.txt", Algorithm: "sha256"},
	}
	cat := &Catalog{Entries: map[string]CatalogEntry{
		"tool": {Name: "tool", Source: "aqua:o/tool", Aqua: aq},
	}}
	e := newTestEngine(t, cat)
	job, err := e.Add(t.Context(), &AddRequest{Name: "tool", Version: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	final := waitJob(t, e, job.ID)
	if final.State != JobFailed || !strings.Contains(final.Error, "checksum mismatch") {
		t.Errorf("job = %+v, want a checksum-mismatch failure", final)
	}
	if _, err := os.Stat(filepath.Join(e.toolsDir, "bin", "tool")); !os.IsNotExist(err) {
		t.Error("bin linked despite checksum failure")
	}
}

func TestJobs_CancelQueued(t *testing.T) {
	e := newTestEngine(t, nil)
	slow, err := e.Add(t.Context(), &AddRequest{
		Name: "slow", Source: SourceManual, Version: "1",
		Install: `sleep 5 && ` + binStub("slow"),
	})
	if err != nil {
		t.Fatal(err)
	}
	queued, err := e.Update()
	if err != nil {
		t.Fatal(err)
	}
	if !e.CancelJob(queued.ID) {
		t.Fatal("cancel queued failed")
	}
	if v := waitJob(t, e, queued.ID); v.State != JobCancelled {
		t.Errorf("queued job state = %s", v.State)
	}
	if !e.CancelJob(slow.ID) {
		t.Fatal("cancel running failed")
	}
	if v := waitJob(t, e, slow.ID); v.State != JobCancelled && v.State != JobFailed {
		t.Errorf("running job state = %s", v.State)
	}
	if e.CancelJob("tj-nope") {
		t.Error("cancel unknown succeeded")
	}
}

// busyQueue occupies the worker with a long-running install and leaves
// one job queued behind it, so a cancellation test can drive the running
// path and the queued path from the same engine.
func busyQueue(t *testing.T, e *Engine) (running, queued *Job) {
	t.Helper()
	running, err := e.Add(t.Context(), &AddRequest{
		Name: "slow", Source: SourceManual, Version: "1",
		Install: `sleep 3 && ` + binStub("slow"),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Wait until the worker actually picked it up: a job still pending
	// would be cancelled through the queued path, not the running one.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if a := e.queue.Active(); a != nil && a.ID == running.ID && a.State == JobRunning {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("job %s never started", running.ID)
		}
		time.Sleep(10 * time.Millisecond)
	}
	queued, err = e.Update()
	if err != nil {
		t.Fatal(err)
	}
	return running, queued
}

// cancelActiveContext kills the running job's context WITHOUT going
// through Cancel or Close — the shape a cancellation path added later
// would have before it learns to name its cause. Nothing may infer
// shutdown from it.
func cancelActiveContext(t *testing.T, e *Engine, _, _ *Job) {
	t.Helper()
	e.queue.mu.Lock()
	active := e.queue.active
	var cancel context.CancelFunc
	if active != nil {
		cancel = active.cancel
	}
	e.queue.mu.Unlock()
	if cancel == nil {
		t.Fatal("no active job context to cancel")
	}
	cancel()
}

// TestRunOne_FlushesOutputBeforeTheTerminalState pins the ordering rule a
// consumer's UI depends on: a job's LAST output batch reaches OnJobOutput
// BEFORE the OnJobChanged transition that says the job finished. The final
// line has no tick left to carry it, only the ticker goroutine's closing
// flush, so finalizing without waiting for that flush races the terminal
// notification. The queue is driven directly because the ordering is the
// queue's, not the engine's.
func TestRunOne_FlushesOutputBeforeTheTerminalState(t *testing.T) {
	var mu sync.Mutex
	var seq []string
	record := func(s string) {
		mu.Lock()
		defer mu.Unlock()
		seq = append(seq, s)
	}
	q := newJobQueue(
		func(j *Job) { record("state:" + j.State) },
		func(_ string, lines []string) { record("output:" + strings.Join(lines, ",")) },
		slog.Default(),
		func(_ context.Context, _ *job, output func(string)) error {
			// Emitted as the job returns, so no flush tick can carry it.
			output("the last line")
			return nil
		},
	)
	defer q.Close()

	jv, err := q.Enqueue(JobKindInstall, []string{"x"})
	if err != nil {
		t.Fatal(err)
	}
	// Wait observes the terminal view under the same lock hold that
	// publishes the terminal transition, so the sequence is complete here.
	if _, err := q.Wait(t.Context(), jv.ID); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	got := slices.Clone(seq)
	mu.Unlock()
	terminal := "state:" + JobDone
	if len(got) == 0 || got[len(got)-1] != terminal {
		t.Errorf("event sequence = %v, want it to END with %q", got, terminal)
	}
	if !slices.Contains(got, "output:the last line") {
		t.Errorf("the job's last output batch never arrived: %v", got)
	}
	if i := slices.Index(got, terminal); i >= 0 {
		for _, e := range got[i+1:] {
			if strings.HasPrefix(e, "output:") {
				t.Errorf("output arrived after the finished transition: %v", got)
				break
			}
		}
	}
}

// TestJobCancelCause pins WHO each cancellation path reports. A consumer
// keys its alerting on the cause, so a shutdown must never read as a
// caller cancel, a caller cancel must never read as shutdown, and a path
// that names no cause must stay unknown instead of defaulting to either.
func TestJobCancelCause(t *testing.T) {
	// want is the expected outcome for one of the two jobs busyQueue
	// leaves behind: "running" holds the worker, "queued" sits behind it.
	type want struct {
		job   string
		cause CancelCause
	}
	cases := map[string]struct {
		cancel func(t *testing.T, e *Engine, running, queued *Job)
		want   []want
	}{
		"caller cancel of the running job": {
			cancel: func(t *testing.T, e *Engine, running, _ *Job) {
				if !e.CancelJob(running.ID) {
					t.Fatal("cancel running failed")
				}
			},
			want: []want{{job: "running", cause: CancelCaller}},
		},
		"caller cancel of a queued job": {
			cancel: func(t *testing.T, e *Engine, _, queued *Job) {
				if !e.CancelJob(queued.ID) {
					t.Fatal("cancel queued failed")
				}
			},
			want: []want{{job: "queued", cause: CancelCaller}},
		},
		"shutdown cancels the running job and drains the queue": {
			cancel: func(_ *testing.T, e *Engine, _, _ *Job) { e.Close() },
			want: []want{
				{job: "running", cause: CancelShutdown},
				{job: "queued", cause: CancelShutdown},
			},
		},
		"a context cancelled by no named path stays unknown": {
			cancel: cancelActiveContext,
			want:   []want{{job: "running", cause: CancelUnknown}},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newTestEngine(t, nil)
			running, queued := busyQueue(t, e)
			tc.cancel(t, e, running, queued)
			for _, w := range tc.want {
				id := running.ID
				if w.job == "queued" {
					id = queued.ID
				}
				v := waitJob(t, e, id)
				if v.State != JobCancelled {
					t.Errorf("%s job state = %s (%s), want %s", w.job, v.State, v.Error, JobCancelled)
					continue
				}
				if v.CancelCause != w.cause {
					t.Errorf("%s job cause = %q, want %q", w.job, v.CancelCause, w.cause)
				}
			}
		})
	}
}

// TestJobCancelAttribution pins the two attribution rules that only a
// race can reach through the public API: a job that already reached a
// terminal state is never stamped with a cancel cause (a Close arriving
// after a successful finish must not mark it cancelled-by-shutdown), and
// the FIRST cause wins (an operator cancel followed by a shutdown stays
// attributed to the operator, because their cancel is why it stopped).
func TestJobCancelAttribution(t *testing.T) {
	cases := map[string]struct {
		state string
		have  CancelCause
		note  CancelCause
		want  CancelCause
	}{
		"running job takes the cause":     {state: JobRunning, have: CancelUnknown, note: CancelShutdown, want: CancelShutdown},
		"queued job takes the cause":      {state: JobQueued, have: CancelUnknown, note: CancelCaller, want: CancelCaller},
		"first cause wins over shutdown":  {state: JobRunning, have: CancelCaller, note: CancelShutdown, want: CancelCaller},
		"finished job is never stamped":   {state: JobDone, have: CancelUnknown, note: CancelShutdown, want: CancelUnknown},
		"failed job is never stamped":     {state: JobFailed, have: CancelUnknown, note: CancelCaller, want: CancelUnknown},
		"cancelled job keeps its verdict": {state: JobCancelled, have: CancelCaller, note: CancelShutdown, want: CancelCaller},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			j := &job{state: tc.state, cause: tc.have}
			j.noteCancelLocked(tc.note)
			if j.cause != tc.want {
				t.Errorf("cause = %q, want %q", j.cause, tc.want)
			}
		})
	}
}

// TestCancelCause_ValuesAndJSON pins the type's contract: the zero value
// means unknown and equals neither real cause, every cause names itself
// for logs, and the wire field is additive — the label appears on a
// cancelled job, nothing appears when the cause is unknown, and
// JobCancelled keeps its value either way.
func TestCancelCause_ValuesAndJSON(t *testing.T) {
	var zero CancelCause
	if zero != CancelUnknown {
		t.Errorf("zero value = %q, want CancelUnknown", zero)
	}
	if zero == CancelShutdown || zero == CancelCaller {
		t.Error("the zero value must not equal a real cause")
	}
	cases := map[string]struct {
		cause CancelCause
		// wantLog is the log/String rendering; wantJSON is the expected
		// wire fragment ("" = the key must be absent entirely).
		wantLog  string
		wantJSON string
	}{
		"unknown":  {cause: CancelUnknown, wantLog: "unknown", wantJSON: ""},
		"shutdown": {cause: CancelShutdown, wantLog: "shutdown", wantJSON: `"cancel_cause":"shutdown"`},
		"caller":   {cause: CancelCaller, wantLog: "caller", wantJSON: `"cancel_cause":"caller"`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := tc.cause.String(); got != tc.wantLog {
				t.Errorf("String() = %q, want %q", got, tc.wantLog)
			}
			raw, err := json.Marshal(&Job{
				ID: "tj-1", Kind: JobKindInstall, State: JobCancelled, CancelCause: tc.cause,
			})
			if err != nil {
				t.Fatal(err)
			}
			body := string(raw)
			if !strings.Contains(body, `"state":"cancelled"`) {
				t.Errorf("payload lost the cancelled state: %s", body)
			}
			switch {
			case tc.wantJSON == "" && strings.Contains(body, "cancel_cause"):
				t.Errorf("an unknown cause must not reach the wire: %s", body)
			case tc.wantJSON != "" && !strings.Contains(body, tc.wantJSON):
				t.Errorf("payload = %s, want it to carry %s", body, tc.wantJSON)
			}
		})
	}
}

func TestSearch_HidesManifestEntries(t *testing.T) {
	cat := &Catalog{Entries: map[string]CatalogEntry{
		"jq":  {Name: "jq", Source: "aqua:jqlang/jq", Featured: true},
		"gh":  {Name: "gh", Source: "aqua:cli/cli", Featured: true},
		"rg":  {Name: "ripgrep", Source: "aqua:BurntSushi/ripgrep", Aliases: []string{"rg"}},
		"xyz": {Name: "xyz", Source: "npm:xyz", Description: "json tool"},
	}}
	e := newTestEngine(t, cat)
	err := e.store.MutateManifest(func(m *Manifest) error {
		m.Tools["jq"] = Tool{Source: "aqua:jqlang/jq", Version: "1.8.1"}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	feat := e.Search("")
	for _, h := range feat {
		if h.Name == "jq" {
			t.Error("featured list should hide installed jq")
		}
	}
	if hits := e.Search("json"); len(hits) == 0 {
		t.Error("description search found nothing")
	}
	if hits := e.Search("rg"); len(hits) == 0 || hits[0].Name != "ripgrep" {
		t.Errorf("alias search = %+v", hits)
	}
}

// TestInventory_LatestFromCacheAndSystem pins the advisory Latest field in
// all three of its states. It is the whole basis of a consumer's "update
// available" badge, so it has to be set when the cache knows a newer version,
// and stay EMPTY both when the cache knows nothing and when what it knows is
// the version already declared — a Latest equal to Version is a badge offering
// an upgrade to the version in use.
func TestInventory_LatestFromCacheAndSystem(t *testing.T) {
	e := newTestEngine(t, nil)
	e.system = []string{"sh"}
	addManual(t, e, "t", nil)
	err := e.store.MutateManifest(func(m *Manifest) error {
		m.Tools["a-newer"] = Tool{Source: "npm:x", Version: "1.0.0"}
		m.Tools["b-current"] = Tool{Source: "npm:y", Version: "9.9.9"}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Seed the version cache as an update job would.
	e.versions.mu.Lock()
	e.versions.cache[latestKey{source: SourceManual}] = "" // manual: never cached
	e.versions.cache[latestKey{source: "npm:x"}] = "9.9.9"
	e.versions.cache[latestKey{source: "npm:y"}] = "9.9.9"
	e.versions.mu.Unlock()

	inv, err := e.Inventory()
	if err != nil {
		t.Fatal(err)
	}
	// Inventory sorts by name, so the rows are a-newer, b-current, t.
	if len(inv.Tools) != 3 {
		t.Fatalf("inventory rows = %d, want 3: %+v", len(inv.Tools), inv.Tools)
	}
	if got := inv.Tools[0].Latest; got != "9.9.9" {
		t.Errorf("Latest for %q (declared 1.0.0, cache 9.9.9) = %q, want %q",
			inv.Tools[0].Name, got, "9.9.9")
	}
	if got := inv.Tools[1].Latest; got != "" {
		t.Errorf("Latest for %q (declared 9.9.9, cache 9.9.9) = %q, want empty: "+
			"the cached version IS the declared one", inv.Tools[1].Name, got)
	}
	if got := inv.Tools[2].Latest; got != "" {
		t.Errorf("Latest for the manual tool %q = %q, want empty", inv.Tools[2].Name, got)
	}
	if len(inv.System) != 1 || !inv.System[0].Installed {
		t.Errorf("system tools = %+v", inv.System)
	}
}

// nopWriteCloser adapts a strings.Builder for gzip.NewWriter.
type nopWriteCloser struct{ b *strings.Builder }

func (w *nopWriteCloser) Write(p []byte) (int, error) { return w.b.Write(p) }

// TestChecksumConfigured_FailsClosed: a configured checksum whose URL
// can't resolve must fail spec resolution, never silently downgrade to
// an unverified install.
func TestChecksumConfigured_FailsClosed(t *testing.T) {
	off := false
	cases := map[string]struct {
		checksum    *AquaChecksum
		wantResolve bool
	}{
		"an unsupported checksum type":  {checksum: &AquaChecksum{Type: "weird_type", Algorithm: "sha256"}},
		"an unparseable asset template": {checksum: &AquaChecksum{Type: "github_release", Asset: "{{.Broken", Algorithm: "sha256"}},
		"an asset with no algorithm":    {checksum: &AquaChecksum{Type: "github_release", Asset: "sums.txt"}},
		// enabled:false is an explicit opt-out and must still resolve.
		"an explicitly disabled checksum": {
			checksum:    &AquaChecksum{Type: "github_release", Asset: "sums.txt", Enabled: &off},
			wantResolve: true,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			aq := &AquaPackage{
				Type: "http", RepoOwner: "o", RepoName: "t",
				URL: "https://example.com/t.raw", Format: "raw",
				Checksum: tc.checksum,
			}
			spec, err := aq.ResolveSpec("v1.0.0")
			if tc.wantResolve && err != nil {
				t.Errorf("ResolveSpec = %v, want it to resolve", err)
			}
			if !tc.wantResolve && err == nil {
				t.Errorf("ResolveSpec = %+v, want it to fail closed", spec)
			}
		})
	}
}

func saturateQueue(t *testing.T, e *Engine) {
	t.Helper()
	slow, err := e.Add(t.Context(), &AddRequest{
		Name: "slow", Source: SourceManual, Version: "1",
		Install: "exec sleep 30",
	})
	if err != nil {
		t.Fatal(err)
	}
	// The worker must drain the slow job from pending before the cap is
	// counted, or one Update below lands in its slot.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if a := e.queue.Active(); a != nil && a.ID == slow.ID && a.State == JobRunning {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Setup: slow job never started")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for range jobQueueCap {
		if _, err := e.Update(); err != nil {
			t.Fatalf("Setup: filling the queue to its cap: %v", err)
		}
	}
}

func TestAdd_QueueFullLeavesNoRow(t *testing.T) {
	e := newTestEngine(t, nil)
	saturateQueue(t, e)
	if _, err := e.Add(t.Context(), &AddRequest{
		Name: "phantom", Source: SourceManual, Version: "1", Install: "true",
	}); !errors.Is(err, ErrQueueFull) {
		t.Errorf("Add on a full queue = %v, want ErrQueueFull", err)
	}
	m, _ := e.store.LoadManifest()
	if _, exists := m.Tools["phantom"]; exists {
		t.Error("rejected add left a manifest row")
	}
}

// TestQueueRefusal_WritesNoManifest: a write the queue refuses is refused
// before the manifest is written, so no undo write exists to clobber a
// concurrent caller's accepted edit of the same field.
func TestQueueRefusal_WritesNoManifest(t *testing.T) {
	yes := true
	python := "3.14"
	dependent := Tool{Source: SourceManual, Version: "1", Install: "true", Requires: []string{"x"}}
	cases := []struct {
		call func(e *Engine) error
		name string
	}{
		{name: "add", call: func(e *Engine) error {
			_, err := e.Add(t.Context(), &AddRequest{Name: "new", Source: SourceManual, Version: "1", Install: "true"})
			return err
		}},
		{name: "patch reinstalling the row", call: func(e *Engine) error {
			_, err := e.Patch("x", PatchRequest{Python: &python})
			return err
		}},
		{name: "forced disable cascading to a dependent", call: func(e *Engine) error {
			_, err := e.Patch("x", PatchRequest{Disabled: &yes, Force: true})
			return err
		}},
		{name: "remove with its dependents", call: func(e *Engine) error {
			_, _, err := e.RemoveWithDependents("x")
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := pipEngine(t, "3.13")
			saturateQueue(t, e)
			if err := e.store.MutateManifest(func(m *Manifest) error {
				m.Tools["x"] = Tool{Source: "pip:x", Version: "1.0.0", Python: "3.13"}
				m.Tools["app"] = dependent
				return nil
			}); err != nil {
				t.Fatalf("Setup: %v", err)
			}
			before, err := e.store.LoadManifest()
			if err != nil {
				t.Fatal(err)
			}
			writes := 0
			write := atomicWrite
			swapBarriers(t, nil, nil, func(path string, data []byte) (bool, error) {
				if path == e.store.manifestPath {
					writes++
				}
				return write(path, data)
			})

			if err := tc.call(e); !errors.Is(err, ErrQueueFull) {
				t.Errorf("call on a full queue = %v, want ErrQueueFull", err)
			}
			if writes != 0 {
				t.Errorf("the refused call wrote the manifest %d times, want none", writes)
			}
			after, err := e.store.LoadManifest()
			if err != nil {
				t.Fatal(err)
			}
			if !maps.EqualFunc(after.Tools, before.Tools, func(a, b Tool) bool { return reflect.DeepEqual(a, b) }) {
				t.Errorf("manifest after the refusal = %+v, want %+v", after.Tools, before.Tools)
			}
		})
	}
}

// TestUninstall_UsesRemovedDefinitions: manual uninstall commands must
// actually run on remove (they ride the job's removed map — the
// manifest row is already gone when the job executes), and the install
// state row goes with them. A row left behind after a successful
// uninstall is exactly the orphan reconcile has to sweep, and until it
// does the engine still claims an owned footprint it no longer has.
func TestUninstall_UsesRemovedDefinitions(t *testing.T) {
	e := newTestEngine(t, nil)
	marker := filepath.Join(e.toolsDir, "uninstall-ran")
	job, err := e.Add(t.Context(), &AddRequest{
		Name: "m", Source: SourceManual, Version: "1",
		Install:   binStub("m"),
		Uninstall: fmt.Sprintf(`touch %q`, marker),
	})
	if err != nil {
		t.Fatal(err)
	}
	waitJob(t, e, job.ID)
	if _, ok := e.store.State().Tools["m"]; !ok {
		t.Fatal("no install state row after the install: nothing for the uninstall to drop")
	}

	jv, _, err := e.Remove("m")
	if err != nil {
		t.Fatal(err)
	}
	final := waitJob(t, e, jv.ID)
	if final.State != JobDone {
		t.Errorf("uninstall job = %+v", final)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Error("manual uninstall command did not run")
	}
	if st, ok := e.store.State().Tools["m"]; ok {
		t.Errorf("install state row survived the uninstall: %+v", st)
	}
}

// TestLinkPMBins_PreservesOwnershipAcrossUpdates: an update whose
// binDiff finds nothing new must keep the previously recorded pm bins
// (multi-bin packages would otherwise read as uninstalled).
func TestLinkPMBins_PreservesOwnershipAcrossUpdates(t *testing.T) {
	dir := t.TempDir()
	in := &installer{toolsDir: dir, output: func(string) {}}
	pmBin := filepath.Join(dir, "npm", "bin")
	if err := os.MkdirAll(pmBin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(in.binDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{"tsc", "tsserver"} {
		if err := os.WriteFile(filepath.Join(pmBin, b), []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Update run: nothing newly added, previous ownership known.
	owned, err := in.linkPMBins(pmBin, nil, []string{"tsc", "tsserver"}, "typescript")
	if err != nil {
		t.Fatal(err)
	}
	if len(owned) != 2 {
		t.Errorf("owned = %v, want both prior bins", owned)
	}
	for _, b := range owned {
		if _, err := os.Lstat(filepath.Join(in.binDir(), b)); err != nil {
			t.Errorf("bin %s not linked", b)
		}
	}
}

// TestInstallAqua_SymlinkEscapeRejected: an archive member that is a
// symlink pointing outside the install tree must be rejected before
// chmod/link publishes it.
func TestInstallAqua_SymlinkEscapeRejected(t *testing.T) {
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Tarball containing bin/tool as a symlink to the victim path.
	var tarball strings.Builder
	gz := gzip.NewWriter(&nopWriteCloser{&tarball})
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Name: "bin/tool", Typeflag: tar.TypeSymlink, Linkname: victim, Mode: 0o777,
	}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(tarball.String()))
	}))
	defer srv.Close()

	aq := &AquaPackage{
		Type: "http", RepoOwner: "o", RepoName: "tool",
		URL: srv.URL + "/tool.tar.gz", Format: "tar.gz",
		Files: []AquaFile{{Name: "tool", Src: "bin/tool"}},
	}
	cat := &Catalog{Entries: map[string]CatalogEntry{
		"tool": {Name: "tool", Source: "aqua:o/tool", Aqua: aq},
	}}
	e := newTestEngine(t, cat)
	job, err := e.Add(t.Context(), &AddRequest{Name: "tool", Version: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	final := waitJob(t, e, job.ID)
	if final.State != JobFailed || !strings.Contains(final.Error, "unpack: bin/tool: symlink target") {
		t.Errorf("job = %+v, want the extraction to refuse the symlink", final)
	}
	if _, err := os.Lstat(filepath.Join(e.toolsDir, "bin", "tool")); !os.IsNotExist(err) {
		t.Error("escaping symlink was published to bin/")
	}
	if fi, _ := os.Stat(victim); fi.Mode().Perm() != 0o600 {
		t.Error("victim file permissions were changed")
	}
}

// TestValidToolName_ScopedEdgeCases pins the slash rule at both ends. The
// accepted side carries the two boundaries the rejected side cannot express: a
// single-character scope is the shortest legal `@scope/name`, and 80 characters
// is the length limit itself, which is inclusive.
func TestValidToolName_ScopedEdgeCases(t *testing.T) {
	bad := map[string]string{
		"@/x":        "an empty scope",
		"@x/":        "an empty name",
		"x/y":        "an unscoped slash",
		"@a/b/c":     "two slashes",
		"/x":         "a leading slash",
		longName(81): "one character past the length limit",
	}
	for n, why := range bad {
		if validToolName(n) {
			t.Errorf("validToolName(%q) = true, want false (%s)", n, why)
		}
	}
	good := map[string]string{
		"@scope/name": "the ordinary scoped shape",
		"@a/b":        "a single-character scope is the shortest legal scope",
		longName(80):  "80 characters is the limit, and the limit is allowed",
	}
	for n, why := range good {
		if !validToolName(n) {
			t.Errorf("validToolName(%q) = false, want true (%s)", n, why)
		}
	}
}

// longName returns a name of exactly n allowed characters.
func longName(n int) string { return strings.Repeat("a", n) }

// TestValidToolName_AcceptsEveryAlphanumericRangeEnd pins the inclusive ends
// of the three character ranges: a name like "JDK-21" or "Z3-9" is ordinary,
// and an off-by-one at a range end refuses it as an invalid name.
func TestValidToolName_AcceptsEveryAlphanumericRangeEnd(t *testing.T) {
	for _, name := range []string{"a", "z", "A", "Z", "0", "9"} {
		if !validToolName(name) {
			t.Errorf("validToolName(%q) = false, want true", name)
		}
	}
}

// TestValidToolName_PathComponents pins the half of the rule the charset
// alone cannot express: the name becomes a path component under opt/, and
// uninstall hands the whole join to os.RemoveAll, so a dot component would
// aim that removal at the shared opt tree ("." / "@a/..") or at its parent
// ("..") instead of at one tool's own directory.
//
// The accepted half is as load-bearing as the rejected one: dots and
// leading dots are legal in a tool name, and only an EXACT "." or ".."
// component is traversal.
func TestValidToolName_PathComponents(t *testing.T) {
	reject := map[string]string{
		"..":       "the parent of the opt tree",
		".":        "the opt tree itself",
		"":         "empty",
		"@a/..":    "a scoped name whose second component is the parent",
		"a/../b":   "a traversal spelled mid-name",
		"..\\evil": "a backslash is not an allowed name character, so it can never be a separator here",
	}
	for name, why := range reject {
		if validToolName(name) {
			t.Errorf("validToolName(%q) = true, want false (%s)", name, why)
		}
	}
	accept := map[string]string{
		"tool.v2":       "an embedded dot is an ordinary name character",
		"..extras":      "two leading dots are not a traversal component",
		"...":           "three dots is a directory name",
		"a..b":          "adjacent dots mid-name are ordinary",
		"@scope/a.b":    "a scoped name with a dotted second component",
		"@../x":         "`@..` is a directory name, not a traversal component: Join keeps it",
		"golangci-lint": "the ordinary shape",
	}
	for name, why := range accept {
		if !validToolName(name) {
			t.Errorf("validToolName(%q) = false, want true (%s)", name, why)
		}
	}
}

func TestPatch_ForceDisableCascades(t *testing.T) {
	e := newTestEngine(t, nil)
	addManual(t, e, "base", nil)
	addManual(t, e, "dep", []string{"base"})
	on := true
	if _, err := e.Patch("base", PatchRequest{Disabled: &on}); !errors.Is(err, ErrHasDependents) {
		t.Errorf("unforced disable with dependents: err = %v, want ErrHasDependents", err)
	}
	jv, err := e.Patch("base", PatchRequest{Disabled: &on, Force: true})
	if err != nil || jv == nil {
		t.Fatalf("forced disable: %v %v", jv, err)
	}
	if final := waitJob(t, e, jv.ID); final.State != JobDone {
		t.Errorf("disable job = %+v tail=%v", final, final.OutputTail)
	}
	m, err := e.store.LoadManifest()
	if err != nil {
		t.Fatal(err)
	}
	if !m.Tools["base"].Disabled || !m.Tools["dep"].Disabled {
		t.Errorf("force disable did not cascade: base=%+v dep=%+v", m.Tools["base"], m.Tools["dep"])
	}
	for _, bin := range []string{"base", "dep"} {
		if _, err := os.Stat(filepath.Join(e.toolsDir, "bin", bin)); !os.IsNotExist(err) {
			t.Errorf("%s footprint not uninstalled by the cascade", bin)
		}
	}
}

func TestWait_UnknownJobErrors(t *testing.T) {
	e := newTestEngine(t, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if _, err := e.Wait(ctx, "tj-nope"); !errors.Is(err, ErrUnknownJob) {
		t.Errorf("Wait on unknown id = %v, want ErrUnknownJob", err)
	}
	if ctx.Err() != nil {
		t.Error("Wait polled to deadline instead of returning immediately")
	}
}

// TestUpdateOne_SkipsUnresolvableCandidate pins the drift-window guard:
// a latest version the baked aqua definition cannot resolve must NOT be
// persisted into the manifest (the old version keeps working; the
// update is skipped with a log line).
func TestUpdateOne_SkipsUnresolvableCandidate(t *testing.T) {
	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"tag_name":"v9.9.9"}`)
	}))
	client := srv.Client()

	constrained := &AquaPackage{
		Type: aquaTypeGitHubRelease, RepoOwner: "o", RepoName: "r",
		Asset:         "tool-{{.Version}}.tar.gz",
		VersionConstr: `Version startsWith "1."`,
	}
	open := &AquaPackage{
		Type: aquaTypeGitHubRelease, RepoOwner: "o", RepoName: "r2",
		Asset: "tool2-{{.Version}}.tar.gz",
	}
	cat := &Catalog{Entries: map[string]CatalogEntry{
		"tool":  {Name: "tool", Source: "aqua:o/r", Aqua: constrained},
		"tool2": {Name: "tool2", Source: "aqua:o/r2", Aqua: open},
	}}
	e := newTestEngineClient(t, cat, client, nil)
	err := e.store.MutateManifest(func(m *Manifest) error {
		m.Tools["tool"] = Tool{Source: "aqua:o/r", Version: "1.0.0"}
		m.Tools["tool2"] = Tool{Source: "aqua:o/r2", Version: "1.0.0"}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := e.store.LoadManifest()
	if err != nil {
		t.Fatal(err)
	}

	var lines []string
	collect := func(s string) { lines = append(lines, s) }

	t.Run("unresolvable candidate skipped", func(t *testing.T) {
		did, err := e.updateOne(t.Context(), m, "tool", false, collect)
		if err != nil || did {
			t.Errorf("updateOne = %v %v, want skip without error", did, err)
		}
		cur, _ := e.store.LoadManifest()
		if got := cur.Tools["tool"].Version; got != "1.0.0" {
			t.Errorf("manifest bumped to unresolvable version %q", got)
		}
		if !strings.Contains(strings.Join(lines, "\n"), "not resolvable") {
			t.Errorf("skip not reported: %v", lines)
		}
	})
	t.Run("resolvable candidate still bumps", func(t *testing.T) {
		did, err := e.updateOne(t.Context(), m, "tool2", false, collect)
		if err != nil || !did {
			t.Errorf("updateOne = %v %v, want bump", did, err)
		}
		cur, _ := e.store.LoadManifest()
		if got := cur.Tools["tool2"].Version; got != "v9.9.9" {
			t.Errorf("resolvable bump not persisted: %q", got)
		}
	})
}

// logCapture collects slog records so a test can assert on the
// operator-facing log lines that are the only observable trace of some
// paths (an artifact installed without checksum verification, a probe
// that could not execute a recorded bin).
type logCapture struct {
	lines []string
	mu    sync.Mutex
}

func (*logCapture) Enabled(context.Context, slog.Level) bool { return true }

func (c *logCapture) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s", r.Level, r.Message)
	r.Attrs(func(a slog.Attr) bool {
		fmt.Fprintf(&b, " %s=%v", a.Key, a.Value)
		return true
	})
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, b.String())
	return nil
}

func (c *logCapture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *logCapture) WithGroup(string) slog.Handler      { return c }

// has reports whether any captured line carries every substring.
func (c *logCapture) has(parts ...string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, line := range c.lines {
		hit := true
		for _, p := range parts {
			if !strings.Contains(line, p) {
				hit = false
				break
			}
		}
		if hit {
			return true
		}
	}
	return false
}

// captureLogs points an engine's loggers at a capture handler.
func captureLogs(e *Engine) *logCapture {
	cap := &logCapture{}
	log := slog.New(cap)
	e.log = log
	e.inst.log = log
	return cap
}

// TestInstallAqua_ChecksumOutcomes pins the checksum invariant end to
// end. A DECLARED checksum source must produce a matching digest or the
// install is refused — an unfetchable checksum file, a file that does not
// list the asset, and a mismatching digest all abort with nothing linked
// and no state row. Only a definition that declares nothing (or whose
// upstream disabled verification) installs unverified, and that path is
// recorded in tools-state.json and warned about on the engine logger, so
// "this tool was installed unverified" is observable rather than inferred.
func TestInstallAqua_ChecksumOutcomes(t *testing.T) {
	payload := "#!/bin/sh\necho tool\n"
	sum := sha256.Sum256([]byte(payload))
	digest := hex.EncodeToString(sum[:])
	asset := "tool_1.0.0_linux_" + runtime.GOARCH + ".raw"
	off := false

	var checksumBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "sums.txt") {
			if checksumBody == "" {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(checksumBody))
			return
		}
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	cases := []struct {
		name      string
		checksum  *AquaChecksum
		body      string
		wantErr   string
		wantState string
		wantWarn  bool
	}{
		{
			name:      "declared and matching digest verifies",
			checksum:  &AquaChecksum{Type: aquaTypeHTTP, URL: srv.URL + "/sums.txt", Algorithm: "sha256"},
			body:      digest + "  " + asset + "\n",
			wantState: checksumVerified,
		},
		{
			name:     "declared but the checksum file cannot be fetched",
			checksum: &AquaChecksum{Type: aquaTypeHTTP, URL: srv.URL + "/sums.txt", Algorithm: "sha256"},
			body:     "", // 404
			wantErr:  "refusing to install",
		},
		{
			name:     "declared but the file does not list the asset",
			checksum: &AquaChecksum{Type: aquaTypeHTTP, URL: srv.URL + "/sums.txt", Algorithm: "sha256"},
			body:     digest + "  something-else.raw\n",
			wantErr:  "refusing to install",
		},
		{
			name:     "declared but the digest mismatches",
			checksum: &AquaChecksum{Type: aquaTypeHTTP, URL: srv.URL + "/sums.txt", Algorithm: "sha256"},
			body:     strings.Repeat("0", 64) + "  " + asset + "\n",
			wantErr:  "checksum mismatch",
		},
		{
			name:      "no checksum declared installs unverified, loudly",
			checksum:  nil,
			wantState: checksumUnverified,
			wantWarn:  true,
		},
		{
			name: "upstream disabled verification installs unverified, loudly",
			checksum: &AquaChecksum{
				Type: aquaTypeHTTP, URL: srv.URL + "/sums.txt", Algorithm: "sha256", Enabled: &off,
			},
			body:      digest + "  " + asset + "\n",
			wantState: checksumUnverified,
			wantWarn:  true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checksumBody = tc.body
			aq := &AquaPackage{
				Type: aquaTypeHTTP, RepoOwner: "o", RepoName: "tool",
				URL:      srv.URL + "/tool_{{trimV .Version}}_{{.OS}}_{{.Arch}}.raw",
				Format:   formatRaw,
				Files:    []AquaFile{{Name: "tool"}},
				Checksum: tc.checksum,
			}
			e := newTestEngine(t, &Catalog{Entries: map[string]CatalogEntry{
				"tool": {Name: "tool", Source: "aqua:o/tool", Aqua: aq},
			}})
			logs := captureLogs(e)

			job, err := e.Add(t.Context(), &AddRequest{Name: "tool", Version: "v1.0.0"})
			if err != nil {
				t.Fatal(err)
			}
			final := waitJob(t, e, job.ID)
			st := e.store.State().Tools["tool"]

			if tc.wantErr != "" {
				if final.State != JobFailed || !strings.Contains(final.Error, tc.wantErr) {
					t.Errorf("job = %+v, want failure containing %q", final, tc.wantErr)
				}
				if _, err := os.Lstat(filepath.Join(e.toolsDir, "bin", "tool")); !os.IsNotExist(err) {
					t.Error("bin linked despite a failed checksum")
				}
				if st.InstalledVersion != "" {
					t.Errorf("state records an install that was refused: %+v", st)
				}
				if !logs.has("ERROR", "REFUSING install", "tool=tool") {
					t.Error("refusal not logged at ERROR on the engine logger")
				}
				return
			}
			if final.State != JobDone {
				t.Errorf("job = %+v tail=%v", final, final.OutputTail)
			}
			if st.Checksum != tc.wantState {
				t.Errorf("state checksum = %q, want %q", st.Checksum, tc.wantState)
			}
			if got := logs.has("WARN", "UNVERIFIED", "tool=tool"); got != tc.wantWarn {
				t.Errorf("unverified warning logged = %v, want %v", got, tc.wantWarn)
			}
		})
	}
}

// TestVerifyArtifact_DeclaredWithoutSourceRefuses: a definition that
// DECLARES a checksum but whose source resolved to no URL must refuse the
// install. Nothing in the resolver is supposed to produce that spec, and
// that is the point — the install path no longer trusts an empty
// ChecksumURL to mean "this artifact needs no verification", so a future
// checksum type that forgets to error cannot silently install unverified.
func TestVerifyArtifact_DeclaredWithoutSourceRefuses(t *testing.T) {
	dir := t.TempDir()
	logs := &logCapture{}
	in := &installer{toolsDir: dir, output: func(string) {}, log: slog.New(logs)}
	artifact := filepath.Join(dir, "artifact")
	if err := os.WriteFile(artifact, []byte("bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		spec     *InstallSpec
		wantErr  string
		wantMark string
	}{
		{
			name:     "declared but unresolved refuses",
			spec:     &InstallSpec{URL: "https://example.com/x", ChecksumDeclared: true},
			wantErr:  "declares a checksum source",
			wantMark: "",
		},
		{
			name:     "undeclared installs unverified",
			spec:     &InstallSpec{URL: "https://example.com/x"},
			wantMark: checksumUnverified,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := in.verifyArtifact(t.Context(), "tool", "v1", downloaded{data: openArtifact(t, artifact), asset: "artifact"}, tc.spec)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("verifyArtifact = %q, %v; want error containing %q", got, err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.wantMark {
				t.Errorf("verifyArtifact = %q, %v; want %q, nil", got, err, tc.wantMark)
			}
		})
	}
}

// TestPruneOldVersions_Retention pins the retention policy: the current
// version always stays, the configured number of most recent previous
// versions stay with it (so a bad update has something to fall back to),
// and transient staging/backup residue is never retained.
func TestPruneOldVersions_Retention(t *testing.T) {
	cases := []struct {
		name string
		keep int
		want []string
	}{
		{name: "unset keeps one previous", keep: 0, want: []string{"v3.0.0", "v2.0.0"}},
		{name: "explicit two", keep: 2, want: []string{"v3.0.0", "v2.0.0", "v1.0.0"}},
		{name: "explicit one", keep: 1, want: []string{"v3.0.0", "v2.0.0"}},
		{name: "negative keeps none", keep: -1, want: []string{"v3.0.0"}},
		{name: "more than exist keeps all", keep: 9, want: []string{"v3.0.0", "v2.0.0", "v1.0.0", "v0.9.0"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			in := &installer{toolsDir: dir, output: func(string) {}}
			root := filepath.Join(in.optDir(), "tool")
			// Oldest first, with distinct mtimes: retention is newest-first.
			ages := map[string]time.Duration{
				"v0.9.0": 96 * time.Hour, "v1.0.0": 72 * time.Hour,
				"v2.0.0": 48 * time.Hour, "v3.0.0": 0,
				".v3.0.0" + stagingSuffix: 0, ".v2.0.0" + backupSuffix: 0,
			}
			for name, age := range ages {
				p := filepath.Join(root, name)
				if err := os.MkdirAll(p, 0o755); err != nil {
					t.Fatal(err)
				}
				when := time.Now().Add(-age)
				if err := os.Chtimes(p, when, when); err != nil {
					t.Fatal(err)
				}
			}
			in.pruneOldVersions("tool", "v3.0.0", tc.keep)

			entries, err := os.ReadDir(root)
			if err != nil {
				t.Fatal(err)
			}
			var left []string
			for _, e := range entries {
				left = append(left, e.Name())
			}
			slices.Sort(left)
			want := append([]string{}, tc.want...)
			slices.Sort(want)
			if !slices.Equal(left, want) {
				t.Errorf("surviving versions = %v, want %v", left, want)
			}
		})
	}
}

// TestMergeCatalogDefaults_KeepsFieldsTheRowAlreadySets pins the direction of
// the merge: the catalog fills what a row LEFT unset and never overwrites what
// the user wrote. Every field here is one an operator sets deliberately to
// diverge from the packaged definition — a description for their own inventory,
// and an uninstall or probe command for a tool the catalog describes wrongly —
// so a merge that wrote catalog values over them would silently discard the
// override and, for uninstall, run the wrong teardown command.
func TestMergeCatalogDefaults_KeepsFieldsTheRowAlreadySets(t *testing.T) {
	cat := CatalogEntry{
		Name:        "widget",
		Source:      SourceManual,
		Description: "catalog description",
		Install:     "catalog-install",
		Uninstall:   "catalog-uninstall",
		Probe:       "catalog-probe",
		Version:     "9.9.9",
	}
	tool := Tool{
		Source:      SourceManual,
		Description: "mine",
		Uninstall:   "my-uninstall",
		Probe:       "my-probe",
	}
	mergeCatalogDefaults(&tool, &cat)

	if tool.Description != "mine" {
		t.Errorf("Description = %q, want %q kept", tool.Description, "mine")
	}
	if tool.Uninstall != "my-uninstall" {
		t.Errorf("Uninstall = %q, want %q kept", tool.Uninstall, "my-uninstall")
	}
	if tool.Probe != "my-probe" {
		t.Errorf("Probe = %q, want %q kept", tool.Probe, "my-probe")
	}
	// The unset fields are the other half of the same rule: without them
	// passing, the three above could hold for a merge that does nothing.
	if tool.Install != "catalog-install" {
		t.Errorf("Install = %q, want the catalog value %q", tool.Install, "catalog-install")
	}
	if tool.Version != "9.9.9" {
		t.Errorf("Version = %q, want the catalog value %q", tool.Version, "9.9.9")
	}
}

// updatePayload is the runnable artifact each fixture tool ships: the probe
// executes what it finds in bin/, so a version tree has to hold a real (if
// trivial) program.
func updatePayload(tool, ver string) string {
	return "#!/bin/sh\necho " + tool + " " + ver + "\n"
}

// updateFixture serves every endpoint an aqua update walks — the release that
// names the latest tag, each tool's artifact, and the artifact's checksum — for
// any number of tools. The server runs on an in-memory network, so the
// definitions' real api.github.com and github.com URLs resolve to this one
// handler and the update path runs unmodified.
func updateFixture(t *testing.T, latestTag string, names ...string) (*http.Client, *Catalog) {
	t.Helper()
	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := filepath.Base(r.URL.Path)
		switch {
		case base == "latest":
			fmt.Fprintf(w, `{"tag_name":%q}`, latestTag)
		case strings.HasSuffix(base, ".txt"):
			tool, ver, _ := strings.Cut(strings.TrimSuffix(base, ".txt"), "_")
			sum := sha256.Sum256([]byte(updatePayload(tool, ver)))
			fmt.Fprintf(w, "%s  %s_%s.raw\n", hex.EncodeToString(sum[:]), tool, ver)
		case strings.HasSuffix(base, ".raw"):
			tool, ver, _ := strings.Cut(strings.TrimSuffix(base, ".raw"), "_")
			_, _ = w.Write([]byte(updatePayload(tool, ver)))
		default:
			http.NotFound(w, r)
		}
	}))
	entries := map[string]CatalogEntry{}
	for _, n := range names {
		entries[n] = CatalogEntry{Name: n, Source: "aqua:o/" + n, Aqua: &AquaPackage{
			Type: aquaTypeGitHubRelease, RepoOwner: "o", RepoName: n,
			Asset:  n + "_{{trimV .Version}}.raw",
			Format: formatRaw,
			Files:  []AquaFile{{Name: n}},
			Checksum: &AquaChecksum{
				Type: aquaTypeGitHubRelease, Asset: n + "_{{trimV .Version}}.txt",
				Algorithm: "sha256",
			},
		}}
	}
	return srv.Client(), &Catalog{Entries: entries}
}

// addFixtureTool installs one fixture tool at ver through the public Add path.
func addFixtureTool(t *testing.T, e *Engine, name, ver string, pin bool) {
	t.Helper()
	job, err := e.Add(t.Context(), &AddRequest{Name: name, Version: ver, Pin: pin})
	if err != nil {
		t.Fatalf("Add(%s %s): %v", name, ver, err)
	}
	if final := waitJob(t, e, job.ID); final.State != JobDone {
		t.Fatalf("install %s %s = %+v tail=%v", name, ver, final, final.OutputTail)
	}
}

// TestUpdate_PinRespectsTheJobScope pins the two halves of the pin rule, which
// between them decide whether pinning means anything: a scheduled pass over the
// whole manifest leaves a pinned tool where it is, and naming that tool is the
// operator's override that moves it.
//
// Both halves end at the STATE file, not just the manifest. An update that
// records the new version without reinstalling leaves the old binary on PATH
// while the inventory advertises the new one, which is the same bug from the
// consumer's side as not updating at all.
func TestUpdate_PinRespectsTheJobScope(t *testing.T) {
	t.Run("scheduled_pass_bumps_the_unpinned_tool_only", func(t *testing.T) {
		client, cat := updateFixture(t, "v2.0.0", "tool", "held")
		e := newTestEngineClient(t, cat, client, nil)
		addFixtureTool(t, e, "tool", "v1.0.0", false)
		addFixtureTool(t, e, "held", "v1.0.0", true)

		jv, err := e.Update()
		if err != nil {
			t.Fatalf("Update(): %v", err)
		}
		final := waitJob(t, e, jv.ID)
		if final.State != JobDone {
			t.Fatalf("update job = %+v tail=%v", final, final.OutputTail)
		}
		m, err := e.store.LoadManifest()
		if err != nil {
			t.Fatal(err)
		}
		if got := m.Tools["tool"].Version; got != "v2.0.0" {
			t.Errorf("manifest version of the unpinned tool = %q, want %q", got, "v2.0.0")
		}
		if got := m.Tools["held"].Version; got != "v1.0.0" {
			t.Errorf("manifest version of the pinned tool = %q, want %q untouched", got, "v1.0.0")
		}
		if got := e.store.State().Tools["tool"].InstalledVersion; got != "v2.0.0" {
			t.Errorf("installed version of the unpinned tool = %q, want %q: "+
				"the bump was recorded but never installed", got, "v2.0.0")
		}
		if got := e.store.State().Tools["held"].InstalledVersion; got != "v1.0.0" {
			t.Errorf("installed version of the pinned tool = %q, want %q untouched", got, "v1.0.0")
		}
	})
	t.Run("naming_the_pinned_tool_overrides_the_pin", func(t *testing.T) {
		client, cat := updateFixture(t, "v2.0.0", "held")
		e := newTestEngineClient(t, cat, client, nil)
		addFixtureTool(t, e, "held", "v1.0.0", true)

		jv, err := e.Update("held")
		if err != nil {
			t.Fatalf("Update(held): %v", err)
		}
		final := waitJob(t, e, jv.ID)
		if final.State != JobDone {
			t.Fatalf("update job = %+v tail=%v", final, final.OutputTail)
		}
		m, err := e.store.LoadManifest()
		if err != nil {
			t.Fatal(err)
		}
		if got := m.Tools["held"].Version; got != "v2.0.0" {
			t.Errorf("manifest version of the explicitly named pinned tool = %q, want %q", got, "v2.0.0")
		}
		if got := e.store.State().Tools["held"].InstalledVersion; got != "v2.0.0" {
			t.Errorf("installed version of the explicitly named pinned tool = %q, want %q", got, "v2.0.0")
		}
	})
}

// TestEnsureInstalled_ReportsAFailedInstallJob pins the synchronous contract
// the programmatic callers depend on: EnsureInstalled returns only once the
// tool is actually there. A caller that gets nil goes on to exec the binary,
// so swallowing a failed job turns "install gh, then use gh" into an
// exec-not-found further away from the cause.
func TestEnsureInstalled_ReportsAFailedInstallJob(t *testing.T) {
	e := newTestEngine(t, nil)
	job, err := e.Add(t.Context(), &AddRequest{
		Name: "broken", Source: SourceManual, Version: "1", Install: "exit 1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if final := waitJob(t, e, job.ID); final.State != JobFailed {
		t.Fatalf("baseline install = %+v, want a failed job to ensure against", final)
	}

	err = e.EnsureInstalled(t.Context(), "broken")
	if err == nil {
		t.Fatal("EnsureInstalled(broken) = nil, want an error: its install job failed")
	}
	if !strings.Contains(err.Error(), "broken") {
		t.Errorf("EnsureInstalled(broken) = %v, want the error to name the tool", err)
	}
}

// TestReconcile_AnnouncesOnlyThePassesItRuns pins the job log against the two
// passes it can report. The output IS the operator's account of what reconcile
// did, so announcing an uninstall pass on a converged-but-for-installs manifest
// (or the reverse) describes work that never happened and sends whoever reads it
// looking for a tool that was never touched.
func TestReconcile_AnnouncesOnlyThePassesItRuns(t *testing.T) {
	t.Run("only_missing_installs", func(t *testing.T) {
		e := newTestEngine(t, nil)
		err := e.store.MutateManifest(func(m *Manifest) error {
			m.Tools["absent"] = manualEntry("absent")
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		out := reconcileOutput(t, e)
		if !strings.Contains(out, "installing missing tools: absent") {
			t.Errorf("reconcile output = %q, want it to announce the install pass", out)
		}
		if strings.Contains(out, "uninstalling disabled tools") {
			t.Errorf("reconcile output = %q, want no uninstall pass announced: nothing was disabled", out)
		}
	})
	t.Run("only_disabled_uninstalls", func(t *testing.T) {
		e := newTestEngine(t, nil)
		addManual(t, e, "extra", nil)
		// Disable through the manifest rather than Patch, so the footprint
		// is still there when reconcile runs — the hand-edited-manifest
		// case reconcile exists for.
		err := e.store.MutateManifest(func(m *Manifest) error {
			tl := m.Tools["extra"]
			tl.Disabled = true
			m.Tools["extra"] = tl
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		out := reconcileOutput(t, e)
		if !strings.Contains(out, "uninstalling disabled tools: extra") {
			t.Errorf("reconcile output = %q, want it to announce the uninstall pass", out)
		}
		if strings.Contains(out, "installing missing tools") {
			t.Errorf("reconcile output = %q, want no install pass announced: nothing was missing", out)
		}
	})
}

// reconcileOutput runs one reconcile to completion and returns its job log.
func reconcileOutput(t *testing.T, e *Engine) string {
	t.Helper()
	jv, enqueued, err := e.Reconcile(ReconcileMissing)
	if err != nil || !enqueued {
		t.Fatalf("reconcile: job=%v enqueued=%v err=%v", jv, enqueued, err)
	}
	final := waitJob(t, e, jv.ID)
	if final.State != JobDone {
		t.Fatalf("reconcile job = %+v tail=%v", final, final.OutputTail)
	}
	return strings.Join(final.OutputTail, "\n")
}

// TestReconcileFull_UpdatePassRefusedByAFullQueue pins the degraded mode of the
// two-job reconcile. The update pass is the optional half: a queue with no room
// for it must not fail the reconcile the caller asked for, and the drop has to
// reach the log, because the caller is handed a reconcile job and has no other
// way to learn the update never ran.
func TestReconcileFull_UpdatePassRefusedByAFullQueue(t *testing.T) {
	e := newTestEngine(t, nil)
	logs := captureLogs(e)
	// Occupy the worker so nothing drains while the queue is filled.
	slow, err := e.Add(t.Context(), &AddRequest{
		Name: "slow", Source: SourceManual, Version: "1",
		Install: `sleep 3 && ` + binStub("slow"),
	})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if a := e.queue.Active(); a != nil && a.ID == slow.ID && a.State == JobRunning {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("slow job never started")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Leave room for exactly the reconcile job, so its update pass is the
	// enqueue that gets refused.
	for range jobQueueCap - 1 {
		if _, err := e.Update(); err != nil {
			t.Fatalf("filling the queue to cap-1: %v", err)
		}
	}

	jv, enqueued, err := e.Reconcile(ReconcileFull)
	if err != nil || !enqueued || jv == nil {
		t.Fatalf("full reconcile with a nearly full queue: job=%v enqueued=%v err=%v", jv, enqueued, err)
	}
	if !logs.has("update pass not enqueued") {
		t.Errorf("the dropped update pass was not logged: %v", logs.lines)
	}
}

func TestReconcile_AFullQueueCoalescesRatherThanRefuses(t *testing.T) {
	e := newTestEngine(t, nil)
	slow, err := e.Add(t.Context(), &AddRequest{
		Name: "slow", Source: SourceManual, Version: "1",
		Install: `sleep 3 && ` + binStub("slow"),
	})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if a := e.queue.Active(); a != nil && a.ID == slow.ID && a.State == JobRunning {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("slow job never started")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for range jobQueueCap {
		if _, err := e.Update(); err != nil {
			t.Fatalf("filling the queue to cap: %v", err)
		}
	}

	first, enqueued, err := e.Reconcile(ReconcileMissing)
	if err != nil || !enqueued || first == nil {
		t.Fatalf("Reconcile on a full queue = job %v, enqueued %v, err %v; want a queued reconcile", first, enqueued, err)
	}
	second, enqueued, err := e.Reconcile(ReconcileMissing)
	if err != nil || !enqueued || second == nil {
		t.Fatalf("second Reconcile = job %v, enqueued %v, err %v; want the queued reconcile", second, enqueued, err)
	}
	if second.ID != first.ID {
		t.Errorf("second Reconcile queued job %s, want the already-queued %s", second.ID, first.ID)
	}
	e.queue.mu.Lock()
	queued := len(e.queue.pending)
	e.queue.mu.Unlock()
	if queued != jobQueueCap+1 {
		t.Errorf("queued jobs = %d, want the %d updates plus one reconcile", queued, jobQueueCap)
	}
}

// TestToolInfo_CarriesChecksumOnlyWhileInstalled pins the fact behind the
// client's "no checksum" badge. The badge must not be derived from the
// source kind: 252 of the catalog's aqua entries declare no checksum
// while 402 declare one, so only the recorded outcome of the install
// that actually ran answers the question.
//
// The second half is the reason the row gates on Installed. A wiped
// tools volume leaves tools-state.json behind — nothing in the delete
// path ran — so a row that reported the surviving "verified" would be
// vouching for bytes that are gone.
func TestToolInfo_CarriesChecksumOnlyWhileInstalled(t *testing.T) {
	e := newTestEngine(t, nil)
	addManual(t, e, "hello", nil)
	// A manual source has no artifact to hash, so the install recorded
	// nothing; write the outcome an aqua or release install would have.
	if err := e.store.setToolStatus("hello", func(s *ToolStatus) {
		s.Checksum = checksumVerified
	}); err != nil {
		t.Fatal(err)
	}
	row := inventoryRow(t, e, "hello")
	if !row.Installed {
		t.Fatalf("Inventory row for hello = %+v, want an installed row", row)
	}
	if row.Checksum != checksumVerified {
		t.Errorf("Inventory row for hello: Checksum = %q, want %q", row.Checksum, checksumVerified)
	}

	if err := os.Remove(filepath.Join(e.toolsDir, "bin", "hello")); err != nil {
		t.Fatal(err)
	}
	e.probes.forget("hello")
	row = inventoryRow(t, e, "hello")
	if row.Installed {
		t.Fatalf("Inventory row for hello = %+v, want an uninstalled row after the bin was removed", row)
	}
	if row.Checksum != "" {
		t.Errorf("Inventory row for hello with the binary gone: Checksum = %q, want %q", row.Checksum, "")
	}
}

// inventoryRow returns the named inventory row, failing the test when it
// is absent.
func inventoryRow(t *testing.T, e *Engine, name string) ToolInfo {
	t.Helper()
	inv, err := e.Inventory()
	if err != nil {
		t.Fatalf("Setup: Inventory() = %v", err)
	}
	for _, row := range inv.Tools {
		if row.Name == name {
			return row
		}
	}
	t.Fatalf("Setup: Inventory() has no row named %q: %+v", name, inv.Tools)
	return ToolInfo{}
}

// TestRemove_RefusesAnEssentialTool pins the protection a consumer's
// selection declares. A UI that merely hides its delete button is not a
// guard — the API is reachable — so the refusal has to live here, and it
// has to survive the cascade: RemoveWithDependents deletes rows the caller
// never named, which is exactly how an essential tool would otherwise
// leave as somebody else's collateral.
//
// Disable stays available on purpose. It is the escape hatch for a user
// who wants the tool gone, and it keeps the row that carries the install
// knowledge, which is the thing deletion destroys.
func TestRemove_RefusesAnEssentialTool(t *testing.T) {
	e := newTestEngine(t, nil)
	addManual(t, e, "gh", nil)
	// dependant requires gh, so the cascade has something to walk.
	addManual(t, e, "dependant", []string{"gh"})
	// Declared by the SELECTION, which is the only authority: the engine
	// reads the live catalog on every removal.
	e.catalog.Store(&Catalog{Entries: map[string]CatalogEntry{
		"gh": {Name: "gh", Source: SourceManual, Essential: true},
	}})

	t.Run("remove is refused", func(t *testing.T) {
		_, _, err := e.Remove("gh")
		if !errors.Is(err, ErrEssential) {
			t.Errorf("Remove(gh) = %v, want ErrEssential", err)
		}
		if !strings.Contains(fmt.Sprint(err), "gh") {
			t.Errorf("Remove(gh) error = %v, want it to name the tool", err)
		}
	})

	t.Run("the cascade cannot take it as collateral", func(t *testing.T) {
		// Removing dependant does not touch gh, so this must SUCCEED —
		// the guard protects the essential row, not everything near it.
		if _, _, err := e.Remove("dependant"); err != nil {
			t.Fatalf("Remove(dependant) = %v, want nil: only gh is essential", err)
		}
	})

	t.Run("an essential dependent blocks a cascade", func(t *testing.T) {
		// base <- gh(essential): removing base with dependents would
		// delete gh, so the whole call is refused rather than half-done.
		addManual(t, e, "base", nil)
		if err := e.store.MutateManifest(func(m *Manifest) error {
			gh := m.Tools["gh"]
			gh.Requires = []string{"base"}
			m.Tools["gh"] = gh
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		// Re-store: Add(base) above resolved against the catalog, and the
		// row for gh must still be the essential one.
		e.catalog.Store(&Catalog{Entries: map[string]CatalogEntry{
			"gh": {Name: "gh", Source: SourceManual, Essential: true},
		}})
		_, _, err := e.RemoveWithDependents("base")
		if !errors.Is(err, ErrEssential) {
			t.Errorf("RemoveWithDependents(base) = %v, want ErrEssential", err)
		}
		m, _ := e.store.LoadManifest()
		if _, ok := m.Tools["base"]; !ok {
			t.Error("the refused cascade still deleted base: the manifest must be untouched")
		}
	})

	t.Run("disable is still allowed", func(t *testing.T) {
		yes := true
		if _, err := e.Patch("gh", PatchRequest{Disabled: &yes, Force: true}); err != nil {
			t.Errorf("Patch(gh, disabled) = %v, want nil: disable is the escape hatch", err)
		}
	})

	t.Run("the row reports it to a consumer", func(t *testing.T) {
		if row := inventoryRow(t, e, "gh"); !row.Essential {
			t.Errorf("Inventory row for gh = %+v, want Essential set", row)
		}
	})
}

// TestResolve_HydratesEssentialFromTheCatalog covers the other half: the
// flag is the SELECTION's live answer, so it is re-read on every resolve
// rather than merged only when unset. A product that stops depending on a
// tool has to be able to release it, and a manifest row written months ago
// must not pin the old answer.
func TestResolve_HydratesEssentialFromTheCatalog(t *testing.T) {
	cat := &Catalog{Entries: map[string]CatalogEntry{
		"gh": {
			Name: "gh", Source: SourceManual, Version: "1",
			Install: binStub("gh"), Probe: "gh", Essential: true,
		},
	}}
	e := newTestEngine(t, cat)
	job, err := e.Add(t.Context(), &AddRequest{Name: "gh"})
	if err != nil {
		t.Fatalf("Add(gh) = %v", err)
	}
	if final := waitJob(t, e, job.ID); final.State != JobDone {
		t.Fatalf("install gh = %+v tail=%v", final, final.OutputTail)
	}
	if row := inventoryRow(t, e, "gh"); !row.Essential {
		t.Errorf("Inventory row for gh = %+v, want Essential hydrated from the catalog", row)
	}
	if _, _, err := e.Remove("gh"); !errors.Is(err, ErrEssential) {
		t.Errorf("Remove(gh) = %v, want ErrEssential from a catalog-declared flag", err)
	}

	// And released again when the selection drops it: the manifest row
	// still carries true from the install above, so this fails if the
	// merge is once-only.
	e.catalog.Store(&Catalog{Entries: map[string]CatalogEntry{
		"gh": {Name: "gh", Source: SourceManual, Version: "1", Install: binStub("gh"), Probe: "gh"},
	}})
	if _, _, err := e.Remove("gh"); err != nil {
		t.Errorf("Remove(gh) after the selection released it = %v, want nil", err)
	}
}

// pipEngine is an engine whose catalog implies no backend for pip:, holding
// the enabled row x at 1.0.0 with the given python request.
func pipEngine(t *testing.T, python string) *Engine {
	t.Helper()
	e := newTestEngine(t, &Catalog{Entries: map[string]CatalogEntry{}, Backends: map[string]string{SourcePip: ""}})
	if err := e.store.MutateManifest(func(m *Manifest) error {
		m.Tools["x"] = Tool{Source: "pip:x", Version: "1.0.0", Python: python}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return e
}

// TestInstallTool_ReinstallsWhenThePythonRequestChanged pins that a venv
// built on another interpreter request is rebuilt even though the version
// matches and the launcher runs, and that the rebuilt row then converges.
func TestInstallTool_ReinstallsWhenThePythonRequestChanged(t *testing.T) {
	argv := fakeUV(t)
	e := pipEngine(t, "3.14")
	writeStub(t, e, "x", "echo x 1.0.0")
	if err := e.store.setToolStatus("x", func(s *ToolStatus) {
		s.InstalledVersion = "1.0.0"
		s.PMBins = []string{"x"}
	}); err != nil {
		t.Fatal(err)
	}

	job, err := e.Install("x")
	if err != nil {
		t.Fatal(err)
	}
	if final := waitJob(t, e, job.ID); final.State != JobDone {
		t.Fatalf("install job = %s, want done (tail %v)", final.State, final.OutputTail)
	}
	if got, want := readArgv(t, argv), []string{"tool install --reinstall --python 3.14 x==1.0.0"}; !slices.Equal(got, want) {
		t.Errorf("uv argv = %q, want %q", got, want)
	}
	if got := e.store.State().Tools["x"].Python; got != "3.14" {
		t.Errorf("recorded python = %q, want 3.14", got)
	}

	job, err = e.Install("x")
	if err != nil {
		t.Fatal(err)
	}
	final := waitJob(t, e, job.ID)
	if out := strings.Join(final.OutputTail, "\n"); !strings.Contains(out, "x 1.0.0 already installed") {
		t.Errorf("second install output = %q, want already installed", out)
	}
	if got := readArgv(t, argv); len(got) != 1 {
		t.Errorf("uv ran %d times, want once (argv %q)", len(got), got)
	}
}

// venvUV puts a uv on PATH that appends its argv and interpreter env to the
// returned file, modelling uv 0.13.6's venv handling. `tool uninstall` drops
// the x venv and launcher. `tool install` exits 1 when failInstall is set,
// before touching anything, as uv does when resolution fails. --python R
// targets the newest UV_PYTHON_INSTALL_DIR entry cpython-R or cpython-R.*
// (cpython-R.0 standing for a download) and rebuilds a venv not on it.
// Without --python, as for a receipt that pins a request, a venv with a
// resolvable bin/python is kept. --force drops the venv.
func venvUV(t *testing.T, failInstall bool) string {
	t.Helper()
	dir := t.TempDir()
	argv := filepath.Join(dir, "argv")
	fail := ""
	if failInstall {
		fail = "exit 1\n"
	}
	script := "#!/bin/sh\n" +
		"echo \"$* UV_MANAGED_PYTHON=$UV_MANAGED_PYTHON UV_PYTHON_INSTALL_DIR=$UV_PYTHON_INSTALL_DIR\" >> " + argv + "\n" +
		"if [ \"$2\" = uninstall ]; then rm -rf \"$UV_TOOL_DIR/x\" \"$UV_TOOL_BIN_DIR/x\"; exit 0; fi\n" +
		fail +
		"case \" $* \" in *\" --force \"*) rm -rf \"$UV_TOOL_DIR/x\";; esac\n" +
		"req=; prev=\n" +
		"for a in \"$@\"; do [ \"$prev\" = --python ] && req=\"$a\"; prev=\"$a\"; done\n" +
		"home=\"$UV_PYTHON_INSTALL_DIR/cpython-3.15.2/bin\"\n" +
		"if [ -n \"$req\" ]; then\n" +
		"target=$(ls -d \"$UV_PYTHON_INSTALL_DIR/cpython-$req\" \"$UV_PYTHON_INSTALL_DIR/cpython-$req\".* 2>/dev/null | sort -V | tail -n 1)\n" +
		"home=\"${target:-$UV_PYTHON_INSTALL_DIR/cpython-$req.0}/bin\"\n" +
		"grep -qxF \"home = $home\" \"$UV_TOOL_DIR/x/pyvenv.cfg\" 2>/dev/null || rm -rf \"$UV_TOOL_DIR/x\"\n" +
		"fi\n" +
		"if [ ! -e \"$UV_TOOL_DIR/x/bin/python\" ]; then\n" +
		"mkdir -p \"$home\" \"$UV_TOOL_DIR/x/bin\"\n" +
		"touch \"$home/python3\"\n" +
		"echo \"home = $home\" > \"$UV_TOOL_DIR/x/pyvenv.cfg\"\n" +
		"ln -sf \"$home/python3\" \"$UV_TOOL_DIR/x/bin/python\"\n" +
		"fi\n" +
		"printf '#!/bin/sh\\necho x 1.0.0\\n' > \"$UV_TOOL_BIN_DIR/x\"\n" +
		"chmod +x \"$UV_TOOL_BIN_DIR/x\"\n"
	if err := os.WriteFile(filepath.Join(dir, "uv"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return argv
}

// TestInstall_RebuildsAVenvOnAnUnmanagedInterpreter pins the migration of a
// venv built before the engine managed interpreters: it reads as not
// installed, and an install names the interpreter, so uv builds a new venv on
// a managed one. A venv already on the newest managed one is reinstalled in
// place.
func TestInstall_RebuildsAVenvOnAnUnmanagedInterpreter(t *testing.T) {
	cases := []struct {
		name      string
		recorded  string
		home      func(e *Engine) string
		installed bool
	}{
		{
			name: "unmanaged interpreter", recorded: "1.0.0",
			home:      func(*Engine) string { return newInterpreterHome(t, t.TempDir()) },
			installed: false,
		},
		{
			name: "managed interpreter with an outdated version", recorded: "0.9.0",
			home:      func(e *Engine) string { return newInterpreterHome(t, pythonInterpreterDir(e.toolsDir)) },
			installed: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			argv := venvUV(t, false)
			e := pipEngine(t, "")
			writeStub(t, e, "x", "echo x 1.0.0")
			if err := e.store.setToolStatus("x", func(s *ToolStatus) {
				s.InstalledVersion = tc.recorded
				s.PMBins = []string{"x"}
			}); err != nil {
				t.Fatal(err)
			}
			writeVenv(t, e, "x", tc.home(e))
			if got := inventoryRow(t, e, "x").Installed; got != tc.installed {
				t.Errorf("inventory before the install: installed = %v, want %v", got, tc.installed)
			}

			job, err := e.Install("x")
			if err != nil {
				t.Fatal(err)
			}

			if final := waitJob(t, e, job.ID); final.State != JobDone {
				t.Fatalf("install job = %s, want done (tail %v)", final.State, final.OutputTail)
			}
			interpreters := pythonInterpreterDir(e.toolsDir)
			want := []string{"tool install --reinstall --python 3 x==1.0.0 UV_MANAGED_PYTHON=1 UV_PYTHON_INSTALL_DIR=" + interpreters}
			if got := readArgv(t, argv); !slices.Equal(got, want) {
				t.Errorf("uv runs = %q, want %q", got, want)
			}
			if !inventoryRow(t, e, "x").Installed {
				t.Error("inventory after the install: x not installed")
			}
			cfg, err := os.ReadFile(filepath.Join(e.toolsDir, "python", "tools", "x", "pyvenv.cfg"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(cfg), "home = "+interpreters+string(os.PathSeparator)) {
				t.Errorf("pyvenv.cfg = %q, want home under %s", cfg, interpreters)
			}
		})
	}
}

// TestInstall_UnresolvableRebuildKeepsTheVenv pins that rebuilding a venv on
// an unmanaged interpreter never removes it first: when uv cannot resolve the
// new one, the old venv and its launcher still run the tool.
func TestInstall_UnresolvableRebuildKeepsTheVenv(t *testing.T) {
	argv := venvUV(t, true)
	e := pipEngine(t, "")
	writeStub(t, e, "x", "echo x 1.0.0")
	if err := e.store.setToolStatus("x", func(s *ToolStatus) {
		s.InstalledVersion = "1.0.0"
		s.PMBins = []string{"x"}
	}); err != nil {
		t.Fatal(err)
	}
	home := newInterpreterHome(t, t.TempDir())
	writeVenv(t, e, "x", home)
	launcher := filepath.Join(pythonBinDir(e.toolsDir), "x")
	if err := os.MkdirAll(filepath.Dir(launcher), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(launcher, []byte("#!/bin/sh\necho x 1.0.0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	job, err := e.Install("x")
	if err != nil {
		t.Fatal(err)
	}

	if final := waitJob(t, e, job.ID); final.State != JobFailed {
		t.Fatalf("install job = %s, want failed (tail %v)", final.State, final.OutputTail)
	}
	want := []string{"tool install --reinstall --python 3 x==1.0.0 UV_MANAGED_PYTHON=1 UV_PYTHON_INSTALL_DIR=" + pythonInterpreterDir(e.toolsDir)}
	if got := readArgv(t, argv); !slices.Equal(got, want) {
		t.Errorf("uv runs = %q, want %q", got, want)
	}
	cfg, err := os.ReadFile(filepath.Join(e.toolsDir, "python", "tools", "x", "pyvenv.cfg"))
	if err != nil {
		t.Errorf("venv after the failed rebuild: %v", err)
	} else if !strings.Contains(string(cfg), "home = "+home+"\n") {
		t.Errorf("pyvenv.cfg = %q, want the old home %s", cfg, home)
	}
	if _, err := os.Stat(launcher); err != nil {
		t.Errorf("launcher after the failed rebuild: %v", err)
	}
}

// TestInstall_RebuildsAVenvWhoseInterpreterIsGone pins the recovery path:
// after an inventory read cached the launcher as working, its venv's
// interpreter is deleted; an explicit install must then rebuild the venv
// through uv on the engine-managed interpreters instead of reporting
// "already installed".
func TestInstall_RebuildsAVenvWhoseInterpreterIsGone(t *testing.T) {
	argv := venvUV(t, false)
	e := pipEngine(t, "")
	writeStub(t, e, "x", "echo x 1.0.0")
	if err := e.store.setToolStatus("x", func(s *ToolStatus) {
		s.InstalledVersion = "1.0.0"
		s.PMBins = []string{"x"}
	}); err != nil {
		t.Fatal(err)
	}
	dead := newInterpreterHome(t, pythonInterpreterDir(e.toolsDir))
	writeVenv(t, e, "x", dead)
	if !inventoryRow(t, e, "x").Installed {
		t.Fatal("inventory before the interpreter died: x not installed")
	}
	if err := os.RemoveAll(filepath.Dir(dead)); err != nil {
		t.Fatal(err)
	}

	job, err := e.Install("x")
	if err != nil {
		t.Fatal(err)
	}

	if final := waitJob(t, e, job.ID); final.State != JobDone {
		t.Fatalf("install job = %s, want done (tail %v)", final.State, final.OutputTail)
	}
	interpreters := filepath.Join(e.toolsDir, "python", "interpreters")
	want := []string{"tool install --reinstall --python 3 x==1.0.0 UV_MANAGED_PYTHON=1 UV_PYTHON_INSTALL_DIR=" + interpreters}
	if got := readArgv(t, argv); !slices.Equal(got, want) {
		t.Errorf("uv runs = %q, want %q", got, want)
	}
	cfg, err := os.ReadFile(filepath.Join(e.toolsDir, "python", "tools", "x", "pyvenv.cfg"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cfg), "home = "+interpreters+string(os.PathSeparator)) {
		t.Errorf("rebuilt pyvenv.cfg = %q, want home under %s", cfg, interpreters)
	}
}

// TestInstall_ClearingThePythonRequestRebuildsOnTheNewest pins that removing
// an entry's python request moves its venv to the newest managed interpreter:
// uv keeps a venv whose receipt pins a request unless the install names an
// interpreter (uv 0.13.6 install.rs#L1113).
func TestInstall_ClearingThePythonRequestRebuildsOnTheNewest(t *testing.T) {
	argv := venvUV(t, false)
	e := pipEngine(t, "")
	writeStub(t, e, "x", "echo x 1.0.0")
	if err := e.store.setToolStatus("x", func(s *ToolStatus) {
		s.InstalledVersion = "1.0.0"
		s.Python = "3.14"
		s.PMBins = []string{"x"}
	}); err != nil {
		t.Fatal(err)
	}
	interpreters := pythonInterpreterDir(e.toolsDir)
	writeVenv(t, e, "x", interpreterHomeAt(t, interpreters, "cpython-3.14.10"))
	newest := interpreterHomeAt(t, interpreters, "cpython-3.15.2")

	job, err := e.Install("x")
	if err != nil {
		t.Fatal(err)
	}

	if final := waitJob(t, e, job.ID); final.State != JobDone {
		t.Fatalf("install job = %s, want done (tail %v)", final.State, final.OutputTail)
	}
	want := []string{"tool install --reinstall --python 3 x==1.0.0 UV_MANAGED_PYTHON=1 UV_PYTHON_INSTALL_DIR=" + interpreters}
	if got := readArgv(t, argv); !slices.Equal(got, want) {
		t.Errorf("uv runs = %q, want %q", got, want)
	}
	cfg, err := os.ReadFile(filepath.Join(e.toolsDir, "python", "tools", "x", "pyvenv.cfg"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cfg), "home = "+newest+"\n") {
		t.Errorf("pyvenv.cfg = %q, want home %s", cfg, newest)
	}
	if got := e.store.State().Tools["x"].Python; got != "" {
		t.Errorf("recorded python = %q, want empty", got)
	}
}

func TestPatch_PythonRequest(t *testing.T) {
	t.Run("a change on an enabled row reinstalls with the request", func(t *testing.T) {
		argv := fakeUV(t)
		e := pipEngine(t, "")
		py := "3.13"

		job, err := e.Patch("x", PatchRequest{Python: &py})

		if err != nil || job == nil {
			t.Fatalf("Patch(python) = %v, %v, want an install job", job, err)
		}
		if final := waitJob(t, e, job.ID); final.State != JobDone {
			t.Errorf("install job = %s, want done (tail %v)", final.State, final.OutputTail)
		}
		if got, want := readArgv(t, argv), []string{"tool install --reinstall --python 3.13 x==1.0.0"}; !slices.Equal(got, want) {
			t.Errorf("uv argv = %q, want %q", got, want)
		}
	})
	t.Run("the same value enqueues nothing", func(t *testing.T) {
		e := pipEngine(t, "3.13")
		py := "3.13"
		if job, err := e.Patch("x", PatchRequest{Python: &py}); err != nil || job != nil {
			t.Errorf("Patch(same python) = %v, %v, want nil, nil", job, err)
		}
	})
	t.Run("a template stores the request without a job", func(t *testing.T) {
		e := pipEngine(t, "")
		disabled := true
		if _, err := e.Patch("x", PatchRequest{Disabled: &disabled}); err != nil {
			t.Fatal(err)
		}
		py := "3.13"

		job, err := e.Patch("x", PatchRequest{Python: &py})

		if err != nil || job != nil {
			t.Errorf("Patch(python) on a template = %v, %v, want nil, nil", job, err)
		}
		if m, _ := e.store.LoadManifest(); m.Tools["x"].Python != "3.13" {
			t.Errorf("stored python = %q, want 3.13", m.Tools["x"].Python)
		}
	})
	t.Run("a path is refused and nothing changes", func(t *testing.T) {
		e := pipEngine(t, "3.13")
		py := "/usr/bin/python3"

		job, err := e.Patch("x", PatchRequest{Python: &py})

		if err == nil || job != nil {
			t.Errorf("Patch(python path) = %v, %v, want an error", job, err)
		}
		if m, _ := e.store.LoadManifest(); m.Tools["x"].Python != "3.13" {
			t.Errorf("stored python = %q, want 3.13 unchanged", m.Tools["x"].Python)
		}
	})
	t.Run("a non-pip row is refused", func(t *testing.T) {
		e := newTestEngine(t, nil)
		addManual(t, e, "m", nil)
		py := "3.13"
		if _, err := e.Patch("m", PatchRequest{Python: &py}); err == nil || !strings.Contains(err.Error(), "only to pip:") {
			t.Errorf("Patch(python) on a manual row error = %v, want the pip-only refusal", err)
		}
	})
}

func TestAdd_RefusesAPythonRequestOnANonPipSource(t *testing.T) {
	e := newTestEngine(t, nil)

	_, err := e.Add(t.Context(), &AddRequest{Name: "pyright", Source: "npm:pyright", Version: "1.1.0", Python: "3.14"})

	if err == nil || !strings.Contains(err.Error(), "only to pip:") {
		t.Errorf("Add error = %v, want the pip-only refusal", err)
	}
	if m, _ := e.store.LoadManifest(); len(m.Tools) != 0 {
		t.Errorf("manifest = %v, want no row", m.Tools)
	}
}

// TestInstall_RefusesARowTheHydratedSourceCannotTake: a source-less row's
// version and python pass ParseManifest on the union grammar alone, so
// hydration must not persist a source that makes the document unreadable;
// the row stays source-less and its own install names the refusal.
func TestInstall_RefusesARowTheHydratedSourceCannotTake(t *testing.T) {
	cases := []struct {
		name string
		row  Tool
		want string
	}{
		{name: "python on an npm source", row: Tool{Python: "3.14"}, want: `x: the catalog's source npm:x refuses this entry: python applies only to pip: sources`},
		{name: "a Debian epoch on an npm source", row: Tool{Version: "1:2.3"}, want: `x: the catalog's source npm:x refuses this entry: version "1:2.3" is not a release tag`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEngine(t, &Catalog{
				Entries:  map[string]CatalogEntry{"x": {Source: "npm:x", Version: "1.0.0"}},
				Backends: map[string]string{SourceNpm: ""},
			})
			if err := e.store.MutateManifest(func(m *Manifest) error {
				m.Tools["x"] = tc.row
				return nil
			}); err != nil {
				t.Fatal(err)
			}

			job, err := e.Install("x")
			if err != nil {
				t.Fatal(err)
			}
			final := waitJob(t, e, job.ID)

			if final.State != JobFailed || !strings.Contains(final.Error, tc.want) {
				t.Errorf("install job = %s %q, want failed containing %q", final.State, final.Error, tc.want)
			}
			m, err := e.store.LoadManifest()
			if err != nil {
				t.Fatalf("manifest unreadable after the job: %v", err)
			}
			if got := m.Tools["x"].Source; got != "" {
				t.Errorf("source = %q, want the row left source-less", got)
			}
		})
	}
}

// TestMutateManifest_RefusesADocumentItsReaderRefuses: the reader refuses
// the whole document over one bad row, so a write of one would fail every
// later read and New.
func TestMutateManifest_RefusesADocumentItsReaderRefuses(t *testing.T) {
	e := newTestEngine(t, nil)

	err := e.store.MutateManifest(func(m *Manifest) error {
		m.Tools["jq"] = Tool{Source: "aqua:jqlang/jq", Version: "../x"}
		return nil
	})

	if err == nil || !strings.Contains(err.Error(), "jq:") {
		t.Errorf("MutateManifest error = %v, want one naming jq", err)
	}
	m, err := e.store.LoadManifest()
	if err != nil {
		t.Fatalf("manifest unreadable after the refused write: %v", err)
	}
	if _, ok := m.Tools["jq"]; ok {
		t.Error("the refused row was written")
	}
}

// TestPatch_QueueFullLeavesEveryField: a patch whose job the queue
// refuses is refused whole, so the manifest never records a request no job
// will realise (a disabled row at a new version, an enabled one whose old
// install stays on disk).
func TestPatch_QueueFullLeavesEveryField(t *testing.T) {
	str := func(s string) *string { return &s }
	yes, no := true, false
	pipRow := Tool{Source: "pip:x", Version: "1.0.0", Python: "3.13"}
	manualRow := Tool{
		Source: SourceManual, Version: "1", Description: "d", Install: "true",
		Uninstall: "true", VersionArgs: []string{"-V"},
	}
	disabledRow := manualRow
	disabledRow.Disabled = true
	cases := []struct {
		name string
		row  Tool
		req  PatchRequest
	}{
		{name: "python on an enabled row", row: pipRow, req: PatchRequest{Python: str("3.14")}},
		{name: "disable with a python change", row: pipRow, req: PatchRequest{Disabled: &yes, Python: str("3.14")}},
		{name: "disable with a version change", row: manualRow, req: PatchRequest{Disabled: &yes, Version: str("2")}},
		{name: "enable with a version change", row: disabledRow, req: PatchRequest{Disabled: &no, Version: str("2")}},
		{name: "every field in one request", row: manualRow, req: PatchRequest{
			Version: str("2"), Pin: &yes, Description: str("e"), Requires: &[]string{"slow"},
			Install: str("exit 0"), Uninstall: str("exit 0"), VersionArgs: &[]string{"--version"},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := pipEngine(t, "3.13")
			saturateQueue(t, e)
			if err := e.store.MutateManifest(func(m *Manifest) error {
				m.Tools["x"] = tc.row
				return nil
			}); err != nil {
				t.Fatalf("Setup: %v", err)
			}

			if _, err := e.Patch("x", tc.req); !errors.Is(err, ErrQueueFull) {
				t.Errorf("Patch on a full queue = %v, want ErrQueueFull", err)
			}
			m, err := e.store.LoadManifest()
			if err != nil {
				t.Fatal(err)
			}
			assertPatchFields(t, m.Tools["x"], tc.row)
		})
	}
	t.Run("a forced disable leaves its dependents enabled", func(t *testing.T) {
		e := pipEngine(t, "3.13")
		saturateQueue(t, e)
		dependent := manualRow
		dependent.Requires = []string{"x"}
		if err := e.store.MutateManifest(func(m *Manifest) error {
			m.Tools["app"] = dependent
			return nil
		}); err != nil {
			t.Fatalf("Setup: %v", err)
		}

		if _, err := e.Patch("x", PatchRequest{Disabled: &yes, Force: true, Version: str("2.0.0")}); !errors.Is(err, ErrQueueFull) {
			t.Errorf("Patch on a full queue = %v, want ErrQueueFull", err)
		}
		m, err := e.store.LoadManifest()
		if err != nil {
			t.Fatal(err)
		}
		assertPatchFields(t, m.Tools["x"], pipRow)
		assertPatchFields(t, m.Tools["app"], dependent)
	})
}

func assertPatchFields(t *testing.T, got, want Tool) {
	t.Helper()
	if got.Version != want.Version || got.Python != want.Python || got.Disabled != want.Disabled ||
		got.Pin != want.Pin || got.Description != want.Description || got.Install != want.Install ||
		got.Uninstall != want.Uninstall {
		t.Errorf("row = {version %q python %q disabled %v pin %v description %q install %q uninstall %q}, "+
			"want {version %q python %q disabled %v pin %v description %q install %q uninstall %q}",
			got.Version, got.Python, got.Disabled, got.Pin, got.Description, got.Install, got.Uninstall,
			want.Version, want.Python, want.Disabled, want.Pin, want.Description, want.Install, want.Uninstall)
	}
	if !slices.Equal(got.Requires, want.Requires) {
		t.Errorf("requires = %q, want %q", got.Requires, want.Requires)
	}
	if !slices.Equal(got.VersionArgs, want.VersionArgs) {
		t.Errorf("version_args = %q, want %q", got.VersionArgs, want.VersionArgs)
	}
}

// fakeRoot makes AptAvailable answer as it does for root, so the apt paths
// run against stubs unprivileged. Call it before newTestEngine: cleanups run
// last in, first out, so the engine's worker stops before geteuid is restored.
func fakeRoot(t *testing.T) {
	t.Helper()
	prev := geteuid
	geteuid = func() int { return 0 }
	t.Cleanup(func() { geteuid = prev })
}

// aptStub models dpkg for one amd64 jq with logging apt-mark, apt-get,
// dpkg-query and apt-cache stubs. Its dir's files are dpkg's record (installed
// holds the version, empty for setAptRow's 1.6-1; held; foreign-held, a held
// installed i386 copy): a held absent package reads "hold not-installed", none
// reads unknown. A gated first argument waits until open(it). apt-get installs
// `pkg=version`'s version, else the candidate (always, with ignore-pin), and
// refuses a held package (or foreign-conflicts) and an unflagged downgrade as
// apt-get -y does (apt-get(8)); set and failQueriesAfter switch failures on.
type aptStub struct {
	dir, log string
}

// aptStubCandidate is the version the stub's apt-cache and apt-get install
// for a bare package name.
const aptStubCandidate = "1.7.1-1"

// aptGetInstallLine is the apt-get call the stub logs for an install whose
// arguments after the install verb are args.
func aptGetInstallLine(args ...string) string {
	return "apt-get -o DPkg::Lock::Timeout=60 -y --no-install-recommends install " + strings.Join(args, " ")
}

// stubApt puts the stubs ahead of the real trusted dirs rather than
// replacing them: the stubs and the queue's jobs still resolve sh, touch and
// rm there, and the set must be in place before the engine's worker starts
// reading it.
func stubApt(t *testing.T, gated ...string) *aptStub {
	t.Helper()
	s := &aptStub{dir: t.TempDir()}
	s.log = filepath.Join(s.dir, "apt.log")
	d := s.dir + "/"
	gate := ""
	for _, g := range gated {
		gate += g + ") while [ ! -e " + d + g + " ]; do sleep 0.02; done;;\n"
	}
	wait := "case \"$1\" in\n" + gate + "esac\n"
	scripts := map[string]string{
		"apt-mark": "echo \"mark $*\" >> " + s.log + "\n" + wait +
			"[ -e " + d + "mark-fail ] && { echo 'E: apt-mark failed' >&2; exit 1; }\n" +
			"case \"$1\" in hold) touch " + d + "held;; unhold) rm -f " + d + "held;; esac\n" +
			"echo \"mark-end $1\" >> " + s.log + "\n",
		"apt-get": "echo \"apt-get $*\" >> " + s.log + "\n" + wait +
			"if [ -e " + d + "held ] || [ -e " + d + "foreign-conflicts ]; then case \" $* \" in *' --allow-change-held-packages '*) ;; *)\n" +
			"echo 'E: Held packages were changed and -y was used without --allow-change-held-packages.' >&2; exit 100;; esac; fi\n" +
			"[ -e " + d + "get-fail ] && { echo 'E: install failed' >&2; exit 100; }\n" +
			"[ -e " + d + "get-noop ] && exit 0\n" +
			"allow=; for a; do [ \"$a\" = --allow-downgrades ] && allow=1; last=$a; done\n" +
			"want=" + aptStubCandidate + "; case $last in *=*) [ -e " + d + "ignore-pin ] || want=${last#*=};; esac\n" +
			"if [ -e " + d + "installed ]; then cur=$(cat " + d + "installed); cur=${cur:-1.6-1}\n" +
			"[ \"$want\" != \"$cur\" ] && [ -z \"$allow\" ] && [ \"$(printf '%s\\n%s\\n' \"$want\" \"$cur\" | sort -V | head -n 1)\" = \"$want\" ] &&\n" +
			"{ echo 'E: Packages were downgraded and -y was used without --allow-downgrades.' >&2; exit 100; }; fi\n" +
			"echo \"$want\" > " + d + "installed\n" +
			"echo \"apt-get-end $1\" >> " + s.log + "\n",
		"dpkg-query": "if [ -e " + d + "query-budget ]; then read n < " + d + "query-budget\n" +
			"[ \"$n\" -gt 0 ] || { echo 'dpkg-query: error: parsing file /var/lib/dpkg/status' >&2; exit 2; }\n" +
			"echo $((n - 1)) > " + d + "query-budget; fi\n" +
			"want=install; [ -e " + d + "held ] && want=hold\n" +
			"status=installed; version=$(cat " + d + "installed 2>/dev/null); version=${version:-1.6-1}\n" +
			"[ -e " + d + "installed ] || { status=not-installed; version=; }\n" +
			"native=; if [ $status = installed ] || [ $want = hold ]; then native=1; fi\n" +
			"foreign=; [ -e " + d + "foreign-held ] && foreign=1\n" +
			"[ -n \"$native$foreign\" ] || { echo \"dpkg-query: no packages found matching $4\" >&2; exit 1; }\n" +
			"case \"$2\" in *Status-Want*) if [ -n \"$foreign\" ]; then printf 'i386\\thold\\tinstalled\\t1.6-1\\n'; fi\n" +
			"if [ -n \"$native\" ]; then printf 'amd64\\t%s\\t%s\\t%s\\n' $want $status \"$version\"; fi;;\n" +
			"*) echo \"$status $version\";; esac\n",
		"apt-cache": "[ \"$1\" = policy ] || exit 1\nprintf 'jq:\\n  Installed: 1.6-1\\n  Candidate: " + aptStubCandidate + "\\n'\n",
		"dpkg":      "[ \"$1\" = --print-architecture ] && echo amd64\n",
	}
	for name, body := range scripts {
		if err := os.WriteFile(filepath.Join(s.dir, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatalf("Setup: %v", err)
		}
	}
	prev := systemBinDirs
	systemBinDirs = append([]string{s.dir}, prev...)
	t.Cleanup(func() { systemBinDirs = prev })
	return s
}

// set creates the named state files: installed and held, mark-fail and
// get-fail to fail apt-mark and apt-get, get-noop for an apt-get that
// installs nothing, ignore-pin, foreign-held and foreign-conflicts.
func (s *aptStub) set(t *testing.T, names ...string) {
	t.Helper()
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(s.dir, n), nil, 0o600); err != nil {
			t.Fatalf("Setup: %v", err)
		}
	}
}

// setInstalled records the package installed at version.
func (s *aptStub) setInstalled(t *testing.T, version string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(s.dir, "installed"), []byte(version+"\n"), 0o600); err != nil {
		t.Fatalf("Setup: %v", err)
	}
}

// installedVersion is the version dpkg reports, empty when not installed.
func (s *aptStub) installedVersion(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(s.dir, "installed"))
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return cmp.Or(strings.TrimSpace(string(data)), "1.6-1")
}

// failQueriesAfter lets n more dpkg-query calls answer, then fails each
// later one with exit 2, dpkg-query's fatal-error status.
func (s *aptStub) failQueriesAfter(t *testing.T, n int) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(s.dir, "query-budget"), []byte(strconv.Itoa(n)+"\n"), 0o600); err != nil {
		t.Fatalf("Setup: %v", err)
	}
}

// clear removes a state file.
func (s *aptStub) clear(t *testing.T, name string) {
	t.Helper()
	if err := os.Remove(filepath.Join(s.dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

// held reports dpkg's hold in the model.
func (s *aptStub) held(t *testing.T) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(s.dir, "held"))
	return err == nil
}

// open releases the calls waiting on gate; safe from another goroutine.
func (s *aptStub) open(t *testing.T, gate string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(s.dir, gate), nil, 0o600); err != nil {
		t.Errorf("open gate %s: %v", gate, err)
	}
}

func (s *aptStub) lines(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(s.log)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

// ran reports whether any logged call starts with prefix.
func (s *aptStub) ran(t *testing.T, prefix string) bool {
	t.Helper()
	return slices.ContainsFunc(s.lines(t), func(l string) bool { return strings.HasPrefix(l, prefix) })
}

// await reports whether a call logged line within d.
func (s *aptStub) await(t *testing.T, line string, d time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if slices.Contains(s.lines(t), line) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// setAptRow writes a jq apt: row at 1.6-1; recorded also writes a state row
// at that version, so the install fast path takes it as already installed.
func setAptRow(t *testing.T, e *Engine, pin, recorded bool) {
	t.Helper()
	if err := e.store.MutateManifest(func(m *Manifest) error {
		m.Tools["jq"] = Tool{Source: "apt:jq", Version: "1.6-1", Pin: pin}
		return nil
	}); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if !recorded {
		return
	}
	if err := e.store.setToolStatus("jq", func(st *ToolStatus) { st.InstalledVersion = "1.6-1" }); err != nil {
		t.Fatalf("Setup: %v", err)
	}
}

// wantJobState waits for the job and checks its terminal state.
func wantJobState(t *testing.T, e *Engine, jv *Job, want string) {
	t.Helper()
	if jv == nil {
		t.Fatalf("job = nil, want one ending %s", want)
	}
	if got := waitJob(t, e, jv.ID); got.State != want {
		t.Errorf("job %s = %s (%s), want %s; output %q", jv.Kind, got.State, got.Error, want, got.OutputTail)
	}
}

// TestAptHold_FollowsThePin: the manifest pin is the dpkg hold the engine
// wants, so every job that installs an apt: row ends with the hold equal to
// the row's pin as it stands then, a hold failure fails the job, and
// Reconcile repairs a hold that disagrees with the pin.
func TestAptHold_FollowsThePin(t *testing.T) {
	yes, no, v := true, false, "1.7.1-1"
	patch := func(t *testing.T, e *Engine, req *PatchRequest) *Job {
		t.Helper()
		jv, err := e.Patch("jq", *req)
		if err != nil {
			t.Fatalf("Patch = %v", err)
		}
		return jv
	}
	install := func(t *testing.T, e *Engine) *Job {
		t.Helper()
		jv, err := e.Install("jq")
		if err != nil {
			t.Fatalf("Install(jq) = %v", err)
		}
		return jv
	}
	reconcile := func(t *testing.T, e *Engine) *Job {
		t.Helper()
		jv, _, err := e.Reconcile(ReconcileMissing)
		if err != nil {
			t.Fatalf("Reconcile = %v", err)
		}
		return jv
	}
	pinnedInstall := aptGetInstallLine("--", "jq=1.6-1")

	t.Run("a refused patch runs no apt call", func(t *testing.T) {
		fakeRoot(t)
		s := stubApt(t)
		s.set(t, "installed")
		e := newTestEngine(t, nil)
		saturateQueue(t, e)
		setAptRow(t, e, false, true)

		if _, err := e.Patch("jq", PatchRequest{Pin: &yes, Version: &v}); !errors.Is(err, ErrQueueFull) {
			t.Errorf("Patch on a full queue = %v, want ErrQueueFull", err)
		}
		if got := s.lines(t); got != nil {
			t.Errorf("apt calls = %q for a refused patch, want none", got)
		}
	})
	t.Run("a pin holds the installed package without reinstalling it", func(t *testing.T) {
		fakeRoot(t)
		s := stubApt(t)
		s.set(t, "installed")
		e := newTestEngine(t, nil)
		setAptRow(t, e, false, true)

		wantJobState(t, e, patch(t, e, &PatchRequest{Pin: &yes}), JobDone)

		if !s.held(t) {
			t.Errorf("held = false after a pin; calls %q", s.lines(t))
		}
		if s.ran(t, "apt-get") {
			t.Errorf("calls = %q, want no apt-get for an installed package", s.lines(t))
		}
	})
	t.Run("an unpin releases the hold", func(t *testing.T) {
		fakeRoot(t)
		s := stubApt(t)
		s.set(t, "installed", "held")
		e := newTestEngine(t, nil)
		setAptRow(t, e, true, true)

		wantJobState(t, e, patch(t, e, &PatchRequest{Pin: &no}), JobDone)

		if s.held(t) {
			t.Errorf("held = true after an unpin; calls %q", s.lines(t))
		}
	})
	t.Run("a pin where apt is unavailable queues no job", func(t *testing.T) {
		prev := geteuid
		geteuid = func() int { return 1000 }
		t.Cleanup(func() { geteuid = prev })
		s := stubApt(t)
		e := newTestEngine(t, nil)
		setAptRow(t, e, false, true)

		if jv := patch(t, e, &PatchRequest{Pin: &yes}); jv != nil {
			t.Errorf("Patch(pin) job = %+v, want none without apt", jv)
		}
		if m, _ := e.store.LoadManifest(); !m.Tools["jq"].Pin {
			t.Error("manifest pin = false, want the pin stored")
		}
		if got := s.lines(t); got != nil {
			t.Errorf("apt calls = %q, want none", got)
		}
	})
	t.Run("a patch after a remove runs no apt call", func(t *testing.T) {
		fakeRoot(t)
		s := stubApt(t)
		e := newTestEngine(t, nil)
		setAptRow(t, e, false, false)
		if _, _, err := e.Remove("jq"); err != nil {
			t.Fatalf("Remove = %v", err)
		}

		if _, err := e.Patch("jq", PatchRequest{Pin: &yes}); !errors.Is(err, ErrNotFound) {
			t.Errorf("Patch after Remove = %v, want ErrNotFound", err)
		}
		if got := s.lines(t); got != nil {
			t.Errorf("apt calls = %q for a removed row, want none", got)
		}
	})
	t.Run("a version patch on a held pinned row installs and stays held", func(t *testing.T) {
		fakeRoot(t)
		s := stubApt(t)
		s.set(t, "installed", "held")
		e := newTestEngine(t, nil)
		setAptRow(t, e, true, true)

		wantJobState(t, e, patch(t, e, &PatchRequest{Version: &v, Pin: &yes}), JobDone)

		if !s.ran(t, "apt-get-end") {
			t.Errorf("calls = %q, want apt-get to install the new version", s.lines(t))
		}
		if !s.held(t) {
			t.Errorf("held = false, want the pinned row held after its install; calls %q", s.lines(t))
		}
	})
	t.Run("an explicit update of a held pinned row installs and stays held", func(t *testing.T) {
		fakeRoot(t)
		s := stubApt(t)
		s.set(t, "installed", "held")
		e := newTestEngine(t, nil)
		setAptRow(t, e, true, true)

		jv, err := e.Update("jq")
		if err != nil {
			t.Fatalf("Update(jq) = %v", err)
		}
		wantJobState(t, e, jv, JobDone)

		if m, _ := e.store.LoadManifest(); m.Tools["jq"].Version != v {
			t.Errorf("manifest version = %q, want the candidate %s", m.Tools["jq"].Version, v)
		}
		if !s.held(t) {
			t.Errorf("held = false, want the pinned row held after its update; calls %q", s.lines(t))
		}
	})
	t.Run("a failed install restores the hold it lifted", func(t *testing.T) {
		fakeRoot(t)
		s := stubApt(t)
		s.set(t, "installed", "held", "get-fail")
		e := newTestEngine(t, nil)
		setAptRow(t, e, true, true)

		wantJobState(t, e, patch(t, e, &PatchRequest{Version: &v}), JobFailed)

		if !s.held(t) {
			t.Errorf("held = false after a failed install of a pinned row; calls %q", s.lines(t))
		}
	})
	t.Run("a failed apt-mark fails the install and reconcile repairs it", func(t *testing.T) {
		fakeRoot(t)
		s := stubApt(t)
		s.set(t, "mark-fail")
		e := newTestEngine(t, nil)
		setAptRow(t, e, true, false)

		wantJobState(t, e, install(t, e), JobFailed)
		if got := e.store.State().Tools["jq"].LastError; !strings.Contains(got, "apt-mark hold jq") {
			t.Errorf("recorded error = %q, want the apt-mark failure", got)
		}
		s.clear(t, "mark-fail")
		wantJobState(t, e, reconcile(t, e), JobDone)

		if !s.held(t) {
			t.Errorf("held = false after the reconcile; calls %q", s.lines(t))
		}
		if got := e.store.State().Tools["jq"].LastError; got != "" {
			t.Errorf("recorded error = %q after the repair, want none", got)
		}
	})
	t.Run("an install releases the hold on a package that is not installed", func(t *testing.T) {
		fakeRoot(t)
		s := stubApt(t)
		s.set(t, "held")
		e := newTestEngine(t, nil)
		setAptRow(t, e, false, false)

		wantJobState(t, e, install(t, e), JobDone)

		if s.held(t) || !s.ran(t, "apt-get-end") {
			t.Errorf("held = %v, calls %q; want the hold released and apt-get to install", s.held(t), s.lines(t))
		}
	})
	t.Run("a failed hold query fails the pin and reconcile repairs it", func(t *testing.T) {
		fakeRoot(t)
		s := stubApt(t)
		s.set(t, "installed")
		e := newTestEngine(t, nil)
		setAptRow(t, e, false, true)
		// The fast path's probe answers; the hold sync's query is the one
		// that fails.
		s.failQueriesAfter(t, 1)

		wantJobState(t, e, patch(t, e, &PatchRequest{Pin: &yes}), JobFailed)
		if got := e.store.State().Tools["jq"].LastError; !strings.Contains(got, "parsing file") {
			t.Errorf("recorded error = %q, want the dpkg-query failure", got)
		}
		if s.ran(t, "mark") {
			t.Errorf("calls = %q, want no apt-mark over an unread record", s.lines(t))
		}
		s.clear(t, "query-budget")
		wantJobState(t, e, reconcile(t, e), JobDone)

		if !s.held(t) {
			t.Errorf("held = false after the reconcile; calls %q", s.lines(t))
		}
		if got := e.store.State().Tools["jq"].LastError; got != "" {
			t.Errorf("recorded error = %q after the repair, want none", got)
		}
	})
	t.Run("reconcile holds a pinned package the image already ships", func(t *testing.T) {
		fakeRoot(t)
		s := stubApt(t)
		s.set(t, "installed")
		e := newTestEngine(t, nil)
		setAptRow(t, e, true, true)

		wantJobState(t, e, reconcile(t, e), JobDone)

		if !s.held(t) {
			t.Errorf("held = false after the reconcile; calls %q", s.lines(t))
		}
		if s.ran(t, "apt-get") {
			t.Errorf("calls = %q, want no apt-get for an installed package", s.lines(t))
		}
	})
	t.Run("reconcile releases a hold on an unpinned row", func(t *testing.T) {
		fakeRoot(t)
		s := stubApt(t)
		s.set(t, "installed", "held")
		e := newTestEngine(t, nil)
		setAptRow(t, e, false, true)

		wantJobState(t, e, reconcile(t, e), JobDone)

		if s.held(t) {
			t.Errorf("held = true after the reconcile of an unpinned row; calls %q", s.lines(t))
		}
	})
	t.Run("a converged row reconciles without apt-get or apt-mark", func(t *testing.T) {
		fakeRoot(t)
		s := stubApt(t)
		s.set(t, "installed", "held")
		e := newTestEngine(t, nil)
		setAptRow(t, e, true, true)

		wantJobState(t, e, reconcile(t, e), JobDone)

		if s.ran(t, "mark") || s.ran(t, "apt-get") {
			t.Errorf("calls = %q, want none for a converged row", s.lines(t))
		}
	})
	t.Run("overlapping pin patches end with the hold equal to the last pin", func(t *testing.T) {
		fakeRoot(t)
		s := stubApt(t, "unhold")
		s.set(t, "installed", "held")
		e := newTestEngine(t, nil)
		setAptRow(t, e, true, true)

		unpin := patch(t, e, &PatchRequest{Pin: &no})
		if !s.await(t, "mark unhold -- jq", 5*time.Second) {
			t.Fatalf("Setup: the unpin never ran apt-mark: %q", s.lines(t))
		}
		pin := patch(t, e, &PatchRequest{Pin: &yes})
		s.open(t, "unhold")
		wantJobState(t, e, unpin, JobDone)
		wantJobState(t, e, pin, JobDone)

		if m, _ := e.store.LoadManifest(); !m.Tools["jq"].Pin {
			t.Errorf("manifest pin = false, want the later patch's true")
		}
		if !s.held(t) {
			t.Errorf("held = false, want the last patch's pin; calls %q", s.lines(t))
		}
	})
	t.Run("an install of an unpinned row runs no apt-mark", func(t *testing.T) {
		fakeRoot(t)
		s := stubApt(t)
		e := newTestEngine(t, nil)
		setAptRow(t, e, false, false)

		wantJobState(t, e, install(t, e), JobDone)

		if s.ran(t, "mark") || s.held(t) {
			t.Errorf("calls = %q, want no apt-mark", s.lines(t))
		}
	})
	t.Run("an unpin during the install stands", func(t *testing.T) {
		fakeRoot(t)
		s := stubApt(t, "-o")
		e := newTestEngine(t, nil)
		setAptRow(t, e, true, false)
		jv := install(t, e)
		if !s.await(t, pinnedInstall, 5*time.Second) {
			t.Fatalf("Setup: the install never ran apt-get: %q", s.lines(t))
		}

		unpin := patch(t, e, &PatchRequest{Pin: &no})
		s.open(t, "-o")
		wantJobState(t, e, jv, JobDone)
		wantJobState(t, e, unpin, JobDone)

		if s.held(t) {
			t.Errorf("held = true, want the unpin to stand; calls %q", s.lines(t))
		}
	})
	t.Run("a remove during the install adds no hold", func(t *testing.T) {
		fakeRoot(t)
		s := stubApt(t, "-o")
		e := newTestEngine(t, nil)
		setAptRow(t, e, true, false)
		jv := install(t, e)
		if !s.await(t, pinnedInstall, 5*time.Second) {
			t.Fatalf("Setup: the install never ran apt-get: %q", s.lines(t))
		}

		if _, _, err := e.Remove("jq"); err != nil {
			t.Fatalf("Remove = %v", err)
		}
		s.open(t, "-o")
		waitJob(t, e, jv.ID)

		if s.held(t) || s.ran(t, "mark hold") {
			t.Errorf("calls = %q, want no hold for a removed row", s.lines(t))
		}
	})
}

// TestAptInstall_PinnedRowInstallsTheExactVersion: a pin means this version,
// so apt-get is asked for `pkg=version` (apt-get(8)) and the package ends at
// it, held, with the state naming it.
func TestAptInstall_PinnedRowInstallsTheExactVersion(t *testing.T) {
	fakeRoot(t)
	s := stubApt(t)
	e := newTestEngine(t, nil)
	setAptRow(t, e, true, false)

	jv, err := e.Install("jq")
	if err != nil {
		t.Fatalf("Install(jq) = %v", err)
	}
	wantJobState(t, e, jv, JobDone)

	if !slices.Contains(s.lines(t), aptGetInstallLine("--", "jq=1.6-1")) {
		t.Errorf("calls = %q, want apt-get to install jq=1.6-1", s.lines(t))
	}
	if got := s.installedVersion(t); got != "1.6-1" {
		t.Errorf("dpkg reports jq %q, want the pinned 1.6-1", got)
	}
	if got := e.store.State().Tools["jq"].InstalledVersion; got != "1.6-1" {
		t.Errorf("installed version = %q, want 1.6-1", got)
	}
	if !s.held(t) {
		t.Errorf("held = false, want the pinned row held; calls %q", s.lines(t))
	}
}

// TestAptInstall_PinnedDowngradeCarriesTheFlag: apt-get -y refuses to
// downgrade without --allow-downgrades (apt-get(8)), a flag that covers the
// whole transaction, so only an install moving the package off another
// installed version carries it.
func TestAptInstall_PinnedDowngradeCarriesTheFlag(t *testing.T) {
	cases := []struct {
		name      string
		installed string
		want      string
	}{
		{name: "a downgrade from the candidate", installed: aptStubCandidate, want: aptGetInstallLine("--allow-downgrades", "--", "jq=1.6-1")},
		{name: "a fresh install", want: aptGetInstallLine("--", "jq=1.6-1")},
		{name: "a reinstall at the pinned version", installed: "1.6-1", want: aptGetInstallLine("--", "jq=1.6-1")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fakeRoot(t)
			s := stubApt(t)
			if tc.installed != "" {
				s.setInstalled(t, tc.installed)
			}
			e := newTestEngine(t, nil)
			setAptRow(t, e, true, false)

			jv, err := e.Install("jq")
			if err != nil {
				t.Fatalf("Install(jq) = %v", err)
			}
			wantJobState(t, e, jv, JobDone)

			if !slices.Contains(s.lines(t), tc.want) {
				t.Errorf("calls = %q, want %q", s.lines(t), tc.want)
			}
			if got := s.installedVersion(t); got != "1.6-1" {
				t.Errorf("dpkg reports jq %q, want the pinned 1.6-1", got)
			}
		})
	}
}

// TestAptInstall_PinnedVersionThatLandsElsewhereFailsTheJob: when apt-get
// succeeds but dpkg reports another version than the pin, the job fails
// naming both, and the state records what dpkg installed.
func TestAptInstall_PinnedVersionThatLandsElsewhereFailsTheJob(t *testing.T) {
	fakeRoot(t)
	s := stubApt(t)
	s.set(t, "ignore-pin")
	e := newTestEngine(t, nil)
	setAptRow(t, e, true, false)

	jv, err := e.Install("jq")
	if err != nil {
		t.Fatalf("Install(jq) = %v", err)
	}
	wantJobState(t, e, jv, JobFailed)

	st := e.store.State().Tools["jq"]
	if want := "dpkg reports jq " + aptStubCandidate + ", the entry pins 1.6-1"; !strings.Contains(st.LastError, want) {
		t.Errorf("recorded error = %q, want it to carry %q", st.LastError, want)
	}
	if st.InstalledVersion != aptStubCandidate {
		t.Errorf("installed version = %q, want dpkg's %s", st.InstalledVersion, aptStubCandidate)
	}
}

// TestAptInstall_NothingInstalledRecordsNoVersion: an apt-get that succeeds
// while dpkg still reports the package absent fails the job and records no
// installed version, since nothing landed.
func TestAptInstall_NothingInstalledRecordsNoVersion(t *testing.T) {
	fakeRoot(t)
	s := stubApt(t)
	s.set(t, "get-noop")
	e := newTestEngine(t, nil)
	setAptRow(t, e, false, false)

	jv, err := e.Install("jq")
	if err != nil {
		t.Fatalf("Install(jq) = %v", err)
	}
	wantJobState(t, e, jv, JobFailed)

	st := e.store.State().Tools["jq"]
	if !strings.Contains(st.LastError, "apt-get succeeded but dpkg reports jq is not installed") {
		t.Errorf("recorded error = %q, want dpkg's absent package after apt-get", st.LastError)
	}
	if st.InstalledVersion != "" {
		t.Errorf("installed version = %q, want none recorded", st.InstalledVersion)
	}
}

// TestAptInstall_FailedReadAfterInstallIsRecordedByTheNextReconcile: when
// dpkg-query fails after apt-get installed the package, the job fails with
// nothing recorded, and the next Reconcile installs again and records the
// version dpkg reports, in the state and the unpinned row, with the error
// cleared.
func TestAptInstall_FailedReadAfterInstallIsRecordedByTheNextReconcile(t *testing.T) {
	for _, tc := range []struct {
		name     string
		recorded bool
		reads    int
	}{
		{name: "no recorded version", recorded: false, reads: 2},
		// The install's fast path reads dpkg first.
		{name: "an older recorded version", recorded: true, reads: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeRoot(t)
			s := stubApt(t)
			e := newTestEngine(t, nil)
			setAptRow(t, e, false, tc.recorded)
			// The install's own read and the hold lift's answer; the read
			// after apt-get is the one that fails.
			s.failQueriesAfter(t, tc.reads)

			jv, err := e.Install("jq")
			if err != nil {
				t.Fatalf("Install(jq) = %v", err)
			}
			wantJobState(t, e, jv, JobFailed)
			if !s.ran(t, "apt-get-end") || s.installedVersion(t) != aptStubCandidate {
				t.Fatalf("calls = %q, dpkg at %q; want apt-get to have installed %s", s.lines(t), s.installedVersion(t), aptStubCandidate)
			}
			if got := e.store.State().Tools["jq"].LastError; !strings.Contains(got, "parsing file") {
				t.Fatalf("recorded error = %q, want the dpkg-query failure", got)
			}

			s.clear(t, "query-budget")
			rj, _, err := e.Reconcile(ReconcileMissing)
			if err != nil {
				t.Fatalf("Reconcile = %v", err)
			}
			wantJobState(t, e, rj, JobDone)

			st := e.store.State().Tools["jq"]
			if st.InstalledVersion != aptStubCandidate || st.LastError != "" {
				t.Errorf("state = %q (error %q), want dpkg's %s and no error", st.InstalledVersion, st.LastError, aptStubCandidate)
			}
			if m, _ := e.store.LoadManifest(); m.Tools["jq"].Version != aptStubCandidate {
				t.Errorf("manifest version = %q, want dpkg's %s", m.Tools["jq"].Version, aptStubCandidate)
			}
		})
	}
}

// TestAptInstall_UnpinnedRowRecordsWhatDpkgInstalled: an unpinned row's
// version is the candidate it last saw, so apt-get gets the bare name, the
// state and the manifest take the version dpkg reports, and the next
// Reconcile has nothing to do.
func TestAptInstall_UnpinnedRowRecordsWhatDpkgInstalled(t *testing.T) {
	fakeRoot(t)
	s := stubApt(t)
	e := newTestEngine(t, nil)
	setAptRow(t, e, false, false)

	jv, err := e.Install("jq")
	if err != nil {
		t.Fatalf("Install(jq) = %v", err)
	}
	wantJobState(t, e, jv, JobDone)

	if !slices.Contains(s.lines(t), aptGetInstallLine("--", "jq")) {
		t.Errorf("calls = %q, want apt-get to install the bare jq", s.lines(t))
	}
	if got := e.store.State().Tools["jq"].InstalledVersion; got != aptStubCandidate {
		t.Errorf("installed version = %q, want dpkg's %s", got, aptStubCandidate)
	}
	if m, _ := e.store.LoadManifest(); m.Tools["jq"].Version != aptStubCandidate {
		t.Errorf("manifest version = %q, want dpkg's %s", m.Tools["jq"].Version, aptStubCandidate)
	}
	rj, _, err := e.Reconcile(ReconcileMissing)
	if err != nil {
		t.Fatalf("Reconcile = %v", err)
	}
	if out := strings.Join(waitJob(t, e, rj.ID).OutputTail, "\n"); !strings.Contains(out, "everything converged") {
		t.Errorf("reconcile output = %q, want everything converged", out)
	}
}

// TestAptInstall_CandidateRewriteKeepsAConcurrentEdit: the manifest takes
// dpkg's version only while the row is still unpinned and at the version the
// job read, so a Patch made during the install is not undone.
func TestAptInstall_CandidateRewriteKeepsAConcurrentEdit(t *testing.T) {
	yes, other := true, "1.5-1"
	cases := []struct {
		name  string
		patch PatchRequest
		// wantVersion is the manifest version once both jobs end, and
		// wantInstalls the apt-get installs that took: the Patch's own job
		// installs again only when it finds its edit standing.
		wantVersion  string
		wantInstalls int
	}{
		{name: "a pin", patch: PatchRequest{Pin: &yes}, wantVersion: "1.6-1", wantInstalls: 2},
		{name: "a version", patch: PatchRequest{Version: &other}, wantVersion: aptStubCandidate, wantInstalls: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fakeRoot(t)
			s := stubApt(t, "-o")
			e := newTestEngine(t, nil)
			setAptRow(t, e, false, false)
			jv, err := e.Install("jq")
			if err != nil {
				t.Fatalf("Install(jq) = %v", err)
			}
			if !s.await(t, aptGetInstallLine("--", "jq"), 5*time.Second) {
				t.Fatalf("Setup: the install never ran apt-get: %q", s.lines(t))
			}

			pj, err := e.Patch("jq", tc.patch)
			if err != nil || pj == nil {
				t.Fatalf("Patch = %v, %v, want a job", pj, err)
			}
			s.open(t, "-o")
			wantJobState(t, e, jv, JobDone)
			wantJobState(t, e, pj, JobDone)

			if m, _ := e.store.LoadManifest(); m.Tools["jq"].Version != tc.wantVersion {
				t.Errorf("manifest version = %q, want %s", m.Tools["jq"].Version, tc.wantVersion)
			}
			if n := strings.Count(strings.Join(s.lines(t), "\n"), "apt-get-end"); n != tc.wantInstalls {
				t.Errorf("apt-get installed %d times, want %d; calls %q", n, tc.wantInstalls, s.lines(t))
			}
		})
	}
}

// TestAptInstall_FailedCandidateRewriteFailsTheJob: a manifest that cannot
// take dpkg's version fails the job and records why on the row, rather than
// a done job leaving the two files naming different versions.
func TestAptInstall_FailedCandidateRewriteFailsTheJob(t *testing.T) {
	fakeRoot(t)
	s := stubApt(t, "-o")
	e := newTestEngine(t, nil)
	setAptRow(t, e, false, false)
	jv, err := e.Install("jq")
	if err != nil {
		t.Fatalf("Install(jq) = %v", err)
	}
	if !s.await(t, aptGetInstallLine("--", "jq"), 5*time.Second) {
		t.Fatalf("Setup: the install never ran apt-get: %q", s.lines(t))
	}
	// A directory where the manifest was fails every later read and write.
	if err := os.Remove(e.store.manifestPath); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if err := os.Mkdir(e.store.manifestPath, 0o755); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	s.open(t, "-o")
	wantJobState(t, e, jv, JobFailed)

	if got := e.store.State().Tools["jq"].LastError; !strings.Contains(got, "record jq's installed version "+aptStubCandidate) {
		t.Errorf("recorded error = %q, want the manifest write failure", got)
	}
}

// TestReconcile_ReinstallsAPinnedAptRowAtAnotherVersion: a pinned row whose
// package dpkg reports at another version is not converged, so Reconcile
// installs the pinned version, downgrading, and holds it.
func TestReconcile_ReinstallsAPinnedAptRowAtAnotherVersion(t *testing.T) {
	fakeRoot(t)
	s := stubApt(t)
	s.setInstalled(t, aptStubCandidate)
	s.set(t, "held")
	e := newTestEngine(t, nil)
	setAptRow(t, e, true, true)

	jv, _, err := e.Reconcile(ReconcileMissing)
	if err != nil {
		t.Fatalf("Reconcile = %v", err)
	}
	wantJobState(t, e, jv, JobDone)

	if !slices.Contains(s.lines(t), aptGetInstallLine("--allow-downgrades", "--", "jq=1.6-1")) {
		t.Errorf("calls = %q, want apt-get to downgrade to jq=1.6-1", s.lines(t))
	}
	if got := s.installedVersion(t); got != "1.6-1" || !s.held(t) {
		t.Errorf("dpkg reports jq %q, held %v; want the pinned 1.6-1 held", got, s.held(t))
	}
}

// TestAptInstall_NamesAHeldForeignCopyWhenAptRefuses: a hold on another
// architecture's copy is a selection the engine never made, so when apt-get
// fails beside one the job's error names that copy and how to release it.
func TestAptInstall_NamesAHeldForeignCopyWhenAptRefuses(t *testing.T) {
	fakeRoot(t)
	s := stubApt(t)
	s.set(t, "foreign-held", "foreign-conflicts")
	e := newTestEngine(t, nil)
	setAptRow(t, e, false, false)

	jv, err := e.Install("jq")
	if err != nil {
		t.Fatalf("Install(jq) = %v", err)
	}
	got := waitJob(t, e, jv.ID)
	if got.State != JobFailed {
		t.Fatalf("job = %s, want failed", got.State)
	}
	for name, msg := range map[string]string{"job error": got.Error, "recorded error": e.store.State().Tools["jq"].LastError} {
		for _, want := range []string{"Held packages were changed", "jq:i386", "another architecture", "apt-mark unhold jq:i386"} {
			if !strings.Contains(msg, want) {
				t.Errorf("%s = %q, want it to contain %q", name, msg, want)
			}
		}
	}
	if lines := s.lines(t); slices.ContainsFunc(lines, func(l string) bool { return strings.HasPrefix(l, "mark ") }) {
		t.Errorf("calls = %q, want no apt-mark on a foreign architecture's selection", lines)
	}
}

// TestAptInstall_NeverUnholdsAForeignCopy: a held Multi-Arch: same copy does
// not block the native install, so the install succeeds and leaves that
// selection alone.
func TestAptInstall_NeverUnholdsAForeignCopy(t *testing.T) {
	fakeRoot(t)
	s := stubApt(t)
	s.set(t, "foreign-held")
	e := newTestEngine(t, nil)
	setAptRow(t, e, false, false)

	jv, err := e.Install("jq")
	if err != nil {
		t.Fatalf("Install(jq) = %v", err)
	}
	wantJobState(t, e, jv, JobDone)

	lines := s.lines(t)
	if !slices.Contains(lines, aptGetInstallLine("--", "jq")) {
		t.Errorf("calls = %q, want apt-get to install jq", lines)
	}
	if slices.ContainsFunc(lines, func(l string) bool { return strings.HasPrefix(l, "mark ") }) {
		t.Errorf("calls = %q, want no apt-mark call", lines)
	}
}

// TestPatch_VersionArgs: version_args is probe input only, so a patch stores
// it without a job and the next probe grades the version it declares
// (Tool.VersionArgs); execve(2) arguments are NUL-terminated, so a NUL
// element is refused rather than stored as a tool that can never execute.
func TestPatch_VersionArgs(t *testing.T) {
	t.Run("declaring args stores them and the next probe grades the version", func(t *testing.T) {
		e := newTestEngine(t, nil)
		addManual(t, e, "m", nil)
		writeStub(t, e, "m", "echo m 9.9.9")
		if !inventoryRow(t, e, "m").Installed {
			t.Fatal("Setup: undeclared args should only require an answer")
		}
		args := []string{"--version"}

		job, err := e.Patch("m", PatchRequest{VersionArgs: &args})

		if err != nil || job != nil {
			t.Fatalf("Patch(version_args) = %v, %v, want nil, nil", job, err)
		}
		if m, _ := e.store.LoadManifest(); !slices.Equal(m.Tools["m"].VersionArgs, args) {
			t.Errorf("stored version_args = %q, want %q", m.Tools["m"].VersionArgs, args)
		}
		if inventoryRow(t, e, "m").Installed {
			t.Error("row prints 9.9.9 against recorded 1 under declared args, want not installed")
		}
	})
	t.Run("an empty list clears them", func(t *testing.T) {
		e := newTestEngine(t, nil)
		addManual(t, e, "m", nil)
		declared := []string{"version"}
		if _, err := e.Patch("m", PatchRequest{VersionArgs: &declared}); err != nil {
			t.Fatal(err)
		}
		empty := []string{}

		if _, err := e.Patch("m", PatchRequest{VersionArgs: &empty}); err != nil {
			t.Fatal(err)
		}

		if m, _ := e.store.LoadManifest(); m.Tools["m"].VersionArgs != nil {
			t.Errorf("stored version_args = %q, want nil", m.Tools["m"].VersionArgs)
		}
	})
	t.Run("a NUL element is refused and nothing changes", func(t *testing.T) {
		e := newTestEngine(t, nil)
		addManual(t, e, "m", nil)
		bad := []string{"--version\x00"}

		job, err := e.Patch("m", PatchRequest{VersionArgs: &bad})

		if err == nil || job != nil || !strings.Contains(err.Error(), "NUL") {
			t.Errorf("Patch(NUL version_args) = %v, %v, want the NUL refusal", job, err)
		}
		if m, _ := e.store.LoadManifest(); m.Tools["m"].VersionArgs != nil {
			t.Errorf("stored version_args = %q, want nil unchanged", m.Tools["m"].VersionArgs)
		}
	})
}

// TestAdd_VersionArgs: an Add may declare the probe's args like every other
// manifest field; an empty list is the same as none, so the catalog's apply.
func TestAdd_VersionArgs(t *testing.T) {
	cat := &Catalog{Entries: map[string]CatalogEntry{
		"c": {Source: SourceManual, Version: "1", VersionArgs: []string{"version"}},
	}}
	cases := []struct {
		name string
		req  AddRequest
		want []string
	}{
		{name: "declared on the request", req: AddRequest{Name: "m", Source: SourceManual, Version: "1", VersionArgs: []string{"-V"}}, want: []string{"-V"}},
		{name: "the request wins over the catalog", req: AddRequest{Name: "c", VersionArgs: []string{"-V"}}, want: []string{"-V"}},
		{name: "an empty list takes the catalog's", req: AddRequest{Name: "c", VersionArgs: []string{}}, want: []string{"version"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEngine(t, cat)
			tc.req.Disabled = true

			if _, err := e.Add(t.Context(), &tc.req); err != nil {
				t.Fatal(err)
			}

			if m, _ := e.store.LoadManifest(); !slices.Equal(m.Tools[tc.req.Name].VersionArgs, tc.want) {
				t.Errorf("stored version_args = %q, want %q", m.Tools[tc.req.Name].VersionArgs, tc.want)
			}
		})
	}
	t.Run("a NUL element is refused before the latest version is resolved", func(t *testing.T) {
		e := newTestEngineClient(t, nil, offlineClient(), nil)

		_, err := e.Add(t.Context(), &AddRequest{Name: "m", Source: "npm:m", VersionArgs: []string{"a\x00b"}})

		if err == nil || err.Error() != "version_args[0] contains a NUL byte" {
			t.Errorf("Add error = %v, want the NUL refusal", err)
		}
		if m, _ := e.store.LoadManifest(); len(m.Tools) != 0 {
			t.Errorf("manifest = %v, want no row", m.Tools)
		}
	})
}
