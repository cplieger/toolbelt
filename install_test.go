package toolbelt

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// setgidParent returns a temp directory with S_ISGID set, having first
// PROVEN that the kernel really widens a fresh 0o755 mkdir inside it.
//
// The widening the mode tests below need has to be real, not mocked: Linux
// propagates S_ISGID from a setgid parent to a new subdirectory, so
// os.Mkdir(dir, managedDirMode) genuinely stores a mode it was not asked
// for, which is the same class of divergence as the inheritable group ACE
// on a ZFS nfs4acl dataset that ensureManagedDir was written for and the
// only one reproducible in a unit test.
//
// The witness is why this is a helper rather than four inline chmods. On a
// filesystem or kernel that honours every mode request there is nothing
// for enforcement to correct, so a create-path assertion would pass
// without exercising enforcement at all — indistinguishable from the
// unverified MkdirAll it replaced. Skipping there says so out loud instead
// of banking a vacuous pass.
func setgidParent(t *testing.T) string {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o755|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	witness := filepath.Join(parent, "witness")
	if err := os.Mkdir(witness, managedDirMode); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(witness)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSetgid == 0 {
		t.Skipf("kernel did not widen a %v mkdir under a setgid parent (got %v); "+
			"this test cannot distinguish a verified create from an unverified one here",
			managedDirMode, fi.Mode())
	}
	if err := os.Remove(witness); err != nil {
		t.Fatal(err)
	}
	return parent
}

// managedDirStoredMode is the exact mode every directory the engine creates
// must be found carrying: a directory, 0o755, no inherited setgid, no group
// write. The comparisons against it below are written out at each site rather
// than performed inside a shared assertion helper, so a failure names the
// directory that broke and the sibling directories in the same test are still
// checked (go-rulebook C18).
const managedDirStoredMode = os.ModeDir | managedDirMode

// storedDirMode returns dir's stored mode for comparison at the call site.
// Lstat, so a symlink substituted for the directory cannot answer for it.
//
// It REPORTS a stat failure rather than aborting — the C18 carve-out this
// helper is: aborting on a value mismatch cost every sibling directory in the
// same test its own run. The zero mode it returns on failure cannot equal
// managedDirStoredMode, so the caller's own comparison fails too and the test
// still ends red.
func storedDirMode(t *testing.T, dir string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(dir)
	if err != nil {
		t.Errorf("stat %s: %v", dir, err)
		return 0
	}
	return fi.Mode()
}

// TestEnsureManagedDir_verifiesTheModeItCreated pins the bug the MkdirAll
// this replaced could not see: it asked for 0o755 and returned nil without
// ever reading back what the filesystem stored, so on a filesystem that
// widens a fresh directory the engine's own directories were born with
// access their creator never requested and nothing raised an error.
//
// The widening is REAL (see setgidParent, which also refuses to let this
// test pass vacuously), so the assertion below can only hold if
// ensureManagedDir chmod'ed the handle and re-read it.
func TestEnsureManagedDir_verifiesTheModeItCreated(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(setgidParent(t), "bin")
	if err := ensureManagedDir(dir); err != nil {
		t.Fatalf("ensureManagedDir: %v", err)
	}
	// The widening is real, so this can only hold if ensureManagedDir
	// chmod'ed the handle and re-read it.
	if got := storedDirMode(t, dir); got != managedDirStoredMode {
		t.Errorf("mode of the dir ensureManagedDir created = %v, want %v", got, managedDirStoredMode)
	}
}

// TestNew_verifiesTheStoredModeOfTheBinDir pins the property on the PATH
// directory, at the call that actually creates it. bin/ is the single
// directory the engine puts on PATH and every entry in it is a symlink the
// probe executes, so a mode wider than 0o755 there lets any member of the
// directory's group repoint an entry at a binary that was never inspected —
// under a root consumer, root code execution.
//
// New is the site that matters BECAUSE it runs first: it creates bin/ before
// any install, so enforcing only in linkBin (whose MkdirAll would then always
// be a no-op) would leave the check present and permanently unreachable. The
// setgid parent widens the ToolsDir this call creates as well, which is the
// realistic shape — the engine's own intermediate level is the one handing
// the inherited bit down to bin/.
func TestNew_verifiesTheStoredModeOfTheBinDir(t *testing.T) {
	t.Parallel()
	toolsDir := filepath.Join(setgidParent(t), "tools")
	e, err := New(&Config{ConfigDir: t.TempDir(), ToolsDir: toolsDir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer e.Close()
	binDir := filepath.Join(toolsDir, "bin")
	if got := storedDirMode(t, binDir); got != managedDirStoredMode {
		t.Errorf("mode of the PATH dir New created = %v, want %v", got, managedDirStoredMode)
	}
}

// TestLinkBin_verifiesTheStoredModeOfThePathDir covers the same directory at
// the other creator. linkBin re-establishes bin/ on every publish, so it is
// the path that runs when the directory was removed after New — the one case
// where an install, not startup, is what brings the PATH directory into
// being, and the check has to hold there too.
func TestLinkBin_verifiesTheStoredModeOfThePathDir(t *testing.T) {
	t.Parallel()
	toolsDir := filepath.Join(setgidParent(t), "tools")
	in := &installer{toolsDir: toolsDir, output: func(string) {}}
	target := filepath.Join(toolsDir, "opt", "rg", "1.0.0", "rg")
	if err := os.MkdirAll(filepath.Dir(target), managedDirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := in.linkBin("rg", target); err != nil {
		t.Fatalf("linkBin: %v", err)
	}
	if got := storedDirMode(t, in.binDir()); got != managedDirStoredMode {
		t.Errorf("mode of the PATH dir linkBin created = %v, want %v", got, managedDirStoredMode)
	}
	if _, err := os.Lstat(filepath.Join(in.binDir(), "rg")); err != nil {
		t.Errorf("bin/rg was not published: %v", err)
	}
}

// TestExtractAndSwap_verifiesTheStoredModeOfThePublishedVersionTree pins the
// reasoning that makes the staging directory the right place to enforce: the
// publish is an os.Rename of that same inode, so whatever mode the staging
// directory carries is the mode the PUBLISHED version tree ends up with. That
// tree holds the binaries bin/ symlinks point at, so a group-writable version
// directory is the repoint attack one level down — the file's own mode, which
// enforceExecutable pins, is no help when the directory it sits in can be
// written.
//
// formatRaw keeps this a rename rather than a tar exec: the archive
// extractors' own directory modes come from the archive and are a different
// concern, but the directory toolbelt creates to hold them is this one.
func TestExtractAndSwap_verifiesTheStoredModeOfThePublishedVersionTree(t *testing.T) {
	t.Parallel()
	base := setgidParent(t)
	toolsDir := filepath.Join(base, "tools")
	in := &installer{toolsDir: toolsDir, output: func(string) {}}
	artifact := filepath.Join(base, "rg-download")
	if err := os.WriteFile(artifact, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	versDir, err := in.extractAndSwap(t.Context(), "rg", "1.0.0", &InstallSpec{Format: formatRaw}, artifact)
	if err != nil {
		t.Fatalf("extractAndSwap: %v", err)
	}
	// Every level the publish created, each asserted at its own line so one
	// widened directory does not hide the other two.
	if got := storedDirMode(t, versDir); got != managedDirStoredMode {
		t.Errorf("mode of the published version tree = %v, want %v", got, managedDirStoredMode)
	}
	if got := storedDirMode(t, filepath.Join(in.optDir(), "rg")); got != managedDirStoredMode {
		t.Errorf("mode of the tool's opt dir = %v, want %v", got, managedDirStoredMode)
	}
	if got := storedDirMode(t, in.optDir()); got != managedDirStoredMode {
		t.Errorf("mode of opt = %v, want %v", got, managedDirStoredMode)
	}
}

// TestEnsureManagedDir_leavesAPreExistingDirectoryAlone pins the deliberate
// LIMIT of the enforcement, which is as much a decision as the enforcement
// itself: a directory this call did not create is never chmod'ed.
//
// The direction that matters is the one an unconditional EnforceMode would
// get wrong. An operator who tightened bin/ to 0o700 would have it widened
// back to 0o755 by the library on the next install — this library undoing
// their hardening while claiming to enforce a mode. A pre-existing directory
// that is too OPEN is verifyRootIntegrity's subject, which is opt-in and
// report-only on purpose.
func TestEnsureManagedDir_leavesAPreExistingDirectoryAlone(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "bin")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := ensureManagedDir(dir); err != nil {
		t.Fatalf("ensureManagedDir on a pre-existing dir: %v", err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o700 {
		t.Errorf("pre-existing dir mode = %v, want 0700 untouched: the enforcement "+
			"widened a directory the operator had tightened", got)
	}
}

// TestEnsureManagedDir_refusesAFileAtTheName keeps the error surface the
// replaced os.MkdirAll had. os.Mkdir reports an occupied name as EEXIST
// whatever occupies it, so reading that as "already established" would hand
// a regular file back to callers as a usable directory and defer the failure
// to the symlink or extraction that follows.
func TestEnsureManagedDir_refusesAFileAtTheName(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "bin")
	if err := os.WriteFile(dir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureManagedDir(dir); err == nil {
		t.Fatal("a regular file at the directory name was accepted")
	}
}

// collector accumulates an installer's output lines for assertions.
type collector struct {
	mu    sync.Mutex
	lines []string
}

func (c *collector) add(s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, s)
}

func (c *collector) joined() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.lines, "\n")
}

// TestDownloadOnce_failsOnATruncatedBody pins the two places a short read can
// be lost. io.Copy reports it and so can Close, and a download that returns nil
// with a partial file on disk is the worst outcome available: extraction runs
// on it, the checksum is the only thing standing between a truncated artifact
// and a published version tree, and a definition that declares no checksum has
// nothing standing there at all.
func TestDownloadOnce_failsOnATruncatedBody(t *testing.T) {
	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Promise more than is written, then return: the connection closes
		// mid-body and the client's read fails.
		w.Header().Set("Content-Length", "4096")
		_, _ = w.Write([]byte("partial"))
	}))
	out := &collector{}
	in := &installer{toolsDir: t.TempDir(), client: srv.Client(), output: out.add}
	dest := filepath.Join(t.TempDir(), "artifact")

	if err := in.downloadOnce(t.Context(), srv.URL+"/tool.raw", dest); err == nil {
		t.Fatal("downloadOnce on a truncated body = nil, want the read failure")
	}
	if strings.Contains(out.joined(), "downloaded") {
		t.Errorf("a failed download reported success: %q", out.joined())
	}
}

// TestDownloadOnce_reportsTheSizeItWrote pins the operator-facing size line. It
// is the only report of how big an artifact was, and the figure is in megabytes.
func TestDownloadOnce_reportsTheSizeItWrote(t *testing.T) {
	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("#!/bin/sh\necho tool\n"))
	}))
	out := &collector{}
	in := &installer{toolsDir: t.TempDir(), client: srv.Client(), output: out.add}
	dest := filepath.Join(t.TempDir(), "artifact")

	if err := in.downloadOnce(t.Context(), srv.URL+"/tool.raw", dest); err != nil {
		t.Fatalf("downloadOnce: %v", err)
	}
	if got := out.joined(); got != "downloaded artifact (0.0 MB)" {
		t.Errorf("download report = %q, want %q", got, "downloaded artifact (0.0 MB)")
	}
	body, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "#!/bin/sh\necho tool\n" {
		t.Errorf("downloaded file = %q, want the served body", body)
	}
}

// TestBinDiff_reportsOnlyWhatTheCallbackAdded pins the ownership boundary the
// package-manager installs rest on. The diff is what decides which bin entries
// the engine records as ITS OWN, and uninstall deletes exactly those: counting a
// pre-existing entry as added makes the engine claim — and later remove — a
// binary another tool put there.
func TestBinDiff_reportsOnlyWhatTheCallbackAdded(t *testing.T) {
	t.Run("a_pre_existing_entry_is_not_reported", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "old"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		in := &installer{toolsDir: dir, output: func(string) {}}

		added, err := in.binDiff(dir, func() error {
			return os.WriteFile(filepath.Join(dir, "new"), []byte("x"), 0o600)
		})
		if err != nil {
			t.Fatalf("binDiff: %v", err)
		}
		if !slices.Equal(added, []string{"new"}) {
			t.Errorf("binDiff added = %v, want [new]: only the entry the callback created", added)
		}
	})
	t.Run("a_callback_failure_is_propagated", func(t *testing.T) {
		dir := t.TempDir()
		in := &installer{toolsDir: dir, output: func(string) {}}
		want := errors.New("install refused")

		added, err := in.binDiff(dir, func() error { return want })
		if !errors.Is(err, want) {
			t.Errorf("binDiff err = %v, want the callback's own error", err)
		}
		if added != nil {
			t.Errorf("binDiff added = %v, want nil for a failed callback", added)
		}
	})
}

// TestLinkPMBins_OwnershipFallback pins the conventional-bin-name fallback and
// its limit. A first install whose diff saw nothing new would otherwise own no
// bins at all and read as uninstalled forever; but the fallback is a LAST
// resort, so a package whose ownership is already known must not silently
// acquire a same-named binary it never created — uninstall would delete it.
func TestLinkPMBins_OwnershipFallback(t *testing.T) {
	t.Run("a_first_install_that_created_nothing_new_owns_the_conventional_name", func(t *testing.T) {
		dir := t.TempDir()
		in := &installer{toolsDir: dir, output: func(string) {}}
		pmBin := pmBinWith(t, in, "tsc")

		owned, err := in.linkPMBins(pmBin, nil, nil, "tsc")
		if err != nil {
			t.Fatalf("linkPMBins: %v", err)
		}
		if !slices.Equal(owned, []string{"tsc"}) {
			t.Errorf("owned = %v, want [tsc] from the conventional bin name", owned)
		}
	})
	t.Run("known_ownership_does_not_absorb_the_conventional_name", func(t *testing.T) {
		dir := t.TempDir()
		in := &installer{toolsDir: dir, output: func(string) {}}
		pmBin := pmBinWith(t, in, "tsc", "typescript")

		owned, err := in.linkPMBins(pmBin, nil, []string{"tsc"}, "typescript")
		if err != nil {
			t.Fatalf("linkPMBins: %v", err)
		}
		if !slices.Equal(owned, []string{"tsc"}) {
			t.Errorf("owned = %v, want [tsc] only: the package's ownership was already known", owned)
		}
	})
}

// pmBinWith creates the package manager's bin dir holding the named entries,
// plus the engine bin dir the links land in, and returns the pm bin path.
func pmBinWith(t *testing.T, in *installer, names ...string) string {
	t.Helper()
	pmBin := filepath.Join(in.toolsDir, "npm", "bin")
	if err := os.MkdirAll(pmBin, managedDirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(in.binDir(), managedDirMode); err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(pmBin, n), []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return pmBin
}

// TestPruneOldVersions_RetainsTheNewestOnDiskNotTheHighestName pins which
// superseded version the retention keeps. It is the tree a bad update falls
// back to, and the one that earned that role is the one most recently
// installed — which is not the highest version string: a deliberate downgrade
// installs an older number last, and keeping the higher name instead would
// discard the version the operator just chose.
func TestPruneOldVersions_RetainsTheNewestOnDiskNotTheHighestName(t *testing.T) {
	dir := t.TempDir()
	out := &collector{}
	in := &installer{toolsDir: dir, output: out.add}
	root := filepath.Join(in.optDir(), "tool")
	// v1.0.0 was installed most recently despite the lower version string.
	ages := map[string]time.Duration{
		"v3.0.0": 0, "v1.0.0": time.Hour, "v2.0.0": 48 * time.Hour,
	}
	for name, age := range ages {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(p, managedDirMode); err != nil {
			t.Fatal(err)
		}
		when := time.Now().Add(-age)
		if err := os.Chtimes(p, when, when); err != nil {
			t.Fatal(err)
		}
	}

	in.pruneOldVersions("tool", "v3.0.0", 1)

	if _, err := os.Stat(filepath.Join(root, "v1.0.0")); err != nil {
		t.Errorf("the most recently installed previous version was pruned: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "v2.0.0")); !os.IsNotExist(err) {
		t.Errorf("stat of the older previous version = %v, want it pruned", err)
	}
	if got := out.joined(); got != "pruned old version tool/v2.0.0" {
		t.Errorf("prune report = %q, want %q", got, "pruned old version tool/v2.0.0")
	}
}

// TestRunShell_streamsEveryLineOfCommandOutput pins the install log. The
// command's own output is the only diagnosis an operator gets for a manual
// install, and the last line of a failing script is routinely the one without a
// trailing newline — a shell's `printf` of an error, or output cut off when the
// process died.
func TestRunShell_streamsEveryLineOfCommandOutput(t *testing.T) {
	out := &collector{}
	in := &installer{toolsDir: t.TempDir(), output: out.add}

	err := in.runShell(t.Context(), `printf 'first line\nlast line without a newline'`,
		"1.0.0", filepath.Join(in.optDir(), "tool"))
	if err != nil {
		t.Fatalf("runShell: %v", err)
	}
	if got := out.joined(); got != "first line\nlast line without a newline" {
		t.Errorf("streamed output = %q, want both lines", got)
	}
}

// TestRunShell_namesTheRunningArchitecture pins the ARCH_* variables an install
// command interpolates into a download URL. Getting the architecture backwards
// downloads a working binary for the wrong machine, which installs cleanly and
// fails at exec.
func TestRunShell_namesTheRunningArchitecture(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skipf("the ARCH_* variables spell only amd64 and arm64; GOARCH here is %s", runtime.GOARCH)
	}
	out := &collector{}
	in := &installer{toolsDir: t.TempDir(), output: out.add}

	err := in.runShell(t.Context(), `printf '%s\n' "$ARCH_AMD64_OR_ARM64"`,
		"1.0.0", filepath.Join(in.optDir(), "tool"))
	if err != nil {
		t.Fatalf("runShell: %v", err)
	}
	if got := out.joined(); got != runtime.GOARCH {
		t.Errorf("ARCH_AMD64_OR_ARM64 = %q, want %q", got, runtime.GOARCH)
	}
}

// TestUninstall_ReportsWhatItRemoved pins the uninstall's account of itself.
// Every line here names something that is now gone, and the closing line is
// what says the removal completed rather than stopped halfway.
func TestUninstall_ReportsWhatItRemoved(t *testing.T) {
	out := &collector{}
	in := &installer{toolsDir: t.TempDir(), output: out.add}
	if err := os.MkdirAll(in.binDir(), managedDirMode); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(in.optDir(), "tool", "1.0.0", "tool")
	if err := os.MkdirAll(filepath.Dir(target), managedDirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := in.linkBin("tool", target); err != nil {
		t.Fatal(err)
	}

	st := &ToolStatus{Bins: []string{"tool"}}
	if err := in.uninstall(t.Context(), "tool", &Tool{Source: SourceManual}, st); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if got := out.joined(); got != "removed tool\nuninstalled tool" {
		t.Errorf("uninstall report = %q, want the removed bin and the completion line", got)
	}
	if _, err := os.Lstat(filepath.Join(in.binDir(), "tool")); !os.IsNotExist(err) {
		t.Errorf("lstat of the PATH entry = %v, want it removed", err)
	}
	if _, err := os.Stat(filepath.Join(in.optDir(), "tool")); !os.IsNotExist(err) {
		t.Errorf("stat of the opt tree = %v, want it removed", err)
	}
}

// TestUninstall_ToleratesButReportsAFailedUninstallCommand pins the deliberate
// asymmetry: a manual uninstall command is upstream's cleanup, so its failure
// must not block the footprint removal the engine is actually responsible for —
// but it cannot be silent either, because the residue it left behind is now
// nobody's and the log line is the only record that it exists.
func TestUninstall_ToleratesButReportsAFailedUninstallCommand(t *testing.T) {
	out := &collector{}
	in := &installer{toolsDir: t.TempDir(), output: out.add}
	if err := os.MkdirAll(in.binDir(), managedDirMode); err != nil {
		t.Fatal(err)
	}

	tool := &Tool{Source: SourceManual, Version: "1.0.0", Uninstall: "exit 1"}
	if err := in.uninstall(t.Context(), "tool", tool, &ToolStatus{}); err != nil {
		t.Fatalf("uninstall = %v, want a failing uninstall command tolerated", err)
	}
	if !strings.Contains(out.joined(), "uninstall command failed (continuing)") {
		t.Errorf("uninstall report = %q, want the failed command reported", out.joined())
	}
	if !strings.Contains(out.joined(), "uninstalled tool") {
		t.Errorf("uninstall report = %q, want the removal to have completed anyway", out.joined())
	}
}

// TestExtractAndSwap_restoresThePreviousTreeWhenTheCommitBarrierFails pins the
// same-version reinstall window. The publish renames the live tree aside before
// moving the new one in, so between those two renames the tool exists only under
// the backup name: a commit barrier that fails there and does NOT put it back
// leaves the version the state file still names missing from disk entirely, and
// the fallback the retention policy kept is not the version that was running.
func TestExtractAndSwap_restoresThePreviousTreeWhenTheCommitBarrierFails(t *testing.T) {
	base := t.TempDir()
	in := &installer{toolsDir: filepath.Join(base, "tools"), output: func(string) {}}
	spec := &InstallSpec{Format: formatRaw}
	first := filepath.Join(base, "first-download")
	if err := os.WriteFile(first, []byte("#!/bin/sh\necho live\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	versDir, err := in.extractAndSwap(t.Context(), "tool", "1.0.0", spec, first)
	if err != nil {
		t.Fatalf("baseline publish: %v", err)
	}

	// Fail only the barrier that commits the publishing rename, so the
	// staging flush before it still succeeds.
	swapBarriers(t, nil, func(p string) error {
		if filepath.Base(p) == "tool" && filepath.Base(filepath.Dir(p)) == "opt" {
			return enospc(p)
		}
		return syncPath(p)
	}, nil)
	second := filepath.Join(base, "second-download")
	if err := os.WriteFile(second, []byte("#!/bin/sh\necho replacement\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = in.extractAndSwap(t.Context(), "tool", "1.0.0", spec, second)
	if err == nil || !strings.Contains(err.Error(), "commit install") {
		t.Fatalf("reinstall = %v, want the commit barrier failure", err)
	}
	body, rerr := os.ReadFile(filepath.Join(versDir, "tool"))
	if rerr != nil {
		t.Fatalf("the live version tree was not restored: %v", rerr)
	}
	if string(body) != "#!/bin/sh\necho live\n" {
		t.Errorf("restored tree holds %q, want the version that was live", body)
	}
}
