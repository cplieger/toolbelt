package toolbelt

import (
	"os"
	"path/filepath"
	"testing"
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
