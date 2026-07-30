package toolbelt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// swapBarriers installs sync/write seams for one test and restores them
// afterwards. The seams are package vars, so these tests never run in
// parallel.
func swapBarriers(t *testing.T, file, dir func(string) error, write func(string, []byte) (bool, error)) {
	t.Helper()
	origFile, origDir, origWrite := fsyncFile, fsyncDir, atomicWrite
	t.Cleanup(func() { fsyncFile, fsyncDir, atomicWrite = origFile, origDir, origWrite })
	if file != nil {
		fsyncFile = file
	}
	if dir != nil {
		fsyncDir = dir
	}
	if write != nil {
		atomicWrite = write
	}
}

// enospc is the failure these barriers actually see in the field.
func enospc(path string) error {
	return &os.PathError{Op: "fsync", Path: path, Err: syscall.ENOSPC}
}

// TestSyncPath_FlushesFilesAndDirs pins the real barrier (the seams above
// stand in for it everywhere else): it accepts both a regular file and a
// directory — on Linux fsync of a directory is what commits a rename — and
// reports a path it cannot open instead of pretending the flush happened.
func TestSyncPath_FlushesFilesAndDirs(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{name: "regular file", path: file},
		{name: "directory", path: dir},
		{name: "missing path", path: filepath.Join(dir, "nope"), wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := syncPath(tc.path)
			if (err != nil) != tc.wantErr {
				t.Fatalf("syncPath(%s) = %v, wantErr %v", tc.path, err, tc.wantErr)
			}
		})
	}
}

// TestSyncTree_OrdersBarriers pins the publish protocol's ordering: every
// file's contents are flushed before any directory's entry list, and a
// child directory before the parent that names it. A parent flushed first
// could name a child whose contents are still in page cache.
func TestSyncTree_OrdersBarriers(t *testing.T) {
	root := filepath.Join(t.TempDir(), "stage")
	for _, dir := range []string{"a/b", "c"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"top", "a/mid", "a/b/deep", "c/other"} {
		if err := os.WriteFile(filepath.Join(root, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("top", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}

	var order []string
	swapBarriers(t,
		func(p string) error { order = append(order, "file:"+mustRel(root, p)); return nil },
		func(p string) error { order = append(order, "dir:"+mustRel(root, p)); return nil },
		nil)
	if err := syncTree(root); err != nil {
		t.Fatalf("syncTree: %v", err)
	}

	firstDir := slices.IndexFunc(order, func(s string) bool { return strings.HasPrefix(s, "dir:") })
	for i, entry := range order {
		if strings.HasPrefix(entry, "file:") && i > firstDir {
			t.Fatalf("file barrier %s ran after a directory barrier: %v", entry, order)
		}
	}
	for _, f := range []string{"file:top", "file:a/mid", "file:a/b/deep", "file:c/other"} {
		if !slices.Contains(order, f) {
			t.Errorf("%s never flushed: %v", f, order)
		}
	}
	if slices.Contains(order, "file:link") {
		t.Errorf("symlink flushed as a file: %v", order)
	}
	deep := slices.Index(order, "dir:a/b")
	mid := slices.Index(order, "dir:a")
	if deep < 0 || mid < 0 || deep > mid || slices.Index(order, "dir:.") != len(order)-1 {
		t.Fatalf("directory barriers not deepest-first with root last: %v", order)
	}
}

// TestSyncTree_PropagatesFailure: a barrier failure (ENOSPC) must abort,
// not be swallowed — nothing may be published on its back.
func TestSyncTree_PropagatesFailure(t *testing.T) {
	root := filepath.Join(t.TempDir(), "stage")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		file func(string) error
		dir  func(string) error
	}{
		{name: "file barrier", file: enospc},
		{name: "directory barrier", dir: enospc},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			swapBarriers(t, tc.file, tc.dir, nil)
			if err := syncTree(root); err == nil || !strings.Contains(err.Error(), "no space left") {
				t.Fatalf("syncTree = %v, want the injected ENOSPC", err)
			}
		})
	}
}

// aquaVersionServer serves a per-version raw artifact plus a matching
// sha256 file, so an install (and an upgrade to another version) runs the
// full download -> verify -> extract -> publish path against a local
// server. The definition it returns points at that server.
func aquaVersionServer(t *testing.T) *AquaPackage {
	t.Helper()
	payload := func(ver string) string { return "#!/bin/sh\necho tool " + ver + "\n" }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := filepath.Base(r.URL.Path)
		switch {
		case strings.HasPrefix(base, "sums_"):
			ver := strings.TrimSuffix(strings.TrimPrefix(base, "sums_"), ".txt")
			sum := sha256.Sum256([]byte(payload(ver)))
			fmt.Fprintf(w, "%s  tool_%s.raw\n", hex.EncodeToString(sum[:]), ver)
		case strings.HasPrefix(base, "tool_"):
			ver := strings.TrimSuffix(strings.TrimPrefix(base, "tool_"), ".raw")
			_, _ = w.Write([]byte(payload(ver)))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return &AquaPackage{
		Type: aquaTypeHTTP, RepoOwner: "o", RepoName: "tool",
		URL:      srv.URL + "/tool_{{trimV .Version}}.raw",
		Format:   formatRaw,
		Files:    []AquaFile{{Name: "tool"}},
		Checksum: &AquaChecksum{Type: aquaTypeHTTP, URL: srv.URL + "/sums_{{trimV .Version}}.txt", Algorithm: "sha256"},
	}
}

// installVersion drives one install of tool at ver through the engine.
func installVersion(t *testing.T, e *Engine, ver string) *Job {
	t.Helper()
	m, err := e.store.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := m.Tools["tool"]; !exists {
		job, aerr := e.Add(context.Background(), &AddRequest{Name: "tool", Version: ver})
		if aerr != nil {
			t.Fatal(aerr)
		}
		return waitJob(t, e, job.ID)
	}
	job, perr := e.Patch("tool", PatchRequest{Version: &ver})
	if perr != nil || job == nil {
		t.Fatalf("patch to %s: job=%v err=%v", ver, job, perr)
	}
	return waitJob(t, e, job.ID)
}

// TestInstall_PublishBarriersAreWired pins that the publish path actually
// runs the protocol: every extracted file's contents, the staging dir
// before the rename that publishes it, the version parent after it, and
// the bin dir that carries the PATH symlink.
func TestInstall_PublishBarriersAreWired(t *testing.T) {
	aq := aquaVersionServer(t)
	e := newTestEngine(t, &Catalog{Entries: map[string]CatalogEntry{
		"tool": {Name: "tool", Source: "aqua:o/tool", Aqua: aq},
	}})
	captureLogs(e)

	var files, dirs []string
	swapBarriers(t,
		func(p string) error { files = append(files, p); return syncPath(p) },
		func(p string) error { dirs = append(dirs, p); return syncPath(p) },
		nil)

	if final := installVersion(t, e, "v1.0.0"); final.State != JobDone {
		t.Fatalf("install = %+v tail=%v", final, final.OutputTail)
	}

	optRoot := filepath.Join(e.toolsDir, "opt", "tool")
	staging := filepath.Join(optRoot, "v1.0.0"+stagingSuffix)
	wantDirs := []string{staging, optRoot, e.binDir()}
	for _, want := range wantDirs {
		if !slices.Contains(dirs, want) {
			t.Errorf("directory barrier missing for %s: %v", want, dirs)
		}
	}
	if slices.Index(dirs, staging) > slices.Index(dirs, optRoot) {
		t.Errorf("staging dir flushed after the publish barrier: %v", dirs)
	}
	if !slices.Contains(files, filepath.Join(staging, "tool")) {
		t.Errorf("extracted file never flushed: %v", files)
	}
	// And the state record landed durably (the real writer ran).
	if st := e.store.State().Tools["tool"]; st.InstalledVersion != "v1.0.0" {
		t.Errorf("state = %+v", st)
	}
}

// TestInstall_SyncFailureRetainsPreviousVersion: a barrier failure at any
// point of the publish or state-write protocol — ENOSPC included — fails
// the install and never destroys the recovery point. Through the publish
// barriers the previous version stays live outright (tree, state row, and
// the symlink on PATH). Once the tree is published, a failing state write
// still fails the install and, decisively, does NOT prune: this engine is
// configured to keep no previous versions, so a successful install would
// have deleted v1.0.0 — retention pruning running only after the state
// record is durable is what keeps it on disk for the retry to fall back to.
func TestInstall_SyncFailureRetainsPreviousVersion(t *testing.T) {
	cases := []struct {
		name string
		file func(string) error
		dir  func(string) error
		// write nil = the real writer.
		write func(string, []byte) (bool, error)
		// wantErr is a substring of the failed job's error.
		wantErr string
		// wantState is the version tools-state.json must report after
		// the failure, and wantLink the version bin/tool must resolve to
		// (empty = any live target, the publish already completed).
		wantState string
		wantLink  string
	}{
		{
			name:      "staged file contents",
			file:      func(p string) error { return enospc(p) },
			wantErr:   "flush staged install",
			wantState: "v1.0.0", wantLink: "v1.0.0",
		},
		{
			name: "staging dir before the rename",
			dir: func(p string) error {
				if strings.HasSuffix(p, stagingSuffix) {
					return enospc(p)
				}
				return syncPath(p)
			},
			wantErr:   "flush staged install",
			wantState: "v1.0.0", wantLink: "v1.0.0",
		},
		{
			name: "parent dir after the rename",
			dir: func(p string) error {
				if filepath.Base(p) == "tool" && filepath.Base(filepath.Dir(p)) == "opt" {
					return enospc(p)
				}
				return syncPath(p)
			},
			wantErr:   "commit install",
			wantState: "v1.0.0", wantLink: "v1.0.0",
		},
		{
			name: "bin dir carrying the PATH symlink",
			dir: func(p string) error {
				if filepath.Base(p) == "bin" {
					return enospc(p)
				}
				return syncPath(p)
			},
			wantErr:   "commit bin link",
			wantState: "v1.0.0", wantLink: "v1.0.0",
		},
		{
			name: "state write fails",
			write: func(path string, data []byte) (bool, error) {
				if strings.HasSuffix(path, "tools-state.json") {
					return false, &os.PathError{Op: "write", Path: path, Err: syscall.ENOSPC}
				}
				return realAtomicWrite(path, data)
			},
			wantErr:   "record install state",
			wantState: "v1.0.0",
		},
		{
			// atomicfile's landed-but-undurable case: the bytes are
			// correct, their survival is not promised. Still an install
			// failure (so the job retries and rewrites), and still no
			// prune of the previous tree.
			name: "state write lands but is not durable",
			write: func(path string, data []byte) (bool, error) {
				if strings.HasSuffix(path, "tools-state.json") {
					if _, err := realAtomicWrite(path, data); err != nil {
						return false, err
					}
					return false, nil
				}
				return realAtomicWrite(path, data)
			},
			wantErr:   "record install state",
			wantState: "v2.0.0",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			aq := aquaVersionServer(t)
			e := newTestEngine(t, &Catalog{Entries: map[string]CatalogEntry{
				"tool": {Name: "tool", Source: "aqua:o/tool", Aqua: aq},
			}})
			captureLogs(e)
			e.keepVersions = -1 // retain nothing: a clean install WOULD prune v1.0.0

			if final := installVersion(t, e, "v1.0.0"); final.State != JobDone {
				t.Fatalf("baseline install = %+v tail=%v", final, final.OutputTail)
			}
			swapBarriers(t, tc.file, tc.dir, tc.write)

			final := installVersion(t, e, "v2.0.0")
			if final.State != JobFailed || !strings.Contains(final.Error, tc.wantErr) {
				t.Fatalf("install = %+v, want failure containing %q", final, tc.wantErr)
			}
			// The recovery point survives: the previous tree was not pruned.
			prev := filepath.Join(e.toolsDir, "opt", "tool", "v1.0.0")
			if _, err := os.Stat(prev); err != nil {
				t.Errorf("previous version tree lost: %v", err)
			}
			if got := e.store.State().Tools["tool"].InstalledVersion; got != tc.wantState {
				t.Errorf("state installed_version = %q, want %q", got, tc.wantState)
			}
			target, err := filepath.EvalSymlinks(filepath.Join(e.binDir(), "tool"))
			switch {
			case err != nil:
				t.Errorf("bin symlink no longer resolves: %v", err)
			case tc.wantLink != "" && !strings.Contains(target, tc.wantLink):
				t.Errorf("bin symlink = %s, want the %s tree", target, tc.wantLink)
			}
		})
	}
}

// TestMutateState_ReportsWriteFailures: the state file is the engine's
// durability record, so a failed write and a landed-but-not-durable write
// are both errors the caller must see, and neither may corrupt the
// previous content.
func TestMutateState_ReportsWriteFailures(t *testing.T) {
	cases := []struct {
		name    string
		write   func(string, []byte) (bool, error)
		wantErr string
	}{
		{
			name:    "write error",
			write:   func(path string, _ []byte) (bool, error) { return false, enospc(path) },
			wantErr: "no space left",
		},
		{
			name:    "not durable",
			write:   func(string, []byte) (bool, error) { return false, nil },
			wantErr: "not durable",
		},
		{
			name:  "durable write succeeds",
			write: realAtomicWrite,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newStore(t.TempDir(), nil, slog.Default())
			if err := st.initFiles(); err != nil {
				t.Fatal(err)
			}
			swapBarriers(t, nil, nil, tc.write)
			err := st.setToolStatus("tool", func(s *ToolStatus) { s.InstalledVersion = "1.0.0" })
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("setToolStatus = %v, want nil", err)
				}
				if got := st.State().Tools["tool"].InstalledVersion; got != "1.0.0" {
					t.Fatalf("state not persisted: %q", got)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("setToolStatus = %v, want an error containing %q", err, tc.wantErr)
			}
			if _, recorded := st.State().Tools["tool"]; recorded {
				t.Fatal("a failed state write left a recorded row")
			}
		})
	}
}
