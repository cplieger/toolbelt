package toolbelt

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cplieger/go/filesafe"
)

// manifestDoc is a tools.json document holding rows, a comma-separated list
// of `"name":{...}` members.
func manifestDoc(rows string) []byte {
	return fmt.Appendf(nil, "{\"version\":%d,\"tools\":{%s}}\n", ManifestVersion, rows)
}

// templateRow is a disabled manual row: recorded intent that queues no install.
func templateRow(name string) string {
	return fmt.Sprintf(`%q:{"source":"manual","install":"true","disabled":true}`, name)
}

func readManifestFile(t *testing.T, e *Engine) []byte {
	t.Helper()
	b, err := os.ReadFile(e.store.manifestPath)
	if err != nil {
		t.Fatalf("read tools.json: %v", err)
	}
	return b
}

func writeManifestFile(t *testing.T, e *Engine, data []byte) {
	t.Helper()
	if err := os.WriteFile(e.store.manifestPath, data, 0o644); err != nil {
		t.Fatalf("Setup: write tools.json: %v", err)
	}
}

func removeManifestFile(t *testing.T, e *Engine) {
	t.Helper()
	if err := os.Remove(e.store.manifestPath); err != nil {
		t.Fatalf("Setup: remove tools.json: %v", err)
	}
}

// jobsOf counts the jobs of kind the queue holds, running, queued or finished.
func jobsOf(e *Engine, kind string) int {
	active, recent := e.Jobs()
	seen := map[string]bool{}
	for _, j := range append(recent, active) {
		if j != nil && j.Kind == kind {
			seen[j.ID] = true
		}
	}
	return len(seen)
}

// settleJobs waits until the queue runs nothing, so a later count sees every
// job a step queued and a queued reconcile is not shared with the next step.
func settleJobs(t *testing.T, e *Engine) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if active, _ := e.Jobs(); active == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the job queue did not drain within 10s")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func addTemplate(t *testing.T, e *Engine, name string) {
	t.Helper()
	if _, err := e.Add(t.Context(), &AddRequest{Name: name, Source: SourceManual, Install: "true", Disabled: true}); err != nil {
		t.Fatalf("Setup: Add(%s) = %v", name, err)
	}
}

func TestReplaceManifest_WaitsForTheStoreLock(t *testing.T) {
	e := newTestEngine(t, nil)
	doc := manifestDoc(templateRow("x"))
	before := jobsOf(e, JobKindReconcile)

	e.store.mu.Lock()
	done := make(chan error, 1)
	go func() { done <- e.ReplaceManifest(doc, nil) }()
	select {
	case err := <-done:
		e.store.mu.Unlock()
		t.Fatalf("ReplaceManifest returned %v while the store lock was held", err)
	case <-time.After(100 * time.Millisecond):
	}
	e.store.mu.Unlock()
	if err := <-done; err != nil {
		t.Fatalf("ReplaceManifest = %v", err)
	}
	if got := readManifestFile(t, e); !bytes.Equal(got, doc) {
		t.Errorf("tools.json = %q, want the replaced bytes %q", got, doc)
	}
	if got := jobsOf(e, JobKindReconcile); got != before+1 {
		t.Errorf("reconcile jobs = %d, want %d", got, before+1)
	}
}

func TestReplaceManifest_ARefusalWritesNothing(t *testing.T) {
	e := newTestEngine(t, nil)
	orig := readManifestFile(t, e)
	errStale := errors.New("stale")

	t.Run("check", func(t *testing.T) {
		var current []byte
		err := e.ReplaceManifest(manifestDoc(templateRow("x")), func(b []byte) error {
			current = b
			return errStale
		})
		if !errors.Is(err, errStale) {
			t.Errorf("ReplaceManifest = %v, want the check's error", err)
		}
		if !bytes.Equal(current, orig) {
			t.Errorf("check saw %q, want the bytes on disk %q", current, orig)
		}
	})
	for name, doc := range map[string]string{
		"truncated":     `{"version":2,"tools":{`,
		"wrong version": `{"version":1,"tools":{}}`,
		"invalid name":  `{"version":2,"tools":{"..":{}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := e.ReplaceManifest([]byte(doc), nil); !errors.Is(err, ErrManifestInvalid) {
				t.Errorf("ReplaceManifest(%s) = %v, want ErrManifestInvalid", doc, err)
			}
		})
	}
	if got := readManifestFile(t, e); !bytes.Equal(got, orig) {
		t.Errorf("tools.json = %q after refusals, want it unchanged %q", got, orig)
	}
	if got := jobsOf(e, JobKindReconcile); got != 0 {
		t.Errorf("reconcile jobs = %d after refusals, want 0", got)
	}
}

func TestSyncManifest_IgnoresTheEnginesOwnWrites(t *testing.T) {
	e := newTestEngine(t, nil)
	addTemplate(t, e, "x")
	changed, err := e.SyncManifest(readManifestFile(t, e), SeenValid)
	if changed || err != nil {
		t.Errorf("SyncManifest(the engine's own write) = %v, %v; want false, nil", changed, err)
	}
	if got := jobsOf(e, JobKindReconcile); got != 0 {
		t.Errorf("reconcile jobs = %d, want 0", got)
	}
}

func TestSyncManifest_ConvergesOnAnEditFoldedIntoAnEngineWrite(t *testing.T) {
	e := newTestEngine(t, nil)
	addTemplate(t, e, "x")
	writeManifestFile(t, e, manifestDoc(templateRow("x")+","+templateRow("hand")))
	desc := "patched"
	if _, err := e.Patch("x", PatchRequest{Description: &desc}); err != nil {
		t.Fatalf("Setup: Patch = %v", err)
	}
	settleJobs(t, e)
	written := readManifestFile(t, e)
	if !bytes.Contains(written, []byte(`"hand"`)) {
		t.Fatalf("Setup: the engine write dropped the hand edit: %q", written)
	}
	before := jobsOf(e, JobKindReconcile)

	changed, err := e.SyncManifest(written, SeenValid)
	if !changed || err != nil {
		t.Errorf("SyncManifest(an engine write over a hand edit) = %v, %v; want true, nil", changed, err)
	}
	if got := jobsOf(e, JobKindReconcile); got != before+1 {
		t.Errorf("reconcile jobs = %d, want %d", got, before+1)
	}
	settleJobs(t, e)
	if changed, err := e.SyncManifest(written, SeenValid); changed || err != nil {
		t.Errorf("a second SyncManifest = %v, %v; want false, nil", changed, err)
	}
}

func TestParseManifest_ErrorsMatchErrManifestInvalid(t *testing.T) {
	for name, tc := range map[string]struct{ doc, text string }{
		"bad json":    {`{"version":2,"tools":{`, "parse: unexpected end of JSON input"},
		"bad version": {`{"version":1,"tools":{}}`, "manifest version 1, want 2"},
		"bad name":    {`{"version":2,"tools":{"..":{}}}`, `invalid tool name ".."`},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseManifest([]byte(tc.doc))
			if !errors.Is(err, ErrManifestInvalid) {
				t.Errorf("ParseManifest(%s) = %v, want ErrManifestInvalid", tc.doc, err)
			}
			if err == nil || err.Error() != tc.text {
				t.Errorf("ParseManifest(%s).Error() = %v, want %q", tc.doc, err, tc.text)
			}
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "tools.json"), []byte(tc.doc), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := New(&Config{ConfigDir: dir, ToolsDir: filepath.Join(dir, "tools")}); !errors.Is(err, ErrManifestInvalid) {
				t.Errorf("New over %s = %v, want ErrManifestInvalid", tc.doc, err)
			}
		})
	}
}

func TestSyncManifest_AnAdoptedAbsenceIsReplacedByTheSeed(t *testing.T) {
	seed := &Manifest{Version: ManifestVersion, Comment: []string{"seeded"}, Tools: map[string]Tool{"gopls": {Disabled: true}}}
	e := newTestEngineClient(t, nil, http.DefaultClient, seed)
	addManual(t, e, "extra", nil)
	want := readManifestFile(t, newTestEngineClient(t, nil, http.DefaultClient, seed))
	removeManifestFile(t, e)
	before := jobsOf(e, JobKindReconcile)

	t.Run("absent", func(t *testing.T) {
		changed, err := e.SyncManifest(nil, SeenAbsent)
		if !changed || err != nil {
			t.Fatalf("SyncManifest(nil, SeenAbsent) = %v, %v; want true, nil", changed, err)
		}
		if got := readManifestFile(t, e); !bytes.Equal(got, want) {
			t.Errorf("tools.json = %q, want the seed as New writes it %q", got, want)
		}
		if got := jobsOf(e, JobKindReconcile); got != before+1 {
			t.Errorf("reconcile jobs = %d, want %d", got, before+1)
		}
		settleJobs(t, e)
		if _, ok := e.store.State().Tools["extra"]; ok {
			t.Error("the reconcile kept the row the seed does not list")
		}
		if changed, err := e.SyncManifest(want, SeenValid); changed || err != nil {
			t.Errorf("SyncManifest(the seeded bytes) = %v, %v; want false, nil", changed, err)
		}
	})
	t.Run("moved on", func(t *testing.T) {
		before := jobsOf(e, JobKindReconcile)
		if changed, err := e.SyncManifest(nil, SeenAbsent); changed || err != nil {
			t.Errorf("SyncManifest(nil, SeenAbsent) over a valid file = %v, %v; want false, nil", changed, err)
		}
		writeManifestFile(t, e, manifestDoc(templateRow("other")))
		if changed, err := e.SyncManifest(want, SeenValid); changed || err != nil {
			t.Errorf("SyncManifest(old bytes) over other bytes = %v, %v; want false, nil", changed, err)
		}
		if got := jobsOf(e, JobKindReconcile); got != before {
			t.Errorf("reconcile jobs = %d, want %d", got, before)
		}
	})
	t.Run("directory", func(t *testing.T) {
		removeManifestFile(t, e)
		if err := os.Mkdir(e.store.manifestPath, 0o755); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(e.store.manifestPath) })
		if changed, err := e.SyncManifest(nil, SeenAbsent); changed || err != nil {
			t.Errorf("SyncManifest(nil, SeenAbsent) over a directory = %v, %v; want false, nil", changed, err)
		}
		if changed, err := e.SyncManifest([]byte{}, SeenUnreadable); changed || err != nil {
			t.Errorf("SyncManifest(empty, SeenUnreadable) over a directory = %v, %v; want false, nil", changed, err)
		}
		changed, err := e.SyncManifest(nil, SeenUnreadable)
		if changed || !errors.Is(err, filesafe.ErrNotRegular) {
			t.Errorf("SyncManifest(nil, SeenUnreadable) over a directory = %v, %v; want false, ErrNotRegular", changed, err)
		}
	})
	t.Run("empty file", func(t *testing.T) {
		writeManifestFile(t, e, []byte{})
		if changed, err := e.SyncManifest(nil, SeenUnreadable); changed || err != nil {
			t.Errorf("SyncManifest(nil, SeenUnreadable) over an empty file = %v, %v; want false, nil", changed, err)
		}
		_, err := e.SyncManifest([]byte{}, SeenUnreadable)
		if !errors.Is(err, ErrManifestInvalid) {
			t.Errorf("SyncManifest(empty, SeenUnreadable) over an empty file = %v, want ErrManifestInvalid", err)
		}
	})
}

func TestMutateManifest_AHeldAbsenceStartsFromTheAppliedManifest(t *testing.T) {
	seed := &Manifest{Version: ManifestVersion, Tools: map[string]Tool{"gopls": {Disabled: true}}}

	t.Run("held absence", func(t *testing.T) {
		e := newTestEngineClient(t, nil, http.DefaultClient, seed)
		if err := e.store.MutateManifest(func(m *Manifest) error {
			m.Tools = map[string]Tool{"a": {Source: SourceManual, Disabled: true}, "b": {Source: SourceManual, Disabled: true}}
			return nil
		}); err != nil {
			t.Fatalf("Setup: %v", err)
		}
		removeManifestFile(t, e)
		m, err := e.store.LoadManifest()
		if err != nil {
			t.Fatalf("LoadManifest = %v", err)
		}
		if got := sortedToolNames(m); got != "a,b" {
			t.Errorf("LoadManifest over a held absence = %s, want the applied rows a,b", got)
		}
		if _, err := os.Stat(e.store.manifestPath); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("LoadManifest wrote tools.json: %v", err)
		}
		addTemplate(t, e, "c")
		got, err := ParseManifest(readManifestFile(t, e))
		if err != nil {
			t.Fatal(err)
		}
		if names := sortedToolNames(got); names != "a,b,c" {
			t.Errorf("Add over a held absence wrote %s, want a,b,c", names)
		}
	})
	t.Run("absence whose seed write failed", func(t *testing.T) {
		e := newTestEngineClient(t, nil, http.DefaultClient, seed)
		addTemplate(t, e, "a")
		removeManifestFile(t, e)
		errDisk := errors.New("disk full")
		write := atomicWrite
		atomicWrite = func(path string, data []byte) (bool, error) {
			if path == e.store.manifestPath {
				return false, errDisk
			}
			return write(path, data)
		}
		t.Cleanup(func() { atomicWrite = write })
		changed, err := e.SyncManifest(nil, SeenAbsent)
		if changed || !errors.Is(err, errDisk) || errors.Is(err, ErrManifestInvalid) {
			t.Errorf("SyncManifest over a failed seed write = %v, %v; want false and the write error", changed, err)
		}
		m, err := e.store.LoadManifest()
		if err != nil {
			t.Fatalf("LoadManifest = %v", err)
		}
		if got := sortedToolNames(m); got != "a,gopls" {
			t.Errorf("LoadManifest after a failed seed write = %s, want the applied a,gopls", got)
		}
		atomicWrite = write
		if changed, err := e.SyncManifest(nil, SeenAbsent); !changed || err != nil {
			t.Errorf("SyncManifest with the write working = %v, %v; want true, nil", changed, err)
		}
		got, err := ParseManifest(readManifestFile(t, e))
		if err != nil || sortedToolNames(got) != "gopls" {
			t.Errorf("tools.json after the retried seed write = %v, %v; want the seed gopls", got, err)
		}
	})
	t.Run("adopted absence, nil seed", func(t *testing.T) {
		e := newTestEngine(t, nil)
		addTemplate(t, e, "a")
		removeManifestFile(t, e)
		if _, err := e.SyncManifest(nil, SeenAbsent); err != nil {
			t.Fatalf("SyncManifest = %v", err)
		}
		m, err := e.store.LoadManifest()
		if err != nil || len(m.Tools) != 0 {
			t.Errorf("LoadManifest after an adopted absence with a nil seed = %v, %v; want an empty manifest", m, err)
		}
	})
	t.Run("absence after an adopted unparseable file", func(t *testing.T) {
		e := newTestEngineClient(t, nil, http.DefaultClient, seed)
		addTemplate(t, e, "a")
		bad := []byte(`{"version":`)
		writeManifestFile(t, e, bad)
		if _, err := e.SyncManifest(bad, SeenUnreadable); !errors.Is(err, ErrManifestInvalid) {
			t.Fatalf("Setup: SyncManifest(unparseable) = %v, want ErrManifestInvalid", err)
		}
		removeManifestFile(t, e)
		if m, err := e.store.LoadManifest(); !errors.Is(err, ErrManifestInvalid) {
			t.Errorf("LoadManifest = %v, %v; want ErrManifestInvalid", m, err)
		}
		_, err := e.Add(t.Context(), &AddRequest{Name: "c", Source: SourceManual, Install: "true", Disabled: true})
		if !errors.Is(err, ErrManifestInvalid) {
			t.Errorf("Add = %v, want ErrManifestInvalid", err)
		}
		if _, err := os.Stat(e.store.manifestPath); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("tools.json exists after the refusals: %v", err)
		}
	})
}

func sortedToolNames(m *Manifest) string {
	names := make([]string, 0, len(m.Tools))
	for n := range m.Tools {
		names = append(names, n)
	}
	slices.Sort(names)
	return strings.Join(names, ",")
}

func TestReadManifest_AFIFOIsRefusedWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tools.json")
	if err := syscall.Mkfifo(path, 0o644); err != nil {
		t.Fatalf("Setup: mkfifo: %v", err)
	}
	t.Cleanup(func() {
		// Releases a reader still blocked in open or read.
		if f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})
	st := newStore(dir, nil, slog.Default())
	done := make(chan error, 1)
	go func() {
		_, err := st.LoadManifest()
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, filesafe.ErrNotRegular) || errors.Is(err, ErrManifestInvalid) {
			t.Errorf("LoadManifest over a FIFO = %v, want ErrNotRegular and not ErrManifestInvalid", err)
		}
	case <-time.After(time.Second):
		t.Fatal("LoadManifest over a FIFO has not returned after 1s")
	}

	t.Run("symlink to a regular file", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "real.json")
		if err := os.WriteFile(target, manifestDoc(templateRow("x")), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, "tools.json")); err != nil {
			t.Fatal(err)
		}
		m, err := newStore(dir, nil, slog.Default()).LoadManifest()
		if err != nil || sortedToolNames(m) != "x" {
			t.Errorf("LoadManifest through a symlink = %v, %v; want the row x", m, err)
		}
	})
}

func TestReplaceManifest_AFileItCannotReadRefusesACheckedSave(t *testing.T) {
	e := newTestEngine(t, nil)
	orig := readManifestFile(t, e)
	e.store.mu.Lock()
	e.store.open = func(path string) (*os.File, error) {
		return nil, &fs.PathError{Op: "open", Path: path, Err: syscall.EIO}
	}
	e.store.mu.Unlock()
	t.Cleanup(func() {
		e.store.mu.Lock()
		e.store.open = nil
		e.store.mu.Unlock()
	})

	checked := false
	err := e.ReplaceManifest(manifestDoc(templateRow("x")), func([]byte) error {
		checked = true
		return nil
	})
	if !errors.Is(err, syscall.EIO) {
		t.Errorf("ReplaceManifest = %v, want the read's EIO", err)
	}
	if checked {
		t.Error("check ran over a tools.json that could not be read")
	}
	if got := readManifestFile(t, e); !bytes.Equal(got, orig) {
		t.Errorf("tools.json = %q after the refusal, want it unchanged %q", got, orig)
	}
	doc := manifestDoc(templateRow("x"))
	if err := e.ReplaceManifest(doc, nil); err != nil {
		t.Errorf("ReplaceManifest with no check = %v, want the write", err)
	}
	if got := readManifestFile(t, e); !bytes.Equal(got, doc) {
		t.Errorf("tools.json = %q, want the unchecked write %q", got, doc)
	}
}

func TestReplaceManifest_ACheckSeesNilForAnAbsentOrNonRegularFile(t *testing.T) {
	for name, plant := range map[string]func(path string) error{
		"absent":    os.Remove,
		"directory": func(path string) error { return errors.Join(os.Remove(path), os.Mkdir(path, 0o755)) },
		"FIFO":      func(path string) error { return errors.Join(os.Remove(path), syscall.Mkfifo(path, 0o644)) },
		"socket": func(path string) error {
			return errors.Join(os.Remove(path), syscall.Mknod(path, syscall.S_IFSOCK|0o644, 0))
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newTestEngine(t, nil)
			if err := plant(e.store.manifestPath); err != nil {
				t.Fatalf("Setup: %v", err)
			}
			checked := false
			err := e.ReplaceManifest(manifestDoc(templateRow("x")), func(current []byte) error {
				checked = true
				if current != nil {
					t.Errorf("check saw %q, want nil", current)
				}
				return nil
			})
			if !checked {
				t.Errorf("check did not run (ReplaceManifest = %v)", err)
			}
			if name == "absent" && err != nil {
				t.Errorf("ReplaceManifest over an absent tools.json = %v, want the write", err)
			}
		})
	}
}

func TestReplaceManifest_RefusesDroppingAnEssentialRow(t *testing.T) {
	cat := &Catalog{Entries: map[string]CatalogEntry{"node": {Name: "node", Source: SourceManual, Essential: true}}}
	e := newTestEngine(t, cat)
	writeManifestFile(t, e, manifestDoc(templateRow("node")+","+templateRow("x")))
	orig := readManifestFile(t, e)

	err := e.ReplaceManifest(manifestDoc(templateRow("x")), nil)
	if !errors.Is(err, ErrEssential) || !strings.Contains(err.Error(), "node") {
		t.Errorf("ReplaceManifest without node = %v, want ErrEssential naming node", err)
	}
	if got := readManifestFile(t, e); !bytes.Equal(got, orig) {
		t.Errorf("tools.json = %q after the refusal, want it unchanged", got)
	}
	if got := jobsOf(e, JobKindReconcile); got != 0 {
		t.Errorf("reconcile jobs = %d after the refusal, want 0", got)
	}
	disabled := manifestDoc(templateRow("node"))
	if err := e.ReplaceManifest(disabled, nil); err != nil {
		t.Errorf("ReplaceManifest with node disabled = %v, want it written", err)
	}
	if err := WriteManifest(t.TempDir(), manifestDoc(templateRow("x"))); err != nil {
		t.Errorf("WriteManifest without node = %v, want it written (no catalog)", err)
	}
}

func TestWriteManifest_ValidatesAndWritesVerbatim(t *testing.T) {
	dir := t.TempDir()
	doc := []byte(utf8BOM + string(manifestDoc(templateRow("x"))))
	if err := WriteManifest(dir, doc); err != nil {
		t.Fatalf("WriteManifest = %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "tools.json"))
	if err != nil || !bytes.Equal(got, doc) {
		t.Errorf("tools.json = %q, %v; want the bytes verbatim", got, err)
	}
	if info, err := os.Stat(filepath.Join(dir, "tools.json")); err != nil || info.Mode().Perm() != engineFileMode {
		t.Errorf("tools.json mode = %v, %v; want %v", info.Mode().Perm(), err, engineFileMode)
	}
	if err := WriteManifest(dir, []byte(`{"version":1}`)); !errors.Is(err, ErrManifestInvalid) {
		t.Errorf("WriteManifest(wrong version) = %v, want ErrManifestInvalid", err)
	}
	if got2, _ := os.ReadFile(filepath.Join(dir, "tools.json")); !bytes.Equal(got2, doc) {
		t.Errorf("a refused WriteManifest changed tools.json to %q", got2)
	}
}
