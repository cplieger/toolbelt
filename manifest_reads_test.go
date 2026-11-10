package toolbelt

import (
	"errors"
	"net/http"
	"os"
	"syscall"
	"testing"

	"github.com/cplieger/go/filesafe"
)

// manifestState puts an engine's tools.json into one state of the one rule:
// a read the store holds (no SyncManifest yet) or one SyncManifest adopted.
type manifestState struct {
	put  func(t *testing.T, e *Engine)
	name string
}

func manifestStates() []manifestState {
	bad := []byte(`{"version":`)
	return []manifestState{
		{name: "held absence", put: func(t *testing.T, e *Engine) { removeManifestFile(t, e) }},
		{name: "held unparseable", put: func(t *testing.T, e *Engine) { writeManifestFile(t, e, bad) }},
		{name: "held fifo", put: func(t *testing.T, e *Engine) {
			removeManifestFile(t, e)
			if err := syscall.Mkfifo(e.store.manifestPath, 0o644); err != nil {
				t.Fatalf("Setup: mkfifo: %v", err)
			}
		}},
		{name: "held absence, failed seed write", put: func(t *testing.T, e *Engine) {
			removeManifestFile(t, e)
			write := atomicWrite
			atomicWrite = func(string, []byte) (bool, error) { return false, errors.New("disk full") }
			_, err := e.SyncManifest(nil, SeenAbsent)
			atomicWrite = write
			if err == nil {
				t.Fatal("Setup: SyncManifest wrote the seed through a failing write")
			}
		}},
		{name: "adopted unparseable", put: func(t *testing.T, e *Engine) {
			writeManifestFile(t, e, bad)
			if _, err := e.SyncManifest(bad, SeenUnreadable); !errors.Is(err, ErrManifestInvalid) {
				t.Fatalf("Setup: SyncManifest(unparseable) = %v", err)
			}
		}},
	}
}

// newReadsEngine is an engine with the seed gopls and an applied manifest of
// a (installed) and b (a template), neither of which the seed lists.
func newReadsEngine(t *testing.T) (*Engine, []byte) {
	t.Helper()
	seed := &Manifest{Version: ManifestVersion, Tools: map[string]Tool{"gopls": {Disabled: true}}}
	e := newTestEngineClient(t, nil, http.DefaultClient, seed)
	if err := e.store.MutateManifest(func(m *Manifest) error {
		m.Tools = map[string]Tool{}
		return nil
	}); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	addManual(t, e, "a", nil)
	addTemplate(t, e, "b")
	return e, readManifestFile(t, e)
}

func TestManifestReads(t *testing.T) {
	want := map[string]struct {
		loadErr   error
		addErr    error
		load, add string
		aKept     bool
	}{
		"held absence":                    {load: "a,b", add: "a,b,c", aKept: true},
		"held unparseable":                {load: "a,b", addErr: ErrManifestInvalid, aKept: true},
		"held fifo":                       {load: "a,b", addErr: filesafe.ErrNotRegular, aKept: true},
		"held absence, failed seed write": {load: "a,b", add: "a,b,c", aKept: true},
		"adopted unparseable":             {loadErr: ErrManifestInvalid, addErr: ErrManifestInvalid, aKept: true},
	}
	for _, st := range manifestStates() {
		w := want[st.name]
		t.Run(st.name, func(t *testing.T) {
			t.Run("LoadManifest", func(t *testing.T) {
				e, applied := newReadsEngine(t)
				st.put(t, e)
				m, err := e.store.LoadManifest()
				switch {
				case w.loadErr != nil:
					if !errors.Is(err, w.loadErr) {
						t.Errorf("LoadManifest = %v, %v; want %v", m, err, w.loadErr)
					}
				case err != nil:
					t.Errorf("LoadManifest = %v, want %s", err, w.load)
				case sortedToolNames(m) != w.load:
					t.Errorf("LoadManifest = %s, want %s", sortedToolNames(m), w.load)
				}
				if st.name[:4] != "held" {
					return
				}
				// A read moves no record: the applied bytes back on disk are still the
				// engine's own, so SyncManifest has nothing to apply.
				_ = os.Remove(e.store.manifestPath)
				writeManifestFile(t, e, applied)
				if changed, err := e.SyncManifest(applied, SeenValid); changed || err != nil {
					t.Errorf("SyncManifest(the applied bytes) after a held read = %v, %v; want false, nil", changed, err)
				}
			})
			t.Run("Add", func(t *testing.T) {
				e, _ := newReadsEngine(t)
				st.put(t, e)
				_, err := e.Add(t.Context(), &AddRequest{Name: "c", Source: SourceManual, Install: "true", Disabled: true})
				if w.addErr != nil {
					if !errors.Is(err, w.addErr) {
						t.Errorf("Add = %v, want %v", err, w.addErr)
					}
					return
				}
				if err != nil {
					t.Fatalf("Add = %v", err)
				}
				m, err := ParseManifest(readManifestFile(t, e))
				if err != nil || sortedToolNames(m) != w.add {
					t.Errorf("Add wrote %v, %v; want %s", m, err, w.add)
				}
			})
			t.Run("Reconcile", func(t *testing.T) {
				e, _ := newReadsEngine(t)
				st.put(t, e)
				job, _, err := e.Reconcile(ReconcileMissing)
				if err != nil && w.loadErr == nil {
					t.Fatalf("Reconcile = %v", err)
				}
				settleJobs(t, e)
				if _, kept := e.store.State().Tools["a"]; kept != w.aKept {
					t.Errorf("a installed after the reconcile = %v, want %v", kept, w.aKept)
				}
				if job == nil {
					return
				}
				// A job that writes nothing to tools.json is never refused as a merge over it.
				if done, err := e.Wait(t.Context(), job.ID); err != nil || done.State != JobDone {
					t.Errorf("the reconcile job ended %s (%s, %v), want done", done.State, done.Error, err)
				}
			})
		})
	}
}
