package toolbelt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"
)

// bigCatalog builds a catalog document above the structural entry floor,
// with a marker entry for swap assertions and a manual-source entry so
// Require verification has something real to check.
func bigCatalog(marker, generated string) *Catalog {
	c := &Catalog{
		Refs:      map[string]string{"mise": marker},
		Generated: generated,
		Entries:   map[string]CatalogEntry{},
	}
	for i := range minCatalogEntries {
		name := fmt.Sprintf("filler-%03d", i)
		c.Entries[name] = CatalogEntry{Name: name, Source: "npm:" + name}
	}
	c.Entries[marker] = CatalogEntry{
		Name: marker, Source: SourceManual, Install: "true", Description: "marker",
	}
	return c
}

func catalogJSON(t *testing.T, c *Catalog) []byte {
	t.Helper()
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// newRefreshEngine builds an engine with the refresh subsystem wired,
// a plain HTTP client (httptest is loopback, which the production SSRF
// transport rightly blocks), and initCatalog run against cfg.
func newRefreshEngine(t *testing.T, cfg *Config) *Engine {
	t.Helper()
	dir := cfg.ConfigDir
	st := newStore(dir, nil, slog.Default())
	if err := st.initFiles(); err != nil {
		t.Fatal(err)
	}
	toolsDir := filepath.Join(dir, "tools")
	if err := os.MkdirAll(filepath.Join(toolsDir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	e := &Engine{
		store:           st,
		refresh:         cfg.Refresh,
		catalogOverlays: cfg.CatalogOverlays,
		client:          http.DefaultClient,
		versions:        newVersionResolver(http.DefaultClient),
		log:             slog.Default(),
		configDir:       dir,
		toolsDir:        toolsDir,
	}
	e.initCatalog(cfg)
	e.inst = &installer{toolsDir: toolsDir, client: http.DefaultClient, output: func(string) {}}
	e.queue = newJobQueue(nil, nil, slog.Default(), e.executeJob)
	e.startCatalogSchedule()
	t.Cleanup(e.Close)
	return e
}

func writeBaked(t *testing.T, dir string, c *Catalog) string {
	t.Helper()
	path := filepath.Join(dir, "baked-catalog.json")
	if err := os.WriteFile(path, catalogJSON(t, c), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func refreshAndWait(t *testing.T, e *Engine) *Job {
	t.Helper()
	jv, err := e.RefreshCatalog()
	if err != nil {
		t.Fatalf("RefreshCatalog: %v", err)
	}
	return waitJob(t, e, jv.ID)
}

func TestApplyOverlay(t *testing.T) {
	base := func() *Catalog {
		return &Catalog{Entries: map[string]CatalogEntry{
			"tool-a": {Name: "tool-a", Source: "npm:tool-a", Description: "old"},
		}}
	}

	t.Run("display patch merges onto existing entry", func(t *testing.T) {
		c := base()
		ov := []byte(`{"entries":{"tool-a":{"description":"new","featured":true,"lsp":true}}}`)
		if err := ApplyOverlay(c, ov, nil); err != nil {
			t.Fatal(err)
		}
		got := c.Entries["tool-a"]
		if got.Description != "new" || !got.Featured || !got.Lsp || got.Source != "npm:tool-a" {
			t.Errorf("merge wrong: %+v", got)
		}
	})

	t.Run("patch on unknown tool errors", func(t *testing.T) {
		c := base()
		ov := []byte(`{"entries":{"ghost":{"description":"x"}}}`)
		if err := ApplyOverlay(c, ov, nil); err == nil {
			t.Error("want error for unknown tool patch")
		}
	})

	t.Run("source-bearing entry replaces and indexes aliases", func(t *testing.T) {
		c := base()
		ov := []byte(`{"entries":{"tool-b":{"source":"manual","install":"true","aliases":["tb"]}}}`)
		if err := ApplyOverlay(c, ov, nil); err != nil {
			t.Fatal(err)
		}
		if _, ok := c.Lookup("tb"); !ok {
			t.Error("alias tb not indexed after overlay")
		}
		if c.Entries["tool-b"].Name != "tool-b" {
			t.Errorf("name not stamped: %+v", c.Entries["tool-b"])
		}
	})

	t.Run("aqua source without definition needs a resolver", func(t *testing.T) {
		c := base()
		ov := []byte(`{"entries":{"tool-c":{"source":"aqua:owner/repo"}}}`)
		if err := ApplyOverlay(c, ov, nil); err == nil {
			t.Error("want error: aqua source, no embedded definition, nil resolver")
		}
		called := ""
		resolver := func(ref string) (*AquaPackage, error) {
			called = ref
			return &AquaPackage{Type: aquaTypeGitHubRelease, RepoOwner: "owner", RepoName: "repo"}, nil
		}
		if err := ApplyOverlay(c, ov, resolver); err != nil {
			t.Fatal(err)
		}
		if called != "owner/repo" {
			t.Errorf("resolver called with %q", called)
		}
		if c.Entries["tool-c"].Aqua == nil {
			t.Error("resolved definition not attached")
		}
	})

	t.Run("broken overlay JSON errors", func(t *testing.T) {
		c := base()
		if err := ApplyOverlay(c, []byte("{"), nil); err == nil {
			t.Error("want parse error")
		}
	})
}

func TestParseCatalog(t *testing.T) {
	t.Run("nil entries normalize", func(t *testing.T) {
		c, err := parseCatalog([]byte(`{"refs":{"mise":"v1"}}`))
		if err != nil {
			t.Fatal(err)
		}
		if c.Entries == nil {
			t.Error("entries not normalized")
		}
	})
	t.Run("broken JSON errors", func(t *testing.T) {
		if _, err := parseCatalog([]byte("nope")); err == nil {
			t.Error("want error")
		}
	})
}

func TestInitCatalogBootOrder(t *testing.T) {
	t.Run("no refresh config loads baked only", func(t *testing.T) {
		dir := t.TempDir()
		baked := writeBaked(t, dir, bigCatalog("baked-marker", "g1"))
		e := newRefreshEngine(t, &Config{ConfigDir: dir, ToolsDir: filepath.Join(dir, "tools"), CatalogPath: baked})
		if _, ok := e.cat().Lookup("baked-marker"); !ok {
			t.Error("baked catalog not loaded")
		}
		if info := e.CatalogInfo(); info.Source != CatalogSourceBaked || info.Scheduled {
			t.Errorf("info = %+v", info)
		}
	})

	t.Run("valid cache preferred over baked", func(t *testing.T) {
		dir := t.TempDir()
		baked := writeBaked(t, dir, bigCatalog("baked-marker", "g1"))
		cached := catalogJSON(t, bigCatalog("cached-marker", "g2"))
		if err := os.WriteFile(filepath.Join(dir, cachedCatalogName), cached, 0o600); err != nil {
			t.Fatal(err)
		}
		e := newRefreshEngine(t, &Config{
			ConfigDir: dir, ToolsDir: filepath.Join(dir, "tools"), CatalogPath: baked,
			Refresh: &CatalogRefresh{URL: "https://example.invalid/catalog.json", Require: []string{"cached-marker"}},
		})
		if _, ok := e.cat().Lookup("cached-marker"); !ok {
			t.Error("cached catalog not loaded")
		}
		if info := e.CatalogInfo(); info.Source != CatalogSourceCached {
			t.Errorf("source = %s, want cached", info.Source)
		}
	})

	t.Run("corrupt cache falls back to baked", func(t *testing.T) {
		dir := t.TempDir()
		baked := writeBaked(t, dir, bigCatalog("baked-marker", "g1"))
		if err := os.WriteFile(filepath.Join(dir, cachedCatalogName), []byte("{broken"), 0o600); err != nil {
			t.Fatal(err)
		}
		e := newRefreshEngine(t, &Config{
			ConfigDir: dir, ToolsDir: filepath.Join(dir, "tools"), CatalogPath: baked,
			Refresh: &CatalogRefresh{URL: "https://example.invalid/catalog.json"},
		})
		if _, ok := e.cat().Lookup("baked-marker"); !ok {
			t.Error("baked fallback not loaded")
		}
		if info := e.CatalogInfo(); info.Source != CatalogSourceBaked {
			t.Errorf("source = %s, want baked", info.Source)
		}
	})

	t.Run("cache missing a required tool falls back to baked", func(t *testing.T) {
		dir := t.TempDir()
		baked := writeBaked(t, dir, bigCatalog("baked-marker", "g1"))
		cached := catalogJSON(t, bigCatalog("cached-marker", "g2"))
		if err := os.WriteFile(filepath.Join(dir, cachedCatalogName), cached, 0o600); err != nil {
			t.Fatal(err)
		}
		e := newRefreshEngine(t, &Config{
			ConfigDir: dir, ToolsDir: filepath.Join(dir, "tools"), CatalogPath: baked,
			Refresh: &CatalogRefresh{URL: "https://example.invalid/catalog.json", Require: []string{"not-there"}},
		})
		if info := e.CatalogInfo(); info.Source != CatalogSourceBaked {
			t.Errorf("source = %s, want baked", info.Source)
		}
	})

	t.Run("missing baked degrades to none", func(t *testing.T) {
		dir := t.TempDir()
		e := newRefreshEngine(t, &Config{ConfigDir: dir, ToolsDir: filepath.Join(dir, "tools")})
		if info := e.CatalogInfo(); info.Source != CatalogSourceNone || info.Entries != 0 {
			t.Errorf("info = %+v", info)
		}
	})

	t.Run("baked catalog newer than cache wins at boot", func(t *testing.T) {
		dir := t.TempDir()
		baked := writeBaked(t, dir, bigCatalog("baked-marker", "2026-07-22T10:00:00Z"))
		cached := catalogJSON(t, bigCatalog("cached-marker", "2026-07-01T10:00:00Z"))
		if err := os.WriteFile(filepath.Join(dir, cachedCatalogName), cached, 0o600); err != nil {
			t.Fatal(err)
		}
		e := newRefreshEngine(t, &Config{
			ConfigDir: dir, ToolsDir: filepath.Join(dir, "tools"), CatalogPath: baked,
			Refresh: &CatalogRefresh{URL: "https://example.invalid/catalog.json"},
		})
		if info := e.CatalogInfo(); info.Source != CatalogSourceBaked {
			t.Errorf("source = %s, want baked (newer image must not be downgraded)", info.Source)
		}
		if _, ok := e.cat().Lookup("baked-marker"); !ok {
			t.Error("baked catalog not chosen")
		}
	})

	t.Run("unknown-tool display patch is skipped, not fatal", func(t *testing.T) {
		dir := t.TempDir()
		baked := writeBaked(t, dir, bigCatalog("baked-marker", "g1"))
		ovPath := filepath.Join(dir, "overlay.json")
		ov := `{"entries":{"vanished-tool":{"description":"cosmetic"},"baked-marker":{"description":"patched"}}}`
		if err := os.WriteFile(ovPath, []byte(ov), 0o600); err != nil {
			t.Fatal(err)
		}
		e := newRefreshEngine(t, &Config{
			ConfigDir: dir, ToolsDir: filepath.Join(dir, "tools"), CatalogPath: baked,
			CatalogOverlays: []string{ovPath},
		})
		got, _ := e.cat().Lookup("baked-marker")
		if got.Description != "patched" {
			t.Errorf("surviving patch not applied: %+v", got)
		}
		if _, ok := e.cat().Lookup("vanished-tool"); ok {
			t.Error("skipped patch materialized an entry")
		}
	})

	t.Run("overlay failure is transactional at boot", func(t *testing.T) {
		// A source-bearing aqua entry without an embedded definition
		// fails (nil runtime resolver); the engine must fall back to
		// the ORIGINAL catalog, not a partially patched one.
		dir := t.TempDir()
		baked := writeBaked(t, dir, bigCatalog("baked-marker", "g1"))
		ovPath := filepath.Join(dir, "overlay.json")
		ov := `{"entries":{"baked-marker":{"description":"patched first"},"broken":{"source":"aqua:o/r"}}}`
		if err := os.WriteFile(ovPath, []byte(ov), 0o600); err != nil {
			t.Fatal(err)
		}
		e := newRefreshEngine(t, &Config{
			ConfigDir: dir, ToolsDir: filepath.Join(dir, "tools"), CatalogPath: baked,
			CatalogOverlays: []string{ovPath},
		})
		got, _ := e.cat().Lookup("baked-marker")
		if got.Description == "patched first" {
			t.Error("partial overlay leaked into the degraded catalog")
		}
		if _, ok := e.cat().Lookup("broken"); ok {
			t.Error("failed overlay entry materialized")
		}
	})

	t.Run("overlays apply to baked catalog at boot", func(t *testing.T) {
		dir := t.TempDir()
		baked := writeBaked(t, dir, bigCatalog("baked-marker", "g1"))
		ovPath := filepath.Join(dir, "overlay.json")
		ov := `{"entries":{"baked-marker":{"description":"patched","featured":true}}}`
		if err := os.WriteFile(ovPath, []byte(ov), 0o600); err != nil {
			t.Fatal(err)
		}
		e := newRefreshEngine(t, &Config{
			ConfigDir: dir, ToolsDir: filepath.Join(dir, "tools"), CatalogPath: baked,
			CatalogOverlays: []string{ovPath},
		})
		got, _ := e.cat().Lookup("baked-marker")
		if got.Description != "patched" || !got.Featured {
			t.Errorf("overlay not applied: %+v", got)
		}
	})
}

func TestCatalogRefreshJob(t *testing.T) {
	serve := func(t *testing.T, body []byte) *httptest.Server {
		t.Helper()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(body)
		}))
		t.Cleanup(srv.Close)
		return srv
	}
	setup := func(t *testing.T, url string, require []string) (*Engine, string) {
		t.Helper()
		dir := t.TempDir()
		baked := writeBaked(t, dir, bigCatalog("old-marker", "gen-old"))
		e := newRefreshEngine(t, &Config{
			ConfigDir: dir, ToolsDir: filepath.Join(dir, "tools"), CatalogPath: baked,
			Refresh: &CatalogRefresh{URL: url, Require: require},
		})
		return e, dir
	}

	t.Run("success swaps, caches, and records provenance", func(t *testing.T) {
		fresh := bigCatalog("new-marker", "gen-new")
		srv := serve(t, catalogJSON(t, fresh))
		e, dir := setup(t, srv.URL, []string{"new-marker"})

		final := refreshAndWait(t, e)
		if final.State != JobDone {
			t.Fatalf("job = %s (%s)", final.State, final.Error)
		}
		if _, ok := e.cat().Lookup("new-marker"); !ok {
			t.Error("catalog not swapped")
		}
		if _, ok := e.cat().Lookup("old-marker"); ok {
			t.Error("old catalog still visible")
		}
		info := e.CatalogInfo()
		if info.Source != CatalogSourceRemote || info.FetchedAt == 0 || info.LastError != "" {
			t.Errorf("info = %+v", info)
		}
		cachedBytes, err := os.ReadFile(filepath.Join(dir, cachedCatalogName))
		if err != nil {
			t.Fatalf("cache not written: %v", err)
		}
		if !bytes.Equal(cachedBytes, catalogJSON(t, fresh)) {
			t.Error("cache is not a faithful copy of the fetched bytes")
		}
	})

	t.Run("invalid JSON keeps last good", func(t *testing.T) {
		srv := serve(t, []byte("<html>error page</html>"))
		e, _ := setup(t, srv.URL, nil)
		final := refreshAndWait(t, e)
		if final.State != JobFailed {
			t.Fatalf("job = %s, want failed", final.State)
		}
		if _, ok := e.cat().Lookup("old-marker"); !ok {
			t.Error("current catalog lost on failed refresh")
		}
		if info := e.CatalogInfo(); info.LastError == "" || info.Source != CatalogSourceBaked {
			t.Errorf("info = %+v", info)
		}
	})

	t.Run("entry floor rejects a gutted catalog", func(t *testing.T) {
		small := &Catalog{Generated: "gen-small", Entries: map[string]CatalogEntry{
			"only": {Name: "only", Source: "npm:only"},
		}}
		srv := serve(t, catalogJSON(t, small))
		e, _ := setup(t, srv.URL, nil)
		if final := refreshAndWait(t, e); final.State != JobFailed {
			t.Fatalf("job = %s, want failed", final.State)
		}
		if _, ok := e.cat().Lookup("old-marker"); !ok {
			t.Error("current catalog lost")
		}
	})

	t.Run("missing required tool rejects", func(t *testing.T) {
		srv := serve(t, catalogJSON(t, bigCatalog("new-marker", "gen-new")))
		e, _ := setup(t, srv.URL, []string{"old-marker"}) // fetched catalog lacks it
		if final := refreshAndWait(t, e); final.State != JobFailed {
			t.Fatalf("job = %s, want failed", final.State)
		}
		if info := e.CatalogInfo(); info.Source != CatalogSourceBaked {
			t.Errorf("source = %s, want baked (no swap)", info.Source)
		}
	})

	t.Run("oversized body rejects", func(t *testing.T) {
		srv := serve(t, bytes.Repeat([]byte("x"), maxCatalogBytes+1))
		e, _ := setup(t, srv.URL, nil)
		if final := refreshAndWait(t, e); final.State != JobFailed {
			t.Fatalf("job = %s, want failed", final.State)
		}
	})

	t.Run("unchanged cache content short-circuits without swap", func(t *testing.T) {
		fresh := bigCatalog("new-marker", "gen-new")
		body := catalogJSON(t, fresh)
		srv := serve(t, body)
		e, dir := setup(t, srv.URL, nil)
		// Pre-seed the cache with exactly the served bytes: the refresh
		// must report already-current, skip the swap, and still bump
		// the freshness signal.
		if err := os.WriteFile(filepath.Join(dir, cachedCatalogName), body, 0o600); err != nil {
			t.Fatal(err)
		}
		final := refreshAndWait(t, e)
		if final.State != JobDone {
			t.Fatalf("job = %s (%s)", final.State, final.Error)
		}
		if _, ok := e.cat().Lookup("new-marker"); ok {
			t.Error("swap happened despite identical cache content")
		}
		if info := e.CatalogInfo(); info.FetchedAt == 0 {
			t.Error("short-circuit did not record the currency check")
		}
	})

	t.Run("same generation with changed content still swaps", func(t *testing.T) {
		// A publisher bug reusing a generation stamp on different
		// content must not wedge consumers: the short-circuit keys on
		// cache bytes, not the stamp.
		clone := bigCatalog("would-be-new", "gen-old")
		srv := serve(t, catalogJSON(t, clone))
		e, _ := setup(t, srv.URL, nil)
		if final := refreshAndWait(t, e); final.State != JobDone {
			t.Fatalf("job = %s (%s)", final.State, final.Error)
		}
		if _, ok := e.cat().Lookup("would-be-new"); !ok {
			t.Error("stamp-equal but content-different catalog was not swapped")
		}
	})

	t.Run("failed cache write repairs on the next refresh", func(t *testing.T) {
		// Simulate a cache diverged from the live catalog (the residue
		// of a failed write): a refresh serving the same live content
		// must fall through the short-circuit and re-persist the cache.
		fresh := bigCatalog("new-marker", "gen-new")
		body := catalogJSON(t, fresh)
		srv := serve(t, body)
		e, dir := setup(t, srv.URL, nil)
		if err := os.WriteFile(filepath.Join(dir, cachedCatalogName), []byte("{diverged"), 0o600); err != nil {
			t.Fatal(err)
		}
		if final := refreshAndWait(t, e); final.State != JobDone {
			t.Fatalf("job = %s (%s)", final.State, final.Error)
		}
		cached, err := os.ReadFile(filepath.Join(dir, cachedCatalogName))
		if err != nil || !bytes.Equal(cached, body) {
			t.Errorf("cache not repaired: err=%v equal=%v", err, bytes.Equal(cached, body))
		}
	})

	t.Run("overlay re-applies to fetched catalog", func(t *testing.T) {
		dir := t.TempDir()
		baked := writeBaked(t, dir, bigCatalog("old-marker", "gen-old"))
		ovPath := filepath.Join(dir, "overlay.json")
		ov := `{"entries":{"new-marker":{"description":"patched by overlay"}}}`
		if err := os.WriteFile(ovPath, []byte(ov), 0o600); err != nil {
			t.Fatal(err)
		}
		srv := serve(t, catalogJSON(t, bigCatalog("new-marker", "gen-new")))
		e := newRefreshEngine(t, &Config{
			ConfigDir: dir, ToolsDir: filepath.Join(dir, "tools"), CatalogPath: baked,
			CatalogOverlays: []string{ovPath},
			Refresh:         &CatalogRefresh{URL: srv.URL},
		})
		// Boot overlay patching new-marker fails on the BAKED catalog
		// (unknown tool there), which is the degrade-and-continue path;
		// the refresh catalog HAS the entry, so the overlay must land.
		if final := refreshAndWait(t, e); final.State != JobDone {
			t.Fatalf("job = %s (%s)", final.State, final.Error)
		}
		got, _ := e.cat().Lookup("new-marker")
		if got.Description != "patched by overlay" {
			t.Errorf("overlay not applied to fetched catalog: %+v", got)
		}
	})

	t.Run("unconfigured refresh refuses", func(t *testing.T) {
		dir := t.TempDir()
		e := newRefreshEngine(t, &Config{ConfigDir: dir, ToolsDir: filepath.Join(dir, "tools")})
		if _, err := e.RefreshCatalog(); err == nil {
			t.Error("want ErrRefreshNotConfigured")
		}
	})

	t.Run("cache round-trip: next boot loads the fetched catalog", func(t *testing.T) {
		// Real RFC 3339 stamps: newest-wins boot selection compares them
		// as strings, so the fetched catalog must be genuinely newer
		// than the baked one for the cache to win the reboot.
		fresh := bigCatalog("new-marker", "2026-07-22T12:00:00Z")
		srv := serve(t, catalogJSON(t, fresh))
		dir := t.TempDir()
		baked := writeBaked(t, dir, bigCatalog("old-marker", "2026-07-01T12:00:00Z"))
		e := newRefreshEngine(t, &Config{
			ConfigDir: dir, ToolsDir: filepath.Join(dir, "tools"), CatalogPath: baked,
			Refresh: &CatalogRefresh{URL: srv.URL, Require: []string{"new-marker"}},
		})
		if final := refreshAndWait(t, e); final.State != JobDone {
			t.Fatalf("refresh failed: %s", final.Error)
		}
		e.Close()

		// A second engine on the same ConfigDir boots from the cache.
		e2 := newRefreshEngine(t, &Config{
			ConfigDir: dir, ToolsDir: filepath.Join(dir, "tools"), CatalogPath: baked,
			Refresh: &CatalogRefresh{URL: srv.URL, Require: []string{"new-marker"}},
		})
		if info := e2.CatalogInfo(); info.Source != CatalogSourceCached {
			t.Errorf("source = %s, want cached", info.Source)
		}
		if _, ok := e2.cat().Lookup("new-marker"); !ok {
			t.Error("cached refresh result not loaded on reboot")
		}
	})
}

func TestCatalogScheduleTicks(t *testing.T) {
	var mu sync.Mutex
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		_, _ = w.Write(catalogJSON(t, bigCatalog("sched-marker", "gen-sched")))
	}))
	defer srv.Close()

	dir := t.TempDir()
	baked := writeBaked(t, dir, bigCatalog("old-marker", "gen-old"))
	e := newRefreshEngine(t, &Config{
		ConfigDir: dir, ToolsDir: filepath.Join(dir, "tools"), CatalogPath: baked,
		Refresh: &CatalogRefresh{URL: srv.URL, Interval: 50 * time.Millisecond},
	})
	if !e.CatalogInfo().Scheduled {
		t.Fatal("Scheduled not reported")
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if e.CatalogInfo().Source == CatalogSourceRemote {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := e.CatalogInfo().Source; got != CatalogSourceRemote {
		t.Fatalf("scheduled refresh never landed (source=%s)", got)
	}
	mu.Lock()
	if hits == 0 {
		t.Error("server never hit")
	}
	mu.Unlock()
	e.Close() // must stop the loop without hanging
}

func TestCatalogSwapIsRaceSafe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(catalogJSON(t, bigCatalog("race-marker", "gen-race")))
	}))
	defer srv.Close()
	dir := t.TempDir()
	baked := writeBaked(t, dir, bigCatalog("old-marker", "gen-old"))
	e := newRefreshEngine(t, &Config{
		ConfigDir: dir, ToolsDir: filepath.Join(dir, "tools"), CatalogPath: baked,
		Refresh: &CatalogRefresh{URL: srv.URL},
	})

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
					_ = e.Search("marker")
					_ = e.CatalogInfo()
					_, _ = e.cat().Lookup("race-marker")
				}
			}
		})
	}
	for range 3 {
		if final := refreshAndWait(t, e); final.State != JobDone {
			t.Errorf("refresh: %s (%s)", final.State, final.Error)
		}
	}
	close(stop)
	wg.Wait()
}

// TestEngineClientPolicyComposition covers the production client's
// composed policy surface offline (the dial-time IP enforcement stays
// covered by the ssrf library's own suite): the URL-policy transport
// must admit the published-catalog URL shapes and refuse plaintext,
// non-443, and private targets before any dial, and the redirect
// policy must accept the GitHub release-download hop chain.
func TestEngineClientPolicyComposition(t *testing.T) {
	client := newEngineClient()
	tr, ok := client.Transport.(urlPolicyTransport)
	if !ok {
		t.Fatalf("transport is %T, want urlPolicyTransport", client.Transport)
	}
	cases := []struct {
		url  string
		want bool // admitted by the URL policy
	}{
		{"https://github.com/cplieger/tool-catalog/releases/latest/download/tool-catalog.json", true},
		{"https://release-assets.githubusercontent.com/github-production-release-asset/x", true},
		{"https://objects.githubusercontent.com/github-production-release-asset/x", true},
		{"http://github.com/cplieger/tool-catalog/releases/latest/download/tool-catalog.json", false},
		// Note: a non-443 port is enforced at DIAL time by
		// ssrf.SafeTransport(WithAllowedPorts(443)), not by the URL
		// policy; that layer is covered by the ssrf library's suite.
		{"https://127.0.0.1/tool-catalog.json", false},
		{"https://192.168.1.10/tool-catalog.json", false},
	}
	for _, tc := range cases {
		t.Run(tc.url, func(t *testing.T) {
			err := tr.policy.Validate(tc.url)
			if got := err == nil; got != tc.want {
				t.Errorf("Validate(%s) err=%v, want admitted=%v", tc.url, err, tc.want)
			}
		})
	}

	t.Run("redirect hop chain is validated and admitted", func(t *testing.T) {
		if client.CheckRedirect == nil {
			t.Fatal("no CheckRedirect installed")
		}
		first, _ := http.NewRequest(http.MethodGet,
			"https://github.com/cplieger/tool-catalog/releases/latest/download/tool-catalog.json", http.NoBody)
		hop, _ := http.NewRequest(http.MethodGet,
			"https://release-assets.githubusercontent.com/github-production-release-asset/abc", http.NoBody)
		if err := client.CheckRedirect(hop, []*http.Request{first}); err != nil {
			t.Errorf("public release-asset hop refused: %v", err)
		}
		bad, _ := http.NewRequest(http.MethodGet, "http://169.254.169.254/latest/meta-data", http.NoBody)
		if err := client.CheckRedirect(bad, []*http.Request{first}); err == nil {
			t.Error("metadata-endpoint hop admitted")
		}
	})
}

func TestParseRequireList(t *testing.T) {
	got := ParseRequireList("# heading\n\n  gopls  \ngh\n# trailing\n\nnode")
	want := []string{"gopls", "gh", "node"}
	if !slices.Equal(got, want) {
		t.Errorf("ParseRequireList = %v, want %v", got, want)
	}
	if ParseRequireList("# only comments\n\n") != nil {
		t.Error("comment-only list should parse to nil")
	}
}
