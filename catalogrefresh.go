package toolbelt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cplieger/atomicfile/v2"
	"github.com/cplieger/httpx/v3"
	"github.com/cplieger/scheduler/v3"
)

// CatalogRefresh configures the runtime catalog refresh: the engine
// periodically fetches a published compiled catalog, verifies it, and
// swaps it in atomically. The catalog is DATA on a daily upstream
// cadence; refreshing it at runtime decouples catalog freshness from
// consumer image rebuilds. The last good catalog always stands: a
// failed fetch, parse, overlay, or verify fails the refresh job and
// changes nothing.
type CatalogRefresh struct {
	// URL of the published compiled catalog (e.g. a GitHub release's
	// latest-download URL). Fetched with the engine's hardened HTTP
	// client: SSRF-validated on every hop, HTTPS on 443 only.
	URL string
	// Require lists tool names a fetched catalog must resolve (the
	// same offline checks as cmd/toolcatalog verify) before it
	// replaces the current one. The consumer's required set; empty
	// skips the name check (the structural floor still applies).
	Require []string
	// Interval between background refreshes. Positive starts the
	// engine-owned schedule (one refresh per interval, with jitter;
	// deliberately no fire-on-start — consumers trigger the boot
	// fetch via RefreshCatalog once their boot work is enqueued);
	// zero disables the schedule while keeping on-demand refresh
	// (RefreshCatalog / the httpapi route) available.
	Interval time.Duration
}

// DefaultCatalogURL is the published compiled catalog's stable
// latest-download URL (the cplieger/tool-catalog release artifact).
// The consumer contract lives here so every app defaults to the same
// publisher and a publisher move is a one-line change; apps expose an
// env override for forks and mirrors.
const DefaultCatalogURL = "https://github.com/cplieger/tool-catalog/releases/latest/download/tool-catalog.json"

// Canonical catalog refresh cadence policy, shared by every consumer.
// The published artifact moves at most a few times per day, so the
// default matches that cadence and the floor keeps an interval typo
// from hammering the publisher; the ceiling keeps a fat-fingered unit
// from silently freezing refreshes for months.
const (
	DefaultCatalogRefresh = 24 * time.Hour
	MinCatalogRefresh     = time.Hour
	MaxCatalogRefresh     = 30 * 24 * time.Hour
)

// ParseCatalogRefresh interprets a consumer's refresh env value into
// the CatalogRefresh.Interval duration under the canonical policy:
// empty or unparseable falls back to DefaultCatalogRefresh, positive
// durations clamp to [MinCatalogRefresh, MaxCatalogRefresh], and
// "off"/"disabled"/"0" return zero (schedule disabled; on-demand
// refresh stays available). name is the env variable named in
// fallback and clamp warnings.
func ParseCatalogRefresh(raw, name string) time.Duration {
	sched := scheduler.ParseInterval(raw, DefaultCatalogRefresh,
		scheduler.WithName(name),
		scheduler.WithBounds(MinCatalogRefresh, MaxCatalogRefresh))
	if sched.Mode != scheduler.ModeBuiltin {
		return 0
	}
	return sched.Interval
}

// Catalog sources reported by CatalogInfo.
const (
	CatalogSourceNone   = "none"   // no catalog available (degraded)
	CatalogSourceBaked  = "baked"  // Config.CatalogPath (image-baked)
	CatalogSourceCached = "cached" // last fetched copy, reloaded from ConfigDir
	CatalogSourceRemote = "remote" // fetched this process lifetime
)

// cachedCatalogName is the on-disk name of the last fetched catalog,
// engine-owned, under ConfigDir beside tools.json.
const cachedCatalogName = "tool-catalog.cached.json"

// maxCatalogBytes bounds a fetched catalog document. The compiled
// catalog runs ~1 MB; anything past this is a broken or hostile URL.
const maxCatalogBytes = 16 << 20

// catalogFetchBudget bounds one refresh fetch (all attempts included)
// so the shared job worker is never held hostage by a slow endpoint.
const catalogFetchBudget = 2 * time.Minute

// minCatalogEntries is the structural floor for a fetched catalog: a
// document with implausibly few entries (a truncated body, an error
// page that parsed as JSON, a gutted registry) must not replace a
// working catalog. Mirrors cmd/toolcatalog's compile-time invariant.
const minCatalogEntries = 400

// catalogState tracks refresh provenance for CatalogInfo, guarded by
// its own mutex (written by the job worker, read by any API caller).
type catalogState struct {
	fetchedAt time.Time
	source    string
	lastError string
	mu        sync.Mutex
}

func (s *catalogState) set(fn func(*catalogState)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s)
}

// initCatalog loads the boot catalog. Candidates: the image-baked file
// (tolerant load, lenient overlay application, no floor — boot must not
// brick) and, with Refresh configured, the cached copy of the last
// successful refresh (full acceptance pipeline). NEWEST WINS by the
// Generated stamp (RFC 3339 UTC strings compare chronologically), so a
// freshly upgraded image whose baked catalog is newer than a stale
// cache is not downgraded at boot. Cache corruption or a failed
// pipeline falls back to baked rather than failing the boot.
func (e *Engine) initCatalog(cfg *Config) {
	baked := loadCatalog(cfg.CatalogPath, e.log)
	chosen := baked
	if overlaid, err := e.overlaidCopy(baked); err == nil {
		chosen = overlaid
	} else {
		// Transactional degrade: the ORIGINAL baked catalog, never a
		// partially patched one.
		e.log.Error("toolbelt: catalog overlays not applied", "error", err)
	}
	source := CatalogSourceBaked
	if len(baked.Entries) == 0 {
		source = CatalogSourceNone
	}
	if cfg.Refresh != nil {
		if cached, err := loadCatalogFile(e.cachedCatalogPath()); err == nil {
			switch {
			case cached.Generated < baked.Generated:
				e.log.Info("toolbelt: baked catalog newer than refresh cache, using baked",
					"baked_generated", baked.Generated, "cached_generated", cached.Generated)
			default:
				if prepared, perr := e.prepareCatalog(cached); perr == nil {
					chosen, source = prepared, CatalogSourceCached
					e.log.Info("toolbelt: catalog loaded from refresh cache",
						"entries", len(prepared.Entries), "refs", prepared.Refs)
				} else {
					e.log.Warn("toolbelt: refresh cache unusable, falling back to baked catalog", "error", perr)
				}
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			e.log.Warn("toolbelt: refresh cache unreadable, falling back to baked catalog", "error", err)
		}
	}
	e.catalog.Store(chosen)
	e.catState.set(func(s *catalogState) { s.source = source })
}

// cachedCatalogPath is the engine-owned cache file for fetched catalogs.
func (e *Engine) cachedCatalogPath() string {
	return filepath.Join(e.configDir, cachedCatalogName)
}

// prepareCatalog runs the acceptance pipeline on a parsed catalog and
// returns the prepared result: the structural entry floor on the RAW
// document (before overlays, so consumer patches cannot mask a gutted
// publisher artifact), then the consumer overlays applied to a COPY (a
// failure leaves no partial mutation behind), then the consumer's
// required-name verification. c itself is never modified.
func (e *Engine) prepareCatalog(c *Catalog) (*Catalog, error) {
	if len(c.Entries) < minCatalogEntries {
		return nil, fmt.Errorf("catalog has %d entries (floor %d)", len(c.Entries), minCatalogEntries)
	}
	prepared, err := e.overlaidCopy(c)
	if err != nil {
		return nil, err
	}
	if e.refresh != nil {
		if errs := VerifyCatalog(prepared, e.refresh.Require); len(errs) > 0 {
			return nil, fmt.Errorf("required tools unresolved: %w", errors.Join(errs...))
		}
	}
	return prepared, nil
}

// overlaidCopy applies the consumer's overlay files, in order, to a
// copied catalog and returns the copy; the input is never mutated, so
// an overlay failure is transactional (callers keep the original).
// Runtime leniency for DISPLAY patches: a source-less patch naming a
// tool the catalog no longer has is SKIPPED with a warning instead of
// failing the load — a cosmetic description patch must never veto
// catalog freshness when an upstream entry disappears. Everything else
// stays strict: source-bearing entries replace/create wholesale, and
// aqua entries without embedded definitions still error (no registry
// checkout exists at runtime; resolveAqua is nil).
func (e *Engine) overlaidCopy(c *Catalog) (*Catalog, error) {
	cp := &Catalog{
		Refs:      c.Refs,
		Licenses:  c.Licenses,
		Generated: c.Generated,
		Entries:   maps.Clone(c.Entries),
	}
	for _, path := range e.catalogOverlays {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("overlay %s: %w", path, err)
		}
		var ov overlayDoc
		if err := json.Unmarshal(data, &ov); err != nil {
			return nil, fmt.Errorf("overlay %s: %w", path, err)
		}
		for name := range ov.Entries {
			patch := ov.Entries[name]
			if _, known := cp.Entries[name]; !known && patch.Source == "" {
				e.log.Warn("toolbelt: overlay patches unknown tool, skipping",
					"overlay", path, "tool", name)
				delete(ov.Entries, name)
			}
		}
		if err := applyOverlayDoc(cp, ov, nil); err != nil {
			return nil, fmt.Errorf("overlay %s: %w", path, err)
		}
	}
	cp.aliases = buildAliasIndex(cp.Entries)
	return cp, nil
}

// RefreshCatalog enqueues a catalog-refresh job: fetch the published
// catalog, verify it, persist it to the refresh cache, and swap it in.
// Returns ErrRefreshNotConfigured when Config.Refresh is nil. The
// returned job is observable like any other (jobs API, callbacks);
// Wait on it to gate on completion.
func (e *Engine) RefreshCatalog() (*Job, error) {
	if e.refresh == nil {
		return nil, ErrRefreshNotConfigured
	}
	return e.queue.Enqueue(JobKindCatalogRefresh, nil)
}

// ErrRefreshNotConfigured marks RefreshCatalog on an engine constructed
// without Config.Refresh.
var ErrRefreshNotConfigured = errors.New("catalog refresh not configured")

// CatalogInfo reports the live catalog's provenance and freshness: what
// is loaded (refs, generation timestamp, entry count), where it came
// from (baked file, refresh cache, live fetch), the last refresh error,
// and whether the background schedule is running.
func (e *Engine) CatalogInfo() CatalogInfo {
	c := e.cat()
	info := CatalogInfo{
		Refs:      maps.Clone(c.Refs),
		Generated: c.Generated,
		Entries:   len(c.Entries),
		Scheduled: e.refresh != nil && e.refresh.Interval > 0,
	}
	if e.refresh != nil {
		info.URL = e.refresh.URL
	}
	e.catState.set(func(s *catalogState) {
		info.Source = s.source
		info.LastError = s.lastError
		if !s.fetchedAt.IsZero() {
			info.FetchedAt = s.fetchedAt.UnixMilli()
		}
	})
	return info
}

// runCatalogRefresh executes one catalog-refresh job on the worker
// goroutine: fetch, parse, prepare (overlays + verify), persist the RAW
// fetched bytes to the refresh cache (the load pipeline re-applies
// overlays, so the cache stays a faithful copy of the published
// artifact), and swap the prepared catalog in. Any failure leaves the
// current catalog untouched and records the error for CatalogInfo.
func (e *Engine) runCatalogRefresh(ctx context.Context, output func(string)) (err error) {
	defer func() {
		e.catState.set(func(s *catalogState) {
			if err != nil {
				s.lastError = err.Error()
			} else {
				s.lastError = ""
			}
		})
	}()
	cfg := e.refresh
	output("fetching " + cfg.URL)
	// Own deadline, far under jobTimeout: the refresh runs on the SAME
	// single-flight worker as installs, so a slow-drip response must not
	// monopolize the queue. Two minutes is generous for a ~1 MB document.
	fetchCtx, cancel := context.WithTimeout(ctx, catalogFetchBudget)
	defer cancel()
	body, err := httpx.GetBytes(fetchCtx, e.client, cfg.URL,
		httpx.WithMaxAttempts(3), httpx.WithMaxBodyBytes(maxCatalogBytes))
	if err != nil {
		return fmt.Errorf("fetch catalog: %w", err)
	}
	fetched, err := parseCatalog(body)
	if err != nil {
		return fmt.Errorf("parse catalog: %w", err)
	}
	cur := e.cat()
	// Currency short-circuit compares CONTENT, not metadata: the fetched
	// bytes against the cache file. Byte equality proves both "nothing
	// changed upstream" and "the cache is intact", so a refresh after a
	// failed cache write cannot get stuck reporting current while the
	// cache stays stale, and a publisher bug that reuses a generation
	// stamp on different content still swaps. A missing or divergent
	// cache falls through to the full pipeline, which re-persists it.
	if cached, cerr := os.ReadFile(e.cachedCatalogPath()); cerr == nil && bytes.Equal(cached, body) {
		e.catState.set(func(s *catalogState) { s.fetchedAt = time.Now() })
		output(fmt.Sprintf("already current (generated %s, %d entries)", cur.Generated, len(cur.Entries)))
		return nil
	}
	prepared, err := e.prepareCatalog(fetched)
	if err != nil {
		return fmt.Errorf("reject fetched catalog (keeping current): %w", err)
	}
	if _, err := atomicfile.WriteFile(ctx, e.cachedCatalogPath(), body,
		atomicfile.WithMode(0o644), atomicfile.WithMkdirMode(0o755)); err != nil {
		// The prepared catalog is good; a cache-write failure only costs
		// restart persistence, and the next refresh repairs it (the
		// content short-circuit above misses on a divergent cache).
		// Swap anyway, but surface it.
		e.log.Warn("toolbelt: refresh cache not persisted", "error", err)
		output("warning: refresh cache not persisted: " + err.Error())
	}
	e.catalog.Store(prepared)
	e.catState.set(func(s *catalogState) {
		s.source = CatalogSourceRemote
		s.fetchedAt = time.Now()
	})
	output(fmt.Sprintf("catalog refreshed: %d entries, refs %v (was %d entries, refs %v)",
		len(prepared.Entries), prepared.Refs, len(cur.Entries), cur.Refs))
	e.log.Info("toolbelt: catalog refreshed",
		"entries", len(prepared.Entries), "refs", prepared.Refs, "generated", prepared.Generated)
	return nil
}

// startCatalogSchedule launches the engine-owned refresh loop when the
// config asks for one: one refresh per interval, with jitter. There is
// deliberately NO fire-on-start: the schedule starts inside New, and an
// immediate enqueue would land AHEAD of the consumer's boot-critical
// jobs on the single-flight queue (web-terminal-kiro gates session
// creation on its boot reconcile). Consumers trigger the boot fetch
// explicitly via RefreshCatalog once their boot work is enqueued. The
// loop only ENQUEUES; execution serializes with all other tool work on
// the job worker. Close stops the loop and waits for it.
func (e *Engine) startCatalogSchedule() {
	if e.refresh == nil || e.refresh.Interval <= 0 {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.stopRefresh = cancel
	e.refreshWG.Go(func() {
		scheduler.RunLoop(ctx, func(context.Context) {
			if _, err := e.RefreshCatalog(); err != nil {
				e.log.Warn("toolbelt: scheduled catalog refresh not enqueued", "error", err)
			}
		}, scheduler.LoopOptions{
			Interval: e.refresh.Interval,
			Jitter:   0.1,
		})
	})
}
