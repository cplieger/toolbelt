package toolbelt

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"
)

// aptIndex is the searchable Debian package list, and it is also the
// name oracle the install gate consults (see installer.aptKnownName).
//
// Built from apt's OWN index (apt-cache dumpavail, 68,799 packages on
// Debian trixie, 4.6 MB parsed) rather than a shipped artifact, since a
// baked list would still need a build+refresh+staleness story to match
// what apt already maintains. Per-keystroke apt-cache search measured
// 0.48-0.53s, so the list is parsed once and searched in memory instead.
//
// The refresh is LAZY: nothing fetches until something asks for apt
// results, since the headless consumer may never search at all. The
// install path is unaffected — apt-get runs its own update regardless.
//
// Deliberately NO Section-based filtering: an earlier design filtering to
// "tool-shaped" sections dropped python3 and libc6-dev along with most of
// the database/php/ruby/java/rust packages. Ranking plus a result cap
// keeps the list usable instead; see rankAptNames.
type aptIndex struct {
	log   *slog.Logger
	names map[string]string // package name -> short description
	err   error
	// updateErr is the outcome of the one refresh updateOnce guards.
	updateErr error

	fetched time.Time
	mu      sync.RWMutex
	// updateOnce guards the one `apt-get update` this process runs. Both
	// the search corpus and the install path need an index on disk, and
	// both images ship without one.
	updateOnce sync.Once
	loading    bool
}

// aptIndexTTL is how long a parsed index is considered current. It
// matches the catalog's own default refresh cadence: both answer "what
// can I install today", and a package list a day old is the same
// staleness a user already accepts from the catalog.
const aptIndexTTL = 24 * time.Hour

// aptUpdateBudget bounds the index refresh. A cold update measured 1.2s
// on a healthy mirror; the budget is generous because a slow mirror
// should delay a search result, not fail it.
const aptUpdateBudget = 3 * time.Minute

// aptListsDir is where apt stores the package indexes it downloads.
const aptListsDir = "/var/lib/apt/lists"

// ensureLists runs `apt-get update` at most once per process, only when
// no index is on disk. Required, not an optimisation: both consumer
// images delete /var/lib/apt/lists at build time, and `apt-get install`
// does not refresh it itself, so the first install in a fresh container
// would fail "Unable to locate package" for one that plainly exists.
// Does not re-run on a merely stale index — that fails as a clear
// install error instead of costing a network round trip per converge.
func (a *aptIndex) ensureLists(ctx context.Context) error {
	if a == nil {
		return nil
	}
	a.updateOnce.Do(func() {
		if entries, err := os.ReadDir(aptListsDir); err == nil && len(entries) > 0 {
			for _, e := range entries {
				// The directory survives with only its `partial`/`auxfiles`
				// subdirectories after a cleanup, which is not an index.
				if !e.IsDir() {
					return
				}
			}
		}
		uctx, cancel := context.WithTimeout(ctx, aptUpdateBudget)
		defer cancel()
		out, err := exec.CommandContext(uctx, "apt-get", "-qq", "update").CombinedOutput()
		if err != nil {
			a.updateErr = fmt.Errorf("apt-get update: %w: %s", err, strings.TrimSpace(string(out)))
			return
		}
	})
	return a.updateErr
}

func newAptIndex(log *slog.Logger) *aptIndex {
	if log == nil {
		log = slog.Default()
	}
	return &aptIndex{log: log}
}

// ready reports whether a parsed index is available to consult. The
// install gate reads this to decide whether it can verify a name at all
// (see installer.aptKnownName).
func (a *aptIndex) ready() bool {
	if a == nil {
		return false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.names) > 0
}

// has reports whether pkg is a literal package name in the index.
func (a *aptIndex) has(pkg string) bool {
	if a == nil {
		return false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	_, ok := a.names[pkg]
	return ok
}

// stale reports whether the index needs a refresh: never loaded, or
// older than the TTL.
func (a *aptIndex) stale() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.names) == 0 || time.Since(a.fetched) > aptIndexTTL
}

// Search ranks the package list against a query.
//
// It returns (nil, false) when no index is available, which a consumer
// must render as "apt search is unavailable" rather than as an empty
// result: those two answers look identical and mean opposite things, and
// conflating them is how the original catalog bug hid for as long as it
// did.
//
// A query shorter than aptMinQuery returns nothing. With 68,799 names, a
// single character matches tens of thousands of them and every one of
// those results is noise.
func (a *aptIndex) Search(query string) ([]AptHit, bool) {
	q := strings.ToLower(strings.TrimSpace(query))
	if a == nil || len(q) < aptMinQuery {
		return nil, a != nil && a.ready()
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if len(a.names) == 0 {
		return nil, false
	}
	return rankAptNames(a.names, q), true
}

// aptMinQuery is the shortest query the package corpus answers.
const aptMinQuery = 2

// aptSearchLimit caps the apt result block. It is capped independently
// of the catalog's own limit so one corpus cannot crowd the other out of
// a merged response.
const aptSearchLimit = 8

// AptHit is one package-list search result.
type AptHit struct {
	Name        string
	Description string
	// Candidate is the version apt would install, filled in by the
	// engine for the hits it returns rather than by the index (it costs
	// one apt-cache invocation per package, so it is resolved for the
	// capped result set only).
	Candidate string
}

// rankAptNames scores the package corpus with [Match] and orders it with
// [CompareRank] — the catalog's own scoring, which is what lets a
// consumer merge the two corpora into one relevance-ordered list. A
// package has no aliases, which is the only difference between the two
// corpora and the reason this once carried a near-copy of the tier table.
func rankAptNames(names map[string]string, q string) []AptHit {
	type scored struct {
		hit   AptHit
		score int
	}
	var hits []scored
	for name, desc := range names {
		_, score := Match(name, nil, desc, q)
		if score == 0 {
			continue
		}
		hits = append(hits, scored{AptHit{Name: name, Description: desc}, score})
	}
	slices.SortStableFunc(hits, func(a, b scored) int {
		return CompareRank(
			Rank{Name: a.hit.Name, Score: a.score},
			Rank{Name: b.hit.Name, Score: b.score},
		)
	})
	lim := min(len(hits), aptSearchLimit)
	out := make([]AptHit, 0, lim)
	for i := range hits[:lim] {
		out = append(out, hits[i].hit)
	}
	return out
}

// ensure makes the index usable as an oracle, synchronously: the lists
// on disk, and the names parsed into memory.
//
// The install path calls this rather than the lazy refresh, because its
// correctness depends on the answer. Without a parsed index,
// installer.aptKnownName falls back to refusing any name containing an
// apt expansion character, so a legitimate `docker.io` or `g++` would be
// rejected until somebody happened to run a search first. The parse costs
// one pass over ~68,800 stanzas and is well under a second.
func (a *aptIndex) ensure(ctx context.Context) error {
	if a == nil {
		return nil
	}
	if err := a.ensureLists(ctx); err != nil {
		return err
	}
	if a.ready() {
		return nil
	}
	names, err := a.load(ctx)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.names = names
	a.fetched = time.Now()
	a.log.Info("toolbelt: apt package index loaded", "packages", len(names))
	return nil
}

// knownName reports whether pkg is a literal package name apt knows,
// ensuring the index first. Must run BEFORE anything else asks apt about
// the name: a token matching no literal package is retried by apt as an
// UNANCHORED REGEX (measured, apt 3.0.3: `apt-get install -s -- 'jq.'`
// plans 1366 packages from 126 matched names, no flag disables it).
// `apt-cache policy` expands the same way — asked about `jq.` it answers
// with whichever matched package's version, which measured live pinned a
// `jq.` entry at jq's own 2.1.2-3 — so a version resolver needs this gate
// too. When no index can be loaded, the fallback refuses any name
// containing an expansion character: false NEGATIVES only.
func (a *aptIndex) knownName(ctx context.Context, pkg string) error {
	if !aptValidName(pkg) {
		return fmt.Errorf("invalid package name %q", pkg)
	}
	if a != nil {
		if err := a.ensure(ctx); err != nil {
			a.log.Warn("toolbelt: apt package index unavailable, falling back to the conservative name check", "error", err)
		}
	}
	if a == nil || !a.ready() {
		return aptFallbackAllows(pkg)
	}
	if !a.has(pkg) {
		return fmt.Errorf("%q is not a package in the index", pkg)
	}
	return nil
}

// aptFallbackAllows is the fallback knownName uses when no index can be
// loaded: refuses a name containing an apt expansion character, admits
// everything else.
func aptFallbackAllows(pkg string) error {
	if strings.ContainsAny(pkg, aptExpansionChars) {
		return fmt.Errorf("cannot verify %q against the package index, and the name contains one of %q which apt would expand as a regex", pkg, aptExpansionChars)
	}
	return nil
}

// refresh updates the package index, at most one refresh at a time.
//
// A caller never waits on another caller's refresh: a second concurrent
// search gets the index as it stands (possibly empty, which Search
// reports as unavailable) rather than blocking a request on a network
// operation. This is a search surface, so a late-but-complete answer is
// worth less than a prompt honest one.
func (a *aptIndex) refresh(ctx context.Context) {
	if a == nil || !AptAvailable() {
		return
	}
	a.mu.Lock()
	if a.loading {
		a.mu.Unlock()
		return
	}
	a.loading = true
	a.mu.Unlock()

	names, err := a.load(ctx)

	a.mu.Lock()
	defer a.mu.Unlock()
	a.loading = false
	a.err = err
	if err != nil {
		// Keep whatever list is already parsed. A failed refresh degrades
		// to a stale list, never to no list, which is the same
		// keep-last-good posture the catalog refresh takes.
		a.log.Warn("toolbelt: apt package index refresh failed", "error", err)
		return
	}
	a.names = names
	a.fetched = time.Now()
	a.log.Info("toolbelt: apt package index loaded", "packages", len(names))
}

// load runs apt-get update and parses the available-package list.
func (a *aptIndex) load(ctx context.Context) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, aptUpdateBudget)
	defer cancel()
	if err := a.ensureLists(ctx); err != nil {
		// Not fatal to the parse: an index from a previous run may still
		// be on disk, and a stale one yields false negatives only.
		a.log.Warn("toolbelt: apt-get update failed, parsing whatever index is on disk", "error", err)
	}
	cmd := exec.CommandContext(ctx, "apt-cache", "dumpavail")
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	names := parseAptAvailable(pipe)
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("apt-cache dumpavail: %w", err)
	}
	if len(names) == 0 {
		return nil, errors.New("apt-cache dumpavail produced no packages")
	}
	return names, nil
}

// parseAptAvailable reads RFC822-ish package stanzas and returns
// name -> short description.
//
// It deliberately keeps only those two fields. The full stanza set is
// ~200 MB of text; names and short descriptions are 4.6 MB, which is
// everything a search result needs.
func parseAptAvailable(r io.Reader) map[string]string {
	names := make(map[string]string, 70000)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var pkg string
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			pkg = ""
		case strings.HasPrefix(line, "Package: "):
			pkg = strings.TrimSpace(line[len("Package: "):])
			if _, seen := names[pkg]; !seen {
				names[pkg] = ""
			}
		case pkg != "" && strings.HasPrefix(line, "Description: "):
			if names[pkg] == "" {
				names[pkg] = strings.TrimSpace(line[len("Description: "):])
			}
		case pkg != "" && strings.HasPrefix(line, "Description-en: "):
			if names[pkg] == "" {
				names[pkg] = strings.TrimSpace(line[len("Description-en: "):])
			}
		}
	}
	return names
}
