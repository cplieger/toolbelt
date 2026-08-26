package toolbelt

import (
	"bufio"
	"cmp"
	"context"
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
// It is apt's OWN index rather than a shipped artifact. Measured on
// Debian trixie: a cold `apt-get update` costs 1.2s and 20.5 MB on
// disk, `apt-cache dumpavail` yields 68,799 packages, and names plus
// descriptions parse to 4.6 MB in memory. Against that, a baked list
// would need a build step, a refresh pipeline and a staleness story to
// end up with the same data apt already maintains.
//
// Querying through `apt-cache search` per keystroke was measured at
// 0.48-0.53s, far too slow for type-ahead, so the list is parsed once
// and searched in memory.
//
// The refresh is LAZY: nothing fetches until something actually asks for
// apt results. One consumer has a human searching and earns the cost
// immediately; the other is headless and may never search at all, so
// paying 20.5 MB and a network round trip at every boot for it would be
// waste. The install path is unaffected either way, because apt-get runs
// its own update.
//
// There is deliberately NO Section-based filtering. An earlier design
// filtered to "tool-shaped" sections and it dropped python3,
// python3-pip and python3-venv, which are all Section: python, along
// with libc6-dev (libdevel) and most of the database, php, ruby, java
// and rust packages. Ranking plus a result cap is what keeps the list
// usable; see rankAptNames.
type aptIndex struct {
	log *slog.Logger

	mu      sync.RWMutex
	names   map[string]string // package name -> short description
	fetched time.Time
	err     error
	loading bool

	// updateOnce guards the one `apt-get update` this process runs. Both
	// the search corpus and the install path need an index on disk, and
	// both images ship without one.
	updateOnce sync.Once
	updateErr  error
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

// ensureLists runs `apt-get update` at most once per process, and only
// when no index is on disk.
//
// This is required rather than an optimisation: BOTH consumer images
// delete /var/lib/apt/lists at build time to keep the image small, and
// `apt-get install` does NOT refresh the index itself, so the first
// install in a fresh container fails with "Unable to locate package" for
// a package that plainly exists. The search corpus needs the same
// indexes, so one mechanism serves both and neither pays for the other.
//
// It deliberately does not re-run on a stale index. An index Debian has
// moved past yields a version apt cannot fetch, which surfaces as a
// clear install failure; re-updating on every install would put a network
// round trip in front of every converge instead.
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

// rankAptNames scores the package corpus with the same tiers the catalog
// uses (exact, prefix, substring, description) and the same
// length-before-name tie-break.
//
// The tie-break is what makes this corpus usable at all: every prefix
// match scores alike, so ordering by name alone put python3 909th of
// 6,607 hits for "python" behind 908 alphabetically-earlier python-*
// packages, and nodejs 1,701st for "node". See rankEntries for the
// measurement.
func rankAptNames(names map[string]string, q string) []AptHit {
	type scored struct {
		hit   AptHit
		score int
	}
	var hits []scored
	for name, desc := range names {
		score := aptMatchScore(name, desc, q)
		if score == 0 {
			continue
		}
		hits = append(hits, scored{AptHit{Name: name, Description: desc}, score})
	}
	slices.SortStableFunc(hits, func(a, b scored) int {
		return cmp.Or(
			cmp.Compare(b.score, a.score),
			cmp.Compare(len(a.hit.Name), len(b.hit.Name)),
			cmp.Compare(a.hit.Name, b.hit.Name),
		)
	})
	lim := min(len(hits), aptSearchLimit)
	out := make([]AptHit, 0, lim)
	for i := range hits[:lim] {
		out = append(out, hits[i].hit)
	}
	return out
}

func aptMatchScore(name, desc, q string) int {
	ln := strings.ToLower(name)
	switch {
	case ln == q:
		return 100
	case strings.HasPrefix(ln, q):
		return 80
	case strings.Contains(ln, q):
		return 50
	case strings.Contains(strings.ToLower(desc), q):
		return 20
	}
	return 0
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
// ensuring the index first.
//
// This is the gate that stops an unbounded install, and it must run
// BEFORE anything else asks apt about the name. A token containing an
// expansion character that matches no literal package is retried by apt
// as an UNANCHORED REGEX: measured on apt 3.0.3, `apt-get install -s --
// 'jq.'` plans 1366 packages from 126 matched names, and apt has no flag
// to disable the fallback.
//
// `apt-cache policy` expands the same way, which is the subtle half:
// asked about `jq.` it answers with a version belonging to whichever
// package the pattern matched, so a resolver that runs first would record
// a version from a package the user never named. Measured live, that
// produced a `jq.` entry pinned at jq's own 2.1.2-3.
//
// The oracle is the parsed index, so this costs a map lookup. When no
// index can be loaded the fallback refuses any name containing an
// expansion character, which yields false NEGATIVES only: a real
// docker.io waits for an index and self-heals, while a plain typo needs
// no filter because apt matches it literally, finds nothing, and says so.
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

// aptFallbackAllows is the name check used when no package index can be
// loaded at all.
//
// It refuses any name containing an apt expansion character and admits
// everything else, which yields false NEGATIVES only. A real docker.io
// waits for an index and self-heals on the next attempt; a plain typo
// needs no filter here because apt matches it literally, finds nothing,
// and reports that itself.
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
		// A failed update is not fatal to the parse: an index from a
		// previous run may still be on disk, and a partial index yields
		// false NEGATIVES only (a real package waits for the next refresh),
		// never a false positive, because its names come from real
		// repository metadata.
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
		return nil, fmt.Errorf("apt-cache dumpavail produced no packages")
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
