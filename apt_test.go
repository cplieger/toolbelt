package toolbelt

import (
	"log/slog"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestAptValidName covers the grammar gate. Every rejected case below is
// a real apt behaviour rather than a hypothetical: apt-get reads each of
// them as something other than "install this package", so a token that
// slips through here reaches apt with a meaning nobody intended.
func TestAptValidName(t *testing.T) {
	cases := []struct {
		name string
		ok   bool
		why  string
	}{
		{name: "gcc", ok: true},
		{name: "libc6-dev", ok: true},
		{name: "g++", ok: true, why: "a trailing + is part of a real package name"},
		{name: "python3.13", ok: true, why: "a dot is part of real package names"},
		{name: "docker.io", ok: true},
		{name: "libjq+1", ok: true, why: "legal name; the index oracle is what catches its expansion risk"},

		{name: "", ok: false},
		{name: "gcc-", ok: false, why: "apt-get reads a trailing - as REMOVE"},
		{name: "gcc=1.2", ok: false, why: "a version pin is not a name"},
		{name: "gcc:amd64", ok: false, why: "an architecture qualifier is not a name"},
		{name: "--reinstall", ok: false, why: "an option must never look like a name"},
		{name: "-y", ok: false},
		{name: "GCC", ok: false, why: "Debian names are lowercase"},
		{name: "../etc/passwd", ok: false},
		{name: "gcc libc6", ok: false, why: "one name per entry; a space would smuggle a second"},
		{name: "gcc/stable", ok: false, why: "a release qualifier is not a name"},
		{name: ".foo", ok: false, why: "must start alphanumeric"},
		{name: "gcc;rm -rf /", ok: false},
		{name: "gcc$(id)", ok: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := aptValidName(tc.name); got != tc.ok {
				t.Errorf("aptValidName(%q) = %v, want %v (%s)", tc.name, got, tc.ok, tc.why)
			}
		})
	}
}

// TestAptStatusFrom is the five-state dpkg table. The middle row is the
// defect this parser exists for: a package removed with its config files
// left behind still reports a version and exits 0, so a version-only
// read calls it installed. After a container recreate that mistake scales
// to every apt entry at once.
func TestAptStatusFrom(t *testing.T) {
	cases := []struct {
		state    string
		out      string
		wantVer  string
		wantInst bool
	}{
		{state: "installed", out: "installed 5.2.37-2+b9\n", wantVer: "5.2.37-2+b9", wantInst: true},
		{state: "removed-config-files", out: "config-files 8.4-1+deb13u1\n", wantInst: false},
		{state: "purged", out: "not-installed \n", wantInst: false},
		{state: "half-configured", out: "half-configured 1.0\n", wantInst: false},
		{state: "library-no-binary", out: "installed 2.41-12+deb13u3\n", wantVer: "2.41-12+deb13u3", wantInst: true},
		{state: "empty-output", out: "", wantInst: false},
	}
	for _, tc := range cases {
		t.Run(tc.state, func(t *testing.T) {
			gotVer, gotInst := aptStatusFrom(tc.out)
			if gotInst != tc.wantInst {
				t.Errorf("aptStatusFrom(%q) installed = %v, want %v", tc.out, gotInst, tc.wantInst)
			}
			if gotVer != tc.wantVer {
				t.Errorf("aptStatusFrom(%q) version = %q, want %q", tc.out, gotVer, tc.wantVer)
			}
		})
	}
}

// TestAptStatusFrom_AgreesWithRealDpkg checks the parser against the real
// tool rather than against remembered output, on a host that has it. The
// fixtures above were captured from this command; this is what notices if
// dpkg ever changes the format.
func TestAptStatusFrom_AgreesWithRealDpkg(t *testing.T) {
	if _, err := exec.LookPath("dpkg-query"); err != nil {
		t.Skip("dpkg-query is not on this host")
	}
	out, err := exec.Command("dpkg-query", "-W", "-f=${db:Status-Status} ${Version}", "--", "bash").Output()
	if err != nil {
		t.Skipf("bash is not a dpkg-managed package here: %v", err)
	}
	version, installed := aptStatusFrom(string(out))
	if !installed {
		t.Fatalf("real dpkg output %q parsed as not installed", out)
	}
	if version == "" {
		t.Errorf("real dpkg output %q parsed to an empty version", out)
	}
}

// TestAptCandidateFrom covers the version an apt row displays. "(none)"
// is apt's answer for a name it knows and cannot install, so recording
// it as a version would put a pinned entry on a package that can never
// resolve.
func TestAptCandidateFrom(t *testing.T) {
	const installable = `python3:
  Installed: (none)
  Candidate: 3.13.5-1
  Version table:
     3.13.5-1 500
`
	const virtual = `awk:
  Installed: (none)
  Candidate: (none)
  Version table:
`
	if got, err := aptCandidateFrom(installable); err != nil || got != "3.13.5-1" {
		t.Errorf("aptCandidateFrom(installable) = %q, %v; want 3.13.5-1, nil", got, err)
	}
	if _, err := aptCandidateFrom(virtual); err == nil {
		t.Error("a (none) candidate was accepted as a version")
	}
	if _, err := aptCandidateFrom("garbage\n"); err == nil {
		t.Error("output with no Candidate line was accepted")
	}
}

// TestAptArchivesLockBusy pins the one apt failure worth retrying.
// DPkg::Lock::Timeout waits on the frontend lock and fails immediately on
// the archives lock, so treating every lock failure alike would either
// retry things that will never succeed or give up on the one that would.
func TestAptArchivesLockBusy(t *testing.T) {
	busy := []string{
		"E: Could not get lock /var/cache/apt/archives/lock. It is held by process 123",
		"E: Unable to lock the download directory",
	}
	for _, out := range busy {
		if !aptArchivesLockBusy(out) {
			t.Errorf("aptArchivesLockBusy(%q) = false, want true", out)
		}
	}
	notBusy := []string{
		"E: Unable to locate package nosuchthing",
		"E: Could not get lock /var/lib/dpkg/lock-frontend",
		"",
	}
	for _, out := range notBusy {
		if aptArchivesLockBusy(out) {
			t.Errorf("aptArchivesLockBusy(%q) = true, want false", out)
		}
	}
}

// TestAptKnownName_UsesTheIndexAndFallsBackConservatively covers the gate
// that stops an unbounded install. A token containing an apt expansion
// character that matches no literal package is retried by apt as an
// UNANCHORED REGEX: measured on apt 3.0.3, `apt-get install -s -- 'jq.'`
// plans 1366 packages from 126 matched names, and apt has no flag to turn
// that off. So the rule is to hand apt nothing not already known to be a
// literal name.
func TestAptKnownName_UsesTheIndexAndFallsBackConservatively(t *testing.T) {
	idx := newAptIndex(slog.Default())
	idx.names = map[string]string{"gcc": "GNU C compiler", "docker.io": "Linux container runtime"}
	idx.fetched = time.Now()
	in := &installer{aptIdx: idx, output: func(string) {}, log: slog.Default()}

	if err := in.aptKnownName(t.Context(), "gcc"); err != nil {
		t.Errorf("a name in the index was refused: %v", err)
	}
	if err := in.aptKnownName(t.Context(), "docker.io"); err != nil {
		t.Errorf("an indexed name containing a dot was refused: %v", err)
	}
	if err := in.aptKnownName(t.Context(), "jq."); err == nil {
		t.Error("a name absent from the index was accepted, which is the unbounded-install path")
	}
	if err := in.aptKnownName(t.Context(), "gcc-"); err == nil {
		t.Error("a removal-shaped token reached the oracle")
	}

	// A nil index cannot load one, so it takes the fallback and must not
	// panic on the way.
	nilIdx := &installer{output: func(string) {}, log: slog.Default()}
	if err := nilIdx.aptKnownName(t.Context(), "jq."); err == nil {
		t.Error("a nil index accepted an expandable name")
	}
	if err := nilIdx.aptKnownName(t.Context(), "gcc"); err != nil {
		t.Errorf("a nil index refused an expansion-free name: %v", err)
	}
}

// TestAptFallbackAllows covers the check used when no index can be loaded
// at all. The direction is deliberate: refusing a real package until an
// index arrives costs a retry, while accepting an expandable name costs an
// unbounded root install, so the fallback errs toward refusal.
//
// It is tested as a predicate rather than through the oracle because the
// oracle tries to LOAD an index first, and on a Debian host it succeeds,
// so the branch is unreachable end to end. The alternative would be a
// production seam to disable loading, which is a worse trade than testing
// the decision directly.
func TestAptFallbackAllows(t *testing.T) {
	for _, ok := range []string{"gcc", "libc6-dev", "nosuchpackage", "make"} {
		if err := aptFallbackAllows(ok); err != nil {
			t.Errorf("aptFallbackAllows(%q) = %v, want nil", ok, err)
		}
	}
	for _, refused := range []string{"jq.", "python3.13", "docker.io", "libjq+1", "g++"} {
		if err := aptFallbackAllows(refused); err == nil {
			t.Errorf("aptFallbackAllows(%q) = nil; apt would expand it as a regex", refused)
		}
	}
}

// TestParseAptAvailable reads the stanza format apt-cache dumpavail
// emits. Only the name and the short description are kept: the full
// stanza set is ~200 MB of text and a search result needs neither the
// dependencies nor the long description.
func TestParseAptAvailable(t *testing.T) {
	const doc = `Package: gcc
Version: 4:14.2.0-1
Section: devel
Description: GNU C compiler
 This is the GNU C compiler, a fairly portable optimizing compiler.

Package: libc6-dev
Version: 2.41-12
Section: libdevel
Description: GNU C Library: Development Libraries

Package: python3
Section: python
Description-en: interactive high-level object-oriented language

Package: nodesc
Version: 1.0
`
	got := parseAptAvailable(strings.NewReader(doc))
	want := map[string]string{
		"gcc":       "GNU C compiler",
		"libc6-dev": "GNU C Library: Development Libraries",
		"python3":   "interactive high-level object-oriented language",
		"nodesc":    "",
	}
	if len(got) != len(want) {
		t.Fatalf("parsed %d packages, want %d: %v", len(got), len(want), got)
	}
	for name, desc := range want {
		if got[name] != desc {
			t.Errorf("%s description = %q, want %q", name, got[name], desc)
		}
	}
	// The continuation line of gcc's long description must not become a
	// package, which is what happens if the parser keys on ": " anywhere
	// rather than on a stanza field at the start of a line.
	for name := range got {
		if strings.HasPrefix(name, " ") || strings.Contains(name, " ") {
			t.Errorf("a continuation line became a package name: %q", name)
		}
	}
}

// TestRankAptNames_PutsTheShortestPrefixMatchFirst is the apt half of the
// ranking measurement. Ordering prefix matches by name alone put python3
// 909th of 6,607 hits for "python" behind 908 alphabetically-earlier
// python-* packages, which is what made an earlier design reach for a
// Section filter that dropped python3 entirely.
func TestRankAptNames_PutsTheShortestPrefixMatchFirst(t *testing.T) {
	names := map[string]string{
		"python3":         "interactive high-level object-oriented language",
		"python-acme-doc": "ACME protocol client (documentation)",
		"python-attrs":    "Attributes without boilerplate",
		"python3-pip":     "Python package installer",
		"ipython3":        "enhanced interactive Python shell",
		"unrelated":       "nothing to do with it",
	}
	got := rankAptNames(names, "python")
	if len(got) == 0 {
		t.Fatal("rankAptNames returned nothing")
	}
	if got[0].Name != "python3" {
		order := make([]string, 0, len(got))
		for i := range got {
			order = append(order, got[i].Name)
		}
		t.Errorf("first hit = %q, want python3 (order: %v)", got[0].Name, order)
	}
	for i := range got {
		if got[i].Name == "unrelated" {
			t.Error("a non-matching package was returned")
		}
	}
	if len(rankAptNames(names, "nothing to do")) == 0 {
		t.Error("a description-only match returned nothing")
	}
}

// TestAptIndexSearch_DistinguishesUnavailableFromEmpty covers the pair of
// answers that look identical and mean opposite things. Reporting "no
// results" for an index that was never loaded is the exact shape of the
// original catalog bug: the user reads it as "this tool does not exist".
func TestAptIndexSearch_DistinguishesUnavailableFromEmpty(t *testing.T) {
	empty := newAptIndex(slog.Default())
	if hits, ok := empty.Search("gcc"); ok || hits != nil {
		t.Errorf("an unloaded index reported ok=%v hits=%v, want false/nil", ok, hits)
	}
	loaded := newAptIndex(slog.Default())
	loaded.names = map[string]string{"gcc": "GNU C compiler"}
	if hits, ok := loaded.Search("nosuchthing"); !ok || len(hits) != 0 {
		t.Errorf("a loaded index with no matches reported ok=%v hits=%v, want true/empty", ok, hits)
	}
	// Below the minimum query length there is nothing to rank: one
	// character matches tens of thousands of the 68,799 names.
	if hits, _ := loaded.Search("g"); len(hits) != 0 {
		t.Errorf("a single-character query returned %d hits, want 0", len(hits))
	}
	var nilIdx *aptIndex
	if hits, ok := nilIdx.Search("gcc"); ok || hits != nil {
		t.Error("a nil index did not report unavailable")
	}
}

// TestSearchApt_ReportsUnavailableRatherThanEmpty covers the engine's own
// apt surface. The distinction is the whole point: an empty result and an
// unconsultable package list look identical to a client, and reporting the
// second as the first is what made a user searching for python conclude
// the tool did not exist.
func TestSearchApt_ReportsUnavailableRatherThanEmpty(t *testing.T) {
	dir := t.TempDir()
	e, err := New(&Config{ConfigDir: dir, ToolsDir: dir + "/tools", Logger: slog.Default()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)

	hits, ok := e.SearchApt("gcc")
	if !AptAvailable() {
		if ok || hits != nil {
			t.Errorf("SearchApt on a host without apt reported ok=%v hits=%v, want false/nil", ok, hits)
		}
		return
	}
	// On a host WITH apt the first call triggers a background refresh and
	// returns whatever is loaded, which on a cold engine is nothing. Both
	// answers are legitimate; what must never happen is ok=true with a nil
	// list, which would claim the corpus answered when it had not.
	if !ok && hits != nil {
		t.Errorf("SearchApt returned hits while reporting the corpus unavailable: %v", hits)
	}
}

// TestSearchApt_FillsTheCandidateForTheCappedSet pins where the version
// on an apt row comes from. It is resolved per result rather than in the
// index because it costs one apt-cache call each: eight is nothing,
// 68,799 would be absurd. Without it a client cannot show that the
// catalog offers one version of a tool and Debian another, which is the
// reason both blocks are shown at all.
func TestSearchApt_FillsTheCandidateForTheCappedSet(t *testing.T) {
	if !AptAvailable() {
		t.Skip("apt is not usable on this host")
	}
	dir := t.TempDir()
	e, err := New(&Config{ConfigDir: dir, ToolsDir: dir + "/tools", Logger: slog.Default()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	// Load synchronously rather than racing the background refresh.
	if err := e.aptIdx.ensure(t.Context()); err != nil {
		t.Skipf("no package index available here: %v", err)
	}
	hits, ok := e.SearchApt("bash")
	if !ok {
		t.Fatal("the package corpus reported unavailable after a successful load")
	}
	if len(hits) == 0 {
		t.Fatal("no hits for bash, which trixie certainly has")
	}
	if hits[0].Name != "bash" {
		t.Errorf("first hit = %q, want the exact match bash", hits[0].Name)
	}
	if hits[0].Candidate == "" {
		t.Errorf("bash carries no candidate version; a row would show nothing to compare against the catalog")
	}
}
