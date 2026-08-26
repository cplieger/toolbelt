package toolbelt

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"
)

// Discovery of apt packages this engine did not install.
//
// The inventory's Tools rows come from the manifest — intent — so a package
// somebody installed in the shell has no row and is invisible. That is the
// right shape for MANAGED tools and the wrong shape for answering "what is
// on this box", which is a question a consumer's tools table should not have
// to lie about.
//
// So discovery is a THIRD read-only group beside Tools and System, and it
// deliberately does not touch the manifest. Writing observations there would
// make intent indistinguishable from fact and hand the reconciler rows to
// converge that nobody asked for.
//
// Nothing here guesses at provenance, and that is what makes it cheap. An
// earlier design snapshotted the package set at first boot so a later diff
// could name what the user added; it needed a baseline file, a policy for a
// missing one, and it was still only a guess. The manifest already answers
// the same question exactly: a row means this engine owns the package, no row
// means somebody else does.

// aptExtendedStatesPath is apt's own record of which packages arrived as
// dependencies rather than being asked for.
//
// Read as a FILE rather than asked of apt. Measured on a Debian trixie
// container: `apt-mark showmanual` 498ms and `apt list --installed` 557ms,
// both dominated by loading apt's package cache, against 6ms for the whole
// dpkg dump below plus a 26 KB read for this. The inventory is a polled read
// path, so a half-second answer is not available to it.
const aptExtendedStatesPath = "/var/lib/apt/extended_states"

// aptDiscoverTimeout bounds the dpkg dump. It is a local database read with
// no network, so this is a wedge guard rather than a work budget.
const aptDiscoverTimeout = 20 * time.Second

// aptBasePriorities are the Debian priority levels that mean "part of the
// base system", which is the line between a package the IMAGE chose and a
// package the OS came with.
//
// Two exclusions do the work together, and neither is sufficient alone.
// apt's auto-installed record removes dependencies — measured, 438 of 536
// packages here — and this removes what is left of the base system, which is
// manually-marked because debootstrap marks it so. What survives is what a
// Dockerfile asked for and what a user or an agent installed later.
//
// Priority rather than a timestamp, and that was measured rather than
// preferred. Per-package install-record mtimes DO cluster by image layer, but
// every anchor for the boundary is wrong: apt state lives in the container
// layer, so it survives a restart while PID 1 does not, and packages
// installed during an earlier run of the same container predate the current
// process — a container-start anchor hides exactly the runtime installs this
// exists to surface. BuildKit can also normalise a binary's mtime to epoch,
// which would make an executable-mtime anchor show everything. A priority is
// a fact about the package that no build or restart moves.
//
// `standard` is deliberately NOT here. Debian calls it part of a normal
// install, but in a slim image it is what a Dockerfile pulled in
// (ca-certificates, openssh-client and xz-utils on the measured image, all
// three named in that Dockerfile's own apt line), so excluding it would hide
// installs the reader asked for.
var aptBasePriorities = map[string]bool{
	"required":  true,
	"important": true,
}

// aptDiscovery caches the installed-package list.
//
// Cached because the enumeration parses 536 rows and a 26 KB file, which is
// work the UI's poll should not repeat, and INVALIDATED rather than timed
// out: the only thing that changes the answer is a package install or
// removal, and this engine knows when it ran one. A TTL would either serve a
// stale list right after an install — the one moment a reader is looking —
// or re-enumerate for nothing the rest of the time.
type aptDiscovery struct {
	mu     sync.Mutex
	cached []AptPackage
	loaded bool
}

// Invalidate drops the cached list. Called after any apt job, so the next
// read re-enumerates.
func (d *aptDiscovery) Invalidate() {
	d.mu.Lock()
	d.loaded = false
	d.cached = nil
	d.mu.Unlock()
}

// List returns the installed apt packages nobody in this engine installed:
// what the image asked for and what a user or an agent added later, with
// dependencies and the base system excluded.
//
// Nil when apt is not this host's package manager or the enumeration fails —
// an inventory that cannot answer says nothing rather than reporting an empty
// box as a fact.
func (d *aptDiscovery) List(ctx context.Context) []AptPackage {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.loaded {
		return d.cached
	}
	if !AptAvailable() {
		d.loaded = true
		return nil
	}
	pkgs, err := aptInstalledPackages(ctx)
	if err != nil {
		// Not cached as an answer: a transient failure must not pin an
		// empty list until the next install.
		return nil
	}
	d.cached, d.loaded = pkgs, true
	return d.cached
}

// aptInstalledPackages enumerates the installed packages worth showing.
func aptInstalledPackages(ctx context.Context) ([]AptPackage, error) {
	ctx, cancel := context.WithTimeout(ctx, aptDiscoverTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "dpkg-query", "-W",
		"-f=${binary:Package}\t${Version}\t${db:Status-Status}\t${Priority}\t${Essential}\n").Output()
	if err != nil {
		return nil, err
	}
	// A missing or unreadable states file means no package reads as a
	// dependency. That is the honest degradation: apt's own default for a
	// package it has no record of is manual, and showing too much is
	// recoverable by reading the list while showing nothing is not.
	return parseDpkgPackages(out, aptAutoInstalled(aptExtendedStatesPath)), nil
}

// parseDpkgPackages turns the dpkg dump into the discovered set.
//
// Tab-separated because a Version can contain a space in no field dpkg emits
// here, but a Priority can be empty — and with spaces an empty field makes
// the columns after it shift, which would read a priority as a status.
func parseDpkgPackages(dump []byte, auto map[string]bool) []AptPackage {
	var pkgs []AptPackage
	sc := bufio.NewScanner(bytes.NewReader(dump))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) != 5 {
			continue
		}
		name, version, status, priority, essential := f[0], f[1], f[2], f[3], f[4]
		// An architecture-qualified name (`libfoo:i386`) is one package to
		// apt; the bare name is what a caller would type.
		if bare, _, found := strings.Cut(name, ":"); found {
			name = bare
		}
		switch {
		case name == "":
		// `installed` is the only status meaning the files are present:
		// config-files, half-configured and deinstall all report a version.
		case status != aptStatusInstalled:
		case auto[name]:
		case essential == "yes", aptBasePriorities[priority]:
		default:
			pkgs = append(pkgs, AptPackage{Name: name, Version: version})
		}
	}
	slices.SortFunc(pkgs, func(a, b AptPackage) int { return strings.Compare(a.Name, b.Name) })
	return slices.CompactFunc(pkgs, func(a, b AptPackage) bool { return a.Name == b.Name })
}

// aptAutoInstalled reads apt's extended-states file into the set of package
// names that arrived as dependencies. An unreadable file yields an empty set,
// which shows more rather than fewer (see aptInstalledPackages).
func aptAutoInstalled(path string) map[string]bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	auto := map[string]bool{}
	var pkg string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "":
			// A stanza ended without saying Auto-Installed: 1.
			pkg = ""
		case strings.HasPrefix(line, "Package:"):
			pkg = strings.TrimSpace(strings.TrimPrefix(line, "Package:"))
		case line == "Auto-Installed: 1" && pkg != "":
			auto[pkg] = true
		}
	}
	return auto
}
