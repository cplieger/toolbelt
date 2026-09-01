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
// The manifest is intent, so a package installed outside it has no row and
// is invisible — right for MANAGED tools, wrong for "what is on this box".
// Discovery is therefore a THIRD read-only group beside Tools and System,
// and it never writes to the manifest: that would make intent
// indistinguishable from fact.
//
// Provenance is never guessed. An earlier design snapshotted the package set
// at boot to diff against later, needing a baseline file and a policy for a
// missing one — still only a guess. The manifest already answers exactly:
// a row means this engine owns the package, no row means it does not.

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
// base system" — the line between a package the IMAGE chose and one the OS
// came with. Neither exclusion alone suffices: apt's auto-installed record
// removes dependencies (measured, 438 of 536 packages here), and this
// removes the rest of the base system, debootstrap-marked manual.
//
// Priority, not a timestamp: apt state lives in the container layer and
// survives a restart while PID 1 does not, and BuildKit can normalise a
// binary's mtime to epoch — every timestamp anchor is wrong here, while
// priority is a fact about the package no build or restart moves.
//
// `standard` is deliberately excluded: in a slim image it is what a
// Dockerfile pulled in (ca-certificates, openssh-client, xz-utils, measured),
// so including it would hide installs the reader asked for.
var aptBasePriorities = map[string]bool{
	"required":  true,
	"important": true,
}

// aptDiscovery caches the installed-package list. INVALIDATED, not
// TTL'd: a package install/removal is the only thing that changes the
// answer, and this engine knows when it ran one — a TTL would either
// serve a stale list right after an install or re-enumerate for nothing.
type aptDiscovery struct {
	cached []AptPackage
	mu     sync.Mutex
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
		case status != aptStatusInstalled: // see aptStatusInstalled
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
