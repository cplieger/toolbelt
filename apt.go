package toolbelt

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// The apt source installs Debian packages, and it is the one source
// whose artifacts do NOT live on the persistent volume: apt writes into
// /usr, which is the container layer, so an apt entry dies with the
// container and is re-applied by the boot converge. Three consequences
// shape everything below.
//
// Detection cannot execute a binary. A package such as libc6-dev ships
// none, and after `apt-get remove` a config-files-only package still
// reports a version, so the dpkg STATUS word is the only honest probe
// (aptInstalled).
//
// Uninstall is a no-op. Removing an entry stops it being reinstalled; it
// does not remove the package now, because the entry was never a record
// of something on disk in the first place.
//
// Nothing here is reachable on a host that is not Debian-derived or not
// root, and the engine reports that as a capability rather than
// discovering it as a failure (AptAvailable).

// aptNamePattern is the anchored package-name grammar. It is the first
// of two gates and it exists to stop anything that is not shaped like a
// package name from reaching apt-get: an option, a `pkg=version` pin, a
// `pkg:arch` qualifier, or a path.
//
// A trailing '-' is rejected separately (see aptValidName) because
// apt-get reads `pkg-` as a REMOVE request, so a grammar-valid token
// ending in '-' would smuggle a removal through an install-only path.
var aptNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`)

// aptExpansionChars are the characters apt treats as regex operators
// when a token matches no literal package name. They decide the
// fallback in aptKnownName when the name oracle is unavailable.
//
// Both matter and one is easy to miss: '.' is any-character, and '+' is
// one-or-more, so `libjq+1` resolves to `libjq1` just as `jq.` resolves
// to a hundred-odd names. A grammar that admits real names (python3.13,
// docker.io, g++) cannot exclude either character, which is why the
// oracle rather than the grammar is what makes this safe.
const aptExpansionChars = ".+"

// ErrAptUnavailable marks an apt operation attempted where apt cannot
// work: a non-Debian host, or a process that is not root.
var ErrAptUnavailable = errors.New("apt is not available (needs a Debian-derived host and root)")

// aptValidName reports whether s is shaped like a Debian package name
// and cannot be read by apt-get as anything other than a name.
func aptValidName(s string) bool {
	if !aptNamePattern.MatchString(s) {
		return false
	}
	// apt-get reads a trailing '-' as "remove this". No Debian package
	// name ends in '-'; a trailing '+' stays legal, because g++ exists.
	return !strings.HasSuffix(s, "-")
}

// aptSetHold marks an apt package held (or releases the hold), which is
// what makes a pinned row survive apt's own dependency resolution: a held
// package is one apt refuses to upgrade or remove as a side effect of some
// other install.
//
// dpkg's own marking, not a preferences file. A pin is per-package state
// with exactly this meaning, and /etc/apt/preferences.d would put this
// engine's opinion in a file an operator also edits by hand.
func (in *installer) aptSetHold(ctx context.Context, pkg string, hold bool) error {
	// The name goes to apt-mark as an argv element, so no shell parses it,
	// but the grammar gate still runs: a name this engine would refuse to
	// install is a name it must not mark either.
	if !aptValidName(pkg) {
		return fmt.Errorf("refusing to hold %q: not a valid package name", pkg)
	}
	action := "unhold"
	if hold {
		action = "hold"
	}
	ctx, cancel := context.WithTimeout(ctx, aptHoldTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "apt-mark", action, "--", pkg)
	cmd.Env = aptEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("apt-mark %s %s: %w: %s", action, pkg, err, strings.TrimSpace(string(out)))
	}
	in.logf("apt-mark %s %s", action, pkg)
	return nil
}

// aptStatusInstalled is the one ${db:Status-Status} value meaning the
// package's files are on disk. config-files, half-configured and deinstall
// all report a version too, which is why the status word is read rather
// than the version's presence.
const aptStatusInstalled = "installed"

// aptHoldTimeout bounds an apt-mark call. It writes one dpkg selection and
// touches no network, so this is a wedge guard rather than a work budget.
const aptHoldTimeout = 30 * time.Second

// AptAvailable reports whether this process can install apt packages:
// euid 0 and apt-get on PATH. Consumers surface it rather than offering
// an install that always fails, and the engine's own converge skips apt
// entries when it is false.
//
// Root is required because apt writes to /usr and the dpkg database.
// There is no sudo path here by design: the two consumers of this
// library run as root deliberately, and a library that shells out to
// sudo would be inventing a privilege escalation its caller did not ask
// for.
func AptAvailable() bool {
	if os.Geteuid() != 0 {
		return false
	}
	_, err := exec.LookPath("apt-get")
	return err == nil
}

// aptInstalled reports whether a package is installed AND its version.
//
// The status word is load-bearing. `dpkg-query -W -f='${Version}'`
// alone reports a version for a package that has been REMOVED with its
// config files left behind: measured on apt 3.0.3, after
// `apt-get remove nano`, that query prints 8.4-1+deb13u1 and exits 0
// with no binary on disk. Only ${db:Status-Status} == "installed"
// distinguishes the two, and a non-zero exit means dpkg has never heard
// of the package at all.
func (in *installer) aptInstalled(ctx context.Context, pkg string) (version string, installed bool) {
	cmd := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${db:Status-Status} ${Version}", "--", pkg)
	out, err := cmd.Output()
	if err != nil {
		// dpkg exits non-zero for a package it has no record of at all,
		// which is absence rather than an error worth reporting.
		return "", false
	}
	return aptStatusFrom(string(out))
}

// aptStatusFrom reads one `dpkg-query -W -f='${db:Status-Status}
// ${Version}'` answer.
//
// The status word is the whole point. dpkg keeps a record for a package
// that has been REMOVED with its configuration files left in place, and
// that record still carries a version: measured on apt 3.0.3, after
// `apt-get remove nano`, the same query prints `config-files 8.4-1+deb13u1`
// and exits 0 with no binary on disk. A version-only read therefore
// reports a removed package as installed, and after a container recreate
// it would report every apt entry as present while nothing is.
func aptStatusFrom(out string) (version string, installed bool) {
	status, version, ok := strings.Cut(strings.TrimSpace(out), " ")
	if !ok || status != aptStatusInstalled {
		return "", false
	}
	return strings.TrimSpace(version), true
}

// aptCandidate reports the version apt would install now: the
// Candidate line of `apt-cache policy`. It is what an apt row displays
// and what decides whether an update is available, because an apt entry
// has no upstream version of its own to resolve.
func (in *installer) aptCandidate(ctx context.Context, pkg string) (string, error) {
	if err := in.aptKnownName(ctx, pkg); err != nil {
		return "", err
	}
	out, err := exec.CommandContext(ctx, "apt-cache", "policy", "--", pkg).Output()
	if err != nil {
		return "", fmt.Errorf("apt-cache policy %s: %w", pkg, err)
	}
	cand, err := aptCandidateFrom(string(out))
	if err != nil {
		return "", fmt.Errorf("%s: %w", pkg, err)
	}
	return cand, nil
}

// aptCandidateFrom extracts the Candidate version from apt-cache policy
// output. Shared by the installer and the version resolver so the two
// cannot disagree about what "the version apt would install" means.
//
// "(none)" is apt's answer for a package it knows of but cannot install
// (a pure virtual name, or one with no candidate in the configured
// sources), and it must not be recorded as a version.
func aptCandidateFrom(policy string) (string, error) {
	sc := bufio.NewScanner(strings.NewReader(policy))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		v, ok := strings.CutPrefix(line, "Candidate:")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if v == "" || v == "(none)" {
			return "", errors.New("no installation candidate")
		}
		return v, nil
	}
	return "", errors.New("no Candidate line in apt-cache policy output")
}

// aptKnownName delegates to the shared oracle (see aptIndex.knownName),
// which both the installer and the version resolver consult so neither
// can ask apt about a name the other would have refused.
func (in *installer) aptKnownName(ctx context.Context, pkg string) error {
	return in.aptIdx.knownName(ctx, pkg)
}

// aptGetArgs are the options every apt-get invocation carries.
//
// DPkg::Lock::Timeout is what makes a collision with an apt run in the
// user's own shell a wait rather than a failure. It does NOT cover every
// lock: measured with record locks, it waits on the frontend lock and
// fails immediately on /var/cache/apt/archives/lock, which is why
// installApt retries that specific failure.
func aptGetArgs(extra ...string) []string {
	args := []string{
		"-o", "DPkg::Lock::Timeout=60",
		"-y",
		"--no-install-recommends",
	}
	return append(args, extra...)
}

// aptArchivesLockRetries bounds the retry for the one lock the timeout
// option does not cover.
const (
	aptArchivesLockRetries = 3
	aptArchivesLockBackoff = 3 * time.Second
)

// installApt installs one Debian package.
//
// It returns no bins. apt's files land in /usr, which this engine does
// not own and must not link into its own bin dir: PATH already reaches
// them, and a symlink would make an uninstall ambiguous between "drop
// the entry" and "remove the package".
func (in *installer) installApt(ctx context.Context, pkg string) error {
	if !AptAvailable() {
		return ErrAptUnavailable
	}
	if err := in.aptKnownName(ctx, pkg); err != nil {
		return err
	}
	return in.aptGetInstall(ctx, []string{pkg})
}

// aptGetInstall runs one apt-get install over a package set, retrying
// the archives-lock failure the lock timeout cannot cover.
func (in *installer) aptGetInstall(ctx context.Context, pkgs []string) error {
	var lastErr error
	for attempt := 1; attempt <= aptArchivesLockRetries; attempt++ {
		args := aptGetArgs(append([]string{"install"}, append([]string{"--"}, pkgs...)...)...)
		out, err := in.runCombined(ctx, "apt-get", args...)
		if err == nil {
			return nil
		}
		lastErr = err
		if !aptArchivesLockBusy(out) {
			return err
		}
		in.output(fmt.Sprintf("apt: the archives lock is held (attempt %d/%d), waiting %s",
			attempt, aptArchivesLockRetries, aptArchivesLockBackoff))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(aptArchivesLockBackoff):
		}
	}
	return lastErr
}

// aptArchivesLockBusy reports whether apt-get failed on the archives
// lock specifically. DPkg::Lock::Timeout does not cover it, so this is
// the one failure worth retrying rather than reporting.
func aptArchivesLockBusy(output string) bool {
	return strings.Contains(output, "/var/cache/apt/archives/lock") ||
		strings.Contains(output, "Unable to lock the download directory")
}

// aptEnv is the environment every apt-get invocation runs under.
//
// DEBIAN_FRONTEND=noninteractive is not optional: a package whose
// maintainer script asks debconf a question would otherwise block on a
// prompt no operator can see, and the job would hang until its context
// expired rather than failing. Nothing here reads a terminal.
func aptEnv() []string {
	return append(os.Environ(),
		"DEBIAN_FRONTEND=noninteractive",
		"DEBCONF_NONINTERACTIVE_SEEN=true",
	)
}

// runCombined runs a command, streams its output into the job as it
// arrives, and returns that output as text.
//
// The engine's streamCmd does the streaming half only. apt needs the
// text as well, because deciding whether to retry means reading which
// lock apt failed on, and a caller that has already streamed the lines
// away cannot answer that.
func (in *installer) runCombined(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = aptEnv()
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return "", err
	}
	var all strings.Builder
	sc := bufio.NewScanner(pipe)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		all.WriteString(line)
		all.WriteByte('\n')
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			in.output(trimmed)
		}
	}
	werr := cmd.Wait()
	out := all.String()
	if werr != nil {
		return out, fmt.Errorf("%s failed: %w", name, werr)
	}
	return out, nil
}
