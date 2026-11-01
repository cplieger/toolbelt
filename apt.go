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

// apt writes into /usr, the container layer, so an apt entry dies with the
// container and the boot converge re-applies it. Hence: detection reads the
// dpkg status word, never a binary (aptQuery); uninstall drops the entry and
// leaves the package (installer.uninstall); and a host that is not
// Debian-derived or not root reports apt as a capability (AptAvailable).

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
var ErrAptUnavailable = errors.New("apt is not available without a Debian-derived host and root")

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

// syncAptHold makes a package's dpkg hold equal hold, and is the only caller
// of apt-mark; a pin means apt will not move the package as another
// install's side effect. A hold is released whatever the package's status,
// since apt-get -y refuses a held package, but only an installed one is held.
// dpkg's own marking, not /etc/apt/preferences.d, which operators hand-edit.
func (in *installer) syncAptHold(ctx context.Context, pkg string, hold bool) error {
	// The name goes to apt-mark as an argv element, so no shell parses it,
	// but the grammar gate still runs: a name this engine would refuse to
	// install is a name it must not mark either.
	if !aptValidName(pkg) {
		return fmt.Errorf("refusing to hold %q: not a valid package name", pkg)
	}
	ctx, cancel := context.WithTimeout(ctx, aptHoldTimeout)
	defer cancel()
	st, err := aptQuery(ctx, pkg)
	if err != nil {
		return err
	}
	if st.held == hold || hold && !st.installed {
		return nil
	}
	action := "unhold"
	if hold {
		action = "hold"
	}
	cmd, err := systemCommand(ctx, "apt-mark", action, "--", pkg)
	if err != nil {
		return err
	}
	cmd.Env = aptEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		return commandFailed("apt-mark "+action+" "+pkg, err, string(out))
	}
	in.logf("apt-mark %s %s", action, pkg)
	return nil
}

// aptStatusInstalled is the one ${db:Status-Status} value meaning the
// package's files are on disk. config-files, half-configured and deinstall
// all report a version too, which is why the status word is read rather
// than the version's presence.
const aptStatusInstalled = "installed"

// geteuid is a variable so tests can drive the apt paths against stub
// binaries without running as root.
var geteuid = os.Geteuid

// aptHoldTimeout bounds an apt-mark call. It writes one dpkg selection and
// touches no network, so this is a wedge guard rather than a work budget.
const aptHoldTimeout = 30 * time.Second

// AptAvailable reports whether this process can install apt packages: euid 0,
// and apt-get present per resolveSystemBin, so this gate and the spawn it guards
// answer about one file. Consumers surface it rather than offering an install
// that always fails, and the engine's own converge skips apt when it is false.
//
// Root is required because apt writes to /usr and the dpkg database.
// There is no sudo path here by design: the two consumers of this
// library run as root deliberately, and a library that shells out to
// sudo would be inventing a privilege escalation its caller did not ask
// for.
func AptAvailable() bool {
	if geteuid() != 0 {
		return false
	}
	return hasSystemBin("apt-get")
}

// aptStatus is one package's dpkg record. held is the selection apt-mark
// sets, which dpkg reports as the "hold" want state (dpkg-query(1), Status),
// on a package that is not installed too.
type aptStatus struct {
	version   string
	installed bool
	held      bool
}

// aptUnknownPackage is what dpkg-query prints, with exit status 1, for a
// name it has no record of (dpkg-query(1), EXIT STATUS).
const aptUnknownPackage = "no packages found matching"

// aptQuery reads a package's dpkg record. A package dpkg has no record of
// reads as the zero aptStatus; every other failure is an error, so a caller
// never takes an unread record for an absent one.
func aptQuery(ctx context.Context, pkg string) (aptStatus, error) {
	cmd, err := systemCommand(ctx, "dpkg-query", "-W", aptStatusFormat, "--", pkg)
	if err != nil {
		return aptStatus{}, err
	}
	cmd.Env = aptEnv()
	out, err := cmd.Output()
	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok &&
		exitErr.ExitCode() == 1 && strings.Contains(string(exitErr.Stderr), aptUnknownPackage) {
		return aptStatus{}, nil
	}
	if err != nil {
		return aptStatus{}, commandFailed("dpkg-query "+pkg, err, "")
	}
	st, err := aptStatusFrom(string(out))
	if err != nil {
		return aptStatus{}, fmt.Errorf("dpkg-query %s: %w", pkg, err)
	}
	return st, nil
}

// aptStatusFormat is the dpkg-query format aptStatusFrom parses.
const aptStatusFormat = "-f=${db:Status-Want} ${db:Status-Status} ${Version}"

// aptStatusFrom reads one aptStatusFormat answer; a package that is not
// installed has no version, so its answer can end after the status word.
// The status word decides: after `apt-get remove nano` (apt 3.0.3) dpkg keeps
// a config-files record at 8.4-1+deb13u1 and exits 0 with no binary on disk,
// so a version-only read reports every apt entry present after a recreate.
func aptStatusFrom(out string) (aptStatus, error) {
	fields := strings.SplitN(strings.TrimSpace(out), " ", 3)
	if len(fields) < 2 {
		return aptStatus{}, fmt.Errorf("unreadable dpkg status %q", strings.TrimSpace(out))
	}
	st := aptStatus{held: fields[0] == "hold", installed: fields[1] == aptStatusInstalled}
	if st.installed && len(fields) == 3 {
		st.version = strings.TrimSpace(fields[2])
	}
	return st, nil
}

// aptCandidate reports the version apt would install now. It is what an apt
// row displays and what decides whether an update is available, because an
// apt entry has no upstream version of its own to resolve.
func (in *installer) aptCandidate(ctx context.Context, pkg string) (string, error) {
	return aptPolicyCandidate(ctx, in.aptIdx, pkg)
}

// aptPolicyCandidate reads the Candidate line of `apt-cache policy` for pkg,
// after the index oracle accepts the name.
func aptPolicyCandidate(ctx context.Context, idx *aptIndex, pkg string) (string, error) {
	// The oracle runs FIRST: apt-cache policy expands a pattern as apt-get
	// install does, so "jq." would answer with whichever package matched and
	// record that version against a name the user never gave.
	if err := idx.knownName(ctx, pkg); err != nil {
		return "", err
	}
	cmd, err := systemCommand(ctx, "apt-cache", "policy", "--", pkg)
	if err != nil {
		return "", err
	}
	cmd.Env = aptEnv()
	out, err := cmd.Output()
	if err != nil {
		return "", commandFailed("apt-cache policy "+pkg, err, "")
	}
	cand, err := aptCandidateFrom(string(out))
	if err != nil {
		return "", fmt.Errorf("%s: %w", pkg, err)
	}
	return cand, nil
}

// aptCandidateFrom extracts the Candidate version from apt-cache policy
// output.
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
	return append([]string{
		"-o", "DPkg::Lock::Timeout=60",
		"-y",
		"--no-install-recommends",
	}, extra...)
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
	// apt-get -y refuses to change a held package. Lifting this package's
	// hold, rather than passing --allow-change-held-packages, keeps every
	// other held package fixed: that flag covers the whole transaction, so a
	// dependency another pin holds could move (apt-get(8)). The job restores
	// the hold as its last step (Engine.holdToPin).
	if err := in.syncAptHold(ctx, pkg, false); err != nil {
		return fmt.Errorf("lift the hold for the install: %w", err)
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
		in.output(fmt.Sprintf("apt: the archives lock is held, attempt %d of %d, waiting %s",
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

// aptEnv is the environment every apt-family spawn runs under: the inherited
// PATH with the trusted directories prepended, so bin/ cannot precede them for
// whatever apt or a dpkg maintainer script resolves for itself (systemPATHFirst).
//
// DEBIAN_FRONTEND=noninteractive is not optional: a package whose
// maintainer script asks debconf a question would otherwise block on a
// prompt no operator can see, and the job would hang until its context
// expired rather than failing. Nothing here reads a terminal.
func aptEnv() []string {
	return systemPATHFirst(append(os.Environ(),
		"DEBIAN_FRONTEND=noninteractive",
		"DEBCONF_NONINTERACTIVE_SEEN=true",
	))
}

// runCombined runs a command, streams its output into the job as it
// arrives, and returns that output as text.
//
// streamCmd keeps only a bounded tail for its error. apt needs the whole
// text, because deciding whether to retry means reading which lock apt
// failed on, and that line can sit anywhere in the output.
func (in *installer) runCombined(ctx context.Context, name string, args ...string) (string, error) {
	cmd, err := systemCommand(ctx, name, args...)
	if err != nil {
		return "", err
	}
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
		return out, commandFailed(name, werr, out)
	}
	return out, nil
}
