//go:build linux

package pin

import (
	"cmp"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cplieger/toolbelt/v3/internal/custody"
)

// Layout and protocol constants.
const (
	// sentinelName marks a version directory as completely installed. It lives
	// INSIDE the directory it describes, so it cannot drift from the artifact
	// it vouches for, and it is written LAST.
	sentinelName = ".complete"
	// versionsSuffix names the version-addressed installation root, appended to
	// the release name under Root.
	versionsSuffix = "-versions"
	// stateSuffix names the diagnostic state record under Root.
	stateSuffix = "-state.json"
	// stagePrefix prefixes every in-progress staging tree under the
	// installation root. Dot-prefixed so no version scan and no bare-name PATH
	// lookup can reach it.
	stagePrefix = ".stage-"

	// dirMode and fileMode are what this package REQUESTS. Nothing reads them
	// back: whether the filesystem stored something wider is custody's
	// question, asked once about the tree rather than per directory, and answered
	// with a verdict rather than a repair.
	dirMode  os.FileMode = 0o755
	fileMode os.FileMode = 0o600
)

// Bounded deadlines for every external command. A wedged artifact must not stall
// a start forever.
const (
	probeTimeout     = 10 * time.Second
	assertionTimeout = 10 * time.Second
)

// Retry and retention policy. One retained predecessor is what makes a bad
// activation recoverable without a rollback journal.
const (
	defaultMaxAttempts = 4
	retryBackoff       = 30 * time.Second
	maxRetryBackoff    = 10 * time.Minute
	retainPredecessors = 1
)

// Reason explains a withheld readiness verdict. It is an enum rather than a
// string because the wording a consumer shows its own users is the consumer's:
// the library owns only the distinction between the states.
type Reason uint8

// The readiness reasons, in the order a start walks them.
const (
	// ReasonReady means readiness is not withheld. Its String is empty.
	ReasonReady Reason = iota
	// ReasonInstalling means the first attempt of this process is still in
	// flight and no version has ever been activated.
	ReasonInstalling
	// ReasonRetrying means an attempt failed and another one is scheduled.
	ReasonRetrying
	// ReasonUnavailable means no version is active and no further attempt is
	// scheduled. Only a repair plus [Manager.Rescan], or a fresh process, can
	// clear it.
	ReasonUnavailable
	// ReasonAssertion means a version is active but a Required assertion could
	// not be asserted against it, so a guarantee the install depends on does
	// not hold.
	ReasonAssertion
)

// String returns a short, package-agnostic description of the reason, and "" for
// [ReasonReady].
func (r Reason) String() string {
	switch r {
	case ReasonReady:
		return ""
	case ReasonInstalling:
		return "installing"
	case ReasonRetrying:
		return "install retrying"
	case ReasonUnavailable:
		return "unavailable"
	case ReasonAssertion:
		return "required assertion not enforced"
	}
	return "unavailable"
}

// phase is where the manager is in the install lifecycle. It is unexported
// because [Reason] is the only distinction a caller needs; the phases exist to
// tell "still installing" from "retrying" from "gave up".
type phase uint8

const (
	phaseIdle phase = iota
	phaseInstalling
	phaseRetrying
	phaseReady
	phaseFailed
)

// stateRecord is the diagnostic record written to <Root>/<Name>-state.json for
// an operator reading the volume. None of it is an input to [Manager.Ready]:
// an assertion's effect lives in the package's mutable configuration, so only
// the assertion THIS process performed gates readiness.
type stateRecord struct {
	UpdatedAt     time.Time `json:"updated_at"`
	ActiveVersion string    `json:"active_version"`
	Dir           string    `json:"dir"`
	Pinned        string    `json:"pinned"`
	LastError     string    `json:"last_error,omitempty"`
	AssertionsOK  bool      `json:"assertions_ok"`
}

// selection is one activatable version: its directory name, that directory's
// absolute path, and the absolute path of its primary artifact.
type selection struct {
	version string
	dir     string
	bin     string
}

// Manager installs, activates and maintains one pinned release. It is safe for
// concurrent use: [Manager.Ensure] and [Manager.Rescan] serialise against each
// other, while the readers never block behind an install.
//
//nolint:govet // fieldalignment: the field order IS this struct's lock-ownership documentation (seams, then the resolved facts, then each lock immediately above what it guards). Packing it for the ~48 bytes fieldalignment can reclaim separates both mutexes from the fields they protect, which is the wrong trade for a struct allocated exactly once per manager.
type Manager struct {
	// Seams the tests replace; a consumer configures behaviour through Config.
	fetch func(ctx context.Context, url string, dst io.Writer) error
	run   runCommand
	fsync func(path string) error
	// rename is root-RELATIVE, so every rename this package performs is confined
	// by the kernel rather than by the caller having built the two paths
	// correctly. See [Manager.renameIn] for why that is the seam's shape.
	rename func(root *os.Root, oldname, newname string) error
	now    func() time.Time
	sleep  func(ctx context.Context, d time.Duration) error

	// installed records the versions this process published from a verified
	// archive, so an untrusted tree can still become ready after a reinstall.
	installed map[string]bool

	cfg Config

	// Facts resolved once at construction, so a caller mutating the Config's
	// maps or slices afterwards cannot change what this manager installs.
	// trust is the caller's declared writer set, copied at construction so a later
	// mutation of the Config's slices cannot change what this manager accepts.
	trust custody.Trust
	log   *slog.Logger

	// archiveURL is the pinned archive's absolute URL, both placeholders
	// substituted. The version is pinned rather than a floating "latest" so a
	// deployment is reproducible and the digest check is meaningful.
	archiveURL  string
	format      string
	digest      string
	primary     string
	versionsDir string
	// stateName is the state record's single path component under Root, which is
	// what [Manager.writeFileDurably] takes; statePath is the same fact spelled
	// absolutely, for the diagnostics that name it to an operator.
	stateName string
	statePath string

	// opSem serialises Ensure and Rescan and is held across I/O, so readers never
	// take it. A buffered channel rather than a mutex because the wait must be
	// cancellable: a parked HTTP handler driving Rescan must be able to give up.
	opSem chan struct{}

	// mu guards active, state, custodyErr, phase, assertionsOK and purged, and is
	// never held across I/O.
	mu     sync.Mutex
	active selection
	state  stateRecord

	// custodyErr is the last custody.Trust.Verify verdict on the installation tree,
	// re-evaluated at the start of every operation because a volume can be
	// remounted or re-permissioned under a running process. nil means this
	// process has exclusive control, which is what makes a sentinel in that tree
	// worth believing.
	custodyErr error

	// phase and the two flags sit at the end rather than beside what they
	// describe only because a one-byte field in the middle of this set costs
	// eight bytes of padding.
	phase phase
	// assertionsOK records whether THIS process asserted every required
	// assertion against active.bin. It is the readiness authority.
	assertionsOK bool
	// purged latches the one-shot purge so retries and rescans do not walk the
	// co-owned link directory again.
	purged bool
}

// New validates cfg and returns a manager. It resolves the architecture from
// runtime.GOARCH, requires a well-formed digest for it and an archive URL whose
// extension names a format, and refuses a config with no Required assertion.
// Nothing the manager keeps shares memory with cfg: the snapshot is taken before
// validation, so what was validated is what the manager uses.
func New(cfg *Config) (*Manager, error) {
	if cfg == nil {
		return nil, errors.New("pin: Config is required")
	}
	c := cfg.snapshot()
	if err := c.validate(); err != nil {
		return nil, err
	}
	goarch := c.goarch
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	token, ok := c.ArchTokens[goarch]
	if !ok {
		return nil, fmt.Errorf("pin: unsupported architecture: %s has no published archive (ArchTokens covers %v)",
			goarch, slices.Sorted(maps.Keys(c.ArchTokens)))
	}
	digest, ok := c.Digests[goarch]
	if !ok {
		return nil, fmt.Errorf("pin: unsupported architecture: %s has no pinned digest (Digests covers %v)",
			goarch, slices.Sorted(maps.Keys(c.Digests)))
	}
	if err := validateDigest(digest); err != nil {
		return nil, fmt.Errorf("pin: %s digest: %w", goarch, err)
	}
	resolved := strings.NewReplacer(versionPlaceholder, c.Version, archPlaceholder, token).Replace(c.URLTemplate)
	format, ok := formatOf(resolved)
	if !ok {
		return nil, fmt.Errorf("pin: URLTemplate resolves to %q for %s, whose last path segment must end in .zip, .tar, .tar.gz, .tgz, .tar.bz2, .tbz2 or .tbz",
			resolved, goarch)
	}
	c.goarch = goarch
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = defaultMaxAttempts
	}
	return &Manager{
		opSem:       make(chan struct{}, 1),
		fetch:       httpFetch,
		run:         execRunner,
		fsync:       fsyncPath,
		rename:      renameIn,
		now:         time.Now,
		sleep:       sleepCtx,
		installed:   map[string]bool{},
		cfg:         c,
		trust:       custody.Trust{UIDs: c.TrustedUIDs},
		log:         cmp.Or(c.Logger, slog.Default()),
		format:      format,
		digest:      digest,
		archiveURL:  resolved,
		primary:     c.Name,
		versionsDir: filepath.Join(c.Root, c.Name+versionsSuffix),
		stateName:   c.Name + stateSuffix,
		statePath:   filepath.Join(c.Root, c.Name+stateSuffix),
		phase:       phaseIdle,
		state:       stateRecord{Pinned: c.Version},
	}, nil
}

// acquireOp waits for the single operation slot, honouring ctx while waiting,
// and returns ctx.Err() with nothing acquired if the caller gave up. The free
// slot is probed first, non-blocking: a select with both cases ready picks at
// random, so an expired deadline would otherwise fail an uncontended operation.
func (m *Manager) acquireOp(ctx context.Context) error {
	select {
	case m.opSem <- struct{}{}:
		return nil
	default:
	}
	select {
	case m.opSem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// releaseOp frees the operation slot. Only a caller whose acquireOp returned nil
// may call it.
func (m *Manager) releaseOp() { <-m.opSem }

// Ensure brings the pinned version online and is idempotent: a start that
// already has the pin activatable downloads nothing and still re-asserts every
// assertion. The order is the design: the one-shot purge, the partial sweep, a
// selection that probes each candidate, the install only when the pin is not
// activatable, the assertions against what was selected, the links, and only
// then pruning.
func (m *Manager) Ensure(ctx context.Context) error {
	// Cancellable wait, then the work keeps the caller's context: Ensure is
	// driven by boot and shutdown, where cancelling a long download is exactly
	// what a caller wants. Rescan is the one that detaches (see there).
	if err := m.acquireOp(ctx); err != nil {
		return err
	}
	defer m.releaseOp()

	// Custody first, and NOTHING mutates the tree before it. The purge and the
	// partial sweep are deletes, and deleting inside a tree this library is about to
	// refuse would assert exactly the authority the refusal exists to disclaim.
	m.checkCustody()
	if m.mayMutateTree() {
		m.purgeOnce()
		m.prunePartials()
	} else {
		m.log.Warn("skipping the legacy purge and the partial sweep: both are deletes, and this process does not exclusively control the installation tree",
			"package", m.cfg.Name, "root", m.versionsDir, "reason", m.custodyVerdict())
	}

	sel, ok := m.selectActive(ctx)
	var installErr error
	if !ok || sel.version != m.cfg.Version {
		installErr = m.install(ctx)
		if installErr == nil {
			sel, ok = m.selectActive(ctx)
		} else {
			m.log.Warn("install failed; keeping any previously complete version",
				"package", m.cfg.Name, "pinned", m.cfg.Version, "error", installErr)
		}
	}
	if !ok {
		return m.recordUnavailable(installErr)
	}
	return m.finish(ctx, sel, installErr)
}

// mayMutateTree reports whether this process may delete inside the
// installation tree or write its state record there: only under a clean
// custody verdict.
func (m *Manager) mayMutateTree() bool {
	return m.custodyVerdict() == nil
}

// finish activates sel: it re-asserts the assertions against the SELECTED
// artifact (their effect lives in the package's mutable configuration, not in
// the immutable version directory, so a remembered success proves nothing),
// commits the state, republishes the convenience links, and prunes.
func (m *Manager) finish(ctx context.Context, sel selection, installErr error) error {
	assertErr := m.applyAssertions(ctx, sel.bin)
	m.commit(sel, installErr, assertErr)
	// The last mutations of the tree go through the same gate as the sweeps: a run
	// that has just logged that it will not touch the tree must not then write in it.
	if m.mayMutateTree() {
		m.markActivated(sel.version)
		m.publishConvenienceLinks(sel)
		// A failed install prunes nothing: the versions on the volume are the
		// fallback set that makes the failure survivable. Every other run prunes,
		// a rescan and a start that found the pin installed included.
		if installErr == nil {
			m.pruneSuperseded(ctx, sel.version)
		}
	} else {
		m.log.Warn("skipping the convenience links and the retention prune: both write inside a tree this process does not exclusively control",
			"package", m.cfg.Name, "root", m.versionsDir, "reason", m.custodyVerdict())
	}
	switch {
	case assertErr != nil:
		return assertErr
	case installErr != nil:
		return installErr
	}
	return nil
}

// markActivated sets the version directory's mtime to now, which is the
// activation time retention orders predecessors by. Only the directory's own
// time changes, never an artifact's. A failure only warns.
func (m *Manager) markActivated(version string) {
	root, err := os.OpenRoot(m.versionsDir)
	if err != nil {
		m.log.Warn("failed to open the installation root to record the activation",
			"package", m.cfg.Name, "error", err)
		return
	}
	defer root.Close()
	now := m.now()
	if err := root.Chtimes(version, now, now); err != nil {
		m.log.Warn("failed to record the activation time; retention may keep an older predecessor",
			"package", m.cfg.Name, "version", version, "error", err)
	}
}

// EnsureWithRetry drives [Manager.Ensure] with bounded exponential backoff. A
// single one-shot attempt would leave a failed first start withholding readiness
// forever with no further effort. It never exits the process, and it returns the
// last error after the attempts are exhausted.
func (m *Manager) EnsureWithRetry(ctx context.Context) error {
	var lastErr error
	for attempt := 1; attempt <= m.cfg.MaxAttempts; attempt++ {
		m.setAttemptPhase(attempt)
		lastErr = m.Ensure(ctx)
		if lastErr == nil {
			m.settlePhase()
			return nil
		}
		if ctx.Err() != nil || attempt == m.cfg.MaxAttempts {
			break
		}
		m.setPhase(phaseRetrying)
		wait := m.backoff(attempt)
		m.log.Warn("retrying the install after a failure",
			"package", m.cfg.Name, "attempt", attempt, "of", m.cfg.MaxAttempts,
			"retry_in", wait.String(), "error", lastErr)
		if err := m.sleep(ctx, wait); err != nil {
			lastErr = err
			break
		}
	}
	m.settlePhase()
	if ready, _ := m.Ready(); !ready && lastErr != nil {
		m.log.Error("no usable version is installed and the bounded install retries are exhausted; the installation can still be repaired in place and picked up by a rescan",
			"package", m.cfg.Name, "pinned", m.cfg.Version,
			"attempts", m.cfg.MaxAttempts, "root", m.versionsDir, "error", lastErr)
	}
	return lastErr
}

// backoff returns the wait before the attempt after n, doubling from
// retryBackoff up to maxRetryBackoff.
func (m *Manager) backoff(n int) time.Duration {
	wait := retryBackoff
	for range n - 1 {
		wait *= 2
		if wait >= maxRetryBackoff {
			return maxRetryBackoff
		}
	}
	return wait
}

// Rescan re-derives the active version from what is on disk right now, without
// downloading anything, and re-asserts the assertions. It makes a repair
// performed in place — an operator restoring a version directory, or replacing a
// wedged artifact — observable without a fresh process. It returns whether a
// version is active afterwards.
func (m *Manager) Rescan(ctx context.Context) (bool, error) {
	// Waiting is cancellable, so a queued caller can give up. The admitted work is
	// not: a failed probe sweep records the release unavailable, so a caller that
	// cancels mid-rescan would turn a healthy manager unready. Each probe is bounded
	// by probeTimeout, so detaching cannot hang.
	if err := m.acquireOp(ctx); err != nil {
		return false, err
	}
	defer m.releaseOp()
	ctx = context.WithoutCancel(ctx)

	m.checkCustody()
	sel, ok := m.selectActive(ctx)
	if !ok {
		err := m.recordUnavailable(nil)
		m.settlePhase()
		return false, err
	}
	err := m.finish(ctx, sel, nil)
	m.settlePhase()
	return err == nil, err
}

// Ready reports whether the installation may be used, and why not when it may
// not.
//
// It is true only when a version is active AND this process asserted every
// required assertion against that exact artifact. The persisted record is never
// consulted: an assertion's effect lives in the package's own mutable
// configuration, so remembering that it once succeeded is stale evidence.
func (m *Manager) Ready() (ready bool, why Reason) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case m.active.bin == "":
		return false, reasonFor(m.phase)
	case !m.assertionsOK:
		return false, ReasonAssertion
	}
	return true, ReasonReady
}

// reasonFor maps a phase with no active version to its readiness reason.
func reasonFor(p phase) Reason {
	switch p {
	case phaseIdle, phaseInstalling:
		return ReasonInstalling
	case phaseRetrying:
		return ReasonRetrying
	case phaseReady, phaseFailed:
		return ReasonUnavailable
	}
	return ReasonUnavailable
}

// Version returns the active version, or "" when none is active.
func (m *Manager) Version() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active.version
}

// PathEntry returns the absolute directory to lead PATH with, or "" when no
// version is active. It holds only files this release's installs put there, so
// leading with it shadows nothing else.
func (m *Manager) PathEntry() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active.dir
}

// PathEnv returns the overlay to append to [os.Environ] before spawning anything
// that must resolve this release's artifact, or nil when no version is active:
// PATH led by [Manager.PathEntry], then the inherited PATH when there is one, so
// consumers do not each write their own composer.
func (m *Manager) PathEnv() []string {
	return pathEnv(m.PathEntry())
}

// Path returns the absolute path of the active primary artifact, or "" when no
// version is active. This — never the convenience link — is what a consumer
// runs.
func (m *Manager) Path() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active.bin
}

// versionDir is the absolute directory for one version.
func (m *Manager) versionDir(version string) string {
	return filepath.Join(m.versionsDir, version)
}

// pathEnv is the one PATH rule this package owns: entry leads, and the inherited
// PATH follows only when there is one. An empty element names the working
// directory, so a trailing separator would make the child search wherever the
// caller stands, inverting the narrowing the lead entry exists for; an empty
// entry therefore yields no overlay at all. A function, not a method, because
// [binPathEnv] applies it to a staged binary before any version is active.
func pathEnv(entry string) []string {
	if entry == "" {
		return nil
	}
	if inherited := os.Getenv("PATH"); inherited != "" {
		return []string{"PATH=" + entry + string(os.PathListSeparator) + inherited}
	}
	return []string{"PATH=" + entry}
}

// binPathEnv leads PATH with bin's own directory under [pathEnv]'s rule. Every
// command run against an installed or staged binary carries it, so the probe
// and the assertions run the binary under the PATH a consumer gives it through
// [Manager.PathEnv]: a bare-name exec it makes finds its own version directory
// first. exec.Cmd keeps the last of duplicate Env entries, so the caller's
// environment still applies.
func binPathEnv(bin string) []string {
	return pathEnv(filepath.Dir(bin))
}

// applyAssertions runs every configured assertion against bin. A required
// failure is returned (it withholds readiness); a best-effort failure only
// warns.
func (m *Manager) applyAssertions(ctx context.Context, bin string) error {
	var required error
	for _, a := range m.cfg.Assertions {
		_, err := m.run(ctx, &command{
			Path:    bin,
			Env:     binPathEnv(bin),
			Args:    a.Args,
			Timeout: assertionTimeout,
		})
		switch {
		case err == nil:
			continue
		case !a.Required:
			m.log.Warn("a best-effort assertion failed; a dependent feature may misbehave",
				"package", m.cfg.Name, "assertion", a.Name, "error", err)
		default:
			m.log.Error("failed to assert a required assertion; withholding readiness because a guarantee the install depends on does not hold",
				"package", m.cfg.Name, "assertion", a.Name, "path", bin, "error", err)
			if required == nil {
				required = fmt.Errorf("required assertion %s: %w", a.Name, err)
			}
		}
	}
	return required
}

// applyRequiredAssertions runs only the required assertions, for the staged gate
// where the best-effort ones are applied later against the published artifact.
func (m *Manager) applyRequiredAssertions(ctx context.Context, bin string) error {
	for _, a := range m.cfg.Assertions {
		if !a.Required {
			continue
		}
		if _, err := m.run(ctx, &command{
			Path:    bin,
			Env:     binPathEnv(bin),
			Args:    a.Args,
			Timeout: assertionTimeout,
		}); err != nil {
			return fmt.Errorf("refusing to publish a version whose required assertion %s does not hold: %w", a.Name, err)
		}
	}
	return nil
}

// commit records the activation under the state lock and persists the diagnostic
// record. The lock is held only across in-memory assignment; the state file is
// written outside it.
func (m *Manager) commit(sel selection, installErr, assertErr error) {
	m.mu.Lock()
	m.active = sel
	m.assertionsOK = assertErr == nil
	m.state.ActiveVersion = sel.version
	m.state.Dir = sel.dir
	m.state.Pinned = m.cfg.Version
	m.state.AssertionsOK = assertErr == nil
	m.state.LastError = firstErrText(assertErr, installErr)
	m.state.UpdatedAt = m.now().UTC()
	snapshot := m.state
	if m.assertionsOK {
		m.phase = phaseReady
	}
	m.mu.Unlock()

	if installErr != nil {
		m.log.Warn("serving a previously installed version; the pinned version could not be installed",
			"package", m.cfg.Name, "active", sel.version, "pinned", m.cfg.Version, "path", sel.bin)
	} else {
		m.log.Info("version active", "package", m.cfg.Name, "version", sel.version, "path", sel.bin)
	}
	m.saveState(&snapshot)
}

// recordUnavailable clears the active version and records why. It returns the
// install error when there was one, so a caller can distinguish "the install
// failed" from "nothing was ever installed".
func (m *Manager) recordUnavailable(installErr error) error {
	err := installErr
	// A custody refusal is the more useful answer than "no complete version is
	// installed": it names the volume and the thing to change, where ErrNoVersion
	// points the operator at an install that is present and simply not trusted. This is
	// the path a mid-process verdict flip takes, where no install was even tried.
	if err == nil {
		err = m.custodyVerdict()
	}
	if err == nil {
		err = ErrNoVersion
	}
	m.mu.Lock()
	m.active = selection{}
	m.assertionsOK = false
	m.state.ActiveVersion = ""
	m.state.Dir = ""
	m.state.Pinned = m.cfg.Version
	m.state.AssertionsOK = false
	m.state.LastError = err.Error()
	m.state.UpdatedAt = m.now().UTC()
	snapshot := m.state
	m.mu.Unlock()

	m.log.Error("no usable version is installed; readiness stays withheld until one is",
		"package", m.cfg.Name, "pinned", m.cfg.Version, "error", err)
	m.saveState(&snapshot)
	return err
}

// setAttemptPhase marks the first attempt installing and every later one
// retrying, but never downgrades a manager that is already serving.
func (m *Manager) setAttemptPhase(attempt int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.phase == phaseReady {
		return
	}
	if attempt == 1 {
		m.phase = phaseInstalling
		return
	}
	m.phase = phaseRetrying
}

func (m *Manager) setPhase(p phase) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.phase = p
}

// settlePhase recomputes the terminal phase from the live state: ready when a
// version is active with its assertions asserted, failed otherwise.
func (m *Manager) settlePhase() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active.bin != "" && m.assertionsOK {
		m.phase = phaseReady
		return
	}
	m.phase = phaseFailed
}

// saveState writes the diagnostic record durably. A failure only warns: nothing in
// the record is an input to readiness, so losing it must not fail an otherwise good
// install.
//
// It is skipped entirely in a tree this process does not control, because the
// record is a file written under Root and the refusal has to mean what it says.
// Nothing is lost: the same facts are already in the returned error and the log
// line.
func (m *Manager) saveState(s *stateRecord) {
	if !m.mayMutateTree() {
		return
	}
	blob, err := json.Marshal(s)
	if err != nil {
		m.log.Warn("failed to encode the state record", "package", m.cfg.Name, "error", err)
		return
	}

	if err := m.writeFileDurably(m.stateName, append(blob, '\n'), fileMode); err != nil {
		m.log.Warn("failed to persist the state record; it is diagnostic only, so readiness is unaffected",
			"package", m.cfg.Name, "path", m.statePath, "error", err)
	}
}

// firstErrText returns the first non-nil error's text, or "".
func firstErrText(errs ...error) string {
	for _, err := range errs {
		if err != nil {
			return err.Error()
		}
	}
	return ""
}

// validateDigest rejects anything that is not a 64-character lowercase hex
// SHA-256, so a truncated or mangled pin fails at construction rather than after
// a large download.
func validateDigest(digest string) error {
	if len(digest) != 64 {
		return fmt.Errorf("want 64 hex characters, got %d", len(digest))
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return errors.New("not hexadecimal")
	}
	if strings.ToLower(digest) != digest {
		return errors.New("must be lowercase hexadecimal")
	}
	return nil
}

// validateVersion constrains the pin to the characters a version can hold. The
// value is interpolated into BOTH a download URL and a filesystem path under
// Root, so a separator or a traversal component in it would escape the
// installation root.
func validateVersion(version string) error {
	if version == "" {
		return errors.New("is required")
	}
	for _, r := range version {
		switch {
		case r >= '0' && r <= '9',
			r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r == '.', r == '-', r == '+', r == '_':
		default:
			return fmt.Errorf("illegal character %q, want only letters, digits and .-+_", r)
		}
	}
	if strings.HasPrefix(version, ".") || strings.Contains(version, "..") {
		return errors.New("must not start with a dot or contain \"..\"")
	}
	return nil
}

// sleepCtx waits d or until ctx is done, whichever comes first. time.Sleep would
// block a shutdown.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
