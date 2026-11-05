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
)

// Layout and protocol constants.
const (
	// sentinelName marks a version directory as completely installed. It lives
	// INSIDE the directory it describes, so it cannot drift from the artifacts
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
	// back: whether the filesystem stored something wider is [verifyCustody]'s
	// question, asked once about the tree rather than per directory, and answered
	// with a verdict rather than a repair.
	dirMode  os.FileMode = 0o755
	fileMode os.FileMode = 0o600
)

// Bounded deadlines for every external command. A wedged artifact must not stall
// a start forever.
const (
	probeTimeout            = 10 * time.Second
	assertionTimeout        = 10 * time.Second
	defaultInstallerTimeout = 120 * time.Second
)

// Defaults applied by New.
const (
	defaultMaxAttempts  = 4
	defaultRetryBackoff = 30 * time.Second
	maxRetryBackoff     = 10 * time.Minute
	defaultRetain       = 1
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

// State is the manager's persisted record, written to
// <Root>/<Name>-state.json. It is DIAGNOSTIC ONLY: every field is there for an
// operator reading the volume, and none of them is an input to
// [Manager.Ready]. AssertionsOK in particular records the last result as
// history — the assertion THIS process performed is the only thing that gates
// readiness, because an assertion's effect lives in the package's own mutable
// configuration rather than in the immutable version directory.
type State struct {
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
	// Seams. Every one of these is a boundary the tests replace; none is part
	// of the public surface, because a consumer configures behaviour through
	// Release and Config, not by substituting the filesystem.
	fetch func(ctx context.Context, url string, dst io.Writer) error
	run   runCommand
	fsync func(path string) error
	// rename is root-RELATIVE, so every rename this package performs is confined
	// by the kernel rather than by the caller having built the two paths
	// correctly. See [Manager.renameIn] for why that is the seam's shape.
	rename       func(root *os.Root, oldname, newname string) error
	now          func() time.Time
	sleep        func(ctx context.Context, d time.Duration) error
	unpack       Unpacker
	parseVersion func(out string) string

	// installed records the versions this process published from a verified
	// archive, so an untrusted tree can still become ready after a reinstall.
	installed map[string]bool

	cfg Config

	// Facts resolved once at construction, so a caller mutating the Config's
	// maps or slices afterwards cannot change what this manager installs.
	// trust is the caller's declared writer set, copied at construction so a later
	// mutation of the Config's slices cannot change what this manager accepts.
	trust trustedWriters

	archToken   string
	digest      string
	urlTemplate string
	primary     string
	versionsDir string
	// stateName is the state record's single path component under Root, which is
	// what [Manager.writeFileDurably] takes; statePath is the same fact spelled
	// absolutely, for the diagnostics that name it to an operator.
	stateName string
	statePath string

	// opSem serialises the long filesystem operations (Ensure, Rescan). It is
	// deliberately NOT the state lock: it IS held across I/O, which is the whole
	// point, so the readers must never take it.
	//
	// A buffered channel rather than a sync.Mutex because the WAIT must be
	// cancellable. A mutex's Lock is not selectable, so a second caller parked
	// behind a running operation could not abandon: an HTTP handler driving
	// Rescan would hold its goroutine inside the library until the operation it
	// never started finished. Consumers were compensating for that with their own
	// admission gates; the wait belongs here, with the lock it is waiting on.
	opSem chan struct{}

	// mu guards active, state, custodyErr, phase, assertionsOK and purged, and is
	// never held across I/O.
	mu     sync.Mutex
	active selection
	state  State

	// custodyErr is the last [verifyCustody] verdict on the installation tree,
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

// New validates cfg and returns a manager.
//
// It resolves the architecture from runtime.GOARCH when [Config.GOARCH] is
// empty, requires a well-formed digest for the resolved architecture, merges
// [Release.Mandatory] into [Config.Assert], and refuses a profile that declares
// no mandatory assertions.
//
// The caller's Config is not modified, and nothing the manager keeps shares memory
// with it: the snapshot is taken BEFORE validation, so what was validated is what
// the manager will use. That covers the two POINTERS as well as the maps and slices
// — [Config.Purge] and [Release.Installer] — and the argv inside every
// [Assertion], which is what a later mutation would otherwise have been able to
// rewrite. See [Config.snapshot].
func New(cfg *Config) (*Manager, error) {
	if cfg == nil {
		return nil, errors.New("pinstall: Config is required")
	}
	c := cfg.snapshot()
	if err := c.Release.validate(); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	goarch := c.GOARCH
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	token, ok := c.Release.ArchTokens[goarch]
	if !ok {
		return nil, fmt.Errorf("%w: %s has no published archive (Release.ArchTokens covers %v)",
			ErrUnsupportedArch, goarch, slices.Sorted(maps.Keys(c.Release.ArchTokens)))
	}
	digest, ok := c.Digests[goarch]
	if !ok {
		return nil, fmt.Errorf("%w: %s has no pinned digest (Config.Digests covers %v)",
			ErrUnsupportedArch, goarch, slices.Sorted(maps.Keys(c.Digests)))
	}
	if err := validateDigest(digest); err != nil {
		return nil, fmt.Errorf("pinstall: %s digest: %w", goarch, err)
	}
	primary := c.Release.binary()
	c.GOARCH = goarch
	c.Assert = mergeAssertions(c.Assert, c.Release.Mandatory)
	c.Require = withPrimaryArtifact(c.Require, primary)
	applyConfigDefaults(&c)
	template := cmp.Or(c.URLTemplate, c.Release.URLTemplate)
	return &Manager{
		opSem:        make(chan struct{}, 1),
		fetch:        httpFetch,
		run:          execRunner,
		fsync:        fsyncPath,
		rename:       renameIn,
		now:          time.Now,
		sleep:        sleepCtx,
		unpack:       orDefaultUnpacker(c.Release.Unpack),
		parseVersion: orDefaultParser(c.Release.ParseVersion),
		installed:    map[string]bool{},
		cfg:          c,
		trust:        trustedWriters{uids: slices.Clone(c.TrustedUIDs), gids: slices.Clone(c.TrustedGIDs)},
		archToken:    token,
		digest:       digest,
		urlTemplate:  template,
		primary:      primary,
		versionsDir:  filepath.Join(c.Root, c.Release.Name+versionsSuffix),
		stateName:    c.Release.Name + stateSuffix,
		statePath:    filepath.Join(c.Root, c.Release.Name+stateSuffix),
		phase:        phaseIdle,
		state:        State{Pinned: c.Version},
	}, nil
}

// applyConfigDefaults fills the zero-valued knobs with the library's policy.
func applyConfigDefaults(c *Config) {
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = defaultMaxAttempts
	}
	if c.RetryBackoff <= 0 {
		c.RetryBackoff = defaultRetryBackoff
	}
	if c.Retain <= 0 {
		c.Retain = defaultRetain
	}
}

// orDefaultUnpacker returns u, or [UnpackZip] when u is nil.
func orDefaultUnpacker(u Unpacker) Unpacker {
	if u != nil {
		return u
	}
	return UnpackZip
}

// orDefaultParser returns p, or [LastFieldOfFirstLine] when p is nil.
func orDefaultParser(p func(string) string) func(string) string {
	if p != nil {
		return p
	}
	return LastFieldOfFirstLine
}

// validateRoot refuses a Root that is empty, relative or holds a ".." component.
// Join cleans ".." lexically while an open resolves it after a symlink, so the
// custody verdict and the operations it authorises could reach two directories.
func validateRoot(root string) error {
	switch {
	case root == "":
		return errors.New("pinstall: Root is required")
	case !filepath.IsAbs(root):
		return fmt.Errorf("pinstall: Root %q must be absolute, because its paths are handed to a subprocess", root)
	case slices.Contains(strings.Split(root, "/"), ".."):
		return fmt.Errorf("pinstall: Root %q must not contain a \"..\" component", root)
	}
	return nil
}

// validate checks the deployment half of the configuration.
func (c *Config) validate() error {
	if err := validateVersion(c.Version); err != nil {
		return fmt.Errorf("pinstall: Version %q: %w", c.Version, err)
	}
	if err := validateRoot(c.Root); err != nil {
		return err
	}
	if len(c.Digests) == 0 {
		return errors.New("pinstall: Digests is required. Map a GOARCH to that archive's lowercase hex SHA-256")
	}
	if c.URLTemplate != "" {
		if err := validateURLTemplate("URLTemplate", c.URLTemplate); err != nil {
			return err
		}
	}
	if err := validateRelPath("LinkDir", c.LinkDir, true); err != nil {
		return err
	}
	// root.MkdirAll and the listing resolve ".." after a symlink, while every link,
	// fsync and log path is Join-cleaned, so the two would reach different directories.
	if slices.Contains(strings.Split(c.LinkDir, "/"), "..") {
		return fmt.Errorf("pinstall: LinkDir %q must not contain a \"..\" component", c.LinkDir)
	}
	for _, group := range [][]string{c.Require, c.Optional} {
		for _, name := range group {
			if err := validateIdentifier("artifact name", name); err != nil {
				return err
			}
		}
	}
	if c.Purge != nil {
		return c.Purge.validate(c.LinkDir)
	}
	return nil
}

// acquireOp waits for the single operation slot, honouring ctx while WAITING.
// Returns ctx.Err() if the caller gave up first, in which case nothing was
// acquired and the caller must not release.
//
// The free slot is probed FIRST, non-blocking, and that ordering is load-bearing:
// a select with both cases ready chooses pseudo-randomly, so a single select
// would sometimes refuse a slot nobody is holding to a caller whose context is
// already done. Cancellation is meant to end a WAIT, never to deny immediate
// service — an already-expired deadline would otherwise make an uncontended
// operation fail at random.
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

// Ensure brings the pinned version online and is idempotent: on a start that
// already has the pin complete and activatable it downloads nothing and still
// re-asserts every assertion.
//
// The order is the design. The one-shot purge runs first (it deletes a previous
// layout outright, so nothing downstream can be fooled by it), then partial
// directories go (a partial is never a selection candidate), then selection
// probes each candidate's own version before accepting it, then — only when the
// pin is not already activatable — the install runs, then the assertions are
// re-asserted against whatever was selected, then the convenience links are
// republished, and only then may pruning run.
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
		slog.Warn("skipping the legacy purge and the partial sweep: both are deletes, and this process does not exclusively control the installation tree",
			"package", m.cfg.Release.Name, "root", m.versionsDir, "reason", m.custodyVerdict())
	}

	sel, ok := m.selectActive(ctx)
	var installErr error
	if !ok || sel.version != m.cfg.Version {
		installErr = m.install(ctx)
		if installErr == nil {
			sel, ok = m.selectActive(ctx)
		} else {
			slog.Warn("install failed; keeping any previously complete version",
				"package", m.cfg.Release.Name, "pinned", m.cfg.Version, "error", installErr)
		}
	}
	if !ok {
		return m.recordUnavailable(installErr)
	}
	return m.finish(ctx, sel, installErr)
}

// mayMutateTree reports whether this process may delete inside the installation tree
// or write its state record there.
//
// A clean custody verdict is one answer. [Config.InstallWithoutCustody] is the other, and it
// has
// to be: with the waiver set the library installs into the tree anyway, so refusing to
// sweep it would leave the documented [Config.Purge] knob silently dead and let
// partial directories and orphan staging trees accumulate without bound. The waiver is
// the operator saying they accept this library operating there.
func (m *Manager) mayMutateTree() bool {
	return m.custodyVerdict() == nil || m.cfg.InstallWithoutCustody
}

// finish activates sel: it re-asserts the assertions against the SELECTED
// artifact (their effect lives in the package's mutable configuration, not in
// the immutable version directory, so a remembered success proves nothing),
// commits the state, republishes the convenience links, and prunes.
func (m *Manager) finish(ctx context.Context, sel selection, installErr error) error {
	assertErr := m.applyAssertions(ctx, sel.bin)
	m.commit(sel, installErr, assertErr)
	// The last two mutations of the tree, and both go through the same gate as the
	// sweeps. They are reachable with a failed verdict — this process installs under a
	// clean one, the volume is re-permissioned, and the next Rescan selects through
	// the waiver's installed set — and a run that has just logged that it will not
	// touch the tree must not then delete directories and write a symlink in it.
	if m.mayMutateTree() {
		m.publishConvenienceLinks(sel)
		// Pruning runs only after a successful install, and therefore only after
		// publish has synced the parent directory. A FAILED install prunes nothing:
		// the versions on the volume are the fallback set that makes the failure
		// survivable.
		if installErr == nil {
			m.pruneSuperseded(ctx, sel.version)
		}
	} else {
		slog.Warn("skipping the convenience links and the retention prune: both write inside a tree this process does not exclusively control",
			"package", m.cfg.Release.Name, "root", m.versionsDir, "reason", m.custodyVerdict())
	}
	switch {
	case assertErr != nil:
		return assertErr
	case installErr != nil:
		return installErr
	}
	return nil
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
		slog.Warn("retrying the install after a failure",
			"package", m.cfg.Release.Name, "attempt", attempt, "of", m.cfg.MaxAttempts,
			"retry_in", wait.String(), "error", lastErr)
		if err := m.sleep(ctx, wait); err != nil {
			lastErr = err
			break
		}
	}
	m.settlePhase()
	if ready, _ := m.Ready(); !ready && lastErr != nil {
		slog.Error("no usable version is installed and the bounded install retries are exhausted; the installation can still be repaired in place and picked up by a rescan",
			"package", m.cfg.Release.Name, "pinned", m.cfg.Version,
			"attempts", m.cfg.MaxAttempts, "root", m.versionsDir, "error", lastErr)
	}
	return lastErr
}

// backoff returns the wait before the attempt after n, doubling from
// [Config.RetryBackoff] up to a ten minute cap.
//
// The cap is applied on ENTRY as well as after each doubling, because the first wait is
// [Config.RetryBackoff] itself and nothing else clamps it: the field is validated only for
// being positive, so a caller configuring an hour got an hour before the first retry from a
// function documented to cap at ten minutes.
func (m *Manager) backoff(n int) time.Duration {
	wait := min(m.cfg.RetryBackoff, maxRetryBackoff)
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
	// Waiting is cancellable; the admitted work is NOT. Both halves are
	// load-bearing and neither is sufficient alone.
	//
	// Cancellable wait: a queued caller (a second POST to a repair hook) must be
	// able to give up without holding a goroutine inside the library.
	//
	// Detached work: every candidate probe runs through exec.CommandContext, and
	// a probe sweep that fails records the release UNAVAILABLE, clearing the
	// active version. So a caller that cancels mid-rescan — a curl --max-time, a
	// browser tab closing — would convert a healthy manager into one that reports
	// itself unready until the next successful rescan. A rescan that has STARTED
	// must therefore finish on its own terms. Nothing is lost by detaching: the
	// probes are individually bounded by probeTimeout, so this cannot hang.
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
// required assertion against that exact artifact. The persisted
// [State.AssertionsOK] is never consulted: an assertion's effect lives in the
// package's own mutable configuration, so remembering that it once succeeded is
// stale evidence.
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

// Active returns the diagnostic state record and whether a version is active.
func (m *Manager) Active() (State, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state, m.active.bin != ""
}

// PathEntry returns the absolute directory to lead PATH with, or "" when no
// version is active. It holds only this release's own artifacts, so leading with
// it shadows nothing else.
func (m *Manager) PathEntry() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active.dir
}

// PathEnv returns the environment overlay to append to [os.Environ] before
// spawning anything that must resolve this release's artifacts, or nil when no
// version is active — [Manager.PathEntry] already composed into [pathEnv]'s
// rule, so a consumer satisfying the lead-PATH contract does not restate it.
//
// It is exported because stating a contract is not the same as shipping it. Both
// of this library's consumers were told to lead PATH with [Manager.PathEntry]
// and each wrote its own composer, which with this package's own [binPathEnv]
// made three copies of one rule; the library's copy is the one that drifted,
// appending an empty inherited PATH and so producing the trailing separator
// [pathEnv] exists to avoid.
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
// PATH follows only when there is one. The result is the single-assignment
// overlay a caller appends to [os.Environ].
//
// Refusing to append an EMPTY inherited value is the whole reason this is a
// function rather than a concatenation at each site. A PATH element that is
// empty names the CURRENT WORKING DIRECTORY, so the trailing separator left by
// appending nothing makes the child search whatever directory the calling
// process happened to be standing in — for a server that is its own work tree,
// and a bare-name sidecar lookup lands on anything a user put there. Leading
// with a directory that holds only this release's verified artifacts exists to
// NARROW that lookup, so the degenerate case does not merely fail to help, it
// inverts the guarantee. An empty entry is the same failure with one element
// instead of two, so it yields no overlay at all rather than a PATH that is
// nothing but the cwd.
//
// It is a package-level function, not a method, because the rule is needed for
// a directory the manager cannot name: [binPathEnv] applies it to a STAGED
// binary, before any version is active and therefore before [Manager.PathEntry]
// has an answer.
func pathEnv(entry string) []string {
	if entry == "" {
		return nil
	}
	if inherited := os.Getenv("PATH"); inherited != "" {
		return []string{"PATH=" + entry + string(os.PathListSeparator) + inherited}
	}
	return []string{"PATH=" + entry}
}

// binPathEnv returns the environment overlay that leads PATH with bin's own
// directory, under [pathEnv]'s rule. Every command pinstall runs AGAINST an
// installed or staged binary carries it, because a multi-binary release's
// primary executable may resolve its sidecars by BARE NAME on PATH rather than
// beside its own executable — kiro-cli is the live case: `kiro-cli settings`
// delegates to the kiro-cli-chat sidecar via PATH only, so without this overlay
// every settings assertion fails with ENOENT even though the sidecar sits right
// next to the asserted binary. The caller's process environment keeps working
// because exec.Cmd deduplicates Env taking the LAST entry.
func binPathEnv(bin string) []string {
	return pathEnv(filepath.Dir(bin))
}

// applyAssertions runs every configured assertion against bin. A required
// failure is returned (it withholds readiness); a best-effort failure only
// warns.
func (m *Manager) applyAssertions(ctx context.Context, bin string) error {
	var required error
	for _, a := range m.cfg.Assert {
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
			slog.Warn("a best-effort assertion failed; a dependent feature may misbehave",
				"package", m.cfg.Release.Name, "assertion", a.Name, "error", err)
		default:
			slog.Error("failed to assert a required assertion; withholding readiness because a guarantee the install depends on does not hold",
				"package", m.cfg.Release.Name, "assertion", a.Name, "path", bin, "error", err)
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
	for _, a := range m.cfg.Assert {
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
		slog.Warn("serving a previously installed version; the pinned version could not be installed",
			"package", m.cfg.Release.Name, "active", sel.version, "pinned", m.cfg.Version, "path", sel.bin)
	} else {
		slog.Info("version active", "package", m.cfg.Release.Name, "version", sel.version, "path", sel.bin)
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
	//
	// Only when the verdict is what BLOCKED activation, though. Under
	// [Config.InstallWithoutCustody] a failed verdict is the accepted state rather than the
	// exclusion cause, and reporting it there would send an operator to fix permissions
	// they deliberately chose while hiding the real reason — a replaced artifact under
	// an intact sentinel, say, which is ErrVersionMismatch's story to tell.
	if err == nil && !m.cfg.InstallWithoutCustody {
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

	slog.Error("no usable version is installed; readiness stays withheld until one is",
		"package", m.cfg.Release.Name, "pinned", m.cfg.Version, "error", err)
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
// It is skipped entirely in a tree this process does not control and was not waived
// into, because the record is a file written under Root and the refusal has to mean
// what it says. Nothing is lost: the same facts are already in the returned error and
// the log line.
func (m *Manager) saveState(s *State) {
	if !m.mayMutateTree() {
		return
	}
	blob, err := json.Marshal(s)
	if err != nil {
		slog.Warn("failed to encode the state record", "package", m.cfg.Release.Name, "error", err)
		return
	}

	if err := m.writeFileDurably(m.stateName, append(blob, '\n'), fileMode); err != nil {
		slog.Warn("failed to persist the state record; it is diagnostic only, so readiness is unaffected",
			"package", m.cfg.Release.Name, "path", m.statePath, "error", err)
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
