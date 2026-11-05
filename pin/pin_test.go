//go:build linux

package pin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// TestNewValidatesItsPins pins the architecture-dependent half of construction
// (TestConfigValidationRefusesEachBrokenField has the rest): a supported
// architecture and a well-formed digest for THAT architecture. Rejecting a mangled pin at construction beats
// discovering it after a large download.
func TestNewValidatesItsPins(t *testing.T) {
	tests := map[string]struct {
		mutate  func(*Config)
		wantErr string
	}{
		"traversal version":     {mutate: func(c *Config) { c.Version = "../../etc" }, wantErr: "Version"},
		"separator in version":  {mutate: func(c *Config) { c.Version = "2.14.2/x" }, wantErr: "illegal character"},
		"dotted version":        {mutate: func(c *Config) { c.Version = ".hidden" }, wantErr: "dot"},
		"no digests at all":     {mutate: func(c *Config) { c.Digests = nil }, wantErr: "Digests is required"},
		"no digest for arch":    {mutate: func(c *Config) { delete(c.Digests, "amd64") }, wantErr: "no pinned digest"},
		"unsupported arch":      {mutate: func(c *Config) { c.goarch = "sparc64" }, wantErr: "no published archive"},
		"truncated digest":      {mutate: func(c *Config) { c.Digests["amd64"] = sixtyFourHexChars[:63] }, wantErr: "64 hex"},
		"non-hex digest":        {mutate: func(c *Config) { c.Digests["amd64"] = strings.Repeat("z", 64) }, wantErr: "hexadecimal"},
		"uppercase digest":      {mutate: func(c *Config) { c.Digests["amd64"] = strings.ToUpper(sixtyFourHexChars) }, wantErr: "lowercase"},
		"other arch digest bad": {mutate: func(c *Config) { c.Digests["arm64"] = "junk" }},
		"valid":                 {mutate: func(*Config) {}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			env := newFakeEnv(t)
			cfg := env.config(tc.mutate)
			m, err := New(cfg)
			switch {
			case tc.wantErr == "":
				if err != nil {
					t.Fatalf("New: %v", err)
				}
				if m.cfg.MaxAttempts <= 0 || m.archiveURL == "" || m.format != "zip" {
					t.Errorf("New left a default unset: attempts=%d url=%q format=%q",
						m.cfg.MaxAttempts, m.archiveURL, m.format)
				}
			case err == nil:
				t.Fatalf("New accepted %s", name)
			case !strings.Contains(err.Error(), tc.wantErr):
				t.Errorf("error = %v, want one mentioning %q", err, tc.wantErr)
			}
		})
	}
}

// TestNewRejectsAConfigPointerOfNil pins the one input that cannot be validated
// field by field.
func TestNewRejectsAConfigPointerOfNil(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("New(nil) returned no error")
	}
}

// TestNewCopiesEverythingItDependsOn pins that a caller mutating its own Config
// after construction cannot change what the manager installs. The maps and slices
// in a Config are shared by a shallow copy, so the facts have to be resolved once.
func TestNewCopiesEverythingItDependsOn(t *testing.T) {
	env := newFakeEnv(t)
	cfg := env.config()
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	wantURL := m.archiveURL

	cfg.Digests["amd64"] = strings.Repeat("f", 64)
	cfg.ArchTokens["amd64"] = "hijacked"
	cfg.Version = "9.9.9"

	if m.digest != env.digest {
		t.Errorf("digest = %q, want the digest resolved at construction %q", m.digest, env.digest)
	}
	if m.archiveURL != wantURL {
		t.Errorf("archiveURL = %q, want %q", m.archiveURL, wantURL)
	}
	if m.cfg.Version != pinnedVersion {
		t.Errorf("Version = %q, want %q", m.cfg.Version, pinnedVersion)
	}
}

// TestEnsureReassertsRequiredAssertionsOnAStartThatSkipsTheInstall pins that an
// assertion cannot be remembered. Its effect lives in the package's own mutable
// configuration, not in the immutable version directory, so even the fast path
// where the pinned directory is already complete must re-prove it against the
// selected artifact — and a failure there withholds readiness rather than warning.
func TestEnsureReassertsRequiredAssertionsOnAStartThatSkipsTheInstall(t *testing.T) {
	t.Run("asserted without downloading anything", func(t *testing.T) {
		env := newFakeEnv(t)
		dir := env.placeVersion(pinnedVersion)
		m := env.manager(func(c *Config) {
			c.Assertions = append(c.Assertions, Assertion{Name: "telemetry.enabled", Args: []string{"settings", "telemetry.enabled", "false"}})
		})

		if err := m.Ensure(t.Context()); err != nil {
			t.Fatalf("Ensure: %v", err)
		}
		if env.fetchCount() != 0 {
			t.Errorf("fetches = %d, want 0 on a start that already has the pin", env.fetchCount())
		}
		want := "assert settings " + mandatoryName + " true on " + filepath.Join(dir, toolName)
		if env.countCalls(want) != 1 {
			t.Errorf("calls = %v, want exactly one %q against the SELECTED artifact", env.called(), want)
		}
		if env.countCalls("assert settings telemetry.enabled false") != 1 {
			t.Error("the best-effort assertions were not applied on the skip-install start")
		}
		if ready, why := m.Ready(); !ready {
			t.Errorf("Ready() = false (%s), want true", why)
		}
	})

	t.Run("a failed reassertion withholds readiness", func(t *testing.T) {
		env := newFakeEnv(t)
		env.placeVersion(pinnedVersion)
		env.onAssert = failAssertion(mandatoryName)
		m := env.manager()

		err := m.Ensure(t.Context())
		if err == nil || !strings.Contains(err.Error(), mandatoryName) {
			t.Fatalf("Ensure error = %v, want one naming %s", err, mandatoryName)
		}
		ready, why := m.Ready()
		if ready || why != ReasonAssertion {
			t.Errorf("Ready() = (%v, %v), want (false, %v)", ready, why, ReasonAssertion)
		}
		// The artifact stays reachable for repair even though it is not ready.
		if got := m.Path(); got == "" {
			t.Error("Path() is empty; the usable artifact must stay available for an in-place repair")
		}
	})

	t.Run("a best-effort failure does not withhold readiness", func(t *testing.T) {
		env := newFakeEnv(t)
		env.placeVersion(pinnedVersion)
		env.onAssert = failAssertion("chat.notificationMethod")
		m := env.manager(func(c *Config) {
			c.Assertions = append(c.Assertions, Assertion{Name: "chat.notificationMethod", Args: []string{"settings", "chat.notificationMethod", "osc9"}})
		})

		if err := m.Ensure(t.Context()); err != nil {
			t.Fatalf("Ensure: %v", err)
		}
		if ready, why := m.Ready(); !ready {
			t.Errorf("Ready() = false (%s), want true: a best-effort assertion is not integrity-relevant", why)
		}
	})
}

// failAssertion returns an onAssert hook that fails only the assertion whose argv
// mentions name.
func failAssertion(name string) func(string, []string) error {
	return func(_ string, args []string) error {
		if slices.Contains(args, name) {
			return errors.New("the assertion command failed")
		}
		return nil
	}
}

// TestPersistedAssertionsOKNeverGatesReadiness pins that the persisted record is
// diagnostic history only. A state file claiming the assertions held must not make
// a manager whose live reassertion failed report ready.
func TestPersistedAssertionsOKNeverGatesReadiness(t *testing.T) {
	env := newFakeEnv(t)
	dir := env.placeVersion(pinnedVersion)
	seed, err := json.Marshal(stateRecord{
		ActiveVersion: pinnedVersion,
		Dir:           dir,
		Pinned:        pinnedVersion,
		AssertionsOK:  true,
		UpdatedAt:     time.Unix(1, 0).UTC(),
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(env.statePath(), seed, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	env.onAssert = failAssertion(mandatoryName)
	m := env.manager()

	if err := m.Ensure(t.Context()); err == nil {
		t.Fatal("Ensure returned nil although a required assertion failed")
	}
	if ready, why := m.Ready(); ready || why != ReasonAssertion {
		t.Errorf("Ready() = (%v, %v), want (false, %v) -- the persisted record must never be the authority",
			ready, why, ReasonAssertion)
	}
	if m.state.AssertionsOK {
		t.Error("State.AssertionsOK stayed true after a failed reassertion; it must record THIS start's result")
	}
}

// TestStateSaveFailureDoesNotAffectReadiness pins that the diagnostic record is
// not on the readiness path: losing it warns, it does not fail an otherwise good
// install.
func TestStateSaveFailureDoesNotAffectReadiness(t *testing.T) {
	logs := captureLogs(t)
	env := newFakeEnv(t)
	env.placeVersion(pinnedVersion)
	env.onRename = failRenameTo(env.statePath())
	m := env.manager()

	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure error = %v, want nil despite the state save failure", err)
	}
	if ready, why := m.Ready(); !ready {
		t.Errorf("Ready() = false (%s), want true", why)
	}
	// Not on the readiness path is not the same as unreported: a volume whose state
	// record silently stops being written leaves an operator reading a stale file.
	if got := logs.at(slog.LevelWarn, "path"); len(got) != 1 || got[0].attrs["path"] != env.statePath() {
		t.Errorf("Warn records naming a path = %v, want one naming %s", got, env.statePath())
	}
	// A failed durable write leaves no debris behind either: the staged temp name is
	// removed on every failure path, so a Root this package shares with another owner
	// does not collect one per failed start.
	tmp := filepath.Join(env.root, "."+toolName+stateSuffix+".tmp")
	if exists(tmp) {
		t.Errorf("Root holds %s, want the staged temp removed after the rename failed", tmp)
	}
}

// failRenameTo returns an onRename hook that fails exactly the rename whose
// destination is target.
func failRenameTo(target string) func(string, string) error {
	return func(_, newpath string) error {
		if newpath == target {
			return errors.New("injected rename failure")
		}
		return nil
	}
}

// TestEnsureWithRetryIsBoundedAndReportsTerminalFailure pins the first half of the
// healing posture: a failing install is retried with growing backoff, the attempts
// are BOUNDED, and the end state is a distinguishable terminal verdict rather than
// an endless loop or a process exit.
func TestEnsureWithRetryIsBoundedAndReportsTerminalFailure(t *testing.T) {
	env := newFakeEnv(t)
	env.archiveLacksArtifacts = true
	m := env.manager(func(c *Config) {
		c.MaxAttempts = 3
	})

	err := m.EnsureWithRetry(t.Context())
	if err == nil {
		t.Fatal("EnsureWithRetry returned nil although every attempt failed")
	}
	if got := env.fetchCount(); got != 3 {
		t.Errorf("fetches = %d, want 3 (one per bounded attempt)", got)
	}
	want := []time.Duration{retryBackoff, 2 * retryBackoff}
	if got := env.sleeps(); len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("backoffs = %v, want %v (doubling, one fewer than the attempts)", got, want)
	}
	if ready, why := m.Ready(); ready || why != ReasonUnavailable {
		t.Errorf("Ready() = (%v, %v), want (false, %v)", ready, why, ReasonUnavailable)
	}
}

// TestEnsureWithRetryStopsEarlyOnShutdown pins that a shutdown during the retry
// loop ends it rather than burning the remaining attempts: once on a cancelled
// context, and once when the backoff wait itself reports the cancellation.
func TestEnsureWithRetryStopsEarlyOnShutdown(t *testing.T) {
	t.Run("a cancelled context stops after the attempt in flight", func(t *testing.T) {
		env := newFakeEnv(t)
		env.archiveLacksArtifacts = true
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		m := env.manager(func(c *Config) { c.MaxAttempts = 4 })

		if err := m.EnsureWithRetry(ctx); err == nil {
			t.Fatal("EnsureWithRetry returned nil although the install failed")
		}
		if got := env.fetchCount(); got != 1 {
			t.Errorf("fetches = %d, want 1: a cancelled context must not start a second attempt", got)
		}
		if got := env.sleeps(); len(got) != 0 {
			t.Errorf("backoffs = %v, want none on a cancelled context", got)
		}
	})

	t.Run("a wait that reports cancellation is returned", func(t *testing.T) {
		env := newFakeEnv(t)
		env.archiveLacksArtifacts = true
		m := env.manager(func(c *Config) { c.MaxAttempts = 4 })
		m.sleep = func(context.Context, time.Duration) error { return context.Canceled }

		err := m.EnsureWithRetry(t.Context())
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("EnsureWithRetry error = %v, want context.Canceled", err)
		}
		if got := env.fetchCount(); got != 1 {
			t.Errorf("fetches = %d, want 1: the loop must stop at the cancelled wait", got)
		}
	})
}

// TestReadinessReasonDistinguishesTheLifecyclePhases pins that a caller gating on
// readiness can tell installing from retrying from terminally failed, which is the
// whole reason [Reason] is an enum rather than a bool.
func TestReadinessReasonDistinguishesTheLifecyclePhases(t *testing.T) {
	tests := map[string]struct {
		phase phase
		want  Reason
	}{
		"idle":                     {phase: phaseIdle, want: ReasonInstalling},
		"installing":               {phase: phaseInstalling, want: ReasonInstalling},
		"retrying":                 {phase: phaseRetrying, want: ReasonRetrying},
		"failed":                   {phase: phaseFailed, want: ReasonUnavailable},
		"ready but nothing active": {phase: phaseReady, want: ReasonUnavailable},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			env := newFakeEnv(t)
			m := env.manager()
			m.setPhase(tc.phase)
			ready, why := m.Ready()
			if ready {
				t.Fatal("Ready() = true with no active version")
			}
			if why != tc.want {
				t.Errorf("reason = %v, want %v", why, tc.want)
			}
		})
	}
}

// TestReasonStringIsEmptyOnlyWhenReady pins the one property a consumer builds its
// own wording on: a withheld verdict always has something to say.
func TestReasonStringIsEmptyOnlyWhenReady(t *testing.T) {
	for r := ReasonReady; r <= ReasonAssertion+1; r++ {
		got := r.String()
		if (r == ReasonReady) != (got == "") {
			t.Errorf("Reason(%d).String() = %q; only ReasonReady may be empty", r, got)
		}
	}
}

// TestRescanMakesAnInPlaceRepairVisible pins the second half of the healing
// posture. A first start that fails with nothing to fall back on leaves the
// consumer up and unready; an operator who repairs the install in place must
// become observable without a fresh process.
func TestRescanMakesAnInPlaceRepairVisible(t *testing.T) {
	env := newFakeEnv(t)
	env.archiveLacksArtifacts = true
	m := env.manager(func(c *Config) { c.MaxAttempts = 2 })

	if err := m.EnsureWithRetry(t.Context()); err == nil {
		t.Fatal("EnsureWithRetry returned nil although every attempt failed")
	}
	if ready, why := m.Ready(); ready || why != ReasonUnavailable {
		t.Fatalf("Ready() = (%v, %v), want (false, %v) before the repair", ready, why, ReasonUnavailable)
	}
	before := env.fetchCount()

	// The repair: an operator restores a complete version directory by hand.
	dir := env.placeVersion(pinnedVersion)

	ok, err := m.Rescan(t.Context())
	if err != nil || !ok {
		t.Fatalf("Rescan = (%v, %v), want (true, nil)", ok, err)
	}
	if ready, why := m.Ready(); !ready {
		t.Errorf("Ready() = false (%s), want true after the in-place repair", why)
	}
	if got := m.Path(); got != filepath.Join(dir, toolName) {
		t.Errorf("Path() = %q, want %q", got, filepath.Join(dir, toolName))
	}
	if env.fetchCount() != before {
		t.Errorf("Rescan downloaded the archive (%d -> %d); it must only re-derive from disk", before, env.fetchCount())
	}
	if m.Version() == "" || m.state.LastError != "" {
		t.Errorf("state = %+v (version %q), want the previous failure cleared", m.state, m.Version())
	}
}

// TestRescanReportsUnreadyWhenTheRepairIsIncomplete pins the negative half: a
// half-restored directory (no sentinel) is not a repair, so Rescan keeps readiness
// withheld instead of activating a partial install.
func TestRescanReportsUnreadyWhenTheRepairIsIncomplete(t *testing.T) {
	env := newFakeEnv(t)
	env.placePartial(pinnedVersion)
	m := env.manager()

	ok, err := m.Rescan(t.Context())
	if ok {
		t.Fatal("Rescan accepted a directory with no completion sentinel")
	}
	if !errors.Is(err, ErrNoVersion) {
		t.Errorf("Rescan error = %v, want ErrNoVersion", err)
	}
	if ready, why := m.Ready(); ready || why != ReasonUnavailable {
		t.Errorf("Ready() = (%v, %v), want (false, %v)", ready, why, ReasonUnavailable)
	}
}

// TestEnsureIsIdempotent pins that a second Ensure on a converged volume downloads
// nothing, keeps the same active version, and still re-asserts every assertion.
func TestEnsureIsIdempotent(t *testing.T) {
	env := newFakeEnv(t)
	m := env.manager()

	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	first := m.Path()
	afterFirst := env.countCalls("assert settings " + mandatoryName)

	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	if got := env.fetchCount(); got != 1 {
		t.Errorf("fetches = %d, want 1 -- the second Ensure must not re-download", got)
	}
	if got := m.Path(); got != first {
		t.Errorf("Path() = %q, want the unchanged %q", got, first)
	}
	if got := env.countCalls("assert settings " + mandatoryName); got <= afterFirst {
		t.Error("the second Ensure did not reassert the required assertion")
	}
}

// TestEnsureWithRetryUsesTheLibraryPolicyWhenTheRetryKnobsAreUnset pins the two retry
// defaults as VALUES rather than as "something non-zero". A MaxAttempts left at zero is
// a retry loop that never runs a single attempt — a start that installs nothing and
// reports no error — and a backoff left at zero is a hot loop against the upstream.
func TestEnsureWithRetryUsesTheLibraryPolicyWhenTheRetryKnobsAreUnset(t *testing.T) {
	env := newFakeEnv(t)
	env.archiveLacksArtifacts = true
	m := env.manager(func(c *Config) {
		c.MaxAttempts = 0
	})

	if err := m.EnsureWithRetry(t.Context()); err == nil {
		t.Fatal("EnsureWithRetry returned nil although every attempt failed")
	}
	if got := env.fetchCount(); got != defaultMaxAttempts {
		t.Errorf("fetches = %d, want %d: one per attempt of the default bound", got, defaultMaxAttempts)
	}
	want := []time.Duration{retryBackoff, 2 * retryBackoff, 4 * retryBackoff}
	if got := env.sleeps(); !slices.Equal(got, want) {
		t.Errorf("backoffs = %v, want %v: the default backoff, doubling", got, want)
	}
}

// TestReadinessReportsInstallingWhileAFreshAttemptIsInFlight pins the lifecycle
// distinction a consumer shows its own users. The FIRST attempt of a run is installing
// rather than retrying, and a manager that has already exhausted its attempts says
// installing again while a new run is in flight rather than still reporting the state it
// gave up in — "we are working on it" and "we gave up" are the two answers a start page
// has to tell apart, and only the phase carries the difference.
func TestReadinessReportsInstallingWhileAFreshAttemptIsInFlight(t *testing.T) {
	env := newFakeEnv(t)
	m := env.manager(func(c *Config) { c.MaxAttempts = 1 })
	var seen []Reason
	env.onFetch = func(io.Writer) error {
		_, why := m.Ready()
		seen = append(seen, why)
		return errors.New("the archive could not be fetched")
	}

	if err := m.EnsureWithRetry(t.Context()); err == nil {
		t.Fatal("EnsureWithRetry returned nil although the fetch failed")
	}
	if len(seen) != 1 || seen[0] != ReasonInstalling {
		t.Fatalf("reasons observed mid-attempt = %v, want [%v] on the first attempt of a fresh manager", seen, ReasonInstalling)
	}

	// The same question asked of a manager that has given up: the run that follows is a
	// fresh attempt, not the terminal state.
	if err := m.EnsureWithRetry(t.Context()); err == nil {
		t.Fatal("EnsureWithRetry returned nil on the second run although the fetch failed")
	}
	if len(seen) != 2 || seen[1] != ReasonInstalling {
		t.Fatalf("reasons observed mid-attempt = %v, want [%v %v]: a new run reports installing, not the state the last one ended in",
			seen, ReasonInstalling, ReasonInstalling)
	}
}

// TestServingAPredecessorSaysThePinIsNotInstalled pins the distinction between the two
// activations. Serving the pinned version is routine; serving a PREDECESSOR because the
// pin could not be installed is a degraded state an operator has to act on, and the
// verdict a consumer reads is "ready" in both cases — so the log line is the only place
// the difference exists.
func TestServingAPredecessorSaysThePinIsNotInstalled(t *testing.T) {
	logs := captureLogs(t)
	env := newFakeEnv(t)
	env.placeVersion(prevVersion)
	env.archiveLacksArtifacts = true
	m := env.manager()

	// The install failure is reported; the previous version still serves.
	if err := m.Ensure(t.Context()); err == nil {
		t.Fatal("Ensure returned nil although the pinned version could not be installed")
	}
	if ready, why := m.Ready(); !ready {
		t.Fatalf("Ready() = false (%s), want true on the previous version", why)
	}
	got := logs.at(slog.LevelWarn, "active")
	if len(got) != 1 {
		t.Fatalf("Warn records naming the active version = %v, want 1 for a start serving a predecessor", got)
	}
	if got[0].attrs["active"] != prevVersion || got[0].attrs["pinned"] != pinnedVersion {
		t.Errorf("Warn named active=%q pinned=%q, want active=%q pinned=%q",
			got[0].attrs["active"], got[0].attrs["pinned"], prevVersion, pinnedVersion)
	}
}

// TestExhaustedRetriesWithNothingUsableIsAnError pins the terminal report. Every
// individual attempt has already been logged as a failure by then; what this line adds
// is that the bounded retries are OVER and nothing is installed, which is the moment an
// operator has to intervene — and a start that ends ready must not emit it.
func TestExhaustedRetriesWithNothingUsableIsAnError(t *testing.T) {
	logs := captureLogs(t)
	env := newFakeEnv(t)
	env.archiveLacksArtifacts = true
	m := env.manager(func(c *Config) { c.MaxAttempts = 2 })

	if err := m.EnsureWithRetry(t.Context()); err == nil {
		t.Fatal("EnsureWithRetry returned nil although every attempt failed")
	}
	got := logs.at(slog.LevelError, "attempts")
	if len(got) != 1 {
		t.Fatalf("Error records naming the attempt bound = %v, want 1 once the retries are exhausted", got)
	}
	if got[0].attrs["attempts"] != "2" {
		t.Errorf("attempts = %q, want %q", got[0].attrs["attempts"], "2")
	}

	// A run that ends ready reports no such thing.
	fine := newFakeEnv(t)
	if err := fine.manager().EnsureWithRetry(t.Context()); err != nil {
		t.Fatalf("EnsureWithRetry on a working install: %v", err)
	}
	if got := logs.at(slog.LevelError, "attempts"); len(got) != 1 {
		t.Errorf("Error records naming the attempt bound = %v, want the count unchanged after a successful run", got)
	}
}

// TestBackoffDoublesAndCaps pins the retry schedule's shape, including the cap that
// stops a long-lived process from waiting hours between attempts.
func TestBackoffDoublesAndCaps(t *testing.T) {
	env := newFakeEnv(t)
	m := env.manager()
	tests := map[int]time.Duration{
		1: retryBackoff,
		2: 2 * retryBackoff,
		3: 4 * retryBackoff,
		4: 8 * retryBackoff,
		5: 16 * retryBackoff,
		6: maxRetryBackoff,
		9: maxRetryBackoff,
	}
	for attempt, want := range tests {
		if got := m.backoff(attempt); got != want {
			t.Errorf("backoff(%d) = %v, want %v", attempt, got, want)
		}
	}
}

// TestSleepCtxHonoursCancellation pins that the backoff wait is cancellable, so a
// shutdown during a retry window does not block on a timer.
func TestSleepCtxHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepCtx(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("sleepCtx error = %v, want context.Canceled", err)
	}
	if err := sleepCtx(t.Context(), time.Millisecond); err != nil {
		t.Errorf("sleepCtx error = %v, want nil", err)
	}
}

// TestProbeAndAssertionsLeadPATHWithTheBinaryDir pins that every command pin
// runs against an installed or staged binary leads PATH with that binary's own
// directory, the PATH a consumer gives it through PathEnv, so what the probe
// and the assertions prove holds where the consumer runs it.
func TestProbeAndAssertionsLeadPATHWithTheBinaryDir(t *testing.T) {
	env := newFakeEnv(t)
	m := env.manager()

	var mu sync.Mutex
	envsByBin := map[string][]string{}
	inner := m.run
	m.run = func(ctx context.Context, c *command) ([]byte, error) {
		mu.Lock()
		envsByBin[c.Path] = append([]string(nil), c.Env...)
		mu.Unlock()
		return inner(ctx, c)
	}

	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(envsByBin) == 0 {
		t.Fatal("no probe or assertion commands ran; the test proved nothing")
	}
	for bin, cmdEnv := range envsByBin {
		want := "PATH=" + filepath.Dir(bin) + string(os.PathListSeparator)
		var found bool
		for _, kv := range cmdEnv {
			if strings.HasPrefix(kv, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("command against %s ran without its directory leading PATH; env = %v", bin, cmdEnv)
		}
	}
}

// TestPathEnvNeverAdmitsTheWorkingDirectory pins the degenerate half of the
// lead-PATH rule. An empty PATH element means the working directory, so
// appending an empty inherited PATH would leave a trailing separator and hand
// the child the calling server's cwd as a search directory, where a bare-name
// exec runs whatever stands there. An empty inherited PATH must therefore
// produce the entry ALONE.
func TestPathEnvNeverAdmitsTheWorkingDirectory(t *testing.T) {
	const entry = "/opt/toolkit-versions/2.14.2"

	tests := map[string]struct {
		inherited string
		entry     string
		want      []string
	}{
		"empty inherited PATH yields the entry alone": {
			inherited: "",
			entry:     entry,
			want:      []string{"PATH=" + entry},
		},
		"inherited PATH follows the entry": {
			inherited: "/usr/local/bin:/usr/bin",
			entry:     entry,
			want:      []string{"PATH=" + entry + string(os.PathListSeparator) + "/usr/local/bin:/usr/bin"},
		},
		"a single inherited element still follows": {
			inherited: "/usr/bin",
			entry:     entry,
			want:      []string{"PATH=" + entry + string(os.PathListSeparator) + "/usr/bin"},
		},
		"no entry yields no overlay at all": {
			inherited: "/usr/bin",
			entry:     "",
			want:      nil,
		},
		"no entry and no inherited PATH yields no overlay either": {
			inherited: "",
			entry:     "",
			want:      nil,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Setenv("PATH", tc.inherited)

			got := pathEnv(tc.entry)
			if !slices.Equal(got, tc.want) {
				t.Errorf("pathEnv(%q) with PATH=%q = %#v, want %#v", tc.entry, tc.inherited, got, tc.want)
			}
			assertNoWorkingDirectoryOnPATH(t, got)
		})
	}
}

// TestPathEnvAndTheProbeOverlayCannotDrift is the reason the rule is one
// unexported composer instead of a sentence in the docs. The library STATED that
// a consumer must lead PATH with PathEntry and then applied that rule three
// times without exporting it once — twice in the consumers, once here for its
// own version probe and settings assertions — and the copy that drifted was this
// package's, which appended an empty inherited PATH. The exported overlay and
// the internal one must therefore be the same value for the active version, in
// both the ordinary and the degenerate case.
func TestPathEnvAndTheProbeOverlayCannotDrift(t *testing.T) {
	env := newFakeEnv(t)
	m := env.manager()

	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	tests := map[string]string{
		"an ordinary inherited PATH": "/usr/local/bin:/usr/bin",
		"no inherited PATH at all":   "",
	}

	for name, inherited := range tests {
		t.Run(name, func(t *testing.T) {
			t.Setenv("PATH", inherited)

			exported := m.PathEnv()
			internal := binPathEnv(m.Path())
			if !slices.Equal(exported, internal) {
				t.Errorf("PathEnv() = %#v but the probe overlay for %s = %#v; the two copies of one rule have drifted",
					exported, m.Path(), internal)
			}
			if want := []string{"PATH=" + m.PathEntry() + pathSuffix(inherited)}; !slices.Equal(exported, want) {
				t.Errorf("PathEnv() = %#v, want %#v", exported, want)
			}
			assertNoWorkingDirectoryOnPATH(t, exported)
			assertNoWorkingDirectoryOnPATH(t, internal)
		})
	}
}

// TestPathEnvIsNilWithoutAnActiveVersion pins the no-overlay case: with nothing
// active there is no directory to lead with, and an overlay reading "PATH=" is
// not a narrower search path but a cwd-only one.
func TestPathEnvIsNilWithoutAnActiveVersion(t *testing.T) {
	env := newFakeEnv(t)
	m := env.manager()

	t.Setenv("PATH", "")
	if got := m.PathEnv(); got != nil {
		t.Errorf("PathEnv() = %#v before any version is active, want nil", got)
	}
}

// pathSuffix is what the inherited PATH contributes to the overlay: nothing when
// it is empty, otherwise the separator and its own value.
func pathSuffix(inherited string) string {
	if inherited == "" {
		return ""
	}
	return string(os.PathListSeparator) + inherited
}

// assertNoWorkingDirectoryOnPATH fails when any produced assignment carries an
// empty PATH element. That is the whole bug expressed as a property: an empty
// element is the current working directory, whether it arrives as a trailing
// separator, a leading one, or a doubled one in the middle.
func assertNoWorkingDirectoryOnPATH(t *testing.T, overlay []string) {
	t.Helper()
	for _, kv := range overlay {
		value, ok := strings.CutPrefix(kv, "PATH=")
		if !ok {
			continue
		}
		if strings.HasSuffix(value, string(os.PathListSeparator)) {
			t.Errorf("PATH=%q ends in a separator, so its last element is empty and resolves to the working directory", value)
		}
		for i, element := range filepath.SplitList(value) {
			if element == "" {
				t.Errorf("PATH=%q has an empty element at index %d, which resolves to the working directory", value, i)
			}
		}
	}
}

// The operation slot has two halves and neither is sufficient alone: WAITING for
// it honours the caller's context, and the work that has been ADMITTED does not.
// Consumers were compensating for the absence of both with their own admission
// gates plus a context.WithoutCancel wrapper, which is library knowledge that
// nothing kept in step (one of two consumers had neither).

// TestOperationWaitIsCancellable pins that a caller giving up while queued returns
// promptly instead of holding a goroutine until an operation it never started ends.
// It runs in a synctest bubble because "still waiting" is a negative assertion,
// only probabilistic on a real clock; synctest.Wait returns once every goroutine is
// durably blocked, which makes reading the channel after it a proof. The queued
// caller parks on a channel send inside a select, which is durable; a goroutine
// spinning or parked on a socket would hang the bubble instead.
func TestOperationWaitIsCancellable(t *testing.T) {
	env := newFakeEnv(t)
	synctest.Test(t, func(t *testing.T) {
		m := env.manager()

		// Occupy the slot exactly as a running operation would.
		if err := m.acquireOp(t.Context()); err != nil {
			t.Fatalf("acquireOp: %v", err)
		}
		defer m.releaseOp()

		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- m.acquireOp(ctx) }()

		// It must still be waiting: the slot is taken.
		synctest.Wait()
		select {
		case err := <-done:
			t.Fatalf("acquireOp returned %v while the slot was held", err)
		default:
		}

		cancel()
		synctest.Wait()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("acquireOp err = %v, want context.Canceled", err)
			}
		default:
			t.Fatal("acquireOp did not return after its context was cancelled; the wait is not cancellable")
		}
	})
}

// A queued Rescan whose caller disconnects must not run, and must not disturb the
// manager's state.
func TestRescanQueuedCallerCanAbandon(t *testing.T) {
	env := newFakeEnv(t)
	env.placeVersion(pinnedVersion)
	m := env.manager()
	if _, err := m.Rescan(t.Context()); err != nil {
		t.Fatalf("priming Rescan: %v", err)
	}
	readyBefore, _ := m.Ready()

	if err := m.acquireOp(t.Context()); err != nil {
		t.Fatalf("acquireOp: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the caller is already gone

	done := make(chan error, 1)
	go func() {
		_, err := m.Rescan(ctx)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Rescan err = %v, want context.Canceled for an abandoned queued caller", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an abandoned queued Rescan never returned")
	}
	m.releaseOp()

	if ready, why := m.Ready(); ready != readyBefore {
		t.Errorf("Ready() = (%v, %v) after an abandoned rescan, want it unchanged (%v)", ready, why, readyBefore)
	}
}

// The half that matters most: an ADMITTED rescan finishes on its own terms. Its
// probes run through exec.CommandContext and a failed probe sweep records the
// release unavailable, so honouring the caller's cancellation here would let a
// `curl --max-time` turn a healthy manager into an unready one.
func TestAdmittedRescanIgnoresCallerCancellation(t *testing.T) {
	env := newFakeEnv(t)
	env.placeVersion(pinnedVersion)
	m := env.manager()

	// Cancelled BEFORE the call, so the detachment is the only thing that can
	// make this succeed: an undetached implementation fails every probe.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ok, err := m.Rescan(ctx)
	if err != nil || !ok {
		t.Fatalf("Rescan = (%v, %v) with an already-cancelled caller, want (true, nil): the admitted work must be detached", ok, err)
	}
	if ready, why := m.Ready(); !ready {
		t.Errorf("Ready() = false (%s) after a rescan whose caller had cancelled; the cancellation cleared the active version", why)
	}
}

// Ensure deliberately does NOT detach: it is driven by boot and shutdown, where
// cancelling a long download is exactly what the caller wants. Only the wait
// became cancellable.
func TestEnsureStillHonoursCancellation(t *testing.T) {
	env := newFakeEnv(t)
	m := env.manager()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := m.Ensure(ctx); err == nil {
		t.Fatal("Ensure returned nil for an already-cancelled context; a shutdown could no longer stop an install")
	}
}

// TestNewSnapshotsTheCallerConfig pins that every reference-bearing field is
// copied, not just the ones read at construction: the argv of each assertion,
// ProbeArgs, TrustedUIDs and both Purge slices (the DELETE list, aliased across
// the validation that just approved it) are read long after New returns. Each is
// mutated in place, which is the write an alias would carry.
func TestNewSnapshotsTheCallerConfig(t *testing.T) {
	env := newFakeEnv(t)
	cfg := env.config(func(c *Config) {
		c.Purge = &Purge{Artifacts: []string{"legacy-artifact"}, Names: []string{toolName}, Marker: legacyMarker}
		c.Assertions = append(c.Assertions, Assertion{Name: "extra", Args: []string{"settings", "extra", "true"}})
		c.TrustedUIDs = []int{4000}
	})
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Everything a caller could reach into after construction.
	cfg.Digests["amd64"] = "mutated"
	cfg.TrustedUIDs[0] = 4242
	cfg.ArchTokens["amd64"] = "mutated"
	cfg.ProbeArgs[0] = "mutated"
	for i := range cfg.Assertions {
		cfg.Assertions[i].Args[0] = "mutated"
	}
	cfg.Purge.Artifacts[0] = "../escaped"
	cfg.Purge.Names[0] = "mutated"

	checks := map[string]string{
		"Digests":         m.cfg.Digests["amd64"],
		"ArchTokens":      m.cfg.ArchTokens["amd64"],
		"ProbeArgs":       m.cfg.ProbeArgs[0],
		"Purge.Artifacts": m.cfg.Purge.Artifacts[0],
		"Purge.Names":     m.cfg.Purge.Names[0],
		"resolved digest": m.digest,
	}
	for field, got := range checks {
		if got == "mutated" || got == "../escaped" {
			t.Errorf("%s reads %q after the caller mutated its own Config, so New aliased it", field, got)
		}
	}
	for _, a := range m.cfg.Assertions {
		if slices.Contains(a.Args, "mutated") {
			t.Errorf("assertion %q argv reads %v after the caller mutated its own Config, so New aliased it", a.Name, a.Args)
		}
	}
	if slices.Contains(m.trust.UIDs, 4242) || slices.Contains(m.cfg.TrustedUIDs, 4242) {
		t.Errorf("the trust set reads %v/%v, so New aliased it", m.trust.UIDs, m.cfg.TrustedUIDs)
	}
}

// TestNewUsesTheConfiguredLogger pins Config.Logger: set, it receives the
// manager's lines and slog.Default none; nil, the manager keeps the default
// that was installed when New ran.
func TestNewUsesTheConfiguredLogger(t *testing.T) {
	t.Run("set", func(t *testing.T) {
		def := captureLogs(t)
		own := &logRecorder{}
		m := newFakeEnv(t).manager(func(c *Config) { c.Logger = slog.New(own) })
		if err := m.Ensure(t.Context()); err != nil {
			t.Fatalf("Ensure: %v", err)
		}
		if got := own.messages(slog.LevelInfo); !slices.Contains(got, "version active") {
			t.Errorf("the configured logger saw %v, want the install's lines", got)
		}
		if got := def.messages(slog.LevelInfo); len(got) != 0 {
			t.Errorf("slog.Default saw %v, want nothing while Config.Logger is set", got)
		}
	})
	t.Run("nil", func(t *testing.T) {
		atNew := captureLogs(t)
		m := newFakeEnv(t).manager()
		later := captureLogs(t)
		if err := m.Ensure(t.Context()); err != nil {
			t.Fatalf("Ensure: %v", err)
		}
		if got := atNew.messages(slog.LevelInfo); !slices.Contains(got, "version active") {
			t.Errorf("the default installed at New saw %v, want the install's lines", got)
		}
		if got := later.messages(slog.LevelInfo); len(got) != 0 {
			t.Errorf("a default installed after New saw %v, want nothing", got)
		}
	})
}

// TestFinishRecordsTheActivationOnlyInATreeItMayMutate pins that finish writes
// the activation time only under a clean custody verdict: under a refusal the
// selected directory keeps its mtime, under a clean one it takes the clock's.
func TestFinishRecordsTheActivationOnlyInATreeItMayMutate(t *testing.T) {
	for _, refused := range []bool{true, false} {
		t.Run(fmt.Sprintf("refused %v", refused), func(t *testing.T) {
			env := newFakeEnv(t)
			dir := env.placeVersion(prevVersion)
			before := time.Unix(1600000000, 0)
			if err := os.Chtimes(dir, before, before); err != nil {
				t.Fatalf("Chtimes: %v", err)
			}
			m := env.manager()
			sel, ok := m.selectActive(t.Context())
			if !ok || sel.version != prevVersion {
				t.Fatalf("selectActive = %+v, %v, want %s", sel, ok, prevVersion)
			}
			if refused {
				m.setCustody(errors.New("the installation root is writable by group 1000"))
			}
			_ = m.finish(t.Context(), sel, errors.New("the pin did not install"))
			fi, err := os.Stat(dir)
			if err != nil {
				t.Fatalf("Stat: %v", err)
			}
			want := m.now()
			if refused {
				want = before
			}
			if !fi.ModTime().Equal(want) {
				t.Errorf("mtime = %v, want %v", fi.ModTime(), want)
			}
		})
	}
}
