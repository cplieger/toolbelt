//go:build linux

package pin

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestEnsureInstallsPinnedVersion pins the happy path end to end: the archive is
// fetched once, the version directory holds the required and optional artifacts
// plus the sentinel, the sentinel names the pin, the manager is ready, and
// Path/PathEntry point INSIDE the version directory rather than at the convenience
// link.
func TestEnsureInstallsPinnedVersion(t *testing.T) {
	env := newFakeEnv(t)
	m := env.manager()

	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if env.fetchCount() != 1 {
		t.Errorf("fetches = %d, want 1", env.fetchCount())
	}
	dir := env.versionDir(pinnedVersion)
	for _, name := range []string{toolName, toolSidecar, toolExtra, sentinelName} {
		if !exists(filepath.Join(dir, name)) {
			t.Errorf("%s missing from the published version directory", name)
		}
	}
	raw, err := os.ReadFile(filepath.Join(dir, sentinelName))
	if err != nil {
		t.Fatalf("read sentinel: %v", err)
	}
	if got := strings.TrimSpace(string(raw)); got != pinnedVersion {
		t.Errorf("sentinel = %q, want %q", got, pinnedVersion)
	}
	if ready, why := m.Ready(); !ready {
		t.Errorf("Ready() = false (%s), want true", why)
	}
	if got, want := m.Path(), filepath.Join(dir, toolName); got != want {
		t.Errorf("Path() = %q, want the absolute version-directory path %q", got, want)
	}
	if got := m.PathEntry(); got != dir {
		t.Errorf("PathEntry() = %q, want %q", got, dir)
	}
	if !exists(env.statePath()) {
		t.Error("the diagnostic state record was not written")
	}
}

// TestArchiveURLRendersBothPlaceholders pins the one string a profile supplies
// that decides what is downloaded: {version} from the pin, {arch} from the
// resolved architecture's publisher token.
func TestArchiveURLRendersBothPlaceholders(t *testing.T) {
	tests := map[string]struct {
		goarch string
		want   string
	}{
		"amd64": {goarch: "amd64", want: "https://example.invalid/2.14.2/tool-x86_64-linux.zip"},
		"arm64": {goarch: "arm64", want: "https://example.invalid/2.14.2/tool-aarch64-linux.zip"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			env := newFakeEnv(t)
			m := env.manager(func(c *Config) { c.goarch = tc.goarch })
			if got := m.archiveURL(); got != tc.want {
				t.Errorf("archiveURL() = %q, want %q", got, tc.want)
			}
		})
	}

	t.Run("Config.URLTemplate overrides the release's", func(t *testing.T) {
		env := newFakeEnv(t)
		m := env.manager(func(c *Config) { c.URLTemplate = "http://mirror.invalid/{arch}/{version}/a.zip" })
		if got, want := m.archiveURL(), "http://mirror.invalid/x86_64-linux/2.14.2/a.zip"; got != want {
			t.Errorf("archiveURL() = %q, want %q", got, want)
		}
	})
}

// TestEnsureDigestMismatchPlacesNothing pins the refusal: a body that does not
// match the pinned digest yields a typed ErrDigestMismatch, and NOTHING is placed
// under the installation root -- no version directory, no staging tree.
// Verification happens before anything reaches the persistent volume, so a mismatch
// cannot leave a candidate behind for a later start to trust.
func TestEnsureDigestMismatchPlacesNothing(t *testing.T) {
	env := newFakeEnv(t)
	env.onFetch = func(dst io.Writer) error {
		_, err := dst.Write([]byte("not the pinned archive"))
		return err
	}
	m := env.manager()

	err := m.Ensure(t.Context())
	if err == nil || !strings.Contains(err.Error(), "archive SHA-256 mismatch") {
		t.Fatalf("Ensure error = %v, want the digest mismatch", err)
	}
	if entries, rerr := os.ReadDir(env.versionsRoot()); rerr == nil && len(entries) != 0 {
		t.Errorf("installation root holds %v, want nothing placed on a digest mismatch", entries)
	}
	if env.countCalls("installer") != 0 {
		t.Error("the archive's installer ran despite the digest mismatch")
	}
	if ready, why := m.Ready(); ready || why != ReasonInstalling {
		t.Errorf("Ready() = (%v, %v), want (false, %v)", ready, why, ReasonInstalling)
	}
}

// TestDigestIsSelectedPerArchitecture pins per-arch digest selection: the digest
// pinned for one architecture must never satisfy another's install. A swapped pair
// is the exact mistake a hand-edited pin bump makes, and it has to fail rather than
// install the wrong artifact.
func TestDigestIsSelectedPerArchitecture(t *testing.T) {
	amd := strings.Repeat("a", 64)
	arm := strings.Repeat("b", 64)
	tests := map[string]struct {
		goarch string
		want   string
		ok     bool
	}{
		"amd64 takes its own pin":  {goarch: "amd64", want: amd, ok: true},
		"arm64 takes its own pin":  {goarch: "arm64", want: arm, ok: true},
		"an unmapped arch refuses": {goarch: "riscv64"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			env := newFakeEnv(t)
			m, err := New(env.config(func(c *Config) {
				c.goarch = tc.goarch
				c.Digests = map[string]string{"amd64": amd, "arm64": arm}
			}))
			switch {
			case tc.ok && err != nil:
				t.Fatalf("New: %v", err)
			case !tc.ok:
				if err == nil || !strings.Contains(err.Error(), "unsupported architecture") {
					t.Fatalf("error = %v, want the unsupported architecture", err)
				}
			case m.digest != tc.want:
				t.Errorf("digest = %q, want %q", m.digest, tc.want)
			}
		})
	}
}

// TestEnsureSyncFailureAtEveryProtocolPointRetainsPreviousVersion pins the
// durability protocol. Atomic visibility is not crash durability, so the install
// syncs every file, then the sentinel, then the staged directory, then -- after the
// rename -- the installation root. A failure at ANY of those points must fail the
// install and leave the complete version already on the volume active and ready.
//
// Each case names one sync point by the path the manager syncs there, so a
// reordering of the protocol that skips a sync makes the matching case fail.
func TestEnsureSyncFailureAtEveryProtocolPointRetainsPreviousVersion(t *testing.T) {
	injected := errors.New("injected sync failure")
	tests := map[string]struct {
		// match reports whether the path is the protocol point under test.
		match func(root, path string) bool
		// published is whether the pinned directory survives the failure. A
		// failure before the rename leaves nothing; a failure syncing the PARENT
		// happens after it, and the directory is durable except for its parent
		// entry, which the next start re-probes.
		published bool
	}{
		"a required artifact": {
			match: func(_, path string) bool {
				return filepath.Base(path) == toolName && strings.Contains(path, stagePrefix)
			},
		},
		"an optional artifact": {
			match: func(_, path string) bool {
				return filepath.Base(path) == toolExtra && strings.Contains(path, stagePrefix)
			},
		},
		"the completion sentinel": {
			match: func(_, path string) bool { return filepath.Base(path) == sentinelName },
		},
		"the staged version directory": {
			match: func(_, path string) bool {
				return filepath.Base(path) == "v" && strings.Contains(path, stagePrefix)
			},
		},
		"the installation root": {
			match:     func(root, path string) bool { return path == root },
			published: true,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			env := newFakeEnv(t)
			prev := env.placeVersion(prevVersion)
			root := env.versionsRoot()
			env.onSync = func(path string) error {
				if tc.match(root, path) {
					return injected
				}
				return nil
			}
			m := env.manager()

			err := m.Ensure(t.Context())
			if !errors.Is(err, injected) {
				t.Fatalf("Ensure error = %v, want the injected sync failure", err)
			}
			// The previous complete version is retained and serving: a sync
			// failure must never cost the volume its working install.
			if !exists(filepath.Join(prev, toolName)) {
				t.Error("the previous complete version was destroyed by a failed install")
			}
			if ready, why := m.Ready(); !ready {
				t.Errorf("Ready() = false (%s), want true on the retained previous version", why)
			}
			if got := m.Version(); got != prevVersion {
				t.Errorf("Version() = %q, want %q", got, prevVersion)
			} else if m.state.LastError == "" {
				t.Error("the state record's LastError is empty; the failed install must be recorded for diagnosis")
			}
			if got := exists(env.versionDir(pinnedVersion)); got != tc.published {
				t.Errorf("pinned directory exists = %v, want %v", got, tc.published)
			}
			// No staging tree may survive a failed install.
			for _, entry := range env.versionDirs() {
				if strings.HasPrefix(entry, stagePrefix) {
					t.Errorf("staging tree %q survived a failed install", entry)
				}
			}
		})
	}
}

// TestEnsurePublishRenameFailureKeepsPreviousActive pins the publish boundary: when
// the single same-filesystem rename that makes a version visible fails, the install
// fails and the previously complete version stays selected. There is no
// half-published state to fall into, because the rename IS the publication.
func TestEnsurePublishRenameFailureKeepsPreviousActive(t *testing.T) {
	env := newFakeEnv(t)
	prev := env.placeVersion(prevVersion)
	target := env.versionDir(pinnedVersion)
	env.onRename = failRenameTo(target)
	m := env.manager()

	err := m.Ensure(t.Context())
	if err == nil || !strings.Contains(err.Error(), "publishing the version directory") {
		t.Fatalf("Ensure error = %v, want the injected publish-rename failure", err)
	}
	if exists(target) {
		t.Error("the pinned version directory exists although the publish rename failed")
	}
	if !exists(filepath.Join(prev, toolName)) {
		t.Fatal("the previous complete version was destroyed by a failed publish")
	}
	if ready, why := m.Ready(); !ready {
		t.Errorf("Ready() = false (%s), want true on the previous version", why)
	}
	if got := m.Path(); got != filepath.Join(prev, toolName) {
		t.Errorf("Path() = %q, want the previous version's artifact %q", got, filepath.Join(prev, toolName))
	}
}

// TestEnsureFailedInstallWithNoPreviousVersionIsUnready pins the other half of the
// failure posture: with nothing on the volume to fall back to, readiness is
// withheld, the reason distinguishes the lifecycle state, and no partial directory
// is left for a later start to trust.
func TestEnsureFailedInstallWithNoPreviousVersionIsUnready(t *testing.T) {
	env := newFakeEnv(t)
	env.installerFails = true
	m := env.manager()

	if err := m.Ensure(t.Context()); err == nil {
		t.Fatal("Ensure returned nil although the installer produced nothing")
	}
	if ready, why := m.Ready(); ready || why != ReasonInstalling {
		t.Errorf("Ready() = (%v, %v), want (false, %v)", ready, why, ReasonInstalling)
	}
	if got := m.Path(); got != "" {
		t.Errorf("Path() = %q, want empty when nothing is active", got)
	}
	if dirs := env.versionDirs(); len(dirs) != 0 {
		t.Errorf("installation root holds %v, want nothing", dirs)
	}
}

// TestEnsureRefusesAStagedArtifactAtTheWrongVersion pins the staged gate: a
// candidate that installs cleanly but reports a version other than the pin is never
// published, so a mismatched upstream artifact cannot become a version directory
// named after the pin.
func TestEnsureRefusesAStagedArtifactAtTheWrongVersion(t *testing.T) {
	env := newFakeEnv(t)
	env.produces[toolName] = "9.9.9"
	m := env.manager()

	err := m.Ensure(t.Context())
	if err == nil || !strings.Contains(err.Error(), "9.9.9") {
		t.Fatalf("Ensure error = %v, want a refusal naming the staged version", err)
	}
	if exists(env.versionDir(pinnedVersion)) {
		t.Error("a wrongly versioned candidate was published under the pinned name")
	}
}

// TestEnsureRefusesToPublishWhenARequiredAssertionFails pins the integrity gate: a
// candidate a required assertion cannot hold on is never published, so the
// guarantee is proved BEFORE the version becomes selectable rather than after.
func TestEnsureRefusesToPublishWhenARequiredAssertionFails(t *testing.T) {
	env := newFakeEnv(t)
	env.onAssert = failAssertion(mandatoryName)
	m := env.manager()

	err := m.Ensure(t.Context())
	if err == nil || !strings.Contains(err.Error(), mandatoryName) {
		t.Fatalf("Ensure error = %v, want a refusal naming %s", err, mandatoryName)
	}
	if exists(env.versionDir(pinnedVersion)) {
		t.Error("a candidate whose required assertion does not hold was published")
	}
}

// TestEnsureInstallsFromAnArchiveThatAlreadyHoldsTheArtifacts pins that the
// artifacts come straight out of ArtifactDir in the archive, nothing else from it
// is published, and NO subprocess runs except the version probe and the assertions.
func TestEnsureInstallsFromAnArchiveThatAlreadyHoldsTheArtifacts(t *testing.T) {
	env := newFakeEnv(t)
	env.release.ArtifactDir = "payload"
	env.useArchive(buildZip(t, map[string]zipEntry{
		"payload/" + toolName:    {body: fakeBinaryBody(pinnedVersion), mode: 0o755},
		"payload/" + toolSidecar: {body: fakeBinaryBody(pinnedVersion), mode: 0o755},
		"payload/NOTICE":         {body: "docs\n", mode: 0o644},
	}))
	m := env.manager(func(c *Config) { c.Optional = nil })

	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	for _, call := range env.called() {
		if !strings.HasPrefix(call, "probe ") && !strings.HasPrefix(call, "assert ") &&
			!strings.HasPrefix(call, "fetch ") && !strings.HasPrefix(call, "fsync ") &&
			!strings.HasPrefix(call, "rename ") {
			t.Errorf("unexpected boundary crossing %q", call)
		}
	}
	dir := env.versionDir(pinnedVersion)
	for _, name := range []string{toolName, toolSidecar, sentinelName} {
		if !exists(filepath.Join(dir, name)) {
			t.Errorf("%s missing from the published version directory", name)
		}
	}
	if exists(filepath.Join(dir, "NOTICE")) {
		t.Error("a non-artifact archive entry was published into the version directory")
	}
	if ready, why := m.Ready(); !ready {
		t.Errorf("Ready() = false (%s), want true", why)
	}
}

// archiveCandidateNames lists every entry directly under the installation root
// that could name a downloaded archive.
func archiveCandidateNames(t *testing.T, versionsRoot string) []string {
	t.Helper()
	entries, err := os.ReadDir(versionsRoot)
	if err != nil {
		t.Fatalf("ReadDir the installation root: %v", err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".download") {
			out = append(out, e.Name())
		}
	}
	return out
}

// TestEnsureRefusesAnArchiveItCannotUnpack pins that an archive whose digest
// matches but which internal/unpack refuses aborts the install and publishes
// nothing.
func TestEnsureRefusesAnArchiveItCannotUnpack(t *testing.T) {
	env := newFakeEnv(t)
	env.useArchive([]byte("not a zip archive"))
	m := env.manager()

	err := m.Ensure(t.Context())
	if err == nil || !strings.Contains(err.Error(), "unpacking the archive") {
		t.Fatalf("Ensure error = %v, want the unpack refusal", err)
	}
	if dirs := env.versionDirs(); len(dirs) != 0 {
		t.Errorf("installation root holds %v, want nothing", dirs)
	}
}

// TestDownloadedArchiveHasNoNameWhileItIsBeingUsed pins the TOCTOU fix: the
// archive is unlinked the instant it exists, so while the staged artifact is
// probed NOTHING in the installation tree refers to those bytes.
func TestDownloadedArchiveHasNoNameWhileItIsBeingUsed(t *testing.T) {
	env := newFakeEnv(t)
	var namesDuringProbe []string
	env.onProbe = func(path string) ([]byte, error) {
		namesDuringProbe = append(namesDuringProbe, archiveCandidateNames(t, env.versionsRoot())...)
		return env.probeAnswer(path)
	}
	m := env.manager()

	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if len(namesDuringProbe) != 0 {
		t.Errorf("the installation tree still names the archive as %v; a name is something another principal can repoint", namesDuringProbe)
	}
}

// TestHTTPFetchRefusesEmptyAndNonOK pins the fetch boundary's two cheap refusals.
// An empty body is a partial download, and reporting it as such beats letting the
// digest check render it as a mismatch, which points the operator at the pin
// instead of the transfer.
func TestHTTPFetchRefusesEmptyAndNonOK(t *testing.T) {
	tests := map[string]struct {
		handler http.HandlerFunc
		want    string
	}{
		"empty body": {
			handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) },
			want:    "empty",
		},
		"not found": {
			handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) },
			want:    "unexpected status",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()
			err := httpFetch(t.Context(), srv.URL, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("httpFetch error = %v, want one mentioning %q", err, tc.want)
			}
		})
	}
}

// TestHTTPFetchStreamsABodyThrough pins the happy fetch: the bytes arrive
// unmodified, which is what the digest is then computed over.
func TestHTTPFetchStreamsABodyThrough(t *testing.T) {
	body := strings.Repeat("payload", 1000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()
	var got strings.Builder
	if err := httpFetch(t.Context(), srv.URL, &got); err != nil {
		t.Fatalf("httpFetch: %v", err)
	}
	if got.String() != body {
		t.Errorf("fetched %d bytes, want %d identical bytes", got.Len(), len(body))
	}
}

// TestCopyWithStallGuardAbortsAStalledTransfer pins the stall watchdog. A flat
// absolute deadline on a large download is a bandwidth floor rather than a hang
// guard, so the transfer is bounded by LACK OF PROGRESS instead.
func TestCopyWithStallGuardAbortsAStalledTransfer(t *testing.T) {
	release := make(chan struct{})
	cancelled := false
	cancel := func() {
		if !cancelled {
			cancelled = true
			close(release)
		}
	}
	first := true
	src := readerFunc(func(p []byte) (int, error) {
		if first {
			first = false
			p[0] = 'x'
			return 1, nil
		}
		<-release // unblocks only when the watchdog cancels
		return 0, errors.New("context canceled")
	})

	err := copyWithStallGuard(cancel, io.Discard, src, 20*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "no progress") {
		t.Fatalf("copyWithStallGuard error = %v, want a no-progress abort", err)
	}
	if !cancelled {
		t.Error("the watchdog did not cancel the request context")
	}
}

// TestEnsureInstallsEveryOptionalArtifactAnArchiveProvides pins the Optional contract
// on the ordinary shape for a package whose extras ship in the same archive: more
// optional artifacts than required ones. "Installed when the archive provides it" is
// the contract Optional's own doc states, and it is per artifact rather than per
// archive.
func TestEnsureInstallsEveryOptionalArtifactAnArchiveProvides(t *testing.T) {
	const secondExtra = "toolkit-doc"
	env := newEnv(t, toolRelease(), nil, nil, []string{toolSidecar, toolExtra, secondExtra})
	env.produces = map[string]string{
		toolName:    pinnedVersion,
		toolSidecar: pinnedVersion,
		toolExtra:   pinnedVersion,
		secondExtra: pinnedVersion,
	}
	m := env.manager()

	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	dir := env.versionDir(pinnedVersion)
	for _, name := range []string{toolName, toolSidecar, toolExtra, secondExtra} {
		if !exists(filepath.Join(dir, name)) {
			t.Errorf("%s missing from the published version directory", name)
		}
	}
}

// TestCopyWithStallGuardKeepsASlowButProgressingTransfer pins the other side of the
// watchdog. The bound is LACK of progress, not elapsed time, so a transfer slower than
// the window overall must run to completion: aborting it would turn the guard back into
// the bandwidth floor an absolute deadline already is.
func TestCopyWithStallGuardKeepsASlowButProgressingTransfer(t *testing.T) {
	const window = 100 * time.Millisecond
	const chunks = 8
	reads := 0
	src := readerFunc(func(p []byte) (int, error) {
		if reads == chunks {
			return 0, io.EOF
		}
		reads++
		// A slow upstream: each chunk arrives well inside the window, while the
		// transfer as a whole takes considerably longer than one.
		time.Sleep(window / 4)
		p[0] = 'x'
		return 1, nil
	})

	var got bytes.Buffer
	if err := copyWithStallGuard(func() {}, &got, src, window); err != nil {
		t.Fatalf("copyWithStallGuard error = %v, want nil: every read delivered bytes inside the window", err)
	}
	if got.Len() != chunks {
		t.Errorf("copied %d bytes, want %d", got.Len(), chunks)
	}
}

// TestCopyWithStallGuardTreatsAReadYieldingNothingAsNoProgress pins what counts as
// progress. io.Reader's own contract calls a zero count with a nil error "nothing
// happened", so counting it would let an upstream hold a transfer open indefinitely
// without ever sending a byte — the exact hang the watchdog exists to bound.
func TestCopyWithStallGuardTreatsAReadYieldingNothingAsNoProgress(t *testing.T) {
	const window = 100 * time.Millisecond
	const emptyReads = 8
	reads := 0
	src := readerFunc(func(p []byte) (int, error) {
		if reads == emptyReads {
			p[0] = 'x'
			return 1, io.EOF
		}
		reads++
		time.Sleep(window / 4)
		return 0, nil
	})

	err := copyWithStallGuard(func() {}, io.Discard, src, window)
	if err == nil || !strings.Contains(err.Error(), "no progress") {
		t.Fatalf("copyWithStallGuard error = %v, want a no-progress abort", err)
	}
}

// TestFsyncPathReportsAMissingPathAsSuch pins the classification of the one failure
// the sync helper can be handed: a name that is not there. The seam's error is what a
// caller reports to an operator, and "no such file" is what distinguishes a tree that
// was never created from a volume that will not commit.
func TestFsyncPathReportsAMissingPathAsSuch(t *testing.T) {
	err := fsyncPath(filepath.Join(t.TempDir(), "absent"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("fsyncPath on a missing path = %v, want an error wrapping fs.ErrNotExist", err)
	}
}

// TestTheProfileNoticeIsLoggedOncePerInstall pins the one log line the profile itself
// supplies. A Notice is how a consumer discharges an obligation it has taken on — a
// third-party licence acceptance, typically — so an install that quietly stops emitting
// it retires that obligation without anyone deciding to.
func TestTheProfileNoticeIsLoggedOncePerInstall(t *testing.T) {
	logs := captureLogs(t)
	env := newFakeEnv(t)
	notice := env.release.Notice
	if notice == "" {
		t.Fatal("the profile declares no notice, so this fixture proves nothing")
	}

	if err := env.manager().Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if got := logs.messages(slog.LevelInfo); !slices.Contains(got, notice) {
		t.Errorf("Info messages = %v, want one that is the profile's own notice %q", got, notice)
	}

	// And a profile declaring none does not log an empty line in its place.
	quiet := newFakeEnv(t)
	quiet.release.Notice = ""
	if err := quiet.manager().Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure with no notice declared: %v", err)
	}
	if got := logs.messages(slog.LevelInfo); slices.Contains(got, "") {
		t.Errorf("Info messages = %v, want no empty message for a profile that declares no notice", got)
	}
}

// TestWriteFileDurablyLeavesNoTempOnFailure pins that the durable-write helper
// cleans up after itself: a failed sync or rename must not leave a dot-prefixed
// temp file next to the record it failed to write.
func TestWriteFileDurablyLeavesNoTempOnFailure(t *testing.T) {
	target := "record.json"
	tests := map[string]func(env *fakeEnv, dir string){
		"sync fails": func(env *fakeEnv, dir string) {
			env.onSync = func(path string) error {
				if strings.Contains(path, target) {
					return errors.New("injected sync failure")
				}
				return nil
			}
		},
		"rename fails": func(env *fakeEnv, dir string) {
			env.onRename = failRenameTo(filepath.Join(dir, target))
		},
	}
	for name, arrange := range tests {
		t.Run(name, func(t *testing.T) {
			env := newFakeEnv(t)
			dir := filepath.Join(env.root, "records")
			arrange(env, dir)
			m := env.manager()

			if err := m.writeFileDurably(filepath.Join(dir, target), []byte("x"), fileMode); err == nil {
				t.Fatal("writeFileDurably returned nil despite the injected failure")
			}
			if exists(filepath.Join(dir, "."+target+".tmp")) {
				t.Error("the staged temp file survived the failure")
			}
		})
	}
}

// TestExecRunnerBoundsAndIsolatesASubprocess pins the production runner, the one
// boundary the harness replaces everywhere else. Every subprocess this library
// spawns — the archive's installer, the version probe, every assertion — goes
// through it, so its three properties are worth pinning directly: the argv is
// passed as separate elements with no shell in the path, the extra environment is
// appended rather than replacing the process environment, and the timeout bounds a
// command that never returns.
func TestExecRunnerBoundsAndIsolatesASubprocess(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("no POSIX shell available: %v", err)
	}
	// Shortened for the two timeout cases below; without cmd.WaitDelay they run
	// for the wedged command's full lifetime instead, which is what they detect.
	restore := waitDelay
	waitDelay = 100 * time.Millisecond
	t.Cleanup(func() { waitDelay = restore })

	t.Run("returns stdout and passes argv unsplit", func(t *testing.T) {
		out, err := execRunner(t.Context(), &command{
			Path:    sh,
			Args:    []string{"-c", `printf '%s\n' "$1"`, "sh", "one two; three"},
			Timeout: 10 * time.Second,
		})
		if err != nil {
			t.Fatalf("execRunner: %v", err)
		}
		// A shell would have split on the space and the semicolon; the runner
		// hands the whole string over as one argv element.
		if got := strings.TrimSpace(string(out)); got != "one two; three" {
			t.Errorf("stdout = %q, want the argument passed through unsplit", got)
		}
	})

	t.Run("appends the extra environment to the process environment", func(t *testing.T) {
		out, err := execRunner(t.Context(), &command{
			Path:    sh,
			Args:    []string{"-c", `printf '%s|%s\n' "$PINSTALL_TEST_HOME" "${PATH:+set}"`},
			Env:     []string{"PINSTALL_TEST_HOME=/private/home"},
			Timeout: 10 * time.Second,
		})
		if err != nil {
			t.Fatalf("execRunner: %v", err)
		}
		if got, want := strings.TrimSpace(string(out)), "/private/home|set"; got != want {
			t.Errorf("output = %q, want %q (the extra variable present AND PATH inherited)", got, want)
		}
	})

	t.Run("a non-zero exit is an error", func(t *testing.T) {
		if _, err := execRunner(t.Context(), &command{
			Path: sh, Args: []string{"-c", "exit 3"}, Timeout: 10 * time.Second,
		}); err == nil {
			t.Error("execRunner returned nil for a command that exited non-zero")
		}
	})

	t.Run("the timeout bounds a command that never returns", func(t *testing.T) {
		start := time.Now()
		_, err := execRunner(t.Context(), &command{
			Path: sh, Args: []string{"-c", "sleep 30"}, Timeout: 50 * time.Millisecond,
		})
		if err == nil {
			t.Fatal("execRunner returned nil for a command that outlived its timeout")
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("execRunner took %v; the timeout did not bound the run", elapsed)
		}
	})

	// The shape that defeats a naive timeout: the child forks a helper that
	// inherits the output pipe and then dies. Killing the child does not close the
	// pipe, so the wait blocks on the grandchild unless a wait delay force-closes
	// it. Without cmd.WaitDelay this case runs for the grandchild's full lifetime.
	t.Run("a backgrounded grandchild holding the output pipe cannot outlast the bound", func(t *testing.T) {
		start := time.Now()
		_, err := execRunner(t.Context(), &command{
			Path:    sh,
			Args:    []string{"-c", "sleep 30 & printf 'started\\n'; sleep 30"},
			Timeout: 50 * time.Millisecond,
		})
		elapsed := time.Since(start)
		if err == nil {
			t.Fatal("execRunner returned nil for a command that outlived its timeout")
		}
		if elapsed > 5*time.Second {
			t.Errorf("execRunner took %v; the wait delay did not bound the run", elapsed)
		}
	})

	t.Run("an absent program is an error, not a panic", func(t *testing.T) {
		if _, err := execRunner(t.Context(), &command{
			Path: filepath.Join(t.TempDir(), "nope"), Timeout: time.Second,
		}); err == nil {
			t.Error("execRunner returned nil for a program that does not exist")
		}
	})
}

// TestPublishClearsASymlinkedDestinationThroughTheRoot pins the confinement of the one
// delete in this package that used to bypass it.
//
// publish clears the pinned version directory before renaming the staged tree into place,
// and that entry is the one entry there another principal may have replaced — it is
// reachable precisely when the probe rejected what was sitting under an intact sentinel. So
// the delete goes through an [os.Root] on the installation root, like every other removal
// inside the tree, and a symlink at that name is unlinked rather than followed: what it
// points at is outside the tree and is not this package's to delete.
func TestPublishClearsASymlinkedDestinationThroughTheRoot(t *testing.T) {
	env := newFakeEnv(t)
	// A tree outside the installation root, with something in it that must survive.
	outside := t.TempDir()
	foreign := filepath.Join(outside, "not-ours")
	if err := os.WriteFile(foreign, []byte("somebody else's data\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.MkdirAll(env.versionsRoot(), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	dst := env.versionDir(pinnedVersion)
	if err := os.Symlink(outside, dst); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	m := env.manager()
	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	if !exists(foreign) {
		t.Error("clearing the previous version directory deleted through the symlink and escaped the installation tree")
	}
	if !exists(outside) {
		t.Error("clearing the previous version directory removed the tree the symlink pointed at")
	}
	fi, err := os.Lstat(dst)
	if err != nil {
		t.Fatalf("Lstat the published version directory: %v", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Error("the published version directory is still the planted symlink, so publish wrote through a foreign pointer")
	}
	if !exists(filepath.Join(dst, toolName)) {
		t.Error("the published version directory does not hold the primary artifact")
	}
}

// TestMoveArtifactRefusesASymlinkedSourceDirectory pins the artifact move inside the
// staging tree.
//
// The source directory is the extracted archive. os.Root PERMITS creating a symlink
// whose target leaves the root (it validates the name being created, not the text the
// link carries) and refuses to FOLLOW one, so an archive symlink can leave one at
// ArtifactDir.
//
// Before the confinement, filepath.Join followed it and os.Rename moved a file from
// outside the staging tree INTO the version directory this package is about to
// publish — which makes the one claim everything here reduces to (the artifact came
// out of the digest-verified archive) false, and destroys the file at its original
// location, since a rename is not a copy.
func TestMoveArtifactRefusesASymlinkedSourceDirectory(t *testing.T) {
	env := newFakeEnv(t)
	stage := t.TempDir()
	outside := filepath.Join(stage, "outside")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatalf("MkdirAll the directory outside the staging tree: %v", err)
	}
	planted := filepath.Join(outside, toolName)
	if err := os.WriteFile(planted, []byte("not from the archive\n"), 0o755); err != nil {
		t.Fatalf("seed the file outside the staging tree: %v", err)
	}
	// What the archive left where a directory of artifacts belongs.
	srcRel := filepath.Join(stageExtractDir, "artifacts")
	if err := os.MkdirAll(filepath.Join(stage, stageExtractDir), 0o755); err != nil {
		t.Fatalf("MkdirAll the extraction directory: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(stage, srcRel)); err != nil {
		t.Fatalf("Symlink the artifact dir out of the staging tree: %v", err)
	}
	root := openRoot(t, stage)
	if err := root.MkdirAll(stageVersionDir, dirMode); err != nil {
		t.Fatalf("MkdirAll the staged version directory: %v", err)
	}

	to, err := env.manager().moveArtifact(root, srcRel, toolName)
	if err == nil {
		t.Errorf("moveArtifact = %q, want a refusal: the source directory leaves the staging tree", to)
	} else if !strings.Contains(err.Error(), "not reachable inside the staging tree") {
		t.Errorf("moveArtifact error = %v, want one naming the containment refusal", err)
	}
	if !exists(planted) {
		t.Error("the file outside the staging tree was renamed away, so the move escaped")
	}
	if exists(filepath.Join(stage, stageVersionDir, toolName)) {
		t.Error("the staged version directory holds an artifact that never came out of the archive")
	}
}
