//go:build linux

package pin

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// The pin under test and the two versions used as "already on the volume".
const (
	pinnedVersion = "2.14.2"
	prevVersion   = "2.14.1"
	oldVersion    = "2.14.0"
)

// The harness's primary profile: a package whose archive holds its artifact
// under pkg/bin. It is deliberately NOT a real upstream: the library must name
// no vendor.
const (
	toolName          = "toolkit"
	toolSidecar       = "toolkit-chat"
	toolArtifactDir   = "pkg/bin"
	mandatoryName     = "pkg.disableAutoupdates"
	toolURLTemplate   = "https://example.invalid/{version}/tool-{arch}.zip"
	testLinkDir       = "bin"
	sixtyFourHexChars = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

// TestMain silences the manager's slog output for the whole package: every
// install path logs, and the volume drowns real failures in test output.
func TestMain(m *testing.M) {
	// The umask is pinned for the whole test binary, and it is not cosmetic. t.TempDir
	// creates its numbered subdirectory with a plain mkdir(0777), so a developer whose
	// umask is 002 — the default for a regular user on Debian, Ubuntu and Fedora — gets
	// a GROUP-WRITABLE fixture root, and this package's custody check then correctly
	// refuses to install into it. Measured: 48 tests fail under umask 002 and pass under
	// 022, with the production behaviour right in both cases. CI runs at 022 and so does
	// the container this suite was written in, which is how three review rounds missed
	// it. Fixing the harness is the answer; softening the check would not be.
	syscall.Umask(0o022)
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}

// logRecord is one captured log line, flattened to what a test asserts on.
type logRecord struct {
	attrs map[string]string
	msg   string
	level slog.Level
}

// logRecorder collects every record the manager logs, at every level.
type logRecorder struct {
	mu   sync.Mutex
	seen []logRecord
}

func (*logRecorder) Enabled(context.Context, slog.Level) bool { return true }

func (h *logRecorder) Handle(_ context.Context, r slog.Record) error {
	rec := logRecord{level: r.Level, msg: r.Message, attrs: make(map[string]string, r.NumAttrs())}
	r.Attrs(func(a slog.Attr) bool {
		rec.attrs[a.Key] = a.Value.String()
		return true
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	h.seen = append(h.seen, rec)
	return nil
}

func (h *logRecorder) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *logRecorder) WithGroup(string) slog.Handler      { return h }

// at returns the captured records logged at level carrying key, whatever its value.
// The key is the discriminator rather than the message, so a rewording of a diagnostic
// does not break a test about which line was emitted.
func (h *logRecorder) at(level slog.Level, key string) []logRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []logRecord
	for _, r := range h.seen {
		if _, ok := r.attrs[key]; ok && r.level == level {
			out = append(out, r)
		}
	}
	return out
}

// messages returns the messages of the captured records at level.
func (h *logRecorder) messages(level slog.Level) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, r := range h.seen {
		if r.level == level {
			out = append(out, r.msg)
		}
	}
	return out
}

// captureLogs sends this package's log output to a recorder for the rest of the
// test, which is how a warn-only path is asserted on: the log line is the
// observable half of a deliberately non-fatal failure. slog's default is
// process-global, so a test holding this must not run in parallel. slog.SetDefault
// also redirects the standard log package and skips that when handed slog's own
// default handler, so restoring the previous logger does not undo it: the log
// writer and flags are saved and restored explicitly, after slog, since
// reinstalling a non-default handler re-runs the redirect.
func captureLogs(t *testing.T) *logRecorder {
	t.Helper()
	rec := &logRecorder{}
	prev, prevWriter, prevFlags := slog.Default(), log.Writer(), log.Flags()
	slog.SetDefault(slog.New(rec))
	t.Cleanup(func() {
		slog.SetDefault(prev)
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
	})
	return rec
}

// TestCaptureLogsRestoresLogGlobals pins the restore in captureLogs: the swap
// redirects the standard log package's writer and zeroes its flags, and the
// cleanup must put both back. Without it, one test silences slog for the rest of
// the package, because slog's own default handler writes through log.Output.
func TestCaptureLogsRestoresLogGlobals(t *testing.T) {
	// TestMain's discard logger already zeroed log's flags for the whole binary,
	// so hand the restore a non-zero value to put back; without one the flags
	// half of this test cannot fail.
	original := log.Flags()
	t.Cleanup(func() { log.SetFlags(original) })
	log.SetFlags(log.LstdFlags)

	wantWriter, wantFlags := log.Writer(), log.Flags()

	t.Run("swap", func(t *testing.T) {
		captureLogs(t)
		if log.Writer() == wantWriter {
			t.Fatal("captureLogs did not redirect log.Writer(); the restore under test would guard nothing")
		}
	})

	if got := log.Writer(); got != wantWriter {
		t.Errorf("log.Writer() after captureLogs cleanup = %T(%p), want the original %T(%p)", got, got, wantWriter, wantWriter)
	}
	if got := log.Flags(); got != wantFlags {
		t.Errorf("log.Flags() after captureLogs cleanup = %d, want %d", got, wantFlags)
	}
}

// TestCaptureLogsRestoresThePreviousHandler pins the other half of the restore:
// the cleanup puts back the handler that was installed, so a nested capture
// hands the outer one its recorder back instead of a fresh discard handler.
func TestCaptureLogsRestoresThePreviousHandler(t *testing.T) {
	outer := captureLogs(t)

	t.Run("nested", func(t *testing.T) {
		inner := captureLogs(t)
		slog.Info("inner line")
		if got := inner.messages(slog.LevelInfo); len(got) != 1 {
			t.Fatalf("inner recorder captured %v, want exactly one line", got)
		}
	})

	slog.Info("outer line")
	if got := outer.messages(slog.LevelInfo); len(got) != 1 || got[0] != "outer line" {
		t.Errorf("outer recorder captured %v after the nested capture returned, want [outer line]", got)
	}
}

// toolRelease is the release half of the primary test profile.
func toolRelease() Config {
	return Config{
		Name:        toolName,
		URLTemplate: toolURLTemplate,
		ArchTokens:  map[string]string{"amd64": "x86_64-linux", "arm64": "aarch64-linux"},
		ArtifactDir: toolArtifactDir,
		ProbeArgs:   []string{"--version"},
		Notice:      "toolkit is third-party content; installing it accepts its licence",
		Assertions:  []Assertion{{Name: mandatoryName, Args: []string{"settings", mandatoryName, "true"}, Required: true}},
	}
}

// fakeEnv is the test double for every boundary the manager crosses: the archive
// fetch, subprocess execution, fsync, rename, the clock and the sleep. Together
// they make an install run end to end with no network, no real archive and no
// real package.
type fakeEnv struct {
	t    *testing.T
	root string

	release Config

	// fixed is an archive a test supplied; nil builds one from produces when the
	// config is built, so the pinned digest always matches what fetch serves.
	fixed   []byte
	archive []byte
	digest  string

	// produces maps the executable names the archive holds under ArtifactDir
	// to the version each one reports.
	produces map[string]string
	// archiveLacksArtifacts makes the archive hold no executable at all, the
	// shape that fails the staged gates.
	archiveLacksArtifacts bool
	// probeAnswerFor renders the version a fake artifact encodes into the shape
	// that package's probe prints.
	probeAnswerFor func(version string) string

	onFetch  func(dst io.Writer) error
	onProbe  func(bin string) ([]byte, error)
	onAssert func(bin string, args []string) error
	onSync   func(path string) error
	onRename func(oldpath, newpath string) error

	mu      sync.Mutex
	calls   []string
	fetches int
	slept   []time.Duration
}

// newEnv wires an env to one profile and one archive.
func newEnv(t *testing.T, release Config, archive []byte) *fakeEnv {
	t.Helper()
	e := &fakeEnv{
		t:              t,
		root:           t.TempDir(),
		release:        release,
		fixed:          archive,
		probeAnswerFor: func(v string) string { return toolName + " " + v + "\n" },
	}
	if archive != nil {
		e.setArchive(archive)
	}
	return e
}

// useArchive pins archive for this env, so config does not rebuild one.
func (e *fakeEnv) useArchive(archive []byte) {
	e.fixed = archive
	e.setArchive(archive)
}

// setArchive makes archive what fetch serves and the pinned digest's subject.
func (e *fakeEnv) setArchive(archive []byte) {
	sum := sha256.Sum256(archive)
	e.archive = archive
	e.digest = hex.EncodeToString(sum[:])
}

// builtArchive is the archive the primary profile ships: every produced
// executable under ArtifactDir, beside a NOTICE file.
func (e *fakeEnv) builtArchive() []byte {
	entries := map[string]zipEntry{"pkg/NOTICE": {body: "toolkit\n", mode: 0o644}}
	if !e.archiveLacksArtifacts {
		for name, version := range e.produces {
			entries[e.release.ArtifactDir+"/"+name] = zipEntry{body: fakeBinaryBody(version), mode: 0o755}
		}
	}
	return buildZip(e.t, entries)
}

// newFakeEnv is the primary env: an archive holding the primary artifact and a
// sidecar executable pin installs nothing for.
func newFakeEnv(t *testing.T) *fakeEnv {
	t.Helper()
	env := newEnv(t, toolRelease(), nil)
	env.produces = map[string]string{
		toolName:    pinnedVersion,
		toolSidecar: pinnedVersion,
	}
	return env
}

// zipEntry is one entry in a test archive: a file by default, or a directory when
// dir is set (which is how a real archiver emits an explicit "./" or "pkg/" entry).
type zipEntry struct {
	body string
	mode os.FileMode
	dir  bool
}

// namedEntry is a zipEntry with its name attached, for the archives whose ORDER or
// duplicate names matter and a map therefore cannot express.
type namedEntry struct {
	name string
	zipEntry
}

// buildZip builds a real zip in memory, so extraction is exercised for real
// while the runner seam stands in for executing what comes out of it.
func buildZip(t *testing.T, entries map[string]zipEntry) []byte {
	t.Helper()
	ordered := make([]namedEntry, 0, len(entries))
	for _, name := range slices.Sorted(maps.Keys(entries)) {
		ordered = append(ordered, namedEntry{name: name, zipEntry: entries[name]})
	}
	return buildZipOrdered(t, ordered)
}

// buildZipOrdered writes entries in the given order, so a test can express a
// duplicate name or a specific sequence.
func buildZipOrdered(t *testing.T, entries []namedEntry) []byte {
	t.Helper()
	raw, err := encodeZip(entries)
	if err != nil {
		t.Fatalf("building the test archive: %v", err)
	}
	return raw
}

// encodeZip is the writer both builders share, returning an error instead of
// failing a test so a fuzz target can use it on names archive/zip may reject.
func encodeZip(entries []namedEntry) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		if e.body == "" {
			// An empty entry has nothing to compress, and a deflate stream for one is
			// pure cost: the entry-ceiling fixtures build tens of thousands of them.
			h.Method = zip.Store
		}
		mode := e.mode
		if e.dir {
			mode |= os.ModeDir
		}
		h.SetMode(mode)
		w, err := zw.CreateHeader(h)
		if err != nil {
			return nil, fmt.Errorf("CreateHeader(%q): %w", e.name, err)
		}
		if _, err := w.Write([]byte(e.body)); err != nil {
			return nil, fmt.Errorf("Write(%q): %w", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("closing the archive: %w", err)
	}
	return buf.Bytes(), nil
}

// manager builds a manager wired to this env, with every seam replaced.
func (e *fakeEnv) manager(mutate ...func(*Config)) *Manager {
	e.t.Helper()
	m, err := New(e.config(mutate...))
	if err != nil {
		e.t.Fatalf("New: %v", err)
	}
	e.wire(m)
	return m
}

// config is the env's Config, before New validates it.
func (e *fakeEnv) config(mutate ...func(*Config)) *Config {
	if e.fixed == nil {
		e.setArchive(e.builtArchive())
	}
	cfg := e.release
	cfg.ArchTokens = maps.Clone(e.release.ArchTokens)
	cfg.ProbeArgs = slices.Clone(e.release.ProbeArgs)
	cfg.Assertions = slices.Clone(e.release.Assertions)
	cfg.Version = pinnedVersion
	cfg.Digests = map[string]string{"amd64": e.digest, "arm64": e.digest}
	cfg.Root = e.root
	cfg.goarch = "amd64"
	cfg.LinkDir = testLinkDir
	cfg.MaxAttempts = 1
	for _, f := range mutate {
		f(&cfg)
	}
	return &cfg
}

// wire replaces every seam on m with this env's double.
func (e *fakeEnv) wire(m *Manager) {
	m.fetch = e.fetch
	m.run = e.run
	m.fsync = e.fsync
	m.rename = e.rename
	m.now = func() time.Time { return time.Unix(1700000000, 0).UTC() }
	m.sleep = e.sleep
}

func (e *fakeEnv) record(format string, args ...any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls = append(e.calls, fmt.Sprintf(format, args...))
}

func (e *fakeEnv) called() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.calls)
}

func (e *fakeEnv) countCalls(substr string) int {
	n := 0
	for _, c := range e.called() {
		if strings.Contains(c, substr) {
			n++
		}
	}
	return n
}

func (e *fakeEnv) fetch(_ context.Context, url string, dst io.Writer) error {
	e.mu.Lock()
	e.fetches++
	e.mu.Unlock()
	e.record("fetch %s", url)
	if e.onFetch != nil {
		return e.onFetch(dst)
	}
	_, err := dst.Write(e.archive)
	return err
}

func (e *fakeEnv) fetchCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.fetches
}

// run dispatches on the shape of the command: the release's own probe argv, or
// an assertion.
func (e *fakeEnv) run(_ context.Context, c *command) ([]byte, error) {
	switch {
	case slices.Equal(c.Args, e.release.ProbeArgs):
		e.record("probe %s", c.Path)
		if e.onProbe != nil {
			return e.onProbe(c.Path)
		}
		return e.probeAnswer(c.Path)
	default:
		e.record("assert %s on %s", strings.Join(c.Args, " "), c.Path)
		if e.onAssert != nil {
			return nil, e.onAssert(c.Path, c.Args)
		}
		return nil, nil
	}
}

func (e *fakeEnv) fsync(path string) error {
	e.record("fsync %s", path)
	if e.onSync != nil {
		if err := e.onSync(path); err != nil {
			return err
		}
	}
	return fsyncPath(path)
}

// rename stands in for the manager's rename seam. The seam is root-RELATIVE (see
// [renameIn]), and the hook is not: it keeps taking the two ABSOLUTE paths, because
// what a test wants to name is the file it staged, not an offset into a root handle
// it never opened. The join happens here, once.
func (e *fakeEnv) rename(root *os.Root, oldname, newname string) error {
	oldpath := filepath.Join(root.Name(), oldname)
	newpath := filepath.Join(root.Name(), newname)
	e.record("rename %s -> %s", oldpath, newpath)
	if e.onRename != nil {
		if err := e.onRename(oldpath, newpath); err != nil {
			return err
		}
	}
	return root.Rename(oldname, newname)
}

func (e *fakeEnv) sleep(_ context.Context, d time.Duration) error {
	e.mu.Lock()
	e.slept = append(e.slept, d)
	e.mu.Unlock()
	return nil
}

func (e *fakeEnv) sleeps() []time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.slept)
}

// writeFakeBinary writes an executable file that records the version it answers
// the probe with, so a test can "tamper" with an installed artifact by rewriting
// its content.
func writeFakeBinary(path, version string) error {
	// An executable bit is the point: selfContained rejects anything else.
	return os.WriteFile(path, []byte(fakeBinaryBody(version)), 0o755)
}

// fakeBinaryBody is the content of a fake artifact at one version.
func fakeBinaryBody(version string) string {
	return "fake artifact\nversion=" + version + "\n"
}

// probeAnswer reads the version a fake artifact encodes and renders it in the
// shape this profile's probe prints.
func (e *fakeEnv) probeAnswer(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		if v, ok := strings.CutPrefix(line, "version="); ok {
			return []byte(e.probeAnswerFor(v)), nil
		}
	}
	return nil, fmt.Errorf("%s is not a fake artifact", path)
}

// placedAt is the activation time placeVersion gives every directory it writes, so
// placed versions share one and retention orders them by version precedence,
// whatever timestamp resolution the filesystem has.
var placedAt = time.Unix(1600000000, 0)

// placeVersion writes a COMPLETE version directory straight onto the volume,
// standing in for an install a previous start finished.
func (e *fakeEnv) placeVersion(version string, names ...string) string {
	e.t.Helper()
	dir := e.versionDir(version)
	if len(names) == 0 {
		names = []string{e.release.Name}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		e.t.Fatalf("MkdirAll(%s): %v", dir, err)
	}
	for _, n := range names {
		if err := writeFakeBinary(filepath.Join(dir, n), version); err != nil {
			e.t.Fatalf("writeFakeBinary(%s): %v", n, err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, sentinelName), []byte(version+"\n"), 0o600); err != nil {
		e.t.Fatalf("write sentinel: %v", err)
	}
	if err := os.Chtimes(dir, placedAt, placedAt); err != nil {
		e.t.Fatalf("Chtimes(%s): %v", dir, err)
	}
	return dir
}

// placePartial writes a version directory with the artifacts but NO sentinel: the
// shape an interrupted install leaves behind.
func (e *fakeEnv) placePartial(version string) string {
	e.t.Helper()
	dir := e.versionDir(version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		e.t.Fatalf("MkdirAll(%s): %v", dir, err)
	}
	if err := writeFakeBinary(filepath.Join(dir, e.release.Name), version); err != nil {
		e.t.Fatalf("writeFakeBinary(%s): %v", e.release.Name, err)
	}
	return dir
}

func (e *fakeEnv) versionsRoot() string {
	return filepath.Join(e.root, e.release.Name+versionsSuffix)
}

func (e *fakeEnv) versionDir(version string) string {
	return filepath.Join(e.versionsRoot(), version)
}

func (e *fakeEnv) statePath() string {
	return filepath.Join(e.root, e.release.Name+stateSuffix)
}

// versionDirs lists the non-staging entries under the installation root.
func (e *fakeEnv) versionDirs() []string {
	entries, err := os.ReadDir(e.versionsRoot())
	if err != nil {
		return nil
	}
	out := []string{}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".") {
			out = append(out, entry.Name())
		}
	}
	return out
}

// dirNames lists the names in dir, sorted.
func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// openRoot opens dir as an os.Root closed when the test ends.
func openRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot(%s): %v", dir, err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}
