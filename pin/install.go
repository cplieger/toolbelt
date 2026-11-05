//go:build linux

package pin

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// The placeholders a URL template carries.
const (
	versionPlaceholder = "{version}"
	archPlaceholder    = "{arch}"
)

// Transfer ceilings and watchdogs.
const (
	maxArchiveBytes int64 = 2 << 30
	// stallWindow aborts a transfer that makes no progress for this long. A flat
	// absolute deadline on a large download is a BANDWIDTH FLOOR rather than a
	// hang guard, so lack of progress is what bounds it.
	stallWindow = 60 * time.Second
	// connectTimeout bounds only the handshake, never the body.
	connectTimeout = 20 * time.Second
)

// command is one bounded external command execution. It is the manager's only
// path to a subprocess, so replacing the runner removes every process dependency
// from the tests.
type command struct {
	// Path is the absolute program path.
	Path string
	// Env holds extra variables appended to the process environment.
	Env []string
	// Args are passed as separate elements, never through a shell.
	Args []string
	// Timeout bounds the run; every call site sets one.
	Timeout time.Duration
	// CaptureStderr folds stderr into the returned output, for commands whose
	// diagnostics are worth surfacing.
	CaptureStderr bool
}

// runCommand is the manager's process-execution seam.
type runCommand func(ctx context.Context, c *command) ([]byte, error)

// waitDelay is the grace period after a timed-out command is killed, before its
// output pipes are force-closed.
//
// It is what makes the timeout a real bound. exec.CommandContext kills the child
// on the deadline, but the wait still blocks on the output pipes — and a child
// that forked before dying leaves a grandchild holding the write end, so without
// a delay the call returns only when that grandchild exits. An installer script
// backgrounding a helper is exactly that shape, so a wedged one would stall a
// start indefinitely despite the timeout. A package variable so the tests can
// shorten it.
var waitDelay = 5 * time.Second

// execRunner is the production runner: one bounded, context-cancellable
// subprocess with no shell in the path.
func execRunner(ctx context.Context, c *command) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	// #nosec G204 -- the path and args come from the caller's own profile and
	// the operator-supplied pin, never from request data, and they are passed as
	// separate argv elements so no shell parses them.
	cmd := exec.CommandContext(ctx, c.Path, c.Args...)
	cmd.WaitDelay = waitDelay
	if len(c.Env) > 0 {
		cmd.Env = append(os.Environ(), c.Env...)
	}
	if c.CaptureStderr {
		return cmd.CombinedOutput()
	}
	return cmd.Output()
}

// httpFetch is the production archive fetcher: a bounded body and a stall
// watchdog instead of an absolute deadline.
func httpFetch(ctx context.Context, url string, dst io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return fmt.Errorf("building the archive request: %w", err)
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSHandshakeTimeout:   connectTimeout,
			ResponseHeaderTimeout: connectTimeout,
			ForceAttemptHTTP2:     true,
		},
	}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetching the archive: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("fetching the archive: unexpected status %s", resp.Status)
	}
	return copyWithStallGuard(cancel, dst, io.LimitReader(resp.Body, maxArchiveBytes), stallWindow)
}

// copyWithStallGuard streams src into dst, cancelling the transfer when no bytes
// arrive for window. It refuses an empty body: a zero-length "success" is a
// partial download, and the digest check would otherwise report it as a mismatch
// and hide the real cause.
func copyWithStallGuard(cancel context.CancelFunc, dst io.Writer, src io.Reader, window time.Duration) error {
	progress := make(chan struct{}, 1)
	done := make(chan struct{})
	stalled := make(chan struct{})
	go func() {
		timer := time.NewTimer(window)
		defer timer.Stop()
		for {
			select {
			case <-done:
				return
			case <-progress:
				timer.Reset(window)
			case <-timer.C:
				close(stalled)
				cancel()
				return
			}
		}
	}()

	written, err := io.Copy(dst, readerFunc(func(p []byte) (int, error) {
		n, rerr := src.Read(p)
		if n > 0 {
			select {
			case progress <- struct{}{}:
			default:
			}
		}
		return n, rerr
	}))
	close(done)

	select {
	case <-stalled:
		return fmt.Errorf("archive transfer made no progress for %s and was aborted", window)
	default:
	}
	if err != nil {
		return fmt.Errorf("reading the archive body: %w", err)
	}
	if written == 0 {
		return errors.New("archive body was empty, which suggests a partial download")
	}
	return nil
}

// readerFunc adapts a function to io.Reader so the copy can observe progress
// without a bespoke type.
type readerFunc func(p []byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

// archiveURL is the pinned archive's absolute URL. The version is pinned rather
// than a floating "latest" so a given deployment is reproducible and the digest
// check is meaningful.
func (m *Manager) archiveURL() string {
	url := strings.ReplaceAll(m.urlTemplate, versionPlaceholder, m.cfg.Version)
	return strings.ReplaceAll(url, archPlaceholder, m.archToken)
}

// The staging tree's fixed layout under its own root. Named so the absolute paths
// below and the root-relative names [Manager.assemble] and [Manager.publish] hand
// to an [os.Root] have one source rather than two spellings that can drift.
const (
	stageExtractDir = "x"
	stageHomeDir    = "home"
	stageVersionDir = "v"
)

// stageTree is one in-progress installation: the extracted archive, a private
// home for an in-archive installer, and the version directory that will be
// renamed into place. All three live under the installation root, so the publish
// stays a same-filesystem rename rather than a copy.
type stageTree struct {
	root string
	// rel is root's own name relative to the installation root, which is what
	// [Manager.publish] needs to name the staged version directory to an [os.Root]
	// on that root.
	rel        string
	extract    string
	home       string
	versionDir string
}

// install performs one complete installation attempt. On every failure path
// nothing outside the staging tree is left behind and the versions already on the
// volume keep serving.
//
// Custody of the installation root is proved FIRST, before a byte is fetched: the
// digest gate downstream is only worth running on a tree nobody else can write to
// (see [verifyCustody]). Then the archive is downloaded into a file that is
// unlinked the instant it exists, so from that point on it has no name at all —
// nothing to swap, nothing to rewrite by path, and nothing left on the volume if
// this process dies mid-install. The same descriptor carries the bytes through the
// digest check and into the extraction, so the proof and the use are about the
// same bytes by construction.
func (m *Manager) install(ctx context.Context) error {
	slog.Info("installing", "package", m.cfg.Release.Name, "version", m.cfg.Version, "arch", m.cfg.GOARCH)
	if m.cfg.Release.Notice != "" {
		slog.Info(m.cfg.Release.Notice, "package", m.cfg.Release.Name, "version", m.cfg.Version)
	}

	if err := m.ensureVersionsDir(); err != nil {
		return err
	}
	if err := m.requireCustody(); err != nil {
		return err
	}

	archive, dlErr := m.downloadArchive(ctx)
	if dlErr != nil {
		return dlErr
	}
	// Closed as soon as the extraction is done; the defer only covers the failure
	// paths between here and there. Closing twice is harmless.
	defer func() { _ = archive.close() }()

	stage, stageErr := m.newStage()
	if stageErr != nil {
		return stageErr
	}
	defer os.RemoveAll(stage.root)

	if err := m.extract(ctx, archive, stage); err != nil {
		return err
	}
	// The archive's blocks are the caller's disk, and nothing after the extraction
	// reads them. Release them before the installer, the gates and the publish run,
	// rather than holding a copy of the download alongside the extracted tree and
	// the version directory for the rest of the install.
	if err := archive.close(); err != nil {
		return fmt.Errorf("closing the archive: %w", err)
	}
	src, srcErr := m.runInstaller(ctx, stage)
	if srcErr != nil {
		return srcErr
	}
	if err := m.gateStaged(ctx, filepath.Join(src, m.primary)); err != nil {
		return err
	}
	if err := m.assemble(stage, src); err != nil {
		return err
	}
	if err := m.publish(stage); err != nil {
		return err
	}
	m.mu.Lock()
	m.installed[m.cfg.Version] = true
	m.mu.Unlock()
	slog.Info("installed", "package", m.cfg.Release.Name, "version", m.cfg.Version,
		"dir", m.versionDir(m.cfg.Version))
	return nil
}

// extract unpacks the verified archive into the staging tree through an [os.Root],
// so no archive entry can name its way out of the extraction directory.
func (m *Manager) extract(ctx context.Context, archive *verifiedArchive, stage *stageTree) error {
	dst, err := os.OpenRoot(stage.extract)
	if err != nil {
		return fmt.Errorf("opening the extraction directory: %w", err)
	}
	defer func() { _ = dst.Close() }()
	if err := m.unpack(ctx, archive.reader(), dst); err != nil {
		return fmt.Errorf("unpacking the archive: %w", err)
	}
	return nil
}

// downloadArchive fetches the pinned archive and proves it is the artifact the
// pin names. Verification is the whole point: nothing downstream re-checks the
// digest, and nothing is placed on the persistent volume until it passes.
//
// The archive is created inside the installation root and UNLINKED immediately, so
// for the entire time it holds bytes it has no name. That is a deletion rather than
// a defence added: with no name there is nothing for another principal to point
// elsewhere, nothing to rewrite by path, no temp directory whose permissions need
// checking, no TMPDIR the caller controls in the threat surface, and no cleanup to
// get right — the kernel reclaims the space when the last descriptor closes,
// including when this process dies mid-download. The installation root is the right
// home for it because custody there has just been proved, and it is the same
// filesystem the extracted tree lands on.
//
// It returns the archive still OPEN, because the proof and the extraction have to
// be about the same bytes. Digesting a file and then handing its PATH to the
// unpacker proves nothing even while a name exists: a name can be pointed at
// another inode in between. The descriptor these bytes were written and hashed
// through is the one the unpacker reads. The caller closes it.
func (m *Manager) downloadArchive(ctx context.Context) (*verifiedArchive, error) {
	f, err := m.anonymousFile()
	if err != nil {
		return nil, err
	}
	sum := sha256.New()
	// Digest the bytes as they land, so a large archive is read once.
	if fetchErr := m.fetch(ctx, m.archiveURL(), io.MultiWriter(f, sum)); fetchErr != nil {
		_ = f.Close()
		return nil, fetchErr
	}
	// The verified length is the descriptor's own write offset, not a stat of the
	// path: it counts the bytes that went through the hash, so the reader handed
	// out below cannot reach past what was proved.
	size, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("measuring the archive that was written: %w", err)
	}
	got := hex.EncodeToString(sum.Sum(nil))
	if got != m.digest {
		_ = f.Close()
		return nil, fmt.Errorf("%w: arch=%s expected=%s actual=%s. Bump the version and every digest literal together",
			ErrDigestMismatch, m.cfg.GOARCH, m.digest, got)
	}
	slog.Info("archive SHA-256 verified against the pinned digest",
		"package", m.cfg.Release.Name, "arch", m.cfg.GOARCH, "sha256", got)
	return &verifiedArchive{file: f, size: size}, nil
}

// anonymousFile returns an open, writable file under the installation root that
// has already been removed from the directory, so it is reachable only through the
// returned descriptor.
//
// Create-then-unlink rather than O_TMPFILE: that flag's value is
// architecture-dependent and reaching it means a dependency outside the standard
// library, while the only thing it buys here is closing the instant between the
// create and the unlink — an instant inside a directory whose custody was just
// proved, where no other principal can act at all. The dot prefix keeps the name
// out of the version scan and out of prunePartials for that instant.
func (m *Manager) anonymousFile() (*os.File, error) {
	f, err := os.CreateTemp(m.versionsDir, ".download-*")
	if err != nil {
		return nil, fmt.Errorf("creating the archive file: %w", err)
	}
	if err := os.Remove(f.Name()); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("unlinking the archive file: %w", err)
	}
	return f, nil
}

// verifiedArchive is a downloaded archive whose digest matched, held open on the
// descriptor its bytes were written and hashed through, with the exact length
// that hash covers.
//
// It has no path field because it has no path: the file was unlinked before the
// first byte arrived. Nothing downstream re-checks the digest, so the only thing
// making the extraction trustworthy is that it reads these bytes.
type verifiedArchive struct {
	file *os.File
	size int64
}

// reader returns a reader over exactly the verified bytes. Each call builds a
// fresh one: an [io.SectionReader] carries its own offset, so sequential reading
// by an unpacker moves nothing on the shared descriptor.
func (a *verifiedArchive) reader() *io.SectionReader {
	return io.NewSectionReader(a.file, 0, a.size)
}

// close releases the descriptor, which is also what frees the archive's disk
// space: the file is already unlinked, so this is its last reference.
func (a *verifiedArchive) close() error { return a.file.Close() }

// newStage creates the staging tree under the installation root.
//
// No mode is verified here and none is repaired. The staging tree sits inside a
// root whose custody install() proved before anything was created, so the modes of
// the directories under it are not a boundary anybody can be on the wrong side of.
// That is the point of proving custody once instead of per-directory.
func (m *Manager) newStage() (*stageTree, error) {
	root, err := os.MkdirTemp(m.versionsDir, stagePrefix+"*")
	if err != nil {
		return nil, fmt.Errorf("creating the staging tree: %w", err)
	}
	stage := &stageTree{
		root:       root,
		rel:        filepath.Base(root),
		extract:    filepath.Join(root, stageExtractDir),
		home:       filepath.Join(root, stageHomeDir),
		versionDir: filepath.Join(root, stageVersionDir),
	}
	for _, dir := range []string{stage.extract, stage.home} {
		if err := os.MkdirAll(dir, dirMode); err != nil {
			return nil, fmt.Errorf("creating %s: %w", dir, err)
		}
	}
	return stage, nil
}

// ensureVersionsDir creates the installation root, so custody can be judged on the
// directory that will actually hold the tree rather than on the deepest ancestor
// that happened to exist. It requests dirMode and does not read the result back:
// what the filesystem stored is [verifyCustody]'s question, and its answer is a
// verdict rather than a repair.
func (m *Manager) ensureVersionsDir() error {
	if err := os.MkdirAll(m.versionsDir, dirMode); err != nil {
		return fmt.Errorf("creating the installation root: %w", err)
	}
	return nil
}

// runInstaller runs the archive's own installer against the PRIVATE staging home,
// so the artifacts it drops there never land on PATH or in the real home before
// they are verified. It returns the directory the artifacts are expected in.
//
// The installer's exit code is deliberately not fatal: an upstream installer
// commonly touches shell profiles and other surfaces that legitimately fail in a
// minimal container. What matters is whether the artifacts it produced pass the
// staged gates. With no installer configured the archive itself already holds the
// artifacts and no subprocess runs at all.
func (m *Manager) runInstaller(ctx context.Context, stage *stageTree) (string, error) {
	inst := m.cfg.Release.Installer
	if inst == nil {
		return filepath.Join(stage.extract, m.cfg.Release.ArtifactDir), nil
	}
	script := filepath.Join(stage.extract, inst.Path)
	if !selfContained(script) {
		return "", fmt.Errorf("the archive holds no executable installer at %s", inst.Path)
	}
	homeEnv := cmp.Or(inst.HomeEnv, "HOME")
	timeout := inst.Timeout
	if timeout <= 0 {
		timeout = defaultInstallerTimeout
	}
	out, err := m.run(ctx, &command{
		Path:          script,
		Env:           []string{homeEnv + "=" + stage.home},
		Args:          inst.Args,
		Timeout:       timeout,
		CaptureStderr: true,
	})
	if err != nil {
		slog.Warn("the archive's installer reported a failure; continuing to the staged-artifact gates, which decide",
			"package", m.cfg.Release.Name, "installer", inst.Path,
			"error", err, "output", truncate(string(out), 2000))
	}
	return filepath.Join(stage.home, m.cfg.Release.ArtifactDir), nil
}

// gateStaged refuses a staged candidate that is not the pinned, self-contained
// primary artifact, and refuses one whose required assertions do not hold.
func (m *Manager) gateStaged(ctx context.Context, staged string) error {
	if !selfContained(staged) {
		return fmt.Errorf("no self-contained executable at %s. It is absent, not executable, or a symlink whose target is removed during staging cleanup", staged)
	}
	got, err := m.probeVersion(ctx, staged)
	if err != nil {
		return fmt.Errorf("probing the staged artifact: %w", err)
	}
	if got != m.cfg.Version {
		return fmt.Errorf("staged artifact reports version %q, want %q", got, m.cfg.Version)
	}
	// The required assertions are asserted against the STAGED artifact before
	// publication, so a candidate they cannot hold on never becomes a version
	// directory. This is not a substitute for the every-start reassertion in
	// finish: an assertion's effect lives in the package's mutable
	// configuration, so it has to be re-proved on every start too.
	return m.applyRequiredAssertions(ctx, staged)
}

// assemble moves the artifacts out of src into the staged version directory and
// makes the result DURABLE, in the order the protocol requires: every file is
// written and Synced, then the ".complete" sentinel is written and Synced LAST,
// then the directory itself is Synced. Only after that may publish rename it into
// place.
//
// Atomic visibility is not crash durability: a successful rename proves no
// concurrent lookup sees a half-populated directory, it does not prove the new
// directory entry or the file data reached stable storage. Any sync failure —
// ENOSPC included — fails the install, which leaves every complete version
// already on the volume untouched.
//
// The moves go through an [os.Root] on the staging tree because src is territory
// something ELSE wrote: an in-archive installer chose what it dropped there, and
// with no installer it is the extracted archive. [os.Root] permits CREATING a
// symlink whose target leaves the root (measured: it validates the name being
// created, not the text the link carries) and refuses to FOLLOW one, so a custom
// [Unpacker] reproducing an archive symlink can legitimately leave one at
// ArtifactDir — and the plain filepath.Join this used to do followed it. Measured
// on the unconfined form: a file outside the staging tree was renamed INTO the
// published version directory, which makes the one claim this package reduces to
// (the artifact came out of the digest-verified archive) false, and destroys the
// file at its original location.
func (m *Manager) assemble(stage *stageTree, src string) error {
	root, err := os.OpenRoot(stage.root)
	if err != nil {
		return fmt.Errorf("opening the staging tree: %w", err)
	}
	defer root.Close()
	srcRel, err := filepath.Rel(stage.root, src)
	if err != nil {
		return fmt.Errorf("locating the artifact directory inside the staging tree: %w", err)
	}
	if mkErr := root.MkdirAll(stageVersionDir, dirMode); mkErr != nil {
		return fmt.Errorf("creating the staged version directory: %w", mkErr)
	}
	moved, err := m.moveArtifacts(root, srcRel)
	if err != nil {
		return err
	}
	for _, path := range moved {
		if err := m.fsync(path); err != nil {
			return fmt.Errorf("syncing %s: %w", filepath.Base(path), err)
		}
	}
	if err := m.writeSentinel(stage.versionDir); err != nil {
		return err
	}
	// The last point at which the DIRECTORY ITSELF and the sentinel can be refused, and
	// against the same predicate selection applies at activation. moveArtifact judged each
	// artifact as it was renamed in; these two entries are the ones this package CREATED,
	// and nothing had judged them. A filesystem is free to store a wider mode than MkdirAll
	// and WriteFile asked for — an inherited NFSv4 ACE on OpenZFS does exactly that, which
	// is the filesystem family this library parses those lists for.
	//
	// Publishing one anyway installs a version selection refuses for the life of the
	// volume: the install reports SUCCESS, and every later start re-fetches the archive and
	// reports ErrNoVersion with the complete directory sitting right there. Config.
	// MaxAttempts exists to prevent exactly that loop, and cannot, because each attempt
	// succeeds.
	if wide, reason := m.wideArtifact(stage.versionDir); wide != "" {
		// Same wording discipline as selectActive's refusal twenty lines away, because
		// this is the same verdict reached one step earlier: name what is wrong in terms
		// the operator can act on rather than echoing wideArtifact's "." marker, and wrap
		// ErrNoCustody so a caller can tell a custody refusal from a fetch failure. The
		// reason travels with the name so the operator is not told an entry is writable
		// when what actually happened is that its access-control list could not be read.
		what := fmt.Sprintf("an entry in it (%s)", wide)
		if wide == "." {
			what = "the directory itself"
		}
		return fmt.Errorf("%w: refusing to publish the version directory %s because %s %s, and selection would therefore never activate it%s",
			ErrNoCustody, stage.versionDir, what, reason, m.trust.hint())
	}
	if err := m.fsync(stage.versionDir); err != nil {
		return fmt.Errorf("syncing the staged version directory: %w", err)
	}
	return nil
}

// moveArtifacts moves every declared artifact out of srcRel into the staged version
// directory and returns their absolute paths, in the order they were moved.
//
// The asymmetry between the two sets is the whole reason they are one function
// rather than one loop: a required artifact that will not move fails the install,
// while an optional one only warns, because "installed when the archive provides it"
// is the contract Optional's own doc states.
func (m *Manager) moveArtifacts(root *os.Root, srcRel string) ([]string, error) {
	moved := make([]string, 0, len(m.cfg.Require)+len(m.cfg.Optional))
	for _, name := range m.cfg.Require {
		dst, err := m.moveArtifact(root, srcRel, name)
		if err != nil {
			return nil, fmt.Errorf("required artifact %s: %w", name, err)
		}
		moved = append(moved, dst)
	}
	for _, name := range m.cfg.Optional {
		dst, err := m.moveArtifact(root, srcRel, name)
		if err != nil {
			slog.Warn("optional artifact not installed",
				"package", m.cfg.Release.Name, "artifact", name, "error", err)
			continue
		}
		moved = append(moved, dst)
	}
	return moved, nil
}

// moveArtifact moves one artifact out of srcRel and into the staged version
// directory, both resolved inside root, refusing anything that is not a
// self-contained executable: a symlink would pass an existence and executability
// check and then dangle the moment the staging tree is removed. It returns the
// artifact's absolute path.
//
// Containment is proved FIRST, with root.Lstat, and that ordering is load-bearing
// rather than tidy. The two predicates below have to read an absolute path — the
// ownership question needs the raw stat and the access-control question needs a
// getxattr, neither of which an [os.Root] offers — so on a source directory that
// resolves out of the tree they would judge some file elsewhere on the volume and
// then hand a name the rename refuses. Asking the root first means the predicates
// only ever see an object inside the staging tree, and the diagnosis names the real
// obstacle instead of a rename failure two lines later.
func (m *Manager) moveArtifact(root *os.Root, srcRel, name string) (string, error) {
	fromRel := filepath.Join(srcRel, name)
	if _, err := root.Lstat(fromRel); err != nil {
		return "", fmt.Errorf("is not reachable inside the staging tree: %w", err)
	}
	from := filepath.Join(root.Name(), fromRel)
	if !selfContained(from) {
		return "", errors.New("absent, not executable, or a symlink into the staging tree")
	}
	// An in-archive installer chooses its own modes, and this rename is the last
	// point at which what it chose can be refused: publish moves this inode into
	// place and a rename cannot change a mode. A group- or other-writable artifact
	// in a published version directory is a binary this package executes and
	// another principal can rewrite, which is the integrity gate the pin exists to
	// provide. It is refused rather than repaired, for the same reason nothing else
	// here is repaired. The predicate's own diagnosis is carried through, because
	// "writable" and "its access-control list could not be read" send the operator
	// to two different places.
	if reason, private := m.entryPrivate(from, false, os.Geteuid()); !private {
		return "", fmt.Errorf("%s, and this package will not publish an artifact it executes that it cannot prove is private", reason)
	}
	toRel := filepath.Join(stageVersionDir, name)
	if err := m.rename(root, fromRel, toRel); err != nil {
		return "", err
	}
	return filepath.Join(root.Name(), toRel), nil
}

// writeSentinel writes the ".complete" marker LAST, holding the version whose
// full artifact set the directory contains. It lives inside the directory it
// describes, so it cannot drift from those artifacts.
//
// It is a plain file and therefore forgeable by anyone who can write into the
// tree, which is exactly what custody excludes; see [verifyCustody] for why that
// is the defence rather than the sentinel's own mode.
func (m *Manager) writeSentinel(dir string) error {
	path := filepath.Join(dir, sentinelName)
	if err := os.WriteFile(path, []byte(m.cfg.Version+"\n"), fileMode); err != nil {
		return fmt.Errorf("writing the completion sentinel: %w", err)
	}
	if err := m.fsync(path); err != nil {
		return fmt.Errorf("syncing the completion sentinel: %w", err)
	}
	return nil
}

// publish renames the staged version directory to its final name and syncs the
// parent, completing the durability protocol. Pruning may only run after this
// returns nil.
//
// Both halves now go through the same [os.Root]: the delete always did, and the
// rename that follows it lands at the same name in the same untrusted directory, so
// leaving it on an absolute path was the delete's own reasoning applied to one of
// the two operations.
func (m *Manager) publish(stage *stageTree) error {
	// The destination can exist here for exactly one reason: the pinned
	// directory was rejected by the version probe (a replaced artifact under an
	// intact sentinel) and is being replaced. It is untrusted, so removing it is
	// correct, and the retained predecessor is what covers the crash window
	// between the remove and the rename.
	//
	// Untrusted is also why the delete goes through an [os.Root] on the installation root
	// rather than through the absolute path, which is the rule the rest of this package's
	// removals already follow (see [Manager.removeUnderRoot]). The entry being cleared is
	// the one entry here that another principal may have replaced, and the pin is a single
	// validated path component, so the root handle resolves the tree once and confines the
	// delete to it: a redirected component cannot turn "clear the rejected version
	// directory" into a delete somewhere else on the volume.
	root, err := os.OpenRoot(m.versionsDir)
	if err != nil {
		return fmt.Errorf("opening the installation root to clear the previous %s directory: %w", m.cfg.Version, err)
	}
	defer root.Close()
	if err := root.RemoveAll(m.cfg.Version); err != nil {
		return fmt.Errorf("clearing the previous %s directory: %w", m.cfg.Version, err)
	}
	if err := m.rename(root, filepath.Join(stage.rel, stageVersionDir), m.cfg.Version); err != nil {
		return fmt.Errorf("publishing the version directory: %w", err)
	}
	if err := m.fsync(m.versionsDir); err != nil {
		return fmt.Errorf("syncing the installation root: %w", err)
	}
	return nil
}

// writeFileDurably writes data to the single path component name directly under
// [Config.Root], through a temp file in the same directory: write, sync, rename,
// sync the parent.
//
// name is root-RELATIVE and every step goes through an [os.Root] on Root, which is
// not decoration. Root is judged by the custody walk as an ANCESTOR of the
// installation root, so a sticky one — the 1777 shape that makes /tmp usable as a
// root, and the shape [checkComponent] deliberately exempts from the write question
// — passes the check while still letting another principal CREATE entries in it.
// Sticky stops them replacing the state record; it does not stop them planting the
// temp NAME first. os.WriteFile on that name follows the symlink, so the write left
// the tree: measured, an arbitrary file outside Root truncated and overwritten with
// the state record, and the state path left as a symlink pointing at it. The same
// reachability comes free with [Config.InstallWithoutCustody], which re-authorises
// this write into a tree the check has already refused.
//
// The two reads stay on absolute paths, and only because the confined create is
// what makes them safe: an entry this process just created inside a sticky
// directory is one sticky itself forbids another principal from replacing, so by
// the time the syncs run the names resolve to this process's own files.
func (m *Manager) writeFileDurably(name string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(m.cfg.Root, dirMode); err != nil {
		return fmt.Errorf("creating %s: %w", m.cfg.Root, err)
	}
	root, err := os.OpenRoot(m.cfg.Root)
	if err != nil {
		return fmt.Errorf("opening %s to write %s: %w", m.cfg.Root, name, err)
	}
	defer root.Close()
	tmp := "." + name + ".tmp"
	if err := root.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := m.fsync(filepath.Join(m.cfg.Root, tmp)); err != nil {
		_ = root.Remove(tmp)
		return err
	}
	if err := m.rename(root, tmp, name); err != nil {
		_ = root.Remove(tmp)
		return err
	}
	return m.fsync(m.cfg.Root)
}

// renameIn is the production rename: root-relative, so the kernel resolves both
// names inside root and refuses either one that leaves it.
//
// The seam is shaped this way rather than as [os.Rename] over two absolute paths
// because three of this package's four renames land in territory something else
// wrote — the directory holding the convenience links, the directory holding the
// state record, and the artifact tree an in-archive installer populated — and a
// symlink at any component of those made the rename land outside Root. An
// [os.Root] answers that in the kernel, on every component, which is the same
// answer [UnpackZip] already gets for an archive entry and [Manager.publish]
// already gets for the one delete it makes into untrusted territory.
func renameIn(root *os.Root, oldname, newname string) error {
	return root.Rename(oldname, newname)
}

// fsyncPath commits the file or directory at path to stable storage. fsync on a
// read-only descriptor is valid on Linux, so one helper covers both.
func fsyncPath(path string) error {
	f, err := os.Open(path) // #nosec G304 -- path is always built from Root and this package's own constants.
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("fsync %s: %w", path, err)
	}
	return nil
}

// truncate bounds a diagnostic string so a runaway installer log cannot flood the
// log pipeline.
func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "...(truncated)"
}
