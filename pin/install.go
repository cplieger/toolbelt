//go:build linux

package pin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/cplieger/toolbelt/v3/internal/unpack"
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
}

// runCommand is the manager's process-execution seam.
type runCommand func(ctx context.Context, c *command) ([]byte, error)

// waitDelay bounds the wait for a killed command's output pipes: a child that
// forked before dying leaves a grandchild holding them, and without the delay a
// wedged one would stall a start despite the timeout. A variable so the tests can
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

// The staging tree's fixed layout under its own root. Named so the absolute paths
// below and the root-relative names [Manager.assemble] and [Manager.publish] hand
// to an [os.Root] have one source rather than two spellings that can drift.
const (
	stageExtractDir = "x"
	stageVersionDir = "v"
)

// extractLimits bound one extraction: a pinned archive is commonly hundreds of
// megabytes, so these are sanity bounds against a hostile or corrupt response.
var extractLimits = unpack.Limits{MaxBytes: 3 << 30, MaxEntries: 20000}

// stageTree is one in-progress installation: the extracted archive and the
// version directory that will be renamed into place. Both live under the
// installation root, so the publish stays a same-filesystem rename.
type stageTree struct {
	root string
	// rel is root's own name relative to the installation root, which is what
	// [Manager.publish] needs to name the staged version directory to an [os.Root]
	// on that root.
	rel        string
	extract    string
	versionDir string
}

// install performs one complete installation attempt; on every failure path
// nothing outside the staging tree is left and the versions on the volume keep
// serving. Custody of the installation root is proved before a byte is fetched,
// and the archive's bytes go from one unlinked descriptor through the digest
// check into the extraction.
func (m *Manager) install(ctx context.Context) error {
	m.log.Info("installing", "package", m.cfg.Name, "version", m.cfg.Version, "arch", m.cfg.goarch)
	if m.cfg.Notice != "" {
		m.log.Info(m.cfg.Notice, "package", m.cfg.Name, "version", m.cfg.Version)
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
	// reads them. Release them before the gates and the publish run,
	// rather than holding a copy of the download alongside the extracted tree and
	// the version directory for the rest of the install.
	if err := archive.close(); err != nil {
		return fmt.Errorf("closing the archive: %w", err)
	}
	src := filepath.Join(stage.extract, m.cfg.ArtifactDir)
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
	m.log.Info("installed", "package", m.cfg.Name, "version", m.cfg.Version,
		"dir", m.versionDir(m.cfg.Version))
	return nil
}

// extract unpacks the verified archive into the staging tree through
// internal/unpack, which confines every entry to the extraction directory.
func (m *Manager) extract(ctx context.Context, archive *verifiedArchive, stage *stageTree) error {
	dst, err := os.OpenRoot(stage.extract)
	if err != nil {
		return fmt.Errorf("opening the extraction directory: %w", err)
	}
	defer func() { _ = dst.Close() }()
	if err := unpack.Archive(ctx, archive.reader(), m.format, dst, extractLimits, nil); err != nil {
		return fmt.Errorf("unpacking the archive: %w", err)
	}
	return nil
}

// downloadArchive fetches the pinned archive and proves it is the artifact the
// pin names; nothing downstream re-checks the digest. The file is created in the
// installation root, whose custody was just proved, and unlinked at once, so its
// bytes have no name another principal could repoint and nothing to clean up. It
// returns the archive still open: the descriptor that was hashed is the one the
// unpacker reads, so the proof and the extraction are about the same bytes.
func (m *Manager) downloadArchive(ctx context.Context) (*verifiedArchive, error) {
	f, err := m.anonymousFile()
	if err != nil {
		return nil, err
	}
	sum := sha256.New()
	// Digest the bytes as they land, so a large archive is read once.
	if fetchErr := m.fetch(ctx, m.archiveURL, io.MultiWriter(f, sum)); fetchErr != nil {
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
		return nil, fmt.Errorf("archive SHA-256 mismatch: arch=%s expected=%s actual=%s. Bump the version and every digest literal together",
			m.cfg.goarch, m.digest, got)
	}
	m.log.Info("archive SHA-256 verified against the pinned digest",
		"package", m.cfg.Name, "arch", m.cfg.goarch, "sha256", got)
	return &verifiedArchive{file: f, size: size}, nil
}

// anonymousFile returns an open, writable file under the installation root that
// is already unlinked, so only the descriptor reaches it. Create-then-unlink
// rather than O_TMPFILE, whose value is architecture-dependent; the instant
// between the two is inside a directory whose custody was just proved, and the
// dot prefix keeps the name out of every scan meanwhile.
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
		versionDir: filepath.Join(root, stageVersionDir),
	}
	if err := os.MkdirAll(stage.extract, dirMode); err != nil {
		return nil, fmt.Errorf("creating %s: %w", stage.extract, err)
	}
	return stage, nil
}

// ensureVersionsDir creates the installation root, so custody can be judged on the
// directory that will actually hold the tree rather than on the deepest ancestor
// that happened to exist. It requests dirMode and does not read the result back:
// what the filesystem stored is custody.Trust.Verify's question, and its answer is a
// verdict rather than a repair.
func (m *Manager) ensureVersionsDir() error {
	if err := os.MkdirAll(m.versionsDir, dirMode); err != nil {
		return fmt.Errorf("creating the installation root: %w", err)
	}
	return nil
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

// assemble moves the artifact out of src into the staged version directory and
// makes the result durable: the file synced, then the ".complete" sentinel
// written and synced last, then the directory synced; only then may publish
// rename it. Any sync failure fails the install and leaves every complete
// version untouched. The move goes through an [os.Root] on the staging tree, so an
// archive symlink at ArtifactDir cannot pull a file from outside it.
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
	moved, err := m.moveArtifact(root, srcRel)
	if err != nil {
		return fmt.Errorf("artifact %s: %w", m.primary, err)
	}
	if err := m.fsync(moved); err != nil {
		return fmt.Errorf("syncing %s: %w", m.primary, err)
	}
	if err := m.writeSentinel(stage.versionDir); err != nil {
		return err
	}
	// The last point at which the directory itself and the sentinel, which this
	// package created, can be refused, by the predicate selection applies: a
	// filesystem may store a wider mode than requested (an inherited NFSv4 ACE on
	// OpenZFS), and publishing it would install a version selection refuses forever,
	// each attempt reporting success.
	if wide, reason := m.wideArtifact(stage.versionDir); wide != "" {
		// Same wording discipline as selectActive's refusal in versions.go, because
		// this is the same verdict reached one step earlier: name what is wrong in terms
		// the operator can act on rather than echoing wideArtifact's "." marker. The
		// reason travels with the name so the operator is not told an entry is writable
		// when what actually happened is that its access-control list could not be read.
		what := fmt.Sprintf("an entry in it (%s)", wide)
		if wide == "." {
			what = "the directory itself"
		}
		return fmt.Errorf("the installation root is not under this process's exclusive control: refusing to publish the version directory %s, which selection would never activate, because %s %s",
			stage.versionDir, what, reason)
	}
	if err := m.fsync(stage.versionDir); err != nil {
		return fmt.Errorf("syncing the staged version directory: %w", err)
	}
	return nil
}

// moveArtifact moves the primary artifact out of srcRel into the staged version
// directory, both inside root, refusing anything but a self-contained
// executable, and returns its absolute path. Containment is proved first with
// root.Lstat, because the ownership and access-list checks below read an
// absolute path and would otherwise judge a file outside the staging tree.
func (m *Manager) moveArtifact(root *os.Root, srcRel string) (string, error) {
	fromRel := filepath.Join(srcRel, m.primary)
	if _, err := root.Lstat(fromRel); err != nil {
		return "", fmt.Errorf("is not reachable inside the staging tree: %w", err)
	}
	from := filepath.Join(root.Name(), fromRel)
	if !selfContained(from) {
		return "", errors.New("absent, not executable, or a symlink into the staging tree")
	}
	// This rename is the last point at which the archive's chosen modes can be
	// refused: a writable artifact in a published version directory is a binary
	// another principal can rewrite. It is refused, not repaired, with the
	// predicate's own diagnosis.
	if reason, private := m.trust.EntryPrivate(from, os.Geteuid()); !private {
		return "", errors.New("this package will not publish an artifact it executes that it cannot prove is private: it " + reason)
	}
	toRel := filepath.Join(stageVersionDir, m.primary)
	if err := m.rename(root, fromRel, toRel); err != nil {
		return "", err
	}
	return filepath.Join(root.Name(), toRel), nil
}

// writeSentinel writes the ".complete" marker LAST, holding the version of the
// artifact the directory contains. It lives inside the directory it describes,
// so it cannot drift from that artifact.
//
// It is a plain file and therefore forgeable by anyone who can write into the
// tree, which is exactly what custody excludes; see custody.Trust.Verify for why that
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
// returns nil. The delete and the rename go through one [os.Root], because both
// land at the same name in a directory another principal may write.
func (m *Manager) publish(stage *stageTree) error {
	// The destination exists only when the pinned directory failed the version
	// probe and is being replaced; the retained predecessor covers the crash window
	// between the remove and the rename. The delete goes through an [os.Root], since
	// this is the one entry here another principal may have replaced.
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
// [Config.Root] through a temp file in the same directory: write, sync, rename,
// sync the parent. Every step goes through an [os.Root] on Root because a sticky
// Root passes custody while letting another principal plant the temp name first,
// and a plain write would follow that symlink out of the tree. The syncs stay on
// absolute paths, which sticky makes safe for entries this process created.
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
// The seam is root-relative rather than [os.Rename] over two absolute paths
// because three of this package's four renames land in territory something else
// wrote (the convenience links' directory, the state record's directory and the
// extracted archive), where a symlink at any component would move the rename
// outside Root.
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
