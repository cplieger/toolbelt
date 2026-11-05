package unpack

import (
	"archive/tar"
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// maxLinkTarget bounds a zip symlink entry's content, its target text.
const maxLinkTarget = 4096

// extractor is one extraction's state. dirs holds every directory it has
// created or checked to be a real one: no entry can later replace it, because
// every create refuses an existing name.
type extractor struct {
	dst      *os.Root
	ctxErr   func() error
	dirs     map[string]bool
	lim      Limits
	streamed int64
	written  int64
	entries  int
}

func newExtractor(ctx context.Context, dst *os.Root, lim Limits) *extractor {
	return &extractor{dst: dst, ctxErr: ctx.Err, dirs: map[string]bool{}, lim: lim}
}

// stream meters the decompressed archive stream.
func (x *extractor) stream(r io.Reader) io.Reader {
	return &meter{r: r, ctxErr: x.ctxErr, total: &x.streamed, limit: x.lim.MaxBytes}
}

// count charges one entry against the entry limit.
func (x *extractor) count() error {
	x.entries++
	if x.entries > x.lim.MaxEntries {
		return &limitError{fmt.Sprintf("unpack: archive exceeds the %d entry limit", x.lim.MaxEntries)}
	}
	return nil
}

func (x *extractor) untar(stream io.Reader) error {
	tr := tar.NewReader(stream)
	for {
		if err := x.ctxErr(); err != nil {
			return err
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return tagRead(err)
		}
		if err := x.count(); err != nil {
			return err
		}
		if err := x.tarEntry(hdr, tr); err != nil {
			return err
		}
	}
}

func (x *extractor) tarEntry(hdr *tar.Header, body io.Reader) error {
	switch hdr.Typeflag {
	case tar.TypeXGlobalHeader:
		return nil // archive-wide metadata (git archive's commit id), no file
	case tar.TypeDir:
		return x.dir(hdr.Name)
	case tar.TypeReg, tar.TypeGNUSparse:
		return x.file(hdr.Name, hdr.FileInfo().Mode(), hdr.ModTime, body)
	case tar.TypeSymlink:
		return x.symlink(hdr.Name, hdr.Linkname)
	case tar.TypeLink:
		return x.hardlink(hdr.Name, hdr.Linkname)
	case tar.TypeChar:
		return refuseType(hdr.Name, "character device")
	case tar.TypeBlock:
		return refuseType(hdr.Name, "block device")
	case tar.TypeFifo:
		return refuseType(hdr.Name, "FIFO")
	default:
		return refuseType(hdr.Name, fmt.Sprintf("type %q", hdr.Typeflag))
	}
}

func (x *extractor) unzip(r *io.SectionReader) error {
	zr, err := zip.NewReader(r, r.Size())
	if err != nil {
		return tagRead(err)
	}
	for _, f := range zr.File {
		if err := x.ctxErr(); err != nil {
			return err
		}
		if err := x.count(); err != nil {
			return err
		}
		if err := x.zipEntry(f); err != nil {
			return err
		}
	}
	return nil
}

func (x *extractor) zipEntry(f *zip.File) error {
	mode := f.Mode()
	switch {
	case mode.IsDir():
		return x.dir(f.Name)
	case mode&fs.ModeSymlink != 0:
		target, err := zipContent(f, maxLinkTarget)
		if err != nil {
			return err
		}
		return x.symlink(f.Name, target)
	case mode.IsRegular():
		rc, err := f.Open()
		if err != nil {
			return tagRead(err)
		}
		defer rc.Close()
		return x.file(f.Name, mode, f.Modified, rc)
	default:
		return refuseType(f.Name, "special file")
	}
}

// zipContent reads a small entry whole, refusing one over limit bytes.
func zipContent(f *zip.File, limit int64) (string, error) {
	rc, err := f.Open()
	if err != nil {
		return "", tagRead(err)
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return "", tagRead(err)
	}
	if int64(len(b)) > limit {
		return "", fmt.Errorf("unpack: %s: symlink target is over %d bytes", f.Name, limit)
	}
	return string(b), nil
}

func refuseType(name, kind string) error {
	return fmt.Errorf("unpack: %s: %s entries are refused", name, kind)
}

// fileMode is the mode a regular file entry lands with.
func fileMode(archived fs.FileMode) fs.FileMode {
	m := archived.Perm()&0o755 | 0o600
	if archived&0o111 != 0 {
		m |= 0o700
	}
	return m
}

func (x *extractor) dir(name string) error {
	rel, err := x.prepare(name)
	if err != nil || rel == "." || x.dirs[rel] {
		return err
	}
	fi, err := x.dst.Lstat(rel)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return named(name, x.mkdir(rel))
	case err != nil:
		return named(name, err)
	case !fi.IsDir():
		return fmt.Errorf("unpack: %s: the name is already taken", name)
	}
	x.dirs[rel] = true
	return nil
}

func (x *extractor) mkdir(rel string) error {
	if err := x.dst.Mkdir(rel, 0o755); err != nil {
		return err
	}
	// Mkdir's mode passes through the umask; the tree's must not depend on it.
	if err := x.dst.Chmod(rel, 0o755); err != nil {
		return err
	}
	x.dirs[rel] = true
	return nil
}

// file writes a regular file entry. Its archived modification time is applied
// because timestamp-validated caches (CPython's .pyc files) compare against it.
func (x *extractor) file(name string, mode fs.FileMode, mtime time.Time, body io.Reader) error {
	rel, err := x.prepare(name)
	if err != nil {
		return err
	}
	if rel == "." {
		return fmt.Errorf("unpack: %s: names the destination itself", name)
	}
	f, err := x.dst.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return named(name, err)
	}
	m := &meter{r: body, ctxErr: x.ctxErr, total: &x.written, limit: x.lim.MaxBytes}
	_, err = io.Copy(f, m)
	if err == nil {
		err = f.Chmod(fileMode(mode)) // fchmod: the umask must not narrow it
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && !mtime.IsZero() {
		err = x.dst.Chtimes(rel, time.Time{}, mtime)
	}
	return named(name, err)
}

func (x *extractor) symlink(name, target string) error {
	rel, err := x.prepare(name)
	if err != nil {
		return err
	}
	if rel == "." {
		return fmt.Errorf("unpack: %s: names the destination itself", name)
	}
	if err := checkLinkTarget(rel, target); err != nil {
		return err
	}
	return named(name, x.dst.Symlink(target, rel))
}

// hardlink links name to old only when old is a regular file already in the
// tree. Root.Link does not follow old, so linking a symlink would copy it to
// another depth, where checkLinkTarget's verdict no longer holds.
func (x *extractor) hardlink(name, old string) error {
	rel, err := x.prepare(name)
	if err != nil {
		return err
	}
	refused := fmt.Errorf("unpack: %s: hard link target %s is not a regular file", name, old)
	oldRel, err := local(old)
	if err != nil || oldRel == "." || !x.dirs[path.Dir(oldRel)] && path.Dir(oldRel) != "." {
		return refused
	}
	fi, err := x.dst.Lstat(oldRel)
	if err != nil || !fi.Mode().IsRegular() {
		return refused
	}
	return named(name, x.dst.Link(oldRel, rel))
}

// maxName is Linux's PATH_MAX. A PAX record can carry a far longer name,
// whose every component would become a directory.
const maxName = 4096

// local cleans an entry name into dst's form, refusing one that leaves dst.
func local(name string) (string, error) {
	if len(name) > maxName {
		return "", fmt.Errorf("unpack: %.64s...: the name is over %d bytes", name, maxName)
	}
	rel := path.Clean(name)
	if name == "" || rel != "." && !filepath.IsLocal(rel) {
		return "", fmt.Errorf("unpack: %s: the name leaves the destination", name)
	}
	return rel, nil
}

// prepare returns name's path in dst, creating its missing parents. A parent
// that is a symlink is refused even when it stays inside dst, because os.Root
// follows in-root links and the entry would land somewhere its name does not say.
func (x *extractor) prepare(name string) (string, error) {
	rel, err := local(name)
	if err != nil {
		return "", err
	}
	dir := path.Dir(rel)
	if dir == "." || x.dirs[dir] {
		return rel, nil
	}
	for end := 0; end < len(dir); {
		if i := strings.IndexByte(dir[end+1:], '/'); i >= 0 {
			end += 1 + i
		} else {
			end = len(dir)
		}
		if err := x.parent(name, dir[:end]); err != nil {
			return "", err
		}
	}
	return rel, nil
}

// parent makes sure p, a parent of entry name, is a real directory, creating
// it when it is missing.
func (x *extractor) parent(name, p string) error {
	if x.dirs[p] {
		return nil
	}
	fi, err := x.dst.Lstat(p)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// A created parent counts as an entry, or a few deep names would
		// make directories past the entry limit.
		if cerr := x.count(); cerr != nil {
			return cerr
		}
		return named(name, x.mkdir(p))
	case err != nil:
		return named(name, err)
	case fi.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("unpack: %s: parent %s is a symlink", name, p)
	case !fi.IsDir():
		return fmt.Errorf("unpack: %s: parent %s is not a directory", name, p)
	}
	x.dirs[p] = true
	return nil
}

// named names the entry on a destination error, leaving a limit, a
// cancellation and a stream error as they are.
func named(name string, err error) error {
	if err == nil || own(err) {
		return err
	}
	if _, ok := errors.AsType[*streamError](err); ok {
		return err
	}
	return fmt.Errorf("unpack: %s: %w", name, err)
}

// checkLinkTarget refuses a symlink target that is not a canonical relative
// path whose leading ".." climb no higher than the link's own directory depth.
// With every parent a real directory, such a link resolves inside the tree
// whatever is created later, because the verdict reads only the text and depth.
func checkLinkTarget(name, target string) error {
	refused := fmt.Errorf("unpack: %s: symlink target %s is not a canonical relative path inside the destination", name, target)
	// A cleaned path holds ".." only as leading elements: Clean removes every
	// name/.. pair, so equality also refuses a ".." after a name.
	if target == "" || path.IsAbs(target) || path.Clean(target) != target {
		return refused
	}
	ups := 0
	for rest := target; rest == ".." || strings.HasPrefix(rest, "../"); rest = strings.TrimPrefix(rest[2:], "/") {
		ups++
	}
	if ups > strings.Count(path.Clean(name), "/") {
		return refused
	}
	return nil
}

// checkTree re-judges every symlink in dst, those the archive did not create
// directly included: each must pass checkLinkTarget and resolve inside dst or
// dangle there.
func checkTree(dst *os.Root) error {
	return fs.WalkDir(dst.FS(), ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("unpack: %s: %w", name, err)
		}
		if d.Type()&fs.ModeSymlink == 0 {
			return nil
		}
		target, err := dst.Readlink(name)
		if err != nil {
			return fmt.Errorf("unpack: %s: %w", name, err)
		}
		if err := checkLinkTarget(name, target); err != nil {
			return err
		}
		if _, err := dst.Stat(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("unpack: %s: symlink target does not resolve inside the destination", name)
		}
		return nil
	})
}
