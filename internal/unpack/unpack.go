// Package unpack extracts a verified archive through an os.Root. No entry
// lands outside the root, writes through a symlink, or keeps a privilege the
// archive records: owners, setuid, setgid and sticky bits and device nodes
// never reach the tree.
package unpack

import (
	"compress/bzip2"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/cplieger/go/textsafe"
)

// Limits bounds one extraction. MaxBytes caps the decompressed stream read
// and, separately, the file content written; MaxEntries caps the archive's
// entries plus the parent directories they need and do not declare.
type Limits struct {
	MaxBytes   int64
	MaxEntries int
}

// FilterFunc builds the system decompressor run for the xz and zstd formats.
// The command must stop when ctx is done (exec.CommandContext). Archive and
// Single own the returned command: they set its stdin, stdout, stderr and
// WaitDelay, and reap it before they return.
type FilterFunc func(ctx context.Context, name string, args ...string) (*exec.Cmd, error)

// Format names, aqua's long spellings.
const (
	formatRaw    = "raw"
	formatTar    = "tar"
	formatTarGz  = "tar.gz"
	formatTarBz2 = "tar.bz2"
	formatTarXz  = "tar.xz"
	formatTarZst = "tar.zst"
	formatZip    = "zip"
	formatGz     = "gz"
	formatBz2    = "bz2"
	formatXz     = "xz"
	formatZst    = "zst"
)

// filterNames maps a format needing a system decompressor onto its binary.
var filterNames = map[string]string{
	formatTarXz: "xz", formatXz: "xz",
	formatTarZst: "zstd", formatZst: "zstd",
}

// Archive extracts src (zip or any tar format, read from offset 0) into dst.
// It refuses an entry whose name leaves dst, crosses a symlink or already
// exists, a special file, a symlink checkLinkTarget refuses, and a hard link
// to anything but a regular file already extracted. Files keep their archived
// mtime and at most 0o755 (see fileMode); directories are 0o755. A nil filter
// refuses tar.xz and tar.zst. On error the partial tree is the caller's to
// remove.
func Archive(ctx context.Context, src *io.SectionReader, format string, dst *os.Root, lim Limits, filter FilterFunc) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	x := newExtractor(ctx, dst, lim)
	r := io.NewSectionReader(src, 0, src.Size())
	var err error
	switch format {
	case formatZip:
		err = x.unzip(r)
	case formatTar:
		err = x.untar(x.stream(r))
	case formatTarGz:
		err = x.gunzip(r, x.untar)
	case formatTarBz2:
		err = x.untar(x.stream(bzip2.NewReader(r)))
	case formatTarXz, formatTarZst:
		err = x.filtered(ctx, filter, filterNames[format], r, x.untar)
	default:
		return fmt.Errorf("unpack: unsupported archive format %q", format)
	}
	if err == nil {
		err = checkTree(dst)
	}
	return safe(err)
}

// Single writes the decompressed content of src, a raw, gz, bz2, xz or zst
// file, to dst/name with mode 0o755, under the same limits and filter rules
// as Archive. name must be a single path component.
func Single(ctx context.Context, src *io.SectionReader, format string, dst *os.Root, name string, lim Limits, filter FilterFunc) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if name == "." || strings.Contains(name, "/") || !filepath.IsLocal(name) {
		return safe(fmt.Errorf("unpack: %q is not a file name", name))
	}
	x := newExtractor(ctx, dst, lim)
	r := io.NewSectionReader(src, 0, src.Size())
	write := func(stream io.Reader) error { return x.file(name, 0o755, time.Time{}, stream) }
	var err error
	switch format {
	case formatRaw:
		err = write(x.stream(r))
	case formatGz:
		err = x.gunzip(r, write)
	case formatBz2:
		err = write(x.stream(bzip2.NewReader(r)))
	case formatXz, formatZst:
		err = x.filtered(ctx, filter, filterNames[format], r, write)
	default:
		return fmt.Errorf("unpack: unsupported file format %q", format)
	}
	return safe(err)
}

// gunzip runs consume over the gzip stream in r, metered.
func (x *extractor) gunzip(r io.Reader, consume func(io.Reader) error) error {
	z, err := gzip.NewReader(r)
	if err != nil {
		return tagRead(err)
	}
	defer z.Close()
	return consume(x.stream(z))
}

// limitError is a limit this package enforced.
type limitError struct{ msg string }

func (e *limitError) Error() string { return e.msg }

// streamError is a failure reading the archive's bytes, as opposed to a
// decision this package made or a write to the destination.
type streamError struct{ err error }

func (e *streamError) Error() string { return "unpack: reading the archive: " + e.err.Error() }
func (e *streamError) Unwrap() error { return e.err }

// tagRead marks err, returned by a read of the archive, as a streamError,
// leaving the end of input, this package's own decisions and an error already
// marked as they are.
func tagRead(err error) error {
	switch {
	case err == nil, errors.Is(err, io.EOF), own(err):
		return err
	}
	if _, ok := errors.AsType[*streamError](err); ok {
		return err
	}
	return &streamError{err}
}

// own reports whether err is a decision this package made while reading: a
// limit or the caller's cancellation.
func own(err error) bool {
	if _, ok := errors.AsType[*limitError](err); ok {
		return true
	}
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// safeError renders its cause on one line with every unsafe rune replaced,
// because entry names and a filter's stderr come from the archive.
type safeError struct{ err error }

func (e *safeError) Error() string { return textsafe.SanitizeSingleLine(e.err.Error()) }
func (e *safeError) Unwrap() error { return e.err }

func safe(err error) error {
	if err == nil {
		return nil
	}
	return &safeError{err}
}

// meter counts the bytes read through it into total, failing past limit, and
// stops reading once the extraction's context is done.
type meter struct {
	r      io.Reader
	ctxErr func() error
	total  *int64
	limit  int64
}

// Read returns no data with the limit error: io.ReadFull drops an error that
// arrives with the bytes it asked for, so the limit would pass unseen.
func (m *meter) Read(p []byte) (int, error) {
	if err := m.ctxErr(); err != nil {
		return 0, err
	}
	if *m.total > m.limit {
		return 0, m.exceeded()
	}
	if room := m.limit - *m.total; int64(len(p))-1 > room {
		p = p[:room+1]
	}
	n, err := m.r.Read(p)
	*m.total += int64(n)
	if *m.total > m.limit {
		return 0, m.exceeded()
	}
	return n, tagRead(err)
}

func (m *meter) exceeded() error {
	return &limitError{fmt.Sprintf("unpack: archive exceeds the %d byte limit", m.limit)}
}
