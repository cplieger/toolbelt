//go:build linux

package pin

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
)

// Extraction ceilings. A pinned archive is commonly hundreds of megabytes, so
// these are sanity bounds against a hostile or corrupt response, not tight fits.
const (
	maxExtractBytes   int64 = 3 << 30
	maxExtractEntries       = 20000
)

// Unpacker extracts a verified archive into dst.
//
// archive reads exactly the byte range the pinned digest was proved over, on the
// very descriptor the download wrote and hashed. Both access shapes work:
// [io.SectionReader] is an [io.ReaderAt] for a format that needs random access
// (zip reads its directory from the tail) and an [io.Reader] for one that streams.
// [io.SectionReader.Size] is the verified length.
//
// There is no path to the archive in this signature. A name can be pointed at a
// different inode between the digest check and the read, so an implementation that
// opened one would extract bytes nothing ever proved — defeating the pin as
// completely as replacing the installed binary. Sharing the descriptor is what
// makes the proof and the extraction the same bytes by construction. (An
// implementation determined to find a path can still reach the file through
// [io.SectionReader.Outer]; the signature removes the accident, not the intent.)
//
// dst is an [os.Root] on the extraction directory. Write THROUGH it and an archive
// entry cannot escape: os.Root refuses an absolute name, a traversing name, and a
// symlink leaving the tree, in the kernel, on every operation. That is strictly
// stronger than the lexical check this library used to perform and used to require
// of custom unpackers by documentation — a lexical check cannot see an entry that
// writes through a symlink an earlier entry in the same archive planted, which is
// the classic tar escape.
//
// It is a better tool, not a cage. An Unpacker is ordinary in-process Go code: it
// can read dst.Name() and call os.OpenFile itself, so nothing here can stop an
// implementation that goes around the root. What the parameter does is remove the
// need to re-derive containment correctly, and make the contained path the shortest
// one. Do not join dst's name onto an entry name and open the result; use the
// [os.Root] methods.
//
// An implementation MUST still bound the entry count and the total bytes written:
// containment is not a size limit, and a hostile archive that cannot escape can
// still fill the volume.
type Unpacker func(ctx context.Context, archive *io.SectionReader, dst *os.Root) error

// UnpackZip is the shipped [Unpacker]: archive/zip written through the destination
// root, with entry-count and total-size guards. It is used whenever
// [Release.Unpack] is nil.
//
// Executable bits survive (an in-archive installer has to run) but nothing wider
// than owner-write does, because the extracted tree lands on a persistent volume.
func UnpackZip(ctx context.Context, archive *io.SectionReader, dst *os.Root) error {
	r, err := zip.NewReader(archive, archive.Size())
	if err != nil {
		return fmt.Errorf("opening the archive: %w", err)
	}
	if len(r.File) > maxExtractEntries {
		return fmt.Errorf("archive holds %d entries, over the %d limit", len(r.File), maxExtractEntries)
	}
	var total int64
	for _, entry := range r.File {
		if err := ctx.Err(); err != nil {
			return err
		}
		written, err := unpackZipEntry(entry, dst, maxExtractBytes-total)
		if err != nil {
			return err
		}
		total += written
	}
	return nil
}

// unpackZipEntry writes one archive entry, creating its parents and refusing to
// exceed budget bytes. Every path operation goes through dst, so an entry naming
// its way out of the tree fails here rather than being silently rewritten.
func unpackZipEntry(entry *zip.File, dst *os.Root, budget int64) (int64, error) {
	name, err := entryTarget(entry.Name)
	if err != nil {
		return 0, err
	}
	if entry.FileInfo().IsDir() {
		if name == "." {
			// The explicit root entry some archivers emit ("./"). It names the
			// extraction directory, which already exists.
			return 0, nil
		}
		if err := dst.MkdirAll(name, dirMode); err != nil {
			return 0, fmt.Errorf("creating %s: %w", entry.Name, err)
		}
		return 0, nil
	}
	if name == "." {
		return 0, fmt.Errorf("archive entry %q names the extraction directory itself, not a file", entry.Name)
	}
	if parent := path.Dir(name); parent != "." {
		if err := dst.MkdirAll(parent, dirMode); err != nil {
			return 0, fmt.Errorf("creating the parent of %s: %w", entry.Name, err)
		}
	}
	return extractFile(entry, name, dst, budget)
}

// entryTarget normalises a zip entry name into the form dst's methods take: slash
// separated (which zip names always are) and free of the redundant "//", "./" and
// resolvable ".." that real archivers emit and os.Root's walk rejects outright.
//
// Cleaning is safe here, and that is worth stating because sanitising an entry name
// is normally the bug rather than the fix. [path.Clean] cannot turn an escaping
// name into a contained one: it collapses a component pair only when a real parent
// precedes it, so "a/b/../../c" becomes "c" because that IS where the entry
// resolves, while "../x", "a/../../x" and "/etc/x" stay escaping or absolute. The
// containment DECISION therefore still belongs to dst, which refuses every one of
// those; this only spells the name in a form dst can walk.
func entryTarget(name string) (string, error) {
	if name == "" {
		return "", errors.New("archive holds an entry with an empty name")
	}
	return path.Clean(name), nil
}

// extractFile writes one file entry to name through dst, refusing to exceed budget
// bytes.
func extractFile(entry *zip.File, name string, dst *os.Root, budget int64) (int64, error) {
	if budget <= 0 {
		return 0, fmt.Errorf("archive exceeds the %d byte extraction limit", maxExtractBytes)
	}
	src, err := entry.Open()
	if err != nil {
		return 0, fmt.Errorf("opening %s in the archive: %w", entry.Name, err)
	}
	defer src.Close()
	mode := entry.Mode().Perm() & 0o755
	if mode&0o100 != 0 {
		mode |= 0o700
	}
	// O_EXCL: an archive carrying the same entry name twice is not something to
	// resolve by letting the last one win, and open(2) ignores the mode argument
	// outright when the path is already occupied, so a duplicate entry would
	// otherwise inherit whatever mode the first one landed with.
	out, err := dst.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return 0, fmt.Errorf("creating %s: %w", entry.Name, err)
	}
	written, copyErr := io.Copy(out, io.LimitReader(src, budget+1))
	closeErr := out.Close()
	switch {
	case copyErr != nil:
		return written, fmt.Errorf("extracting %s: %w", entry.Name, copyErr)
	case closeErr != nil:
		return written, fmt.Errorf("closing %s: %w", entry.Name, closeErr)
	case written > budget:
		return written, fmt.Errorf("archive exceeds the %d byte extraction limit", maxExtractBytes)
	}
	return written, nil
}
