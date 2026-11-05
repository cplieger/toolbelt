package toolbelt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/cplieger/go/filesafe"
	"github.com/cplieger/go/pathinside"
	"github.com/cplieger/toolbelt/v3/internal/unpack"
)

// Aqua format names: what a definition's format field holds, what an asset
// name's extension resolves to, and what extractArtifact switches on.
// formatRaw is a plain binary, the one format aqua requires spelled out.
const (
	formatRaw    = "raw"
	formatTarGz  = "tar.gz"
	formatTarBz2 = "tar.bz2"
	formatTarXz  = "tar.xz"
	formatTarZst = "tar.zst"
	formatTarLz4 = "tar.lz4"
	formatTarSz  = "tar.sz"
	formatTarBr  = "tar.br"
	formatTar    = "tar"
	formatZip    = "zip"
	formatGz     = "gz"
	formatBz2    = "bz2"
	formatXz     = "xz"
	formatZst    = "zst"
	formatLz4    = "lz4"
	formatSz     = "sz"
	formatBr     = "br"
)

// assetFormats maps an asset name's extension onto aqua's format name, the
// tar forms first so tar.gz is matched before gz. The table is aqua's own:
// https://aquaproj.github.io/docs/reference/registry-config/format
var assetFormats = []struct{ ext, format string }{
	{formatTarGz, formatTarGz},
	{"tgz", formatTarGz},
	{formatTarBz2, formatTarBz2},
	{"tbz2", formatTarBz2},
	{"tbz", formatTarBz2},
	{formatTarXz, formatTarXz},
	{"txz", formatTarXz},
	{formatTarZst, formatTarZst},
	{formatTarLz4, formatTarLz4},
	{"tlz4", formatTarLz4},
	{formatTarSz, formatTarSz},
	{"tsz", formatTarSz},
	{formatTarBr, formatTarBr},
	{"tbr", formatTarBr},
	{formatTar, formatTar},
	{formatZip, formatZip},
	{formatGz, formatGz},
	{formatBz2, formatBz2},
	{formatXz, formatXz},
	{formatZst, formatZst},
	{formatLz4, formatLz4},
	{formatSz, formatSz},
	{formatBr, formatBr},
}

// splitAssetFormat returns an asset name without its archive extension and
// the aqua format that extension names. A name carrying no archive or
// compression extension is formatRaw: that is what an aqua definition with
// no format field means, and raw is the only format aqua requires spelled out.
func splitAssetFormat(asset string) (stem, format string) {
	// Matched on a tail of the extension's own byte length rather than on
	// a lowered copy: lowering can change the length (U+0130 lowers to an
	// ASCII i) and the stem is sliced from the original.
	for _, f := range assetFormats {
		ext := "." + f.ext
		if len(asset) >= len(ext) && strings.EqualFold(asset[len(asset)-len(ext):], ext) {
			return asset[:len(asset)-len(ext)], f.format
		}
	}
	return asset, formatRaw
}

// canonicalFormat maps a short tar spelling a definition may declare (tgz,
// tbz, ...) onto the long name extractArtifact switches on. Any other value,
// the empty one included, is returned unchanged.
func canonicalFormat(format string) string {
	for _, f := range assetFormats {
		if f.ext == format {
			return f.format
		}
	}
	return format
}

// Engine extraction limits, sanity bounds against a hostile or corrupt
// archive. The largest catalog archives measured on 2026-11-05: codeql 2.27.4
// (zip, 3,831 entries, 772 MB), zig 0.17.1 (20,792 entries, 374 MB), temurin
// 21 (542 entries, 362 MB); the Go 1.27.3 toolchain tree is 17,374 entries.
const (
	maxExtractBytes   int64 = 16 << 30
	maxExtractEntries       = 250_000
)

// extractArtifact unpacks a verified artifact into destDir, an empty
// directory, through internal/unpack, by its canonical format (see
// canonicalFormat). A format it cannot extract is an error, never a raw
// install: an archive written out as the binary passes every later check.
func extractArtifact(ctx context.Context, artifact *io.SectionReader, format, destDir, binName string) error {
	lim := unpack.Limits{MaxBytes: maxExtractBytes, MaxEntries: maxExtractEntries}
	switch format {
	case formatTarGz, formatTarXz, formatTarBz2, formatTarZst, formatTar, formatZip:
		return withRoot(destDir, func(root *os.Root) error {
			return unpack.Archive(ctx, artifact, format, root, lim, filterCommand)
		})
	case formatRaw, formatGz, formatBz2, formatXz, formatZst:
		name := filepath.Base(binName)
		return withRoot(destDir, func(root *os.Root) error {
			return unpack.Single(ctx, artifact, format, root, name, lim, filterCommand)
		})
	default:
		return fmt.Errorf("unsupported archive format %q", format)
	}
}

func withRoot(dir string, fn func(*os.Root) error) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	return fn(root)
}

// filterCommand is the decompressor internal/unpack runs for xz and zstd.
func filterCommand(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
	cmd, err := systemCommand(ctx, name, args...)
	if err != nil {
		return nil, err
	}
	cmd.Env = systemEnvPATH()
	return cmd, nil
}

// binExecMode is the mode an installed binary is pinned to: runnable by
// anyone who can reach the tools dir, writable only by its owner.
const binExecMode os.FileMode = 0o755

// enforceExecutable makes path binExecMode and proves the filesystem stored
// exactly that, refusing the install otherwise: a chmod is only a request, and
// an inheritable group ACE can widen it (measured on ZFS nfs4acl, a 0o600
// create comes back 0770). filesafe.EnforceMode fchmods and fstats the same
// descriptor, so it certifies the file it changed. O_NOFOLLOW refuses a
// symlink at the name and O_NONBLOCK keeps a FIFO there from blocking the open.
func enforceExecutable(path string) error {
	return enforceStoredMode(path, binExecMode, 0)
}

// enforceDirMode is enforceExecutable's directory sibling, for the
// directories the engine creates for itself (see ensureManagedDir).
//
// O_DIRECTORY refuses a regular file, device node, or socket left at the
// name. With it in the mix, a planted symlink at the final component is
// reported as ENOTDIR rather than the ELOOP O_NOFOLLOW alone gives — a
// caller must not match on ELOOP to detect it here.
func enforceDirMode(dir string, mode os.FileMode) error {
	return enforceStoredMode(dir, mode, syscall.O_DIRECTORY)
}

// enforceStoredMode is the shared open-then-certify sequence: open path
// so the kernel refuses to redirect it, then hand the descriptor to
// filesafe.EnforceMode. extraFlags carries O_DIRECTORY for a directory.
// Shared rather than duplicated so the file and directory callers cannot
// drift apart on O_NOFOLLOW/O_NONBLOCK (see enforceExecutable).
func enforceStoredMode(path string, mode os.FileMode, extraFlags int) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|extraFlags, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = filesafe.EnforceMode(f, mode)
	return err
}

// insideStrictly reports whether target lies lexically beneath root and is
// not root itself: pathinside.Root.Contains admits root, but the result is
// chmodded and published as bin/<name>, so a registry entry naming the
// version directory must be refused. resolveDeclaredFiles resolves symlinks
// with filepath.EvalSymlinks first and tests the resolved path.
func insideStrictly(root pathinside.Root, target string) bool {
	return root.Contains(target) && filepath.Clean(target) != filepath.Clean(string(root))
}

// safeJoin joins root and rel, rejecting any path that escapes root
// (absolute rel or .. traversal) and any path that resolves to root
// itself. Guards files[].src from the registry against writing outside
// the tool's install dir.
//
// Absoluteness is refused separately because filepath.Clean CLAMPS a
// traversal at the filesystem root ("/.." cleans to "/") while
// filepath.Join re-attaches it to a relative base.
func safeJoin(root pathinside.Root, rel string) (string, error) {
	if rel == "" {
		return "", errors.New("empty path")
	}
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("absolute path %q not allowed", rel)
	}
	joined := filepath.Join(string(root), rel)
	if !insideStrictly(root, joined) {
		return "", fmt.Errorf("path %q escapes install dir", rel)
	}
	return joined, nil
}
