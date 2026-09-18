package toolbelt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/cplieger/atomicfile/v3"
	"github.com/cplieger/pathinside/v2"
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

// extractArtifact unpacks a downloaded artifact into destDir according
// to the aqua format, canonical long names only (see canonicalFormat).
// Archive extraction shells out to the system tar and unzip, which the
// consumer image must bake in (tar, xz-utils, bzip2, zstd, unzip) — no Go
// decompression dependencies. destDir must exist and be empty. A format
// the image cannot extract is an error, never a raw install: an archive
// written out as the binary passes every later check.
func extractArtifact(ctx context.Context, artifact, format, destDir, binName string) error {
	switch format {
	case formatTarGz:
		return runQuiet(ctx, "tar", "-xzf", artifact, "-C", destDir)
	case formatTarXz:
		return runQuiet(ctx, "tar", "-xJf", artifact, "-C", destDir)
	case formatTarBz2:
		return runQuiet(ctx, "tar", "-xjf", artifact, "-C", destDir)
	case formatTarZst:
		return runQuiet(ctx, "tar", "--zstd", "-xf", artifact, "-C", destDir)
	case formatTar:
		return runQuiet(ctx, "tar", "-xf", artifact, "-C", destDir)
	case formatZip:
		return runQuiet(ctx, "unzip", "-q", artifact, "-d", destDir)
	case formatGz:
		return decompressTo(ctx, filepath.Join(destDir, binName), "gunzip", "-c", artifact)
	case formatBz2:
		return decompressTo(ctx, filepath.Join(destDir, binName), "bzip2", "-dc", artifact)
	case formatXz:
		return decompressTo(ctx, filepath.Join(destDir, binName), "xz", "-dc", artifact)
	case formatZst:
		return decompressTo(ctx, filepath.Join(destDir, binName), "zstd", "-dc", artifact)
	case formatRaw:
		// filepath.Base strips directory components so binName cannot escape destDir.
		out := filepath.Join(destDir, filepath.Base(binName))
		if rerr := os.Rename(artifact, out); rerr != nil {
			// Cross-device rename fails; stream-copy instead of buffering in memory.
			if cerr := copyFile(artifact, out); cerr != nil {
				return cerr
			}
		}
		return enforceExecutable(out)
	default:
		return fmt.Errorf("unsupported archive format %q", format)
	}
}

// binExecMode is the mode an installed binary is pinned to: runnable by
// anyone who can reach the tools dir, writable only by its owner.
const binExecMode os.FileMode = 0o755

// enforceExecutable makes path runnable and PROVES the filesystem stored
// exactly binExecMode, refusing the install when it stored anything else.
//
// A pathname chmod is only a REQUEST: a filesystem with an inheritable
// group ACE can override it (measured on ZFS nfs4acl, a 0o600 create
// comes back 0770), and a 0775 binary published to bin/ on PATH is then
// writable by its whole group. atomicfile.EnforceMode fchmods and fstats
// the SAME descriptor, so it cannot certify a different file than it
// chmod'd (a chmod-name-then-stat-name sequence can, if the name is
// swapped in between). O_NOFOLLOW makes the kernel refuse a symlink at
// the final component rather than follow it. O_NONBLOCK avoids blocking
// forever opening a FIFO tar recreated with no writer.
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
// atomicfile.EnforceMode. extraFlags carries O_DIRECTORY for a directory.
// Shared rather than duplicated so the file and directory callers cannot
// drift apart on O_NOFOLLOW/O_NONBLOCK (see enforceExecutable).
func enforceStoredMode(path string, mode os.FileMode, extraFlags int) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|extraFlags, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = atomicfile.EnforceMode(f, mode)
	return err
}

// copyFile stream-copies src to dst (mode 0o600; callers chmod to add
// exec bits). The cross-device fallback when os.Rename can't move a file.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}

// decompressTo runs a decompressor with its stdout wired straight to
// the output file — no shell, no quoting concerns.
func decompressTo(ctx context.Context, out, name string, args ...string) error {
	f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	cmd, err := systemCommand(ctx, name, args...)
	if err != nil {
		_ = f.Close()
		return err
	}
	cmd.Env = systemEnvPATH()
	cmd.Stdout = f
	var stderr strings.Builder
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	if cerr := f.Close(); runErr == nil {
		runErr = cerr
	}
	if runErr != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 500 {
			msg = msg[:500]
		}
		return fmt.Errorf("%s failed: %w (%s)", name, runErr, msg)
	}
	return nil
}

// runQuiet runs a command, returning combined output only on failure.
func runQuiet(ctx context.Context, name string, args ...string) error {
	cmd, err := systemCommand(ctx, name, args...)
	if err != nil {
		return err
	}
	cmd.Env = systemEnvPATH()
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 500 {
			msg = msg[:500]
		}
		return fmt.Errorf("%s failed: %w (%s)", name, err, msg)
	}
	return nil
}

// insideStrictly reports whether target lies STRICTLY beneath root:
// lexically within the tree, and not root itself.
//
// pathinside.Root.Contains admits root as part of its own tree by
// contract; the equality check here is this package's own rule, because
// resolveDeclaredFiles chmods the result and it is published as bin/<name>,
// so a registry entry naming the version directory itself must be
// refused. The judgment is LEXICAL — resolveDeclaredFiles resolves with
// filepath.EvalSymlinks first and tests the resolved path.
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
