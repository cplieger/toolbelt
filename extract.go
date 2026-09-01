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

	"github.com/cplieger/atomicfile/v3"
	"github.com/cplieger/pathinside/v2"
)

// extractArtifact unpacks a downloaded artifact into destDir according
// to the aqua format. Archive extraction shells out to the system tar
// and unzip, which the consumer image must bake in (tar, xz-utils, unzip) — no Go
// decompression dependencies. destDir must exist and be empty.
func extractArtifact(ctx context.Context, artifact, format, destDir, binName string) error {
	switch format {
	case "tar.gz", "tgz":
		return runQuiet(ctx, "tar", "-xzf", artifact, "-C", destDir)
	case "tar.xz", "txz":
		return runQuiet(ctx, "tar", "-xJf", artifact, "-C", destDir)
	case "tar.bz2", "tbz2":
		return runQuiet(ctx, "tar", "-xjf", artifact, "-C", destDir)
	case "tar.zst":
		return runQuiet(ctx, "tar", "--zstd", "-xf", artifact, "-C", destDir)
	case "tar":
		return runQuiet(ctx, "tar", "-xf", artifact, "-C", destDir)
	case "zip":
		return runQuiet(ctx, "unzip", "-q", artifact, "-d", destDir)
	case "gz":
		return decompressTo(ctx, filepath.Join(destDir, binName), "gunzip", "-c", artifact)
	case "xz":
		return decompressTo(ctx, filepath.Join(destDir, binName), "xz", "-dc", artifact)
	case formatRaw, "":
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
	cmd := exec.CommandContext(ctx, name, args...)
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
	cmd := exec.CommandContext(ctx, name, args...)
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
// linkDeclaredFiles chmods the result and publishes bin/<name> as a
// symlink to it, so a registry entry naming the version directory itself
// must be refused. The judgment is LEXICAL — linkDeclaredFiles resolves
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
