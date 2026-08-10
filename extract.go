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

	"github.com/cplieger/atomicfile/v2"
	"github.com/cplieger/pathinside"
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
		// Single gzip-compressed binary: decompress to the bin name.
		return decompressTo(ctx, filepath.Join(destDir, binName), "gunzip", "-c", artifact)
	case "xz":
		return decompressTo(ctx, filepath.Join(destDir, binName), "xz", "-dc", artifact)
	case formatRaw, "":
		// Plain binary: move into place under the bin name.
		// filepath.Base strips any directory components so the bin name
		// can never escape destDir.
		out := filepath.Join(destDir, filepath.Base(binName))
		if rerr := os.Rename(artifact, out); rerr != nil {
			// Cross-device fallback: stream-copy (binaries can be large,
			// so avoid slurping the whole artifact into memory).
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
// The chmod this replaces was a second REQUEST, not a result. open(2) and
// chmod(2) both hand the mode through the umask, and a filesystem
// carrying an inheritable group ACE overrides the outcome regardless of
// what was asked: measured on a ZFS nfs4acl dataset, a 0o600 create comes
// back 0770. For this package the widened outcome is specific and bad.
// 0775 is a group-WRITABLE executable, and the very next thing an install
// does is publish bin/<name> as a symlink to it and put that bin dir on
// PATH — so every process that inherits it runs a binary any member of
// the file's group can rewrite, silently, after the install reported
// success. atomicfile.EnforceMode fchmods the handle, fstats that SAME
// handle, and returns ErrModeNotStored naming both modes instead of nil,
// so the install fails loudly rather than publishing that.
//
// The handle is the substance, not a detail: chmod-the-name-then-stat-the-
// name can chmod one file and certify another if the name is swapped in
// between, while fchmod(2) and fstat(2) on one descriptor cannot be
// redirected by a rename. O_NOFOLLOW has the KERNEL refuse a symlink left
// at the final component rather than following it into a chmod of
// somebody else's file, which no check-then-open sequence can do without
// a race. O_NONBLOCK is not optional either: tar recreates a FIFO member
// faithfully, and a read-only open of a FIFO with no writer blocks in
// open(2) forever — a hang the pathname chmod could not have, so adding
// the handle without it would trade a mode bug for a wedged install.
func enforceExecutable(path string) error {
	return enforceStoredMode(path, binExecMode, 0)
}

// enforceDirMode is enforceExecutable's directory sibling: it proves the
// filesystem stored mode on a DIRECTORY, for the managed directories the
// engine creates for itself (see ensureManagedDir, which owns the policy
// of when a directory is this library's to certify).
//
// O_DIRECTORY is the only difference in the sequence, and it earns its
// place twice: it refuses a regular file, a device node or a socket left
// at the name, so the mode this returns is always a directory's, and it
// demotes the shared sequence's O_NONBLOCK from load-bearing to belt-and-
// braces (the kernel rejects O_DIRECTORY on a FIFO before it would block
// waiting for a writer). O_NONBLOCK is inherited from the shared sequence
// anyway because it costs nothing, and the two flags together are the
// shape atomicfile's own openPrivateDir settled on. One consequence worth
// knowing: with O_DIRECTORY in the mix Linux reports a symlink at the
// final component as ENOTDIR rather than the ELOOP O_NOFOLLOW alone
// gives, so a caller must not match on ELOOP to detect a planted link
// here.
func enforceDirMode(dir string, mode os.FileMode) error {
	return enforceStoredMode(dir, mode, syscall.O_DIRECTORY)
}

// enforceStoredMode is the shared open-then-certify sequence: open path
// in a way the kernel refuses to redirect, then hand the DESCRIPTOR to
// atomicfile.EnforceMode so the chmod and the stat that certifies it
// cannot describe two different objects. extraFlags carries O_DIRECTORY
// when the caller means a directory.
//
// It is one function rather than two copies because the flag set is the
// substance of the check, and the file and directory callers must not be
// able to drift on it: dropping O_NOFOLLOW from either would turn the
// enforcement into a chmod of whatever a planted link points at, and
// dropping O_NONBLOCK from the file arm would wedge the install on a
// FIFO (see enforceExecutable for both arguments in full).
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

// insideStrictly reports whether target lies STRICTLY beneath base:
// lexically within the tree, and not base itself.
//
// pathinside.Inside owns the containment half — a separator-precise
// comparison that refuses the prefix sibling (opt/rg/14.1.1-evil against
// opt/rg/14.1.1) and answers false for a pair that cannot be compared
// lexically at all, such as a relative target against an absolute base.
//
// The equality half stays here, spelled out, because it is this package's
// rule and not the predicate's: Inside admits a root as part of its own
// tree by contract (a scan or a watch legitimately starts at the root),
// while both callers need a FILE. linkDeclaredFiles enforces mode 0o755
// on the result and publishes bin/<name> as a symlink to it, so a
// registry entry naming the version directory itself must be refused.
//
// The judgment is LEXICAL: it says nothing about symlinks, which is why
// linkDeclaredFiles resolves with filepath.EvalSymlinks first and tests
// the resolved path.
func insideStrictly(base, target string) bool {
	return pathinside.Inside(base, target) && filepath.Clean(target) != filepath.Clean(base)
}

// safeJoin joins base and rel, rejecting any path that escapes base
// (absolute rel or .. traversal) and any path that resolves to base
// itself. Guards files[].src from the registry against writing outside
// the tool's install dir.
//
// Absoluteness is refused on its own grounds rather than left to the
// containment test: filepath.Clean CLAMPS a traversal at the filesystem
// root ("/.." cleans to "/") while filepath.Join re-attaches it to a
// relative base, and an absolute name deserves its own message anyway.
func safeJoin(base, rel string) (string, error) {
	if rel == "" {
		return "", errors.New("empty path")
	}
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("absolute path %q not allowed", rel)
	}
	joined := filepath.Join(base, rel)
	if !insideStrictly(base, joined) {
		return "", fmt.Errorf("path %q escapes install dir", rel)
	}
	return joined, nil
}
