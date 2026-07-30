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
		return os.Chmod(out, 0o755)
	default:
		return fmt.Errorf("unsupported archive format %q", format)
	}
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
// while both callers need a FILE. linkDeclaredFiles chmods the result
// 0o755 and publishes bin/<name> as a symlink to it, so a registry entry
// naming the version directory itself must be refused.
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
