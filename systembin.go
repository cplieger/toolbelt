package toolbelt

// Resolving an image-baked binary from a fixed directory set instead of PATH,
// because bin/ precedes the system directories and lives on the volume.
// README's Security model states what the pin buys and what it cannot.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// systemBinDirs is the trusted search set, in order. Both entries because a
// consumer image need not be usrmerged; /usr/local/bin is excluded as
// admin-group-writable on some hosts.
//
// A var so a test can point it at a stub; never reassigned in production.
var systemBinDirs = []string{"/usr/bin", "/bin"}

// errSystemBin is the resolver's refusal. Unexported: it reaches a consumer as a
// job error's text and neither branches on it.
var errSystemBin = errors.New("image-baked binary not found in the trusted system directories")

// resolveSystemBin returns the absolute path of an image-baked binary.
//
// It reads no environment, because a settable override would import the very
// property being removed. A miss REFUSES rather than falling back to PATH: a
// fallback at one site voids the pin everywhere, since an attacker picks the
// site. Symlinks are followed — xz ships its tools as links and busybox ships
// everything that way.
func resolveSystemBin(name string) (string, error) {
	if name == "" || strings.ContainsRune(name, filepath.Separator) {
		return "", fmt.Errorf("%w: %q is not a bare binary name", errSystemBin, name)
	}
	for _, dir := range systemBinDirs {
		candidate := filepath.Join(dir, name)
		info, err := os.Stat(candidate)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			continue
		}
		return candidate, nil
	}
	return "", fmt.Errorf("%w: %s is not in %s (the consumer image must bake it in)",
		errSystemBin, name, strings.Join(systemBinDirs, " or "))
}

// hasSystemBin reports whether an image-baked binary is present.
//
// It exists so a presence gate and the spawn it guards ask about the same file;
// they were two independent PATH lookups of one name.
func hasSystemBin(name string) bool {
	_, err := resolveSystemBin(name)
	return err == nil
}

// systemCommand builds a command with argv[0] pinned to the trusted set.
//
// One producer, so the only way left to spawn a system binary by name is a
// direct exec.CommandContext call, which stands out against the calls around it.
// The child's env is the CALLER's to set: what a child resolves for itself
// differs per site, so a default here would silently pick one.
func systemCommand(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
	path, err := resolveSystemBin(name)
	if err != nil {
		return nil, err
	}
	return exec.CommandContext(ctx, path, args...), nil
}

// systemEnvPATH returns an environment whose PATH is the trusted set alone, for
// a child needing nothing from the managed tree.
//
// Pinning argv[0] does not pin what the child resolves: /usr/bin/gunzip is a
// #!/bin/sh script calling gzip by bare name, and GNU tar shells out to its own
// decompressor.
func systemEnvPATH() []string {
	return []string{"PATH=" + strings.Join(systemBinDirs, string(os.PathListSeparator))}
}

// systemPATHFirst returns env with the trusted directories prepended to whatever
// PATH it carries.
//
// Prepended rather than replaced for apt alone: Debian policy lets a dpkg
// maintainer script rely on /usr/sbin, and the ordering already delivers the
// hardening. Leaving bin/ reachable for a name absent from the trusted set costs
// nothing, since every name spawned here is present.
func systemPATHFirst(env []string) []string {
	trusted := strings.Join(systemBinDirs, string(os.PathListSeparator))
	out := make([]string, 0, len(env)+1)
	inherited := ""
	for _, kv := range env {
		if rest, ok := strings.CutPrefix(kv, "PATH="); ok {
			inherited = rest
			continue
		}
		out = append(out, kv)
	}
	if inherited != "" {
		trusted += string(os.PathListSeparator) + inherited
	}
	return append(out, "PATH="+trusted)
}
