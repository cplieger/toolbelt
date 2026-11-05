//go:build linux

// Package custody judges whether a directory is under this process's
// exclusive control: it and every directory on the way to it, through every
// symlink, belong to this uid or root and nobody else can write them, by mode
// or by POSIX.1e or NFSv4 access-control list. It reads and reports; it never
// repairs.
package custody

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"syscall"
)

// errNoCustody is what every refusal from Verify wraps.
var errNoCustody = errors.New("not under this process's exclusive control")

// Verify judges dir, which must exist, and every component of every path its
// resolution visits: the path as written, then for each symlink the path it
// points at. leafIsRoot says dir itself is the tree being protected, which a
// sticky bit does not exempt; an ancestor's sticky bit does, unless its
// access-control list lets another principal take it or rewrite the list.
func (t Trust) Verify(dir string, leafIsRoot bool) error {
	euid := os.Geteuid()
	path := dir
	for range maxSymlinkHops + 1 {
		if err := walkChain(path, euid, t, leafIsRoot); err != nil {
			return err
		}
		next, expanded, err := expandFirstSymlink(path)
		if err != nil {
			return fmt.Errorf("%w: resolving %s: %w", errNoCustody, dir, err)
		}
		if !expanded {
			return nil
		}
		path = next
	}
	return fmt.Errorf("%w: resolving %s: the chain has not resolved after %d symbolic links: %w",
		errNoCustody, dir, maxSymlinkHops, syscall.ELOOP)
}

// maxSymlinkHops is Linux's SYMLOOP_MAX, so a chain this refuses is one open()
// would refuse too.
const maxSymlinkHops = 40

// expandFirstSymlink replaces path's first symlink component with its target.
// One link per call: the caller judges the path between expansions, which is
// what puts the directory holding every intermediate link under the walk.
// filepath.EvalSymlinks resolves them all at once and hides those directories.
func expandFirstSymlink(path string) (expanded string, found bool, err error) {
	clean := filepath.Clean(path)
	for _, component := range ancestors(clean) {
		fi, err := os.Lstat(component)
		if err != nil {
			return "", false, fmt.Errorf("examining %s: %w", component, err)
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			continue
		}
		target, readErr := os.Readlink(component)
		if readErr != nil {
			return "", false, fmt.Errorf("reading the symlink %s: %w", component, readErr)
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(component), target)
		}
		return filepath.Join(target, clean[len(component):]), true, nil
	}
	return clean, false, nil
}

// walkChain judges every component of path from "/" down. It carries one fact
// forward: whether the parent is a sticky directory a stranger can write, the
// only place a symlink's owner matters (checkSymlink).
func walkChain(path string, euid int, trust Trust, leafIsRoot bool) error {
	components := ancestors(path)
	parentShared := false
	last := len(components) - 1
	for i, component := range components {
		if err := checkComponent(component, euid, leafIsRoot && i == last, parentShared, trust); err != nil {
			return err
		}
		parentShared = sharedSticky(component, euid, trust)
	}
	return nil
}

// sharedSticky reports whether path denotes, through a symlink if it is one, a
// sticky directory a stranger can write by mode or list. A link's own mode
// says nothing about the directory the next component lives in. An answer it
// cannot obtain counts as shared, which can only add checkSymlink's demand.
func sharedSticky(path string, euid int, trust Trust) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return true
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSticky == 0 {
		return false
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return true
	}
	writers, err := writersOf(path, fi, stat)
	if err != nil {
		return true
	}
	_, shared := trust.firstStranger(writers, euid)
	return shared
}

// ancestors returns every component of an absolute path from "/" down to the
// path itself.
func ancestors(path string) []string {
	out := []string{path}
	for {
		parent := filepath.Dir(path)
		if parent == path {
			break
		}
		out = append(out, parent)
		path = parent
	}
	slices.Reverse(out)
	return out
}

// checkComponent judges one component. A directory's owner must be trusted
// because the owner can widen its mode at any time. A sticky ancestor is
// exempt from the write question, since sticky stops a stranger renaming our
// entries; the protected directory itself is not, since sticky does not stop a
// stranger creating entries in it.
func checkComponent(path string, euid int, leafIsRoot, parentShared bool, trust Trust) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: examining %s: %w", errNoCustody, path, err)
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: %s: the filesystem reported no ownership information", errNoCustody, path)
	}
	mode := fi.Mode()
	owner := int(stat.Uid)
	if mode&os.ModeSymlink != 0 {
		return checkSymlink(path, owner, euid, parentShared, trust)
	}
	if !trust.allowsOwner(owner, euid) {
		return fmt.Errorf("%w: %s is owned by uid %d rather than uid %d or root, so its permissions are that user's to change%s",
			errNoCustody, path, owner, euid, trust.hint())
	}
	if !mode.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", errNoCustody, path)
	}
	if !leafIsRoot && mode&os.ModeSticky != 0 {
		controllers, ctlErr := controllersOf(path, stat)
		if ctlErr != nil {
			return fmt.Errorf("%w: %w", errNoCustody, ctlErr)
		}
		if stranger, found := trust.firstStranger(controllers, euid); found {
			return fmt.Errorf("%w: %s, mode %#o, is sticky, but its access-control list lets %s take its ownership or rewrite that list, and either removes the protection the sticky bit was providing%s",
				errNoCustody, path, mode.Perm(), stranger, trust.hintFor(stranger))
		}
		return nil
	}
	writers, err := writersOf(path, fi, stat)
	if err != nil {
		return fmt.Errorf("%w: %w", errNoCustody, err)
	}
	if stranger, found := trust.firstStranger(writers, euid); found {
		return fmt.Errorf("%w: %s, mode %#o, can be modified by %s%s%s",
			errNoCustody, path, mode.Perm(), stranger, stickyNote(mode, leafIsRoot), trust.hintFor(stranger))
	}
	return nil
}

// stickyNote says why the sticky bit did not exempt the protected directory.
func stickyNote(mode os.FileMode, leafIsRoot bool) string {
	if leafIsRoot && mode&os.ModeSticky != 0 {
		return ", and the sticky bit stops another principal renaming the directory away but not creating entries inside it"
	}
	return ""
}

// checkSymlink judges a symlink on the path. Replacing a link needs write on
// its directory, which the walk already refuses to strangers, so its owner
// matters only inside a sticky directory strangers can write, where sticky
// lets the link's owner replace it.
func checkSymlink(path string, owner, euid int, parentShared bool, trust Trust) error {
	if !parentShared {
		return nil
	}
	if !trust.allowsOwner(owner, euid) {
		return fmt.Errorf("%w: %s is a symlink owned by uid %d inside a sticky directory others can write, so that user can repoint it at a tree of their choosing%s",
			errNoCustody, path, owner, trust.hint())
	}
	return nil
}
