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
	"strings"
	"syscall"
)

// errNoCustody is what every refusal from Verify wraps.
var errNoCustody = errors.New("not under this process's exclusive control")

// Verify judges dir, which must exist, and every directory the kernel passes
// through to reach it: the path is followed one component at a time, every
// symlink's target included, and ".." moves to the parent of the directory
// actually reached, never lexically. leafIsRoot says dir itself is the tree
// being protected, which a sticky bit does not exempt; an ancestor's sticky
// bit does, unless its access-control list lets another principal take it or
// rewrite the list.
func (t Trust) Verify(dir string, leafIsRoot bool) error {
	if dir == "" {
		return fmt.Errorf("%w: an empty path", errNoCustody)
	}
	if !filepath.IsAbs(dir) {
		wd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("%w: resolving %s: %w", errNoCustody, dir, err)
		}
		dir = wd + "/" + dir // not Join: Join cleans ".." lexically
	}
	w := &walk{trust: t, euid: os.Geteuid(), at: "/"}
	if err := checkComponent(w.at, w.euid, false, t); err != nil {
		return err
	}
	w.shared = sharedSticky(w.at, w.euid, t)
	pending := components(dir)
	for len(pending) > 0 {
		next, err := w.step(pending[0])
		if err != nil {
			return err
		}
		pending = append(next, pending[1:]...)
	}
	if leafIsRoot {
		return checkComponent(w.at, w.euid, true, t)
	}
	return nil
}

// walk is Verify's position: at is the physical directory reached, every
// directory above it judged on the way down.
type walk struct {
	at     string
	trust  Trust
	euid   int
	hops   int
	shared bool // at is a sticky directory a stranger can write
}

// step moves through one component, returning the components a symlink's
// target puts in front of the rest of the path.
func (w *walk) step(name string) ([]string, error) {
	if name == ".." {
		w.at = filepath.Dir(w.at)
		w.shared = sharedSticky(w.at, w.euid, w.trust)
		return nil, nil
	}
	next := filepath.Join(w.at, name) // one name, no "..": nothing to clean
	fi, err := lstatFn(next)
	if err != nil {
		return nil, fmt.Errorf("%w: examining %s: %w", errNoCustody, next, err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		if cerr := checkComponent(next, w.euid, false, w.trust); cerr != nil {
			return nil, cerr
		}
		w.at = next
		w.shared = sharedSticky(w.at, w.euid, w.trust)
		return nil, nil
	}
	if lerr := checkLink(next, fi, w.euid, w.shared, w.trust); lerr != nil {
		return nil, lerr
	}
	w.hops++
	if w.hops > maxSymlinkHops {
		return nil, fmt.Errorf("%w: resolving %s: the chain has not resolved after %d symbolic links: %w",
			errNoCustody, next, maxSymlinkHops, syscall.ELOOP)
	}
	target, err := os.Readlink(next)
	if err != nil {
		return nil, fmt.Errorf("%w: reading the symlink %s: %w", errNoCustody, next, err)
	}
	if filepath.IsAbs(target) {
		w.at = "/"
		w.shared = sharedSticky(w.at, w.euid, w.trust)
	}
	return components(target), nil
}

// lstatFn is replaced in tests: no unprivileged test can own a symlink as
// another user.
var lstatFn = os.Lstat

// maxSymlinkHops is Linux's SYMLOOP_MAX, so a chain this refuses is one open()
// would refuse too.
const maxSymlinkHops = 40

// components splits path into its names, dropping empty ones and ".", and
// keeping "..", which only the walk can resolve.
func components(path string) []string {
	var out []string
	for c := range strings.SplitSeq(path, "/") {
		if c != "" && c != "." {
			out = append(out, c)
		}
	}
	return out
}

// sharedSticky reports whether the directory at path, a physical path, is
// sticky and writable by a stranger by mode or list. An answer it cannot
// obtain counts as shared, which can only add checkSymlink's demand.
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

// checkComponent judges one component. A directory's owner must be trusted
// because the owner can widen its mode at any time. A sticky ancestor is
// exempt from the write question, since sticky stops a stranger renaming our
// entries; the protected directory itself is not, since sticky does not stop a
// stranger creating entries in it.
func checkComponent(path string, euid int, leafIsRoot bool, trust Trust) error {
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

// checkLink judges a symlink on the path by its owner (checkSymlink).
func checkLink(path string, fi os.FileInfo, euid int, parentShared bool, trust Trust) error {
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: %s: the filesystem reported no ownership information", errNoCustody, path)
	}
	return checkSymlink(path, int(stat.Uid), euid, parentShared, trust)
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
