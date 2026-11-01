package toolbelt

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/cplieger/atomicfile/v4"
)

const groupOtherWrite os.FileMode = 0o022

// enforceMode is a package var so tests can stand in for a filesystem that
// does not store the mode asked for.
var enforceMode = atomicfile.EnforceMode

// entryID is what changes on an entry an install writes: a new file has a new
// inode, and a write or chmod in place stamps ctime (inode(7)). Size and mtime
// catch a rewrite inside one coarse clock tick, which ctime alone can miss.
type entryID struct {
	dev, ino     uint64
	size         int64
	mtime, ctime int64
	mode         os.FileMode
}

func identityOf(info fs.FileInfo) (entryID, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return entryID{}, fmt.Errorf("stat %s: no device, inode or ctime", info.Name())
	}
	return entryID{
		dev: st.Dev, ino: st.Ino, size: info.Size(),
		mtime: info.ModTime().UnixNano(), ctime: st.Ctim.Nano(), mode: info.Mode(),
	}, nil
}

// treeSnapshot is the identity of every entry of one written tree before an
// install. A nil snapshot stands for an owned tree, whose entries are all the
// tool's.
type treeSnapshot map[string]entryID

// snapshotTrees records each shared tree's entries before an install, so
// stripWritten leaves alone what the install did not change.
func snapshotTrees(trees []writtenTree) ([]treeSnapshot, error) {
	snaps := make([]treeSnapshot, len(trees))
	for i, tree := range trees {
		if tree.owned {
			continue
		}
		snap := treeSnapshot{}
		err := walkTree(tree, func(_ *os.Root, path string, info fs.FileInfo) error {
			id, err := identityOf(info)
			snap[path] = id
			return err
		})
		if err != nil {
			return nil, fmt.Errorf("snapshot %s: %w", filepath.Join(tree.dir, tree.sub), err)
		}
		snaps[i] = snap
	}
	return snaps, nil
}

// stripWritten clears group and other write from every directory and regular
// file under trees that is new or changed since before, so an install that
// failed after publishing a file is hardened too. npm, uv, go and tar create
// entries through the umask, and on a ZFS nfs4acl volume an inherited group
// ACE stores them 0770, so a group member could change what the engine runs.
// It keeps going past a failed entry and returns every failure.
func stripWritten(trees []writtenTree, before []treeSnapshot) error {
	var errs []error
	for i, tree := range trees {
		if err := stripTree(tree, before[i]); err != nil {
			errs = append(errs, fmt.Errorf("strip group and other write from %s: %w", filepath.Join(tree.dir, tree.sub), err))
		}
	}
	return errors.Join(errs...)
}

func stripTree(tree writtenTree, before treeSnapshot) error {
	var failed []error
	err := walkTree(tree, func(root *os.Root, path string, info fs.FileInfo) error {
		if info.Mode()&groupOtherWrite == 0 {
			return nil
		}
		if prev, ok := before[path]; ok {
			if id, err := identityOf(info); err == nil && id == prev {
				return nil
			}
		}
		if err := stripEntry(root, path); err != nil {
			failed = append(failed, fmt.Errorf("%s: %w", path, err))
		}
		return nil
	})
	return errors.Join(append(failed, err)...)
}

// walkTree calls fn for every directory and regular file under tree, never
// tree.dir itself, which VerifyRootIntegrity judges. It walks through an
// os.Root without following a symlink, so a swapped name cannot reach outside
// tree.dir.
func walkTree(tree writtenTree, fn func(root *os.Root, path string, info fs.FileInfo) error) error {
	root, err := os.OpenRoot(tree.dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	return fs.WalkDir(root.FS(), tree.sub, func(path string, d fs.DirEntry, err error) error {
		switch {
		case path == tree.sub && errors.Is(err, fs.ErrNotExist):
			return nil
		case err != nil:
			return err
		case path == ".", !d.IsDir() && !d.Type().IsRegular():
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		return fn(root, path, info)
	})
}

// stripEntry reads the mode from the descriptor it changes, so an entry
// swapped after the walk's lstat is judged as what was opened.
func stripEntry(root *os.Root, path string) error {
	f, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	mode := fi.Mode()
	if !mode.IsDir() && !mode.IsRegular() || mode&groupOtherWrite == 0 {
		return nil
	}
	keep := mode.Perm() | mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky)
	_, err = enforceMode(f, keep&^groupOtherWrite)
	return err
}
