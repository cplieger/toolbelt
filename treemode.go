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

// stripGroupOtherWrite clears group and other write from every directory and
// regular file under dir/sub, never dir itself, which VerifyRootIntegrity
// judges. npm, uv, go and tar create entries through the umask, and on a ZFS
// nfs4acl volume an inherited group ACE stores them 0770, so a group member
// could change what the engine runs. Symlinks are skipped, and each entry is
// changed through a descriptor opened inside an os.Root, so a swapped name
// cannot reach outside dir.
func stripGroupOtherWrite(dir, sub string) error {
	root, err := os.OpenRoot(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	err = fs.WalkDir(root.FS(), sub, func(path string, d fs.DirEntry, err error) error {
		switch {
		case path == sub && errors.Is(err, fs.ErrNotExist):
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
		if info.Mode()&groupOtherWrite == 0 {
			return nil
		}
		return stripEntry(root, path)
	})
	if err != nil {
		return fmt.Errorf("strip group and other write from %s: %w", filepath.Join(dir, sub), err)
	}
	return nil
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
	_, err = atomicfile.EnforceMode(f, keep&^groupOtherWrite)
	return err
}
