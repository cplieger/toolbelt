//go:build linux

package custody

import (
	"fmt"
	"os"
	"syscall"
)

// EntryPrivate reports whether the file or directory at path can be modified
// only by root, euid and the declared users. Custody of the directory holding
// it does not answer this: directory write permission governs adding and
// renaming entries, not rewriting one that exists. reason completes the
// sentence "<path> ...", and an access-control list that could not be read is
// reported as such rather than as a writer.
func (t Trust) EntryPrivate(path string, wantDir bool, euid int) (reason string, private bool) {
	fi, err := os.Lstat(path)
	if err != nil {
		return "could not be examined: " + err.Error(), false
	}
	// A link's own mode grants nothing on Linux, and chmod follows it.
	if fi.Mode()&os.ModeSymlink != 0 {
		return "is a symlink, which will not be executed", false
	}
	if fi.Mode().IsDir() != wantDir {
		if wantDir {
			return "is not a directory", false
		}
		return "is a directory rather than a file", false
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "has no ownership information", false
	}
	if !t.allowsOwner(int(stat.Uid), euid) {
		return fmt.Sprintf("is owned by uid %d", stat.Uid), false
	}
	writers, err := writersOf(path, fi, stat)
	if err != nil {
		return "could not be judged: " + err.Error(), false
	}
	if p, stranger := t.firstStranger(writers, euid); stranger {
		return "is writable by " + p.String(), false
	}
	return "", true
}
