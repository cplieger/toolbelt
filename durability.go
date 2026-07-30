package toolbelt

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
)

// Durability barriers for the publish path. Both are package vars so
// tests can inject a failing barrier (ENOSPC and friends) at each point
// the protocol relies on: the content barrier for a written file, and
// the directory barrier before and after a publishing rename.
//
// Production code in this package must go through these two functions
// rather than calling (*os.File).Sync directly — a fault-injection test
// can then reach every barrier a versioned publish depends on, and a
// new barrier is one call away from being covered.
var (
	fsyncFile = syncPath
	fsyncDir  = syncPath
)

// errNotDurable marks a write that landed but whose commit could not be
// flushed to stable storage: the bytes are visible now and may be gone
// after a power loss, so the engine treats it as a failed write rather
// than recording state it cannot stand behind.
var errNotDurable = errors.New("commit not durable: fsync failed")

// syncPath opens path and fsyncs it. It serves both barriers: on Linux
// fsync of a directory flushes its entry list (the rename), and fsync of
// a regular file flushes its contents. A read-only descriptor is
// sufficient for both.
func syncPath(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	if serr := f.Sync(); serr != nil {
		f.Close()
		return fmt.Errorf("fsync %s: %w", path, serr)
	}
	return f.Close()
}

// syncTree flushes a freshly staged tree: every regular file's contents
// first, then every directory's entry list deepest-first, finishing with
// root itself. Called before the rename that publishes the tree, so a
// crash immediately after the rename can never expose a versioned
// install dir whose file contents never reached disk.
//
// Symlink members are skipped deliberately: a symlink has no content of
// its own, and the directory barrier that records it covers it.
func syncTree(root string) error {
	var dirs []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		switch {
		case d.IsDir():
			dirs = append(dirs, path)
			return nil
		case d.Type().IsRegular():
			return fsyncFile(path)
		default:
			return nil
		}
	})
	if err != nil {
		return err
	}
	// Lexicographic order puts a parent before its children, so walking
	// the reverse flushes children before the parent that names them.
	slices.Sort(dirs)
	slices.Reverse(dirs)
	for _, dir := range dirs {
		if err := fsyncDir(dir); err != nil {
			return err
		}
	}
	return nil
}
