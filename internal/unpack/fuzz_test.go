package unpack

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// FuzzArchive_confined checks every tar Archive accepts against the tree it
// left, read afresh: every symlink passes checkLinkTarget and resolves inside
// dst or dangles there, nothing lands beside dst, and the limits held.
func FuzzArchive_confined(f *testing.F) {
	for _, ents := range [][]ent{
		{sym("a", "."), reg("a/x", "x", 0o644)},
		{sym("a", "."), sym("e", "a/a/a/a/../../../../etc/cron.d/evil")},
		{sym("a", "."), sym("e", "a/missing/../a/../../outside.txt"), dir("missing/")},
		{dir("sub/"), sym("lnk", "sub"), reg("lnk/file", "x", 0o644)},
		{sym("a/b/l", "../../x"), reg("x", "x", 0o644), hard("l2", "a/b/l")},
		{reg("../outside.txt", "pwned", 0o644)},
		{reg("lib/npm-cli.js", "js", 0o755), sym("bin/npm", "../lib/npm-cli.js"), hard("bin/npm2", "lib/npm-cli.js")},
		{ent{typ: tar.TypeChar, name: "null"}},
	} {
		f.Add(tarOf(f, ents...))
	}
	lim := Limits{MaxBytes: 1 << 20, MaxEntries: 64}
	f.Fuzz(func(t *testing.T, data []byte) {
		base := t.TempDir()
		dst := filepath.Join(base, "dst")
		if err := os.Mkdir(dst, 0o755); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(dst)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		if Archive(t.Context(), io.NewSectionReader(bytes.NewReader(data), 0, int64(len(data))), formatTar, root, lim, nil) != nil {
			return
		}
		if beside, err := os.ReadDir(base); err != nil || len(beside) != 1 {
			t.Fatalf("base holds %v, %v; want dst alone", beside, err)
		}
		// A hard-linked inode's bytes are counted once.
		var written int64
		nodes := 0
		inodes := map[uint64]bool{}
		err = fs.WalkDir(os.DirFS(dst), ".", func(name string, d fs.DirEntry, err error) error {
			if err != nil || name == "." {
				return err
			}
			nodes++
			if d.Type().IsRegular() {
				fi, err := d.Info()
				if err != nil {
					return err
				}
				if ino := fi.Sys().(*syscall.Stat_t).Ino; !inodes[ino] {
					inodes[ino] = true
					written += fi.Size()
				}
			}
			if d.Type()&fs.ModeSymlink == 0 {
				return nil
			}
			target, err := os.Readlink(filepath.Join(dst, name))
			if err != nil {
				return err
			}
			if err := checkLinkTarget(name, target); err != nil {
				t.Errorf("kept %s -> %s: %v", name, target, err)
			}
			if _, err := root.Stat(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("kept %s -> %s, which leaves dst: %v", name, target, err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if written > lim.MaxBytes || nodes > lim.MaxEntries {
			t.Errorf("tree holds %d bytes in %d nodes, over the limits", written, nodes)
		}
	})
}
