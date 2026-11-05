package unpack

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// ent is one archive entry for the fixtures; typ is a tar type flag, which
// zipOf maps onto zip modes.
type ent struct {
	mtime time.Time
	name  string
	link  string
	body  string
	mode  int64
	typ   byte
}

func reg(name, body string, mode int64) ent {
	return ent{typ: tar.TypeReg, name: name, body: body, mode: mode}
}
func dir(name string) ent { return ent{typ: tar.TypeDir, name: name, mode: 0o755} }
func sym(name, target string) ent {
	return ent{typ: tar.TypeSymlink, name: name, link: target, mode: 0o777}
}
func hard(name, old string) ent { return ent{typ: tar.TypeLink, name: name, link: old} }

func tarOf(t testing.TB, ents ...ent) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range ents {
		h := &tar.Header{Typeflag: e.typ, Name: e.name, Linkname: e.link, Mode: e.mode, Size: int64(len(e.body)), ModTime: e.mtime, Format: tar.FormatPAX}
		if e.typ == tar.TypeChar {
			h.Devmajor, h.Devminor = 1, 3
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tw, e.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gzipOf(t testing.TB, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func zipOf(t testing.TB, ents ...ent) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range ents {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate, Modified: e.mtime}
		body := e.body
		switch e.typ {
		case tar.TypeDir:
			if !strings.HasSuffix(h.Name, "/") {
				h.Name += "/"
			}
			h.SetMode(fs.ModeDir | 0o755)
		case tar.TypeSymlink:
			h.SetMode(fs.ModeSymlink | 0o777)
			body = e.link
		case tar.TypeChar:
			h.SetMode(fs.ModeDevice | fs.ModeCharDevice | 0o666)
		default:
			h.SetMode(fs.FileMode(e.mode))
		}
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(w, body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// archiveOf encodes ents in format, one of tar, tar.gz and zip.
func archiveOf(t testing.TB, format string, ents ...ent) []byte {
	t.Helper()
	switch format {
	case formatTar:
		return tarOf(t, ents...)
	case formatTarGz:
		return gzipOf(t, tarOf(t, ents...))
	case formatZip:
		return zipOf(t, ents...)
	}
	t.Fatalf("archiveOf: format %q", format)
	return nil
}

var generous = Limits{MaxBytes: 64 << 20, MaxEntries: 1000}

// extract runs Archive over data into base/dst and returns dst. base also
// holds the sentinel outside.txt, so an escape has a real target to reach.
func extract(t *testing.T, format string, data []byte, lim Limits) (string, error) {
	t.Helper()
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "outside.txt"), []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(base, "dst")
	if err := os.Mkdir(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	err = Archive(t.Context(), io.NewSectionReader(bytes.NewReader(data), 0, int64(len(data))), format, root, lim, nil)
	return dst, err
}

func lstatMode(t *testing.T, path string) fs.FileMode {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode()
}

func assertAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Lstat(%s) = %v, want not-exist", path, err)
	}
}

// assertOwnedByUs checks R4.8 over the whole tree: no archived owner lands.
func assertOwnedByUs(t *testing.T, dst string) {
	t.Helper()
	err := filepath.WalkDir(dst, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if st := fi.Sys().(*syscall.Stat_t); int(st.Uid) != os.Geteuid() {
			t.Errorf("%s: uid %d, want %d", p, st.Uid, os.Geteuid())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

var (
	date2019 = time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)
	allFmts  = []string{formatTar, formatTarGz, formatZip}
	tarFmts  = []string{formatTar, formatTarGz}
)

// TestArchive_EntryRules is R4.1 to R4.9 per format.
func TestArchive_EntryRules(t *testing.T) {
	t.Parallel()
	escapeC21 := "a/missing/../a/../../outside.txt"
	cases := []struct {
		check   func(t *testing.T, dst string)
		name    string
		wantErr string
		ents    []ent
		formats []string
	}{
		{
			name: "setuid member lands without it", formats: allFmts,
			ents: []ent{reg("tool", "x", 0o4777)},
			check: func(t *testing.T, dst string) {
				if got := lstatMode(t, filepath.Join(dst, "tool")); got != 0o755 {
					t.Errorf("mode %v, want -rwxr-xr-x", got)
				}
			},
		},
		{
			name: "modes are masked and owner read write added", formats: allFmts,
			ents: []ent{reg("ro", "x", 0o444), reg("gx", "x", 0o010), reg("wide", "x", 0o666)},
			check: func(t *testing.T, dst string) {
				for name, want := range map[string]fs.FileMode{"ro": 0o644, "gx": 0o710, "wide": 0o644} {
					if got := lstatMode(t, filepath.Join(dst, name)); got != want {
						t.Errorf("%s: mode %v, want %v", name, got, want)
					}
				}
			},
		},
		{
			name: "directories are 0755", formats: allFmts,
			ents: []ent{{typ: tar.TypeDir, name: "d/", mode: 0o777}, reg("e/f", "x", 0o644)},
			check: func(t *testing.T, dst string) {
				for _, d := range []string{"d", "e"} {
					if got := lstatMode(t, filepath.Join(dst, d)); got != fs.ModeDir|0o755 {
						t.Errorf("%s: mode %v, want drwxr-xr-x", d, got)
					}
				}
			},
		},
		{
			name: "character device refused", formats: allFmts, wantErr: "entries are refused",
			ents:  []ent{{typ: tar.TypeChar, name: "null", mode: 0o666}},
			check: func(t *testing.T, dst string) { assertAbsent(t, filepath.Join(dst, "null")) },
		},
		{
			name: "FIFO refused", formats: tarFmts, wantErr: "FIFO entries are refused",
			ents:  []ent{{typ: tar.TypeFifo, name: "pipe", mode: 0o666}},
			check: func(t *testing.T, dst string) { assertAbsent(t, filepath.Join(dst, "pipe")) },
		},
		{
			name: "dangling in-tree link kept", formats: allFmts,
			ents: []ent{sym("dangling", "missing")},
			check: func(t *testing.T, dst string) {
				if got, err := os.Readlink(filepath.Join(dst, "dangling")); err != nil || got != "missing" {
					t.Errorf("Readlink = %q, %v; want missing", got, err)
				}
			},
		},
		{
			name: "node's npm link kept", formats: allFmts,
			ents: []ent{reg("lib/node_modules/npm/bin/npm-cli.js", "js", 0o755), sym("bin/npm", "../lib/node_modules/npm/bin/npm-cli.js")},
			check: func(t *testing.T, dst string) {
				if b, err := os.ReadFile(filepath.Join(dst, "bin", "npm")); err != nil || string(b) != "js" {
					t.Errorf("ReadFile(bin/npm) = %q, %v; want the script", b, err)
				}
			},
		},
		{
			name: "write through a link to the root refused", formats: allFmts, wantErr: "parent a is a symlink",
			ents:  []ent{sym("a", "."), reg("a/x", "x", 0o644)},
			check: func(t *testing.T, dst string) { assertAbsent(t, filepath.Join(dst, "x")) },
		},
		{
			name: "link climbing out through a link to the root refused", formats: allFmts, wantErr: "is not a canonical relative path",
			ents:  []ent{sym("a", "."), sym("e", "a/a/a/a/../../../../etc/cron.d/evil")},
			check: func(t *testing.T, dst string) { assertAbsent(t, filepath.Join(dst, "e")) },
		},
		{
			name: "dangling escape refused before its missing directory exists", formats: allFmts, wantErr: "is not a canonical relative path",
			ents:  []ent{sym("a", "."), sym("e", escapeC21), dir("missing/")},
			check: func(t *testing.T, dst string) { assertAbsent(t, filepath.Join(dst, "e")) },
		},
		{
			name: "dangling escape refused after its missing directory exists", formats: allFmts, wantErr: "is not a canonical relative path",
			ents:  []ent{sym("a", "."), dir("missing/"), sym("e", escapeC21)},
			check: func(t *testing.T, dst string) { assertAbsent(t, filepath.Join(dst, "e")) },
		},
		{
			// Only the post-pass sees a loop: the target text alone is canonical.
			name: "symlink loop refused", formats: allFmts, wantErr: "unpack: a: symlink target does not resolve inside the destination",
			ents: []ent{sym("a", "b"), sym("b", "a")},
		},
		{
			name: "write through an in-tree link to a sibling refused", formats: allFmts, wantErr: "parent lnk is a symlink",
			ents:  []ent{dir("sub/"), sym("lnk", "sub"), reg("lnk/file", "x", 0o644)},
			check: func(t *testing.T, dst string) { assertAbsent(t, filepath.Join(dst, "sub", "file")) },
		},
		{
			name: "absolute name refused", formats: allFmts, wantErr: "the name leaves the destination",
			ents: []ent{reg("/outside.txt", "pwned", 0o644)},
		},
		{
			name: "dot-dot name refused", formats: allFmts, wantErr: "the name leaves the destination",
			ents: []ent{reg("../outside.txt", "pwned", 0o644)},
		},
		{
			name: "name climbing out past a directory refused", formats: allFmts, wantErr: "the name leaves the destination",
			ents: []ent{reg("a/../../outside.txt", "pwned", 0o644)},
		},
		{
			name: "second entry at a name refused", formats: allFmts, wantErr: "file exists",
			ents: []ent{reg("x", "first", 0o644), reg("x", "second", 0o755)},
			check: func(t *testing.T, dst string) {
				if b, err := os.ReadFile(filepath.Join(dst, "x")); err != nil || string(b) != "first" {
					t.Errorf("ReadFile(x) = %q, %v; want the first entry's content", b, err)
				}
			},
		},
		{
			name: "file over a directory refused", formats: allFmts, wantErr: "file exists",
			ents: []ent{dir("d/"), reg("d", "x", 0o644)},
		},
		{
			name: "link over a file refused", formats: allFmts, wantErr: "file exists",
			ents: []ent{reg("x", "first", 0o644), sym("x", "y")},
		},
		{
			name: "directory over a file refused", formats: allFmts, wantErr: "the name is already taken",
			ents: []ent{reg("d", "x", 0o644), dir("d/")},
		},
		{
			name: "directory declared again accepted", formats: allFmts,
			ents: []ent{dir("d/"), reg("d/f", "x", 0o644), dir("d/")},
		},
		{
			name: "hard link to a symlink refused", formats: tarFmts, wantErr: "hard link target a/b/l is not a regular file",
			ents:  []ent{sym("a/b/l", "../../x"), reg("x", "x", 0o644), hard("l2", "a/b/l")},
			check: func(t *testing.T, dst string) { assertAbsent(t, filepath.Join(dst, "l2")) },
		},
		{
			name: "hard link to a directory refused", formats: tarFmts, wantErr: "hard link target d is not a regular file",
			ents: []ent{dir("d/"), hard("h", "d")},
		},
		{
			name: "hard link to a missing name refused", formats: tarFmts, wantErr: "hard link target nope is not a regular file",
			ents: []ent{hard("h", "nope")},
		},
		{
			name: "hard link through a symlinked parent refused", formats: tarFmts, wantErr: "hard link target lnk/f is not a regular file",
			ents: []ent{reg("sub/f", "x", 0o644), sym("lnk", "sub"), hard("h", "lnk/f")},
		},
		{
			name: "hard link to a regular file kept", formats: tarFmts,
			ents: []ent{reg("d/f", "x", 0o755), hard("h", "d/f")},
			check: func(t *testing.T, dst string) {
				a, err := os.Lstat(filepath.Join(dst, "d", "f"))
				if err != nil {
					t.Fatal(err)
				}
				b, err := os.Lstat(filepath.Join(dst, "h"))
				if err != nil {
					t.Fatal(err)
				}
				if !os.SameFile(a, b) {
					t.Error("h is not the same inode as d/f")
				}
			},
		},
		{
			name: "archive times land on files only", formats: allFmts,
			ents: []ent{
				{typ: tar.TypeDir, name: "./", mode: 0o755, mtime: date2019},
				{typ: tar.TypeDir, name: "d/", mode: 0o755, mtime: date2019},
				{typ: tar.TypeReg, name: "d/f", body: "x", mode: 0o644, mtime: date2019},
			},
			check: func(t *testing.T, dst string) {
				for _, d := range []string{dst, filepath.Join(dst, "d")} {
					fi, err := os.Lstat(d)
					if err != nil {
						t.Fatal(err)
					}
					if age := time.Since(fi.ModTime()); age > time.Minute || age < -time.Minute {
						t.Errorf("%s: mtime %v, want the extraction time", d, fi.ModTime())
					}
				}
				fi, err := os.Lstat(filepath.Join(dst, "d", "f"))
				if err != nil {
					t.Fatal(err)
				}
				if !fi.ModTime().Equal(date2019) {
					t.Errorf("d/f: mtime %v, want the archived %v", fi.ModTime(), date2019)
				}
			},
		},
	}
	for _, tc := range cases {
		for _, format := range tc.formats {
			t.Run(tc.name+" "+format, func(t *testing.T) {
				t.Parallel()
				dst, err := extract(t, format, archiveOf(t, format, tc.ents...), generous)
				switch {
				case tc.wantErr == "" && err != nil:
					t.Fatalf("Archive = %v, want nil", err)
				case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
					t.Fatalf("Archive = %v, want an error containing %q", err, tc.wantErr)
				}
				if b, rerr := os.ReadFile(filepath.Join(filepath.Dir(dst), "outside.txt")); rerr != nil || string(b) != "sentinel" {
					t.Errorf("outside.txt = %q, %v; want it untouched", b, rerr)
				}
				assertOwnedByUs(t, dst)
				if tc.check != nil {
					tc.check(t, dst)
				}
			})
		}
	}
}

// TestArchive_Sparse covers both sparse encodings archive/tar reads, which
// expand to more bytes than the stream carries.
func TestArchive_Sparse(t *testing.T) {
	t.Parallel()
	want := append(make([]byte, 1<<20), "end\n"...)
	for _, fixture := range []string{"sparse-pax.tar", "sparse-gnu.tar"} {
		t.Run(fixture, func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(filepath.Join("testdata", fixture))
			if err != nil {
				t.Fatal(err)
			}
			dst, err := extract(t, formatTar, data, generous)
			if err != nil {
				t.Fatalf("Archive: %v", err)
			}
			got, err := os.ReadFile(filepath.Join(dst, "sparse"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("sparse holds %d bytes, want the 1 MiB hole and \"end\\n\"", len(got))
			}
			_, err = extract(t, formatTar, data, Limits{MaxBytes: 64 << 10, MaxEntries: 10})
			if err == nil || !strings.Contains(err.Error(), "exceeds the 65536 byte limit") {
				t.Errorf("Archive under a 64 KiB limit = %v, want the byte limit: the hole counts as written", err)
			}
		})
	}
}

func TestArchive_TarBz2(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("testdata", "hello.tar.bz2"))
	if err != nil {
		t.Fatal(err)
	}
	dst, err := extract(t, formatTarBz2, data, generous)
	if err != nil {
		t.Fatalf("Archive: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dst, "hello")); err != nil || string(b) != "hello\n" {
		t.Errorf("hello = %q, %v", b, err)
	}
}

func TestArchive_Limits(t *testing.T) {
	t.Parallel()
	for _, format := range allFmts {
		t.Run("bytes "+format, func(t *testing.T) {
			t.Parallel()
			data := archiveOf(t, format, reg("big", strings.Repeat("x", 2000), 0o644))
			_, err := extract(t, format, data, Limits{MaxBytes: 1999, MaxEntries: 10})
			if err == nil || !strings.Contains(err.Error(), "archive exceeds the 1999 byte limit") {
				t.Errorf("Archive = %v, want the byte limit", err)
			}
			if _, err := extract(t, format, data, Limits{MaxBytes: 1 << 20, MaxEntries: 10}); err != nil {
				t.Errorf("Archive under a fitting limit = %v", err)
			}
		})
		t.Run("entries "+format, func(t *testing.T) {
			t.Parallel()
			data := archiveOf(t, format, reg("a", "", 0o644), reg("b", "", 0o644), reg("c", "", 0o644))
			_, err := extract(t, format, data, Limits{MaxBytes: 1 << 20, MaxEntries: 2})
			if err == nil || !strings.Contains(err.Error(), "archive exceeds the 2 entry limit") {
				t.Errorf("Archive = %v, want the entry limit", err)
			}
			if _, err := extract(t, format, data, Limits{MaxBytes: 1 << 20, MaxEntries: 3}); err != nil {
				t.Errorf("Archive under a fitting limit = %v", err)
			}
		})
	}
	t.Run("implied directories", func(t *testing.T) {
		t.Parallel()
		data := tarOf(t, reg("a/b/c/f", "", 0o644))
		_, err := extract(t, formatTar, data, Limits{MaxBytes: 1 << 20, MaxEntries: 3})
		if err == nil || !strings.Contains(err.Error(), "archive exceeds the 3 entry limit") {
			t.Errorf("Archive = %v, want the entry limit: a, a/b and a/b/c count", err)
		}
		if _, err := extract(t, formatTar, data, Limits{MaxBytes: 1 << 20, MaxEntries: 4}); err != nil {
			t.Errorf("Archive under a fitting limit = %v", err)
		}
	})
	t.Run("name length", func(t *testing.T) {
		t.Parallel()
		long := strings.Repeat("a/", maxName/2) + "f"
		_, err := extract(t, formatTar, tarOf(t, reg(long, "", 0o644)), generous)
		if err == nil || !strings.Contains(err.Error(), "the name is over 4096 bytes") {
			t.Errorf("Archive = %.120v, want the name refused", err)
		}
	})
	t.Run("one byte over", func(t *testing.T) {
		t.Parallel()
		// The last 512-byte read lands exactly one byte past the limit and
		// fills io.ReadFull's buffer, which drops an error sent with data.
		data := tarOf(t, reg("a", "", 0o644))
		_, err := extract(t, formatTar, data, Limits{MaxBytes: int64(len(data)) - 1, MaxEntries: 10})
		if err == nil || !strings.Contains(err.Error(), "byte limit") {
			t.Errorf("Archive = %v, want the byte limit", err)
		}
		if _, err := extract(t, formatTar, data, Limits{MaxBytes: int64(len(data)), MaxEntries: 10}); err != nil {
			t.Errorf("Archive at exactly the limit = %v", err)
		}
	})
	t.Run("stream", func(t *testing.T) {
		t.Parallel()
		// Empty files write nothing, but their headers are decompressed stream.
		data := gzipOf(t, tarOf(t, reg("a", "", 0o644), reg("b", "", 0o644), reg("c", "", 0o644), reg("d", "", 0o644)))
		_, err := extract(t, formatTarGz, data, Limits{MaxBytes: 2048, MaxEntries: 10})
		if err == nil || !strings.Contains(err.Error(), "byte limit") {
			t.Errorf("Archive = %v, want the byte limit on the decompressed stream", err)
		}
	})
}

func TestArchive_RefusesWhatItCannotRead(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct{ format, want string }{
		"unknown format":     {"tar.lz4", `unpack: unsupported archive format "tar.lz4"`},
		"xz without filter":  {formatTarXz, "unpack: xz: no decompression filter is configured"},
		"zst without filter": {formatTarZst, "unpack: zstd: no decompression filter is configured"},
		"corrupt gzip":       {formatTarGz, "unpack: reading the archive: gzip: invalid header"},
		"corrupt zip":        {formatZip, "unpack: reading the archive: zip: not a valid zip file"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dst, err := extract(t, tc.format, []byte("not an archive at all"), generous)
			if err == nil || err.Error() != tc.want {
				t.Errorf("Archive = %v, want %q", err, tc.want)
			}
			if entries, rerr := os.ReadDir(dst); rerr != nil || len(entries) != 0 {
				t.Errorf("dst holds %v, %v; want nothing", entries, rerr)
			}
		})
	}
}

func TestArchive_EntryNamesAreSanitizedInErrors(t *testing.T) {
	t.Parallel()
	_, err := extract(t, formatTar, tarOf(t, ent{typ: tar.TypeChar, name: "evil\x1b[31m\nname"}), generous)
	if err == nil || strings.ContainsAny(err.Error(), "\x1b\n") {
		t.Errorf("Archive = %q, want a refusal with no escape or newline", err)
	}
}

func TestSingle(t *testing.T) {
	t.Parallel()
	bz, err := os.ReadFile(filepath.Join("testdata", "hello.bz2"))
	if err != nil {
		t.Fatal(err)
	}
	for format, data := range map[string][]byte{
		formatRaw: []byte("hello\n"),
		formatGz:  gzipOf(t, []byte("hello\n")),
		formatBz2: bz,
	} {
		t.Run(format, func(t *testing.T) {
			t.Parallel()
			dst := t.TempDir()
			root, err := os.OpenRoot(dst)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			src := io.NewSectionReader(bytes.NewReader(data), 0, int64(len(data)))
			if err := Single(t.Context(), src, format, root, "tool", generous, nil); err != nil {
				t.Fatalf("Single: %v", err)
			}
			if b, err := os.ReadFile(filepath.Join(dst, "tool")); err != nil || string(b) != "hello\n" {
				t.Errorf("tool = %q, %v", b, err)
			}
			if got := lstatMode(t, filepath.Join(dst, "tool")); got != 0o755 {
				t.Errorf("tool: mode %v, want -rwxr-xr-x", got)
			}
			err = Single(t.Context(), src, format, root, "tool", generous, nil)
			if err == nil || !strings.Contains(err.Error(), "file exists") {
				t.Errorf("Single over an existing name = %v, want the refusal", err)
			}
			err = Single(t.Context(), src, format, root, "big", Limits{MaxBytes: 5, MaxEntries: 1}, nil)
			if err == nil || !strings.Contains(err.Error(), "exceeds the 5 byte limit") {
				t.Errorf("Single under a 5-byte limit = %v, want the byte limit", err)
			}
		})
	}
	t.Run("names", func(t *testing.T) {
		t.Parallel()
		root, err := os.OpenRoot(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		src := io.NewSectionReader(strings.NewReader("x"), 0, 1)
		for _, name := range []string{"", ".", "..", "a/b", "/abs"} {
			if err := Single(t.Context(), src, formatRaw, root, name, generous, nil); err == nil || !strings.Contains(err.Error(), "is not a file name") {
				t.Errorf("Single(name %q) = %v, want the name refused", name, err)
			}
		}
	})
}

// TestCheckLinkTarget is the creation rule's table (5.5).
func TestCheckLinkTarget(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, target string
		ok           bool
	}{
		{"bin/npm", "../lib/x", true},
		{"bin/x", "../../x", false},
		{"a/b/l", "../../x", true},
		{"a/b/l", "../../../x", false},
		{"x", "y", true},
		{"x", ".", true},
		{"x", "..", false},
		{"bin/x", "a/../b", false},
		{"bin/x", "../a/../b", false},
		{"x", "./x", false},
		{"x", "x/", false},
		{"x", "x//y", false},
		{"x", "/etc/x", false},
		{"x", "", false},
		{"e", "a/a/a/a/../../../../etc/cron.d/evil", false},
	} {
		err := checkLinkTarget(tc.name, tc.target)
		if (err == nil) != tc.ok {
			t.Errorf("checkLinkTarget(%q, %q) = %v, want ok=%v", tc.name, tc.target, err, tc.ok)
		}
	}
}

// TestCheckTree drives the post-pass on trees built directly with os.Root,
// because no archive reaches its refusals while the entry rules hold.
func TestCheckTree(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		build   func(r *os.Root) error
		name    string
		wantErr string
	}{
		{
			name:    "hard link to a symlink at another depth",
			wantErr: "unpack: l2: symlink target ../../x is not a canonical relative path inside the destination",
			build: func(r *os.Root) error {
				return errors.Join(r.MkdirAll("a/b", 0o755), r.Symlink("../../x", "a/b/l"), r.Link("a/b/l", "l2"))
			},
		},
		{
			name:    "escape through a link to the root",
			wantErr: "is not a canonical relative path",
			build: func(r *os.Root) error {
				return errors.Join(r.Symlink(".", "a"), r.Symlink("a/a/a/a/../../../../etc/cron.d/evil", "e"))
			},
		},
		{
			name:    "link that never resolves",
			wantErr: "unpack: loop: symlink target does not resolve inside the destination",
			build:   func(r *os.Root) error { return r.Symlink("loop", "loop") },
		},
		{
			name: "node's dangling npm link",
			build: func(r *os.Root) error {
				return errors.Join(r.Mkdir("bin", 0o755), r.Symlink("../lib/node_modules/npm/bin/npm-cli.js", "bin/npm"))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root, err := os.OpenRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if err := tc.build(root); err != nil {
				t.Fatal(err)
			}
			err = checkTree(root)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Errorf("checkTree = %v, want nil", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Errorf("checkTree = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// TestFilter_DescendantHoldingStdout pins R4.7 for a descendant that keeps
// the filter's stdout open: the call returns within the 2 s WaitDelay.
func TestFilter_DescendantHoldingStdout(t *testing.T) {
	t.Parallel()
	t.Run("Archive", func(t *testing.T) {
		t.Parallel()
		f := newFakeFilter(t, `cat "$1"; sleep 30 &`, tarOf(t, reg("tool", "x", 0o755)))
		took, err := filterArchive(t, f.run, oneMiB)
		if err != nil || took > 5*time.Second {
			t.Errorf("Archive = %v after %v, want nil within 5s", err, took)
		}
	})
	t.Run("Single", func(t *testing.T) {
		t.Parallel()
		f := newFakeFilter(t, `cat "$1"; sleep 30 &`, []byte("binary"))
		root, err := os.OpenRoot(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		start := time.Now()
		err = Single(ctx, io.NewSectionReader(strings.NewReader("x"), 0, 1), formatXz, root, "tool", oneMiB, f.run)
		if took := time.Since(start); err != nil || took > 5*time.Second {
			t.Errorf("Single = %v after %v, want nil within 5s", err, took)
		}
	})
}

// TestArchive_ChecksTheGzipTrailer pins that a tar.gz whose content was
// corrupted after compression is refused by gzip's CRC, which sits after
// tar's end-of-archive blocks.
func TestArchive_ChecksTheGzipTrailer(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.NoCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(tarOf(t, reg("tool", "echo genuine\n", 0o755))); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	i := bytes.Index(data, []byte("echo genuine"))
	if i < 0 {
		t.Fatal("INVALID: stored gzip does not hold the content verbatim")
	}
	data[i+5] = 'G'
	_, err = extract(t, formatTarGz, data, generous)
	if err == nil || !strings.Contains(err.Error(), "gzip: invalid checksum") {
		t.Errorf("Archive = %v, want the gzip checksum refusal", err)
	}
}

// TestArchive_SkipsAGlobalHeader pins that git archive's pax global header
// (its commit id) is metadata, not an entry.
func TestArchive_SkipsAGlobalHeader(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeXGlobalHeader, Name: "pax_global_header", PAXRecords: map[string]string{"comment": "0123abcd"}}); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "a", Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	dst, err := extract(t, formatTar, buf.Bytes(), generous)
	if err != nil {
		t.Fatalf("Archive = %v, want nil", err)
	}
	entries, err := os.ReadDir(dst)
	if err != nil || len(entries) != 1 || entries[0].Name() != "a" {
		t.Errorf("dst holds %v, %v; want a alone", entries, err)
	}
}

// TestArchive_DirectoryModeIgnoresTheUmask changes the process umask, so it
// is not parallel: parallel tests wait until sequential ones finish.
func TestArchive_DirectoryModeIgnoresTheUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	dst, err := extract(t, formatTar, tarOf(t, dir("d/"), reg("e/f", "x", 0o644)), generous)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"d", "e"} {
		if got := lstatMode(t, filepath.Join(dst, d)); got != fs.ModeDir|0o755 {
			t.Errorf("%s: mode %v under umask 077, want drwxr-xr-x", d, got)
		}
	}
}

func TestArchive_RefusesAnOverlongZipSymlinkTarget(t *testing.T) {
	t.Parallel()
	_, err := extract(t, formatZip, zipOf(t, sym("l", strings.Repeat("a", maxLinkTarget+1))), generous)
	if err == nil || !strings.Contains(err.Error(), "symlink target is over 4096 bytes") {
		t.Errorf("Archive = %.120v, want the target length refused", err)
	}
}

func TestSingle_SanitizesErrors(t *testing.T) {
	t.Parallel()
	f := newFakeFilter(t, `printf '\033[31m\nbad' >&2; exit 1`, nil)
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	err = Single(t.Context(), io.NewSectionReader(strings.NewReader("x"), 0, 1), formatXz, root, "tool", oneMiB, f.run)
	if err == nil || strings.ContainsAny(err.Error(), "\x1b\n") || !strings.Contains(err.Error(), "bad") {
		t.Errorf("Single = %q, want the filter's stderr on one line with no escape", err)
	}
}

// cancelAfter reports no error for its first n Err calls, then Canceled.
type cancelAfter struct {
	context.Context
	n int
}

func (c *cancelAfter) Err() error {
	if c.n == 0 {
		return context.Canceled
	}
	c.n--
	return nil
}

// TestArchive_ZipStopsWhenCancelled uses directory entries, which read
// nothing through the meter, so only the per-entry check sees the cancel.
func TestArchive_ZipStopsWhenCancelled(t *testing.T) {
	t.Parallel()
	data := zipOf(t, dir("a/"), dir("b/"), dir("c/"))
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	ctx := &cancelAfter{Context: t.Context(), n: 2}
	err = Archive(ctx, io.NewSectionReader(bytes.NewReader(data), 0, int64(len(data))), formatZip, root, generous, nil)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Archive = %v, want context.Canceled", err)
	}
	if _, serr := root.Lstat("c"); !errors.Is(serr, fs.ErrNotExist) {
		t.Errorf("c was extracted after the cancellation: %v", serr)
	}
}

// TestMeter_HandlesAnUnboundedLimit pins that the largest limit does not
// overflow the read cap.
func TestMeter_HandlesAnUnboundedLimit(t *testing.T) {
	t.Parallel()
	_, err := extract(t, formatTar, tarOf(t, reg("a", "x", 0o644)), Limits{MaxBytes: 1<<63 - 1, MaxEntries: 10})
	if err != nil {
		t.Errorf("Archive = %v, want nil", err)
	}
}
