package unpack

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeFilter stands in for xz: it runs script under sh with $1 naming a file
// holding data, and keeps the command so a test can check it was reaped.
type fakeFilter struct {
	cmd    *exec.Cmd
	script string
	file   string
	mu     sync.Mutex
}

func newFakeFilter(t *testing.T, script string, data []byte) *fakeFilter {
	t.Helper()
	file := filepath.Join(t.TempDir(), "stream")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return &fakeFilter{script: script, file: file}
}

func (f *fakeFilter) run(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
	if name != "xz" || len(args) != 1 || args[0] != "-dc" {
		return nil, errors.New("fakeFilter: unexpected " + name + " " + strings.Join(args, " "))
	}
	cmd := exec.CommandContext(ctx, "sh", "-c", f.script, "_", f.file)
	f.mu.Lock()
	f.cmd = cmd
	f.mu.Unlock()
	return cmd, nil
}

// reaped reports whether the filter process was waited for.
func (f *fakeFilter) reaped() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cmd != nil && f.cmd.ProcessState != nil
}

// filterArchive runs Archive as tar.xz through filter, under a 10-second
// deadline, and returns the error and how long the call took.
func filterArchive(t *testing.T, filter FilterFunc, lim Limits) (time.Duration, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	start := time.Now()
	err = Archive(ctx, io.NewSectionReader(strings.NewReader("compressed"), 0, 10), formatTarXz, root, lim, filter)
	return time.Since(start), err
}

// headerOnly is one tar header declaring a 1 GiB file, with no content.
func headerOnly(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := tar.NewWriter(&buf).WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "big", Mode: 0o644, Size: 1 << 30}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

var oneMiB = Limits{MaxBytes: 1 << 20, MaxEntries: 10}

func TestArchive_FilterLifecycle(t *testing.T) {
	t.Parallel()
	valid := tarOf(t, reg("tool", "x", 0o755))
	cases := []struct {
		name    string
		script  string
		want    string // exact error text; "" for nil
		data    []byte
		reaped  bool
		prefix  bool // want is a prefix
		eofLike bool // the error must reach io.ErrUnexpectedEOF
	}{
		{
			name: "endless file content ends at the byte limit", data: headerOnly(t),
			script: `cat "$1"; exec cat /dev/zero`, want: "unpack: archive exceeds the 1048576 byte limit", reaped: true,
		},
		{
			name: "endless output after a complete archive ends at the byte limit", data: valid,
			script: `cat "$1"; exec cat /dev/zero`, want: "unpack: archive exceeds the 1048576 byte limit", reaped: true,
		},
		{name: "complete archive and exit 0 succeeds", data: valid, script: `cat "$1"`, reaped: true},
		{
			name: "refused entry", data: tarOf(t, ent{typ: tar.TypeChar, name: "null"}),
			script: `cat "$1"; exec cat /dev/zero`, want: "unpack: null: character device entries are refused", reaped: true,
		},
		{name: "exit 1 after a valid stream", data: valid, script: `cat "$1"; exit 1`, want: "unpack: xz: exit status 1", reaped: true},
		{
			name: "exit 1 after a valid stream with stderr", data: valid,
			script: `cat "$1"; echo bad >&2; exit 1`, want: "unpack: xz: exit status 1: bad", reaped: true,
		},
		{
			name: "exit 1 mid-header", data: headerOnly(t)[:100],
			script: `cat "$1"; echo bad >&2; exit 1`, want: "unpack: xz: exit status 1: bad: ", prefix: true, eofLike: true, reaped: true,
		},
		{
			name: "format not recognized", data: nil,
			script: `echo 'File format not recognized' >&2; exit 1`, want: "unpack: xz: exit status 1: File format not recognized", reaped: true,
		},
		{
			name: "8000 stderr bytes and exit 0 succeeds", data: valid,
			script: `cat "$1"; head -c 8000 /dev/zero | tr '\0' e >&2`, reaped: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFakeFilter(t, tc.script, tc.data)
			_, err := filterArchive(t, f.run, oneMiB)
			got := ""
			if err != nil {
				got = err.Error()
			}
			switch {
			case tc.prefix && !strings.HasPrefix(got, tc.want):
				t.Errorf("Archive = %q, want a prefix %q", got, tc.want)
			case !tc.prefix && got != tc.want:
				t.Errorf("Archive = %q, want %q", got, tc.want)
			}
			if tc.eofLike && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Errorf("Archive = %v, want it to reach io.ErrUnexpectedEOF", err)
			}
			if f.reaped() != tc.reaped {
				t.Errorf("filter reaped = %v, want %v", f.reaped(), tc.reaped)
			}
		})
	}
}

func TestArchive_FilterDescendantHoldingStderr(t *testing.T) {
	t.Parallel()
	f := newFakeFilter(t, `cat "$1"; sleep 30 >&2 &`, tarOf(t, reg("tool", "x", 0o755)))
	took, err := filterArchive(t, f.run, oneMiB)
	if err != nil {
		t.Errorf("Archive = %v, want nil", err)
	}
	if took > 5*time.Second {
		t.Errorf("Archive took %v, want under 5s: WaitDelay did not bound the reap", took)
	}
}

func TestArchive_FilterCancelled(t *testing.T) {
	t.Parallel()
	f := newFakeFilter(t, `cat "$1"; exec sleep 30`, headerOnly(t))
	ctx, cancel := context.WithCancel(t.Context())
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	stop := time.AfterFunc(200*time.Millisecond, cancel)
	defer stop.Stop()
	start := time.Now()
	err = Archive(ctx, io.NewSectionReader(strings.NewReader("x"), 0, 1), formatTarXz, root, oneMiB, f.run)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Archive = %v, want context.Canceled", err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("Archive took %v after the cancel, want it to return promptly", took)
	}
	if !f.reaped() {
		t.Error("filter not reaped")
	}
}

func TestArchive_FilterThatCannotStart(t *testing.T) {
	t.Parallel()
	called := false
	missing := func(ctx context.Context, _ string, _ ...string) (*exec.Cmd, error) {
		called = true
		return exec.CommandContext(ctx, filepath.Join(t.TempDir(), "xz")), nil
	}
	_, err := filterArchive(t, missing, oneMiB)
	if !called || err == nil || !strings.HasPrefix(err.Error(), "unpack: xz: ") {
		t.Errorf("Archive = %v, want the start failure as unpack: xz: ...", err)
	}
}

func TestStderrCap(t *testing.T) {
	t.Parallel()
	t.Run("writes never fail", func(t *testing.T) {
		t.Parallel()
		var c stderrCap
		for _, n := range []int{100, stderrKeep + 1000, 3000} {
			if got, err := c.Write(make([]byte, n)); got != n || err != nil {
				t.Errorf("Write(%d bytes) = %d, %v; want %d, nil", n, got, err, n)
			}
		}
		if len(c.b) != stderrKeep {
			t.Errorf("kept %d bytes, want %d", len(c.b), stderrKeep)
		}
	})
	t.Run("a child writing past the cap exits clean", func(t *testing.T) {
		t.Parallel()
		var c stderrCap
		cmd := exec.CommandContext(t.Context(), "sh", "-c", `head -c 8000 /dev/zero | tr '\0' e >&2`)
		cmd.Stderr = &c
		if err := cmd.Run(); err != nil {
			t.Errorf("Run = %v, want nil", err)
		}
		if len(c.b) != stderrKeep {
			t.Errorf("kept %d bytes, want %d", len(c.b), stderrKeep)
		}
	})
	t.Run("suffix trims trailing newlines", func(t *testing.T) {
		t.Parallel()
		for in, want := range map[string]string{"": "", "\n": "", "bad\n": ": bad", "a\nb\r\n": ": a\nb"} {
			c := stderrCap{b: []byte(in)}
			if got := c.suffix(); got != want {
				t.Errorf("suffix(%q) = %q, want %q", in, got, want)
			}
		}
	})
}

// TestArchive_RealFilters runs the system xz and zstd when the host has them.
func TestArchive_RealFilters(t *testing.T) {
	t.Parallel()
	for format, bin := range map[string]string{formatTarXz: "xz", formatTarZst: "zstd"} {
		t.Run(bin, func(t *testing.T) {
			t.Parallel()
			path, err := exec.LookPath(bin)
			if err != nil {
				t.Skipf("%s not installed", bin)
			}
			compress := exec.CommandContext(t.Context(), path, "-c")
			compress.Stdin = bytes.NewReader(tarOf(t, reg("tool", "hello", 0o755)))
			data, err := compress.Output()
			if err != nil {
				t.Fatal(err)
			}
			filter := func(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
				return exec.CommandContext(ctx, name, args...), nil
			}
			dst := t.TempDir()
			root, err := os.OpenRoot(dst)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if err := Archive(t.Context(), io.NewSectionReader(bytes.NewReader(data), 0, int64(len(data))), format, root, generous, filter); err != nil {
				t.Fatalf("Archive: %v", err)
			}
			if b, err := os.ReadFile(filepath.Join(dst, "tool")); err != nil || string(b) != "hello" {
				t.Errorf("tool = %q, %v", b, err)
			}
			corrupt := append([]byte(nil), data...)
			corrupt[len(corrupt)/2] ^= 0xff
			root2, err := os.OpenRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer root2.Close()
			err = Archive(t.Context(), io.NewSectionReader(bytes.NewReader(corrupt), 0, int64(len(corrupt))), format, root2, generous, filter)
			if err == nil || !strings.HasPrefix(err.Error(), "unpack: "+bin+": exit status") {
				t.Errorf("Archive of a corrupt stream = %v, want the decompressor's exit status", err)
			}
		})
	}
}
