package toolbelt

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cplieger/go/keyenc"
)

// TestProbeFingerprintCannotBeForged pins that two different probe
// subjects never share a fingerprint: a collision reuses one binary's
// verdict for another shape. Each pair below would collapse under a plain
// separator join.
func TestProbeFingerprintCannotBeForged(t *testing.T) {
	// Build the two subjects as real files, since probeFingerprint stats them:
	// identical size and mtime, so only the varying components can distinguish
	// the fingerprints.
	dir := t.TempDir()
	write := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
		return p
	}
	fixed := write("fixed")

	cases := map[string]struct {
		leftWant, rightWant string
		leftArgs, rightArgs []string
	}{
		"separator moves from the version into the arg list": {
			leftWant: "1.0|--x", leftArgs: nil,
			rightWant: "1.0", rightArgs: []string{"--x"},
		},
		"arg elements merge across the list join": {
			leftWant: "1.0", leftArgs: []string{"--", "version"},
			rightWant: "1.0", rightArgs: []string{"--version"},
		},
		"empty arg list is distinct from one empty arg": {
			leftWant: "1.0", leftArgs: nil,
			rightWant: "1.0", rightArgs: []string{""},
		},
		"escape character does not shift the split": {
			leftWant: `1.0\`, leftArgs: nil,
			rightWant: "1.0", rightArgs: []string{`\`},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			left, err := probeFingerprint(fixed, tc.leftWant, tc.leftArgs)
			if err != nil {
				t.Fatalf("left fingerprint: %v", err)
			}
			right, err := probeFingerprint(fixed, tc.rightWant, tc.rightArgs)
			if err != nil {
				t.Fatalf("right fingerprint: %v", err)
			}
			if left == right {
				t.Errorf("distinct probe subjects share the fingerprint %q", left)
			}
		})
	}
}

// TestProbeFingerprintSeparatesPathFromVersion pins the path/version boundary
// specifically: two DIFFERENT binaries whose (path, version) pairs concatenate
// to the same string must keep distinct fingerprints. This is the pair that
// matters most in practice, because an install root is operator-configured and
// a version string comes from the manifest.
func TestProbeFingerprintSeparatesPathFromVersion(t *testing.T) {
	dir := t.TempDir()
	// One real path that contains the separator, and one that does not, chosen
	// so the naive concatenation of (path, version) is identical.
	withSep := filepath.Join(dir, "tool|1.0")
	plain := filepath.Join(dir, "tool")
	for _, p := range []string{withSep, plain} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}

	left, err := probeFingerprint(withSep, "", nil)
	if err != nil {
		t.Fatalf("left fingerprint: %v", err)
	}
	right, err := probeFingerprint(plain, "1.0", nil)
	if err != nil {
		t.Fatalf("right fingerprint: %v", err)
	}
	if left == right {
		t.Errorf("a path carrying the separator collided with a version: %q", left)
	}
}

// TestProbeFingerprintIsStableForOrdinaryInput pins the plain separator-joined
// form for the inputs the reconciler produces: no ordinary component carries a
// reserved character, so keyenc neither escapes nor hashes any of them.
func TestProbeFingerprintIsStableForOrdinaryInput(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "jq")
	if err := os.WriteFile(bin, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	fi, err := os.Stat(bin)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	got, err := probeFingerprint(bin, "1.8.1", []string{"--version"})
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(bin)
	if err != nil {
		t.Fatalf("evalsymlinks: %v", err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	want := strings.Join([]string{
		resolved, "-rw-------", "1", strconv.FormatInt(fi.ModTime().UnixNano(), 10),
		strconv.FormatUint(st.Dev, 10), strconv.FormatUint(st.Ino, 10), strconv.FormatInt(st.Ctim.Nano(), 10),
		"1.8.1", "--version",
	}, ":")
	if got != want {
		t.Errorf("probeFingerprint() = %q, want the plain joined form %q", got, want)
	}
	if keyenc.IsHashed(got) {
		t.Error("an ordinary fingerprint must not be reduced to a hashed identity")
	}
}

// TestFileIdentity_SeparatesARenameWithinOneClockTick pins that a file
// renamed over another within one clock tick, which then shares its ctime,
// mtime, mode and size, still reads as a different file.
func TestFileIdentity_SeparatesARenameWithinOneClockTick(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tool")
	next := filepath.Join(dir, "tool.next")
	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := os.WriteFile(target, []byte("1"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(next, []byte("2"), 0o600); err != nil {
			t.Fatal(err)
		}
		oldStat := statTimes(t, target)
		before, err := fileIdentity(target)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(next, target); err != nil {
			t.Fatal(err)
		}
		after, err := fileIdentity(target)
		if err != nil {
			t.Fatal(err)
		}
		if statTimes(t, target) == oldStat {
			if slices.Equal(before, after) {
				t.Errorf("a rename within one tick kept the identity %q", before)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Skip("this kernel stamped every rename on a later tick than the write")
		}
	}
}

// statTimes is a file's mtime and ctime.
func statTimes(t *testing.T, path string) [2]int64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return [2]int64{fi.ModTime().UnixNano(), fi.Sys().(*syscall.Stat_t).Ctim.Nano()}
}
