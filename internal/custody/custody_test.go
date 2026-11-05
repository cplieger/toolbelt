package custody

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// TestVerifyCustodyAcceptsATreeOnlyThisProcessCanWrite pins the positive side, and
// it is the case that must not regress into a refusal: an ordinary private
// directory under the system temp root passes, INCLUDING the world-writable sticky
// ancestor every such path has.

// TestVerifyCustodyAcceptsATreeOnlyThisProcessCanWrite pins the positive side, and
// it is the case that must not regress into a refusal: an ordinary private
// directory under the system temp root passes, INCLUDING the world-writable sticky
// ancestor every such path has.
func TestVerifyCustodyAcceptsATreeOnlyThisProcessCanWrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tools", "pkg-versions")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := (Trust{}).Verify(dir, true); err != nil {
		t.Fatalf("Verify refused a private tree: %v", err)
	}

	// The witness: the chain really does include a world-writable ancestor, so
	// the sticky exemption is what let this pass rather than the absence of one.
	sticky := false
	for component := mustEval(t, dir); ; component = filepath.Dir(component) {
		fi, err := os.Lstat(component)
		if err != nil {
			t.Fatalf("lstat %s: %v", component, err)
		}
		if fi.Mode().Perm()&0o022 != 0 && fi.Mode()&os.ModeSticky != 0 {
			sticky = true
		}
		if component == "/" {
			break
		}
	}
	if !sticky {
		t.Skip("no world-writable sticky ancestor on this system, so the exemption is untested here")
	}
}

// TestVerifyCustodyRefusesAWritableComponent pins the refusal on every shape of
// non-owner write, at every depth of the chain. A component anywhere above the
// protected directory is enough: a principal who can write to a parent renames the
// version tree away and puts its own at that name, and nothing downstream re-digests
// the substitute.
func TestVerifyCustodyRefusesAWritableComponent(t *testing.T) {
	const strangerGID = 65500
	tests := map[string]struct {
		mode  os.FileMode
		chgrp bool
		want  string
	}{
		"group writable, by a group that is not root": {mode: 0o775, chgrp: true, want: "gid 65500"},
		"other writable": {mode: 0o757, want: "everyone"},
		// Both bits set names the GROUP, not everyone: writersOf enumerates the group
		// first and firstStranger stops at the first stranger. The group is pinned so
		// the assertion names it whatever gid the test process carries.
		"both writable, the group reported first":       {mode: 0o777, chgrp: true, want: "gid 65500"},
		"group write only, by a group that is not root": {mode: 0o720, chgrp: true, want: "gid 65500"},
	}
	for name, tc := range tests {
		for _, depth := range []string{"the root itself", "a parent"} {
			t.Run(name+", "+depth, func(t *testing.T) {
				base := t.TempDir()
				parent := filepath.Join(base, "tools")
				root := filepath.Join(parent, "pkg-versions")
				if err := os.MkdirAll(root, 0o755); err != nil {
					t.Fatalf("MkdirAll: %v", err)
				}
				offender := root
				if depth == "a parent" {
					offender = parent
				}
				if tc.chgrp {
					if err := os.Chown(offender, -1, strangerGID); err != nil {
						t.Skipf("cannot hand %s to gid %d (%v), so a group grant to a stranger is untestable here", offender, strangerGID, err)
					}
				}
				if err := os.Chmod(offender, tc.mode); err != nil {
					t.Fatalf("chmod %s: %v", offender, err)
				}

				err := (Trust{}).Verify(root, true)
				if !errors.Is(err, errNoCustody) {
					t.Fatalf("Verify error = %v, want errNoCustody", err)
				}
				if !strings.Contains(err.Error(), offender) {
					t.Errorf("error %q does not name the offending path %s", err, offender)
				}
				if !strings.Contains(err.Error(), tc.want) {
					t.Errorf("error %q does not name the writer (%s)", err, tc.want)
				}
			})
		}
	}
}

// TestVerifyCustodyTrustsNoGroup pins that group 0 is a stranger above the
// root too: a non-root member could rename the root within a 0775 parent and
// plant its own.
func TestVerifyCustodyTrustsNoGroup(t *testing.T) {
	t.Run("a group-0 writable ancestor, by mode", func(t *testing.T) {
		if os.Geteuid() != 0 || os.Getegid() != 0 {
			t.Skip("needs root for the fixture's group to be group 0")
		}
		parent := filepath.Join(t.TempDir(), "shared")
		root := filepath.Join(parent, "pkg-versions")
		if err := os.MkdirAll(root, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0o775); err != nil {
			t.Fatal(err)
		}
		if err := (Trust{}).Verify(root, true); !errors.Is(err, errNoCustody) || !strings.Contains(err.Error(), "can be modified by gid 0") {
			t.Errorf("Verify = %v, want the gid-0 writable ancestor refused", err)
		}
	})
	t.Run("a group-0 entry in an ancestor's list", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "shared")
		root := filepath.Join(parent, "pkg-versions")
		if err := os.MkdirAll(root, 0o755); err != nil {
			t.Fatal(err)
		}
		group0 := buildNFS4ACL(nfs4TypeAllow, nfs4FlagIdentifierGroup, 0, nfs4WriteData, 0)
		defer serveACL(t, parent, xattrNFS4XDR, group0)()
		if err := (Trust{}).Verify(root, true); !errors.Is(err, errNoCustody) || !strings.Contains(err.Error(), "can be modified by gid 0") {
			t.Errorf("Verify = %v, want the ancestor's gid-0 grant refused", err)
		}
	})
	t.Run("a sticky ancestor group 0 can write holds the walk to its links' owners", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "shared")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, os.ModeSticky|0o755); err != nil {
			t.Fatal(err)
		}
		group0 := buildNFS4ACL(nfs4TypeAllow, nfs4FlagIdentifierGroup, 0, nfs4WriteData, 0)
		defer serveACL(t, dir, xattrNFS4XDR, group0)()
		if !sharedSticky(dir, os.Geteuid(), Trust{}) {
			t.Error("sharedSticky = false for a sticky directory group 0 can write")
		}
	})
}

// TestVerifyCustodyFollowsDotDotAsTheKernelDoes pins that ".." moves to the
// parent of the directory a symlink reached, not of the link's own name, so
// the directory the kernel passes through is the one judged.
func TestVerifyCustodyFollowsDotDotAsTheKernelDoes(t *testing.T) {
	base := mustEval(t, t.TempDir())
	open := filepath.Join(base, "home", "open")
	landing := filepath.Join(open, "deep", "safedir")
	opt := filepath.Join(base, "opt")
	for _, d := range []string{filepath.Join(open, "deep", "dir"), filepath.Join(landing, "tb"), filepath.Join(opt, "safedir", "tb"), filepath.Join(opt, "leaf")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(open, "deep", "dir"), filepath.Join(opt, "a")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a/../safedir", filepath.Join(opt, "link")); err != nil {
		t.Fatal(err)
	}
	t.Run("in a relative path", func(t *testing.T) {
		t.Chdir(opt)
		if err := (Trust{}).Verify("a/../safedir", true); !errors.Is(err, errNoCustody) || !strings.Contains(err.Error(), open+", mode 0777") {
			t.Errorf("Verify(a/../safedir) = %v, want the world-writable directory the kernel passes through refused", err)
		}
	})
	for name, path := range map[string]string{
		"in a link target":     filepath.Join(opt, "link", "tb"),
		"in the path as given": opt + "/a/../safedir", // not Join, which cleans ".." away
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := filepath.EvalSymlinks(path); err != nil || !strings.HasPrefix(got, open+"/") {
				t.Fatalf("INVALID: %s resolves to %q, %v; want a path under %s", path, got, err, open)
			}
			if err := (Trust{}).Verify(path, true); !errors.Is(err, errNoCustody) || !strings.Contains(err.Error(), open+", mode 0777") {
				t.Errorf("Verify = %v, want the world-writable directory the kernel passes through refused", err)
			}
		})
	}
}

// TestVerifyCustodyJudgesARelativePathFromRoot pins that a relative path is
// walked from "/", not from the working directory.
func TestVerifyCustodyJudgesARelativePathFromRoot(t *testing.T) {
	open := filepath.Join(t.TempDir(), "open")
	if err := os.MkdirAll(filepath.Join(open, "work", "tools"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Chdir(filepath.Join(open, "work"))
	if err := (Trust{}).Verify("tools", true); !errors.Is(err, errNoCustody) || !strings.Contains(err.Error(), open+", mode 0777") {
		t.Errorf("Verify(relative) = %v, want the world-writable ancestor above the working directory refused", err)
	}
}

// TestVerifyCustodyExemptsAStickyDirectoryOnlyAsAnAncestor pins leafIsRoot:
// a 1777 directory passes when judged as the parent of the tree and is
// refused as the tree itself.
func TestVerifyCustodyExemptsAStickyDirectoryOnlyAsAnAncestor(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	if err := (Trust{}).Verify(dir, false); err != nil {
		t.Errorf("Verify(1777, ancestor) = %v, want nil", err)
	}
	err := (Trust{}).Verify(dir, true)
	if !errors.Is(err, errNoCustody) || !strings.Contains(err.Error(), "sticky bit stops") {
		t.Errorf("Verify(1777, protected) = %v, want the refusal naming the sticky bit", err)
	}
}

// TestVerifyCustodyNeverTrustsEveryone pins the one identity that cannot be
// declared: a grant to everyone names no identity a list could cover.
func TestVerifyCustodyNeverTrustsEveryone(t *testing.T) {
	root := filepath.Join(t.TempDir(), "pkg-versions")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Chmod(root, 0o707); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	// Every identity this process could possibly name, including its own group, so the
	// refusal is not an artifact of an incomplete list.
	trust := Trust{UIDs: []int{0, 1, 2, 3000, os.Geteuid()}}
	err := trust.Verify(root, true)
	if !errors.Is(err, errNoCustody) {
		t.Fatalf("Verify error = %v, want errNoCustody: no list of identities can cover everyone", err)
	}
	if !strings.Contains(err.Error(), "everyone") {
		t.Errorf("error %q does not name everyone as the writer", err)
	}
}

// TestVerifyCustodyEvaluatesAnNFSv4ACL pins the check a mode cannot make. An NFSv4 ACL
// can grant a named non-root user write access the mode does not show, so the list is
// PARSED and its grants are judged like any other writer — refused when the identity is a
// stranger, accepted when the caller has declared it.
func TestVerifyCustodyEvaluatesAnNFSv4ACL(t *testing.T) {
	sample := nfs4Samples["root-owned tools directory, mode 0750"]
	blob, err := base64.StdEncoding.DecodeString(sample.b64)
	if err != nil {
		t.Fatalf("decoding the fixture: %v", err)
	}

	tests := map[string]struct {
		trust   Trust
		wantErr bool
		wantIn  string
	}{
		"nothing declared": {
			trust: Trust{}, wantErr: true, wantIn: "uid 3000",
		},
		"the wrong uid declared": {
			trust: Trust{UIDs: []int{4242}}, wantErr: true, wantIn: "uid 3000",
		},
		"the writer declared": {
			trust: Trust{UIDs: []int{3000}},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "pkg-versions")
			if err := os.MkdirAll(root, 0o755); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			defer serveACL(t, root, xattrNFS4XDR, blob)()

			err := tc.trust.Verify(root, true)
			if tc.wantErr {
				if !errors.Is(err, errNoCustody) {
					t.Fatalf("Verify error = %v, want errNoCustody", err)
				}
				if !strings.Contains(err.Error(), tc.wantIn) {
					t.Errorf("error %q does not name the writer (%s)", err, tc.wantIn)
				}
				return
			}
			if err != nil {
				t.Fatalf("Verify refused a tree whose only extra writer the caller declared: %v", err)
			}
		})
	}
}

// TestVerifyCustodyRefusesAnUnreadableACL pins the fail-closed direction. Reading the list
// is part of establishing the precondition, so an attribute this process cannot read leaves
// it in the same position as finding a grant it cannot accept. Only the answers that
// genuinely mean "this filesystem has no extended attributes" are benign.
func TestVerifyCustodyRefusesAnUnreadableACL(t *testing.T) {
	tests := map[string]struct {
		err     error
		wantErr bool
	}{
		"an I/O error":            {err: syscall.EIO, wantErr: true},
		"permission denied":       {err: syscall.EACCES, wantErr: true},
		"a value too big to read": {err: syscall.E2BIG, wantErr: true},
		"no such attribute":       {err: syscall.ENODATA},
		"no extended attributes":  {err: syscall.ENOTSUP},
		// ENOSYS means the call did not happen (a seccomp filter), so it says
		// nothing about the object and must not read as "no list".
		"the call was denied or is unimplemented": {err: syscall.ENOSYS, wantErr: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "pkg-versions")
			if err := os.MkdirAll(root, 0o755); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			old := getxattrFn
			getxattrFn = func(string, string, []byte) (int, error) { return 0, tc.err }
			defer func() { getxattrFn = old }()

			err := (Trust{}).Verify(root, true)
			switch {
			case tc.wantErr && !errors.Is(err, errNoCustody):
				t.Fatalf("Verify error = %v, want errNoCustody when getxattr answers %v", err, tc.err)
			case tc.wantErr && !errors.Is(err, errACLUnreadable):
				t.Errorf("Verify error = %v, want it to wrap errACLUnreadable", err)
			case !tc.wantErr && err != nil:
				t.Fatalf("Verify error = %v, want nil when getxattr answers %v", err, tc.err)
			}
		})
	}
}

// TestVerifyCustodyRefusesAMalformedACL pins that bytes which are not a well-formed list
// refuse rather than parse to an empty writer set. Under-reporting writers is precisely how
// this check would wave through the tree it exists to refuse.
func TestVerifyCustodyRefusesAMalformedACL(t *testing.T) {
	root := filepath.Join(t.TempDir(), "pkg-versions")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	defer serveACL(t, root, xattrNFS4XDR, []byte("not an acl"))()

	err := (Trust{}).Verify(root, true)
	if !errors.Is(err, errNoCustody) || !errors.Is(err, errACLUnreadable) {
		t.Fatalf("Verify error = %v, want errNoCustody wrapping errACLUnreadable", err)
	}
}

// TestVerifyCustodyAcceptsAPOSIXACLThatGrantsNothing pins the dialect that needs no
// declaration: under POSIX.1e the mask caps every named entry, so a list granting a user
// rwx under an r-x mask grants no write and the tree stays private. The fixture is a real
// ACL the kernel enforces, not a parsed blob.
func TestVerifyCustodyAcceptsAPOSIXACLThatGrantsNothing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "pkg-versions")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	switch err := setPOSIXACL(root, posixACLNamedUserUnderMask); {
	case err == nil:
	case errors.Is(err, syscall.ENOTSUP), errors.Is(err, syscall.EOPNOTSUPP):
		t.Skipf("this filesystem does not support POSIX ACLs (%v)", err)
	default:
		t.Fatalf("the kernel rejected the fixture ACL (%v); the encoding in encodePOSIXACL is wrong", err)
	}
	if fi, err := os.Lstat(root); err != nil {
		t.Fatalf("lstat: %v", err)
	} else if fi.Mode().Perm()&0o022 != 0 {
		t.Fatalf("the fixture widened the mode to %#o; it is meant to leave it at 0755", fi.Mode().Perm())
	}

	if err := (Trust{}).Verify(root, true); err != nil {
		t.Fatalf("Verify refused a directory whose POSIX ACL grants no write: %v", err)
	}
}

// TestVerifyCustodyRefusesANonDirectoryAndAMissingPath pins the two cheap
// structural refusals, which are the ones a caller hits from a typo rather than
// from an attack.
func TestVerifyCustodyRefusesANonDirectoryAndAMissingPath(t *testing.T) {
	base := t.TempDir()
	file := filepath.Join(base, "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	t.Run("a file in the chain", func(t *testing.T) {
		if err := (Trust{}).Verify(filepath.Join(file, "versions"), true); !errors.Is(err, errNoCustody) {
			t.Errorf("Verify error = %v, want errNoCustody", err)
		}
	})
	t.Run("the root itself is a file", func(t *testing.T) {
		if err := (Trust{}).Verify(file, true); !errors.Is(err, errNoCustody) {
			t.Errorf("Verify error = %v, want errNoCustody", err)
		}
	})
	t.Run("a path that does not exist", func(t *testing.T) {
		if err := (Trust{}).Verify(filepath.Join(base, "absent", "versions"), true); !errors.Is(err, errNoCustody) {
			t.Errorf("Verify error = %v, want errNoCustody", err)
		}
	})
}

// TestVerifyCustodyJudgesTheResolvedChain pins that a symlink is resolved before
// the walk, so the directory a link lands in is what gets judged. Judging the link
// itself would be both wrong (a symlink's own mode grants nothing on Linux) and
// exploitable (a safe-looking link into a world-writable directory).
func TestVerifyCustodyJudgesTheResolvedChain(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(filepath.Join(real, "pkg-versions"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	viaLink := filepath.Join(link, "pkg-versions")

	if err := (Trust{}).Verify(viaLink, true); err != nil {
		t.Fatalf("Verify refused a private tree reached through a symlink: %v", err)
	}

	if err := os.Chmod(real, 0o777); err != nil {
		t.Fatalf("chmod the link target: %v", err)
	}
	err := (Trust{}).Verify(viaLink, true)
	if !errors.Is(err, errNoCustody) {
		t.Fatalf("Verify error = %v, want errNoCustody once the link's TARGET is world-writable", err)
	}
	if !strings.Contains(err.Error(), real) {
		t.Errorf("error %q names the link rather than the resolved directory %s", err, real)
	}
}

// TestVerifyCustodyJudgesTheDirectoryHoldingAnIntermediateSymlink pins the
// directory holding a link in the middle of a chain, which filepath.EvalSymlinks
// would visit and discard, so a walk of the endpoints alone misses it.
func TestVerifyCustodyJudgesTheDirectoryHoldingAnIntermediateSymlink(t *testing.T) {
	base := t.TempDir()
	priv := filepath.Join(base, "priv")
	mid := filepath.Join(base, "mid")
	target := filepath.Join(base, "target")
	for _, dir := range []string{priv, mid, target} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll(%s): %v", dir, err)
		}
	}
	link := filepath.Join(mid, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	entry := filepath.Join(priv, "entry")
	if err := os.Symlink(link, entry); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	if err := (Trust{}).Verify(entry, true); err != nil {
		t.Fatalf("Verify refused a private two-hop chain: %v", err)
	}

	if err := os.Chmod(mid, 0o777); err != nil {
		t.Fatalf("chmod the directory holding the middle link: %v", err)
	}
	err := (Trust{}).Verify(entry, true)
	if !errors.Is(err, errNoCustody) {
		t.Fatalf("Verify error = %v, want errNoCustody: everyone can write %s, which holds the link the chain goes through", err, mid)
	}
	if !strings.Contains(err.Error(), mid) {
		t.Errorf("error %q does not name %s, the directory that can repoint the middle of the chain", err, mid)
	}
	if !strings.Contains(err.Error(), "0777") {
		t.Errorf("error %q does not quote the offending mode", err)
	}

	// The witness that this is the same directory the walk already knew how to refuse, so
	// what was missing was the judge and not the rule.
	if err := (Trust{}).Verify(mid, true); !errors.Is(err, errNoCustody) {
		t.Fatalf("Verify(%s) = %v, want errNoCustody when named directly", mid, err)
	}
}

// TestVerifyCustodyRefusesASymlinkCycle pins the bound on the resolution. A cycle has no
// resolved path, so there is nothing to judge and nothing to be told about: an error is the
// only answer that is not a clean verdict about a tree nobody can reach. Resolving the chain
// one link at a time is what makes the bound this walk's own responsibility rather than
// EvalSymlinks's.
func TestVerifyCustodyRefusesASymlinkCycle(t *testing.T) {
	base := t.TempDir()
	a := filepath.Join(base, "a")
	b := filepath.Join(base, "b")
	if err := os.Symlink(b, a); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if err := os.Symlink(a, b); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	err := (Trust{}).Verify(a, true)
	if !errors.Is(err, errNoCustody) {
		t.Fatalf("Verify error = %v, want errNoCustody for a chain that does not resolve", err)
	}
	if !errors.Is(err, syscall.ELOOP) {
		t.Errorf("error %v does not carry ELOOP, which is what an operator will recognise this as", err)
	}
}

// TestVerifyCustodyFollowsAsManyLinksAsTheKernelWould pins where the resolution bound
// sits. The bound mirrors SYMLOOP_MAX, so a chain the kernel would resolve has to be one
// this walk resolves too: refusing one link earlier would refuse a tree open(2) reaches
// perfectly well, and the refusal is an install outage rather than a diagnosis.
func TestVerifyCustodyFollowsAsManyLinksAsTheKernelWould(t *testing.T) {
	// chain links a run of symlinks ending at a private directory and returns the head.
	chain := func(t *testing.T, links int) string {
		t.Helper()
		base := t.TempDir()
		target := filepath.Join(base, "installed")
		if err := os.Mkdir(target, 0o755); err != nil {
			t.Fatalf("Mkdir(%s): %v", target, err)
		}
		next := target
		for i := links - 1; i >= 0; i-- {
			link := filepath.Join(base, fmt.Sprintf("hop%02d", i))
			if err := os.Symlink(next, link); err != nil {
				t.Fatalf("Symlink(%s -> %s): %v", link, next, err)
			}
			next = link
		}
		return next
	}

	t.Run("a chain at the bound resolves", func(t *testing.T) {
		if err := (Trust{}).Verify(chain(t, maxSymlinkHops), true); err != nil {
			t.Errorf("verifyCustodyChain over %d links = %v, want nil: the kernel follows a chain this long",
				maxSymlinkHops, err)
		}
	})

	t.Run("a chain past the bound is refused", func(t *testing.T) {
		err := (Trust{}).Verify(chain(t, maxSymlinkHops+1), true)
		if !errors.Is(err, syscall.ELOOP) {
			t.Errorf("verifyCustodyChain over %d links = %v, want an ELOOP refusal", maxSymlinkHops+1, err)
		}
	})
}

// TestVerifyCustodyRefusesAForeignSymlinkInAStickyDirectoryWidenedOnlyByItsACL
// pins that sharedSticky reads the list: a 1755 sticky directory an EVERYONE@
// entry makes writable is shared, so a stranger's symlink in it is refused.
func TestVerifyCustodyRefusesAForeignSymlinkInAStickyDirectoryWidenedOnlyByItsACL(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("planting a foreign-owned symlink needs root; sharedSticky's own test is the unprivileged witness for the rule")
	}
	base := t.TempDir()
	shared := filepath.Join(base, "shared")
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(filepath.Join(real, "pkg-versions"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.MkdirAll(shared, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// Sticky, and 0755: the MODE says nobody else can create an entry here.
	if err := os.Chmod(shared, os.ModeSticky|0o755); err != nil {
		t.Fatalf("chmod sticky: %v", err)
	}
	hop := filepath.Join(shared, "hop")
	if err := os.Symlink(real, hop); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if err := os.Lchown(hop, 12345, 12345); err != nil {
		t.Skipf("cannot chown a symlink here (%v), so the foreign-link case is untested", err)
	}
	// The list is what actually makes the directory shared, and it is the only difference
	// from the 1777 case the suite already pins.
	everyone := buildNFS4ACL(nfs4TypeAllow, 0, nfs4WhoIsSpecial, nfs4WriteData, nfs4WhoEveryone)
	defer serveACL(t, shared, xattrNFS4XDR, everyone)()

	err := (Trust{}).Verify(filepath.Join(hop, "pkg-versions"), true)
	if !errors.Is(err, errNoCustody) {
		t.Fatalf("Verify error = %v, want errNoCustody: the list lets anyone create entries in %s, so uid 12345's link there can be repointed", err, shared)
	}
	if !strings.Contains(err.Error(), "12345") {
		t.Errorf("error %q does not name the uid that can repoint the link", err)
	}
}

// mustEval resolves path's symlinks or fails the test.
func mustEval(t *testing.T, path string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("EvalSymlinks(%s): %v", path, err)
	}
	return resolved
}

// serveACL makes the attribute reader return blob as target's attr, and nothing for any
// other path or name. It is the seam for the NFSv4 dialect, which no ordinary test
// filesystem can produce.
func serveACL(t *testing.T, target, attr string, blob []byte) func() {
	t.Helper()
	resolved := mustEval(t, target)
	old := getxattrFn
	getxattrFn = func(path, name string, dest []byte) (int, error) {
		if path != resolved || name != attr {
			return 0, syscall.ENODATA
		}
		if dest == nil {
			return len(blob), nil
		}
		if len(dest) < len(blob) {
			return 0, syscall.ERANGE
		}
		return copy(dest, blob), nil
	}
	return func() { getxattrFn = old }
}

// TestVerifyCustodyRefusesAWritableDirectoryHoldingASymlinkOnThePath pins the
// second half of the chain rule. Verify resolves symlinks, but every later
// operation in this package reaches the tree through the NAME (MkdirTemp,
// CreateTemp, OpenRoot, Rename, RemoveAll), so a component another principal can
// replace is a component that can be repointed after the verdict. Judging only the
// resolved chain let a 0777 directory holding the symlink go unexamined.
func TestVerifyCustodyRefusesAWritableDirectoryHoldingASymlinkOnThePath(t *testing.T) {
	base := t.TempDir()
	pub := filepath.Join(base, "pub")
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(filepath.Join(real, "pkg-versions"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.MkdirAll(pub, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Symlink(real, filepath.Join(pub, "tools")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	viaLink := filepath.Join(pub, "tools", "pkg-versions")

	if err := (Trust{}).Verify(viaLink, true); err != nil {
		t.Fatalf("Verify refused a private chain reached through a symlink: %v", err)
	}

	// The resolved target is untouched and still private; only the directory
	// HOLDING the link becomes writable, which is what repoints the name.
	if err := os.Chmod(pub, 0o777); err != nil {
		t.Fatalf("chmod the directory holding the symlink: %v", err)
	}
	err := (Trust{}).Verify(viaLink, true)
	if !errors.Is(err, errNoCustody) {
		t.Fatalf("Verify error = %v, want errNoCustody: the symlink's own directory is writable by everyone, so the name can be repointed", err)
	}
	if !strings.Contains(err.Error(), pub) {
		t.Errorf("error %q does not name %s, the directory that can repoint the path", err, pub)
	}
}

// TestVerifyCustodyRefusesAForeignSymlinkReachedThroughAnotherLink pins that
// sharedSticky follows a symlink: a link's own mode carries no sticky bit, so a
// foreign link in a sticky directory reached through a private link to it must
// be refused as it is when named directly.
func TestVerifyCustodyRefusesAForeignSymlinkReachedThroughAnotherLink(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("planting a foreign-owned symlink needs root")
	}
	base := t.TempDir()
	shared := filepath.Join(base, "shared")
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(filepath.Join(real, "pkg-versions"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.MkdirAll(shared, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// A world-writable sticky directory, i.e. /tmp's shape, which the ancestor rule
	// deliberately accepts.
	if err := os.Chmod(shared, 0o777|os.ModeSticky); err != nil {
		t.Fatalf("chmod sticky: %v", err)
	}
	hop := filepath.Join(shared, "hop")
	if err := os.Symlink(real, hop); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	// Owned by somebody else, which inside a sticky directory means only THEY can
	// remove or replace it.
	if err := os.Lchown(hop, 12345, 12345); err != nil {
		t.Skipf("cannot chown a symlink here (%v), so the foreign-link case is untested", err)
	}

	t.Run("named directly", func(t *testing.T) {
		err := (Trust{}).Verify(filepath.Join(hop, "pkg-versions"), true)
		if !errors.Is(err, errNoCustody) {
			t.Fatalf("Verify error = %v, want errNoCustody", err)
		}
		if !strings.Contains(err.Error(), "12345") {
			t.Errorf("error %q does not name the uid that can repoint the link", err)
		}
	})

	t.Run("reached through a private link to the sticky directory", func(t *testing.T) {
		via := filepath.Join(base, "via")
		if err := os.Symlink(shared, via); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		err := (Trust{}).Verify(filepath.Join(via, "hop", "pkg-versions"), true)
		if !errors.Is(err, errNoCustody) {
			t.Fatalf("Verify error = %v, want errNoCustody: the same foreign link is on the path, one indirection further", err)
		}
	})
}

// TestSharedStickyAsksTheListAndFailsClosed pins the one fact that decides whether a
// symlink must be owned by us, in both of the directions it can be wrong.
func TestSharedStickyAsksTheListAndFailsClosed(t *testing.T) {
	const stranger = 4242
	euid := os.Geteuid()

	// A directory of its own inside the temp root, so its mode is the fixture's rather
	// than whatever t.TempDir chose.
	newDir := func(t *testing.T, mode os.FileMode) string {
		t.Helper()
		dir := filepath.Join(t.TempDir(), "d")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		return dir
	}

	t.Run("a private directory", func(t *testing.T) {
		dir := newDir(t, 0o755)
		if sharedSticky(dir, euid, Trust{}) {
			t.Errorf("sharedSticky(%s) = true on a private directory", dir)
		}
	})

	t.Run("sticky and world-writable by mode", func(t *testing.T) {
		dir := newDir(t, os.ModeSticky|0o777)
		if !sharedSticky(dir, euid, Trust{}) {
			t.Errorf("sharedSticky(%s) = false on a sticky directory everyone can write", dir)
		}
	})

	t.Run("sticky at 1755, wide only by its access-control list", func(t *testing.T) {
		dir := newDir(t, os.ModeSticky|0o755)
		defer serveACL(t, dir, xattrNFS4XDR, buildNFS4ACL(nfs4TypeAllow, 0, 0, nfs4WriteData, stranger))()

		if !sharedSticky(dir, euid, Trust{}) {
			t.Errorf("sharedSticky(%s) = false although its list lets uid %d write: the mode is a lossy projection of the list, and the loss runs the unsafe way",
				dir, stranger)
		}
		if sharedSticky(dir, euid, Trust{UIDs: []int{stranger}}) {
			t.Errorf("sharedSticky(%s) = true although the caller declared uid %d, which is not a stranger anywhere else in this walk",
				dir, stranger)
		}
	})

	t.Run("sticky at 1755, with a list that grants no write", func(t *testing.T) {
		dir := newDir(t, os.ModeSticky|0o755)
		const readData uint32 = 0x00000001
		defer serveACL(t, dir, xattrNFS4XDR, buildNFS4ACL(nfs4TypeAllow, 0, 0, readData, stranger))()

		if sharedSticky(dir, euid, Trust{}) {
			t.Errorf("sharedSticky(%s) = true although the list grants uid %d nothing but read", dir, stranger)
		}
	})

	t.Run("a list that could not be read", func(t *testing.T) {
		dir := newDir(t, os.ModeSticky|0o755)
		old := getxattrFn
		getxattrFn = func(string, string, []byte) (int, error) { return 0, syscall.EIO }
		defer func() { getxattrFn = old }()

		if !sharedSticky(dir, euid, Trust{}) {
			t.Error("sharedSticky = false for a sticky directory whose list it could not read, which retires the ownership demand instead of adding it")
		}
	})

	t.Run("a path it could not stat", func(t *testing.T) {
		dir := newDir(t, 0o755)
		if !sharedSticky(filepath.Join(dir, "does-not-exist"), euid, Trust{}) {
			t.Error("sharedSticky = false for a path it could not stat, which retires the ownership demand instead of adding it")
		}
	})

	t.Run("a wide list on a directory that is not sticky", func(t *testing.T) {
		// Outside the scope of this fact: without the sticky bit the walk refuses such a
		// component outright, and this answer only decides whether a symlink INSIDE it
		// must be ours.
		dir := newDir(t, 0o755)
		defer serveACL(t, dir, xattrNFS4XDR, buildNFS4ACL(nfs4TypeAllow, 0, 0, nfs4WriteData, stranger))()

		if sharedSticky(dir, euid, Trust{}) {
			t.Errorf("sharedSticky(%s) = true on a directory with no sticky bit", dir)
		}
	})

	t.Run("a regular file", func(t *testing.T) {
		dir := newDir(t, 0o755)
		file := filepath.Join(dir, "a-file")
		if err := os.WriteFile(file, nil, 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if sharedSticky(file, euid, Trust{}) {
			t.Error("sharedSticky = true for a regular file, which is not a directory anything can be created in")
		}
	})
}

// TestVerifyCustodyRefusesTheProcessOwnGroup is the unprivileged witness for
// group-write refusal: the runner's own primary gid needs no chown, and no
// group is trusted.
func TestVerifyCustodyRefusesTheProcessOwnGroup(t *testing.T) {
	gid := os.Getgid()
	root := filepath.Join(t.TempDir(), "pkg-versions")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Chmod(root, 0o775); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	err := (Trust{}).Verify(root, true)
	if !errors.Is(err, errNoCustody) {
		t.Fatalf("Verify error = %v, want errNoCustody for a group-writable root", err)
	}
	if want := fmt.Sprintf("gid %d", gid); !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not name the writing group (%s)", err, want)
	}
}

// TestVerifyCustodyRefusesAStickyAncestorWhoseACLGivesItAway pins the one condition the
// sticky exemption depends on and cannot itself check: that nobody else can clear the
// sticky bit. WRITE_OWNER takes the directory and then chmod; WRITE_ACL grants the rest.
// Every other write grant on a sticky ancestor stays exempt, because the kernel applies
// the sticky rule to each removal and rename whatever the list says.
func TestVerifyCustodyRefusesAStickyAncestorWhoseACLGivesItAway(t *testing.T) {
	const stranger = 4242

	tests := map[string]struct {
		mask      uint32
		wantRefus bool
	}{
		"write access, which sticky genuinely contains": {mask: nfs4WriteData},
		"append, likewise": {mask: nfs4AppendData},
		// fs/namei.c may_delete_dentry checks sticky after the directory permission.
		"delete child, which the kernel's sticky rule still overrides": {mask: nfs4DeleteChild},
		"take ownership, which removes the sticky bit":                 {mask: nfs4WriteOwner, wantRefus: true},
		"rewrite the list, which grants the rest":                      {mask: nfs4WriteACL, wantRefus: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			parent := filepath.Join(base, "tools")
			root := filepath.Join(parent, "pkg-versions")
			if err := os.MkdirAll(root, 0o755); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			// A world-writable sticky ancestor: the /tmp shape the exemption exists for.
			// os.ModeSticky is a FileMode bit of its own, not octal 0o1000 -- passing
			// 0o1777 sets plain 0777, which the walk then refuses as world-writable
			// before the sticky branch is ever reached.
			if err := os.Chmod(parent, os.ModeSticky|0o777); err != nil {
				t.Fatalf("chmod: %v", err)
			}

			blob := buildNFS4ACL(nfs4TypeAllow, 0, 0, tc.mask, stranger)
			defer serveACL(t, parent, xattrNFS4XDR, blob)()

			err := (Trust{}).Verify(root, true)
			switch {
			case tc.wantRefus && !errors.Is(err, errNoCustody):
				t.Errorf("Verify = %v, want errNoCustody: the list lets uid %d remove the sticky protection the exemption relies on",
					err, stranger)
			case !tc.wantRefus && err != nil:
				t.Errorf("Verify = %v, want nil: a plain write grant on a sticky ancestor is what the exemption exists to allow", err)
			}
			if tc.wantRefus && err != nil && !strings.Contains(err.Error(), "sticky") {
				t.Errorf("error %q does not explain that the sticky bit was what failed", err)
			}
		})
	}
}

// TestVerifyCustodyAcceptsTheListZFSDerivesForA1777Ancestor serves the list OpenZFS stores
// for a chmod 1777 directory, whose group@ and everyone@ entries carry DELETE_CHILD. Linux
// still enforces sticky over that grant, so the ancestor passes; every other shared shape
// built from the same list must still be refused.
func TestVerifyCustodyAcceptsTheListZFSDerivesForA1777Ancestor(t *testing.T) {
	const stranger = 4242
	zfs1777, err := base64.StdEncoding.DecodeString(nfs4Samples[zfs1777Sample].b64)
	if err != nil {
		t.Fatalf("decoding the fixture: %v", err)
	}
	// Appends one ALLOW entry for uid stranger and bumps the entry count in the header.
	withWriteACL := slices.Clone(zfs1777)
	binary.BigEndian.PutUint32(withWriteACL[4:], binary.BigEndian.Uint32(withWriteACL[4:])+1)
	withWriteACL = append(withWriteACL, buildNFS4ACL(nfs4TypeAllow, 0, 0, nfs4WriteACL, stranger)[nfs4HeaderSize:]...)

	tests := map[string]struct {
		blob       []byte
		onRoot     bool
		parentMode os.FileMode
		rootMode   os.FileMode
		wantErr    string
	}{
		"a 1777 ancestor passes": {
			blob: zfs1777, parentMode: os.ModeSticky | 0o777, rootMode: 0o755,
		},
		"a 1777 protected directory is refused": {
			blob: zfs1777, onRoot: true, parentMode: 0o755, rootMode: os.ModeSticky | 0o777,
			wantErr: "can be modified by",
		},
		"a 0777 ancestor is refused": {
			blob: zfs1777, parentMode: 0o777, rootMode: 0o755,
			wantErr: "can be modified by",
		},
		"a 1777 ancestor whose list also grants WRITE_ACL is refused": {
			blob: withWriteACL, parentMode: os.ModeSticky | 0o777, rootMode: 0o755,
			wantErr: "lets uid 4242 take its ownership or rewrite that list",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			parent := filepath.Join(t.TempDir(), "tools")
			root := filepath.Join(parent, "pkg-versions")
			if err := os.MkdirAll(root, 0o755); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			if err := os.Chmod(root, tc.rootMode); err != nil {
				t.Fatalf("chmod root: %v", err)
			}
			if err := os.Chmod(parent, tc.parentMode); err != nil {
				t.Fatalf("chmod parent: %v", err)
			}
			served := parent
			if tc.onRoot {
				served = root
			}
			defer serveACL(t, served, xattrNFS4XDR, tc.blob)()

			err := (Trust{}).Verify(root, true)
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("Verify = %v, want nil: the kernel enforces sticky over DELETE_CHILD", err)
				}
				return
			}
			if !errors.Is(err, errNoCustody) || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Verify = %v, want errNoCustody containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestAllowsOwnerJudgesTheOwningIdentity is the only coverage the ownership rule has. No
// filesystem fixture can express it: root is always allowed, and every directory an
// unprivileged test can create belongs to the runner, which is also always allowed. So the
// rule is asserted directly, which is possible at any privilege because both identities
// are parameters rather than ambient state.
func TestAllowsOwnerJudgesTheOwningIdentity(t *testing.T) {
	const euid, admin, stranger = 1000, 3000, 4242

	tests := map[string]struct {
		owner int
		trust Trust
		want  bool
	}{
		"this process":                     {owner: euid, want: true},
		"root":                             {owner: 0, want: true},
		"a stranger":                       {owner: stranger, want: false},
		"a stranger the caller declared":   {owner: admin, trust: Trust{UIDs: []int{admin}}, want: true},
		"a stranger beside a declared one": {owner: stranger, trust: Trust{UIDs: []int{admin}}, want: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := tc.trust.allowsOwner(tc.owner, euid); got != tc.want {
				t.Errorf("allowsOwner(owner=%d, euid=%d) with %+v = %v, want %v", tc.owner, euid, tc.trust, got, tc.want)
			}
		})
	}
}

// TestVerifyCustodyWalksThroughASymlinkToTheResolvedTree pins that the walk judges the path
// it RESOLVES to and not only the path as written, without needing any privilege: the
// refusal comes from the list the seam serves on the resolved directory.
//
// It deliberately does NOT witness checkSymlink -- that guard is about who owns the LINK,
// and this passes with it disabled, because the resolved walk catches the target on its own.
// checkSymlink's witness is the unit test below it.
func TestVerifyCustodyWalksThroughASymlinkToTheResolvedTree(t *testing.T) {
	const stranger = 4242

	base := t.TempDir()
	real := filepath.Join(base, "elsewhere")
	link := filepath.Join(base, "tools")
	root := filepath.Join(link, "pkg-versions")
	if err := os.MkdirAll(filepath.Join(real, "pkg-versions"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	// The list sits on the RESOLVED directory, which is the object the walk would miss if
	// it only judged the path as written.
	wide := buildNFS4ACL(nfs4TypeAllow, 0, 0, nfs4WriteData, stranger)
	defer serveACL(t, real, xattrNFS4XDR, wide)()

	err := (Trust{}).Verify(root, true)
	if !errors.Is(err, errNoCustody) {
		t.Fatalf("Verify = %v, want errNoCustody: the resolved directory is writable by uid %d", err, stranger)
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("uid %d", stranger)) {
		t.Errorf("error %q does not name the identity the resolved directory grants write to", err)
	}
}

// TestCheckSymlinkJudgesWhoOwnsTheLink is checkSymlink's unprivileged witness:
// handing a link to another uid needs CAP_CHOWN, so every end-to-end case skips
// on CI.
func TestCheckSymlinkJudgesWhoOwnsTheLink(t *testing.T) {
	const euid, admin, stranger = 1000, 3000, 4242

	tests := map[string]struct {
		owner        int
		parentShared bool
		trust        Trust
		wantRefusal  bool
	}{
		"a stranger's link in a sticky directory others can write": {owner: stranger, parentShared: true, wantRefusal: true},
		"the same link where the parent is not shared":             {owner: stranger},
		"our own link, shared parent":                              {owner: euid, parentShared: true},
		"root's link, shared parent":                               {owner: 0, parentShared: true},
		"a declared identity's link, shared parent":                {owner: admin, parentShared: true, trust: Trust{UIDs: []int{admin}}},
		"an undeclared stranger beside a declared one":             {owner: stranger, parentShared: true, trust: Trust{UIDs: []int{admin}}, wantRefusal: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := checkSymlink("/some/link", tc.owner, euid, tc.parentShared, tc.trust)
			switch {
			case tc.wantRefusal && !errors.Is(err, errNoCustody):
				t.Errorf("checkSymlink(owner=%d, shared=%v) = %v, want errNoCustody: that user can repoint the link",
					tc.owner, tc.parentShared, err)
			case !tc.wantRefusal && err != nil:
				t.Errorf("checkSymlink(owner=%d, shared=%v) = %v, want nil", tc.owner, tc.parentShared, err)
			}
		})
	}
}

// TestAllowsTrustsOnlyUsers is the unprivileged witness for the trust rule:
// no group, group 0 included, and never everyone.
func TestAllowsTrustsOnlyUsers(t *testing.T) {
	const euid, admin = 1000, 3000
	trust := Trust{UIDs: []int{admin}}
	for _, p := range []principal{{kind: principalGroup, id: 0}, {kind: principalGroup, id: euid}, {kind: principalEveryone}} {
		if trust.allows(p, euid) {
			t.Errorf("%v is trusted", p)
		}
	}
	for _, p := range []principal{{kind: principalUser, id: 0}, {kind: principalUser, id: euid}, {kind: principalUser, id: admin}} {
		if !trust.allows(p, euid) {
			t.Errorf("%v is not trusted", p)
		}
	}
}

// TestARefusalNamesTheTrustKnobOnlyWhileItCanHelp pins the hint's directions:
// it names TrustedUIDs for a user writer while none is declared, and never for
// a group or everyone, which no declaration can cover.
func TestARefusalNamesTheTrustKnobOnlyWhileItCanHelp(t *testing.T) {
	const knob, stranger = "TrustedUIDs", 4242
	userGrant := buildNFS4ACL(nfs4TypeAllow, 0, 0, nfs4WriteData, stranger)
	everyoneGrant := buildNFS4ACL(nfs4TypeAllow, 0, nfs4WhoIsSpecial, nfs4WriteData, nfs4WhoEveryone)
	tests := map[string]struct {
		blob     []byte
		trust    Trust
		wantHint bool
	}{
		"a user writer, nothing declared":          {blob: userGrant, wantHint: true},
		"a user writer, another user declared":     {blob: userGrant, trust: Trust{UIDs: []int{1234}}},
		"everyone as the writer, nothing declared": {blob: everyoneGrant},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "root")
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			defer serveACL(t, dir, xattrNFS4XDR, tc.blob)()
			err := tc.trust.Verify(dir, true)
			if !errors.Is(err, errNoCustody) {
				t.Fatalf("Verify(%+v) = %v, want errNoCustody", tc.trust, err)
			}
			if got := strings.Contains(err.Error(), knob); got != tc.wantHint {
				t.Errorf("error %q names %s = %v, want %v", err, knob, got, tc.wantHint)
			}
		})
	}
}

// ownedBy reports fi as owned by uid.
type ownedBy struct {
	os.FileInfo
	st syscall.Stat_t
}

func (o ownedBy) Sys() any { return &o.st }

// TestVerifyCustodyJudgesTheOwnerOfALinkInASharedDirectory is the
// unprivileged witness that the walk judges a link's owner where sticky lets
// that owner replace it: lstatFn reports the link as a stranger's.
func TestVerifyCustodyJudgesTheOwnerOfALinkInASharedDirectory(t *testing.T) {
	const stranger = 4242
	base := mustEval(t, t.TempDir())
	shared := filepath.Join(base, "shared")
	tree := filepath.Join(base, "private", "tools")
	for _, d := range []string{filepath.Join(shared, "sub"), tree} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(shared, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(shared, "link")
	if err := os.Symlink(tree, link); err != nil {
		t.Fatal(err)
	}
	if err := (Trust{}).Verify(link, true); err != nil {
		t.Fatalf("INVALID: Verify through our own link = %v, want nil", err)
	}
	old := lstatFn
	defer func() { lstatFn = old }()
	lstatFn = func(path string) (os.FileInfo, error) {
		fi, err := old(path)
		if err != nil || path != link {
			return fi, err
		}
		st := *fi.Sys().(*syscall.Stat_t)
		st.Uid = stranger
		return ownedBy{FileInfo: fi, st: st}, nil
	}
	// Through "sub/..", the walk must judge shared again, not keep sub's answer.
	for _, path := range []string{link, shared + "/sub/../link"} {
		err := (Trust{}).Verify(path, true)
		if !errors.Is(err, errNoCustody) || !strings.Contains(err.Error(), fmt.Sprintf("symlink owned by uid %d", stranger)) {
			t.Errorf("Verify(%s) = %v, want the stranger's link in a shared sticky directory refused", path, err)
		}
	}
}

// TestVerifyCustodyRefusesAnEmptyPath pins that "" is refused, not read as
// the working directory, which can be a private tree.
func TestVerifyCustodyRefusesAnEmptyPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	if err := (Trust{}).Verify(".", true); err != nil {
		t.Fatalf("INVALID: Verify(.) = %v; the working directory must pass, or the guard is not what refuses", err)
	}
	if err := (Trust{}).Verify("", true); !errors.Is(err, errNoCustody) || !strings.Contains(err.Error(), "an empty path") {
		t.Errorf("Verify(\"\") = %v, want the empty path refused", err)
	}
}
