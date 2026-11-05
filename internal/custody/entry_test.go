//go:build linux

package custody

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestEntryPrivateRefusesAnEntryOwnedByAnotherIdentity is the only coverage the ownership
// half of the artifact rule has, and EntryPrivate gates activation of every version
// directory: dropping this check let a binary owned by a stranger be executed as root,
// because its owner may rewrite it whatever the mode says.
//
// The identity doing the asking is a parameter, as it is on checkSymlink, so the rule gates
// at any privilege: no fixture an unprivileged process can create belongs to anybody else,
// and a rule that read its identity from the ambient process would be pinned only where
// privilege exists — the root-only-green shape that once left the trusted-writer knobs
// disconnected with CI green.
func TestEntryPrivateRefusesAnEntryOwnedByAnotherIdentity(t *testing.T) {
	const stranger = 4242

	path := filepath.Join(t.TempDir(), "artifact")
	if err := os.WriteFile(path, []byte("x"), 0o700); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if os.Geteuid() == 0 {
		// Root's own files are trusted whatever euid is asked about, so as root the
		// fixture has to belong to somebody else — which root is the one identity able to
		// arrange.
		if err := os.Chown(path, stranger, -1); err != nil {
			t.Fatalf("chown the fixture to uid %d: %v", stranger, err)
		}
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("the filesystem reported no ownership information for the fixture")
	}
	owner := int(stat.Uid)
	if owner == 0 {
		t.Fatalf("the fixture is owned by root, which is trusted whoever asks, so this test would prove nothing")
	}
	// Neither the owner nor root: an identity for which the fixture is somebody else's.
	other := owner + 1

	m := Trust{}
	if _, private := m.EntryPrivate(path, false, owner); !private {
		t.Fatalf("EntryPrivate refused an entry owned by the identity running the check, so the fixture is wrong")
	}
	if reason, private := m.EntryPrivate(path, false, other); private {
		t.Errorf("EntryPrivate accepted an entry owned by uid %d when asked as uid %d; that user can rewrite a binary this package executes", owner, other)
	} else if want := fmt.Sprintf("is owned by uid %d", owner); reason != want {
		t.Errorf("EntryPrivate reason = %q, want %q: the operator has to be told which identity owns it", reason, want)
	}
	declared := Trust{UIDs: []int{owner}}
	if _, private := declared.EntryPrivate(path, false, other); !private {
		t.Errorf("EntryPrivate refused uid %d after the caller declared it, which is the whole point of the declaration", owner)
	}
}

// TestEntryPrivateFailsClosedWhenTheListCannotBeRead pins the direction of the one error
// EntryPrivate cannot resolve, AND the words it reports it in. An access-control list it
// could not evaluate is not proof there is nothing to find, and this predicate's answer
// decides whether a version directory is activated, so "I could not look" must never come
// back as "there was nothing there".
//
// The wording half is the operator's half, and it is the reason this predicate returns a
// diagnosis rather than a bool. ErrACLUnreadable and ErrACLDialectUnsupported exist to
// separate "could not be evaluated" from "a stranger can write", so a refusal that reports
// the second for the first sends the operator to chmod a mode that is already correct while
// the real obstacle — a dialect, a seccomp filter denying getxattr, an I/O error — goes
// unmentioned.
func TestEntryPrivateFailsClosedWhenTheListCannotBeRead(t *testing.T) {
	m := Trust{}
	euid := os.Geteuid()
	path := filepath.Join(t.TempDir(), "artifact")
	if err := os.WriteFile(path, []byte("x"), 0o700); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, private := m.EntryPrivate(path, false, euid); !private {
		t.Fatalf("EntryPrivate refused a private fixture, so this test would prove nothing")
	}

	old := getxattrFn
	getxattrFn = func(string, string, []byte) (int, error) { return 0, syscall.EIO }
	defer func() { getxattrFn = old }()

	reason, private := m.EntryPrivate(path, false, euid)
	if private {
		t.Fatal("EntryPrivate accepted an entry whose access-control list it could not read")
	}
	if !strings.Contains(reason, "could not be evaluated") {
		t.Errorf("EntryPrivate reason = %q, want one saying the list could not be evaluated", reason)
	}
	if strings.Contains(reason, "writable") {
		t.Errorf("EntryPrivate reason = %q: nobody was found writable here, and reporting one sends the operator to fix a mode that is already correct", reason)
	}
}

// TestEntryPrivateRefusesASymlinkAsASymlink pins the one refusal whose diagnosis the
// operator cannot act on if it is reported by mode.
//
// A symlink's own mode is 0777 on every Linux system and grants nothing. Judged by that
// mode it reports an entry everyone can write, and chmod cannot fix it: chmod follows the
// link to its target, so the operator changes a different object and the exclusion stays.
// checkSymlink states this rule for the path walk; this is the copy that has to agree, and
// it also closes a fail-OPEN window — Getxattr follows the link, so a link whose TARGET
// carries a POSIX.1e list was judged by the target's list under the link's own stat.
func TestEntryPrivateRefusesASymlinkAsASymlink(t *testing.T) {
	m := Trust{}
	dir := t.TempDir()
	target := filepath.Join(dir, "artifact")
	if err := os.WriteFile(target, []byte("x"), 0o700); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	reason, private := m.EntryPrivate(link, false, os.Geteuid())
	if private {
		t.Fatal("EntryPrivate accepted a symlink; this package executes what is in a version directory, and a link is not that file")
	}
	if !strings.Contains(reason, "symlink") {
		t.Errorf("EntryPrivate reason = %q, want one naming it a symlink: reported by mode the operator is told everyone can write it, and chmod on a link follows to its target", reason)
	}
	if strings.Contains(reason, "writable") {
		t.Errorf("EntryPrivate reason = %q: a link's 0777 mode is not a grant, and reporting it as one is an exclusion nobody can clear", reason)
	}
}
