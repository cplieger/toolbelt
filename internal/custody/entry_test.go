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

// TestEntryPrivateRefusesAnEntryOwnedByAnotherIdentity pins the ownership half of
// the artifact rule: EntryPrivate gates activation, and a binary owned by a
// stranger can be rewritten by its owner whatever its mode says. The asking
// identity is a parameter, as on checkSymlink, so the rule is pinned at any
// privilege: no fixture an unprivileged process creates belongs to anybody else.
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
	if _, private := m.EntryPrivate(path, owner); !private {
		t.Fatalf("EntryPrivate refused an entry owned by the identity running the check, so the fixture is wrong")
	}
	if reason, private := m.EntryPrivate(path, other); private {
		t.Errorf("EntryPrivate accepted an entry owned by uid %d when asked as uid %d; that user can rewrite a binary this package executes", owner, other)
	} else if want := fmt.Sprintf("is owned by uid %d", owner) + m.hint(); reason != want {
		t.Errorf("EntryPrivate reason = %q, want %q: the operator has to be told which identity owns it", reason, want)
	}
	declared := Trust{UIDs: []int{owner}}
	if _, private := declared.EntryPrivate(path, other); !private {
		t.Errorf("EntryPrivate refused uid %d after the caller declared it, which is the whole point of the declaration", owner)
	}
}

// TestEntryPrivateFailsClosedWhenTheListCannotBeRead pins the direction and the
// wording of the one error EntryPrivate cannot resolve. A list it could not
// evaluate is not proof there is nothing to find, and the answer decides whether a
// version directory is activated, so "could not look" never reads as "nothing
// there". The wording must not report a writer either: that sends the operator to
// chmod a mode that is already correct while the real obstacle (a dialect, a
// seccomp filter denying getxattr, an I/O error) goes unmentioned.
func TestEntryPrivateFailsClosedWhenTheListCannotBeRead(t *testing.T) {
	m := Trust{}
	euid := os.Geteuid()
	path := filepath.Join(t.TempDir(), "artifact")
	if err := os.WriteFile(path, []byte("x"), 0o700); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, private := m.EntryPrivate(path, euid); !private {
		t.Fatalf("EntryPrivate refused a private fixture, so this test would prove nothing")
	}

	old := getxattrFn
	getxattrFn = func(string, string, []byte) (int, error) { return 0, syscall.EIO }
	defer func() { getxattrFn = old }()

	reason, private := m.EntryPrivate(path, euid)
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

// TestEntryPrivateRefusesASymlinkAsASymlink pins the refusal whose diagnosis the
// operator cannot act on if it is reported by mode. A symlink's 0777 grants
// nothing, and chmod follows the link to its target, so "everyone can write it"
// is an exclusion nobody can clear. It is the copy of checkSymlink's rule, and it
// closes a fail-open window: Getxattr follows the link, so a link was judged by
// its target's list under its own stat.
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

	reason, private := m.EntryPrivate(link, os.Geteuid())
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

// TestEntryPrivateNamesTheTrustKnobOnlyWhileItCanHelp pins the hint on a writer
// refusal: a user writer is pointed at TrustedUIDs while none is declared, and
// a group or everyone never is, since no declaration can cover them.
func TestEntryPrivateNamesTheTrustKnobOnlyWhileItCanHelp(t *testing.T) {
	const knob, stranger = "TrustedUIDs", 4242
	userGrant := buildNFS4ACL(nfs4TypeAllow, 0, 0, nfs4WriteData, stranger)
	everyoneGrant := buildNFS4ACL(nfs4TypeAllow, 0, nfs4WhoIsSpecial, nfs4WriteData, nfs4WhoEveryone)
	tests := map[string]struct {
		blob     []byte
		mode     os.FileMode
		trust    Trust
		wantHint bool
	}{
		"a user writer, nothing declared":      {blob: userGrant, mode: 0o700, wantHint: true},
		"a user writer, another user declared": {blob: userGrant, mode: 0o700, trust: Trust{UIDs: []int{1234}}},
		"everyone as the writer":               {blob: everyoneGrant, mode: 0o700},
		"the group as the writer":              {mode: 0o720},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "artifact")
			if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal(err)
			}
			if tc.blob != nil {
				defer serveACL(t, path, xattrNFS4XDR, tc.blob)()
			}
			reason, private := tc.trust.EntryPrivate(path, os.Geteuid())
			if private || !strings.HasPrefix(reason, "is writable by ") {
				t.Fatalf("EntryPrivate = %q, %v, want a writer refusal", reason, private)
			}
			if got := strings.Contains(reason, knob); got != tc.wantHint {
				t.Errorf("reason %q names %s = %v, want %v", reason, knob, got, tc.wantHint)
			}
		})
	}
}
