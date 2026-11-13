package custody

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// Real access-control lists, read from an OpenZFS nfsv4 dataset with their stat data and
// cross-checked bit for bit against nfs4xdr_getfacl's rendering of the same object.
//
// The 0770 sample is the lossy case: the mode says nothing about the named uid 3000 who
// can write. The two 0750 samples carry a wide group@ entry that is INHERIT_ONLY, so it
// applies to new children (a 0700 mkdir there stores 0770), not to the directory. The
// 1777 sample is the list ZFS derives from a chmod 1777, the shape of /tmp there.
var nfs4Samples = map[string]struct {
	b64  string
	uid  uint32
	gid  uint32
	mode uint32
	want []principal
}{
	"dataset root, owned by a service account, mode 0770 with a named admin and a group grant": {
		b64:  "AAIAAAAAAAQAAAAAAAAAAwAAAAAAHwH/AAALuAAAAAAAAAADAAAAAQAeAf8AAAABAAAAAAAAAEMAAAABABIA7wAAAAIAAAAAAAAAAAAAAAEAEgCIAAAAAw==",
		uid:  1500,
		gid:  1500,
		mode: 0o770,
		want: []principal{
			{kind: principalUser, id: 3000},  // the named admin, WRITE_DATA and more
			{kind: principalGroup, id: 1500}, // group@, resolved to the object's gid
		},
	},
	"root-owned tools directory, mode 0750": {
		b64:  "AAIAAAAAAAYAAAAAAAAAgwAAAAAAHwH/AAALuAAAAAAAAACLAAAAAQAeAf8AAAABAAAAAAAAAMsAAAABABIA7wAAAAIAAAAAAAAAAAAAAAEAHgH/AAAAAQAAAAAAAABAAAAAAQASAKkAAAACAAAAAAAAAAAAAAABABIAiAAAAAM=",
		uid:  0,
		gid:  0,
		mode: 0o750,
		// Only the admin. The wide group@ entry on this directory is INHERIT_ONLY
		// (rendered "fdi" by nfs4xdr_getfacl), so it does not apply to the directory
		// itself — it exists to be copied onto things created inside it, which is
		// exactly why a 0700 mkdir there stores 0770 while the directory itself is
		// 0750. The entry that does apply grants the group r-x.
		want: []principal{{kind: principalUser, id: 3000}},
	},
	"root:service config directory, mode 0750": {
		b64:  "AAIAAAAAAAYAAAAAAAAAgwAAAAAAHwH/AAALuAAAAAAAAACLAAAAAQAeAf8AAAABAAAAAAAAAMsAAAABABIA7wAAAAIAAAAAAAAAAAAAAAEAHgH/AAAAAQAAAAAAAABAAAAAAQASAKkAAAACAAAAAAAAAAAAAAABABIAiAAAAAM=",
		uid:  0,
		gid:  1500,
		mode: 0o750,
		// Same shape: the group@ entry granting write is inherit-only, so the
		// directory on the path is writable only by the admin. This is the sample that
		// corrected my own reading of the tree — the mode understates for the
		// directory's CHILDREN, not for the directory.
		want: []principal{{kind: principalUser, id: 3000}},
	},
	zfs1777Sample: {
		b64:  "AAMAAQAAAAMAAAAAAAAAAAAAAAEAHgH/AAAAAQAAAAAAAABAAAAAAQASAO8AAAACAAAAAAAAAAAAAAABABIA7wAAAAM=",
		uid:  0,
		gid:  0,
		mode: 0o777,
		want: []principal{{kind: principalGroup, id: 0}, {kind: principalEveryone}},
	},
}

// zfs1777Sample names the nfs4Samples entry whose group@ and everyone@ write grants carry
// DELETE_CHILD, which ZFS adds to every mode-derived write grant on a directory.
const zfs1777Sample = "shared sticky directory, mode 1777, the list ZFS derives from that mode"

// TestParseNFS4ACLAgainstRealSamples pins the NFSv4 parser on lists a real ZFS dataset
// carries. A hand-built fixture would only prove the parser agrees with my reading of the
// format; these prove it agrees with the filesystem.
func TestParseNFS4ACLAgainstRealSamples(t *testing.T) {
	for name, tc := range nfs4Samples {
		t.Run(name, func(t *testing.T) {
			blob, err := base64.StdEncoding.DecodeString(tc.b64)
			if err != nil {
				t.Fatalf("decoding the fixture: %v", err)
			}
			got, err := parseNFS4ACL(blob, &syscall.Stat_t{Uid: tc.uid, Gid: tc.gid})
			if err != nil {
				t.Fatalf("parseNFS4ACL: %v", err)
			}
			if !samePrincipals(got, tc.want) {
				t.Errorf("writers = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestParseNFS4ACLRefusesMalformedInput pins the parser's own boundary. It reads
// untrusted bytes off a filesystem, so every shape that is not a well-formed list has to
// be an error rather than a short read that silently reports fewer writers than there
// are — under-reporting writers is how this check would wave through the exact tree it
// exists to refuse.
func TestParseNFS4ACLRefusesMalformedInput(t *testing.T) {
	valid, err := base64.StdEncoding.DecodeString(nfs4Samples["dataset root, owned by a service account, mode 0770 with a named admin and a group grant"].b64)
	if err != nil {
		t.Fatalf("decoding the fixture: %v", err)
	}
	tests := map[string][]byte{
		"empty":                    {},
		"header only":              valid[:8],
		"truncated header":         valid[:4],
		"one byte short of an ace": valid[:len(valid)-1],
		"one byte long":            append(slices.Clone(valid), 0),
		"count larger than body":   append(slices.Clone(valid[:4]), 0xFF, 0xFF, 0xFF, 0xFF),
	}
	for name, blob := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseNFS4ACL(blob, &syscall.Stat_t{}); err == nil {
				t.Error("parseNFS4ACL accepted a malformed list")
			}
		})
	}
}

// TestParseNFS4ACLSkipsWhatCannotGrantWrite pins the three reasons an entry is passed
// over, each of which would otherwise produce a spurious writer and a refusal nobody can
// act on.
func TestParseNFS4ACLSkipsWhatCannotGrantWrite(t *testing.T) {
	tests := map[string]struct {
		aceType, flag, special, mask, id uint32
		want                             []principal
	}{
		"a deny entry": {
			aceType: 1, special: 0, mask: nfs4WriteData, id: 4242,
		},
		"an inherit-only entry": {
			flag: nfs4FlagInheritOnly, special: 0, mask: nfs4WriteData, id: 4242,
		},
		"an allow entry with no write bit": {
			special: 0, mask: 0x00120088, id: 4242,
		},
		"an allow entry that only writes attributes": {
			special: 0, mask: 0x00000110, id: 4242,
		},
		"a named user with write": {
			special: 0, mask: nfs4WriteData, id: 4242,
			want: []principal{{kind: principalUser, id: 4242}},
		},
		"a named group with write": {
			flag: nfs4FlagIdentifierGroup, special: 0, mask: nfs4AppendData, id: 77,
			want: []principal{{kind: principalGroup, id: 77}},
		},
		"a principal who can rewrite the acl": {
			special: 0, mask: nfs4WriteACL, id: 4242,
			want: []principal{{kind: principalUser, id: 4242}},
		},
		"a principal who can take ownership": {
			special: 0, mask: nfs4WriteOwner, id: 4242,
			want: []principal{{kind: principalUser, id: 4242}},
		},
		"everyone with write": {
			special: 1, mask: nfs4WriteData, id: nfs4WhoEveryone,
			want: []principal{{kind: principalEveryone}},
		},
		"the owner with write": {
			special: 1, mask: nfs4WriteData, id: nfs4WhoOwner,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			blob := buildNFS4ACL(tc.aceType, tc.flag, tc.special, tc.mask, tc.id)
			got, err := parseNFS4ACL(blob, &syscall.Stat_t{Gid: 9})
			if err != nil {
				t.Fatalf("parseNFS4ACL: %v", err)
			}
			if !samePrincipals(got, tc.want) {
				t.Errorf("writers = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestParsePOSIXACLAppliesTheMask pins the one thing that makes POSIX.1e different: the
// mask is the ceiling on every named entry and on the owning group, so an entry granting
// write under a mask that withholds it grants nothing. Getting this backwards would
// refuse every ordinary Linux volume that happens to carry an ACL.
func TestParsePOSIXACLAppliesTheMask(t *testing.T) {
	const rwx, rx = 7, 5
	// A distinctive owning gid: GROUP_OBJ carries no id of its own, so this is what the
	// parser must report for it, and nothing else in the table uses the number.
	owning := &syscall.Stat_t{Gid: 8888}
	tests := map[string]struct {
		entries []posixACLEntry
		want    []principal
	}{
		"a named user with write, unmasked": {
			entries: []posixACLEntry{
				{tag: posixTagUserObj, perm: rwx, id: aclUndefinedID},
				{tag: posixTagUser, perm: rwx, id: 1234},
				{tag: posixTagGroupObj, perm: rx, id: aclUndefinedID},
				{tag: posixTagMask, perm: rwx, id: aclUndefinedID},
				{tag: posixTagOther, perm: rx, id: aclUndefinedID},
			},
			want: []principal{{kind: principalUser, id: 1234}},
		},
		"the same user, capped by the mask": {
			entries: []posixACLEntry{
				{tag: posixTagUserObj, perm: rwx, id: aclUndefinedID},
				{tag: posixTagUser, perm: rwx, id: 1234},
				{tag: posixTagGroupObj, perm: rx, id: aclUndefinedID},
				{tag: posixTagMask, perm: rx, id: aclUndefinedID},
				{tag: posixTagOther, perm: rx, id: aclUndefinedID},
			},
		},
		"a named group with write, unmasked": {
			entries: []posixACLEntry{
				{tag: posixTagUserObj, perm: rwx, id: aclUndefinedID},
				{tag: posixTagGroup, perm: rwx, id: 77},
				{tag: posixTagGroupObj, perm: rx, id: aclUndefinedID},
				{tag: posixTagMask, perm: rwx, id: aclUndefinedID},
				{tag: posixTagOther, perm: rx, id: aclUndefinedID},
			},
			want: []principal{{kind: principalGroup, id: 77}},
		},
		"a mask appearing before the entries it caps": {
			entries: []posixACLEntry{
				{tag: posixTagMask, perm: rx, id: aclUndefinedID},
				{tag: posixTagUserObj, perm: rwx, id: aclUndefinedID},
				{tag: posixTagUser, perm: rwx, id: 1234},
				{tag: posixTagGroupObj, perm: rx, id: aclUndefinedID},
				{tag: posixTagOther, perm: rx, id: aclUndefinedID},
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := parsePOSIXACL(encodePOSIXACL(tc.entries), owning)
			if err != nil {
				t.Fatalf("parsePOSIXACL: %v", err)
			}
			if !samePrincipals(got, tc.want) {
				t.Errorf("writers = %v, want %v", got, tc.want)
			}
		})
	}
}

// samePrincipals compares two writer sets without caring about order.
func samePrincipals(got, want []principal) bool {
	if len(got) != len(want) {
		return false
	}
	remaining := slices.Clone(want)
	for _, g := range got {
		i := slices.Index(remaining, g)
		if i < 0 {
			return false
		}
		remaining = slices.Delete(remaining, i, i+1)
	}
	return true
}

// ACL builders shared by the tests. The on-disk formats are stable kernel and protocol
// ABI, so encoding them by hand keeps the suite free of a setfacl binary that many
// minimal images (including the container this was written in) do not ship, and lets a
// test express a list no tool would let it write.
const aclUndefinedID uint32 = 0xFFFFFFFF

// posixACLEntry is one entry in the POSIX.1e xattr encoding.
type posixACLEntry struct {
	id   uint32
	tag  uint16
	perm uint16
}

// encodePOSIXACL renders entries in the system.posix_acl_access layout.
func encodePOSIXACL(entries []posixACLEntry) []byte {
	blob := binary.LittleEndian.AppendUint32(nil, posixACLVersion)
	for _, e := range entries {
		blob = binary.LittleEndian.AppendUint16(blob, e.tag)
		blob = binary.LittleEndian.AppendUint16(blob, e.perm)
		blob = binary.LittleEndian.AppendUint32(blob, e.id)
	}
	return blob
}

// buildNFS4ACL renders a one-entry NFSv4 list in the system.nfs4_acl_xdr layout.
func buildNFS4ACL(aceType, flag, special, mask, id uint32) []byte {
	blob := binary.BigEndian.AppendUint32(nil, 0)
	blob = binary.BigEndian.AppendUint32(blob, 1)
	for _, field := range []uint32{aceType, flag, special, mask, id} {
		blob = binary.BigEndian.AppendUint32(blob, field)
	}
	return blob
}

// setPOSIXACL writes entries as path's POSIX access ACL, for the tests that want a real
// one the kernel enforces rather than a parsed fixture.
func setPOSIXACL(path string, entries []posixACLEntry) error {
	return syscall.Setxattr(path, xattrPOSIXACL, encodePOSIXACL(entries), 0)
}

// posixACLNamedUserUnderMask grants a named user rwx while the mask allows only r-x, so
// the user ends up without write and the directory's mode stays 0755.
var posixACLNamedUserUnderMask = []posixACLEntry{
	{tag: posixTagUserObj, perm: 7, id: aclUndefinedID},
	{tag: posixTagUser, perm: 7, id: 1234},
	{tag: posixTagGroupObj, perm: 5, id: aclUndefinedID},
	{tag: posixTagMask, perm: 5, id: aclUndefinedID},
	{tag: posixTagOther, perm: 5, id: aclUndefinedID},
}

// TestParseNFS4ACLRefusesAnUnknownDiscriminator pins the direction this parser must never
// fail in. whoIsSpecial says whether an ACE's id is a uid/gid or a special-principal
// number, and reading "not zero" as "special" makes the two answers trade places: an
// ALLOW entry naming uid 1 under an unrecognised discriminator reads as OWNER@, which the
// caller checks separately and this parser therefore DROPS. A writer set missing a writer
// is a clean custody verdict, and no call site can refuse on a verdict that carries no
// error -- so a silent drop is strictly worse than any over-report.
func TestParseNFS4ACLRefusesAnUnknownDiscriminator(t *testing.T) {
	const grantedID = 1 // equal to nfs4WhoOwner, which is what makes the drop silent
	stat := &syscall.Stat_t{Gid: 9}

	tests := map[string]struct {
		special uint32
		wantErr bool
		// wantOwner marks the one case where an empty writer set is the RIGHT answer:
		// the entry really does name OWNER@, whose ownership the caller checks itself.
		wantOwner bool
	}{
		"named, the discriminator this parser understands": {special: 0},
		"special, naming OWNER@ which the caller checks":   {special: nfs4WhoIsSpecial, wantOwner: true},
		"two, which would read a uid as OWNER@":            {special: 2, wantErr: true},
		"three":                                            {special: 3, wantErr: true},
		"a flag bit, not a discriminator at all":           {special: 0x40, wantErr: true},
		"every bit set":                                    {special: 0xFFFFFFFF, wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			blob := buildNFS4ACL(nfs4TypeAllow, 0, tc.special, nfs4WriteData, grantedID)

			writers, err := parseNFS4ACL(blob, stat)
			switch {
			case tc.wantErr && err == nil:
				t.Errorf("parseNFS4ACL(whoIsSpecial=%d) = %v, nil; want an error rather than a writer set that may be missing the granted identity",
					tc.special, writers)
			case !tc.wantErr && err != nil:
				t.Errorf("parseNFS4ACL(whoIsSpecial=%d) = %v on a discriminator it understands", tc.special, err)
			}
			// The fail-open shape itself: an empty set with no error, for a list that
			// grants write to somebody. Only OWNER@ may answer that way, and only
			// because ownership is checked separately by the caller.
			if err == nil && !tc.wantOwner && len(writers) == 0 {
				t.Errorf("parseNFS4ACL(whoIsSpecial=%d) reported no writers and no error for an ALLOW entry granting write to id %d",
					tc.special, grantedID)
			}
		})
	}
}

// TestParsePOSIXACLRefusesASecondMask pins that a duplicate mask is refused rather than
// resolved by taking the last one. The mask is a CEILING on every named entry, so a
// second one silently retires the first and hides every named writer under it.
// posix_acl_valid rejects this on setxattr, so the local kernel cannot produce it; a
// filesystem or a remote server handing over the raw blob can.
func TestParsePOSIXACLRefusesASecondMask(t *testing.T) {
	const rwx, rx = 7, 5

	hidden := []posixACLEntry{
		{tag: posixTagUserObj, perm: rwx, id: aclUndefinedID},
		{tag: posixTagMask, perm: rwx, id: aclUndefinedID},
		{tag: posixTagUser, perm: rwx, id: 1234},
		{tag: posixTagMask, perm: rx, id: aclUndefinedID},
		{tag: posixTagGroupObj, perm: rx, id: aclUndefinedID},
		{tag: posixTagOther, perm: rx, id: aclUndefinedID},
	}

	writers, err := parsePOSIXACL(encodePOSIXACL(hidden), &syscall.Stat_t{Gid: 8888})
	if err == nil {
		t.Errorf("parsePOSIXACL(two masks) = %v, nil; want a refusal rather than a set the second mask emptied", writers)
	}
}

// TestParsePOSIXACLReadsOtherFromTheList pins the last place this parser could have
// relied on the mode instead of the list. An OTHER entry granting write names everyone,
// and it must do so from the ACL itself: posix_acl_update_mode keeps the two in step on
// Linux, but "these two always match" is the assumption the whole check exists to refuse,
// and the mode is the half an attacker-facing filesystem controls independently.
func TestParsePOSIXACLReadsOtherFromTheList(t *testing.T) {
	const rwx, rx = 7, 5

	tests := map[string]struct {
		other uint16
		want  bool
	}{
		"other may write":      {other: rwx, want: true},
		"other may not write":  {other: rx, want: false},
		"other may do nothing": {other: 0, want: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			entries := []posixACLEntry{
				{tag: posixTagUserObj, perm: rwx, id: aclUndefinedID},
				{tag: posixTagGroupObj, perm: rx, id: aclUndefinedID},
				{tag: posixTagOther, perm: tc.other, id: aclUndefinedID},
			}

			writers, err := parsePOSIXACL(encodePOSIXACL(entries), &syscall.Stat_t{Gid: 8888})
			if err != nil {
				t.Fatalf("parsePOSIXACL: %v", err)
			}
			got := slices.Contains(writers, principal{kind: principalEveryone})
			if got != tc.want {
				t.Errorf("parsePOSIXACL(other=%#o) named everyone = %v, want %v (writers=%v)",
					tc.other, got, tc.want, writers)
			}
		})
	}
}

// TestParsePOSIXACLNamesTheOwningGroupFromTheList pins the last tag whose grant could have
// been read off the mode instead of the list. GROUP_OBJ carries no id of its own -- it
// means the object's own group -- so reporting it needs the stat the caller already holds.
func TestParsePOSIXACLNamesTheOwningGroupFromTheList(t *testing.T) {
	const rwx, rw, rx = 7, 6, 5
	const owningGid = 8888

	tests := map[string]struct {
		groupObj uint16
		mask     uint16
		want     bool
	}{
		"the owning group may write, unmasked": {groupObj: rw, mask: rwx, want: true},
		"the same grant, capped by the mask":   {groupObj: rw, mask: rx},
		"the owning group may not write":       {groupObj: rx, mask: rwx},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			entries := []posixACLEntry{
				{tag: posixTagUserObj, perm: rwx, id: aclUndefinedID},
				{tag: posixTagGroupObj, perm: tc.groupObj, id: aclUndefinedID},
				{tag: posixTagMask, perm: tc.mask, id: aclUndefinedID},
				{tag: posixTagOther, perm: rx, id: aclUndefinedID},
			}

			writers, err := parsePOSIXACL(encodePOSIXACL(entries), &syscall.Stat_t{Gid: owningGid})
			if err != nil {
				t.Fatalf("parsePOSIXACL: %v", err)
			}
			got := slices.Contains(writers, principal{kind: principalGroup, id: owningGid})
			if got != tc.want {
				t.Errorf("parsePOSIXACL named the owning group (gid %d) = %v, want %v (writers=%v)",
					owningGid, got, tc.want, writers)
			}
		})
	}
}

// TestParsePOSIXACLExemptsOnlyOtherFromTheMask pins, with a mask present, that
// other:: write counts however restrictive the mask and group:: stays capped.
func TestParsePOSIXACLExemptsOnlyOtherFromTheMask(t *testing.T) {
	const rwx, rw, rx = 7, 6, 5
	const owningGid = 8888

	tests := map[string]struct {
		mask      uint16
		other     uint16
		groupObj  uint16
		wantEvery bool
		wantGroup bool
	}{
		"other writes under a mask that withholds write": {
			mask: rx, other: rw, groupObj: rx, wantEvery: true,
		},
		"the owning group writes under the same mask, and is capped": {
			mask: rx, other: rx, groupObj: rw,
		},
		"both write, mask permits: both reported": {
			mask: rwx, other: rw, groupObj: rw, wantEvery: true, wantGroup: true,
		},
		"both write, mask withholds: only other survives": {
			mask: rx, other: rw, groupObj: rw, wantEvery: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			entries := []posixACLEntry{
				{tag: posixTagUserObj, perm: rwx, id: aclUndefinedID},
				{tag: posixTagGroupObj, perm: tc.groupObj, id: aclUndefinedID},
				{tag: posixTagMask, perm: tc.mask, id: aclUndefinedID},
				{tag: posixTagOther, perm: tc.other, id: aclUndefinedID},
			}

			writers, err := parsePOSIXACL(encodePOSIXACL(entries), &syscall.Stat_t{Gid: owningGid})
			if err != nil {
				t.Fatalf("parsePOSIXACL: %v", err)
			}
			gotEvery := slices.Contains(writers, principal{kind: principalEveryone})
			gotGroup := slices.Contains(writers, principal{kind: principalGroup, id: owningGid})
			if gotEvery != tc.wantEvery {
				t.Errorf("named everyone = %v, want %v (mask=%#o other=%#o, writers=%v)",
					gotEvery, tc.wantEvery, tc.mask, tc.other, writers)
			}
			if gotGroup != tc.wantGroup {
				t.Errorf("named the owning group = %v, want %v (mask=%#o group_obj=%#o, writers=%v)",
					gotGroup, tc.wantGroup, tc.mask, tc.groupObj, writers)
			}
		})
	}
}

// TestControllersOfAnswersOnlyForNFSv4 pins that controllersOf propagates an
// unreadable list and answers nothing for POSIX.1e, which cannot grant chmod or
// chown: those stay with the owner the caller checks.
func TestControllersOfAnswersOnlyForNFSv4(t *testing.T) {
	const stranger = 4242
	const rwx = 7

	t.Run("an NFSv4 list granting WRITE_OWNER names the principal", func(t *testing.T) {
		blob := buildNFS4ACL(nfs4TypeAllow, 0, 0, nfs4WriteOwner, stranger)
		old := getxattrFn
		getxattrFn = serveOne(xattrNFS4XDR, blob)
		defer func() { getxattrFn = old }()

		got, err := controllersOf("/irrelevant", &syscall.Stat_t{Gid: 9})
		if err != nil {
			t.Fatalf("controllersOf: %v", err)
		}
		if !slices.Contains(got, principal{kind: principalUser, id: stranger}) {
			t.Errorf("controllers = %v, want uid %d, who can take ownership and clear the sticky bit", got, stranger)
		}
	})

	t.Run("the list ZFS derives for a 1777 directory names nobody", func(t *testing.T) {
		blob, err := base64.StdEncoding.DecodeString(nfs4Samples[zfs1777Sample].b64)
		if err != nil {
			t.Fatalf("decoding the fixture: %v", err)
		}
		old := getxattrFn
		getxattrFn = serveOne(xattrNFS4XDR, blob)
		defer func() { getxattrFn = old }()

		got, err := controllersOf("/irrelevant", &syscall.Stat_t{Gid: 9})
		if err != nil {
			t.Fatalf("controllersOf: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("controllers = %v, want none: only owner@ holds WRITE_ACL or WRITE_OWNER, and DELETE_CHILD is not a control", got)
		}
	})

	t.Run("a POSIX.1e list answers nothing, because it cannot grant either", func(t *testing.T) {
		// A list granting a named user everything POSIX.1e can express. None of it is
		// WRITE_ACL or WRITE_OWNER, which is the point.
		entries := []posixACLEntry{
			{tag: posixTagUserObj, perm: rwx, id: aclUndefinedID},
			{tag: posixTagUser, perm: rwx, id: stranger},
			{tag: posixTagMask, perm: rwx, id: aclUndefinedID},
			{tag: posixTagOther, perm: rwx, id: aclUndefinedID},
		}
		old := getxattrFn
		getxattrFn = serveOne(xattrPOSIXACL, encodePOSIXACL(entries))
		defer func() { getxattrFn = old }()

		got, err := controllersOf("/irrelevant", &syscall.Stat_t{Gid: 9})
		if err != nil {
			t.Fatalf("controllersOf: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("controllers = %v, want none: POSIX.1e cannot grant WRITE_ACL or WRITE_OWNER", got)
		}
	})

	t.Run("an unreadable list propagates rather than reading as none", func(t *testing.T) {
		old := getxattrFn
		getxattrFn = func(string, string, []byte) (int, error) { return 0, syscall.EIO }
		defer func() { getxattrFn = old }()

		if got, err := controllersOf("/irrelevant", &syscall.Stat_t{Gid: 9}); err == nil {
			t.Errorf("controllersOf = %v, nil; want the read error, because not looking is not the same as finding nothing", got)
		}
	})
}

// serveOne answers one attribute name with blob and ENODATA for every other, for the tests
// that drive a parser through the getxattr seam without a real filesystem.
func serveOne(attr string, blob []byte) func(string, string, []byte) (int, error) {
	return func(_, name string, dest []byte) (int, error) {
		if name != attr {
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
}

// TestReadACLReadsTheListInOneCall pins the removal of the window between a size probe and
// a read. The attribute is not stable across two syscalls, and the principal who can change
// it in between is the one this whole check exists to catch: a holder of WRITE_ACL on a path
// component can add a grant, let the probe see it, and drop it before the read.
func TestReadACLReadsTheListInOneCall(t *testing.T) {
	blob := buildNFS4ACL(nfs4TypeAllow, 0, 0, nfs4WriteData, 4242)
	reads, probes := 0, 0
	old := getxattrFn
	getxattrFn = func(_, name string, dest []byte) (int, error) {
		if name != xattrNFS4XDR {
			return 0, syscall.ENODATA
		}
		if dest == nil {
			probes++
			return len(blob), nil
		}
		reads++
		if reads > 1 {
			// The grant the first call saw is gone, which is the shape a principal
			// holding WRITE_ACL produces by removing its own entry.
			return 0, syscall.ENODATA
		}
		if len(dest) < len(blob) {
			return 0, syscall.ERANGE
		}
		return copy(dest, blob), nil
	}
	defer func() { getxattrFn = old }()

	dialect, got, err := readACL("/irrelevant")
	if err != nil {
		t.Fatalf("readACL: %v", err)
	}
	if dialect == nil || dialect.xattr != xattrNFS4XDR {
		t.Errorf("readACL named %v, want %q", dialect, xattrNFS4XDR)
	}
	if !bytes.Equal(got, blob) {
		t.Errorf("readACL returned %x, want the whole list %x", got, blob)
	}
	if probes != 0 {
		t.Errorf("readACL made %d size probes; the read must be a single call, because the attribute can change between two", probes)
	}
	if reads != 1 {
		t.Errorf("readACL read %s %d times, want exactly once", xattrNFS4XDR, reads)
	}
}

// TestReadACLRefusesWhatItCannotSize pins the two answers that must not reach the absence
// branch. Neither is an attribute that is not there: one is longer than any list this
// package would parse, the other is present and empty. Reading either as absence is the
// fail-open direction, because a clean verdict carries no error for a caller to refuse on.
func TestReadACLRefusesWhatItCannotSize(t *testing.T) {
	tests := map[string]struct {
		fn func(string, string, []byte) (int, error)
	}{
		"a list longer than the parser's ceiling": {
			fn: func(_, name string, _ []byte) (int, error) {
				if name != xattrNFS4XDR {
					return 0, syscall.ENODATA
				}
				return 0, syscall.ERANGE
			},
		},
		"a present but zero-length value": {
			fn: func(_, name string, _ []byte) (int, error) {
				if name != xattrNFS4XDR {
					return 0, syscall.ENODATA
				}
				return 0, nil
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			old := getxattrFn
			getxattrFn = tc.fn
			defer func() { getxattrFn = old }()

			gotDialect, _, err := readACL("/irrelevant")
			if err == nil {
				t.Fatalf("readACL = %v, nil; want a refusal rather than the absence of a list", gotDialect)
			}
			if !errors.Is(err, errACLUnreadable) {
				t.Errorf("readACL error = %v, want it to wrap errACLUnreadable", err)
			}
		})
	}
}

// TestReadACLRefusesTheStringPrincipalDialect pins the refusal that replaced a silent
// misread. system.nfs4_acl is the attribute nfs4-acl-tools manipulates, and it carries
// VARIABLE-LENGTH STRING principals rather than the numeric ids of system.nfs4_acl_xdr,
// which is where every list this parser was built against came from. Decoding one with the
// other's fixed-size layout misreads ids where the lengths line up and skips entries where
// they do not, so the answer is a writer set quietly missing a writer.
func TestReadACLRefusesTheStringPrincipalDialect(t *testing.T) {
	// A plausible string-principal list: one ACE naming "root@example.com".
	blob := append(binary.BigEndian.AppendUint32(nil, 0), binary.BigEndian.AppendUint32(nil, 1)...)
	blob = append(blob, []byte("\x00\x00\x00\x00root@example.com")...)

	t.Run("readACL names the dialect and the remedy", func(t *testing.T) {
		old := getxattrFn
		getxattrFn = serveOne(xattrNFS4ACL, blob)
		defer func() { getxattrFn = old }()

		dialect, _, err := readACL("/irrelevant")
		if err == nil {
			t.Fatalf("readACL = %v, nil; want a refusal naming the dialect it cannot decode", dialect)
		}
		if !errors.Is(err, errACLDialectUnsupported) {
			t.Errorf("readACL error = %v, want it to wrap errACLDialectUnsupported", err)
		}
		if !errors.Is(err, errACLUnreadable) {
			t.Errorf("readACL error = %v, want it to wrap errACLUnreadable so existing matchers keep working", err)
		}
		for _, want := range []string{xattrNFS4ACL, "Remove the list"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("readACL error %q does not mention %s", err, want)
			}
		}
	})

	t.Run("the whole check refuses rather than reporting a clean tree", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "pkg-versions")
		if err := os.MkdirAll(root, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		defer serveACL(t, root, xattrNFS4ACL, blob)()

		err := (Trust{}).Verify(root, true)
		if !errors.Is(err, errNoCustody) || !errors.Is(err, errACLDialectUnsupported) {
			t.Fatalf("Verify error = %v, want errNoCustody wrapping errACLDialectUnsupported", err)
		}
	})
}

// TestWritersOfTakesNoModeFloorUnderPOSIXACL pins which half of the mode this function may
// believe, per dialect. It is the one direction in this file that fails CLOSED, and it
// breaks the feature rather than the guarantee.
func TestWritersOfTakesNoModeFloorUnderPOSIXACL(t *testing.T) {
	const owningGid = 8888
	const rwx, rx = 7, 5
	owningGroup := principal{kind: principalGroup, id: owningGid}
	everyone := principal{kind: principalEveryone}
	namedUser := principal{kind: principalUser, id: 1234}

	// The measured shape: the mask is rwx, which is what raises the stored mode to 0770,
	// while the owning group's own entry grants r-x.
	maskedGroupObj := []posixACLEntry{
		{tag: posixTagUserObj, perm: rwx, id: aclUndefinedID},
		{tag: posixTagUser, perm: rwx, id: 1234},
		{tag: posixTagGroupObj, perm: rx, id: aclUndefinedID},
		{tag: posixTagMask, perm: rwx, id: aclUndefinedID},
		{tag: posixTagOther, perm: 0, id: aclUndefinedID},
	}

	tests := map[string]struct {
		attr    string
		blob    []byte
		mode    os.FileMode
		want    []principal
		wantErr bool
	}{
		"a POSIX.1e mask does not grant the owning group anything": {
			attr: xattrPOSIXACL, blob: encodePOSIXACL(maskedGroupObj),
			mode: 0o770, want: []principal{namedUser},
		},
		"the POSIX.1e OTHER entry, not the mode's other bits, names everyone": {
			attr: xattrPOSIXACL,
			blob: encodePOSIXACL([]posixACLEntry{
				{tag: posixTagUserObj, perm: rwx, id: aclUndefinedID},
				{tag: posixTagGroupObj, perm: rx, id: aclUndefinedID},
				{tag: posixTagOther, perm: rx, id: aclUndefinedID},
			}),
			mode: 0o777, want: nil,
		},
		"under NFSv4 the mode is an independent projection, so it is still a floor": {
			attr: xattrNFS4XDR, blob: buildNFS4ACL(nfs4TypeAllow, 0, 0, 0, 0),
			mode: 0o770, want: []principal{owningGroup},
		},
		"with no list at all the mode is the whole answer": {
			attr: "system.nothing.served", blob: nil,
			mode: 0o777, want: []principal{owningGroup, everyone},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "component")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatalf("Mkdir: %v", err)
			}
			// chmod rather than Mkdir's argument, because the umask would mask it.
			if err := os.Chmod(dir, tc.mode); err != nil {
				t.Fatalf("Chmod: %v", err)
			}
			fi, err := os.Lstat(dir)
			if err != nil {
				t.Fatalf("Lstat: %v", err)
			}
			old := getxattrFn
			getxattrFn = serveOne(tc.attr, tc.blob)
			defer func() { getxattrFn = old }()

			got, err := writersOf(dir, fi, &syscall.Stat_t{Gid: owningGid})
			if err != nil {
				t.Fatalf("writersOf: %v", err)
			}
			if !samePrincipals(got, tc.want) {
				t.Errorf("writersOf(mode %#o) = %v, want %v", tc.mode, got, tc.want)
			}
		})
	}
}

// TestParseNFS4ACLRefusesAnUnknownACEType pins the difference between "not ALLOW" and
// "cannot grant". The three other types RFC 7530 defines are genuinely non-granting -- DENY
// only ever subtracts, AUDIT and ALARM ask the server to log or signal -- so passing over
// them is correct. A type this parser does not know is not in that set: a filesystem
// extension or a future type, silently skipped, drops the writer the entry names, and a
// writer set missing a writer is a clean verdict no caller can refuse on.
func TestParseNFS4ACLRefusesAnUnknownACEType(t *testing.T) {
	const grantedID = 4242
	tests := map[string]struct {
		aceType    uint32
		wantErr    bool
		wantWriter bool
	}{
		"allow, the only type that grants":          {aceType: nfs4TypeAllow, wantWriter: true},
		"deny, which can only ever subtract":        {aceType: nfs4TypeDeny},
		"audit, which asks the server to log":       {aceType: nfs4TypeAudit},
		"alarm, which asks the server to signal":    {aceType: nfs4TypeAlarm},
		"four, which RFC 7530 does not define":      {aceType: 4, wantErr: true},
		"a high bit, as a filesystem extension may": {aceType: 0x40000000, wantErr: true},
		"every bit set": {aceType: 0xFFFFFFFF, wantErr: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			blob := buildNFS4ACL(tc.aceType, 0, 0, nfs4WriteData, grantedID)
			writers, err := parseNFS4ACL(blob, &syscall.Stat_t{Gid: 9})
			switch {
			case tc.wantErr && err == nil:
				t.Fatalf("parseNFS4ACL(type=%d) = %v, nil; want a refusal rather than a writer set that may be missing the granted identity",
					tc.aceType, writers)
			case !tc.wantErr && err != nil:
				t.Fatalf("parseNFS4ACL(type=%d) = %v on a type it is meant to understand", tc.aceType, err)
			}
			if err != nil {
				return
			}
			got := slices.Contains(writers, principal{kind: principalUser, id: grantedID})
			if got != tc.wantWriter {
				t.Errorf("parseNFS4ACL(type=%d) named uid %d = %v, want %v (writers=%v)",
					tc.aceType, grantedID, got, tc.wantWriter, writers)
			}
		})
	}
}

// TestParseNFS4ACLRefusesAnUnknownSpecialPrincipal pins the branch beside the discriminator
// one. Once whoIsSpecial says the id is a special-principal number, only three numbers are
// defined; a fourth cannot be resolved to an identity, and guessing it away would drop
// whatever it names from the writer set.
func TestParseNFS4ACLRefusesAnUnknownSpecialPrincipal(t *testing.T) {
	tests := map[string]struct {
		id      uint32
		wantErr bool
	}{
		"OWNER@, which the caller checks itself":    {id: nfs4WhoOwner},
		"GROUP@, resolved to the object's gid":      {id: nfs4WhoGroup},
		"EVERYONE@":                                 {id: nfs4WhoEveryone},
		"zero, which names no special principal":    {id: 0, wantErr: true},
		"four, one past the three RFC 7530 defines": {id: 4, wantErr: true},
		"every bit set":                             {id: 0xFFFFFFFF, wantErr: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			blob := buildNFS4ACL(nfs4TypeAllow, 0, nfs4WhoIsSpecial, nfs4WriteData, tc.id)
			writers, err := parseNFS4ACL(blob, &syscall.Stat_t{Gid: 9})
			switch {
			case tc.wantErr && err == nil:
				t.Errorf("parseNFS4ACL(special id=%d) = %v, nil; want a refusal rather than a set that may omit the identity it grants",
					tc.id, writers)
			case !tc.wantErr && err != nil:
				t.Errorf("parseNFS4ACL(special id=%d) = %v on a principal RFC 7530 defines", tc.id, err)
			}
		})
	}
}

// TestParsePOSIXACLRefusesMalformedInput is the POSIX half of the boundary
// TestParseNFS4ACLRefusesMalformedInput pins for NFSv4. Every refusal in decodePOSIXACL was
// unwitnessed: the one malformed-ACL test in the suite feeds its blob to the NFSv4 xattr, so
// this decoder had never seen a bad one.
//
// It is the dialect where a short read is most dangerous, because the encoding carries no
// entry count -- the count is derived from the length, so any truncation to a multiple of the
// entry size is a well-formed SHORTER list, and a shorter list is a smaller writer set.
func TestParsePOSIXACLRefusesMalformedInput(t *testing.T) {
	const rwx, rx = 7, 5
	valid := encodePOSIXACL([]posixACLEntry{
		{tag: posixTagUserObj, perm: rwx, id: aclUndefinedID},
		{tag: posixTagUser, perm: rwx, id: 1234},
		{tag: posixTagGroupObj, perm: rx, id: aclUndefinedID},
		{tag: posixTagMask, perm: rwx, id: aclUndefinedID},
		{tag: posixTagOther, perm: rx, id: aclUndefinedID},
	})
	overCap := append(binary.LittleEndian.AppendUint32(nil, posixACLVersion),
		make([]byte, (posixACLMaxEntries+1)*posixACLEntrySize)...)

	tests := map[string][]byte{
		"empty":                          {},
		"a truncated header":             valid[:posixACLHeaderSize-1],
		"an unsupported version":         append(binary.LittleEndian.AppendUint32(nil, posixACLVersion+1), valid[posixACLHeaderSize:]...),
		"one byte short of a whole list": valid[:len(valid)-1],
		"one byte long":                  append(slices.Clone(valid), 0),
		"over the entry cap":             overCap,
		"an unknown entry tag": encodePOSIXACL([]posixACLEntry{
			{tag: posixTagUserObj, perm: rwx, id: aclUndefinedID},
			{tag: 0x40, perm: rwx, id: 1234},
			{tag: posixTagGroupObj, perm: rx, id: aclUndefinedID},
			{tag: posixTagOther, perm: rx, id: aclUndefinedID},
		}),
		// The three entries every access ACL carries. writersOf takes no mode floor for
		// this dialect, so a list missing one of them would answer "nobody" for a
		// principal the object may grant write to.
		"no owning-group entry": encodePOSIXACL([]posixACLEntry{
			{tag: posixTagUserObj, perm: rwx, id: aclUndefinedID},
			{tag: posixTagOther, perm: rx, id: aclUndefinedID},
		}),
		"no other entry": encodePOSIXACL([]posixACLEntry{
			{tag: posixTagUserObj, perm: rwx, id: aclUndefinedID},
			{tag: posixTagGroupObj, perm: rx, id: aclUndefinedID},
		}),
		"no owner entry": encodePOSIXACL([]posixACLEntry{
			{tag: posixTagGroupObj, perm: rx, id: aclUndefinedID},
			{tag: posixTagOther, perm: rx, id: aclUndefinedID},
		}),
		"two owning-group entries": encodePOSIXACL([]posixACLEntry{
			{tag: posixTagUserObj, perm: rwx, id: aclUndefinedID},
			{tag: posixTagGroupObj, perm: rx, id: aclUndefinedID},
			{tag: posixTagGroupObj, perm: rwx, id: aclUndefinedID},
			{tag: posixTagOther, perm: rx, id: aclUndefinedID},
		}),
	}
	for name, blob := range tests {
		t.Run(name, func(t *testing.T) {
			if writers, err := parsePOSIXACL(blob, &syscall.Stat_t{Gid: 8888}); err == nil {
				t.Errorf("parsePOSIXACL accepted a malformed list and reported %v", writers)
			}
		})
	}
}

// TestParseNFS4ACLAcceptsAListWithNoEntries pins the other side of the header-length
// check. A list of exactly the header and nothing else is well formed and grants
// nobody anything, so it has to be READ as an empty writer set rather than reported as
// a truncated read: refusing it would refuse every object whose ACL is empty, and the
// mode floor is what covers the identities such an object still lets write.
func TestParseNFS4ACLAcceptsAListWithNoEntries(t *testing.T) {
	blob := binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 0), 0)

	got, err := parseNFS4ACL(blob, &syscall.Stat_t{Uid: 1000, Gid: 1500})
	if err != nil {
		t.Fatalf("parseNFS4ACL(%x) = %v, want an empty writer set on a list carrying no entries", blob, err)
	}
	if len(got) != 0 {
		t.Errorf("parseNFS4ACL(%x) = %v, want no writers", blob, got)
	}
}

// TestParseNFS4ACLAcceptsAListAtTheEntryCeiling pins the entry cap's accepting side.
// The cap is a sanity bound against a hostile count, so a list exactly at it is one
// this parser must still read to the end — the alternative is a refusal on a list the
// filesystem considers valid, and a refusal is an install outage.
//
// The last entry carries the only write grant, so a parser that stopped early would
// report a writer set missing the identity the list names.
func TestParseNFS4ACLAcceptsAListAtTheEntryCeiling(t *testing.T) {
	const namedUID = 4242
	blob := binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 0), nfs4MaxACEs)
	blob = append(blob, make([]byte, (nfs4MaxACEs-1)*nfs4ACESize)...)
	granting := buildNFS4ACL(nfs4TypeAllow, 0, 0, nfs4WriteData, namedUID)
	blob = append(blob, granting[nfs4HeaderSize:]...)

	got, err := parseNFS4ACL(blob, &syscall.Stat_t{Uid: 1000, Gid: 1500})
	if err != nil {
		t.Fatalf("parseNFS4ACL on a list of %d entries = %v, want the list read", nfs4MaxACEs, err)
	}
	want := []principal{{kind: principalUser, id: namedUID}}
	if !samePrincipals(got, want) {
		t.Errorf("parseNFS4ACL on a list of %d entries = %v, want %v", nfs4MaxACEs, got, want)
	}
}

// TestParsePOSIXACLAcceptsAListAtTheEntryCeiling is the POSIX.1e half of the same
// boundary. The named entry granting write is the LAST one in the list, so a decoder
// that stopped one entry short would answer "nobody" for an object that grants a
// stranger write — the one direction this check must not fail in.
func TestParsePOSIXACLAcceptsAListAtTheEntryCeiling(t *testing.T) {
	const rwx, rx = 7, 5
	const namedUID uint32 = 1234
	entries := []posixACLEntry{
		{tag: posixTagUserObj, perm: rwx, id: aclUndefinedID},
		{tag: posixTagGroupObj, perm: rx, id: aclUndefinedID},
		{tag: posixTagOther, perm: 0, id: aclUndefinedID},
	}
	for id := len(entries); id < posixACLMaxEntries-1; id++ {
		entries = append(entries, posixACLEntry{tag: posixTagUser, perm: rx, id: uint32(2000 + id)})
	}
	entries = append(entries, posixACLEntry{tag: posixTagUser, perm: rwx, id: namedUID})

	blob := encodePOSIXACL(entries)
	got, err := parsePOSIXACL(blob, &syscall.Stat_t{Gid: 8888})
	if err != nil {
		t.Fatalf("parsePOSIXACL on a list of %d entries = %v, want the list read", len(entries), err)
	}
	want := []principal{{kind: principalUser, id: int(namedUID)}}
	if !samePrincipals(got, want) {
		t.Errorf("parsePOSIXACL on a list of %d entries = %v, want %v", len(entries), got, want)
	}
}

// TestControllersOfWrapsAParseError pins the last unwitnessed path in the sticky exemption.
// An unreadable list already propagates; a list that reads fine and does not PARSE went
// through a different return, and a nil error there would exempt a world-writable sticky
// ancestor on the strength of a list nobody decoded.
func TestControllersOfWrapsAParseError(t *testing.T) {
	old := getxattrFn
	getxattrFn = serveOne(xattrNFS4XDR, []byte("not an acl"))
	defer func() { getxattrFn = old }()

	got, err := controllersOf("/irrelevant", &syscall.Stat_t{Gid: 9})
	if err == nil {
		t.Fatalf("controllersOf = %v, nil; want the parse error, because a list nobody decoded is not a list granting nothing", got)
	}
	if !errors.Is(err, errACLUnreadable) {
		t.Errorf("controllersOf error = %v, want it to wrap errACLUnreadable", err)
	}
}

// nfs4FuzzSeeds are the shapes the NFSv4 parser has to have an answer for: the real captured
// lists, one entry of every kind, and the boundaries of the encoding itself.
func nfs4FuzzSeeds(f *testing.F) [][]byte {
	f.Helper()
	valid, err := base64.StdEncoding.DecodeString(
		nfs4Samples["dataset root, owned by a service account, mode 0770 with a named admin and a group grant"].b64,
	)
	if err != nil {
		f.Fatalf("decoding the fixture: %v", err)
	}
	seeds := [][]byte{
		{},
		valid,
		valid[:nfs4HeaderSize],         // a header with no entries
		valid[:nfs4HeaderSize-1],       // a truncated header
		valid[:len(valid)-1],           // one byte short of an entry
		append(slices.Clone(valid), 0), // one byte long
		binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 0), 0xFFFFFFFF),    // count larger than body
		binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 0), nfs4MaxACEs+1), // over the entry cap
		buildNFS4ACL(nfs4TypeAllow, 0, 0, nfs4WriteData, 4242),                              // a named user
		buildNFS4ACL(nfs4TypeAllow, nfs4FlagIdentifierGroup, 0, nfs4WriteData, 77),          // a named group
		buildNFS4ACL(nfs4TypeAllow, 0, nfs4WhoIsSpecial, nfs4WriteData, nfs4WhoEveryone),    // EVERYONE@
		buildNFS4ACL(nfs4TypeAllow, 0, nfs4WhoIsSpecial, nfs4WriteData, nfs4WhoGroup),       // GROUP@
		buildNFS4ACL(nfs4TypeAllow, 0, nfs4WhoIsSpecial, nfs4WriteData, nfs4WhoOwner),       // OWNER@
		buildNFS4ACL(nfs4TypeAllow, 0, nfs4WhoIsSpecial, nfs4WriteData, 4),                  // an unknown special principal
		buildNFS4ACL(nfs4TypeAllow, nfs4FlagInheritOnly, 0, nfs4WriteData, 4242),            // inherit-only
		buildNFS4ACL(nfs4TypeDeny, 0, 0, nfs4WriteData, 4242),                               // a deny entry
		buildNFS4ACL(9, 0, 0, nfs4WriteData, 4242),                                          // an unknown ace type
		buildNFS4ACL(nfs4TypeAllow, 0, 7, nfs4WriteData, 4242),                              // an unknown discriminator
		buildNFS4ACL(nfs4TypeAllow, 0, 0, nfs4WriteOwner, 4242),                             // a control grant only
		buildNFS4ACL(nfs4TypeAllow, 0, 0, 0xFFFFFFFF, 4242),                                 // every access bit
	}
	return seeds
}

// FuzzParseNFS4ACL pins the invariant the whole custody check rests on, against arbitrary
// bytes: a parse that reports no error must not report a writer set missing a principal the
// list grants write to. This parser reads untrusted binary input off a filesystem, and its
// answer decides whether a tree whose binary the consumer executes as root is trusted, so an
// under-report is not a smaller answer -- it is a clean verdict no call site can refuse on.
func FuzzParseNFS4ACL(f *testing.F) {
	for _, seed := range nfs4FuzzSeeds(f) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, blob []byte) {
		const owningGid = 8888
		stat := &syscall.Stat_t{Gid: owningGid}

		writers, err := parseNFS4ACL(blob, stat)
		if err != nil {
			if len(writers) != 0 {
				t.Fatalf("parseNFS4ACL refused %x and still reported %v; a refusal must carry no writer set", blob, writers)
			}
			return
		}
		// The parser accepted the list, so its length claims agree with its header. Those
		// are what make the walk below safe, and a parser that accepted anything else
		// would be reading entries out of bytes that are not entries.
		if len(blob) < nfs4HeaderSize {
			t.Fatalf("parseNFS4ACL accepted %d bytes, which is shorter than the header", len(blob))
		}
		count := int(binary.BigEndian.Uint32(blob[4:8]))
		body := blob[nfs4HeaderSize:]
		if count > nfs4MaxACEs || len(body) != count*nfs4ACESize {
			t.Fatalf("parseNFS4ACL accepted a header claiming %d entries with %d bytes of body", count, len(body))
		}

		for i := range count {
			ace := body[i*nfs4ACESize : (i+1)*nfs4ACESize]
			aceType := binary.BigEndian.Uint32(ace[0:4])
			flag := binary.BigEndian.Uint32(ace[4:8])
			special := binary.BigEndian.Uint32(ace[8:12])
			mask := binary.BigEndian.Uint32(ace[12:16])
			id := binary.BigEndian.Uint32(ace[16:20])
			if aceType != nfs4TypeAllow || flag&nfs4FlagInheritOnly != 0 || mask&nfs4WriteMask == 0 {
				continue
			}
			var want principal
			switch {
			case special == 0 && flag&nfs4FlagIdentifierGroup != 0:
				want = principal{kind: principalGroup, id: int(id)}
			case special == 0:
				want = principal{kind: principalUser, id: int(id)}
			case id == nfs4WhoGroup:
				want = principal{kind: principalGroup, id: owningGid}
			case id == nfs4WhoEveryone:
				want = principal{kind: principalEveryone}
			default:
				// OWNER@, whose ownership the caller checks itself. Every other
				// discriminator and special number is refused above, so nothing else
				// reaches here.
				continue
			}
			if !slices.Contains(writers, want) {
				t.Fatalf("parseNFS4ACL(%x) = %v with no error, but entry %d grants write to %v", blob, writers, i, want)
			}
		}

		controllers, ctlErr := parseNFS4Granted(blob, stat, nfs4ControlMask)
		if ctlErr != nil {
			return
		}
		for _, c := range controllers {
			if !slices.Contains(writers, c) {
				t.Fatalf("parseNFS4Granted(%x, control) named %v, which the write question did not report in %v", blob, c, writers)
			}
		}
	})
}

// posixFuzzSeeds are the shapes the POSIX.1e parser has to have an answer for. The encoding
// carries no entry count, so the truncation cases matter more here than anywhere else: every
// length that is a multiple of the entry size is a well-formed SHORTER list.
func posixFuzzSeeds() [][]byte {
	const rwx, rw, rx = 7, 6, 5
	valid := encodePOSIXACL([]posixACLEntry{
		{tag: posixTagUserObj, perm: rwx, id: aclUndefinedID},
		{tag: posixTagUser, perm: rwx, id: 1234},
		{tag: posixTagGroupObj, perm: rw, id: aclUndefinedID},
		{tag: posixTagMask, perm: rwx, id: aclUndefinedID},
		{tag: posixTagOther, perm: rx, id: aclUndefinedID},
	})
	return [][]byte{
		{},
		valid,
		encodePOSIXACL(posixACLNamedUserUnderMask),
		valid[:posixACLHeaderSize],           // a header with no entries
		valid[:posixACLHeaderSize-1],         // a truncated header
		valid[:len(valid)-1],                 // one byte short of a whole entry
		append(slices.Clone(valid), 0),       // one byte long
		valid[:len(valid)-posixACLEntrySize], // a list truncated to whole entries
		append(binary.LittleEndian.AppendUint32(nil, posixACLVersion+1), valid[posixACLHeaderSize:]...), // an unsupported version
		append(binary.LittleEndian.AppendUint32(nil, posixACLVersion),
			make([]byte, (posixACLMaxEntries+1)*posixACLEntrySize)...), // over the entry cap
		encodePOSIXACL([]posixACLEntry{ // an unknown tag
			{tag: posixTagUserObj, perm: rwx, id: aclUndefinedID},
			{tag: 0x40, perm: rwx, id: 1234},
			{tag: posixTagGroupObj, perm: rx, id: aclUndefinedID},
			{tag: posixTagOther, perm: rx, id: aclUndefinedID},
		}),
		encodePOSIXACL([]posixACLEntry{ // two masks, which hide every named writer
			{tag: posixTagUserObj, perm: rwx, id: aclUndefinedID},
			{tag: posixTagMask, perm: rwx, id: aclUndefinedID},
			{tag: posixTagUser, perm: rwx, id: 1234},
			{tag: posixTagMask, perm: rx, id: aclUndefinedID},
			{tag: posixTagGroupObj, perm: rx, id: aclUndefinedID},
			{tag: posixTagOther, perm: rx, id: aclUndefinedID},
		}),
		encodePOSIXACL([]posixACLEntry{ // no mask at all, so nothing is capped
			{tag: posixTagUserObj, perm: rwx, id: aclUndefinedID},
			{tag: posixTagGroupObj, perm: rw, id: aclUndefinedID},
			{tag: posixTagOther, perm: rw, id: aclUndefinedID},
		}),
		encodePOSIXACL([]posixACLEntry{ // no owning-group entry
			{tag: posixTagUserObj, perm: rwx, id: aclUndefinedID},
			{tag: posixTagOther, perm: rx, id: aclUndefinedID},
		}),
	}
}

// FuzzParsePOSIXACL pins the same invariant for the dialect an ordinary Linux volume carries:
// a parse reporting no error must not omit a principal the list grants write to. It is the
// stronger of the two targets in one respect, because writersOf takes no mode floor for this
// dialect -- the mode's group bits are this list's mask -- so the writer set is the whole
// answer and an omission is invisible.
//
// The oracle states the two rules that make the dialect different: the mask is a ceiling on
// every named entry and on the owning group, and OTHER is not subject to it at all.
func FuzzParsePOSIXACL(f *testing.F) {
	for _, seed := range posixFuzzSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, blob []byte) {
		const owningGid = 8888

		writers, err := parsePOSIXACL(blob, &syscall.Stat_t{Gid: owningGid})
		if err != nil {
			if len(writers) != 0 {
				t.Fatalf("parsePOSIXACL refused %x and still reported %v; a refusal must carry no writer set", blob, writers)
			}
			return
		}
		if len(blob) < posixACLHeaderSize || (len(blob)-posixACLHeaderSize)%posixACLEntrySize != 0 {
			t.Fatalf("parsePOSIXACL accepted %d bytes, which is not a header followed by whole entries", len(blob))
		}
		if v := binary.LittleEndian.Uint32(blob[:posixACLHeaderSize]); v != posixACLVersion {
			t.Fatalf("parsePOSIXACL accepted version %d", v)
		}
		body := blob[posixACLHeaderSize:]

		// At most one mask, because a second one silently retires the first; absent, there
		// is no ceiling at all.
		mask, masks := uint16(0xFFFF), 0
		for i := 0; i < len(body); i += posixACLEntrySize {
			if binary.LittleEndian.Uint16(body[i:i+2]) == posixTagMask {
				mask, masks = binary.LittleEndian.Uint16(body[i+2:i+4]), masks+1
			}
		}
		if masks > 1 {
			t.Fatalf("parsePOSIXACL accepted %d mask entries, so the last one hid every writer under it", masks)
		}

		for i := 0; i < len(body); i += posixACLEntrySize {
			tag := binary.LittleEndian.Uint16(body[i : i+2])
			perm := binary.LittleEndian.Uint16(body[i+2 : i+4])
			id := binary.LittleEndian.Uint32(body[i+4 : i+8])
			var want principal
			switch {
			case tag == posixTagOther && perm&posixPermWrite != 0:
				// OTHER is outside the mask in POSIX.1e, however restrictive it is.
				want = principal{kind: principalEveryone}
			case perm&mask&posixPermWrite == 0:
				continue
			case tag == posixTagUser:
				want = principal{kind: principalUser, id: int(id)}
			case tag == posixTagGroup:
				want = principal{kind: principalGroup, id: int(id)}
			case tag == posixTagGroupObj:
				// The owning group, whose id the entry does not carry.
				want = principal{kind: principalGroup, id: owningGid}
			default:
				// USER_OBJ and MASK name no writer of their own.
				continue
			}
			if !slices.Contains(writers, want) {
				t.Fatalf("parsePOSIXACL(%x) = %v with no error, but the entry at %d grants write to %v", blob, writers, i, want)
			}
		}
	})
}
