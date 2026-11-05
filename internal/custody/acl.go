//go:build linux

package custody

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"slices"
	"syscall"
)

// The extended attributes Linux exposes an access-control list through. Only a
// non-trivial list creates one, so a path with none is described by its mode.
const (
	xattrPOSIXACL = "system.posix_acl_access"
	xattrNFS4ACL  = "system.nfs4_acl"     // the nfs client
	xattrNFS4XDR  = "system.nfs4_acl_xdr" // OpenZFS on Linux
)

// aclDialect is one access-control-list encoding; adding a dialect is adding a
// row to aclDialects.
type aclDialect struct {
	// parse names the principals the list grants write to; nil is an encoding
	// deliberately not decoded, refused by name (undecodable says why).
	parse func(blob []byte, stat *syscall.Stat_t) ([]principal, error)
	// controls names the principals that can take the object or rewrite its
	// list; nil means the dialect cannot express either grant.
	controls    func(blob []byte, stat *syscall.Stat_t) ([]principal, error)
	xattr       string
	undecodable string
	// ceiling sizes the one getxattr read. It must be positive: a zero-length
	// buffer makes getxattr a size probe that answers with a nil error.
	ceiling int
	// modeFloor says the mode's group and other write bits grant independently
	// of the list. False for POSIX.1e, where the group bits are the list's mask.
	modeFloor bool
}

// aclDialects is every dialect recognised, in probe order. system.nfs4_acl is
// probed although nothing decodes it, so finding one is a named refusal.
var aclDialects = []aclDialect{{
	xattr:     xattrPOSIXACL,
	ceiling:   posixACLHeaderSize + posixACLMaxEntries*posixACLEntrySize,
	parse:     parsePOSIXACL,
	modeFloor: false,
	controls:  nil,
}, {
	xattr:   xattrNFS4ACL,
	ceiling: nfs4HeaderSize + nfs4MaxACEs*nfs4ACESize,
	// String principals ("root@example.com"), which the fixed-size XDR
	// layout would misread.
	parse:       nil,
	undecodable: "which carries string principals rather than the numeric ids of " + xattrNFS4XDR,
}, {
	xattr:     xattrNFS4XDR,
	ceiling:   nfs4HeaderSize + nfs4MaxACEs*nfs4ACESize,
	parse:     parseNFS4ACL,
	modeFloor: true,
	controls: func(blob []byte, stat *syscall.Stat_t) ([]principal, error) {
		return parseNFS4Granted(blob, stat, nfs4ControlMask)
	},
}}

func init() { validateACLDialects(aclDialects) }

// validateACLDialects panics on a malformed table: the table is a constant of
// the program, so a bad row is a build defect, caught at startup.
func validateACLDialects(dialects []aclDialect) {
	seen := make(map[string]bool, len(dialects))
	for _, d := range dialects {
		switch {
		case d.xattr == "":
			panic("custody: an ACL dialect has no attribute name")
		case seen[d.xattr]:
			panic("custody: duplicate ACL dialect " + d.xattr)
		case d.ceiling <= 0:
			panic("custody: ACL dialect " + d.xattr + " has no ceiling, which would make getxattr a size probe")
		case d.parse == nil && d.undecodable == "":
			panic("custody: undecodable ACL dialect " + d.xattr + " does not say why")
		case d.parse != nil && d.undecodable != "":
			panic("custody: decodable ACL dialect " + d.xattr + " carries an undecodable reason")
		case d.parse == nil && d.controls != nil:
			panic("custody: undecodable ACL dialect " + d.xattr + " claims to report control grants")
		}
		seen[d.xattr] = true
	}
}

// principalKind is what an access-control entry names.
type principalKind uint8

const (
	principalUser principalKind = iota
	principalGroup
	principalEveryone
)

// principal is an identity that can modify a filesystem object; everyone
// carries no id.
type principal struct {
	id   int
	kind principalKind
}

func (p principal) String() string {
	switch p.kind {
	case principalUser:
		return fmt.Sprintf("uid %d", p.id)
	case principalGroup:
		return fmt.Sprintf("gid %d", p.id)
	}
	return "everyone"
}

// POSIX.1e access ACL layout, little-endian kernel ABI
// (include/uapi/linux/posix_acl_xattr.h): a version word, then 8-byte entries.
const (
	posixACLVersion    = 2
	posixACLHeaderSize = 4
	posixACLEntrySize  = 8
	posixACLMaxEntries = 4096 // a sanity bound; real ACLs hold a handful
)

// POSIX.1e entry tags and the write permission bit.
const (
	posixTagUserObj  uint16 = 0x01
	posixTagUser     uint16 = 0x02
	posixTagGroupObj uint16 = 0x04
	posixTagGroup    uint16 = 0x08
	posixTagMask     uint16 = 0x10
	posixTagOther    uint16 = 0x20

	posixPermWrite uint16 = 0x02
)

// NFSv4 ACL as OpenZFS serves it in system.nfs4_acl_xdr: big-endian XDR, a
// flags word, an entry count, then 20-byte entries {type, flag, whoIsSpecial,
// accessMask, id}. Confirmed against ZFS samples (acl_golden_test.go).
const (
	nfs4HeaderSize = 8
	nfs4ACESize    = 20
	nfs4MaxACEs    = 4096
)

// NFSv4 entry types, flags, special principals and access-mask bits
// (RFC 7530 section 6.2.1).
const (
	nfs4TypeAllow uint32 = 0
	nfs4TypeDeny  uint32 = 1
	nfs4TypeAudit uint32 = 2
	nfs4TypeAlarm uint32 = 3

	nfs4FlagIdentifierGroup uint32 = 0x0040
	nfs4FlagInheritOnly     uint32 = 0x0008

	// The only discriminator that makes an entry's id a special principal.
	nfs4WhoIsSpecial uint32 = 1

	nfs4WhoOwner    uint32 = 1
	nfs4WhoGroup    uint32 = 2
	nfs4WhoEveryone uint32 = 3

	nfs4WriteData   uint32 = 0x00000002
	nfs4AppendData  uint32 = 0x00000004
	nfs4DeleteChild uint32 = 0x00000040
	nfs4Delete      uint32 = 0x00010000
	nfs4WriteACL    uint32 = 0x00040000
	nfs4WriteOwner  uint32 = 0x00080000
)

// nfs4WriteMask is every grant that changes what an object is. WRITE_ACL and
// WRITE_OWNER are in it because either lets a principal grant itself the rest;
// timestamps and named attributes are out, since neither replaces a file.
const nfs4WriteMask = nfs4WriteData | nfs4AppendData | nfs4DeleteChild |
	nfs4Delete | nfs4WriteACL | nfs4WriteOwner

// nfs4ControlMask is what dismantles a sticky ancestor's protection. Not
// DELETE_CHILD: Linux (fs/namei.c check_sticky) and OpenZFS
// (zfs_zaccess_delete) apply the sticky rule whatever the list grants, and ZFS
// adds DELETE_CHILD to every mode-derived write grant on a directory.
const nfs4ControlMask = nfs4WriteACL | nfs4WriteOwner

// errACLUnreadable reports a list that is present but could not be evaluated,
// which fails closed.
var errACLUnreadable = errors.New("the access-control list could not be evaluated")

// errACLDialectUnsupported reports a list in a dialect this package does not
// decode.
var errACLDialectUnsupported = fmt.Errorf("%w: the dialect is not one this parser can decode", errACLUnreadable)

// writersOf returns every principal other than the owner that can modify
// path. With no list, or under NFSv4, the mode's group and other write bits
// grant too. Under POSIX.1e they are the list's mask, not a grant, so the list
// alone answers: reading them as a grant names a group the list denies.
func writersOf(path string, fi os.FileInfo, stat *syscall.Stat_t) ([]principal, error) {
	dialect, blob, err := readACL(path)
	if err != nil {
		return nil, err
	}
	var out []principal
	if dialect == nil || dialect.modeFloor {
		perm := fi.Mode().Perm()
		if perm&0o020 != 0 {
			out = append(out, principal{kind: principalGroup, id: int(stat.Gid)})
		}
		if perm&0o002 != 0 {
			out = append(out, principal{kind: principalEveryone})
		}
	}
	if dialect == nil {
		return out, nil
	}
	granted, err := dialect.parse(blob, stat)
	if err != nil {
		return nil, fmt.Errorf("%w: %s holds %s: %w", errACLUnreadable, path, dialect.xattr, err)
	}
	return append(out, granted...), nil
}

// readACL returns the first list path carries, or a nil dialect when it
// carries none. Only ENODATA and ENOTSUP mean no list: any other error,
// ENOSYS from a seccomp filter included, says nothing about the object.
func readACL(path string) (*aclDialect, []byte, error) {
	for i := range aclDialects {
		dialect := &aclDialects[i]
		found, readErr := getxattrAll(path, dialect)
		switch {
		case readErr == nil && dialect.parse == nil:
			return nil, nil, fmt.Errorf("%w: %s holds %s, %s. Remove the list, or serve the directory over a filesystem that exposes %s",
				errACLDialectUnsupported, path, dialect.xattr, dialect.undecodable, xattrNFS4XDR)
		case readErr == nil:
			return dialect, found, nil
		case errors.Is(readErr, syscall.ENODATA), errors.Is(readErr, syscall.ENOTSUP),
			errors.Is(readErr, syscall.EOPNOTSUPP):
			continue
		default:
			return nil, nil, fmt.Errorf("%w: reading %s of %s: %w", errACLUnreadable, dialect.xattr, path, readErr)
		}
	}
	return nil, nil, nil
}

// controllersOf returns every principal that can take path's ownership or
// rewrite its list. Only NFSv4 can grant either.
func controllersOf(path string, stat *syscall.Stat_t) ([]principal, error) {
	dialect, blob, err := readACL(path)
	if err != nil {
		return nil, err
	}
	if dialect == nil || dialect.controls == nil {
		return nil, nil
	}
	granted, err := dialect.controls(blob, stat)
	if err != nil {
		return nil, fmt.Errorf("%w: %s holds %s: %w", errACLUnreadable, path, dialect.xattr, err)
	}
	return granted, nil
}

// getxattrAll reads a list in one call, into a buffer the size of the largest
// list the parser accepts. A size probe then a read is not atomic, and a
// principal holding WRITE_ACL can shrink or drop its own grant in between.
// ERANGE and an empty value are refusals for the same reason.
func getxattrAll(path string, dialect *aclDialect) ([]byte, error) {
	attr := dialect.xattr
	buf := make([]byte, dialect.ceiling)
	n, err := getxattrFn(path, attr, buf)
	switch {
	case errors.Is(err, syscall.ERANGE):
		return nil, fmt.Errorf("%s is longer than the %d bytes this parser would accept: %w", attr, len(buf), err)
	case err != nil:
		return nil, err
	case n <= 0:
		return nil, fmt.Errorf("%s is present but %d bytes long, which is not a list this parser can read", attr, n)
	case n > len(buf):
		return nil, fmt.Errorf("%s answered %d bytes into a %d byte buffer, which is the size-probe reply rather than a list", attr, n, len(buf))
	}
	return buf[:n], nil
}

// getxattrFn is replaced in tests: no unprivileged test can mount a filesystem
// serving an NFSv4 list.
var getxattrFn = syscall.Getxattr

// parsePOSIXACL returns the principals a POSIX.1e access list grants write to,
// other than the owner. The mask caps named users and groups and the owning
// group; it does not cap other.
func parsePOSIXACL(blob []byte, stat *syscall.Stat_t) ([]principal, error) {
	entries, err := decodePOSIXACL(blob)
	if err != nil {
		return nil, err
	}
	mask, err := posixMask(entries)
	if err != nil {
		return nil, err
	}
	var out []principal
	for _, e := range entries {
		if e.tag == posixTagOther {
			if e.perm&posixPermWrite != 0 {
				out = append(out, principal{kind: principalEveryone})
			}
			continue
		}
		if e.perm&mask&posixPermWrite == 0 {
			continue
		}
		switch e.tag {
		case posixTagUser:
			out = append(out, principal{kind: principalUser, id: int(e.id)})
		case posixTagGroup:
			out = append(out, principal{kind: principalGroup, id: int(e.id)})
		case posixTagGroupObj:
			out = append(out, principal{kind: principalGroup, id: int(stat.Gid)})
		}
	}
	return out, nil
}

// posixMask returns the list's mask, or every bit when it has none. A second
// mask is refused: picking either one could hide a named writer.
func posixMask(entries []posixEntry) (uint16, error) {
	mask := uint16(0xFFFF)
	seen := false
	for _, e := range entries {
		if e.tag != posixTagMask {
			continue
		}
		if seen {
			return 0, errors.New("the list carries more than one mask entry")
		}
		mask, seen = e.perm, true
	}
	return mask, nil
}

// decodePOSIXACL refuses any shape but a version word and whole, known entries,
// since a short read would under-report writers.
func decodePOSIXACL(blob []byte) ([]posixEntry, error) {
	if len(blob) < posixACLHeaderSize {
		return nil, fmt.Errorf("%d bytes is shorter than the %d byte header", len(blob), posixACLHeaderSize)
	}
	if v := binary.LittleEndian.Uint32(blob[:posixACLHeaderSize]); v != posixACLVersion {
		return nil, fmt.Errorf("unsupported version %d", v)
	}
	body := blob[posixACLHeaderSize:]
	if len(body)%posixACLEntrySize != 0 {
		return nil, fmt.Errorf("%d bytes of entries is not a multiple of %d", len(body), posixACLEntrySize)
	}
	count := len(body) / posixACLEntrySize
	if count > posixACLMaxEntries {
		return nil, fmt.Errorf("%d entries is over the %d limit", count, posixACLMaxEntries)
	}
	out := make([]posixEntry, 0, count)
	for i := range count {
		raw := body[i*posixACLEntrySize : (i+1)*posixACLEntrySize]
		e := posixEntry{
			tag:  binary.LittleEndian.Uint16(raw[0:2]),
			perm: binary.LittleEndian.Uint16(raw[2:4]),
			id:   binary.LittleEndian.Uint32(raw[4:8]),
		}
		switch e.tag {
		case posixTagUserObj, posixTagUser, posixTagGroupObj, posixTagGroup,
			posixTagMask, posixTagOther:
		default:
			return nil, fmt.Errorf("unknown entry tag %#x", e.tag)
		}
		out = append(out, e)
	}
	if err := requirePOSIXTriple(out); err != nil {
		return nil, err
	}
	return out, nil
}

// requirePOSIXTriple refuses a list without exactly one user::, group:: and
// other:: entry. writersOf takes no mode floor under POSIX.1e, so a list
// missing group:: or other:: would answer nobody for a principal that can write.
func requirePOSIXTriple(entries []posixEntry) error {
	for _, required := range []struct {
		name string
		tag  uint16
	}{
		{"user::", posixTagUserObj},
		{"group::", posixTagGroupObj},
		{"other::", posixTagOther},
	} {
		n := 0
		for _, e := range entries {
			if e.tag == required.tag {
				n++
			}
		}
		if n != 1 {
			return fmt.Errorf("the list carries %d %s entries rather than exactly one", n, required.name)
		}
	}
	return nil
}

// posixEntry is one decoded POSIX.1e entry.
type posixEntry struct {
	id   uint32
	tag  uint16
	perm uint16
}

// parseNFS4ACL returns the principals an NFSv4 list grants write to, other
// than the owner.
func parseNFS4ACL(blob []byte, stat *syscall.Stat_t) ([]principal, error) {
	return parseNFS4Granted(blob, stat, nfs4WriteMask)
}

// parseNFS4Granted returns the principals an ALLOW entry grants any bit of
// want. DENY can only subtract and AUDIT and ALARM grant nothing; an unknown
// type or discriminator is refused, since skipping it could drop a writer.
// An INHERIT_ONLY entry does not apply to the object itself.
func parseNFS4Granted(blob []byte, stat *syscall.Stat_t, want uint32) ([]principal, error) {
	if len(blob) < nfs4HeaderSize {
		return nil, fmt.Errorf("%d bytes is shorter than the %d byte header", len(blob), nfs4HeaderSize)
	}
	count := binary.BigEndian.Uint32(blob[4:8])
	if count > nfs4MaxACEs {
		return nil, fmt.Errorf("%d entries is over the %d limit", count, nfs4MaxACEs)
	}
	body := blob[nfs4HeaderSize:]
	if need := int(count) * nfs4ACESize; len(body) != need {
		return nil, fmt.Errorf("%d entries need %d bytes of body, got %d", count, need, len(body))
	}

	var out []principal
	for i := range int(count) {
		raw := body[i*nfs4ACESize : (i+1)*nfs4ACESize]
		aceType := binary.BigEndian.Uint32(raw[0:4])
		flag := binary.BigEndian.Uint32(raw[4:8])
		special := binary.BigEndian.Uint32(raw[8:12])
		mask := binary.BigEndian.Uint32(raw[12:16])
		id := binary.BigEndian.Uint32(raw[16:20])

		switch aceType {
		case nfs4TypeAllow:
		case nfs4TypeDeny, nfs4TypeAudit, nfs4TypeAlarm:
			continue
		default:
			return nil, fmt.Errorf("entry %d carries unknown type %d", i, aceType)
		}
		if flag&nfs4FlagInheritOnly != 0 || mask&want == 0 {
			continue
		}
		switch {
		case special == 0:
			kind := principalUser
			if flag&nfs4FlagIdentifierGroup != 0 {
				kind = principalGroup
			}
			out = append(out, principal{kind: kind, id: int(id)})
		case special != nfs4WhoIsSpecial:
			return nil, fmt.Errorf("entry %d carries unknown whoIsSpecial %d", i, special)
		case id == nfs4WhoOwner:
		case id == nfs4WhoGroup:
			out = append(out, principal{kind: principalGroup, id: int(stat.Gid)})
		case id == nfs4WhoEveryone:
			out = append(out, principal{kind: principalEveryone})
		default:
			return nil, fmt.Errorf("entry %d names unknown special principal %d", i, id)
		}
	}
	return out, nil
}

// Trust is the users, beside root and this process's uid, whose write access
// the caller declares acceptable: the library can see that a uid may write,
// never that it is already privileged on the host.
type Trust struct {
	UIDs []int
}

func (t Trust) allowsOwner(uid, euid int) bool {
	return uid == euid || uid == 0 || slices.Contains(t.UIDs, uid)
}

// allows reports whether p may write. Everyone never may. Group 0 may write an
// ancestor, though its members do not hold root, because the walk judges every
// directory up to "/" and a root:root 0775 one is common; it may not write the
// protected directory itself (leaf), which this process creates 0755.
func (t Trust) allows(p principal, euid int, leaf bool) bool {
	switch p.kind {
	case principalUser:
		return p.id == euid || p.id == 0 || slices.Contains(t.UIDs, p.id)
	case principalGroup:
		return p.id == 0 && !leaf
	}
	return false
}

func (t Trust) firstStranger(writers []principal, euid int, leaf bool) (principal, bool) {
	for _, p := range writers {
		if !t.allows(p, euid, leaf) {
			return p, true
		}
	}
	return principal{}, false
}

// hint points at TrustedUIDs only while the caller has declared none.
func (t Trust) hint() string {
	if len(t.UIDs) > 0 {
		return ""
	}
	return ". If that user is already privileged on this host, declare it in TrustedUIDs"
}

// hintFor is hint for a writer refusal: only a user can be declared.
func (t Trust) hintFor(p principal) string {
	if p.kind != principalUser {
		return ""
	}
	return t.hint()
}
