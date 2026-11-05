//go:build linux

package custody

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestGetxattrZeroBufferIsASizeProbe pins the KERNEL behaviour the last guard in
// [getxattrAll] defends against, because that guard reads as unreachable until you know
// this: getxattr with a zero-length buffer does not answer ERANGE, it answers the
// attribute's FULL LENGTH with a nil error. That is the size-probe form of the same
// syscall.
func TestGetxattrZeroBufferIsASizeProbe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	const attr = "user.custody_probe"
	value := []byte("0123456789ABCDEF")
	if err := syscall.Setxattr(path, attr, value, 0); err != nil {
		// A filesystem without user-xattr support cannot host this fixture. The seam-driven
		// test below still gates the refusal itself; this one gates the premise.
		t.Skipf("this filesystem does not accept a user extended attribute (%v), so the kernel premise cannot be measured here", err)
	}

	n, err := syscall.Getxattr(path, attr, make([]byte, 0))
	if err != nil {
		t.Fatalf("getxattr with a zero-length buffer returned %v; the guard in getxattrAll assumes this is the size-probe form and answers a length instead", err)
	}
	if n != len(value) {
		t.Errorf("getxattr with a zero-length buffer answered %d, want the attribute's full length %d", n, len(value))
	}
	// The premise stated the way getxattrAll sees it.
	if n <= 0 {
		t.Fatalf("answered %d, so the n <= 0 branch would have caught it and the n > len(buf) guard would be genuinely dead", n)
	}
}

// TestGetxattrAllRefusesASizeProbe drives the branch the kernel premise above makes
// reachable: a dialect whose ceiling is zero. It must refuse rather than panic.
//
// [validateACLDialects] already makes such a row unshippable, so this asserts the second of
// two independent guards. That is deliberate — the table check catches the mistake at
// startup, and this one catches it if a future caller ever builds a dialect value without
// going through the table.
func TestGetxattrAllRefusesASizeProbe(t *testing.T) {
	value := []byte("0123456789ABCDEF")
	old := getxattrFn
	// The kernel's probe reply, measured by TestGetxattrZeroBufferIsASizeProbe: the full
	// length, with a nil error, into a buffer too small to hold it.
	getxattrFn = func(_, _ string, dest []byte) (int, error) {
		if len(dest) < len(value) {
			return len(value), nil
		}
		return copy(dest, value), nil
	}
	defer func() { getxattrFn = old }()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("getxattrAll panicked on a size-probe reply (%v); the guard exists so a zero ceiling cannot slice past its own buffer", r)
		}
	}()
	got, err := getxattrAll("/irrelevant", &aclDialect{xattr: "system.fake_acl", ceiling: 0})
	if err == nil {
		t.Fatalf("getxattrAll returned %x, nil; want a refusal: a probe reply is not a list", got)
	}
	if got != nil {
		t.Errorf("getxattrAll returned %x alongside its error; a refusal must carry no bytes", got)
	}
	if !strings.Contains(err.Error(), "size-probe") {
		t.Errorf("getxattrAll error = %v, want it to name the size-probe reply so the next reader does not delete the guard as dead", err)
	}
}

// TestACLDialectsTableIsWellFormed pins each dialect row's properties, which
// every caller reads from the row.
func TestACLDialectsTableIsWellFormed(t *testing.T) {
	// The probe ORDER is behaviour: POSIX.1e first because it is the common case, and the
	// undecodable dialect must be probed BEFORE the XDR one, or an object carrying both
	// would be decoded rather than refused.
	wantOrder := []string{xattrPOSIXACL, xattrNFS4ACL, xattrNFS4XDR}
	if len(aclDialects) != len(wantOrder) {
		t.Fatalf("aclDialects has %d rows, want %d", len(aclDialects), len(wantOrder))
	}
	for i, want := range wantOrder {
		if aclDialects[i].xattr != want {
			t.Errorf("aclDialects[%d] = %q, want %q: the order is the probe order", i, aclDialects[i].xattr, want)
		}
	}

	byName := map[string]*aclDialect{}
	for i := range aclDialects {
		byName[aclDialects[i].xattr] = &aclDialects[i]
	}

	// POSIX.1e: the mode is the list's MASK, not a grant, so no floor. This is the
	// fail-closed bug writersOf documents; it now lives in exactly one place.
	if posix := byName[xattrPOSIXACL]; posix.modeFloor {
		t.Error("the POSIX.1e row claims a mode floor; the mode's group bits are that list's mask, so a floor names a group the list denies")
	}
	// NFSv4 XDR: the mode IS an independent projection, so the floor applies.
	if xdr := byName[xattrNFS4XDR]; !xdr.modeFloor {
		t.Error("the NFSv4 XDR row claims no mode floor; a 0755 directory can carry a named-user grant, and the mode still names group and everyone")
	}
	// Only NFSv4 can express a control grant.
	if byName[xattrPOSIXACL].controls != nil {
		t.Error("the POSIX.1e row reports control grants; that dialect cannot express WRITE_ACL or WRITE_OWNER")
	}
	if byName[xattrNFS4XDR].controls == nil {
		t.Error("the NFSv4 XDR row reports no control grants; the sticky-ancestor exemption depends on reading them")
	}
	// The undecodable dialect must stay in the table: dropping the row would make a grant
	// served over NFS invisible, which is the same failure by omission the refusal replaced.
	if nfs4 := byName[xattrNFS4ACL]; nfs4.parse != nil {
		t.Error("the system.nfs4_acl row has a parser; it carries string principals, so a fixed-size layout misreads it")
	}
	// Every ceiling must be big enough for that dialect's own header, or the parser can
	// never see a complete list.
	if got := byName[xattrPOSIXACL].ceiling; got < posixACLHeaderSize {
		t.Errorf("the POSIX.1e ceiling is %d, below its %d byte header", got, posixACLHeaderSize)
	}
	for _, name := range []string{xattrNFS4ACL, xattrNFS4XDR} {
		if got := byName[name].ceiling; got < nfs4HeaderSize {
			t.Errorf("the %s ceiling is %d, below the %d byte NFSv4 header", name, got, nfs4HeaderSize)
		}
	}
}

// TestValidateACLDialectsRejectsAMalformedRow drives the startup check with each row shape
// it exists to stop. Without this the validator is a function nothing has ever run against
// bad input, and the zero-ceiling case is the one that matters: it is the difference between
// a build that cannot start and a panic inside a custody decision.
func TestValidateACLDialectsRejectsAMalformedRow(t *testing.T) {
	ok := func(blob []byte, stat *syscall.Stat_t) ([]principal, error) { return nil, nil }
	cases := []struct {
		name     string
		dialects []aclDialect
		want     string
	}{
		{
			name:     "no ceiling turns the read into a size probe",
			dialects: []aclDialect{{xattr: "system.fake_acl", parse: ok}},
			want:     "has no ceiling",
		},
		{
			name:     "negative ceiling",
			dialects: []aclDialect{{xattr: "system.fake_acl", ceiling: -1, parse: ok}},
			want:     "has no ceiling",
		},
		{
			name:     "no attribute name",
			dialects: []aclDialect{{ceiling: 8, parse: ok}},
			want:     "no attribute name",
		},
		{
			name: "duplicate dialect",
			dialects: []aclDialect{
				{xattr: "system.fake_acl", ceiling: 8, parse: ok},
				{xattr: "system.fake_acl", ceiling: 8, parse: ok},
			},
			want: "duplicate ACL dialect",
		},
		{
			name:     "undecodable without a reason",
			dialects: []aclDialect{{xattr: "system.fake_acl", ceiling: 8}},
			want:     "does not say why",
		},
		{
			name:     "decodable carrying a reason",
			dialects: []aclDialect{{xattr: "system.fake_acl", ceiling: 8, parse: ok, undecodable: "because"}},
			want:     "carries an undecodable reason",
		},
		{
			name:     "undecodable claiming control grants",
			dialects: []aclDialect{{xattr: "system.fake_acl", ceiling: 8, undecodable: "because", controls: ok}},
			want:     "claims to report control grants",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatalf("validateACLDialects accepted %+v; want a panic naming %q", tc.dialects, tc.want)
				}
				msg, isStr := r.(string)
				if !isStr || !strings.Contains(msg, tc.want) {
					t.Errorf("panic = %v, want it to contain %q", r, tc.want)
				}
			}()
			validateACLDialects(tc.dialects)
		})
	}
}

// TestValidateACLDialectsAcceptsTheShippedTable is the other half: the check must pass on
// the real table, or the package could not start at all.
func TestValidateACLDialectsAcceptsTheShippedTable(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("validateACLDialects rejected the shipped table: %v", r)
		}
	}()
	validateACLDialects(aclDialects)
}

// TestReadACLReturnsTheDialectNotAName pins that readACL's answer carries the
// row's properties, so no caller re-derives them from an attribute name.
func TestReadACLReturnsTheDialectNotAName(t *testing.T) {
	blob := buildNFS4ACL(nfs4TypeAllow, 0, 0, nfs4WriteData, 4242)
	old := getxattrFn
	getxattrFn = serveOne(xattrNFS4XDR, blob)
	defer func() { getxattrFn = old }()

	dialect, got, err := readACL("/irrelevant")
	if err != nil {
		t.Fatalf("readACL: %v", err)
	}
	if dialect == nil {
		t.Fatal("readACL returned no dialect for an object carrying a list it can decode")
	}
	if dialect.xattr != xattrNFS4XDR {
		t.Errorf("dialect.xattr = %q, want %q", dialect.xattr, xattrNFS4XDR)
	}
	if dialect.parse == nil {
		t.Error("dialect.parse is nil for a dialect this package decodes")
	}
	if dialect.controls == nil {
		t.Error("dialect.controls is nil for the one dialect that can express control grants")
	}
	if !dialect.modeFloor {
		t.Error("dialect.modeFloor is false for NFSv4, where the mode independently names group and everyone")
	}
	if len(got) != len(blob) {
		t.Errorf("readACL returned %d bytes, want the whole %d byte list", len(got), len(blob))
	}
}

// TestReadACLReportsNoDialectWhenThereIsNoList pins the absence case, which is the one a
// nil dialect has to express without being mistaken for a refusal. It also pins that the
// mode floor still applies there: with no list, the mode is the only statement about who
// can write, so treating absence as "no floor" would drop the writers a 0777 directory
// names.
func TestReadACLReportsNoDialectWhenThereIsNoList(t *testing.T) {
	old := getxattrFn
	getxattrFn = func(string, string, []byte) (int, error) { return 0, syscall.ENODATA }
	defer func() { getxattrFn = old }()

	dialect, blob, err := readACL("/irrelevant")
	if err != nil {
		t.Fatalf("readACL on an object with no list: %v", err)
	}
	if dialect != nil {
		t.Errorf("readACL named %q, want no dialect at all", dialect.xattr)
	}
	if blob != nil {
		t.Errorf("readACL returned %x, want no bytes", blob)
	}

	// The floor half, through the real caller.
	dir := t.TempDir()
	target := filepath.Join(dir, "wide")
	if err := os.Mkdir(target, 0o777); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(target, 0o777); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	fi, err := os.Lstat(target)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	stat, statOK := fi.Sys().(*syscall.Stat_t)
	if !statOK {
		t.Fatal("no stat information")
	}
	writers, err := writersOf(target, fi, stat)
	if err != nil {
		t.Fatalf("writersOf: %v", err)
	}
	var everyone bool
	for _, p := range writers {
		if p.kind == principalEveryone {
			everyone = true
		}
	}
	if !everyone {
		t.Errorf("writersOf on a 0777 directory with no list = %v, want everyone among them: with no list the mode is the whole answer", writers)
	}
}

// TestUndecodableDialectNeverReachesAParser pins that readACL refuses the
// undecodable dialect, so no caller reaches a parse with it.
func TestUndecodableDialectNeverReachesAParser(t *testing.T) {
	for i := range aclDialects {
		d := &aclDialects[i]
		if d.parse != nil {
			continue
		}
		old := getxattrFn
		getxattrFn = serveOne(d.xattr, []byte("string-principal payload"))
		dialect, _, err := readACL("/irrelevant")
		getxattrFn = old

		if err == nil {
			t.Errorf("readACL accepted %s; an undecodable dialect must refuse", d.xattr)
		}
		if dialect != nil {
			t.Errorf("readACL returned dialect %q for the undecodable %s; a caller could then parse it", dialect.xattr, d.xattr)
		}
		if !errors.Is(err, errACLDialectUnsupported) {
			t.Errorf("readACL error for %s = %v, want errACLDialectUnsupported", d.xattr, err)
		}
		if !strings.Contains(err.Error(), d.undecodable) {
			t.Errorf("readACL error for %s = %v, want it to carry the row's own reason %q", d.xattr, err, d.undecodable)
		}
	}
}
