package toolbelt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installBase stands in for the version directory the containment rule
// guards. The real one is <toolsDir>/opt/<name>/<version>, so it always
// keeps at least the literal "opt" component: validToolName refuses a
// name with a "." or ".." component and validVersionString admits no
// separator, so neither can collapse the join onto "/" or ".".
const installBase = "/opt/toolbelt/opt/rg/14.1.1"

// TestSafeJoin_Containment pins the rule safeJoin enforces on
// files[].src, which arrives from the aqua registry and is therefore
// externally controlled: the join may land strictly beneath the version
// directory and nowhere else. The accepted half is as load-bearing as
// the rejected one — a registry entry whose name merely contains or
// begins with two dots is an ordinary file and must still install.
func TestSafeJoin_Containment(t *testing.T) {
	cases := map[string]struct {
		rel     string
		want    string // "" means the call must fail
		wantErr string
	}{
		// Accepted: lands beneath the base.
		"plain name":              {rel: "rg", want: installBase + "/rg"},
		"nested":                  {rel: "bin/rg", want: installBase + "/bin/rg"},
		"dot-slash prefix":        {rel: "./bin/rg", want: installBase + "/bin/rg"},
		"doubled separator":       {rel: "bin//rg", want: installBase + "/bin/rg"},
		"interior traversal kept": {rel: "bin/../libexec/rg", want: installBase + "/libexec/rg"},

		// Accepted: two dots that are not a traversal component. A
		// substring or leading-".." test would refuse all four.
		"leading dots in a name":  {rel: "..extras/movie.mkv", want: installBase + "/..extras/movie.mkv"},
		"three dots is a name":    {rel: "...", want: installBase + "/..."},
		"interior dots in a name": {rel: "key..v2", want: installBase + "/key..v2"},
		"dots inside a component": {rel: "a..b/c", want: installBase + "/a..b/c"},

		// Rejected: empty.
		"empty": {rel: "", wantErr: "empty path"},

		// Rejected: absolute where a relative name was required. Refused
		// on its own grounds rather than by the containment test, because
		// Clean CLAMPS a traversal at the filesystem root ("/.." cleans
		// to "/") while Join re-attaches it to a relative base.
		"absolute":                {rel: "/etc/passwd", wantErr: `absolute path "/etc/passwd" not allowed`},
		"absolute root traversal": {rel: "/..", wantErr: `absolute path "/.." not allowed`},
		"absolute inside base":    {rel: installBase + "/rg", wantErr: "not allowed"},

		// Rejected: traversal out of the base.
		"bare dotdot":       {rel: "..", wantErr: `path ".." escapes install dir`},
		"leading traversal": {rel: "../x", wantErr: "escapes install dir"},
		"double traversal":  {rel: "../../etc/passwd", wantErr: "escapes install dir"},
		"buried traversal":  {rel: "a/../../etc/passwd", wantErr: "escapes install dir"},
		"climb to parent":   {rel: "../", wantErr: "escapes install dir"},

		// Rejected: the prefix sibling — the version directory's name is
		// a prefix of the target's. Reachable only by leaving the base, so
		// a rule that compared strings without a separator would accept it.
		"prefix sibling": {rel: "../14.1.1-evil/rg", wantErr: "escapes install dir"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := safeJoin(installBase, tc.rel)
			switch {
			case tc.wantErr != "":
				if err == nil {
					t.Fatalf("safeJoin(base, %q) = %q, want error %q", tc.rel, got, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("safeJoin(base, %q) error = %q, want it to contain %q", tc.rel, err, tc.wantErr)
				}
			case err != nil:
				t.Fatalf("safeJoin(base, %q) = %v, want %q", tc.rel, err, tc.want)
			case got != tc.want:
				t.Errorf("safeJoin(base, %q) = %q, want %q", tc.rel, got, tc.want)
			}
		})
	}
}

// TestSafeJoin_RefusesTheBaseItself pins the half of the rule the
// containment predicate deliberately does NOT carry: pathinside.Inside
// admits a root as part of its own tree, so insideStrictly tests equality
// separately and safeJoin refuses a name that resolves to the version
// directory rather than to something inside it. Every input here is
// lexically inside the base — "." IS the base.
//
// The refusal is load-bearing rather than tidy: linkDeclaredFiles chmods
// the result 0o755 and publishes bin/<name> as a symlink to it, so
// accepting the base would chmod the version directory and publish a bin
// entry pointing at a directory, from a value the registry supplies.
func TestSafeJoin_RefusesTheBaseItself(t *testing.T) {
	for _, rel := range []string{".", "./", "a/..", "a/b/../..", "./a/../.", "bin/.."} {
		t.Run(rel, func(t *testing.T) {
			got, err := safeJoin(installBase, rel)
			if err == nil {
				t.Fatalf("safeJoin(base, %q) = %q, want the base itself refused", rel, got)
			}
			if !strings.Contains(err.Error(), "escapes install dir") {
				t.Errorf("safeJoin(base, %q) error = %q, want the escape message", rel, err)
			}
		})
	}
}

// TestInsideStrictly pins the predicate the symlink gate applies to an
// already-resolved path, where no join happens and the name is not the
// caller's to shape.
//
// Two properties beyond plain containment are asserted here. An
// UNCOMPARABLE pair — a relative target against an absolute base — must
// not read as containment; pathinside.Inside answers false for it, which
// is the refusal the gate previously bought by feeding a ".." sentinel
// through safeJoin. And a target whose name merely starts with the base's
// name is outside: /config/homework is not inside /config/home, the
// separator-precision bug class the predicate exists for.
func TestInsideStrictly(t *testing.T) {
	cases := map[string]struct {
		base, target string
		want         bool
	}{
		"child":                    {base: installBase, target: installBase + "/rg", want: true},
		"grandchild":               {base: installBase, target: installBase + "/bin/rg", want: true},
		"uncleaned child":          {base: installBase, target: installBase + "/./bin/../bin/rg", want: true},
		"base with trailing sep":   {base: installBase + "/", target: installBase + "/rg", want: true},
		"the base itself":          {base: installBase, target: installBase},
		"base written unclean":     {base: installBase, target: installBase + "/bin/.."},
		"parent":                   {base: installBase, target: filepath.Dir(installBase)},
		"unrelated":                {base: installBase, target: "/etc/passwd"},
		"prefix sibling":           {base: installBase, target: installBase + "-evil/rg"},
		"relative against absolut": {base: installBase, target: "rg"},
		"absolute against relativ": {base: "opt/rg/14.1.1", target: installBase + "/rg"},

		// The canonical lookalike pair the library exists for.
		"homework is not home":     {base: "/config/home", target: "/config/homework/rg"},
		"home's own child is home": {base: "/config/home", target: "/config/home/rg", want: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := insideStrictly(tc.base, tc.target); got != tc.want {
				t.Errorf("insideStrictly(%q, %q) = %v, want %v", tc.base, tc.target, got, tc.want)
			}
		})
	}
}

// TestLinkDeclaredFiles_RefusesSymlinkEscape drives the containment
// boundary through the real call path, on the two shapes the lexical
// check of files[].src alone cannot see: the declared file exists and its
// name is perfectly well-formed, but the symlink it resolves through
// lands on the version directory itself or on a directory whose name
// merely starts with the version directory's name.
//
// TestInstallAqua_SymlinkEscapeRejected already covers a symlink pointing
// far outside the tree. Both cases here are near misses, and both must be
// refused before the chmod and before bin/ publication.
func TestLinkDeclaredFiles_RefusesSymlinkEscape(t *testing.T) {
	cases := map[string]struct {
		// linkTarget is resolved against the version directory's parent.
		linkTarget func(versDir string) string
	}{
		"resolves to the version directory": {
			linkTarget: func(versDir string) string { return versDir },
		},
		"resolves to the prefix sibling": {
			linkTarget: func(versDir string) string { return versDir + "-evil" },
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// EvalSymlinks the scratch root so a resolved path compares
			// textually against versDir even when TMPDIR is a symlink.
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			in := &installer{toolsDir: dir, output: func(string) {}}
			versDir := filepath.Join(in.optDir(), "rg", "14.1.1")
			if err := os.MkdirAll(filepath.Join(versDir, "bin"), 0o755); err != nil {
				t.Fatal(err)
			}
			victim := tc.linkTarget(versDir)
			if err := os.MkdirAll(victim, 0o755); err != nil {
				t.Fatal(err)
			}
			// A restrictive mode so a follow-symlink chmod would show.
			if err := os.Chmod(victim, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(victim, filepath.Join(versDir, "bin", "rg")); err != nil {
				t.Fatal(err)
			}

			bins, err := in.linkDeclaredFiles(versDir, []AquaFile{{Name: "rg", Src: "bin/rg"}})
			if err == nil {
				t.Fatalf("linkDeclaredFiles = %v, want the symlink refused", bins)
			}
			if !strings.Contains(err.Error(), "escapes the install dir via symlink") {
				t.Errorf("error = %q, want the symlink-escape message", err)
			}
			if _, lerr := os.Lstat(filepath.Join(in.binDir(), "rg")); !os.IsNotExist(lerr) {
				t.Error("a bin/ link was published for the refused declared file")
			}
			fi, err := os.Stat(victim)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != 0o700 {
				t.Errorf("%s mode = %v, want 0700 (chmod followed the symlink)", victim, fi.Mode().Perm())
			}
		})
	}
}

// FuzzSafeJoin asserts the security invariant on the value the aqua
// registry controls: whatever files[].src holds, an accepted join lands
// strictly beneath the base and a refused one yields no path at all.
//
// The invariant is checked against a filepath.Rel oracle written out
// longhand rather than against pathinside, so the assertion is an
// independent formulation of "strictly beneath" and not a restatement of
// the implementation.
//
// Bug class: traversal that survives or is created by normalization,
// absolute-path smuggling, the prefix sibling, a name that resolves back
// onto the base, and separator confusion in a name that merely contains
// two dots.
func FuzzSafeJoin(f *testing.F) {
	seeds := []string{
		"rg", "bin/rg", "./bin/rg", "bin//rg", "bin/../libexec/rg",
		"", ".", "./", "a/..", "bin/..",
		"..", "../x", "../../etc/passwd", "a/../../etc/passwd",
		"../14.1.1-evil/rg", "..extras/movie.mkv", "...", "key..v2",
		"/etc/passwd", "/..", installBase, installBase + "/rg",
		`a\..\b`, "\x00rg", "rg\n../x",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, rel string) {
		got, err := safeJoin(installBase, rel)
		if err != nil {
			if got != "" {
				t.Fatalf("safeJoin(base, %q) refused but returned %q", rel, got)
			}
			return
		}

		// An accepted name was relative: absoluteness is refused on its
		// own grounds and must never reach the join.
		if filepath.IsAbs(rel) {
			t.Fatalf("safeJoin(base, %q) = %q accepted an absolute name", rel, got)
		}

		// The result is reachable from the base without leaving it, and
		// is not the base itself.
		oracle, rerr := filepath.Rel(installBase, got)
		if rerr != nil {
			t.Fatalf("safeJoin(base, %q) = %q is not comparable to the base: %v", rel, got, rerr)
		}
		if oracle == "." {
			t.Fatalf("safeJoin(base, %q) = %q resolved to the base itself", rel, got)
		}
		if oracle == ".." || strings.HasPrefix(oracle, ".."+string(filepath.Separator)) {
			t.Fatalf("safeJoin(base, %q) = %q leaves the base (rel %q)", rel, got, oracle)
		}

		// The result is already clean, so no later normalization moves it.
		if got != filepath.Clean(got) {
			t.Fatalf("safeJoin(base, %q) = %q is not cleaned", rel, got)
		}
	})
}
