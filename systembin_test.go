package toolbelt

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// stubSystemBin stages an executable stand-in for an image-baked binary and
// points the resolver's trusted set at it for the rest of the test.
//
// It reassigns a package var, so a test using it must NOT call t.Parallel: two
// parallel tests would each retarget the resolver for the other. Restored by
// t.Cleanup rather than defer, so it survives a subtest's failure path.
//
// The trusted set is what it retargets rather than PATH, and that is the whole
// reason this helper exists: a pinned spawn never consults PATH, so a PATH fake
// is not merely ineffective but SILENTLY ineffective — a test asserting that a
// stub did NOT run passes for the wrong reason.
func stubSystemBin(t *testing.T, name, script string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("Setup: stage %s stub: %v", name, err)
	}
	prev := systemBinDirs
	systemBinDirs = []string{dir}
	t.Cleanup(func() { systemBinDirs = prev })
	return path
}

// TestResolveSystemBin_AnswersOnlyFromTheTrustedSet is the property the whole
// file exists for: the resolver must not be reachable through the environment,
// because the directory this library publishes into is on PATH ahead of the
// system ones and a principal with one shell command can write it.
func TestResolveSystemBin_AnswersOnlyFromTheTrustedSet(t *testing.T) {
	planted := t.TempDir()
	if err := os.WriteFile(filepath.Join(planted, "tar"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	// Everything an attacker could plausibly control, pointed at the plant.
	t.Setenv("PATH", planted)
	t.Setenv("TOOLBELT_SYSTEM_BIN_DIRS", planted)

	trusted := t.TempDir()
	if err := os.WriteFile(filepath.Join(trusted, "tar"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	prev := systemBinDirs
	systemBinDirs = []string{trusted}
	t.Cleanup(func() { systemBinDirs = prev })

	got, err := resolveSystemBin("tar")
	if err != nil {
		t.Fatalf("resolveSystemBin(tar) = %v, want the trusted copy", err)
	}
	if want := filepath.Join(trusted, "tar"); got != want {
		t.Errorf("resolveSystemBin(tar) = %q, want %q — the environment decided the answer", got, want)
	}
}

// TestResolveSystemBin_RefusesRatherThanFallingBack pins the direction a miss
// takes. A fallback to a PATH lookup at any ONE site would void the pin
// everywhere, because an attacker picks the site.
func TestResolveSystemBin_RefusesRatherThanFallingBack(t *testing.T) {
	planted := t.TempDir()
	if err := os.WriteFile(filepath.Join(planted, "tar"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	t.Setenv("PATH", planted)

	prev := systemBinDirs
	systemBinDirs = []string{t.TempDir()} // empty: nothing to find
	t.Cleanup(func() { systemBinDirs = prev })

	if got, err := resolveSystemBin("tar"); !errors.Is(err, errSystemBin) {
		t.Errorf("resolveSystemBin over an empty trusted set = (%q, %v), want errSystemBin", got, err)
	}
	if hasSystemBin("tar") {
		t.Error("hasSystemBin disagreed with resolveSystemBin, so a gate can vouch for a binary the spawn cannot find")
	}
}

// TestResolveSystemBin_RefusesANameThatIsNotBare stops the set being escaped by
// the argument rather than by the environment: a name carrying a separator would
// otherwise address any file on the host through filepath.Join.
func TestResolveSystemBin_RefusesANameThatIsNotBare(t *testing.T) {
	prev := systemBinDirs
	systemBinDirs = []string{"/usr/bin"}
	t.Cleanup(func() { systemBinDirs = prev })

	for _, bad := range []string{"", "../../bin/sh", "/bin/sh", "sub/tar", "./tar"} {
		if got, err := resolveSystemBin(bad); !errors.Is(err, errSystemBin) {
			t.Errorf("resolveSystemBin(%q) = (%q, %v), want a refusal", bad, got, err)
		}
	}
}

// TestResolveSystemBin_RequiresAnExecutableRegularFile keeps the resolver from
// answering with something that cannot be spawned — a directory of that name, or
// a readable-but-not-executable file — where the caller would otherwise get an
// exec failure attributed to the tool rather than to the image.
func TestResolveSystemBin_RequiresAnExecutableRegularFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "adir"), 0o755); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "noexec"), []byte("x"), 0o644); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "good"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	prev := systemBinDirs
	systemBinDirs = []string{dir}
	t.Cleanup(func() { systemBinDirs = prev })

	for _, bad := range []string{"adir", "noexec", "absent"} {
		if got, err := resolveSystemBin(bad); err == nil {
			t.Errorf("resolveSystemBin(%q) = %q, want a refusal", bad, got)
		}
	}
	if _, err := resolveSystemBin("good"); err != nil {
		t.Errorf("resolveSystemBin(good) = %v, want the file", err)
	}
}

// TestResolveSystemBin_SearchesInOrder pins that the first trusted directory
// wins, which is what makes the set an ordered preference rather than a bag.
func TestResolveSystemBin_SearchesInOrder(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	for _, d := range []string{first, second} {
		if err := os.WriteFile(filepath.Join(d, "tar"), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("Setup: %v", err)
		}
	}
	prev := systemBinDirs
	systemBinDirs = []string{first, second}
	t.Cleanup(func() { systemBinDirs = prev })

	got, err := resolveSystemBin("tar")
	if err != nil {
		t.Fatalf("resolveSystemBin(tar) = %v", err)
	}
	if want := filepath.Join(first, "tar"); got != want {
		t.Errorf("resolveSystemBin(tar) = %q, want %q", got, want)
	}
}

// TestSystemCommand_PinsArgv0 is the producer's own contract: the command it
// hands back must name a file in the trusted set, never the bare name, or every
// site's pin is decorative.
func TestSystemCommand_PinsArgv0(t *testing.T) {
	want := stubSystemBin(t, "tar", "#!/bin/sh\n")

	cmd, err := systemCommand(t.Context(), "tar", "-xf", "x.tar")
	if err != nil {
		t.Fatalf("systemCommand(tar) = %v", err)
	}
	if cmd.Path != want {
		t.Errorf("cmd.Path = %q, want %q", cmd.Path, want)
	}
	if got := cmd.Args; !slices.Equal(got, []string{want, "-xf", "x.tar"}) {
		t.Errorf("cmd.Args = %q, want the resolved path then the arguments", got)
	}
	// The env is the CALLER's to state, because what a child resolves for
	// itself differs per site. A default here would silently pick one.
	if cmd.Env != nil {
		t.Errorf("cmd.Env = %q, want nil so the caller states its own", cmd.Env)
	}
}

// TestSystemEnvPATH_IsTheTrustedSetAlone covers the transitive leg: pinning
// argv[0] does not pin what the child resolves, and /usr/bin/gunzip is a
// #!/bin/sh script that calls gzip by bare name.
func TestSystemEnvPATH_IsTheTrustedSetAlone(t *testing.T) {
	t.Setenv("PATH", "/planted")
	t.Setenv("HOME", "/root")

	prev := systemBinDirs
	systemBinDirs = []string{"/usr/bin", "/bin"}
	t.Cleanup(func() { systemBinDirs = prev })

	got := systemEnvPATH()
	if want := []string{"PATH=/usr/bin:/bin"}; !slices.Equal(got, want) {
		t.Errorf("systemEnvPATH() = %q, want %q", got, want)
	}
}

// TestSystemPATHFirst_PrependsWithoutDropping is the apt family's variant: a
// dpkg maintainer script may rely on /usr/sbin, so the inherited PATH is kept
// and only the ORDER changes — which is what stops the published bin dir
// preceding the system directories.
func TestSystemPATHFirst_PrependsWithoutDropping(t *testing.T) {
	prev := systemBinDirs
	systemBinDirs = []string{"/usr/bin", "/bin"}
	t.Cleanup(func() { systemBinDirs = prev })

	got := systemPATHFirst([]string{"DEBIAN_FRONTEND=noninteractive", "PATH=/tools/bin:/usr/sbin", "HOME=/root"})

	var gotPATH string
	for _, kv := range got {
		if rest, ok := strings.CutPrefix(kv, "PATH="); ok {
			if gotPATH != "" {
				t.Fatalf("env carries PATH twice (%q), so which one wins is the child's choice", got)
			}
			gotPATH = rest
		}
	}
	if want := "/usr/bin:/bin:/tools/bin:/usr/sbin"; gotPATH != want {
		t.Errorf("PATH = %q, want %q", gotPATH, want)
	}
	for _, keep := range []string{"DEBIAN_FRONTEND=noninteractive", "HOME=/root"} {
		if !slices.Contains(got, keep) {
			t.Errorf("systemPATHFirst dropped %q; it must only reorder PATH", keep)
		}
	}
}

// TestSystemPATHFirst_SetsPATHWhenTheParentHadNone keeps an env with no PATH
// from yielding a trailing separator, which an empty PATH element reads as the
// current directory.
func TestSystemPATHFirst_SetsPATHWhenTheParentHadNone(t *testing.T) {
	prev := systemBinDirs
	systemBinDirs = []string{"/usr/bin"}
	t.Cleanup(func() { systemBinDirs = prev })

	got := systemPATHFirst([]string{"HOME=/root"})
	if want := []string{"HOME=/root", "PATH=/usr/bin"}; !slices.Equal(got, want) {
		t.Errorf("systemPATHFirst(no PATH) = %q, want %q", got, want)
	}
}

// TestSystemBinDirs_ProductionSetIsTheImageContract guards the default against a
// widening nobody meant. The published bin dir must never be a member: it is on
// the volume and this library's own trust model treats it as writable by the
// principal the pin exists to separate from.
func TestSystemBinDirs_ProductionSetIsTheImageContract(t *testing.T) {
	if want := []string{"/usr/bin", "/bin"}; !slices.Equal(systemBinDirs, want) {
		t.Errorf("systemBinDirs = %q, want %q", systemBinDirs, want)
	}
	for _, dir := range systemBinDirs {
		if !filepath.IsAbs(dir) {
			t.Errorf("systemBinDirs entry %q is not absolute, so it resolves against the working directory", dir)
		}
		if strings.Contains(dir, "tools") || strings.Contains(dir, "local") {
			t.Errorf("systemBinDirs entry %q looks like a managed or admin-writable directory", dir)
		}
	}
}

// TestSystemBinDirs_ResolveTheRealImageBinaries is the one case that asserts
// against the HOST rather than a fixture, and it is what would catch the trusted
// set being wrong for a consumer image rather than merely self-consistent.
// Skipped where a binary is genuinely absent, so it never fails for the image's
// own reasons.
func TestSystemBinDirs_ResolveTheRealImageBinaries(t *testing.T) {
	for _, name := range []string{"apt-get", "apt-cache", "apt-mark", "dpkg-query", "tar", "unzip", "gunzip", "xz", "bash"} {
		if _, err := os.Stat(filepath.Join("/usr/bin", name)); err != nil {
			t.Logf("%s is not baked into this host; skipping it", name)
			continue
		}
		if got, err := resolveSystemBin(name); err != nil {
			t.Errorf("resolveSystemBin(%q) = %v, but the binary is on this host", name, err)
		} else if !filepath.IsAbs(got) {
			t.Errorf("resolveSystemBin(%q) = %q, want an absolute path", name, got)
		}
	}
}
