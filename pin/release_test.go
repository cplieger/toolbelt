package pin

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestReleaseValidationRejectsAnIncompleteProfile pins the profile half of
// construction. A profile is written once and reused by every deployment, so a
// mistake in it has to be reported at construction rather than after a download.
func TestReleaseValidationRejectsAnIncompleteProfile(t *testing.T) {
	tests := map[string]struct {
		mutate  func(*Release)
		wantErr string
	}{
		"no name":                {mutate: func(r *Release) { r.Name = "" }, wantErr: "Release.Name is required"},
		"name with a separator":  {mutate: func(r *Release) { r.Name = "a/b" }, wantErr: "single path component"},
		"dot-prefixed name":      {mutate: func(r *Release) { r.Name = ".hidden" }, wantErr: "must not start with a dot"},
		"parent name":            {mutate: func(r *Release) { r.Name = ".." }, wantErr: `must not be ".."`},
		"binary with separator":  {mutate: func(r *Release) { r.Binary = "bin/tool" }, wantErr: "Release.Binary"},
		"no arch tokens":         {mutate: func(r *Release) { r.ArchTokens = nil }, wantErr: "ArchTokens is required"},
		"no url template":        {mutate: func(r *Release) { r.URLTemplate = "" }, wantErr: "URLTemplate is required"},
		"url without version":    {mutate: func(r *Release) { r.URLTemplate = "https://x/a-{arch}.zip" }, wantErr: "{version}"},
		"url with no scheme":     {mutate: func(r *Release) { r.URLTemplate = "x/{version}.zip" }, wantErr: "http or https"},
		"url with no host":       {mutate: func(r *Release) { r.URLTemplate = "https:///{version}.zip" }, wantErr: "no host"},
		"no probe args":          {mutate: func(r *Release) { r.ProbeArgs = nil }, wantErr: "ProbeArgs is required"},
		"absolute artifact dir":  {mutate: func(r *Release) { r.ArtifactDir = "/usr/bin" }, wantErr: "must be relative"},
		"escaping artifact dir":  {mutate: func(r *Release) { r.ArtifactDir = "../../etc" }, wantErr: "escape"},
		"installer without path": {mutate: func(r *Release) { r.Installer = &ArchiveInstaller{} }, wantErr: "Installer.Path is required"},
		"escaping installer":     {mutate: func(r *Release) { r.Installer = &ArchiveInstaller{Path: "../x.sh"} }, wantErr: "escape"},
		"absolute installer":     {mutate: func(r *Release) { r.Installer = &ArchiveInstaller{Path: "/x.sh"} }, wantErr: "must be relative"},
		"complete profile":       {mutate: func(*Release) {}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := toolRelease()
			tc.mutate(&r)
			err := r.validate()
			switch {
			case tc.wantErr == "":
				if err != nil {
					t.Fatalf("validate: %v", err)
				}
			case err == nil:
				t.Fatalf("validate accepted a profile with %s", name)
			case !strings.Contains(err.Error(), tc.wantErr):
				t.Errorf("error = %v, want one mentioning %q", err, tc.wantErr)
			}
		})
	}
}

// TestPurgeValidationRejectsAnEscapingSweep pins the guard on the one parameter that
// only ever deletes. The deletes are already confined by an os.Root, so this refuses
// at construction to report the profile's mistake instead of sweeping nothing.
func TestPurgeValidationRejectsAnEscapingSweep(t *testing.T) {
	tests := map[string]struct {
		purge   Purge
		linkDir string
		wantErr string
	}{
		"absolute artifact":       {purge: Purge{Artifacts: []string{"/etc/passwd"}}, wantErr: "must be relative"},
		"escaping artifact":       {purge: Purge{Artifacts: []string{"../../etc/passwd"}}, wantErr: "escape"},
		"empty artifact":          {purge: Purge{Artifacts: []string{""}}, wantErr: "is required"},
		"name with a separator":   {purge: Purge{Names: []string{"a/b"}}, linkDir: "bin", wantErr: "single path component"},
		"parent name":             {purge: Purge{Names: []string{".."}}, linkDir: "bin", wantErr: `must not be ".."`},
		"names without a linkdir": {purge: Purge{Names: []string{"tool"}}, wantErr: "which is empty"},
		"undotted stage prefix":   {purge: Purge{StagePrefix: "stage-"}, wantErr: "must start with a dot"},
		"undotted marker":         {purge: Purge{Marker: "purged"}, wantErr: "must start with a dot"},
		"marker with a separator": {purge: Purge{Marker: ".a/b"}, wantErr: "single path component"},
		"a valid sweep":           {purge: Purge{Artifacts: []string{"bin/.x.prev"}, Names: []string{"tool"}, StagePrefix: ".s.", Marker: ".done"}, linkDir: "bin"},
		"an empty sweep is legal": {purge: Purge{}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := tc.purge.validate(tc.linkDir)
			switch {
			case tc.wantErr == "":
				if err != nil {
					t.Fatalf("validate: %v", err)
				}
			case err == nil:
				t.Fatalf("validate accepted %s", name)
			case !strings.Contains(err.Error(), tc.wantErr):
				t.Errorf("error = %v, want one mentioning %q", err, tc.wantErr)
			}
		})
	}
}

// TestPackageNameAndArtifactNameAreIndependent pins that the package's identity and
// the file it ships are separate facts. A package named "aws-cli" whose binary is
// called "aws" has to be expressible, and every path has to key on the right one:
// the versions root and the state record on the NAME, the probe target, the required
// set and the convenience link on the ARTIFACT.
func TestPackageNameAndArtifactNameAreIndependent(t *testing.T) {
	const (
		pkgName = "aws-cli"
		binName = "aws"
	)
	env := newFakeEnv(t)
	env.release.Name = pkgName
	env.release.Binary = binName
	env.produces = map[string]string{binName: pinnedVersion}
	env.probeAnswerFor = func(v string) string { return binName + "-" + v + "\n" }
	env.release.ParseVersion = func(out string) string {
		_, v, _ := strings.Cut(strings.TrimSpace(out), "-")
		return v
	}
	m := env.manager(func(c *Config) {
		c.Require = nil
		c.Optional = nil
	})

	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	// Keyed on the package name.
	versionsRoot := filepath.Join(env.root, pkgName+versionsSuffix)
	if got := m.PathEntry(); got != filepath.Join(versionsRoot, pinnedVersion) {
		t.Errorf("PathEntry() = %q, want a directory under %q", got, versionsRoot)
	}
	if !exists(filepath.Join(env.root, pkgName+stateSuffix)) {
		t.Errorf("the state record is not named after the package (%s)", pkgName+stateSuffix)
	}
	// Keyed on the artifact name.
	if got, want := m.Path(), filepath.Join(versionsRoot, pinnedVersion, binName); got != want {
		t.Errorf("Path() = %q, want the artifact %q", got, want)
	}
	if !slices.Contains(m.cfg.Require, binName) {
		t.Errorf("Require = %v, want it to carry the artifact name %q", m.cfg.Require, binName)
	}
	if slices.Contains(m.cfg.Require, pkgName) {
		t.Errorf("Require = %v, want it NOT to carry the package name %q", m.cfg.Require, pkgName)
	}
	if !exists(filepath.Join(env.root, testLinkDir, binName)) {
		t.Errorf("the convenience link is not named after the artifact (%s)", binName)
	}
	if exists(filepath.Join(env.root, testLinkDir, pkgName)) {
		t.Errorf("a convenience link was published under the package name %q", pkgName)
	}
}

// TestBinaryDefaultsToName pins the common case, where the two are the same fact, so
// a profile does not have to state it twice.
func TestBinaryDefaultsToName(t *testing.T) {
	tests := map[string]struct {
		name, binary, want string
	}{
		"binary unset":           {name: "tool", binary: "", want: "tool"},
		"binary set to the same": {name: "tool", binary: "tool", want: "tool"},
		"binary differs":         {name: "aws-cli", binary: "aws", want: "aws"},
	}
	for label, tc := range tests {
		t.Run(label, func(t *testing.T) {
			r := Release{Name: tc.name, Binary: tc.binary}
			if got := r.binary(); got != tc.want {
				t.Errorf("binary() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestPrimaryArtifactIsAlwaysRequired pins that the artifact the probe runs cannot be
// configured out of the required set, whatever a deployment passes.
func TestPrimaryArtifactIsAlwaysRequired(t *testing.T) {
	tests := map[string]struct {
		require []string
		want    []string
	}{
		"empty gets just the primary":      {require: nil, want: []string{"tool"}},
		"primary already present is kept":  {require: []string{"tool"}, want: []string{"tool"}},
		"primary is prepended when absent": {require: []string{"tool-helper"}, want: []string{"tool", "tool-helper"}},
		"order is otherwise preserved":     {require: []string{"tool-helper", "tool"}, want: []string{"tool-helper", "tool"}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := withPrimaryArtifact(tc.require, "tool"); !slices.Equal(got, tc.want) {
				t.Errorf("withPrimaryArtifact = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestNilSeamsFallBackToTheShippedDefaults pins the two nil-defaultable hooks: a
// profile that names neither gets the shipped zip unpacker and the shipped parser, so
// the common case needs no wiring at all.
func TestNilSeamsFallBackToTheShippedDefaults(t *testing.T) {
	env := newFakeEnv(t)
	env.release.Unpack = nil
	env.release.ParseVersion = nil
	m := env.manager()

	if m.unpack == nil || m.parseVersion == nil {
		t.Fatal("New left a nil seam on the manager")
	}
	if got := m.parseVersion("toolkit 1.2.3\n"); got != "1.2.3" {
		t.Errorf("default parser returned %q, want the last field of the first line", got)
	}
	// The real zip unpacker is what ran the install, so a successful Ensure over a
	// genuine zip is the assertion that the default is wired.
	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure with the default seams: %v", err)
	}
	if ready, why := m.Ready(); !ready {
		t.Errorf("Ready() = false (%s), want true", why)
	}
}

// TestValidateVersionConstrainsThePin pins the character set of the one value that is
// interpolated into BOTH a URL and a filesystem path.
func TestValidateVersionConstrainsThePin(t *testing.T) {
	tests := map[string]bool{
		"2.14.2":          true,
		"1.0.0-rc.1":      true,
		"1.0.0+build_7":   true,
		"v2":              true,
		"":                false,
		"../etc":          false,
		"2.14.2/x":        false,
		".hidden":         false,
		"a..b":            false,
		"2.14.2 ":         false,
		"2.14.2\n":        false,
		"2%2e14":          false,
		"2.14.2;rm -rf /": false,
	}
	for version, ok := range tests {
		t.Run(strings.ReplaceAll(version, "\n", "\\n"), func(t *testing.T) {
			err := validateVersion(version)
			if (err == nil) != ok {
				t.Errorf("validateVersion(%q) = %v, want ok=%v", version, err, ok)
			}
		})
	}
}

// FuzzValidateVersion pins the pin validator's security invariant on arbitrary input:
// anything it accepts must be safe to use as a single path component and must survive
// URL interpolation unchanged. This is the value that decides which directory under
// the installation root an install writes to.
func FuzzValidateVersion(f *testing.F) {
	for _, seed := range []string{
		"2.14.2", "", "..", "../..", "a/b", ".x", "1.0.0+b_7-rc.1",
		"\x00", "%2e%2e", strings.Repeat("9", 300), "２.１", "v1?x=1", "v1#f",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, version string) {
		if validateVersion(version) != nil {
			return
		}
		if version == "" {
			t.Fatal("validateVersion accepted an empty version")
		}
		if got := filepath.Clean(version); got != version {
			t.Fatalf("validateVersion accepted %q, which filepath.Clean rewrites to %q", version, got)
		}
		if base := filepath.Base(version); base != version {
			t.Fatalf("validateVersion accepted %q, whose base is %q, so it is not one path component", version, base)
		}
		joined := filepath.Join("/root", version)
		if !strings.HasPrefix(joined, "/root/") {
			t.Fatalf("validateVersion accepted %q, which escapes when joined: %q", version, joined)
		}
		if strings.ContainsAny(version, "/\\?#%&:@ \t\r\n") {
			t.Fatalf("validateVersion accepted %q, which carries a path or URL metacharacter", version)
		}
	})
}

// TestValidateRelPathAndComponent pins the two path guards every profile-supplied
// relative path and bare name goes through.
func TestValidateRelPathAndComponent(t *testing.T) {
	relTests := map[string]struct {
		value      string
		allowEmpty bool
		ok         bool
	}{
		"nested is fine":            {value: "a/b/c", allowEmpty: false, ok: true},
		"dot-prefixed is fine":      {value: ".local/bin", allowEmpty: false, ok: true},
		"empty allowed":             {value: "", allowEmpty: true, ok: true},
		"empty refused":             {value: "", allowEmpty: false},
		"absolute refused":          {value: "/a", allowEmpty: true},
		"parent refused":            {value: "..", allowEmpty: true},
		"parent prefix refused":     {value: "../a", allowEmpty: true},
		"interior parent collapses": {value: "a/../b", allowEmpty: true, ok: true},
		"deep escape refused":       {value: "a/../../b", allowEmpty: true},
	}
	for name, tc := range relTests {
		t.Run("relpath/"+name, func(t *testing.T) {
			err := validateRelPath("f", tc.value, tc.allowEmpty)
			if (err == nil) != tc.ok {
				t.Errorf("validateRelPath(%q, allowEmpty=%v) = %v, want ok=%v", tc.value, tc.allowEmpty, err, tc.ok)
			}
		})
	}

	componentTests := map[string]bool{
		"tool":    true,
		".hidden": true,
		"":        false,
		".":       false,
		"..":      false,
		"a/b":     false,
	}
	for value, ok := range componentTests {
		t.Run("component/"+value, func(t *testing.T) {
			if err := validateComponent("f", value); (err == nil) != ok {
				t.Errorf("validateComponent(%q) = %v, want ok=%v", value, err, ok)
			}
		})
	}
}

// TestValidateDigestRejectsAMangledPin pins the digest shape, so a truncated or
// re-cased pin fails at construction rather than after a large download.
func TestValidateDigestRejectsAMangledPin(t *testing.T) {
	tests := map[string]bool{
		sixtyFourHexChars:                  true,
		strings.Repeat("f", 64):            true,
		"":                                 false,
		sixtyFourHexChars[:63]:             false,
		sixtyFourHexChars + "a":            false,
		strings.Repeat("z", 64):            false,
		strings.ToUpper(sixtyFourHexChars): false,
		" " + sixtyFourHexChars[:63]:       false,
		sixtyFourHexChars[:62] + "\n\n":    false,
	}
	for digest, ok := range tests {
		t.Run(strings.ReplaceAll(digest, "\n", "\\n"), func(t *testing.T) {
			if err := validateDigest(digest); (err == nil) != ok {
				t.Errorf("validateDigest(%q) = %v, want ok=%v", digest, err, ok)
			}
		})
	}
}
