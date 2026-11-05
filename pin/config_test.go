//go:build linux

package pin

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestConfigValidationRefusesEachBrokenField pins New's validation: one row per
// rule, each refused at construction with an error naming the field, rather
// than after a download.
func TestConfigValidationRefusesEachBrokenField(t *testing.T) {
	tests := map[string]struct {
		mutate  func(*Config)
		wantErr string
	}{
		"no name":                  {mutate: func(c *Config) { c.Name = "" }, wantErr: "Name is required"},
		"name with a separator":    {mutate: func(c *Config) { c.Name = "a/b" }, wantErr: "single path component"},
		"dot-prefixed name":        {mutate: func(c *Config) { c.Name = ".hidden" }, wantErr: "must not start with a dot"},
		"parent name":              {mutate: func(c *Config) { c.Name = ".." }, wantErr: `must not be ".."`},
		"no arch tokens":           {mutate: func(c *Config) { c.ArchTokens = nil }, wantErr: "ArchTokens is required"},
		"no url template":          {mutate: func(c *Config) { c.URLTemplate = "" }, wantErr: "URLTemplate is required"},
		"url without version":      {mutate: func(c *Config) { c.URLTemplate = "https://x/a-{arch}.zip" }, wantErr: "{version}"},
		"url with no scheme":       {mutate: func(c *Config) { c.URLTemplate = "x/{version}.zip" }, wantErr: "http or https"},
		"url with no host":         {mutate: func(c *Config) { c.URLTemplate = "https:///{version}.zip" }, wantErr: "no host"},
		"url of an unknown format": {mutate: func(c *Config) { c.URLTemplate = "https://x/{version}/tool-{arch}" }, wantErr: "must end in .zip"},
		"url of a raw binary":      {mutate: func(c *Config) { c.URLTemplate = "https://x/{version}/tool-{arch}.exe" }, wantErr: "must end in .zip"},
		"url of an xz tarball":     {mutate: func(c *Config) { c.URLTemplate = "https://x/{version}/tool-{arch}.tar.xz" }, wantErr: "must end in .zip"},
		"url of a bare extension":  {mutate: func(c *Config) { c.URLTemplate = "https://x/{version}/.zip" }, wantErr: "must end in .zip"},
		"token hiding the extension": {mutate: func(c *Config) {
			c.URLTemplate = "https://x/{version}/tool-{arch}.zip"
			c.ArchTokens["amd64"] = "linux#"
		}, wantErr: "must end in .zip"},
		"no probe args":           {mutate: func(c *Config) { c.ProbeArgs = nil }, wantErr: "ProbeArgs is required"},
		"absolute artifact dir":   {mutate: func(c *Config) { c.ArtifactDir = "/usr/bin" }, wantErr: "must be relative"},
		"escaping artifact dir":   {mutate: func(c *Config) { c.ArtifactDir = "../../etc" }, wantErr: "escape"},
		"missing version":         {mutate: func(c *Config) { c.Version = "" }, wantErr: "Version"},
		"no digests":              {mutate: func(c *Config) { c.Digests = nil }, wantErr: "Digests is required"},
		"missing root":            {mutate: func(c *Config) { c.Root = "" }, wantErr: "Root is required"},
		"relative root":           {mutate: func(c *Config) { c.Root = "tools" }, wantErr: "must be absolute"},
		"dot-dot ending root":     {mutate: func(c *Config) { c.Root += "/x/.." }, wantErr: "must not contain"},
		"dot-dot inside root":     {mutate: func(c *Config) { c.Root = "/srv/link/../tools" }, wantErr: "must not contain"},
		"dot-dot name in root":    {mutate: func(c *Config) { c.Root = "/srv/..tools" }},
		"absolute link dir":       {mutate: func(c *Config) { c.LinkDir = "/usr/local/bin" }, wantErr: "must be relative"},
		"escaping link dir":       {mutate: func(c *Config) { c.LinkDir = "../bin" }, wantErr: "escape"},
		"dot-dot in link dir":     {mutate: func(c *Config) { c.LinkDir = "x/../bin" }, wantErr: "must not contain"},
		"dot-dot ending link dir": {mutate: func(c *Config) { c.LinkDir = "bin/x/.." }, wantErr: "must not contain"},
		"no required assertion":   {mutate: func(c *Config) { c.Assertions = []Assertion{{Name: "a", Args: []string{"x"}}} }, wantErr: "no Required entry"},
		"no assertion at all":     {mutate: func(c *Config) { c.Assertions = nil }, wantErr: "no Required entry"},
		"assertion with no name":  {mutate: func(c *Config) { c.Assertions[0].Name = "" }, wantErr: "has no Name"},
		"assertion with no args":  {mutate: func(c *Config) { c.Assertions[0].Args = nil }, wantErr: "has no Args"},
		"duplicate assertion": {mutate: func(c *Config) {
			c.Assertions = append(c.Assertions, Assertion{Name: c.Assertions[0].Name, Args: []string{"x"}})
		}, wantErr: "two entries named"},
		"negative trusted uid": {mutate: func(c *Config) { c.TrustedUIDs = []int{-1} }, wantErr: "is not a uid"},
		"complete config":      {mutate: func(*Config) {}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			c := newFakeEnv(t).config()
			tc.mutate(c)
			_, err := New(c)
			switch {
			case tc.wantErr == "":
				if err != nil {
					t.Fatalf("New: %v", err)
				}
			case err == nil:
				t.Fatalf("New accepted a config with %s", name)
			case !strings.HasPrefix(err.Error(), "pin: ") || !strings.Contains(err.Error(), tc.wantErr):
				t.Errorf("error = %v, want one starting pin: and mentioning %q", err, tc.wantErr)
			}
		})
	}
}

// TestFormatOfReadsTheURLExtension pins R12: the archive format comes from the
// last path segment of the URL New resolves, never its query or fragment.
func TestFormatOfReadsTheURLExtension(t *testing.T) {
	tests := map[string]string{
		"https://x/1.0/a-amd64.zip":         "zip",
		"https://x/1.0/a-amd64.ZIP":         "zip",
		"https://x/1.0/a-amd64.tar":         "tar",
		"https://x/1.0/a-amd64.tar.gz":      "tar.gz",
		"https://x/1.0/a-amd64.tgz":         "tar.gz",
		"https://x/1.0/a-amd64.tar.bz2":     "tar.bz2",
		"https://x/1.0/a-amd64.tbz2":        "tar.bz2",
		"https://x/1.0/a-amd64.tbz":         "tar.bz2",
		"https://x/1.0/a-amd64.zip?sig=1":   "zip",
		"https://x/1.0/a-amd64.tar.zst":     "",
		"https://x/1.0/a-amd64.gz":          "",
		"https://x/1.0.zip/a-amd64":         "",
		"https://x/1.0/a-amd64.tar.gz#frag": "tar.gz",
		"https://x/1.0/a-amd64#.zip":        "",
		"https://x/1.0/a.tar.gz?v=.zip":     "tar.gz",
	}
	for rawURL, want := range tests {
		t.Run(rawURL, func(t *testing.T) {
			got, ok := formatOf(rawURL)
			if got != want || ok != (want != "") {
				t.Errorf("formatOf(%q) = %q, %v, want %q", rawURL, got, ok, want)
			}
		})
	}
}

// TestNewJudgesTheFormatOnTheResolvedURL pins that the format New records is the
// one of the URL it fetches: an arch token that moves the last path segment
// moves the format with it.
func TestNewJudgesTheFormatOnTheResolvedURL(t *testing.T) {
	m := newFakeEnv(t).manager(func(c *Config) {
		c.URLTemplate = "https://x.example/dl/{version}/{arch}.zip"
		c.ArchTokens["amd64"] = "kiro.tar.gz?v="
	})
	if want := "https://x.example/dl/2.14.2/kiro.tar.gz?v=.zip"; m.archiveURL != want {
		t.Errorf("archiveURL = %q, want %q", m.archiveURL, want)
	}
	if m.format != formatTarGz {
		t.Errorf("format = %q, want %q: the fetched path ends in .tar.gz", m.format, formatTarGz)
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
	relTests := map[string]bool{
		"a/b/c":      true,
		".local/bin": true,
		"":           true,
		"/a":         false,
		"..":         false,
		"../a":       false,
		"a/../b":     true,
		"a/../../b":  false,
	}
	for value, ok := range relTests {
		t.Run("relpath/"+value, func(t *testing.T) {
			if err := validateRelPath("f", value); (err == nil) != ok {
				t.Errorf("validateRelPath(%q) = %v, want ok=%v", value, err, ok)
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
