//go:build linux

package pin

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"path/filepath"
	"slices"
	"strings"

	"github.com/cplieger/go/pathinside"
)

// Config is one pinned release and its deployment: the profile of the package,
// then the pin, the root and local policy. The zero value is not usable; call
// [New].
//
//nolint:govet // fieldalignment: the field order is a reading order (the release, then the deployment), and a Config is allocated once per manager.
type Config struct {
	// Name is the package identity and its primary artifact's file name. It
	// fixes the versions root (<Root>/<Name>-versions), the state file
	// (<Root>/<Name>-state.json) and the completion sentinel's claim.
	Name string
	// URLTemplate is the archive URL, carrying the {version} and {arch}
	// placeholders. The extension of the resolved URL's last path segment
	// picks the format: .zip, .tar, .tar.gz, .tgz, .tar.bz2, .tbz2 or .tbz.
	URLTemplate string
	// ArchTokens maps a GOARCH to the token the publisher uses in its URLs
	// (e.g. "amd64" -> "x86_64-linux").
	ArchTokens map[string]string
	// ArtifactDir is where the primary artifact sits inside the archive. Empty
	// means its root.
	ArtifactDir string
	// ProbeArgs is the argv that makes the primary artifact print its version
	// (e.g. {"--version"}). Every start probes the artifact it activates, and
	// retention probes a predecessor before counting it as a fallback, so the
	// argv must be a pure query.
	ProbeArgs []string
	// Notice is logged once per install attempt when set: the licence
	// acknowledgement a proprietary upstream requires.
	Notice string

	// Version is the pin, validated against a path- and URL-safe character set
	// because it is interpolated into both a URL and a filesystem path.
	Version string
	// Digests maps a GOARCH to the lowercase hex SHA-256 of that
	// architecture's archive.
	Digests map[string]string
	// Root is the persistent installation root: the only tree this package
	// reads, writes or deletes. It must be absolute and hold no ".." component,
	// so the directory the custody check judges is the one every later open
	// reaches.
	Root string
	// LinkDir is a directory under Root holding a convenience symlink to the
	// active version's primary artifact, for an operator shelling into the
	// environment. Nothing in this package reads the links, and an entry
	// another owner put there is never touched. It is relative, with no ".."
	// component. Empty publishes none.
	LinkDir string
	// FormerLinkDirs are directories under Root where an earlier deployment
	// published this package's convenience links. Every activation that may
	// write the tree retracts the links of this manager's shape there, so none
	// dangles after a prune, and touches nothing else. Each is spelled like
	// LinkDir, must not name it, and is skipped if it resolves to it.
	FormerLinkDirs []string
	// Assertions are re-asserted against the active artifact on every start,
	// and the Required ones against the staged artifact before it is
	// published. At least one must be Required.
	Assertions []Assertion
	// Purge sweeps a previous installer's layout once. Nil skips it.
	Purge *Purge
	// Untrusted activates only versions THIS process installed from a
	// verified archive, never one already on the volume, whatever custody
	// concluded. It costs a digest-verified reinstall on every start.
	Untrusted bool
	// TrustedUIDs are users, beside root and this process's uid, whose write
	// access to the tree does not invalidate custody. Each entry claims that
	// user is already at least as privileged as this process. No group can be
	// declared: a group grant reaches every current and future member.
	TrustedUIDs []int
	// MaxAttempts bounds [Manager.EnsureWithRetry]. Zero or less uses 4.
	MaxAttempts int
	// Logger receives every log line. Nil uses [slog.Default] as it is when
	// [New] runs.
	Logger *slog.Logger

	// goarch selects the architecture in tests. Empty resolves runtime.GOARCH.
	goarch string
}

// Assertion is one bounded command run against the active artifact on every
// start, and against the staged artifact before publication when Required.
// Args is the full argv after the artifact path.
type Assertion struct {
	// Name identifies the assertion in logs. It is not passed to the artifact.
	Name string
	// Args is the full argv after the artifact path
	// (e.g. {"settings", "app.disableAutoupdates", "true"}).
	Args []string
	// Required makes a failure withhold readiness and, before publication,
	// refuse to publish. A failure of any other assertion only warns.
	Required bool
}

// Purge is the one-shot sweep of a layout a previous installer left on this
// volume. Each target is removed only when what is on disk has the shape that
// installer left there, so another owner's entry at the same path is refused
// rather than deleted.
type Purge struct {
	// Artifacts are paths relative to Root, removed only when they are regular
	// files.
	Artifacts []string
	// StagePrefix matches orphan staging trees directly under Root, removed
	// only when they are directories. Empty matches nothing.
	StagePrefix string
	// Marker is a dot-file under Root recording that the sweep completed, so it
	// runs once per volume. Empty reruns it every start.
	Marker string
	// Names are entries directly under LinkDir, removed only when they are
	// regular files.
	Names []string
}

// The internal/unpack formats pin supports.
const (
	formatZip    = "zip"
	formatTar    = "tar"
	formatTarGz  = "tar.gz"
	formatTarBz2 = "tar.bz2"
)

// archiveFormats maps a URL's extension to its format.
var archiveFormats = []struct{ ext, format string }{
	{".tar.gz", formatTarGz},
	{".tgz", formatTarGz},
	{".tar.bz2", formatTarBz2},
	{".tbz2", formatTarBz2},
	{".tbz", formatTarBz2},
	{".tar", formatTar},
	{".zip", formatZip},
}

// formatOf returns the archive format of the URL's last path segment.
func formatOf(rawURL string) (string, bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", false
	}
	last := strings.ToLower(u.Path[strings.LastIndex(u.Path, "/")+1:])
	for _, f := range archiveFormats {
		if strings.HasSuffix(last, f.ext) && len(last) > len(f.ext) {
			return f.format, true
		}
	}
	return "", false
}

// snapshot returns a Config that shares no memory with c, so nothing the
// caller does to its own value afterwards changes what the manager installs,
// probes, asserts or deletes. Every map, slice and pointer is copied,
// including each Assertion's argv.
func (c *Config) snapshot() Config {
	out := *c
	out.ArchTokens = maps.Clone(c.ArchTokens)
	out.ProbeArgs = slices.Clone(c.ProbeArgs)
	out.Digests = maps.Clone(c.Digests)
	out.TrustedUIDs = slices.Clone(c.TrustedUIDs)
	out.FormerLinkDirs = slices.Clone(c.FormerLinkDirs)
	if c.Assertions != nil {
		out.Assertions = make([]Assertion, 0, len(c.Assertions))
		for _, a := range c.Assertions {
			a.Args = slices.Clone(a.Args)
			out.Assertions = append(out.Assertions, a)
		}
	}
	if c.Purge != nil {
		p := *c.Purge
		p.Artifacts = slices.Clone(c.Purge.Artifacts)
		p.Names = slices.Clone(c.Purge.Names)
		out.Purge = &p
	}
	return out
}

// validate checks every field that does not depend on the resolved
// architecture; [New] checks the rest.
func (c *Config) validate() error {
	if err := c.validateRelease(); err != nil {
		return err
	}
	return c.validateDeployment()
}

// validateRelease checks the profile half: what is true of the package.
func (c *Config) validateRelease() error {
	if err := validateIdentifier("Name", c.Name); err != nil {
		return err
	}
	if err := validateURLTemplate("URLTemplate", c.URLTemplate); err != nil {
		return err
	}
	if len(c.ArchTokens) == 0 {
		return errors.New("pin: ArchTokens is required. Map a GOARCH to the publisher's token")
	}
	if err := validateRelPath("ArtifactDir", c.ArtifactDir); err != nil {
		return err
	}
	if len(c.ProbeArgs) == 0 {
		return errors.New("pin: ProbeArgs is required, because every start probes the artifact it activates")
	}
	return nil
}

// validateDeployment checks the deployment half: the pin, the root and policy.
func (c *Config) validateDeployment() error {
	if err := validateVersion(c.Version); err != nil {
		return fmt.Errorf("pin: Version %q: %w", c.Version, err)
	}
	if len(c.Digests) == 0 {
		return errors.New("pin: Digests is required. Map a GOARCH to that archive's lowercase hex SHA-256")
	}
	if err := validateRoot(c.Root); err != nil {
		return err
	}
	if err := validateLinkDir("LinkDir", c.LinkDir); err != nil {
		return err
	}
	if err := c.validateFormerLinkDirs(); err != nil {
		return err
	}
	if err := c.validateLists(); err != nil {
		return err
	}
	if c.Purge != nil {
		return c.Purge.validate(c.LinkDir)
	}
	return nil
}

// validateLinkDir refuses a link directory that is absolute, escapes Root or
// holds a ".." component. root.MkdirAll and the listing resolve ".." after a
// symlink, while every link, fsync and log path is Join-cleaned, so the two
// would reach different directories.
func validateLinkDir(field, value string) error {
	if err := validateRelPath(field, value); err != nil {
		return err
	}
	if slices.Contains(strings.Split(value, "/"), "..") {
		return fmt.Errorf("pin: %s %q must not contain a \"..\" component", field, value)
	}
	return nil
}

// validateFormerLinkDirs checks each former link directory. One naming LinkDir
// would retract the primary's link right after it is published.
func (c *Config) validateFormerLinkDirs() error {
	for i, dir := range c.FormerLinkDirs {
		field := fmt.Sprintf("FormerLinkDirs[%d]", i)
		if dir == "" {
			return fmt.Errorf("pin: %s is required", field)
		}
		if err := validateLinkDir(field, dir); err != nil {
			return err
		}
		if c.LinkDir != "" && filepath.Clean(dir) == filepath.Clean(c.LinkDir) {
			return fmt.Errorf("pin: %s %q names LinkDir, whose own link it would retract", field, dir)
		}
	}
	return nil
}

// validateLists checks the assertions and the uids.
func (c *Config) validateLists() error {
	if err := validateAssertions(c.Assertions); err != nil {
		return err
	}
	for _, uid := range c.TrustedUIDs {
		if uid < 0 {
			return fmt.Errorf("pin: TrustedUIDs entry %d is not a uid", uid)
		}
	}
	return nil
}

// validateRoot refuses a Root that is empty, relative or holds a ".." component.
// Join cleans ".." lexically while an open resolves it after a symlink, so the
// custody verdict and the operations it authorises could reach two directories.
func validateRoot(root string) error {
	switch {
	case root == "":
		return errors.New("pin: Root is required")
	case !filepath.IsAbs(root):
		return fmt.Errorf("pin: Root %q must be absolute, because its paths are handed to a subprocess", root)
	case slices.Contains(strings.Split(root, "/"), ".."):
		return fmt.Errorf("pin: Root %q must not contain a \"..\" component", root)
	}
	return nil
}

// validateAssertions requires at least one Required assertion, each named once
// and carrying an argv. With none required, a config that forgot its vendor's
// self-update switch looks the same as one whose vendor has none, and guessing
// wrong ships an ungated install; a vendor with no gate declares its cheapest
// positive check on purpose.
func validateAssertions(assertions []Assertion) error {
	seen := make(map[string]bool, len(assertions))
	required := false
	for i, a := range assertions {
		if a.Name == "" {
			return fmt.Errorf("pin: Assertions[%d] has no Name", i)
		}
		if len(a.Args) == 0 {
			return fmt.Errorf("pin: Assertions[%d] named %s has no Args", i, a.Name)
		}
		if seen[a.Name] {
			return fmt.Errorf("pin: Assertions has two entries named %q", a.Name)
		}
		seen[a.Name] = true
		required = required || a.Required
	}
	if !required {
		return errors.New("pin: Assertions has no Required entry. Declare at least one check that must hold after every install, " +
			"such as the self-update switch or the cheapest bounded command that must succeed against a working install")
	}
	return nil
}

// validateURLTemplate refuses a template that is not an absolute http(s) URL
// or does not carry {version}: without it every release would share one URL,
// which the digest check would report as a mismatch of the pin. Plain http is
// permitted, since the digest is the integrity guarantee.
func validateURLTemplate(field, tmpl string) error {
	if tmpl == "" {
		return fmt.Errorf("pin: %s is required", field)
	}
	if !strings.Contains(tmpl, versionPlaceholder) {
		return fmt.Errorf("pin: %s %q must carry the %s placeholder", field, tmpl, versionPlaceholder)
	}
	u, err := url.Parse(strings.ReplaceAll(tmpl, versionPlaceholder, "0"))
	switch {
	case err != nil:
		return fmt.Errorf("pin: %s %q is not a URL: %w", field, tmpl, err)
	case u.Scheme != "http" && u.Scheme != "https":
		return fmt.Errorf("pin: %s %q must be an http or https URL", field, tmpl)
	case u.Host == "":
		return fmt.Errorf("pin: %s %q has no host", field, tmpl)
	}
	return nil
}

// validateIdentifier refuses anything but a single, non-hidden path component:
// Name is joined into paths under Root and is the artifact's file name, and a
// dot-prefixed name could collide with the sentinel or a staging tree.
func validateIdentifier(field, value string) error {
	if err := validateComponent(field, value); err != nil {
		return err
	}
	if strings.HasPrefix(value, ".") {
		return fmt.Errorf("pin: %s %q must not start with a dot, because dot-prefixed entries are this package's own sentinels and staging trees", field, value)
	}
	return nil
}

// validateComponent refuses anything but a single path component.
func validateComponent(field, value string) error {
	switch {
	case value == "":
		return fmt.Errorf("pin: %s is required", field)
	case value == "." || value == "..":
		return fmt.Errorf("pin: %s must not be %q", field, value)
	case strings.ContainsRune(value, '/'):
		return fmt.Errorf("pin: %s %q must be a single path component", field, value)
	}
	return nil
}

// validateRelPath refuses an absolute or escaping relative path; empty is
// allowed. pathinside.RelEscapes cleans the name first, so a traversal buried
// mid-string is caught, without refusing a name like "..extras/bin".
func validateRelPath(field, value string) error {
	switch {
	case value == "":
		return nil
	case filepath.IsAbs(value):
		return fmt.Errorf("pin: %s %q must be relative", field, value)
	case pathinside.RelEscapes(value):
		return fmt.Errorf("pin: %s %q must not escape its directory", field, value)
	}
	return nil
}
