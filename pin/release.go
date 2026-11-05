//go:build linux

package pin

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/cplieger/go/pathinside"
)

// Release is everything true of the PACKAGE, independent of any deployment: the
// profile a consumer builds once and reuses across every environment. It is
// data, not policy — durability, version selection, retry, retention and the
// readiness verdict belong to the library and are not configurable.
type Release struct {
	// Unpack extracts the verified archive from an open reader, into an
	// [os.Root] on the extraction directory. A nil Unpack uses [UnpackZip].
	// Neither parameter is a path, deliberately — see [Unpacker].
	Unpack Unpacker
	// Installer describes an installer script shipped INSIDE the archive. A nil
	// Installer means the archive already holds the artifacts.
	Installer *ArchiveInstaller
	// ParseVersion extracts a version from the probe's output. A nil
	// ParseVersion uses [LastFieldOfFirstLine].
	ParseVersion func(out string) string
	// ArchTokens maps a GOARCH to the token the publisher uses in its URLs
	// (e.g. "amd64" -> "x86_64-linux"). An architecture absent from the map is
	// [ErrUnsupportedArch].
	ArchTokens map[string]string
	// ProbeArgs is the argv that makes the primary artifact print its version
	// (e.g. {"--version"}). Required: every start probes the artifact it is
	// about to activate, so a release with no probe cannot be verified.
	//
	// It must be safe to run against a version this deployment will NOT activate, and
	// against one it is about to delete. Retention asks the same question of a retained
	// candidate before counting it as a usable fallback, so the argv has to be a pure
	// query: no migration, no cache warm, no write to shared state. A bare version flag
	// is; a subcommand that touches the package's own configuration is not.
	ProbeArgs []string
	// Name is the package identity. It fixes the versions root
	// (<Root>/<Name>-versions), the state file (<Root>/<Name>-state.json) and
	// the sentinel's claim. It is NOT the artifact name — see Binary.
	Name string
	// Binary is the primary artifact: the file the version probe runs, the file
	// its convenience link points at, and an always-present member of the
	// required set. Empty defaults to Name, which covers the common case; a
	// package named "aws-cli" that ships a binary called "aws" sets both.
	Binary string
	// URLTemplate is the archive URL, carrying the {version} and {arch}
	// placeholders (e.g. "https://example.invalid/{version}/pkg-{arch}.zip").
	// {arch} is substituted with the ArchTokens entry for the resolved GOARCH.
	URLTemplate string
	// ArtifactDir is where the artifacts land, relative to the installer's
	// private home when Installer is set and to the extraction directory
	// otherwise. Empty means the root of whichever of the two applies.
	ArtifactDir string
	// Notice is logged once per install attempt when non-empty: the licence
	// acknowledgement a proprietary upstream requires. Profile-owned, because
	// the library must not carry one vendor's licence text.
	Notice string
	// Mandatory are the assertions a deployment cannot configure away. Each one
	// is forced Required and merged over any caller assertion with the same
	// Name, so an integrity gate the package depends on (a self-update switch,
	// a telemetry kill switch) cannot be lost by a deployment's omission.
	//
	// At least one is required: [New] refuses a profile that declares none,
	// because "this package needs no post-install guarantee" and "the profile
	// author forgot" are indistinguishable from the outside.
	//
	// It closes the field list rather than sitting beside ProbeArgs only because
	// a trailing slice costs the garbage collector less to scan.
	Mandatory []Assertion
}

// ArchiveInstaller describes an installer script shipped inside the archive.
// Its exit code is deliberately not fatal: an upstream installer commonly
// touches shell profiles and other surfaces that legitimately fail in a minimal
// container, so what decides is whether the artifacts it produced pass the
// staged gates.
type ArchiveInstaller struct {
	// Path is the script's path relative to the extraction directory
	// (e.g. "pkg/install.sh").
	Path string
	// HomeEnv is the environment variable pointed at the private staging home.
	// Empty means HOME.
	HomeEnv string
	// Args is the argv passed to the script (e.g. {"--no-confirm"}).
	Args []string
	// Timeout bounds the run. Zero uses two minutes.
	Timeout time.Duration
}

// Assertion is one bounded command run against the installed artifact on every
// start, and against the STAGED artifact before publication when Required. Args
// is the full argv after the artifact path, so the library needs no knowledge
// of the package's configuration grammar.
//
// A Required failure withholds readiness (and, before publication, refuses to
// publish). Anything else only warns.
type Assertion struct {
	// Name identifies the assertion in logs and is the key
	// [Release.Mandatory] overrides on. It is not passed to the artifact.
	Name string
	// Args is the full argv after the artifact path
	// (e.g. {"settings", "app.disableAutoupdates", "true"}).
	Args []string
	// Required marks an assertion whose failure is integrity-relevant.
	Required bool
}

// Purge is the one-shot sweep of a layout a PREVIOUS installer left on this
// volume. It is injected rather than built in because the residue is a fact
// about one deployment's history, not about the package: two consumers of the
// same upstream release can have arrived from different installers.
//
// Each target is removed only when what is on disk has the SHAPE the old
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
	// runs once per volume rather than on every start. Empty reruns it every
	// start.
	Marker string
	// Names are entries directly under LinkDir, removed only when they are
	// regular files. A symlink at one of these paths belongs to another owner.
	Names []string
}

// Config is one deployment of one [Release]: the pin, the digests, the root and
// the local policy. The zero value is not usable — call [New].
//
// profile, then the pin, then the root, then policy, then the two custody escapes last
// because they are the fields a reader should meet only after the rest. Packing it for the
// 24 bytes fieldalignment can reclaim scatters that order, and a Config is allocated once
// per manager.
//
//nolint:govet // fieldalignment: the field order IS this struct's documentation — the
type Config struct {
	// Digests maps a GOARCH to the lowercase hex SHA-256 of that
	// architecture's archive. The resolved architecture must have an entry.
	Digests map[string]string
	// Purge sweeps a previous installer's layout once. Nil skips it.
	Purge *Purge
	// Assert are the assertions re-asserted against the active artifact on
	// every start. [Release.Mandatory] is merged in, so a required assertion
	// cannot be dropped here.
	Assert []Assertion
	// Require names artifacts a version directory MUST hold to count as
	// complete. The release's primary artifact is always included.
	Require []string
	// Release is the package profile.
	Release Release
	// Version is the pin, validated against a path- and URL-safe character set
	// because it is interpolated into both a URL and a filesystem path.
	Version string
	// Root is the persistent installation root: the only tree this package
	// reads, writes or deletes. It must be absolute and hold no ".." component,
	// so the directory the custody check judges is the one every later open
	// reaches.
	Root string
	// GOARCH selects the architecture. Empty resolves it from runtime.GOARCH.
	GOARCH string
	// URLTemplate overrides [Release.URLTemplate], for a mirror or a test
	// server. Empty uses the release's own template.
	URLTemplate string
	// LinkDir is a directory under Root holding a NON-AUTHORITATIVE
	// convenience symlink at each artifact the active version holds (the
	// primary, Require, and every Optional present), for an operator shelling
	// into the environment. A link this manager published is retracted once
	// the active version lacks its artifact or the artifact is no longer
	// declared; an entry another owner put in LinkDir is never touched. Empty
	// publishes none. Nothing in this package ever reads the links. It is
	// relative, with no ".." component.
	LinkDir string
	// Optional names artifacts installed when the archive provides them, and
	// only warned about when it does not. It closes the pointer-bearing fields
	// rather than sitting beside Require only because a trailing slice costs the
	// garbage collector less to scan.
	Optional []string
	// Retain is how many predecessors to keep besides the active version. Zero
	// uses 1, which is what makes a bad activation recoverable without a
	// rollback journal.
	//
	// Retention counts only what could actually SERVE, and that is deliberately
	// NOT the same question as what may be deleted. A directory this process may
	// not activate never spends a slot the real fallback needs — keeping a corrupt
	// newer tree while pruning the good older one is the failure that rule exists
	// to prevent, and it would bite exactly when the pin has already failed.
	//
	// What may be deleted is a second question with its own answer. A directory in
	// a state selection refuses is left as found, because the library did not put
	// it there and deleting evidence is not its call, and so is one that may belong
	// to another principal when custody REFUSED the tree. A directory that merely
	// predates this process under [Config.Untrusted] with a clean verdict is
	// neither: nothing will ever activate it, so it is collected. Retain therefore
	// bounds the tree under a clean verdict whether or not Untrusted is set.
	Retain int
	// RetryBackoff is the first [Manager.EnsureWithRetry] backoff; it doubles
	// per attempt up to a ten minute cap. Zero uses 30s.
	RetryBackoff time.Duration
	// MaxAttempts bounds [Manager.EnsureWithRetry]. Zero uses 4. The retries
	// are bounded deliberately: an endless loop re-downloading a large archive
	// is worse than a visible failure an operator can repair.
	MaxAttempts int
	// TrustedUIDs and TrustedGIDs name identities whose write access to the installation
	// tree does NOT invalidate custody, beyond root and this process's own uid, which are
	// always trusted.
	//
	// This is the knob for the situation the library can see but cannot judge. It reads
	// the mode, the ownership and the access-control list of every directory on the way
	// to Root and can tell you that uid 3000 may write there; it can never tell that uid
	// 3000 is the administrator who already holds root through sudo, so writing those
	// files gains that account nothing. You know that, so you say it, and the library
	// goes back to enforcing the rule everywhere else.
	//
	// Each entry is a claim you are making: this identity is already at least as
	// privileged as the process running the install. An identity that is not — the
	// unprivileged account an application runs as, say — genuinely can escalate through a
	// binary this library installs and a consumer executes, and listing it there defeats
	// the point. Listing "everyone" is not possible, because a grant to everyone names no
	// identity to trust; see InstallWithoutCustody.
	TrustedUIDs []int
	// TrustedGIDs is the group half of TrustedUIDs. A group grant is a grant to every
	// current and future member, so it is the weaker claim of the two.
	TrustedGIDs []int
	// InstallWithoutCustody proceeds even though custody of Root could not be established:
	// the refusal becomes a warning and the install runs anyway.
	//
	// It is the blunt instrument, for a volume whose permissions cannot be described by
	// naming identities — one whose filesystem does not make the mode its access decision
	// at all (a cifs mount with noperm, a FUSE filesystem without default_permissions), or
	// one you simply accept as shared. Prefer TrustedUIDs and TrustedGIDs, which keep the
	// check working; reach for this when there is nothing precise to say.
	//
	// It also re-authorises what the library otherwise declines to do in a tree it does
	// not control: the one-shot Purge, the sweep of partial directories and orphan staging
	// trees, the retention prune, the convenience symlinks, and the state record. That
	// follows from what it means — the library is installing there, so refusing to tidy up
	// after itself would leave Purge silently dead and let partial directories accumulate
	// without bound.
	//
	// Setting it implies Untrusted's restriction on activation: in a tree this process does
	// not control, a completion sentinel is forgeable, so only a version THIS process
	// installed from a verified archive is activated. That carries Untrusted's effect on
	// [Config.Retain] with it — see there.
	InstallWithoutCustody bool
	// Untrusted activates only versions THIS process installed from a verified archive,
	// never one already on the volume, regardless of what the custody check concluded.
	//
	// The check has blind spots a caller may know about — a volume mounted into two
	// containers whose processes both map to uid 0 passes every question it asks — and this
	// is how to say so without also declaring the tree unmanageable. It costs a
	// digest-verified reinstall on every start, which is the price of not believing a
	// sentinel.
	//
	// It no longer stops [Config.Retain] bounding the tree. A directory an earlier
	// process installed is one no process will activate — `installed` is per-process and
	// never persisted — so under this flag with a CLEAN custody verdict such a directory
	// is neither a fallback to keep nor evidence to preserve, and pruning collects it.
	// The one shape still left alone is a complete directory in a tree custody REFUSED
	// and the caller waived: there the tree provably has a writer this library cannot
	// account for, so the directory may be another principal's install.
	Untrusted bool
}

// binary returns the primary artifact's file name.
func (r *Release) binary() string {
	return cmp.Or(r.Binary, r.Name)
}

// snapshot returns a Config that shares no memory with c, so nothing the caller
// does to its own value afterwards can change what the manager installs, asserts,
// probes or deletes.
//
// A plain `*cfg` is not that. Every reference-bearing field survives it — two maps,
// six slices, two POINTERS, and one slice inside each [Assertion] — and four of them
// are read long after [New] returns and validation has passed. Measured on the
// shallow copy: mutating the caller's own value after construction rewrote the argv
// of a [Release.Mandatory] assertion, which is the one thing that field exists to
// make impossible ("the set a deployment cannot weaken, reword or drop"); rewrote
// [Release.ProbeArgs], the argv every start runs against the artifact it is about to
// activate; and rewrote both [Purge] slices, which is the DELETE list, after
// [Purge.validate] had passed on the old one, so `../escaped` reached the sweep.
//
// It copies the fields nothing reads after construction as well, and that is
// deliberate rather than thorough-for-its-own-sake: a copy whose boundary is "the
// fields that happen to be read today" is a detail the next reader will miss, and
// the next read added is then a defect nobody edited into existence.
func (c *Config) snapshot() Config {
	out := *c
	out.Digests = maps.Clone(c.Digests)
	out.Assert = cloneAssertions(c.Assert)
	out.Require = slices.Clone(c.Require)
	out.Optional = slices.Clone(c.Optional)
	out.TrustedUIDs = slices.Clone(c.TrustedUIDs)
	out.TrustedGIDs = slices.Clone(c.TrustedGIDs)
	out.Release.ArchTokens = maps.Clone(c.Release.ArchTokens)
	out.Release.ProbeArgs = slices.Clone(c.Release.ProbeArgs)
	out.Release.Mandatory = cloneAssertions(c.Release.Mandatory)
	if c.Release.Installer != nil {
		inst := *c.Release.Installer
		inst.Args = slices.Clone(c.Release.Installer.Args)
		out.Release.Installer = &inst
	}
	if c.Purge != nil {
		p := *c.Purge
		p.Artifacts = slices.Clone(c.Purge.Artifacts)
		p.Names = slices.Clone(c.Purge.Names)
		out.Purge = &p
	}
	return out
}

// cloneAssertions copies a set of assertions and each one's argv. Cloning the outer
// slice alone would leave every [Assertion.Args] pointing at the caller's own
// backing array, which is the argv this package hands to a subprocess.
func cloneAssertions(in []Assertion) []Assertion {
	if in == nil {
		return nil
	}
	out := make([]Assertion, 0, len(in))
	for _, a := range in {
		a.Args = slices.Clone(a.Args)
		out = append(out, a)
	}
	return out
}

// validate checks everything about the profile that cannot depend on a
// deployment.
func (r *Release) validate() error {
	if err := validateIdentifier("Release.Name", r.Name); err != nil {
		return err
	}
	if err := validateIdentifier("Release.Binary", r.binary()); err != nil {
		return err
	}
	if len(r.ArchTokens) == 0 {
		return errors.New("pinstall: Release.ArchTokens is required. Map a GOARCH to the publisher's token")
	}
	if err := validateURLTemplate("Release.URLTemplate", r.URLTemplate); err != nil {
		return err
	}
	if len(r.ProbeArgs) == 0 {
		return errors.New("pinstall: Release.ProbeArgs is required, because every start probes the artifact it activates")
	}
	if err := validateRelPath("Release.ArtifactDir", r.ArtifactDir, true); err != nil {
		return err
	}
	if r.Installer != nil {
		if err := validateRelPath("Release.Installer.Path", r.Installer.Path, false); err != nil {
			return err
		}
	}
	return validateMandatory(r.Mandatory)
}

// validateMandatory enforces the one guarantee a profile cannot omit: at least
// one mandatory assertion, each named and each carrying an argv.
//
// Refusing an empty set is deliberate. A mandatory assertion is how a package's
// own integrity gate survives being turned into profile data: with an empty set,
// a profile that simply forgot its self-update switch is indistinguishable from
// one whose package genuinely has none, and the failure mode of guessing wrong
// is a silently ungated install. A package that truly needs no gate declares its
// cheapest positive check instead (any bounded command that must succeed against
// a working install), which is a claim the profile author has to make on
// purpose.
func validateMandatory(mandatory []Assertion) error {
	if len(mandatory) == 0 {
		return errors.New("pinstall: Release.Mandatory is empty. Declare at least one assertion that must hold after every install, " +
			"such as the self-update switch or the cheapest bounded command that must succeed against a working install, " +
			"so a deployment cannot lose the guarantee by omitting it")
	}
	seen := make(map[string]bool, len(mandatory))
	for i, a := range mandatory {
		if a.Name == "" {
			return fmt.Errorf("pinstall: Release.Mandatory[%d] has no Name, which is the log identity and the override key", i)
		}
		if len(a.Args) == 0 {
			return fmt.Errorf("pinstall: Release.Mandatory[%d] named %s has no Args", i, a.Name)
		}
		if seen[a.Name] {
			return fmt.Errorf("pinstall: Release.Mandatory has two assertions named %q", a.Name)
		}
		seen[a.Name] = true
	}
	return nil
}

// mergeAssertions returns the caller's assertions with every mandatory one
// forced Required and substituted in place, and any mandatory assertion the
// caller did not mention appended. A caller cannot weaken, reword or drop a
// mandatory assertion; it can only choose where in the sequence it runs.
func mergeAssertions(caller, mandatory []Assertion) []Assertion {
	forced := make(map[string]Assertion, len(mandatory))
	for _, a := range mandatory {
		a.Required = true
		forced[a.Name] = a
	}
	out := make([]Assertion, 0, len(caller)+len(mandatory))
	used := make(map[string]bool, len(mandatory))
	for _, a := range caller {
		m, isMandatory := forced[a.Name]
		switch {
		case !isMandatory:
			out = append(out, a)
		case !used[a.Name]:
			used[a.Name] = true
			out = append(out, m)
		}
	}
	for _, a := range mandatory {
		if !used[a.Name] {
			used[a.Name] = true
			out = append(out, forced[a.Name])
		}
	}
	return out
}

// withPrimaryArtifact returns require with the primary artifact guaranteed
// present: the probe runs it and consumers execute it, so a caller cannot
// configure it out of the required set.
func withPrimaryArtifact(require []string, primary string) []string {
	if slices.Contains(require, primary) {
		return require
	}
	return append([]string{primary}, require...)
}

// validateURLTemplate rejects a template that is not an absolute http(s) URL or
// that does not carry the {version} placeholder. A template without {version}
// would silently pin every release to one URL, which the digest check would then
// report as a mismatch — pointing the operator at the pin instead of the
// template. Plain http is permitted: the digest is the integrity guarantee, so a
// local mirror is verifiable, it merely reveals what is being downloaded.
func validateURLTemplate(field, tmpl string) error {
	if tmpl == "" {
		return fmt.Errorf("pinstall: %s is required", field)
	}
	if !strings.Contains(tmpl, versionPlaceholder) {
		return fmt.Errorf("pinstall: %s %q must carry the %s placeholder", field, tmpl, versionPlaceholder)
	}
	u, err := url.Parse(strings.ReplaceAll(tmpl, versionPlaceholder, "0"))
	switch {
	case err != nil:
		return fmt.Errorf("pinstall: %s %q is not a URL: %w", field, tmpl, err)
	case u.Scheme != "http" && u.Scheme != "https":
		return fmt.Errorf("pinstall: %s %q must be an http or https URL", field, tmpl)
	case u.Host == "":
		return fmt.Errorf("pinstall: %s %q has no host", field, tmpl)
	}
	return nil
}

// validateIdentifier rejects anything that is not a single, benign, non-hidden
// path component. Name and Binary are joined into paths under Root and used as
// bare file names, so a separator or a dot component in either would escape the
// installation root, and a dot-prefixed artifact name could collide with the
// sentinel or with a staging tree.
func validateIdentifier(field, value string) error {
	if err := validateComponent(field, value); err != nil {
		return err
	}
	if strings.HasPrefix(value, ".") {
		return fmt.Errorf("pinstall: %s %q must not start with a dot, because dot-prefixed entries are this package's own sentinels and staging trees", field, value)
	}
	return nil
}

// validateComponent rejects anything that is not a single path component.
func validateComponent(field, value string) error {
	switch {
	case value == "":
		return fmt.Errorf("pinstall: %s is required", field)
	case value == "." || value == "..":
		return fmt.Errorf("pinstall: %s must not be %q", field, value)
	case strings.ContainsRune(value, filepath.Separator), strings.ContainsRune(value, '/'):
		return fmt.Errorf("pinstall: %s %q must be a single path component", field, value)
	}
	return nil
}

// validateRelPath rejects an absolute or traversing relative path. Every one of
// these is joined onto a directory this package owns, so refusing at
// construction beats discovering the escape after a download.
//
// The escape test is pathinside.RelEscapes, a separator-precise rule: it cleans
// the name first, so a traversal buried mid-string is caught, and it refuses
// "../a" without refusing a legitimate "..extras/bin". Absoluteness and the
// empty-value decision stay here — pathinside deliberately judges neither, and
// whether an empty path means "the root of whichever directory applies" or "a
// missing required field" is this package's business, not the library's.
func validateRelPath(field, value string, allowEmpty bool) error {
	if value == "" {
		if allowEmpty {
			return nil
		}
		return fmt.Errorf("pinstall: %s is required", field)
	}
	if filepath.IsAbs(value) || strings.HasPrefix(value, "/") {
		return fmt.Errorf("pinstall: %s %q must be relative", field, value)
	}
	if pathinside.RelEscapes(value) {
		return fmt.Errorf("pinstall: %s %q must not escape its directory", field, value)
	}
	return nil
}
