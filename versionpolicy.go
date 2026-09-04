package toolbelt

import (
	"fmt"
	"regexp"
	"strings"
)

// A version's alphabet belongs to the SOURCE that produced it; the path
// constraint this engine adds is a separate axis. One alphabet over every
// source fused the two and refused openssh-client's legal Debian version
// 1:10.0p1-7+deb13u4 for carrying a colon a forge tag may not carry.

// versionGrammar is the alphabet one source's producer can legally emit.
type versionGrammar int

const (
	// grammarUnknown names no alphabet, so a source kind missing from
	// sourceVersionGrammar cannot inherit one by zero value.
	grammarUnknown versionGrammar = iota
	// grammarTag is a forge tag or registry semver — the narrowest,
	// because only these sources put the version in a path component, a
	// URL segment and a bash $VERSION.
	grammarTag
	// grammarDebian is Debian Policy 5.6.12. An apt version reaches no
	// path, URL or argv, so the wider alphabet costs nothing.
	grammarDebian
	// grammarPEP440 is PyPI's alphabet, '!' epoch separator included. A
	// pip version reaches uv's argv and no path.
	grammarPEP440
)

// maxVersionLen bounds every grammar. The value lands in a manifest, a
// state file and (under grammarTag) a path component.
const maxVersionLen = 100

// sourceVersionGrammar maps each source kind to its producer's grammar.
// TestSourceVersionGrammarIsTotal fails when a source constant is added
// without an entry, because the alternative is grammarUnknown reaching a
// caller that then has to guess.
var sourceVersionGrammar = map[string]versionGrammar{
	SourceAqua:    grammarTag,
	SourceRelease: grammarTag,
	SourceNpm:     grammarTag,
	SourceCargo:   grammarTag,
	SourceGo:      grammarTag,
	SourceManual:  grammarTag,
	SourceApt:     grammarDebian,
	SourcePip:     grammarPEP440,
}

// versionPatterns holds one anchored pattern per grammar. Every pattern
// requires a leading alphanumeric, which is what makes ".." and a
// leading "-" unrepresentable: the first would escape the versioned
// install directory and the second would reach a package manager's argv
// as an option.
var versionPatterns = map[versionGrammar]*regexp.Regexp{
	grammarTag: regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`),
	// Two alternatives, not one class: Debian admits a ':' only when an
	// epoch introduces it.
	grammarDebian: regexp.MustCompile(`^(?:[0-9]+:[A-Za-z0-9][A-Za-z0-9.+~:-]*|[A-Za-z0-9][A-Za-z0-9.+~-]*)$`),
	grammarPEP440: regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+!-]*$`),
}

// sourceKind is the part of a source string before its ':' — "apt" for
// "apt:openssh-client", and the whole string for SourceManual, which
// carries no ref.
func sourceKind(source string) string {
	kind, _, _ := strings.Cut(source, ":")
	return kind
}

// validVersion reports whether v is a legal version for the source that
// produced it.
//
// An empty or unrecognised source names no grammar, so the union of all
// three applies. Such a row cannot install (resolveInstallTarget refuses
// a source-less entry) and its source is not patchable, so the version
// stays inert; refusing a legal Debian version on a not-yet-hydrated apt
// template would be this function's own defect one door over.
func validVersion(source, v string) bool {
	if v == "" || len(v) > maxVersionLen {
		return false
	}
	if g, ok := sourceVersionGrammar[sourceKind(source)]; ok {
		return versionPatterns[g].MatchString(v)
	}
	for _, re := range versionPatterns {
		if re.MatchString(v) {
			return true
		}
	}
	return false
}

// versionRejected explains a refused version by naming the grammar it
// failed, so a Debian epoch and a shell injection do not share one
// message.
func versionRejected(source, v string) error {
	g, ok := sourceVersionGrammar[sourceKind(source)]
	if !ok {
		return fmt.Errorf("version %q is not a legal version string", v)
	}
	switch g {
	case grammarDebian:
		return fmt.Errorf("version %q is not a Debian version ([epoch:]upstream[-revision])", v)
	case grammarPEP440:
		return fmt.Errorf("version %q is not a PEP 440 version", v)
	default:
		return fmt.Errorf("version %q is not a release tag (letters, digits, '.', '-', '_', '+')", v)
	}
}

// versionPathComponent reports whether v is usable as a single path
// component. grammarTag already excludes every separator; this is the
// assertion that keeps that true at the site which depends on it, so a
// source kind wired to extraction later cannot reach the join carrying a
// wider grammar's value.
func versionPathComponent(v string) bool {
	return v != "" && v != "." && v != ".." && !strings.ContainsAny(v, `/\`)
}
