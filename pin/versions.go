//go:build linux

package pin

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// LastFieldOfFirstLine is the default [Release.ParseVersion]: the last
// whitespace-separated field of the first line, and "" when there is none. It
// covers the common `<name> <version>` and bare `<version>` shapes and never
// panics on arbitrary input.
//
// A release whose probe prints something else — JSON, a multi-column banner —
// sets its own parser, because probe output has no universal shape.
func LastFieldOfFirstLine(out string) string {
	line, _, _ := strings.Cut(out, "\n")
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

// selfContained reports whether path is an artifact that keeps working after the
// staging tree is removed: a REGULAR executable file, not a symlink. os.Stat
// follows links and a bare executable check is also true for a directory, so both
// are checked explicitly.
func selfContained(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return false
	}
	return fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}

// probeVersion asks an artifact for its version, bounded, and parses the answer
// with the release's parser.
func (m *Manager) probeVersion(ctx context.Context, bin string) (string, error) {
	out, err := m.run(ctx, &command{
		Path:    bin,
		Env:     binPathEnv(bin),
		Args:    m.cfg.Release.ProbeArgs,
		Timeout: probeTimeout,
	})
	if err != nil {
		return "", err
	}
	version := m.parseVersion(string(out))
	if version == "" {
		return "", fmt.Errorf("the version probe produced no parseable version at %s", bin)
	}
	return version, nil
}

// versionDirComplete reports whether a version directory is a completed install:
// the sentinel is a plain file naming exactly this version, and every required
// artifact inside is a self-contained executable.
//
// A directory populated file-by-file at its final name is indistinguishable from
// a finished install without the sentinel, so the sentinel is what separates an
// interrupted staging tree from a complete one — and it is checked against the
// directory's own name, not against the pin, so a retained predecessor still
// reads as complete.
func (m *Manager) versionDirComplete(version string) bool {
	dir := m.versionDir(version)
	sentinel := filepath.Join(dir, sentinelName)
	fi, err := os.Lstat(sentinel)
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	// #nosec G304 -- sentinel is built from Root plus a directory entry name, and
	// it was just proved to be a regular file rather than a link.
	raw, err := os.ReadFile(sentinel)
	if err != nil || strings.TrimSpace(string(raw)) != version {
		return false
	}
	for _, name := range m.cfg.Require {
		if !selfContained(filepath.Join(dir, name)) {
			return false
		}
	}
	return true
}

// usablePredecessors returns up to want complete versions older than active that could
// actually serve as a fallback, newest first.
//
// "Could serve" is the same question selection asks, and asking it here is what makes
// the retained predecessor a real fallback rather than a directory nothing will
// activate: private, and answering the version probe with the version its own directory
// claims. The README promises N predecessors as the recovery mechanism, so counting a
// directory that selection would refuse makes that promise false in exactly the
// situation it exists for.
//
// The walk stops as soon as it has want of them, and it returns the ones it judged
// UNUSABLE alongside, so the caller can spare those without asking again: the earlier
// shape asked each question twice, once to fill the retained set and again to decide
// each victim, which doubled the subprocesses and emitted every diagnosis twice.
//
// The cost, stated plainly because it is a subprocess: up to one bounded version probe
// per complete directory older than the active one, capped by want plus however many
// unusable directories are met before the cap. This runs wherever pruning does, which is
// every Ensure and every Rescan that ends with a version active and no install error —
// not only after an install. With the default want of 1 and a healthy tree it is one.
//
// want is at least 1 by construction: [applyConfigDefaults] replaces a Retain of zero or
// less with defaultRetain, and [Manager.pruneSuperseded] is the only caller, which is why
// the capacity below is used unclamped.
//
// A rolePrunable candidate is added to NEITHER return value, which is how it becomes a
// victim without ever spending a fallback slot. That split is what answers the shape this
// was nearly built as — deciding the slot from completeness and privateness alone, both
// non-executing — whose defect was that one unprobeable predecessor captured the whole
// budget, so a complete-but-corrupt newer directory was kept while the good older one was
// pruned, exactly when the pin had already failed and the fallback was all there was.
// Retention answers two questions with two budgets instead of one budget with a weaker
// question: `keep` still admits only what selection would activate, so the fallback
// guarantee is untouched, and the bound comes from the prunable set having no immunity.
func (m *Manager) usablePredecessors(ctx context.Context, complete []string, active string, want int) (keep, immune []string) {
	keep = make([]string, 0, want)
	for _, version := range predecessorCandidates(complete, active) {
		if len(keep) >= want {
			// Enough keepers. Anything further is a victim either way, and asking
			// would cost a subprocess to reach the same outcome.
			break
		}
		switch m.predecessorRole(ctx, version) {
		case roleFallback:
			keep = append(keep, version)
		case roleImmune:
			immune = append(immune, version)
		case rolePrunable:
			// Deliberately neither: victimsOf prunes what it is not told to spare.
		}
	}
	return keep, immune
}

// activationStage names the check a version directory failed. It exists so selection and
// retention can share ONE set of checks while keeping their own severity and their own
// wording: the same refusal is an exclusion to one caller and a retention decision to the
// other, and those are not the same sentence.
type activationStage uint8

const (
	stageActivatable activationStage = iota // every check passed
	stageUntrusted
	stageWideEntry
	stageProbeFailed
	stageVersionMismatch
)

// activation is what [Manager.activatable] answers: the selection when a version directory
// would be activated, and otherwise the stage that refused it plus what that stage learned.
type activation struct {
	sel      selection
	verdict  error  // the custody verdict, read in the SAME lock acquisition as the trust answer
	err      error  // the version probe's error, when the probe is what failed
	dir      string // the version directory, once trust let it be computed
	bin      string // the primary artifact inside it, once the probe was reached
	entry    string // wideArtifact's offender: an entry name, or "." for the directory itself
	reason   string // why that entry is not provably private
	reported string // the version the probe answered
	stage    activationStage
}

// activatable answers the one question selection and retention BOTH ask of a complete
// version directory: would this be activated?
//
// One predicate rather than two, because retention's whole claim is that it agrees with
// selection. Both used to run the same three checks in the same order with nothing holding
// the copies together, so a fourth check added to selection would have silently missed
// retention — which prunes on this answer, and would then delete the fallback selection
// would have kept, in exactly the situation the fallback exists for.
//
// trusted() comes first, and that ordering is not an optimisation. probeVersion EXECUTES
// the artifact, so asking it about a directory selection has refused would run a binary
// this manager declined to activate, as the manager's own uid, on a volume it shares with
// another principal — which is exactly the deployment [Config.Untrusted] describes.
// Retention is a disk-hygiene decision and must not become an execution path selection
// would not take, so no caller may reorder these three.
//
// It reports and does not log: the callers reach different conclusions from the same
// refusal, at different severities, so the wording stays with them. The custody verdict
// travels along because the trust answer and the reason for it come from one acquisition of
// the state lock (see [Manager.trusted]); nothing here holds that lock across the probe,
// which runs a subprocess.
func (m *Manager) activatable(ctx context.Context, version string) activation {
	mayActivate, verdict := m.trusted(version)
	if !mayActivate {
		return activation{stage: stageUntrusted, verdict: verdict}
	}
	dir := m.versionDir(version)
	if entry, why := m.wideArtifact(dir); entry != "" {
		return activation{stage: stageWideEntry, verdict: verdict, dir: dir, entry: entry, reason: why}
	}
	bin := filepath.Join(dir, m.primary)
	got, err := m.probeVersion(ctx, bin)
	switch {
	case err != nil:
		return activation{stage: stageProbeFailed, verdict: verdict, dir: dir, bin: bin, err: err, reported: got}
	case got != version:
		return activation{stage: stageVersionMismatch, verdict: verdict, dir: dir, bin: bin, reported: got}
	}
	return activation{
		stage:   stageActivatable,
		verdict: verdict,
		dir:     dir,
		bin:     bin,
		sel:     selection{version: version, dir: dir, bin: bin},
	}
}

// retentionRole is what retention does with a complete predecessor. Three answers
// rather than a bool, because "not a fallback" hides two opposite conclusions: a
// directory this library must not touch, and one it must not keep.
type retentionRole uint8

const (
	// roleFallback would survive selection, so it counts against Retain.
	roleFallback retentionRole = iota
	// roleImmune cannot serve AND is not this library's to delete: a directory in a
	// state selection refuses (evidence this library did not create), or one that may
	// belong to another principal sharing a tree custody could not vouch for.
	roleImmune
	// rolePrunable cannot serve and is not evidence, so it is bounded like any other
	// superseded directory. It exists so a tree of directories nothing can ever
	// activate does not grow without limit.
	rolePrunable
)

// predecessorRole classifies one complete predecessor, and says why in the log when it
// is not a fallback.
//
// It asks [Manager.activatable] rather than repeating selection's checks, which is what
// makes retention's claim to agree with selection true rather than merely intended.
//
// THE UNTRUSTED SPLIT IS THE WHOLE REASON THIS RETURNS THREE ANSWERS, and it turns on
// the custody verdict rather than on which flag was set. Untrusted DECLARED over a tree
// custody vouches for means the directory is this deployment's own earlier install:
// `Manager.installed` is per-process and never persisted, so no process — this one or a
// later one — will ever activate it. It is not a fallback, it is not evidence, and
// leaving it forever is what made Retain unable to bound the tree at all. When custody
// itself REFUSED, the same stage means something else: the tree provably has a writer
// this library cannot account for, so a complete directory in it may be another
// principal's install, and deleting a stranger's files is not a disk-hygiene decision.
func (m *Manager) predecessorRole(ctx context.Context, version string) retentionRole {
	a := m.activatable(ctx, version)
	switch a.stage {
	case stageUntrusted:
		if a.verdict == nil {
			slog.Info("pruning a version directory no process can activate: this process did not install it and the tree is declared untrusted, so it is neither a fallback nor evidence",
				"package", m.cfg.Release.Name, "version", version)
			return rolePrunable
		}
		slog.Warn("not counting a version directory towards retention, and not deleting it: custody refused the tree, so this directory may be another principal's install",
			"package", m.cfg.Release.Name, "version", version, "verdict", a.verdict)
		return roleImmune
	case stageWideEntry:
		slog.Warn("not counting a version directory towards retention: selection would refuse it because an entry is not provably private to this process",
			"package", m.cfg.Release.Name, "version", version, "offender", a.entry, "reason", a.reason)
		return roleImmune
	case stageProbeFailed, stageVersionMismatch:
		slog.Warn("not counting a version directory towards retention: it would not survive selection's version probe",
			"package", m.cfg.Release.Name, "version", version, "reported", a.reported, "error", a.err)
		return roleImmune
	}
	return roleFallback
}

// completeVersions lists the completed version directories, newest first.
func (m *Manager) completeVersions() []string {
	entries, err := os.ReadDir(m.versionsDir)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		// Dot-prefixed entries are staging trees, never versions.
		if !e.IsDir() || strings.HasPrefix(name, ".") {
			continue
		}
		if !m.versionDirComplete(name) {
			continue
		}
		out = append(out, name)
	}
	sortVersionsDesc(out)
	return out
}

// trusted reports whether a version directory may be activated. A sentinel proves
// nothing on its own — it is a plain file, trivially forgeable, unlike a digest — so
// without custody of the tree the answer is no: not for any directory found there, and
// not even for one this process installed, unless the caller has explicitly waived the
// precondition and accepted that weaker claim.
//
// TWO independent triggers, and both are needed:
//
//   - The measured custody verdict ([verifyCustody]). A caller cannot be expected to
//     know that its volume carries an inherited ACL, so the library finds out.
//   - [Config.Untrusted], unconditionally. It keeps the meaning it had before the
//     measurement existed, because measurement has blind spots a caller may know
//     about: a volume mounted into two containers whose processes both map to uid 0
//     passes every check here, and the flag is the only way to say so.
//
// What `installed` proves is worth stating exactly, because it is less than it looks:
// THIS process published that version from an archive whose digest matched, at some
// earlier point in its own life. It is not evidence that the bytes are unchanged
// since. In a tree without custody nothing can be, short of re-hashing every artifact
// on every start against a record kept in the same untrusted tree — which is why the
// README lists that as a deliberate non-goal rather than a missing feature. This is
// the strongest available claim in a situation the caller has been told about, not a
// guarantee equivalent to custody.
// The verdict that produced the answer is returned with it, and that is not a
// convenience: a caller that logs `trusted()`'s decision and then asks
// [Manager.custodyVerdict] separately takes the state lock twice, and a verdict that
// changed in between makes the log line describe a decision that was never made. One
// acquisition answers both halves.
func (m *Manager) trusted(version string) (mayActivate bool, verdict error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case m.custodyErr != nil && !m.cfg.InstallWithoutCustody:
		// The verdict says this process does not control the tree and the caller has
		// not accepted that. Nothing here is evidence, INCLUDING what this process
		// installed earlier: that fact proves a publish at some past instant, not the
		// bytes at this one, and in a writable tree the directory or the artifact can
		// be renamed between the checks and the exec. Readiness is withheld rather
		// than granted on a claim the library cannot make.
		return false, m.custodyErr
	case m.custodyErr != nil, m.cfg.Untrusted:
		// Either the caller accepted a tree it shares, or it declared the tree
		// untrustworthy on its own knowledge. Same mitigation: only a version this
		// process published from a verified archive.
		return m.installed[version], m.custodyErr
	}
	return true, m.custodyErr
}

// entryPrivate reports whether a file or directory inside a version tree can be modified
// by any identity the caller has not accounted for.
//
// Custody of the tree does not answer this. Directory write permission governs creating,
// removing and renaming entries, not writing to the contents of an entry that already
// exists, so a group-writable artifact inside a directory nobody else can add to is still
// a binary this package executes and another principal can rewrite. And a version
// directory is not always one this process created: an operator is encouraged to reshape
// the volume, and a tree restored from a backup can hold entries with another owner.
//
// It asks the same questions [verifyCustody] asks of a path component, for the same
// reasons and against the same declared writer set: the owner, the mode, and the
// access-control list. Like everything else here it reads and reports; it never repairs.
//
// euid is a parameter rather than read here, for the same reason [checkSymlink] takes one:
// no unprivileged test can arrange a fixture this process does not own, so an ownership rule
// that reads its identity from the ambient process is a rule nothing gates where CI runs.
//
// The DIAGNOSIS is returned rather than folded into the bool, because the verdicts are not
// the same news and a caller cannot recover them from a false. An access-control list this
// process could not EVALUATE is not a finding that somebody else can write —
// [ErrACLUnreadable] and [ErrACLDialectUnsupported] exist precisely to keep those two
// apart — so reporting it as "writable by another principal" sends the operator to fix a
// mode that is already correct while the real obstacle (a dialect, a seccomp filter, an I/O
// error) goes unmentioned. reason is a predicate whose subject is the entry, so a caller
// completes the sentence: "<name> is writable by gid 3000".
func (m *Manager) entryPrivate(path string, wantDir bool, euid int) (reason string, private bool) {
	fi, err := os.Lstat(path)
	if err != nil {
		return "could not be examined: " + err.Error(), false
	}
	// A symlink is refused AS a symlink, before its mode is consulted. On Linux a link's
	// own mode is 0777 and grants nothing, so judging it by that mode reports an entry
	// everyone can write and hands the operator an exclusion they cannot act on: chmod
	// follows the link to its target. What the link points at is a different object from
	// the entry in this directory, and [checkSymlink] states the same rule for the path
	// walk — this is the copy that has to agree with it.
	if fi.Mode()&os.ModeSymlink != 0 {
		return "is a symlink, which this package will not execute", false
	}
	if fi.Mode().IsDir() != wantDir {
		if wantDir {
			return "is not a directory", false
		}
		return "is a directory rather than a file", false
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "has no ownership information", false
	}
	if !m.trust.allowsOwner(int(stat.Uid), euid) {
		return fmt.Sprintf("is owned by uid %d", stat.Uid), false
	}
	writers, err := writersOf(path, fi, stat)
	if err != nil {
		// An unreadable access-control list is not proof there is nothing to find, so this
		// fails closed like every other unknown here. It is REPORTED as the unknown it is
		// rather than as a writer somebody found, which is the distinction the two ACL
		// sentinel errors exist to carry.
		return "could not be judged: " + err.Error(), false
	}
	if p, stranger := m.trust.firstStranger(writers, euid); stranger {
		return "is writable by " + p.String(), false
	}
	return "", true
}

// wideArtifact returns the name of the first entry in dir that is not provably private to
// this process, together with WHY it is not, or "" when the directory and everything in it
// is private. The directory itself answers as "." — one another principal can write makes
// the modes of the entries inside it irrelevant, since the entries can simply be replaced.
//
// The reason travels with the name because "." and a bare entry name are not an operator
// sentence, and because the refusals are not interchangeable: an entry somebody else can
// write is a permissions problem, an entry whose access-control list could not be read is a
// visibility problem, and only one of the two is fixed with chmod. See [Manager.entryPrivate].
//
// EVERY top-level entry, not only the declared artifacts. [Manager.PathEntry] hands the
// whole version directory to the front of PATH, and a multi-binary release's primary
// artifact resolves its sidecars from there by bare name, so an undeclared executable
// sitting in that directory is reachable too. A version directory is not always one
// this process created: an operator is encouraged to reshape the volume, and a tree
// restored from a backup can hold entries with another owner. Directory permissions
// govern adding, removing and renaming names; they do not stop the owner of an entry
// that is already there from rewriting it, which is why judging the directory alone is not enough.
//
// Top level only, because that is what PATH exposes: an executable in a subdirectory
// is not reachable by bare name. A directory this library assembled holds exactly the
// declared artifacts and the sentinel, so this is a handful of stats.
func (m *Manager) wideArtifact(dir string) (name, reason string) {
	euid := os.Geteuid()
	if why, private := m.entryPrivate(dir, true, euid); !private {
		return ".", why
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ".", "could not be listed: " + err.Error()
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if why, private := m.entryPrivate(filepath.Join(dir, e.Name()), false, euid); !private {
			return e.Name(), why
		}
	}
	return "", ""
}

// selectActive picks the version to run: the pin when it is activatable, else the
// newest other complete version, else none.
//
// A directory name plus a sentinel is NOT proof. Before a candidate is accepted
// its primary artifact is probed and must answer with the version its own
// directory claims. A mismatch — an artifact replaced on the volume while the
// sentinel stayed intact — excludes that directory, falls through to another
// complete version if one exists, and leaves the pin unsatisfied so the caller
// reinstalls.
// The checks themselves live in [Manager.activatable], which retention asks the same
// question of. What stays here is the wording and the severity of each exclusion.
func (m *Manager) selectActive(ctx context.Context) (selection, bool) {
	for _, version := range preferPin(m.completeVersions(), m.cfg.Version) {
		a := m.activatable(ctx, version)
		if a.stage == stageUntrusted {
			slog.Warn("ignoring an existing version directory because this process does not exclusively control the installation tree; only a freshly verified install may be activated",
				"package", m.cfg.Release.Name, "version", version, "reason", a.verdict, "untrusted", m.cfg.Untrusted)
			continue
		}
		if m.cfg.Untrusted {
			slog.Error("activating a version on degraded evidence: Config.Untrusted declares this tree shared, so all that is known is that this process published this version from a verified archive earlier, not that its artifacts are unchanged since",
				"package", m.cfg.Release.Name, "version", version, "reason", a.verdict)
		}
		switch a.stage {
		case stageWideEntry:
			if a.entry == "." {
				slog.Error("excluding a version directory: the directory itself is not provably private to this process, so any artifact in it can be replaced whatever the artifacts' own modes say",
					"package", m.cfg.Release.Name, "version", version, "dir", a.dir, "reason", a.reason)
			} else {
				slog.Error("excluding a version directory: an entry in it is not provably private to this process, so it is a file this process may execute and cannot vouch for",
					"package", m.cfg.Release.Name, "version", version, "entry", a.entry, "reason", a.reason)
			}
			continue
		case stageProbeFailed:
			slog.Warn("excluding a version directory: its artifact did not answer the version probe",
				"package", m.cfg.Release.Name, "version", version, "path", a.bin, "error", a.err)
			continue
		case stageVersionMismatch:
			slog.Error("excluding a version directory: its artifact reports a different version than the directory and sentinel claim, so the install was replaced or tampered with",
				"package", m.cfg.Release.Name, "version", version, "reported", a.reported,
				"path", a.bin, "error", ErrVersionMismatch)
			continue
		}
		return a.sel, true
	}
	return selection{}, false
}

// preferPin returns versions with pin first (when present) and the rest in the
// given order, so the pinned version is always tried before any fallback.
func preferPin(versions []string, pin string) []string {
	out := make([]string, 0, len(versions))
	for _, v := range versions {
		if v == pin {
			out = append(out, v)
		}
	}
	for _, v := range versions {
		if v != pin {
			out = append(out, v)
		}
	}
	return out
}

// sortVersionsDesc orders versions newest first, comparing numeric segments
// numerically so 2.14.2 sorts above 2.9.0.
func sortVersionsDesc(versions []string) {
	slices.SortFunc(versions, func(a, b string) int { return compareVersions(b, a) })
}

// compareVersions returns >0 when a is newer than b, <0 when older, 0 when equal.
// Segments that are not numeric fall back to a string comparison, so an
// unexpected directory name still orders deterministically.
func compareVersions(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := range max(len(as), len(bs)) {
		// A missing segment counts as zero, so 2.14 and 2.14.0 are the same
		// version rather than ordering by string.
		av, bv := "0", "0"
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		an, aerr := strconv.Atoi(av)
		bn, berr := strconv.Atoi(bv)
		if aerr == nil && berr == nil {
			if an != bn {
				return an - bn
			}
			continue
		}
		if av != bv {
			return strings.Compare(av, bv)
		}
	}
	return 0
}

// predecessorCandidates returns the complete versions older than active, newest first.
// It is the lexical half of retention, kept separate from the usability half because it
// is pure: no filesystem, no subprocess, and therefore cheap to pin exhaustively.
func predecessorCandidates(complete []string, active string) []string {
	if active == "" {
		return nil
	}
	older := make([]string, 0, len(complete))
	for _, v := range complete {
		if compareVersions(v, active) < 0 {
			older = append(older, v)
		}
	}
	sortVersionsDesc(older)
	return older
}

// victimsOf returns the complete versions that pruning removes: everything that is
// neither spared (the active version and its retained predecessors) nor unusable.
//
// Anything NEWER than the active version is a victim: reaching that state means the pin
// moved down, and a stale higher version is not a fallback the pin wants kept. An
// unusable one is not, and that asymmetry is deliberate — this library did not put a
// directory into a state selection refuses, so deleting the evidence is not its call.
func victimsOf(complete, spare, unusable []string) []string {
	out := make([]string, 0, len(complete))
	for _, version := range complete {
		if slices.Contains(spare, version) || slices.Contains(unusable, version) {
			continue
		}
		out = append(out, version)
	}
	return out
}

// pruneSuperseded removes the version directories outside the retained set, then syncs
// the installation root again so the removals are durable. Failures warn: disk hygiene
// must not brick a start.
//
// The retained set is the active version plus up to Retain predecessors that could
// ACTUALLY serve (see usablePredecessors). A directory that selection would refuse —
// one holding a rewritable entry, or whose binary disagrees with its own name — must
// not spend the slot the usable predecessor needs, because that deletes the fallback
// and leaves the recovery guarantee resting on something nothing will activate.
//
// Such a directory is also never a victim. It is left exactly as found, for the
// operator to look at: this library did not put it in that state and deleting evidence
// is not its call. The one refusal that is NOT evidence is a directory this process did
// not install in a tree declared untrusted but vouched for by custody — nothing will
// ever activate that, and treating it as immune is what left the tree unbounded (see
// predecessorRole).
func (m *Manager) pruneSuperseded(ctx context.Context, active string) {
	complete := m.completeVersions()
	keep, immune := m.usablePredecessors(ctx, complete, active, m.cfg.Retain)
	victims := victimsOf(complete, append([]string{active}, keep...), immune)
	if len(victims) == 0 {
		return
	}
	removed := m.removeUnderRoot(victims)
	if removed == 0 {
		return
	}
	slog.Info("pruned superseded versions",
		"package", m.cfg.Release.Name, "removed", removed, "active", active, "retain", m.cfg.Retain)
	if err := m.fsync(m.versionsDir); err != nil {
		slog.Warn("failed to sync the installation root after pruning",
			"package", m.cfg.Release.Name, "error", err)
	}
}

// prunePartials removes incomplete version directories and orphan staging trees.
// It runs before selection so a partial directory is never a candidate, and it
// runs while no staging tree of this manager exists — Ensure holds opMu and
// creates its stage later.
//
// InstallWithoutCustody does not change WHAT is swept, only whether sweeping happens at
// all: its caller runs this and the purge only when Manager.mayMutateTree allows, and the
// waiver is one of the two ways that returns true. A foreign-writable tree invalidates a
// directory for ACTIVATION (see trusted); it has never been a reason to delete more
// than the incomplete directories this sweep already targets, because that would throw
// away the fallback set.
func (m *Manager) prunePartials() {
	entries, err := os.ReadDir(m.versionsDir)
	if err != nil {
		return
	}
	victims := make([]string, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		switch {
		case strings.HasPrefix(name, stagePrefix):
			victims = append(victims, name)
		case !e.IsDir(), strings.HasPrefix(name, "."):
			continue
		case !m.versionDirComplete(name):
			victims = append(victims, name)
		}
	}
	if removed := m.removeUnderRoot(victims); removed > 0 {
		slog.Info("removed incomplete install directories",
			"package", m.cfg.Release.Name, "removed", removed)
	}
}

// removeUnderRoot deletes the named entries through an os.Root confined to the
// installation root, so a symlinked or otherwise redirected entry cannot make a
// delete escape the tree. It returns how many were removed.
func (m *Manager) removeUnderRoot(names []string) int {
	if len(names) == 0 {
		return 0
	}
	root, err := os.OpenRoot(m.versionsDir)
	if err != nil {
		slog.Warn("failed to open the installation root for pruning",
			"package", m.cfg.Release.Name, "error", err)
		return 0
	}
	defer root.Close()
	removed := 0
	for _, name := range names {
		if err := root.RemoveAll(name); err != nil {
			slog.Warn("failed to remove an install directory",
				"package", m.cfg.Release.Name, "entry", name, "error", err)
			continue
		}
		removed++
	}
	return removed
}
