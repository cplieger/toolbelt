package toolbelt

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cplieger/go/filesafe"
	"github.com/cplieger/toolbelt/v3/internal/custody"
)

// wantFinding is one expected root-integrity finding: the exact path the
// check must flag, and a substring its reason must carry.
type wantFinding struct {
	path   string
	reason string
}

// quietLogger keeps a deliberately-failing New from writing its refusal
// to the test binary's stderr. The refusal LINE is asserted separately in
// TestNew_VerifyRootIntegrityLogsRefusal.
func quietLogger() *slog.Logger { return slog.New(&logCapture{}) }

// assertFindings checks every expectation against err: the class
// (errors.Is), the detail (errors.AsType), and that each wanted path
// appears with the wanted reason. Reported, not fatal, so one bad
// fixture does not hide the rest of the table.
func assertFindings(t *testing.T, err error, want []wantFinding) {
	t.Helper()
	if err == nil {
		t.Fatalf("New accepted an unfit root; wanted findings %+v", want)
	}
	if !errors.Is(err, ErrRootIntegrity) {
		t.Errorf("errors.Is(err, ErrRootIntegrity) = false for %v", err)
	}
	detail, isDetail := errors.AsType[*RootIntegrityError](err)
	if !isDetail {
		t.Fatalf("errors.AsType did not recover *RootIntegrityError from %v", err)
	}
	if !strings.HasPrefix(err.Error(), "toolbelt: ") {
		t.Errorf("error %q is not prefixed at the New boundary", err)
	}
	for _, w := range want {
		hit := false
		for _, got := range detail.Findings {
			if got.Path == w.path && strings.Contains(got.Reason, w.reason) {
				hit = true
				break
			}
		}
		if !hit {
			t.Errorf("no finding for %s carrying %q; got %+v", w.path, w.reason, detail.Findings)
		}
		// Every finding must also reach the operator through the message.
		if !strings.Contains(err.Error(), w.path) {
			t.Errorf("error message omits %s: %v", w.path, err)
		}
	}
}

// TestNew_VerifyRootIntegrityRefusesUnfitRoots pins the opt-in check on
// the states that make a managed root a root-code-execution surface: the
// engine EXECUTES launchers out of this tree during probing and puts
// bin/ first on PATH, so a root that is a symlink elsewhere, that is not
// a directory at all, or that a non-owner can write must refuse
// construction rather than be probed.
//
// Each case writes the bad state into real temp dirs (real symlinks,
// real chmod — a mode question is not worth mocking) and calls the real
// New.
func TestNew_VerifyRootIntegrityRefusesUnfitRoots(t *testing.T) {
	cases := map[string]struct {
		// setup writes the bad state and returns what the check must
		// report. configDir and toolsDir do not exist yet.
		setup func(t *testing.T, configDir, toolsDir string) []wantFinding
	}{
		"tools dir is a symlink": {
			setup: func(t *testing.T, configDir, toolsDir string) []wantFinding {
				mkdirs(t, configDir, filepath.Join(filepath.Dir(toolsDir), "elsewhere"))
				symlink(t, filepath.Join(filepath.Dir(toolsDir), "elsewhere"), toolsDir)
				return []wantFinding{{toolsDir, "is a symlink"}}
			},
		},
		"config dir is a symlink": {
			setup: func(t *testing.T, configDir, toolsDir string) []wantFinding {
				mkdirs(t, toolsDir, filepath.Join(filepath.Dir(configDir), "elsewhere"))
				symlink(t, filepath.Join(filepath.Dir(configDir), "elsewhere"), configDir)
				return []wantFinding{{configDir, "is a symlink"}}
			},
		},
		"npm parent is a symlink out of the tree": {
			// The parents are in the check set precisely for this: npm/bin
			// is a perfectly ordinary directory, and only the parent's
			// redirect (and the containment leg that resolves through it)
			// says the launcher dir is no longer on the operator's volume.
			setup: func(t *testing.T, configDir, toolsDir string) []wantFinding {
				outside := filepath.Join(filepath.Dir(toolsDir), "outside")
				mkdirs(t, configDir, toolsDir, filepath.Join(outside, "bin"))
				symlink(t, outside, filepath.Join(toolsDir, "npm"))
				return []wantFinding{
					{filepath.Join(toolsDir, "npm"), "is a symlink"},
					{filepath.Join(toolsDir, "npm", "bin"), "outside the tool tree"},
				}
			},
		},
		"python leaf resolves outside the tools dir": {
			setup: func(t *testing.T, configDir, toolsDir string) []wantFinding {
				outside := filepath.Join(filepath.Dir(toolsDir), "outside")
				mkdirs(t, configDir, toolsDir, filepath.Join(outside, "bin"))
				symlink(t, outside, filepath.Join(toolsDir, "python"))
				return []wantFinding{
					{filepath.Join(toolsDir, "python", "bin"), "outside the tool tree"},
				}
			},
		},
		"tools dir is group-writable": {
			setup: func(t *testing.T, configDir, toolsDir string) []wantFinding {
				mkdirs(t, configDir, toolsDir)
				chmod(t, toolsDir, 0o775)
				return []wantFinding{{toolsDir, "mode 0775, can be modified by gid"}}
			},
		},
		"python interpreters dir is group-writable": {
			setup: func(t *testing.T, configDir, toolsDir string) []wantFinding {
				dir := filepath.Join(toolsDir, "python", "interpreters")
				mkdirs(t, configDir, dir)
				chmod(t, dir, 0o775)
				return []wantFinding{{dir, "mode 0775, can be modified by gid"}}
			},
		},
		"npm modules dir is group-writable": {
			setup: func(t *testing.T, configDir, toolsDir string) []wantFinding {
				dir := filepath.Join(toolsDir, "npm", "lib", "node_modules")
				mkdirs(t, configDir, dir)
				chmod(t, dir, 0o770)
				return []wantFinding{{dir, "mode 0770, can be modified by gid"}}
			},
		},
		"npm lib dir is a symlink out of the tree": {
			setup: func(t *testing.T, configDir, toolsDir string) []wantFinding {
				outside := filepath.Join(filepath.Dir(toolsDir), "outside")
				mkdirs(t, configDir, filepath.Join(toolsDir, "npm"), filepath.Join(outside, "node_modules"))
				symlink(t, outside, filepath.Join(toolsDir, "npm", "lib"))
				return []wantFinding{
					{filepath.Join(toolsDir, "npm", "lib"), "is a symlink"},
					{filepath.Join(toolsDir, "npm", "lib", "node_modules"), "outside the tool tree"},
				}
			},
		},
		"python tools dir is group-writable": {
			setup: func(t *testing.T, configDir, toolsDir string) []wantFinding {
				dir := filepath.Join(toolsDir, "python", "tools")
				mkdirs(t, configDir, dir)
				chmod(t, dir, 0o770)
				return []wantFinding{{dir, "mode 0770, can be modified by gid"}}
			},
		},
		"bin dir is other-writable": {
			setup: func(t *testing.T, configDir, toolsDir string) []wantFinding {
				mkdirs(t, configDir, filepath.Join(toolsDir, "bin"))
				chmod(t, filepath.Join(toolsDir, "bin"), 0o757)
				return []wantFinding{{filepath.Join(toolsDir, "bin"), "mode 0757, can be modified by everyone"}}
			},
		},
		"config dir is other-writable": {
			setup: func(t *testing.T, configDir, toolsDir string) []wantFinding {
				mkdirs(t, configDir, toolsDir)
				chmod(t, configDir, 0o707)
				return []wantFinding{{configDir, "mode 0707, can be modified by everyone"}}
			},
		},
		"bin dir is writable by group 0": {
			// No group is trusted: a non-root member of group 0 could write the
			// bin the engine executes.
			setup: func(t *testing.T, configDir, toolsDir string) []wantFinding {
				if os.Getegid() != 0 {
					t.Skip("needs gid 0 for the fixture's group")
				}
				bin := filepath.Join(toolsDir, "bin")
				mkdirs(t, configDir, bin)
				chmod(t, bin, 0o775)
				return []wantFinding{{bin, "can be modified by gid 0"}}
			},
		},
		"tools dir is owned by another user": {
			setup: func(t *testing.T, configDir, toolsDir string) []wantFinding {
				mkdirs(t, configDir, toolsDir)
				if err := os.Chown(toolsDir, strangerID, -1); err != nil {
					t.Skipf("cannot hand the fixture to uid %d (%v)", strangerID, err)
				}
				return []wantFinding{{toolsDir, fmt.Sprintf("is owned by uid %d", strangerID)}}
			},
		},
		"bin dir is under an ancestor others can write": {
			setup: func(t *testing.T, configDir, toolsDir string) []wantFinding {
				mkdirs(t, configDir, filepath.Join(toolsDir, "bin"))
				chmod(t, filepath.Dir(toolsDir), 0o777)
				return []wantFinding{{filepath.Join(toolsDir, "bin"), "can be modified by"}}
			},
		},
		"tools dir is a regular file": {
			setup: func(t *testing.T, configDir, toolsDir string) []wantFinding {
				mkdirs(t, configDir)
				writeFile(t, toolsDir, "not a directory")
				return []wantFinding{{toolsDir, "is not a directory"}}
			},
		},
		"opt dir is a regular file": {
			setup: func(t *testing.T, configDir, toolsDir string) []wantFinding {
				mkdirs(t, configDir, toolsDir)
				writeFile(t, filepath.Join(toolsDir, "opt"), "not a directory")
				return []wantFinding{{filepath.Join(toolsDir, "opt"), "is not a directory"}}
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			configDir := filepath.Join(root, "config")
			toolsDir := filepath.Join(root, "tools")
			want := tc.setup(t, configDir, toolsDir)

			e, err := New(&Config{
				ConfigDir: configDir, ToolsDir: toolsDir,
				VerifyRootIntegrity: true, Logger: quietLogger(),
			})
			if e != nil {
				t.Cleanup(e.Close)
			}
			assertFindings(t, err, want)
		})
	}
}

// TestNew_VerifyRootIntegrityAcceptsFreshVolume is the regression that
// would break every first boot: on a fresh volume almost none of the
// checked directories exist yet (New creates bin/ moments later, and
// npm/ and python/ only ever appear when an ecosystem install runs), so
// absence must be nothing to judge rather than a finding.
func TestNew_VerifyRootIntegrityAcceptsFreshVolume(t *testing.T) {
	cases := map[string]func(t *testing.T, configDir, toolsDir string){
		"nothing exists yet": func(*testing.T, string, string) {},
		"config dir exists, tool tree does not": func(t *testing.T, configDir, _ string) {
			mkdirs(t, configDir)
		},
		"both roots exist, empty": func(t *testing.T, configDir, toolsDir string) {
			mkdirs(t, configDir, toolsDir)
		},
		"bin exists from a previous boot": func(t *testing.T, configDir, toolsDir string) {
			mkdirs(t, configDir, filepath.Join(toolsDir, "bin"), filepath.Join(toolsDir, "opt"))
		},
		"ecosystem trees exist from previous installs": func(t *testing.T, configDir, toolsDir string) {
			mkdirs(t, configDir,
				filepath.Join(toolsDir, "bin"),
				filepath.Join(toolsDir, "npm", "bin"),
				filepath.Join(toolsDir, "python", "bin"))
		},
	}

	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			configDir := filepath.Join(root, "config")
			toolsDir := filepath.Join(root, "tools")
			setup(t, configDir, toolsDir)

			e, err := New(&Config{ConfigDir: configDir, ToolsDir: toolsDir, VerifyRootIntegrity: true})
			if err != nil {
				t.Fatalf("New refused a clean volume: %v", err)
			}
			t.Cleanup(e.Close)
			if _, serr := os.Stat(filepath.Join(toolsDir, "bin")); serr != nil {
				t.Errorf("New did not create the bin dir: %v", serr)
			}
			if _, serr := os.Stat(filepath.Join(configDir, "tools.json")); serr != nil {
				t.Errorf("New did not seed the manifest: %v", serr)
			}
		})
	}
}

// TestNew_VerifyRootIntegrityOffAcceptsUnfitRoot pins the opt-in half:
// with the zero value, a root that the check would refuse is accepted
// exactly as before, symlink followed and all. Both consumers construct
// with keyed literals and no such field, so this is the behavior they
// keep until they set it.
func TestNew_VerifyRootIntegrityOffAcceptsUnfitRoot(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "config")
	toolsDir := filepath.Join(root, "tools")
	elsewhere := filepath.Join(root, "elsewhere")
	mkdirs(t, configDir, elsewhere)
	chmod(t, configDir, 0o777)
	symlink(t, elsewhere, toolsDir)

	e, err := New(&Config{ConfigDir: configDir, ToolsDir: toolsDir})
	if err != nil {
		t.Fatalf("New refused an unfit root with the check off: %v", err)
	}
	t.Cleanup(e.Close)
	// The MkdirAll of bin/ follows the symlinked ToolsDir at every
	// component, which is exactly the behavior the check exists to gate.
	if _, serr := os.Stat(filepath.Join(elsewhere, "bin")); serr != nil {
		t.Errorf("bin dir was not created through the symlink: %v", serr)
	}
}

// TestNew_VerifyRootIntegrityErrorIsClassifiable pins the contract the
// two consumers need to diverge on: one treats an unfit root as fatal,
// the other warns and runs tool-less, so the class must be comparable
// (errors.Is) and the detail recoverable (errors.AsType), with a message
// that names every offending path in a stable order.
func TestNew_VerifyRootIntegrityErrorIsClassifiable(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "config")
	toolsDir := filepath.Join(root, "tools")
	mkdirs(t, configDir, filepath.Join(toolsDir, "bin"), filepath.Join(toolsDir, "npm"))
	chmod(t, configDir, 0o770)
	chmod(t, filepath.Join(toolsDir, "bin"), 0o777)
	chmod(t, filepath.Join(toolsDir, "npm"), 0o775)

	_, err := New(&Config{
		ConfigDir: configDir, ToolsDir: toolsDir,
		VerifyRootIntegrity: true, Logger: quietLogger(),
	})
	if err == nil {
		t.Fatal("New accepted three writable roots")
	}
	if !errors.Is(err, ErrRootIntegrity) {
		t.Errorf("errors.Is(err, ErrRootIntegrity) = false for %v", err)
	}
	for _, other := range []error{ErrNotFound, ErrHasDependents, ErrDisabled, ErrUnknownJob} {
		if errors.Is(err, other) {
			t.Errorf("root-integrity error also matches %v", other)
		}
	}
	detail, isDetail := errors.AsType[*RootIntegrityError](err)
	if !isDetail {
		t.Fatalf("errors.AsType did not recover *RootIntegrityError from %v", err)
	}
	if len(detail.Findings) != 3 {
		t.Fatalf("findings = %+v, want the three writable roots", detail.Findings)
	}
	paths := make([]string, 0, len(detail.Findings))
	for _, f := range detail.Findings {
		paths = append(paths, f.Path)
		if f.Reason == "" {
			t.Errorf("finding for %s carries no reason", f.Path)
		}
		if !strings.Contains(err.Error(), f.Path) || !strings.Contains(err.Error(), f.Reason) {
			t.Errorf("message omits finding %+v: %v", f, err)
		}
	}
	if !slices.IsSorted(paths) {
		t.Errorf("findings are not sorted for determinism: %v", paths)
	}
	// The sentinel's own text is the message's prefix, as with
	// *DependentsError, so a log line reads the same either way.
	if !strings.Contains(err.Error(), ErrRootIntegrity.Error()) {
		t.Errorf("message %q does not carry the sentinel text", err)
	}
}

// TestNew_VerifyRootIntegrityLogsRefusal pins the operator-facing half:
// the refusal is logged at Error with structured fields (never
// interpolated into the message) before New returns, following the
// refuseUnverified precedent, because a consumer that only warns would
// otherwise leave nothing in the log naming the path.
func TestNew_VerifyRootIntegrityLogsRefusal(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "config")
	toolsDir := filepath.Join(root, "tools")
	mkdirs(t, configDir, toolsDir)
	chmod(t, toolsDir, 0o777)

	logs := &logCapture{}
	_, err := New(&Config{
		ConfigDir: configDir, ToolsDir: toolsDir,
		VerifyRootIntegrity: true, Logger: slog.New(logs),
	})
	if err == nil {
		t.Fatal("New accepted a world-writable tools dir")
	}
	if !logs.has("ERROR", "REFUSING to start", "config_dir="+configDir, "tools_dir="+toolsDir) {
		t.Errorf("no structured refusal at Error; lines=%v", logs.lines)
	}
	if !logs.has("finding_count=1", "findings="+toolsDir+" is not under this process's exclusive control: "+toolsDir+", mode 0777, can be modified by ") {
		t.Errorf("refusal does not name the offending path and reason in a field; lines=%v", logs.lines)
	}
}

// TestNew_VerifyRootIntegrityLeavesNothingBehind pins the placement of
// the first check inside New. It runs before newStore (whose initFiles
// writes tools.json, so an unfit existing ConfigDir is refused before
// anything is written through it), before bin/ is created, and before
// newJobQueue, whose worker goroutine a later error would leak because
// the caller gets a nil Engine and can never Close it.
func TestNew_VerifyRootIntegrityLeavesNothingBehind(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "config")
	toolsDir := filepath.Join(root, "tools")
	mkdirs(t, toolsDir)
	chmod(t, toolsDir, 0o775)

	before := runtime.NumGoroutine()
	e, err := New(&Config{
		ConfigDir: configDir, ToolsDir: toolsDir,
		VerifyRootIntegrity: true, Logger: quietLogger(),
	})
	if err == nil {
		t.Fatal("New accepted a group-writable tools dir")
	}
	if e != nil {
		t.Fatalf("New returned an Engine alongside its error: %+v", e)
	}
	for _, path := range []string{
		configDir,
		filepath.Join(configDir, "tools.json"),
		filepath.Join(toolsDir, "bin"),
	} {
		if _, serr := os.Stat(path); serr == nil {
			t.Errorf("refused New created %s", path)
		}
	}
	// The queue's worker is the only goroutine New starts. Poll rather
	// than compare once: an unrelated goroutine from an earlier test may
	// still be winding down, which lowers the count, never raises it.
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before {
		t.Errorf("refused New leaked goroutines: %d -> %d", before, after)
	}
}

// TestNew_VerifyRootIntegrityJudgesTheRootsItCreates pins the second
// check: roots that did not exist at the first check are created by New
// itself, through whatever mode the filesystem stores, so New judges them
// again before it builds an Engine. The config-dir probe runs between the
// two checks, which is where each case widens a root New just created.
func TestNew_VerifyRootIntegrityJudgesTheRootsItCreates(t *testing.T) {
	cases := []struct {
		widen func(configDir, toolsDir string) string
		name  string
	}{
		{
			name:  "tools dir created as the config dir's parent",
			widen: func(_, toolsDir string) string { return toolsDir },
		},
		{
			name:  "config dir created for the manifest",
			widen: func(configDir, _ string) string { return configDir },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			toolsDir := filepath.Join(t.TempDir(), "tools")
			configDir := filepath.Join(toolsDir, "config")
			widened := tc.widen(configDir, toolsDir)

			orig := probeWritable
			t.Cleanup(func() { probeWritable = orig })
			probeWritable = func(ctx context.Context, dir string, opts ...filesafe.Option) (filesafe.ProbeResult, error) {
				chmod(t, widened, 0o770)
				return orig(ctx, dir, opts...)
			}

			e, err := New(&Config{
				ConfigDir: configDir, ToolsDir: toolsDir,
				VerifyRootIntegrity: true, Logger: quietLogger(),
			})
			if e != nil {
				e.Close()
				t.Fatal("New returned an Engine over a root it created group-writable")
			}
			assertFindings(t, err, []wantFinding{{path: widened, reason: "mode 0770, can be modified by gid"}})
		})
	}
}

// TestInspectRoots_ReportsOnly pins the no-repair promise: the check is
// a report, so an offending root keeps its exact mode and the tree gains
// no directory from being inspected. Repair is the consumer entrypoint's,
// and tightening an operator's volume from inside a library would be a
// behavior change neither consumer asked for.
func TestInspectRoots_ReportsOnly(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "config")
	toolsDir := filepath.Join(root, "tools")
	mkdirs(t, configDir, toolsDir)
	chmod(t, toolsDir, 0o777)

	if findings := inspectRoots(configDir, toolsDir, custody.Trust{}); len(findings) != 1 {
		t.Fatalf("findings = %+v, want the one writable root", findings)
	}
	fi, err := os.Lstat(toolsDir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o777 {
		t.Errorf("the check changed the mode of an offending root: %04o", perm)
	}
	entries, err := os.ReadDir(toolsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("the check created %d entries under the tools dir", len(entries))
	}
}

// TestInspectRoots_ToleratesSymlinkedAncestor is the guard against
// over-tightening the containment leg: an operator's volume legitimately
// sits behind a symlinked ancestor (/config -> /mnt/config), so the
// resolved children must be judged against the RESOLVED root. Comparing
// them to the configured string would report every directory on such a
// volume as escaping.
func TestInspectRoots_ToleratesSymlinkedAncestor(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	mkdirs(t, filepath.Join(real, "tools", "bin"), filepath.Join(real, "tools", "npm", "bin"))
	symlink(t, real, filepath.Join(root, "link"))

	configDir := filepath.Join(root, "link", "config")
	mkdirs(t, configDir)
	toolsDir := filepath.Join(root, "link", "tools")
	if findings := inspectRoots(configDir, toolsDir, custody.Trust{}); len(findings) != 0 {
		t.Errorf("a volume behind a symlinked ancestor was refused: %+v", findings)
	}
}

// --- fixture helpers (real dirs, real modes; a mode question is not
// worth mocking) ---

func mkdirs(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// chmod sets an exact mode (MkdirAll applies the process umask, so the
// group/other bits a case needs have to be set afterwards).
func chmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// strangerID is a uid and gid no test process holds.
const strangerID = 54321

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(fmt.Errorf("write %s: %w", path, err))
	}
}

// TestNew_VerifyRootIntegrityHonoursTrustedUIDs grants a stranger write
// through a real POSIX.1e list, whose mask makes the mode read 0775: the
// check names the user, and accepts it once TrustedUIDs declares it.
func TestNew_VerifyRootIntegrityHonoursTrustedUIDs(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "config")
	toolsDir := filepath.Join(root, "tools")
	mkdirs(t, configDir, toolsDir)
	if err := grantUserWrite(toolsDir, strangerID); err != nil {
		t.Skipf("this filesystem takes no POSIX.1e list: %v", err)
	}
	fi, err := os.Lstat(toolsDir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o775 {
		t.Fatalf("INVALID: the list left mode %04o, want the mask in the group bits (0775)", perm)
	}

	_, err = New(&Config{ConfigDir: configDir, ToolsDir: toolsDir, VerifyRootIntegrity: true, Logger: quietLogger()})
	assertFindings(t, err, []wantFinding{{toolsDir, fmt.Sprintf("can be modified by uid %d", strangerID)}})

	e, err := New(&Config{
		ConfigDir: configDir, ToolsDir: toolsDir, VerifyRootIntegrity: true,
		TrustedUIDs: []int{strangerID}, Logger: quietLogger(),
	})
	if err != nil {
		t.Fatalf("New refused a writer TrustedUIDs declares: %v", err)
	}
	e.Close()
}

// grantUserWrite sets path's access list to u::rwx, u:uid:rwx, g::r-x,
// m::rwx, o::r-x.
func grantUserWrite(path string, uid int) error {
	entry := func(tag, perm uint16, id uint32) []byte {
		b := binary.LittleEndian.AppendUint16(nil, tag)
		b = binary.LittleEndian.AppendUint16(b, perm)
		return binary.LittleEndian.AppendUint32(b, id)
	}
	const undefined = 0xFFFFFFFF
	blob := binary.LittleEndian.AppendUint32(nil, 2)
	for _, e := range [][]byte{
		entry(0x01, 7, undefined), entry(0x02, 7, uint32(uid)), entry(0x04, 5, undefined),
		entry(0x10, 7, undefined), entry(0x20, 5, undefined),
	} {
		blob = append(blob, e...)
	}
	return syscall.Setxattr(path, "system.posix_acl_access", blob, 0)
}

// TestNew_VerifyRootIntegrityReportsOneFindingPerRoot pins that a root
// failing two legs is reported once, by the first: consumers count
// findings per directory.
func TestNew_VerifyRootIntegrityReportsOneFindingPerRoot(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "config")
	toolsDir := filepath.Join(root, "tools")
	outside := filepath.Join(root, "outside")
	mkdirs(t, configDir, toolsDir, filepath.Join(outside, "bin"))
	chmod(t, filepath.Join(outside, "bin"), 0o777)
	symlink(t, outside, filepath.Join(toolsDir, "python"))

	_, err := New(&Config{ConfigDir: configDir, ToolsDir: toolsDir, VerifyRootIntegrity: true, Logger: quietLogger()})
	detail, ok := errors.AsType[*RootIntegrityError](err)
	if !ok {
		t.Fatalf("New = %v, want a *RootIntegrityError", err)
	}
	bin := filepath.Join(toolsDir, "python", "bin")
	var reasons []string
	for _, f := range detail.Findings {
		if f.Path == bin {
			reasons = append(reasons, f.Reason)
		}
	}
	if len(reasons) != 1 || !strings.Contains(reasons[0], "mode 0777, can be modified by") {
		t.Errorf("findings for %s = %q, want one, the writable leg", bin, reasons)
	}
}

func TestNew_RefusesANegativeTrustedUID(t *testing.T) {
	root := t.TempDir()
	_, err := New(&Config{
		ConfigDir: filepath.Join(root, "config"), ToolsDir: filepath.Join(root, "tools"),
		TrustedUIDs: []int{1000, -1},
	})
	if err == nil || err.Error() != "toolbelt: TrustedUIDs entry -1 is not a uid" {
		t.Errorf("New = %v, want the negative uid refused", err)
	}
	if _, serr := os.Stat(filepath.Join(root, "config")); serr == nil {
		t.Error("New created the config dir before refusing its Config")
	}
}

func TestNew_RefusesADotDotRoot(t *testing.T) {
	root := t.TempDir()
	tests := map[string]*Config{
		"config dir, inside": {ConfigDir: root + "/link/../config", ToolsDir: root + "/tools"},
		"config dir, ending": {ConfigDir: root + "/config/x/..", ToolsDir: root + "/tools"},
		"tools dir, inside":  {ConfigDir: root + "/config", ToolsDir: root + "/link/../tools"},
		"tools dir, ending":  {ConfigDir: root + "/config", ToolsDir: root + "/tools/x/.."},
	}
	for name, cfg := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := New(cfg)
			if err == nil || !strings.Contains(err.Error(), `must not contain a ".." component`) {
				t.Errorf("New = %v, want the dot-dot root refused", err)
			}
		})
	}
	if _, serr := os.Stat(filepath.Join(root, "config")); serr == nil {
		t.Error("New created the config dir before refusing its Config")
	}
}

// TestManagedDirs_IsTheJudgedSet freezes the directories the integrity
// check judges: a consumer's boot repair tightens exactly these.
func TestManagedDirs_IsTheJudgedSet(t *testing.T) {
	got := managedDirs("/t")
	want := []string{
		"/t/bin", "/t/opt", "/t/npm", "/t/npm/bin", "/t/npm/lib", "/t/npm/lib/node_modules",
		"/t/python", "/t/python/bin", "/t/python/tools", "/t/python/interpreters",
	}
	if !slices.Equal(got, want) {
		t.Errorf("managedDirs = %q, want %q", got, want)
	}
}
