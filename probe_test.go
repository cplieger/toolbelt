package toolbelt

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// writeStub writes an executable shell stub into the engine's bin dir.
func writeStub(t *testing.T, e *Engine, name, body string) {
	t.Helper()
	p := filepath.Join(e.binDir(), name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func writeNpmPackage(t *testing.T, e *Engine, pkg, manifest string) {
	t.Helper()
	dir := filepath.Join(e.toolsDir, "npm", "lib", "node_modules", pkg)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestProbeInstalled_ExecutesTheTool pins install detection: presence of
// bin/<name> is not proof, so a corrupt/wrong-arch binary, a dangling
// link, or the wrong version all read as NOT installed.
func TestProbeInstalled_ExecutesTheTool(t *testing.T) {
	cases := []struct {
		name        string
		setup       func(t *testing.T, e *Engine) (Tool, ToolStatus)
		want        bool
		wantMode    string
		wantWarning string
		wantReason  string
	}{
		{
			name: "runnable binary, no version shape declared",
			setup: func(t *testing.T, e *Engine) (Tool, ToolStatus) {
				writeStub(t, e, "tool", "echo tool 1.2.3")
				return Tool{Source: SourceManual}, ToolStatus{InstalledVersion: "1.2.3", Bins: []string{"tool"}}
			},
			want: true, wantMode: probeModeExec,
		},
		{
			name: "declared version shape, matching answer",
			setup: func(t *testing.T, e *Engine) (Tool, ToolStatus) {
				writeStub(t, e, "tool", "echo tool 1.2.3")
				return Tool{Source: SourceManual, VersionArgs: []string{"--version"}},
					ToolStatus{InstalledVersion: "1.2.3", Bins: []string{"tool"}}
			},
			want: true, wantMode: probeModeVersion,
		},
		{
			name: "declared version shape, v-prefix difference tolerated",
			setup: func(t *testing.T, e *Engine) (Tool, ToolStatus) {
				writeStub(t, e, "tool", "echo 1.2.3")
				return Tool{Source: SourceManual, VersionArgs: []string{"--version"}},
					ToolStatus{InstalledVersion: "v1.2.3", Bins: []string{"tool"}}
			},
			want: true, wantMode: probeModeVersion,
		},
		{
			// A definition whose tool spells its version subcommand
			// without dashes: the declared shape is what must be
			// executed, or the answer that gets graded came from an
			// invocation the definition never asked for.
			name: "the declared version shape is the invocation",
			setup: func(t *testing.T, e *Engine) (Tool, ToolStatus) {
				writeStub(t, e, "tool", `[ "$1" = version ] && echo 1.2.3 || echo 0.0.0`)
				return Tool{Source: SourceManual, VersionArgs: []string{"version"}},
					ToolStatus{InstalledVersion: "1.2.3", Bins: []string{"tool"}}
			},
			want: true, wantMode: probeModeVersion,
		},
		{
			name: "declared version shape, tool reports another version",
			setup: func(t *testing.T, e *Engine) (Tool, ToolStatus) {
				writeStub(t, e, "tool", "echo tool 9.9.9")
				return Tool{Source: SourceManual, VersionArgs: []string{"--version"}},
					ToolStatus{InstalledVersion: "1.2.3", Bins: []string{"tool"}}
			},
			want: false, wantMode: probeModeVersion, wantWarning: "probe failed",
			wantReason: `reported "tool 9.9.9"`,
		},
		{
			name: "declared version shape, tool reports a longer version",
			setup: func(t *testing.T, e *Engine) (Tool, ToolStatus) {
				writeStub(t, e, "tool", "echo tool v1.2.30")
				return Tool{Source: SourceManual, VersionArgs: []string{"--version"}},
					ToolStatus{InstalledVersion: "v1.2.3", Bins: []string{"tool"}}
			},
			want: false, wantMode: probeModeVersion, wantWarning: "probe failed",
			wantReason: `reported "tool v1.2.30"`,
		},
		{
			name: "declared version shape, tool reports the version with a commit hash",
			setup: func(t *testing.T, e *Engine) (Tool, ToolStatus) {
				writeStub(t, e, "tool", "echo tool v0.147.9-a1bdbde19c+extended")
				return Tool{Source: SourceManual, VersionArgs: []string{"--version"}},
					ToolStatus{InstalledVersion: "v0.147.9", Bins: []string{"tool"}}
			},
			want: true, wantMode: probeModeVersion,
		},
		{
			name: "declared version shape but nothing recorded to compare",
			setup: func(t *testing.T, e *Engine) (Tool, ToolStatus) {
				writeStub(t, e, "tool", "echo whatever")
				return Tool{Source: SourceManual, VersionArgs: []string{"--version"}}, ToolStatus{}
			},
			want: true, wantMode: probeModeExec,
		},
		{
			name: "present but not a program",
			setup: func(t *testing.T, e *Engine) (Tool, ToolStatus) {
				p := filepath.Join(e.binDir(), "tool")
				if err := os.WriteFile(p, []byte("truncated download"), 0o755); err != nil {
					t.Fatal(err)
				}
				return Tool{Source: SourceManual}, ToolStatus{InstalledVersion: "1.2.3", Bins: []string{"tool"}}
			},
			want: false, wantMode: probeModeExec, wantWarning: "probe failed",
			wantReason: "cannot execute",
		},
		{
			// The shape that shipped: node's own linux-x64 build links
			// libatomic.so.1, the image did not carry it, and ld.so
			// answered 127. Graded as an answer, that made a runtime
			// that cannot start read as installed, and every npm tool
			// behind it then failed naming ITSELF.
			name: "the loader refused the binary: exit 127",
			setup: func(t *testing.T, e *Engine) (Tool, ToolStatus) {
				writeStub(t, e, "tool",
					`echo "tool: error while loading shared libraries: libatomic.so.1" >&2; exit 127`)
				return Tool{Source: SourceManual}, ToolStatus{InstalledVersion: "1.2.3", Bins: []string{"tool"}}
			},
			want: false, wantMode: probeModeExec, wantWarning: "probe failed",
			wantReason: "libatomic.so.1",
		},
		{
			// The tolerance the 127 rule must not swallow: a tool that
			// does not understand --version still proved it can run.
			name: "a non-zero exit that is not 127 is still an answer",
			setup: func(t *testing.T, e *Engine) (Tool, ToolStatus) {
				writeStub(t, e, "tool", `echo "unknown flag: --version" >&2; exit 2`)
				return Tool{Source: SourceManual}, ToolStatus{InstalledVersion: "1.2.3", Bins: []string{"tool"}}
			},
			want: true, wantMode: probeModeExec,
		},
		{
			name: "present but not executable falls back to presence",
			setup: func(t *testing.T, e *Engine) (Tool, ToolStatus) {
				p := filepath.Join(e.binDir(), "tool")
				if err := os.WriteFile(p, []byte("data file"), 0o644); err != nil {
					t.Fatal(err)
				}
				return Tool{Source: SourceManual}, ToolStatus{InstalledVersion: "1.2.3", Bins: []string{"tool"}}
			},
			want: true, wantMode: probeModePresence, wantWarning: "NOT verified by execution",
		},
		{
			name: "dangling link into a pruned version tree",
			setup: func(t *testing.T, e *Engine) (Tool, ToolStatus) {
				link := filepath.Join(e.binDir(), "tool")
				if err := os.Symlink(filepath.Join(e.toolsDir, "opt", "tool", "v1", "tool"), link); err != nil {
					t.Fatal(err)
				}
				return Tool{Source: SourceManual}, ToolStatus{InstalledVersion: "1.2.3", Bins: []string{"tool"}}
			},
			want: false,
		},
		{
			name: "one recorded bin of several is missing",
			setup: func(t *testing.T, e *Engine) (Tool, ToolStatus) {
				writeStub(t, e, "tsc", "echo 5.9.0")
				return Tool{Source: "npm:typescript"},
					ToolStatus{InstalledVersion: "5.9.0", PMBins: []string{"tsc", "tsserver"}}
			},
			// Naming the missing bin is the whole diagnostic: every
			// RECORDED bin is checked, not just the one that gets run.
			want: false, wantReason: "bin tsserver is missing",
		},
		{
			// An npm package can ship no bin at all (a preset or shared
			// config), so its installed package.json is the only proof.
			name: "npm library package at the recorded version",
			setup: func(t *testing.T, e *Engine) (Tool, ToolStatus) {
				writeNpmPackage(t, e, "@size-limit/preset-app", `{"name":"@size-limit/preset-app","version":"14.3.0"}`)
				return Tool{Source: "npm:@size-limit/preset-app"}, ToolStatus{InstalledVersion: "14.3.0"}
			},
			want: true, wantMode: "package",
		},
		{
			name: "npm library package at another version",
			setup: func(t *testing.T, e *Engine) (Tool, ToolStatus) {
				writeNpmPackage(t, e, "@size-limit/preset-app", `{"name":"@size-limit/preset-app","version":"14.2.0"}`)
				return Tool{Source: "npm:@size-limit/preset-app"}, ToolStatus{InstalledVersion: "14.3.0"}
			},
			want: false, wantMode: "package", wantReason: `package.json reports "14.2.0", recorded version is "14.3.0"`,
		},
		{
			name: "npm library package before the first status write",
			setup: func(t *testing.T, e *Engine) (Tool, ToolStatus) {
				writeNpmPackage(t, e, "stylelint-config-standard", `{"name":"stylelint-config-standard","version":"40.0.0"}`)
				return Tool{Source: "npm:stylelint-config-standard"}, ToolStatus{}
			},
			want: true, wantMode: "package",
		},
		{
			name: "npm package declaring a bin is probed through its bin",
			setup: func(t *testing.T, e *Engine) (Tool, ToolStatus) {
				writeNpmPackage(t, e, "@size-limit/preset-app", `{"name":"@size-limit/preset-app","version":"14.3.0","bin":"cli.js"}`)
				return Tool{Source: "npm:@size-limit/preset-app"}, ToolStatus{InstalledVersion: "14.3.0"}
			},
			want: false, wantReason: "bin tool is missing",
		},
		{
			name: "npm package declaring a bin map is probed through its bin",
			setup: func(t *testing.T, e *Engine) (Tool, ToolStatus) {
				writeNpmPackage(t, e, "tool", `{"name":"tool","version":"1.2.3","bin":{"tool":"cli.js"}}`)
				return Tool{Source: "npm:tool"}, ToolStatus{InstalledVersion: "1.2.3"}
			},
			want: false, wantReason: "bin tool is missing",
		},
		{
			name: "npm package with an empty bin map is a library package",
			setup: func(t *testing.T, e *Engine) (Tool, ToolStatus) {
				writeNpmPackage(t, e, "tool", `{"name":"tool","version":"1.2.3","bin":{}}`)
				return Tool{Source: "npm:tool"}, ToolStatus{InstalledVersion: "1.2.3"}
			},
			want: true, wantMode: "package",
		},
		{
			name: "npm package.json without a version proves nothing",
			setup: func(t *testing.T, e *Engine) (Tool, ToolStatus) {
				writeNpmPackage(t, e, "tool", `{"name":"tool"}`)
				return Tool{Source: "npm:tool"}, ToolStatus{}
			},
			want: false, wantReason: "bin tool is missing",
		},
		{
			// A recorded bin is the install's footprint, so it is checked
			// even when package.json no longer declares one.
			name: "npm package with a recorded bin is probed through it",
			setup: func(t *testing.T, e *Engine) (Tool, ToolStatus) {
				writeNpmPackage(t, e, "tool", `{"name":"tool","version":"1.2.3"}`)
				return Tool{Source: "npm:tool"}, ToolStatus{InstalledVersion: "1.2.3", PMBins: []string{"tool"}}
			},
			want: false, wantReason: "bin tool is missing",
		},
		{
			name: "npm package declaring a bin directory is probed through its bin",
			setup: func(t *testing.T, e *Engine) (Tool, ToolStatus) {
				writeNpmPackage(t, e, "tool", `{"name":"tool","version":"1.2.3","directories":{"bin":"./bin"}}`)
				return Tool{Source: "npm:tool"}, ToolStatus{InstalledVersion: "1.2.3"}
			},
			want: false, wantReason: "bin tool is missing",
		},
		{
			name: "npm package that is not installed is probed through its bin",
			setup: func(*testing.T, *Engine) (Tool, ToolStatus) {
				return Tool{Source: "npm:tool"}, ToolStatus{InstalledVersion: "1.2.3"}
			},
			want: false, wantReason: "bin tool is missing",
		},
		{
			// npm refs are not validated at the door, so the read must
			// stay inside node_modules: the package.json planted at the
			// escape target would otherwise read as installed.
			name: "npm ref escaping node_modules is not read",
			setup: func(t *testing.T, e *Engine) (Tool, ToolStatus) {
				writeNpmPackage(t, e, "other", `{"name":"other","version":"1.0.0"}`)
				writeNpmPackage(t, e, "../../x", `{"name":"x","version":"1.2.3"}`)
				return Tool{Source: "npm:../../x"}, ToolStatus{InstalledVersion: "1.2.3"}
			},
			want: false, wantReason: "bin tool is missing",
		},
		{
			name: "npm library package with an unparseable package.json",
			setup: func(t *testing.T, e *Engine) (Tool, ToolStatus) {
				writeNpmPackage(t, e, "tool", `{"version":`)
				return Tool{Source: "npm:tool"}, ToolStatus{InstalledVersion: "1.2.3"}
			},
			want: false, wantReason: "bin tool is missing",
		},
		{
			name: "nothing installed at all",
			setup: func(*testing.T, *Engine) (Tool, ToolStatus) {
				return Tool{Source: SourceManual}, ToolStatus{}
			},
			// Before the first status write there is nothing recorded, so
			// the derived bin name is what must be looked for — a
			// pre-seeded volume reads as installed on the strength of it.
			want: false, wantReason: "bin tool is missing",
		},
		{
			name: "a tool that never answers is bounded, not hung",
			setup: func(t *testing.T, e *Engine) (Tool, ToolStatus) {
				writeStub(t, e, "tool", "sleep 120")
				return Tool{Source: SourceManual}, ToolStatus{InstalledVersion: "1.2.3", Bins: []string{"tool"}}
			},
			want: false, wantMode: probeModeExec, wantWarning: "probe failed",
			wantReason: "did not answer",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEngine(t, nil)
			logs := captureLogs(e)
			tool, status := tc.setup(t, e)

			start := time.Now()
			got := e.probeTool("tool", &tool, &status)
			elapsed := time.Since(start)

			if got.OK != tc.want {
				t.Errorf("probe OK = %v (%s: %s), want %v", got.OK, got.Mode, got.Reason, tc.want)
			}
			if tc.wantMode != "" && got.Mode != tc.wantMode {
				t.Errorf("probe mode = %q, want %q (reason %q)", got.Mode, tc.wantMode, got.Reason)
			}
			if tc.wantReason != "" && !strings.Contains(got.Reason, tc.wantReason) {
				t.Errorf("probe reason = %q, want it to carry %q", got.Reason, tc.wantReason)
			}
			if elapsed > probeTimeout+probeWaitDelay+2*time.Second {
				t.Errorf("probe took %s: not bounded", elapsed)
			}
			if tc.wantWarning != "" && !logs.has("WARN", tc.wantWarning, "tool=tool") {
				t.Errorf("expected a %q warning, got %v", tc.wantWarning, logs.lines)
			}
		})
	}
}

// TestProbeInstalled_CachesExecPerBinary keeps the probe off the hot read
// path: Inventory is polled, so the same binary must be executed once, not
// once per call — while a replaced binary (reinstall, relink) or a bumped
// recorded version re-probes, and a deleted bin is noticed immediately
// because presence is always re-checked.
func TestProbeInstalled_CachesExecPerBinary(t *testing.T) {
	e := newTestEngine(t, nil)
	captureLogs(e)
	counter := filepath.Join(t.TempDir(), "runs")
	writeStub(t, e, "tool", "printf x >> "+counter+"\necho 1.0.0")
	tool := Tool{Source: SourceManual, VersionArgs: []string{"--version"}}
	status := ToolStatus{InstalledVersion: "1.0.0", Bins: []string{"tool"}}

	runs := func() int {
		data, err := os.ReadFile(counter)
		if err != nil {
			return 0
		}
		return len(data)
	}
	for range 5 {
		if !e.probeInstalled("tool", &tool, &status) {
			t.Fatal("probe should pass")
		}
	}
	if got := runs(); got != 1 {
		t.Fatalf("tool executed %d times for 5 probes, want 1", got)
	}

	// A reinstall replaces the binary: the verdict must be re-established.
	time.Sleep(10 * time.Millisecond)
	writeStub(t, e, "tool", "printf x >> "+counter+"\necho 2.0.0")
	status.InstalledVersion = "2.0.0"
	if !e.probeInstalled("tool", &tool, &status) {
		t.Fatal("probe should pass after the reinstall")
	}
	if got := runs(); got != 2 {
		t.Fatalf("tool executed %d times, want a re-probe after the binary changed", got)
	}

	// A deleted bin is caught by the presence check, cache or not.
	if err := os.Remove(filepath.Join(e.binDir(), "tool")); err != nil {
		t.Fatal(err)
	}
	if e.probeInstalled("tool", &tool, &status) {
		t.Fatal("probe passed for a deleted bin")
	}
}

// TestProbeInstalled_DeclaringVersionArgsReprobes pins that declaring a
// version shape equal to the default (--version) re-grades the binary: the
// same argv runs, but only a declared shape checks the version, so a cached
// verdict from one shape must not answer for the other, in either order.
func TestProbeInstalled_DeclaringVersionArgsReprobes(t *testing.T) {
	undeclared := probeVerdict{OK: true, Mode: probeModeExec}
	declared := probeVerdict{OK: false, Mode: probeModeVersion}
	cases := []struct {
		name  string
		steps [][]string
		want  []probeVerdict
	}{
		{
			name:  "declaring after an undeclared probe",
			steps: [][]string{nil, {"--version"}},
			want:  []probeVerdict{undeclared, declared},
		},
		{
			name:  "undeclaring after a declared probe",
			steps: [][]string{{"--version"}, nil},
			want:  []probeVerdict{declared, undeclared},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEngine(t, nil)
			captureLogs(e)
			writeStub(t, e, "tool", "echo tool 9.9.9")
			status := ToolStatus{InstalledVersion: "1.2.3", Bins: []string{"tool"}}
			for i, args := range tc.steps {
				tool := Tool{Source: SourceManual, VersionArgs: args}
				v := e.probeTool("tool", &tool, &status)
				if v.OK != tc.want[i].OK || v.Mode != tc.want[i].Mode {
					t.Errorf("probe %d with version_args %q = %+v, want OK=%v mode %q",
						i, args, v, tc.want[i].OK, tc.want[i].Mode)
				}
			}
		})
	}
}

// replaceMode is how replaceKeepingStat swaps a file's content.
type replaceMode int

const (
	replaceByRename replaceMode = iota
	replaceInPlace
)

// replaceKeepingStat gives path new content of the same length, then puts
// back its mode and mtime, so only device, inode or ctime can tell the
// files apart. replaceByRename renames a new file over path (a new inode);
// replaceInPlace rewrites path's own inode and waits for its ctime to move,
// which the kernel stamps at clock-tick granularity (inode(7)).
func replaceKeepingStat(t *testing.T, path, content string, how replaceMode) {
	t.Helper()
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if before.Size() != int64(len(content)) {
		t.Fatalf("replacement is %d bytes, %s is %d", len(content), path, before.Size())
	}
	oldCtime := before.Sys().(*syscall.Stat_t).Ctim.Nano()
	restore := func(p string) {
		t.Helper()
		if err := os.Chmod(p, before.Mode().Perm()); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, before.ModTime(), before.ModTime()); err != nil {
			t.Fatal(err)
		}
	}
	switch how {
	case replaceByRename:
		next := path + ".next"
		if err := os.WriteFile(next, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		restore(next)
		if err := os.Rename(next, path); err != nil {
			t.Fatal(err)
		}
	case replaceInPlace:
		deadline := time.Now().Add(2 * time.Second)
		for {
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			restore(path)
			after, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if after.Sys().(*syscall.Stat_t).Ctim.Nano() != oldCtime {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("ctime of %s did not move within 2s", path)
			}
			time.Sleep(time.Millisecond)
		}
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode() != before.Mode() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("replacement changed mode, size or mtime: %v %d %v, was %v %d %v",
			after.Mode(), after.Size(), after.ModTime(), before.Mode(), before.Size(), before.ModTime())
	}
}

// TestProbeInstalled_CachedVerdictFollowsAReplacementKeepingSizeAndMtime
// pins that a probe target swapped for a same-mode, same-size file with its
// mtime put back is probed again rather than served from the cache.
func TestProbeInstalled_CachedVerdictFollowsAReplacementKeepingSizeAndMtime(t *testing.T) {
	cases := map[string]replaceMode{
		"renamed over":       replaceByRename,
		"rewritten in place": replaceInPlace,
	}
	for name, how := range cases {
		t.Run(name, func(t *testing.T) {
			e := newTestEngine(t, nil)
			captureLogs(e)
			writeStub(t, e, "tool", "echo 1.0.0")
			tool := Tool{Source: SourceManual, VersionArgs: []string{"--version"}}
			status := ToolStatus{InstalledVersion: "1.0.0", Bins: []string{"tool"}}
			if v := e.probeTool("tool", &tool, &status); !v.OK {
				t.Fatalf("probe of the original = %+v, want OK", v)
			}

			replaceKeepingStat(t, filepath.Join(e.binDir(), "tool"), "#!/bin/sh\necho 2.0.0\n", how)

			if v := e.probeTool("tool", &tool, &status); v.OK || v.Mode != probeModeVersion {
				t.Errorf("probe of the replacement = %+v, want not OK in version mode", v)
			}
		})
	}
}

// writeVenv lays out a uv tool venv as uv builds one: pyvenv.cfg naming
// home as the interpreter's directory
// (https://docs.python.org/3/library/venv.html) and bin/python an absolute
// link to home/python3. An empty home writes a home-less pyvenv.cfg and no
// bin/python.
func writeVenv(t *testing.T, e *Engine, venv, home string) {
	t.Helper()
	dir := filepath.Join(e.toolsDir, "python", "tools", venv)
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := "home = " + home + "\nimplementation = CPython\nuv = 0.13.6\n"
	if err := os.WriteFile(filepath.Join(dir, "pyvenv.cfg"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	if home == "" {
		return
	}
	if err := os.Symlink(filepath.Join(home, "python3"), filepath.Join(dir, "bin", "python")); err != nil {
		t.Fatal(err)
	}
}

func newInterpreterHome(t *testing.T, dir string) string {
	t.Helper()
	return interpreterHomeAt(t, dir, "cpython-3.15.2")
}

func interpreterHomeAt(t *testing.T, dir, name string) string {
	t.Helper()
	home := filepath.Join(dir, name, "bin")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "python3"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return home
}

// TestProbeInstalled_PipVenvInterpreter pins that a pip: launcher whose venv
// interpreter is gone reads as not installed, though the
// launcher file itself is intact. uv names a tool's venv after the
// normalized package name without extras
// (https://packaging.python.org/en/latest/specifications/name-normalization/).
func TestProbeInstalled_PipVenvInterpreter(t *testing.T) {
	cases := []struct {
		name       string
		ref        string
		setup      func(t *testing.T, e *Engine)
		want       bool
		wantReason string
	}{
		{
			name: "live interpreter",
			ref:  "x",
			setup: func(t *testing.T, e *Engine) {
				writeVenv(t, e, "x", newInterpreterHome(t, pythonInterpreterDir(e.toolsDir)))
			},
			want: true,
		},
		{
			name: "interpreter executable gone while home remains",
			ref:  "x",
			setup: func(t *testing.T, e *Engine) {
				home := newInterpreterHome(t, pythonInterpreterDir(e.toolsDir))
				writeVenv(t, e, "x", home)
				if err := os.Remove(filepath.Join(home, "python3")); err != nil {
					t.Fatal(err)
				}
			},
			want: false, wantReason: filepath.Join("x", "bin", "python"),
		},
		{
			name: "venv without its python link",
			ref:  "x",
			setup: func(t *testing.T, e *Engine) {
				home := newInterpreterHome(t, pythonInterpreterDir(e.toolsDir))
				writeVenv(t, e, "x", home)
				if err := os.Remove(filepath.Join(e.toolsDir, "python", "tools", "x", "bin", "python")); err != nil {
					t.Fatal(err)
				}
			},
			want: false, wantReason: filepath.Join("x", "bin", "python"),
		},
		{
			name: "python link resolving through a link chain",
			ref:  "x",
			setup: func(t *testing.T, e *Engine) {
				home := newInterpreterHome(t, pythonInterpreterDir(e.toolsDir))
				minor := filepath.Join(filepath.Dir(filepath.Dir(home)), "cpython-3.15")
				if err := os.Symlink(filepath.Dir(home), minor); err != nil {
					t.Fatal(err)
				}
				writeVenv(t, e, "x", filepath.Join(minor, "bin"))
			},
			want: true,
		},
		{
			name: "interpreter gone",
			ref:  "x",
			setup: func(t *testing.T, e *Engine) {
				writeVenv(t, e, "x", filepath.Join(t.TempDir(), "cpython-3.14.7", "bin"))
			},
			want: false, wantReason: "cpython-3.14.7",
		},
		{
			name: "copied interpreter whose home is gone",
			ref:  "x",
			setup: func(t *testing.T, e *Engine) {
				writeVenv(t, e, "x", "")
				venv := filepath.Join(e.toolsDir, "python", "tools", "x")
				cfg := "home = " + filepath.Join(t.TempDir(), "cpython-3.14.7", "bin") + "\n"
				if err := os.WriteFile(filepath.Join(venv, "pyvenv.cfg"), []byte(cfg), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(venv, "bin", "python"), []byte("#!/bin/sh\n"), 0o755); err != nil {
					t.Fatal(err)
				}
			},
			want: false, wantReason: "cpython-3.14.7",
		},
		{
			name: "normalized venv name without extras",
			ref:  "Ruamel.Yaml__Clib[cli]",
			setup: func(t *testing.T, e *Engine) {
				writeVenv(t, e, "ruamel-yaml-clib", filepath.Join(t.TempDir(), "gone"))
			},
			want: false, wantReason: "gone",
		},
		{
			name: "interpreter outside the managed dir",
			ref:  "x",
			setup: func(t *testing.T, e *Engine) {
				writeVenv(t, e, "x", newInterpreterHome(t, t.TempDir()))
			},
			want: false, wantReason: "is outside",
		},
		{
			name: "interpreter in a sibling dir sharing the managed dir's name prefix",
			ref:  "x",
			setup: func(t *testing.T, e *Engine) {
				writeVenv(t, e, "x", newInterpreterHome(t, pythonInterpreterDir(e.toolsDir)+"-old"))
			},
			want: false, wantReason: "is outside",
		},
		{
			name: "managed dir reached through a link",
			ref:  "x",
			setup: func(t *testing.T, e *Engine) {
				managed := pythonInterpreterDir(e.toolsDir)
				if err := os.RemoveAll(managed); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Dir(managed), 0o755); err != nil {
					t.Fatal(err)
				}
				target := t.TempDir()
				if err := os.Symlink(target, managed); err != nil {
					t.Fatal(err)
				}
				writeVenv(t, e, "x", newInterpreterHome(t, target))
			},
			want: true,
		},
		{
			name:  "no venv falls back to the exec probe",
			ref:   "x",
			setup: func(*testing.T, *Engine) {},
			want:  true,
		},
		{
			name: "pyvenv.cfg without home is decided by the python link",
			ref:  "x",
			setup: func(t *testing.T, e *Engine) {
				writeVenv(t, e, "x", "")
				python := filepath.Join(newInterpreterHome(t, pythonInterpreterDir(e.toolsDir)), "python3")
				if err := os.Symlink(python, filepath.Join(e.toolsDir, "python", "tools", "x", "bin", "python")); err != nil {
					t.Fatal(err)
				}
			},
			want: true,
		},
		{
			name: "a venv bin link leaving the tool dir is not followed",
			ref:  "x",
			setup: func(t *testing.T, e *Engine) {
				writeVenv(t, e, "x", "")
				bin := filepath.Join(e.toolsDir, "python", "tools", "x", "bin")
				if err := os.Remove(bin); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(t.TempDir(), bin); err != nil {
					t.Fatal(err)
				}
			},
			want: true,
		},
		{
			name: "a venv link leaving the tool dir is not read",
			ref:  "x",
			setup: func(t *testing.T, e *Engine) {
				outside := t.TempDir()
				cfg := "home = " + filepath.Join(outside, "gone") + "\n"
				if err := os.WriteFile(filepath.Join(outside, "pyvenv.cfg"), []byte(cfg), 0o644); err != nil {
					t.Fatal(err)
				}
				tools := filepath.Join(e.toolsDir, "python", "tools")
				if err := os.MkdirAll(tools, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Join(tools, "x")); err != nil {
					t.Fatal(err)
				}
			},
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEngine(t, nil)
			captureLogs(e)
			writeStub(t, e, "x", "echo x 1.0.0")
			tc.setup(t, e)
			tool := Tool{Source: "pip:" + tc.ref}
			status := ToolStatus{InstalledVersion: "1.0.0", PMBins: []string{"x"}}

			got := e.probeTool("x", &tool, &status)

			if got.OK != tc.want {
				t.Errorf("probe OK = %v (%s: %s), want %v", got.OK, got.Mode, got.Reason, tc.want)
			}
			if tc.wantReason != "" && !strings.Contains(got.Reason, tc.wantReason) {
				t.Errorf("probe reason = %q, want it to carry %q", got.Reason, tc.wantReason)
			}
		})
	}
}

// TestProbeInstalled_CachedVerdictDoesNotOutliveTheInterpreter pins that
// removing a venv's interpreter is noticed on the next probe, though the
// launcher (the cache's fingerprint) is unchanged.
func TestProbeInstalled_CachedVerdictDoesNotOutliveTheInterpreter(t *testing.T) {
	cases := map[string]func(home string) error{
		"home removed":                   os.RemoveAll,
		"interpreter executable removed": func(home string) error { return os.Remove(filepath.Join(home, "python3")) },
	}
	for name, remove := range cases {
		t.Run(name, func(t *testing.T) {
			e := newTestEngine(t, nil)
			captureLogs(e)
			writeStub(t, e, "x", "echo x 1.0.0")
			home := newInterpreterHome(t, pythonInterpreterDir(e.toolsDir))
			writeVenv(t, e, "x", home)
			tool := Tool{Source: "pip:x", VersionArgs: []string{"--version"}}
			status := ToolStatus{InstalledVersion: "1.0.0", PMBins: []string{"x"}}
			if v := e.probeTool("x", &tool, &status); !v.OK {
				t.Fatalf("probe with a live interpreter = %+v, want OK", v)
			}

			if err := remove(home); err != nil {
				t.Fatal(err)
			}

			if v := e.probeTool("x", &tool, &status); v.OK || !strings.Contains(v.Reason, "venv interpreter") {
				t.Errorf("probe after the interpreter was removed = %+v, want not OK naming the venv interpreter", v)
			}
		})
	}
}

// TestProbeInstalled_CachedVerdictFollowsTheInterpreter pins that a change
// to the interpreter a live venv links to is noticed on the next probe,
// though the launcher is unchanged. The launcher runs through the venv's
// bin/python as uv writes it, so the kernel refuses it once the
// interpreter cannot execute (execve(2), EACCES).
func TestProbeInstalled_CachedVerdictFollowsTheInterpreter(t *testing.T) {
	cases := []struct {
		change   func(t *testing.T, python string)
		name     string
		wantMode string
	}{
		{
			name: "interpreter loses its execute bit",
			change: func(t *testing.T, python string) {
				if err := os.Chmod(python, 0o644); err != nil {
					t.Fatal(err)
				}
			},
			wantMode: probeModeExec,
		},
		{
			name: "interpreter replaced in place",
			change: func(t *testing.T, python string) {
				fi, err := os.Stat(python)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(python, []byte("#!/bin/sh\necho x 2.0.0\n"), 0o755); err != nil {
					t.Fatal(err)
				}
				later := fi.ModTime().Add(time.Second)
				if err := os.Chtimes(python, later, later); err != nil {
					t.Fatal(err)
				}
			},
			wantMode: probeModeVersion,
		},
		{
			name: "interpreter renamed over, keeping mode, size and mtime",
			change: func(t *testing.T, python string) {
				replaceKeepingStat(t, python, "#!/bin/sh\necho x 2.0.0\n", replaceByRename)
			},
			wantMode: probeModeVersion,
		},
		{
			name: "interpreter rewritten in place, keeping mode, size and mtime",
			change: func(t *testing.T, python string) {
				replaceKeepingStat(t, python, "#!/bin/sh\necho x 2.0.0\n", replaceInPlace)
			},
			wantMode: probeModeVersion,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEngine(t, nil)
			captureLogs(e)
			home := newInterpreterHome(t, pythonInterpreterDir(e.toolsDir))
			python := filepath.Join(home, "python3")
			if err := os.WriteFile(python, []byte("#!/bin/sh\necho x 1.0.0\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			writeVenv(t, e, "x", home)
			venvPython := filepath.Join(e.toolsDir, "python", "tools", "x", "bin", "python")
			if err := os.WriteFile(filepath.Join(e.binDir(), "x"), []byte("#!"+venvPython+"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			tool := Tool{Source: "pip:x", VersionArgs: []string{"--version"}}
			status := ToolStatus{InstalledVersion: "1.0.0", PMBins: []string{"x"}}
			if v := e.probeTool("x", &tool, &status); !v.OK || v.Mode != probeModeVersion {
				t.Fatalf("probe with a live interpreter = %+v, want OK in version mode", v)
			}

			tc.change(t, python)

			v := e.probeTool("x", &tool, &status)
			if v.OK || v.Mode != tc.wantMode {
				t.Errorf("probe after the interpreter changed = %+v, want not OK, mode %q", v, tc.wantMode)
			}
		})
	}
}

// TestProbeBin_PicksOneTarget pins which bin the probe executes: the
// declared probe name, else the derived one, else the first recorded bin —
// never one subprocess per recorded name.
func TestProbeBin_PicksOneTarget(t *testing.T) {
	cases := []struct {
		name string
		tool Tool
		bins []string
		want string
	}{
		{name: "gopls", tool: Tool{}, bins: []string{"gopls"}, want: "gopls"},
		{name: "typescript", tool: Tool{}, bins: []string{"tsc", "tsserver"}, want: "tsc"},
		{name: "x", tool: Tool{Probe: "custom"}, bins: []string{"a", "b"}, want: "custom"},
		{name: "@scope/pkg", tool: Tool{}, bins: nil, want: "pkg"},
		{name: "pyright", tool: Tool{}, bins: []string{"pyright", "pyright-langserver"}, want: "pyright"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := probeBin(tc.name, &tc.tool, tc.bins); got != tc.want {
				t.Fatalf("probeBin(%q, %v) = %q, want %q", tc.name, tc.bins, got, tc.want)
			}
		})
	}
}

// TestVersionAnswered pins the version-answer comparison: upstream
// banners disagree about the v prefix and case, a longer number the
// recorded version is a substring of fails, and any text after the
// version's boundary (a label, a commit hash, a platform) still matches.
func TestVersionAnswered(t *testing.T) {
	cases := []struct {
		out  string
		want string
		ok   bool
	}{
		{out: "jq-1.8.1", want: "1.8.1", ok: true},
		{out: "go version go1.26.5 linux/amd64", want: "go1.26.5", ok: true},
		{out: "v24.18.0", want: "v24.18.0", ok: true},
		{out: "24.18.0", want: "v24.18.0", ok: true},
		{out: "V1.2.3", want: "1.2.3", ok: true},
		{out: "ripgrep 14.1.1 (rev 4649aa9700)", want: "14.1.1", ok: true},
		{out: "jq-1.8.1-dirty", want: "1.8.1", ok: true},
		{out: "1.2.30", want: "1.2.3", ok: false},
		{out: "11.2.3", want: "1.2.3", ok: false},
		{out: "1.2.3.4", want: "1.2.3", ok: false},
		{out: "0.1.2.3", want: "1.2.3", ok: false},
		{out: "v1.2.3", want: "1.2", ok: false},
		{out: "go version go1.26.50 linux/amd64", want: "go1.26.5", ok: false},
		{out: "tool 11.2.3, built against 1.2.3", want: "1.2.3", ok: true},
		{out: "1.2.31", want: "1.2.3", ok: false},
		{out: "tool 1.2.3.0", want: "1.2.3", ok: false},
		{out: "tool 21.2.3-rc1", want: "1.2.3", ok: false},
		{out: "tool v1.2.30-a1bdbde", want: "v1.2.3", ok: false},
		{out: "hugo v0.147.9-a1bdbde19c+extended linux/amd64", want: "v0.147.9", ok: true},
		{out: "jj 0.35.0-c3e1f0a9b7", want: "0.35.0", ok: true},
		{out: "tool 1.2.3-rc1", want: "1.2.3", ok: true},
		{out: "tool 1.2.3rc1", want: "1.2.3", ok: true},
		{out: "tool 1.2.3-snapshot", want: "1.2.3", ok: true},
		{out: "tool 1.2.3.post1", want: "1.2.3", ok: true},
		{out: "tool 1.2.3-amd64", want: "1.2.3", ok: true},
		{out: "tool 1.2.3 (built by alice)", want: "1.2.3", ok: true},
		{out: "tool 1.2.3-rc.1", want: "1.2.3-rc.1", ok: true},
		{out: "9.9.9", want: "1.2.3", ok: false},
		{out: "", want: "1.2.3", ok: false},
		{out: "anything", want: "", ok: true},
	}
	for _, tc := range cases {
		t.Run(strings.ReplaceAll(tc.out, "/", "_")+" against "+tc.want, func(t *testing.T) {
			if got := versionAnswered(tc.out, tc.want); got != tc.ok {
				t.Fatalf("versionAnswered(%q, %q) = %v, want %v", tc.out, tc.want, got, tc.ok)
			}
		})
	}
}

// TestCappedBuffer_BoundsProbeOutput: a tool that ignores --version and
// streams must not be able to grow the engine's heap.
func TestCappedBuffer_BoundsProbeOutput(t *testing.T) {
	var b cappedBuffer
	chunk := strings.Repeat("x", 8<<10)
	for range 32 {
		if n, err := b.Write([]byte(chunk)); n != len(chunk) || err != nil {
			t.Fatalf("Write = %d, %v", n, err)
		}
	}
	if got := len(b.String()); got != probeOutputCap {
		t.Fatalf("buffered %d bytes, want the %d cap", got, probeOutputCap)
	}
}
