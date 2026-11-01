package toolbelt

import (
	"os"
	"path/filepath"
	"strings"
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

// writeNpmPackage writes pkg's package.json where npm's global install puts
// it under the engine's npm prefix.
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
// link, or the wrong version all read as NOT installed. It also pins
// the CannotExec split: the binary was never entered (exit 127) versus
// every other verdict, where the tool ran and this engine merely could
// not grade the answer.
func TestProbeInstalled_ExecutesTheTool(t *testing.T) {
	cases := []struct {
		name           string
		setup          func(t *testing.T, e *Engine) (Tool, ToolStatus)
		want           bool
		wantMode       string
		wantWarning    string
		wantCannotExec bool
		wantReason     string
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
			wantCannotExec: true,
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
			wantCannotExec: true, wantReason: "libatomic.so.1",
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
			// NOT CannotExec: a language server that ignores --version
			// and blocks has started, so a timeout must not fail an
			// install the way an unrunnable binary does.
			want: false, wantMode: probeModeExec, wantWarning: "probe failed",
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
			if got.CannotExec != tc.wantCannotExec {
				t.Errorf("probe CannotExec = %v, want %v (reason %q)", got.CannotExec, tc.wantCannotExec, got.Reason)
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
// banners disagree about the v prefix and case, so containment on the
// trimmed version is the contract.
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
		{out: "1.2.30", want: "1.2.3", ok: true}, // containment: deliberately lenient
		{out: "9.9.9", want: "1.2.3", ok: false},
		{out: "", want: "1.2.3", ok: false},
		{out: "anything", want: "", ok: true},
	}
	for _, tc := range cases {
		t.Run(tc.out+"/"+tc.want, func(t *testing.T) {
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
