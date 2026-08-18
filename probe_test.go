package toolbelt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeStub writes an executable shell stub into the engine's bin dir.
func writeStub(t *testing.T, e *Engine, name, body string) string {
	t.Helper()
	p := filepath.Join(e.binDir(), name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestProbeInstalled_ExecutesTheTool pins install detection: presence of
// bin/<name> is not proof. The probe executes the tool, and when the
// definition declares its version-reporting shape the answer must carry
// the recorded version — so a file that only exists, a corrupt or
// wrong-architecture binary, a dangling link into a pruned version tree,
// and a binary left at the wrong version all read as NOT installed
// (routing them to a reinstall). A recorded bin that cannot be executed
// at all falls back to presence and says so at Warn.
//
// It also pins the CannotExec split, which is what an install's own
// verification acts on: the binary was never entered (ENOEXEC, or the
// loader's exit 127) versus every other verdict, where the tool ran and
// this engine merely could not grade the answer.
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
			want: false,
		},
		{
			name: "nothing installed at all",
			setup: func(*testing.T, *Engine) (Tool, ToolStatus) {
				return Tool{Source: SourceManual}, ToolStatus{}
			},
			want: false,
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
