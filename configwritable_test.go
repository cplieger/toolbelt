package toolbelt

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/cplieger/atomicfile/v4"
)

// probeCall records what New asked the config-dir probe for.
type probeCall struct {
	dir  string
	opts []atomicfile.Option
}

// stubProbe replaces the config-dir probe for one test. A root test process
// writes through a 0o555 directory, so a refused probe has to be staged.
func stubProbe(t *testing.T, res atomicfile.ProbeResult) *[]probeCall {
	t.Helper()
	orig := probeWritable
	t.Cleanup(func() { probeWritable = orig })
	var calls []probeCall
	probeWritable = func(_ context.Context, dir string, opts ...atomicfile.Option) (atomicfile.ProbeResult, error) {
		calls = append(calls, probeCall{dir: dir, opts: opts})
		res.Dir = dir
		return res, nil
	}
	return &calls
}

// seededConfigDir returns a ConfigDir that already holds a manifest, the case
// New writes nothing for.
func seededConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	e, err := New(&Config{ConfigDir: dir, ToolsDir: filepath.Join(dir, "tools")})
	if err != nil {
		t.Fatalf("Setup: first New: %v", err)
	}
	e.Close()
	return dir
}

func TestNew_RefusesUnwritableConfigDir(t *testing.T) {
	modeErr := fmt.Errorf("%w: probe: asked for 0600, filesystem stored 0670", atomicfile.ErrModeNotStored)
	cases := []struct {
		name     string
		res      atomicfile.ProbeResult
		wantIs   error
		wantText string
	}{
		{
			name:     "read_only_volume",
			res:      atomicfile.ProbeResult{Stage: atomicfile.ProbeStageCreate, Err: syscall.EROFS},
			wantIs:   syscall.EROFS,
			wantText: "is not writable (create probe file failed)",
		},
		{
			name:     "mode_widening_acl",
			res:      atomicfile.ProbeResult{Stage: atomicfile.ProbeStageCreate, Err: modeErr},
			wantIs:   atomicfile.ErrModeNotStored,
			wantText: "cannot keep an owner-only staging file, typically because an inherited ACL",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := seededConfigDir(t)
			calls := stubProbe(t, tc.res)
			e, err := New(&Config{ConfigDir: dir, ToolsDir: filepath.Join(dir, "tools")})
			if err == nil {
				e.Close()
				t.Fatalf("New(ConfigDir=%q) with probe %v = nil error, want refusal", dir, tc.res.Err)
			}
			if !errors.Is(err, tc.wantIs) {
				t.Errorf("New error = %v, want errors.Is %v", err, tc.wantIs)
			}
			if !strings.Contains(err.Error(), dir) || !strings.Contains(err.Error(), tc.wantText) {
				t.Errorf("New error = %q, want it to name %q and contain %q", err, dir, tc.wantText)
			}
			if len(*calls) != 1 || (*calls)[0].dir != dir {
				t.Errorf("probe calls = %+v, want one for %q", *calls, dir)
			}
		})
	}
}

// TestNew_WarnsOnProbeTeardownFailure: a probe that wrote and flushed but
// could not unlink proves the store's rename-published writes will succeed.
func TestNew_WarnsOnProbeTeardownFailure(t *testing.T) {
	dir := seededConfigDir(t)
	stubProbe(t, atomicfile.ProbeResult{
		Stage: atomicfile.ProbeStageRemove, Err: syscall.EBUSY, Name: ".probe-leftover", Leaked: true,
	})
	logs := &logCapture{}
	e, err := New(&Config{ConfigDir: dir, ToolsDir: filepath.Join(dir, "tools"), Logger: slog.New(logs)})
	if err != nil {
		t.Fatalf("New(ConfigDir=%q) with a teardown-only probe failure = %v, want success", dir, err)
	}
	e.Close()
	if !logs.has("WARN", "dir="+dir, "stage=remove probe file", "name=.probe-leftover", "leaked=true") {
		t.Errorf("logs = %q, want a WARN naming dir, stage, name and leaked", logs.lines)
	}
}

// TestNew_ProbesConfigDirWithEngineFileMode replays the probe's options
// through a real write over a 0o600 baseline, so options that drop
// WithMode(engineFileMode) leave the replayed file at 0o600.
func TestNew_ProbesConfigDirWithEngineFileMode(t *testing.T) {
	dir := seededConfigDir(t)
	calls := stubProbe(t, atomicfile.ProbeResult{})
	e, err := New(&Config{ConfigDir: dir, ToolsDir: filepath.Join(dir, "tools")})
	if err != nil {
		t.Fatalf("New(ConfigDir=%q) = %v, want success", dir, err)
	}
	e.Close()
	if len(*calls) != 1 {
		t.Fatalf("probe calls = %d, want 1", len(*calls))
	}
	replay := filepath.Join(t.TempDir(), "replay")
	opts := append([]atomicfile.Option{atomicfile.WithMode(0o600)}, (*calls)[0].opts...)
	if _, err := atomicfile.WriteFile(t.Context(), replay, []byte("x"), opts...); err != nil {
		t.Fatalf("Setup: replay write: %v", err)
	}
	info, err := os.Stat(replay)
	if err != nil {
		t.Fatalf("Setup: stat replay: %v", err)
	}
	if got := info.Mode().Perm(); got != engineFileMode {
		t.Errorf("replayed probe options wrote mode %v, want %v", got, engineFileMode)
	}
}
