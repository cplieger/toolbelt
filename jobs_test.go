package toolbelt

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"testing"
)

// newLineQueue builds a queue whose jobs run the given body. The body
// receives the same output callback the real executor does, so a job's
// retained output goes through the production path.
func newLineQueue(t *testing.T, body func(j *job, output func(string)) error) *jobQueue {
	t.Helper()
	q := newJobQueue(nil, nil, slog.New(&logCapture{}),
		func(_ context.Context, j *job, output func(string)) error { return body(j, output) })
	t.Cleanup(q.Close)
	return q
}

// TestJobOutput_KeepsTheMostRecentWindow pins the reload-resume buffer: a
// chatty install (npm prints thousands of lines) must neither grow the
// retained output without bound nor hand the panel its lines out of
// order once the window has wrapped.
func TestJobOutput_KeepsTheMostRecentWindow(t *testing.T) {
	// Two lines past the window, so the buffer has wrapped and the two
	// oldest lines are gone.
	const emitted = jobRingLines + 2
	q := newLineQueue(t, func(_ *job, output func(string)) error {
		for i := 1; i <= emitted; i++ {
			output(fmt.Sprintf("line-%d", i))
		}
		return nil
	})

	jv, err := q.Enqueue(JobKindInstall, []string{"tool"})
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	final, err := q.Wait(t.Context(), jv.ID)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}

	tail := final.OutputTail
	if len(tail) != jobRingLines {
		t.Fatalf("OutputTail after %d lines = %d lines, want the %d-line window", emitted, len(tail), jobRingLines)
	}
	if tail[0] != "line-3" {
		t.Errorf("OutputTail[0] = %q, want line-3 (the two oldest lines fell out)", tail[0])
	}
	if got := tail[len(tail)-1]; got != fmt.Sprintf("line-%d", emitted) {
		t.Errorf("OutputTail[last] = %q, want line-%d", got, emitted)
	}
}

// TestInstallingSet_ReportsAJobBeforeItHasResolvedAPlan pins the per-row
// installing flag across the window the plan is being resolved in: the
// names the caller asked for hold the flag until the worker publishes the
// plan, and the plan replaces them once it exists (an adopted or
// auto-enabled dependency shows as installing too, instead of sitting
// there as an inert not-installed row while its download runs).
func TestInstallingSet_ReportsAJobBeforeItHasResolvedAPlan(t *testing.T) {
	resolved := make(chan struct{})
	release := make(chan struct{})
	beforePlan := make(chan map[string]bool, 1)
	var q *jobQueue
	q = newLineQueue(t, func(j *job, _ func(string)) error {
		beforePlan <- q.InstallingSet()
		q.setCovers(j, []string{"tool", "runtime"})
		close(resolved)
		<-release
		return nil
	})

	if _, err := q.Enqueue(JobKindInstall, []string{"tool"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	before := <-beforePlan
	if !before["tool"] {
		t.Errorf("InstallingSet before the plan = %v, want the requested name in it", before)
	}
	<-resolved
	after := q.InstallingSet()
	close(release)
	if !after["tool"] || !after["runtime"] {
		t.Errorf("InstallingSet after the plan = %v, want tool and runtime", after)
	}
}

// TestJobQueue_TerminalViewsSurviveTheRecentWindow pins what Wait stands
// on. The recent ring is bounded for the jobs endpoint, so a burst longer
// than it pushes early jobs out of history — and a caller blocked in
// EnsureInstalled or a boot gate must still be able to collect its
// result, not be told its job never existed.
func TestJobQueue_TerminalViewsSurviveTheRecentWindow(t *testing.T) {
	// Exactly the terminal map's retention bound: the first job must
	// still be there when the last one lands.
	const burst = 4 * jobHistory
	finished := make(chan string, burst)
	q := newJobQueue(
		func(v *Job) {
			if v.State == JobDone {
				finished <- v.ID // buffered: the callback runs under the queue lock
			}
		},
		nil, slog.New(&logCapture{}),
		func(context.Context, *job, func(string)) error { return nil },
	)
	t.Cleanup(q.Close)

	// One enqueue per completion keeps the queue under its pending cap,
	// and the notification fires after the terminal view is recorded, so
	// all burst jobs are accounted for when the loop ends.
	ids := make([]string, 0, burst)
	for range burst {
		jv, err := q.Enqueue(JobKindInstall, []string{"tool"})
		if err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
		ids = append(ids, jv.ID)
		<-finished
	}

	first, err := q.Wait(t.Context(), ids[0])
	if err != nil {
		t.Fatalf("Wait for the first of %d finished jobs: %v", burst, err)
	}
	if first.State != JobDone {
		t.Errorf("first job state = %s, want %s", first.State, JobDone)
	}

	_, recent := q.Snapshot()
	if len(recent) != jobHistory {
		t.Errorf("Snapshot recent = %d jobs, want the %d-job history window", len(recent), jobHistory)
	}
	var recentIDs []string
	for _, r := range recent {
		recentIDs = append(recentIDs, r.ID)
	}
	if slices.Contains(recentIDs, ids[0]) {
		t.Errorf("the first of %d jobs is still in recent history: %v", burst, recentIDs)
	}
}
