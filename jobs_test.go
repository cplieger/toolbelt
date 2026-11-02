package toolbelt

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"testing"
	"testing/synctest"
	"time"
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

// TestJobQueue_TerminalViewsSurviveTheRecentWindow pins a late Wait. The
// recent ring is bounded for the jobs endpoint, so a burst longer than it
// pushes early jobs out of history, and a caller that starts Wait after
// its job ended must still collect the result, not be told its job never
// existed.
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

// TestJobQueue_ReservationHoldsItsPlaceUnseen pins the transaction Add,
// Patch and Remove stand on: a reserved job counts against the cap and
// keeps its place in the run order, but no reader sees it and the worker,
// free to run, waits for its publish; a released one leaves no trace.
func TestJobQueue_ReservationHoldsItsPlaceUnseen(t *testing.T) {
	ran := make(chan string, jobQueueCap+3)
	unblock := make(chan struct{})
	var q *jobQueue
	q = newLineQueue(t, func(j *job, _ func(string)) error {
		q.mu.Lock()
		reserved := j.reserved
		q.mu.Unlock()
		if reserved {
			t.Errorf("job %v ran while reserved", j.names)
		}
		if j.names[0] == "busy" {
			<-unblock
		}
		ran <- j.names[0]
		return nil
	})

	busy, err := q.Enqueue(JobKindInstall, []string{"busy"})
	if err != nil {
		t.Fatalf("Setup: Enqueue: %v", err)
	}
	res, err := q.reserve(JobKindInstall, []string{"reserved"}, nil)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	later, err := q.Enqueue(JobKindInstall, []string{"later"})
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	// Once busy is collected the worker has moved on to the queue's head.
	close(unblock)
	if v, err := q.Wait(t.Context(), busy.ID); err != nil || v.State != JobDone {
		t.Fatalf("Setup: Wait(busy) = %+v, %v", v, err)
	}
	if _, err := q.Wait(t.Context(), res.id); !errors.Is(err, ErrUnknownJob) {
		t.Errorf("Wait on the reserved job = %v, want ErrUnknownJob (unseen)", err)
	}
	if q.Cancel(res.id) {
		t.Error("Cancel reached the reserved job, want it unseen")
	}
	if set := q.InstallingSet(); set["reserved"] {
		t.Errorf("InstallingSet = %v, want the reserved job left out", set)
	}
	if a := q.Active(); a == nil || a.ID != later.ID || a.State != JobQueued {
		t.Errorf("Active = %+v, want %s still queued behind the reservation", a, later.ID)
	}

	published := q.publish(res)
	if published.ID != res.id || published.State != JobQueued {
		t.Errorf("publish = %+v, want %s queued", published, res.id)
	}
	for _, id := range []string{published.ID, later.ID} {
		if v, err := q.Wait(t.Context(), id); err != nil || v.State != JobDone {
			t.Fatalf("Wait(%s) = %+v, %v, want done", id, v, err)
		}
	}
	if order := []string{<-ran, <-ran, <-ran}; !slices.Equal(order, []string{"busy", "reserved", "later"}) {
		t.Errorf("run order = %q, want busy, then the reservation, then later", order)
	}

	t.Run("a reservation counts against the cap until released", func(t *testing.T) {
		held := make([]*job, 0, jobQueueCap)
		for range jobQueueCap {
			r, err := q.reserve(JobKindInstall, []string{"held"}, nil)
			if err != nil {
				t.Fatalf("Setup: reserve: %v", err)
			}
			held = append(held, r)
		}
		if _, err := q.Enqueue(JobKindInstall, []string{"over"}); !errors.Is(err, ErrQueueFull) {
			t.Errorf("Enqueue past reserved slots = %v, want ErrQueueFull", err)
		}
		for _, r := range held {
			q.release(r)
		}
		jv, err := q.Enqueue(JobKindInstall, []string{"after"})
		if err != nil {
			t.Fatalf("Enqueue after release: %v", err)
		}
		if v, err := q.Wait(t.Context(), jv.ID); err != nil || v.State != JobDone {
			t.Errorf("Wait after release = %+v, %v, want done", v, err)
		}
		if got := <-ran; got != "after" {
			t.Errorf("ran %q after the releases, want after", got)
		}
	})
}

func TestJobQueue_PublishAfterCloseIsCancelled(t *testing.T) {
	q := newLineQueue(t, func(*job, func(string)) error { return nil })
	res, err := q.reserve(JobKindInstall, []string{"tool"}, nil)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	q.Close()
	if _, recent := q.Snapshot(); len(recent) != 0 {
		t.Errorf("history after Close = %+v, want the reservation unseen until publish", recent)
	}

	v := q.publish(res)
	if v.State != JobCancelled || v.CancelCause != CancelShutdown {
		t.Errorf("publish after Close = state %s cause %v, want cancelled by shutdown", v.State, v.CancelCause)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if final, err := q.Wait(ctx, v.ID); err != nil || final.State != JobCancelled {
		t.Errorf("Wait = %+v, %v, want the cancelled view", final, err)
	}
}

// TestJobQueue_WaitKeepsItsJobThroughABurstPastTheHistory pins that a
// caller already blocked in Wait (EnsureInstalled, a boot gate) receives
// its job's result however many jobs finish after it: the bounded
// terminal history may drop the job's id, never a live waiter's answer.
func TestJobQueue_WaitKeepsItsJobThroughABurstPastTheHistory(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// More than the terminal history keeps, so the waited job's id is
		// gone from it by the time the burst ends.
		const burst = 4*jobHistory + 5
		gate := make(chan struct{})
		finished := make(chan string, burst+1)
		q := newJobQueue(
			func(v *Job) {
				if v.State == JobDone {
					finished <- v.ID // buffered: the callback runs under the queue lock
				}
			},
			nil, slog.New(&logCapture{}),
			func(_ context.Context, j *job, _ func(string)) error {
				if j.names[0] == "waited" {
					<-gate
				}
				return nil
			},
		)
		t.Cleanup(q.Close)

		waited, err := q.Enqueue(JobKindInstall, []string{"waited"})
		if err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
		type result struct {
			v   *Job
			err error
		}
		got := make(chan result, 1)
		go func() {
			v, err := q.Wait(t.Context(), waited.ID)
			got <- result{v, err}
		}()
		synctest.Wait() // the worker is parked on the gate, Wait on the job
		close(gate)
		<-finished
		for range burst {
			if _, err := q.Enqueue(JobKindInstall, []string{"burst"}); err != nil {
				t.Fatalf("Enqueue: %v", err)
			}
			<-finished
		}

		r := <-got
		if r.err != nil {
			t.Fatalf("Wait after a %d-job burst: %v, want the waited job's result", burst, r.err)
		}
		if r.v.ID != waited.ID || r.v.State != JobDone {
			t.Errorf("Wait = %s %s, want %s done", r.v.ID, r.v.State, waited.ID)
		}
	})
}

// TestJobQueue_WaitPrefersAFinishedJobToACancelledContext pins the order a
// boot gate relies on: a job that already ended returns its result even
// when the caller's context is gone.
func TestJobQueue_WaitPrefersAFinishedJobToACancelledContext(t *testing.T) {
	q := newLineQueue(t, func(*job, func(string)) error { return nil })
	jv, err := q.Enqueue(JobKindInstall, []string{"tool"})
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if _, err := q.Wait(t.Context(), jv.ID); err != nil {
		t.Fatalf("Setup: Wait: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	v, err := q.Wait(ctx, jv.ID)
	if err != nil {
		t.Fatalf("Wait with a cancelled context on a finished job: %v, want its result", err)
	}
	if v.State != JobDone {
		t.Errorf("Wait = %s, want %s", v.State, JobDone)
	}
}

// TestJobQueue_CloseReleasesAWaiterOnAQueuedJob pins that shutdown answers
// a waiter whose job never ran: it gets the job cancelled by shutdown, not
// a block until its own context expires.
func TestJobQueue_CloseReleasesAWaiterOnAQueuedJob(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q := newJobQueue(nil, nil, slog.New(&logCapture{}),
			func(ctx context.Context, j *job, _ func(string)) error {
				if j.names[0] == "busy" {
					<-ctx.Done() // runs until Close cancels it
					return ctx.Err()
				}
				return nil
			})
		t.Cleanup(q.Close)
		if _, err := q.Enqueue(JobKindInstall, []string{"busy"}); err != nil {
			t.Fatalf("Setup: Enqueue: %v", err)
		}
		queued, err := q.Enqueue(JobKindInstall, []string{"queued"})
		if err != nil {
			t.Fatalf("Setup: Enqueue: %v", err)
		}
		type result struct {
			v   *Job
			err error
		}
		got := make(chan result, 1)
		go func() {
			v, err := q.Wait(t.Context(), queued.ID)
			got <- result{v, err}
		}()
		synctest.Wait() // the worker runs busy, Wait is parked on queued

		q.Close()
		r := <-got
		if r.err != nil {
			t.Fatalf("Wait on a queued job across Close: %v, want its cancelled view", r.err)
		}
		if r.v.State != JobCancelled || r.v.CancelCause != CancelShutdown {
			t.Errorf("Wait = state %s cause %v, want cancelled by shutdown", r.v.State, r.v.CancelCause)
		}
	})
}
