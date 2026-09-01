package toolbelt

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"
)

const (
	// jobRingLines caps each job's retained output for reload-resume.
	jobRingLines = 500
	// jobQueueCap bounds queued (not yet running) jobs.
	jobQueueCap = 8
	// jobHistory bounds finished jobs kept for the jobs endpoint.
	jobHistory = 10
	// outputFlushEvery coalesces output lines into callback batches so
	// a chatty install (npm progress) can't flood the consumer.
	outputFlushEvery = 150 * time.Millisecond
	// jobTimeout bounds one job run. Generous: a reconcile job may
	// install several cold runtimes back to back.
	jobTimeout = 30 * time.Minute
)

// job is the internal mutable job record.
type job struct {
	id    string
	kind  string
	names []string
	// covers is the FULL set of tools an install job touches: the
	// requested names plus every dependency the plan pulled in. Set by
	// the worker once the plan is computed, so the per-row "installing"
	// flag reaches a dependency the user never named. Empty on jobs that
	// resolve no plan, where names is the whole answer.
	//
	// It is deliberately not merged into names: names is the REQUEST, it
	// is on the wire, and a consumer renders the job headline from it.
	covers []string
	state  string
	err    string
	// cause records WHO cancelled the job. It is written at the
	// cancellation site BEFORE the job's context is cancelled, so the
	// finalizer in runOne can attribute a cancellation it only observes
	// as a dead context. CancelUnknown until a site names it.
	cause   CancelCause
	created time.Time
	started time.Time
	ended   time.Time

	// removed carries the manifest entries an uninstall job acts on —
	// the entries are already deleted from the manifest by the time
	// the job runs, and source-specific cleanup (npm/pip uninstalls,
	// manual uninstall commands) needs them.
	removed map[string]Tool

	cancel context.CancelFunc

	// ring is the output buffer: a fixed-size window of the most
	// recent lines.
	ring  []string
	start int // ring read index
	count int
}

func (j *job) appendLine(line string) {
	if len(j.ring) < jobRingLines {
		j.ring = append(j.ring, line)
		j.count++
		return
	}
	j.ring[j.start] = line
	j.start = (j.start + 1) % jobRingLines
}

func (j *job) tail() []string {
	if j.count <= len(j.ring) && j.start == 0 {
		return append([]string{}, j.ring...)
	}
	out := make([]string, 0, len(j.ring))
	for i := range j.ring {
		out = append(out, j.ring[(j.start+i)%len(j.ring)])
	}
	return out
}

func (j *job) view(withTail bool) *Job {
	v := &Job{
		ID:          j.id,
		Kind:        j.kind,
		Names:       append([]string{}, j.names...),
		State:       j.state,
		Error:       j.err,
		CancelCause: j.cause,
		CreatedAt:   j.created.UnixMilli(),
	}
	if !j.started.IsZero() {
		v.StartedAt = j.started.UnixMilli()
	}
	if !j.ended.IsZero() {
		v.EndedAt = j.ended.UnixMilli()
	}
	if withTail {
		v.OutputTail = j.tail()
	}
	return v
}

// jobQueue serializes tool work: one job runs at a time, in order.
type jobQueue struct {
	// onChanged receives every state transition. It is called under the
	// queue lock so transitions arrive in strict order — it MUST NOT
	// block (a fan-out to slow consumers belongs behind a ring/buffer
	// on the consumer side; vibekit's SSE hub append is non-blocking).
	onChanged func(*Job)
	onOutput  func(jobID string, lines []string)
	log       *slog.Logger
	active    *job
	// terminal records every finished job's final view by id so Wait
	// can't be starved by the recent ring's cap (a >10-job burst
	// between polls would otherwise strand a waiter).
	terminal map[string]*Job
	wake     chan struct{}
	run      func(ctx context.Context, j *job, output func(string)) error
	pending  []*job
	recent   []*job
	// wg waits for the worker to exit on Close; stopped signals it to stop.
	wg      sync.WaitGroup
	nextID  int
	mu      sync.Mutex
	stopped bool
}

func newJobQueue(onChanged func(*Job), onOutput func(string, []string), log *slog.Logger,
	run func(ctx context.Context, j *job, output func(string)) error,
) *jobQueue {
	q := &jobQueue{
		onChanged: onChanged,
		onOutput:  onOutput,
		log:       log,
		run:       run,
		wake:      make(chan struct{}, 1),
	}
	q.wg.Go(q.worker)
	return q
}

// Enqueue adds a job. Returns an error when the queue is full.
func (q *jobQueue) Enqueue(kind string, names []string) (*Job, error) {
	return q.enqueue(kind, names, nil)
}

// EnqueueRemoval adds an uninstall job carrying the just-deleted
// manifest entries for source-specific cleanup.
func (q *jobQueue) EnqueueRemoval(names []string, removed map[string]Tool) (*Job, error) {
	return q.enqueue(JobKindUninstall, names, removed)
}

func (q *jobQueue) enqueue(kind string, names []string, removed map[string]Tool) (*Job, error) {
	q.mu.Lock()
	if q.stopped {
		q.mu.Unlock()
		return nil, errors.New("engine shutting down")
	}
	if len(q.pending) >= jobQueueCap {
		q.mu.Unlock()
		return nil, errors.New("too many queued tool jobs")
	}
	q.nextID++
	j := &job{
		id:      fmt.Sprintf("tj-%d-%d", time.Now().UnixMilli(), q.nextID),
		kind:    kind,
		names:   append([]string{}, names...),
		state:   JobQueued,
		created: time.Now(),
		removed: removed,
	}
	q.pending = append(q.pending, j)
	select {
	case q.wake <- struct{}{}:
	default:
	}
	view := j.view(false)
	q.notifyLocked(j)
	q.mu.Unlock()
	return view, nil
}

// noteCancelLocked attributes a cancellation to cause. Caller holds the
// queue lock. A job already in a terminal state is left alone (a late
// Close must not stamp a cancel cause on a finished job), and the
// FIRST cause wins so a race between an operator cancel and shutdown
// stays attributed to the operator.
func (j *job) noteCancelLocked(cause CancelCause) {
	if j.state != JobQueued && j.state != JobRunning {
		return
	}
	if j.cause == CancelUnknown {
		j.cause = cause
	}
}

// Cancel aborts a queued or running job by id. This is the
// Engine.CancelJob path (the httpapi cancel route and direct callers),
// so the cancellation is attributed to CancelCaller.
func (q *jobQueue) Cancel(id string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.active != nil && q.active.id == id && q.active.cancel != nil {
		q.active.noteCancelLocked(CancelCaller) // recorded before the context dies
		q.active.cancel()                       // worker finalizes state + notifies
		return true
	}
	for i, j := range q.pending {
		if j.id != id {
			continue
		}
		q.pending = append(q.pending[:i], q.pending[i+1:]...)
		q.dropQueuedLocked(j, CancelCaller)
		return true
	}
	return false
}

// dropQueuedLocked finalizes a job that never ran as cancelled, with its
// cause attributed, and publishes the transition. Caller holds mu.
func (q *jobQueue) dropQueuedLocked(j *job, cause CancelCause) {
	j.noteCancelLocked(cause)
	j.state = JobCancelled
	j.ended = time.Now()
	q.pushRecentLocked(j)
	q.notifyLocked(j)
}

// Active returns the running (or oldest queued) job, if any.
func (q *jobQueue) Active() *Job {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.active != nil {
		return q.active.view(false)
	}
	if len(q.pending) > 0 {
		return q.pending[0].view(false)
	}
	return nil
}

// Snapshot lists the active job (with output tail) and recent history.
func (q *jobQueue) Snapshot() (active *Job, recent []*Job) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.active != nil {
		active = q.active.view(true)
	} else if len(q.pending) > 0 {
		active = q.pending[0].view(true)
	}
	for _, r := range slices.Backward(q.recent) {
		recent = append(recent, r.view(true))
	}
	return active, recent
}

// InstallingSet returns the tool names covered by the active + queued
// jobs (drives the per-row "installing" flag). An install job reports
// its resolved plan once the worker has one, so an adopted or
// auto-enabled dependency shows as installing instead of sitting there
// as an inert not-installed row while its install is in flight.
func (q *jobQueue) InstallingSet() map[string]bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := map[string]bool{}
	add := func(j *job) {
		if j.kind == JobKindUninstall || j.kind == JobKindDisable {
			return
		}
		names := j.names
		if len(j.covers) > 0 {
			names = j.covers
		}
		for _, n := range names {
			out[n] = true
		}
	}
	if q.active != nil {
		add(q.active)
	}
	for _, j := range q.pending {
		add(j)
	}
	return out
}

// setCovers records an install job's resolved plan and publishes the
// change. The publish matters: plan resolution happens after the
// queued -> running transition, so without it a consumer holds a row
// set that predates the plan until the job ends.
func (q *jobQueue) setCovers(j *job, names []string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	j.covers = append([]string{}, names...)
	q.notifyLocked(j)
}

// Wait blocks until the given job leaves the queue/active slot, then
// returns its terminal view. A job the queue doesn't know (never
// enqueued, or evicted from terminal history) returns ErrUnknownJob
// instead of polling to the ctx deadline. Used by the synchronous
// EnsureInstalled path and boot gates.
func (q *jobQueue) Wait(ctx context.Context, id string) (*Job, error) {
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		v, known := q.lookup(id)
		if v != nil {
			return v, nil
		}
		if !known {
			return nil, fmt.Errorf("%w: %s", ErrUnknownJob, id)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-tick.C:
		}
	}
}

// lookup returns the terminal view when the job has finished, and
// whether the queue knows the id at all (terminal, active, or pending).
func (q *jobQueue) lookup(id string) (*Job, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if s, ok := q.terminal[id]; ok {
		return s, true
	}
	if q.active != nil && q.active.id == id {
		return nil, true
	}
	for _, j := range q.pending {
		if j.id == id {
			return nil, true
		}
	}
	return nil, false
}

// Close stops the worker after the current job (its context is
// cancelled so shutdown isn't held for a slow download). Every job the
// shutdown cancels — the running one and the queued ones the worker
// drains — is attributed to CancelShutdown.
func (q *jobQueue) Close() {
	q.mu.Lock()
	q.stopped = true
	if q.active != nil && q.active.cancel != nil {
		q.active.noteCancelLocked(CancelShutdown)
		q.active.cancel()
	}
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
	q.wg.Wait()
}

func (q *jobQueue) worker() {
	for {
		q.mu.Lock()
		if q.stopped {
			// Drain queued jobs as cancelled so waiters unblock.
			for _, j := range q.pending {
				q.dropQueuedLocked(j, CancelShutdown)
			}
			q.pending = nil
			q.mu.Unlock()
			return
		}
		if len(q.pending) == 0 {
			q.mu.Unlock()
			<-q.wake
			continue
		}
		j := q.pending[0]
		q.pending = q.pending[1:]
		ctx, cancel := context.WithTimeout(context.Background(), jobTimeout)
		j.cancel = cancel
		j.state = JobRunning
		j.started = time.Now()
		q.active = j
		q.notifyLocked(j)
		q.mu.Unlock()

		q.runOne(ctx, j)
		cancel()

		q.mu.Lock()
		q.active = nil
		q.pushRecentLocked(j)
		q.notifyLocked(j)
		q.mu.Unlock()
	}
}

// runOne executes a job, coalescing output lines into callback batches.
func (q *jobQueue) runOne(ctx context.Context, j *job) {
	var outMu sync.Mutex
	var batch []string
	flush := func() {
		outMu.Lock()
		lines := batch
		batch = nil
		outMu.Unlock()
		if len(lines) == 0 || q.onOutput == nil {
			return
		}
		q.onOutput(j.id, lines)
	}
	done := make(chan struct{})
	// flushed closes after the ticker goroutine's FINAL flush() returns;
	// runOne waits on it before publishing terminal state, or a consumer
	// could see tool_job_output arrive after tool_job_changed said the
	// job was done (go-rulebook C20). flush() takes only outMu, never
	// q.mu, so waiting here cannot deadlock against the finalize.
	flushed := make(chan struct{})
	go func() {
		defer close(flushed)
		t := time.NewTicker(outputFlushEvery)
		defer t.Stop()
		for {
			select {
			case <-done:
				flush()
				return
			case <-t.C:
				flush()
			}
		}
	}()

	output := func(line string) {
		q.mu.Lock()
		j.appendLine(line)
		q.mu.Unlock()
		outMu.Lock()
		batch = append(batch, line)
		outMu.Unlock()
	}

	err := q.run(ctx, j, output)
	close(done)
	<-flushed

	// Finalize under the queue lock: Snapshot/Active read the active
	// job's fields (via view) under q.mu, so unlocked writes here race
	// with a concurrent jobs poll.
	q.mu.Lock()
	j.ended = time.Now()
	switch {
	case err == nil:
		j.state = JobDone
	case errors.Is(ctx.Err(), context.Canceled):
		j.state = JobCancelled
		j.err = "cancelled"
		// The cause was recorded by whoever cancelled; a context killed
		// by a path that names none stays unknown rather than defaulting
		// to shutdown.
		q.log.Info("toolbelt: job cancelled", "job", j.id, "kind", j.kind, "cause", j.cause.String())
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		j.state = JobFailed
		j.err = fmt.Sprintf("timed out after %s", jobTimeout)
		q.log.Warn("toolbelt: job timed out", "job", j.id, "kind", j.kind)
	default:
		j.state = JobFailed
		j.err = err.Error()
		q.log.Warn("toolbelt: job failed", "job", j.id, "kind", j.kind, "error", err)
	}
	if j.state != JobCancelled {
		// A cancellation that lost the race (the job finished, timed out,
		// or failed first) must not leave a cause on a result that was
		// not a cancellation.
		j.cause = CancelUnknown
	}
	q.mu.Unlock()
}

// pushRecentLocked appends to history with the cap applied and records
// the terminal view for waiters. Caller holds mu.
func (q *jobQueue) pushRecentLocked(j *job) {
	q.recent = append(q.recent, j)
	if len(q.recent) > jobHistory {
		q.recent = q.recent[len(q.recent)-jobHistory:]
	}
	if q.terminal == nil {
		q.terminal = map[string]*Job{}
	}
	// Terminal views keep the output tail: Wait consumers (boot gates,
	// EnsureInstalled) want the lines for logs and error context.
	q.terminal[j.id] = j.view(true)
	// Bound the map: keep terminal states for at most 4x the history
	// window by evicting ids that fell out of recent long ago.
	if len(q.terminal) > 4*jobHistory {
		keep := map[string]bool{}
		for _, r := range q.recent {
			keep[r.id] = true
		}
		if q.active != nil {
			keep[q.active.id] = true
		}
		for id := range q.terminal {
			if !keep[id] {
				delete(q.terminal, id)
			}
		}
	}
}

// notifyLocked invokes the state-transition callback. Caller holds mu.
// The call is synchronous so transitions reach the consumer in strict
// order; the callback must not block (see the field doc).
func (q *jobQueue) notifyLocked(j *job) {
	if q.onChanged == nil {
		return
	}
	q.onChanged(j.view(false))
}
