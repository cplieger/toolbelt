package unpack

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// filterWaitDelay bounds how long reaping a filter waits on a descendant that
// still holds its stdout or stderr.
const filterWaitDelay = 2 * time.Second

// stderrKeep is how much of a filter's stderr an error carries.
const stderrKeep = 4096

// stderrCap keeps the first stderrKeep bytes written to it. Write never fails:
// os/exec turns a capture's write error, a short count included, into Wait's
// error, which would fail a filter that exited 0.
type stderrCap struct{ b []byte }

func (c *stderrCap) Write(p []byte) (int, error) {
	if room := stderrKeep - len(c.b); room > 0 {
		c.b = append(c.b, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

// suffix is ": <stderr>" with trailing newlines trimmed, or "" when the
// filter wrote nothing.
func (c *stderrCap) suffix() string {
	s := strings.TrimRight(string(c.b), "\r\n")
	if s == "" {
		return ""
	}
	return ": " + s
}

// filtered runs consume, which must read to the end of its stream, over the
// output of the system decompressor name fed with src, and reaps the
// decompressor on every return.
func (x *extractor) filtered(ctx context.Context, filter FilterFunc, name string, src io.Reader, consume func(io.Reader) error) error {
	if filter == nil {
		return fmt.Errorf("unpack: %s: no decompression filter is configured", name)
	}
	fctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd, err := filter(fctx, name, "-dc")
	if err != nil {
		return fmt.Errorf("unpack: %s: %w", name, err)
	}
	var stderr stderrCap
	// stdout is an *os.File, so exec copies only stderr and WaitDelay never
	// cuts output; filterOut ends the stream once the exited filter's pipe idles.
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("unpack: %s: %w", name, err)
	}
	defer r.Close()
	cmd.Stdin = src
	cmd.Stdout = w
	cmd.Stderr = &stderr
	cmd.WaitDelay = filterWaitDelay
	err = cmd.Start()
	_ = w.Close() // the child holds its own copy
	if err != nil {
		return fmt.Errorf("unpack: %s: %w", name, err)
	}
	reaped := &reap{done: make(chan struct{})}
	go func() {
		reaped.err = cmd.Wait()
		// Wakes a read already blocked on a pipe only a descendant still holds.
		_ = r.SetReadDeadline(time.Now().Add(filterWaitDelay))
		close(reaped.done)
	}()
	if uerr := consume(x.stream(&filterOut{r: r, exited: reaped.done})); uerr != nil {
		return reapFailed(ctx, cmd, r, reaped, cancel, name, &stderr, uerr)
	}
	<-reaped.done
	cancel()
	switch werr := reaped.err; {
	case ctx.Err() != nil:
		return ctx.Err()
	case werr != nil && !errors.Is(werr, exec.ErrWaitDelay):
		// The filter failed after a complete-looking stream: corrupt input.
		return fmt.Errorf("unpack: %s: %w%s", name, werr, stderr.suffix())
	}
	return nil
}

// reap is a filter's Wait, run once: err is set before done closes.
type reap struct {
	err  error
	done chan struct{}
}

// filterOut reads the filter's stdout. Once the filter has exited it has
// written all it will, so filterWaitDelay with no byte is the end of the
// stream: a descendant holding the pipe cannot hold the call, and a slow
// consumer loses nothing, since each read re-arms the deadline.
type filterOut struct {
	r      *os.File
	exited <-chan struct{}
}

func (o *filterOut) Read(p []byte) (int, error) {
	select {
	case <-o.exited:
		_ = o.r.SetReadDeadline(time.Now().Add(filterWaitDelay))
	default:
	}
	n, err := o.r.Read(p)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return n, io.EOF
	}
	return n, err
}

// reapFailed stops and reaps a filter after consume failed with uerr. A
// failure reading the stream means the filter closed its stdout first, so it
// gets filterWaitDelay to exit with its own status: a non-zero exit is the
// cause, and its status and stderr lead the error. Any other failure is this
// package's decision, so the filter is killed and its status dropped.
func reapFailed(ctx context.Context, cmd *exec.Cmd, out io.Closer, reaped *reap, cancel context.CancelFunc, name string, stderr *stderrCap, uerr error) error {
	se, isRead := errors.AsType[*streamError](uerr)
	if !isRead {
		cancel()
		_ = out.Close()
		<-reaped.done // its error is the kill this function caused
		if err := ctx.Err(); err != nil {
			return err
		}
		return uerr
	}
	_ = out.Close()
	kill := time.AfterFunc(filterWaitDelay, cancel)
	<-reaped.done // cmd.ProcessState carries the status
	kill.Stop()
	cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	if ps := cmd.ProcessState; ps != nil && ps.Exited() && ps.ExitCode() != 0 {
		return fmt.Errorf("unpack: %s: %s%s: %w", name, ps, stderr.suffix(), se.err)
	}
	return uerr
}
