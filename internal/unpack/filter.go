package unpack

import (
	"context"
	"errors"
	"fmt"
	"io"
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

// filtered runs consume over the output of the system decompressor name fed
// with src, and reaps the decompressor on every return. Output after consume
// returns is read through the same meter, so a filter that never stops
// writing ends at the byte limit.
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
	cmd.Stdin = src
	cmd.Stderr = &stderr
	cmd.WaitDelay = filterWaitDelay
	out, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("unpack: %s: %w", name, err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("unpack: %s: %w", name, err)
	}
	stream := x.stream(out)
	uerr := consume(stream)
	if uerr == nil {
		_, uerr = io.Copy(io.Discard, stream)
	}
	if uerr != nil {
		return reapFailed(ctx, cmd, out, cancel, name, &stderr, uerr)
	}
	werr := cmd.Wait()
	cancel()
	switch {
	case ctx.Err() != nil:
		return ctx.Err()
	case werr != nil && !errors.Is(werr, exec.ErrWaitDelay):
		// The filter failed after a complete-looking stream: corrupt input.
		return fmt.Errorf("unpack: %s: %w%s", name, werr, stderr.suffix())
	}
	return nil
}

// reapFailed stops and reaps a filter after consume failed with uerr. A
// failure reading the stream means the filter closed its stdout first, so it
// gets filterWaitDelay to exit with its own status: a non-zero exit is the
// cause, and its status and stderr lead the error. Any other failure is this
// package's decision, so the filter is killed and its status dropped.
func reapFailed(ctx context.Context, cmd *exec.Cmd, out io.Closer, cancel context.CancelFunc, name string, stderr *stderrCap, uerr error) error {
	se, isRead := errors.AsType[*streamError](uerr)
	if !isRead {
		cancel()
		_ = out.Close()
		_ = cmd.Wait()
		if err := ctx.Err(); err != nil {
			return err
		}
		return uerr
	}
	_ = out.Close()
	kill := time.AfterFunc(filterWaitDelay, cancel)
	_ = cmd.Wait()
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
