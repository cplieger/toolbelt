package toolbelt

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"

	"github.com/cplieger/go/filesafe"
)

// ErrManifestInvalid is wrapped by every refusal of a tools.json document:
// ParseManifest's, New's, WriteManifest's, ReplaceManifest's and
// SyncManifest's. The refusals' error texts do not name it.
var ErrManifestInvalid = errors.New("toolbelt: invalid manifest")

// manifestError carries a refusal's own text and matches ErrManifestInvalid,
// so wrapping it changes no error a consumer already shows.
type manifestError struct{ err error }

func (e *manifestError) Error() string        { return e.err.Error() }
func (e *manifestError) Unwrap() error        { return e.err }
func (e *manifestError) Is(target error) bool { return target == ErrManifestInvalid }

func invalidManifest(err error) error { return &manifestError{err: err} }

// SeenKind is what a caller's read of tools.json found.
type SeenKind uint8

// The kinds of read SyncManifest takes.
const (
	SeenValid  SeenKind = iota + 1 // a document ParseManifest accepts
	SeenAbsent                     // nothing at the path
	// SeenUnreadable is a document ParseManifest refuses, a non-regular file
	// or a read error.
	SeenUnreadable
)

// WriteManifest validates content as the engine reads tools.json and writes it
// verbatim to configDir's tools.json with the engine's file mode, atomically.
// It is for a consumer with no engine running on configDir (use
// Engine.ReplaceManifest otherwise) and checks no catalog, so it cannot refuse
// a document that drops an essential row. A write that landed but could not
// be fsynced is not an error, as for the engine's own manifest writes.
func WriteManifest(configDir string, content []byte) error {
	if configDir == "" {
		return errors.New("toolbelt: WriteManifest needs a config dir")
	}
	if _, err := ParseManifest(content); err != nil {
		return err
	}
	_, err := atomicWrite(filepath.Join(configDir, manifestFile), content)
	return err
}

// ReplaceManifest writes content verbatim as tools.json under the store lock,
// then enqueues a ReconcileMissing pass. It writes nothing and returns the
// refusal when check (nil accepts) refuses the bytes on disk (nil when the
// file is absent or not a regular file), when check is set and a file there
// cannot be read (the read's error), when ParseManifest refuses content, or
// when content drops a row the current manifest holds and the live catalog
// marks essential (ErrEssential, naming the tool).
func (e *Engine) ReplaceManifest(content []byte, check func(current []byte) error) error {
	if err := e.store.replace(content, check, e.cat()); err != nil {
		return err
	}
	e.queueReconcile()
	return nil
}

// SyncManifest adopts tools.json as the caller read it: seen holds a regular file's bytes
// (non-nil, possibly empty) and is nil otherwise. It does nothing and reports false when the
// file no longer holds that read. A valid file the engine did not write, or one an engine write
// folded a hand edit into, is applied; an absent one becomes the seed, written back. Both report
// true and enqueue a ReconcileMissing pass. A failed seed write returns its error and adopts
// nothing, so the caller's next read retries it. An unreadable file is refused and its error
// returned. A polling caller passes an absent or unreadable read only once two consecutive polls
// saw it; until then reads keep the applied manifest.
func (e *Engine) SyncManifest(seen []byte, kind SeenKind) (changed bool, err error) {
	changed, err = e.store.sync(seen, kind)
	if changed {
		e.queueReconcile()
	}
	return changed, err
}

func (e *Engine) queueReconcile() {
	if _, _, err := e.Reconcile(ReconcileMissing); err != nil {
		e.log.Warn("toolbelt: reconcile after a manifest change not enqueued", "error", err)
	}
}

// manifestRead is one read of tools.json.
type manifestRead struct {
	m    *Manifest // the parsed document, when valid
	err  error     // why it is not valid, when unreadable
	data []byte    // the bytes of a regular file; nil for any other read
	kind SeenKind
}

func (r *manifestRead) same(o *manifestRead) bool {
	return r.kind == o.kind && (r.data == nil) == (o.data == nil) && bytes.Equal(r.data, o.data)
}

// base answers what a read (merge false) or a merge write builds on, given r:
// the disk's manifest when valid; otherwise, while r is held (the applied
// record is another read), the applied record's answer; else r's own answer,
// the seed when absent and r's error when unreadable. A merge over an
// unreadable r is always refused, so no write replaces the person's bytes.
func (s *store) base(r *manifestRead, merge bool) (*Manifest, error) {
	if r.kind == SeenValid {
		return r.m, nil
	}
	if r.kind == SeenUnreadable && merge {
		return nil, s.refusal(r)
	}
	from := r
	if s.applied.kind != 0 && !s.applied.same(r) {
		from = &s.applied
	}
	switch from.kind {
	case SeenValid:
		return ParseManifest(from.data)
	case SeenAbsent:
		return s.seedManifest(), nil
	}
	return nil, s.refusal(r)
}

// refusal is r's own error when r has refused bytes or nothing unreadable was
// adopted; otherwise the adopted read's, so a later absence never reads as
// the seed over a file the store refused.
func (s *store) refusal(r *manifestRead) error {
	if r.kind == SeenUnreadable && (r.data != nil || s.applied.kind != SeenUnreadable) {
		return r.err
	}
	return s.applied.err
}

func (s *store) replace(content []byte, check func([]byte) error, c *Catalog) error {
	next, err := ParseManifest(content)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.readManifestLocked()
	if check != nil {
		if r.kind == SeenUnreadable && r.data == nil && !errors.Is(r.err, filesafe.ErrNotRegular) {
			return r.err
		}
		if err := check(r.data); err != nil {
			return err
		}
	}
	if cur, err := s.base(&r, false); err == nil {
		for _, name := range slices.Sorted(maps.Keys(cur.Tools)) {
			if _, kept := next.Tools[name]; !kept && essential(c, name) {
				return fmt.Errorf("%w: %s", ErrEssential, name)
			}
		}
	}
	if err := s.commitManifestLocked(bytes.Clone(content)); err != nil {
		return err
	}
	s.foreign = false
	return nil
}

func (s *store) sync(seen []byte, kind SeenKind) (changed bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.readManifestLocked()
	if !r.same(&manifestRead{kind: kind, data: seen}) {
		return false, nil
	}
	switch kind {
	case SeenValid:
		if s.applied.same(&r) && !s.foreign {
			return false, nil
		}
		s.applied, s.foreign = r, false
		return true, nil
	case SeenAbsent:
		if err := s.writeSeedLocked(); err != nil {
			return false, err
		}
		s.foreign = false
		return true, nil
	default:
		s.applied, s.foreign = r, false
		return false, r.err
	}
}
