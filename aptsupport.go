package toolbelt

import (
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// The reasons apt cannot install here, as a user reads them on an apt: row
// and in a search.
const (
	aptNeedsDebian   = "apt packages need a Debian-derived image with apt-get"
	aptNeedsRoot     = "apt packages need the container to run as root"
	aptNeedsWritable = "apt packages need a writable root filesystem"
)

// aptStateDirs are where an install writes: the package's own files under
// /usr, dpkg's database, apt's auto-install marks, its index and its archives.
// Each is probed apart because any one can be a writable mount over a
// read-only root, and apt fails on the first one that is not.
var aptStateDirs = []string{"/usr", "/var/lib/dpkg", "/var/lib/apt", "/var/lib/apt/lists", "/var/cache/apt"}

// aptDirWritable is a variable so tests can model a read-only root without
// mounting one.
var aptDirWritable = accessWritable

// wOK is access(2)'s W_OK, which package syscall does not export.
const wOK = 0x2

// accessWritable asks the kernel whether dir, or its nearest existing
// ancestor when it is absent (apt creates it), accepts writes. access(2)
// answers EROFS for a read-only mount and writes nothing
// (https://man7.org/linux/man-pages/man2/access.2.html).
func accessWritable(dir string) error {
	for {
		err := syscall.Access(dir, wOK)
		parent := filepath.Dir(dir)
		if !errors.Is(err, fs.ErrNotExist) || parent == dir {
			if err != nil {
				return &fs.PathError{Op: "access", Path: dir, Err: err}
			}
			return nil
		}
		dir = parent
	}
}

// aptHost is the once-per-process half of the verdict: whether this process
// may write what apt writes. cause is the probe failure behind reason.
type aptHost struct {
	cause  error
	reason string
}

// geteuid is a variable so tests can drive the apt paths against stub
// binaries without running as root.
var geteuid = os.Geteuid

var aptSupport = sync.OnceValue(detectAptSupport)

func detectAptSupport() aptHost {
	if geteuid() != 0 {
		return aptHost{reason: aptNeedsRoot}
	}
	for _, dir := range aptStateDirs {
		if err := aptDirWritable(dir); err != nil {
			return aptHost{reason: aptNeedsWritable, cause: err}
		}
	}
	return aptHost{}
}

// AptUnavailableReason says why this process cannot install apt packages, or
// is empty when it can. Root and the writability of apt's directories are
// read once per process; apt-get's presence on every call.
func AptUnavailableReason() string {
	if !hasSystemBin("apt-get") {
		return aptNeedsDebian
	}
	return aptSupport().reason
}

// AptAvailable reports whether this process can install apt packages (see
// [AptUnavailableReason]). Consumers surface it rather than offering an
// install that always fails, and the engine fails every apt: row at once with
// the reason when it is false.
//
// There is no sudo path by design: a library that shells out to sudo would
// be inventing a privilege escalation its caller did not ask for.
func AptAvailable() bool { return AptUnavailableReason() == "" }

// ErrAptUnavailable marks an apt operation attempted where apt cannot work.
// The error's own text is [AptUnavailableReason].
var ErrAptUnavailable = errors.New("apt is unavailable")

type aptUnavailableError struct{ reason string }

func (e aptUnavailableError) Error() string { return e.reason }

func (aptUnavailableError) Is(target error) bool { return target == ErrAptUnavailable }

// aptUnavailable is nil where apt can install, else an [ErrAptUnavailable]
// whose text is the reason.
func aptUnavailable() error {
	if r := AptUnavailableReason(); r != "" {
		return aptUnavailableError{reason: r}
	}
	return nil
}

// logAptSupport states once, at engine start, why apt packages are off, with
// the probe failure the reason alone does not name.
func logAptSupport(log *slog.Logger) {
	r := AptUnavailableReason()
	if r == "" {
		return
	}
	args := []any{"reason", r}
	if c := aptSupport().cause; c != nil && r == aptNeedsWritable {
		args = append(args, "error", c)
	}
	log.Info("toolbelt: apt packages are unavailable", args...)
}
