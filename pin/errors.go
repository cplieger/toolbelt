//go:build linux

package pin

import "errors"

// Errors callers can classify. Everything else is wrapped with context.
var (
	// ErrDigestMismatch reports that the downloaded archive is not the artifact the
	// pinned digest names. No version directory and no staging tree are created when
	// it is returned, so nothing becomes a selection candidate. The installation root
	// itself may exist — custody has to be judged on the real directory — and the
	// archive's own blocks are freed with its descriptor, having never had a name.
	ErrDigestMismatch = errors.New("archive SHA-256 mismatch")
	// ErrUnsupportedArch reports an architecture the release publishes no
	// archive for, or one with no pinned digest.
	ErrUnsupportedArch = errors.New("unsupported architecture")
	// ErrNoVersion reports that no complete version is installed and none could
	// be installed, so there is nothing to activate.
	ErrNoVersion = errors.New("no complete version is installed")
	// ErrVersionMismatch reports that a candidate artifact answered the version
	// probe with something other than the version its directory and sentinel
	// claim.
	ErrVersionMismatch = errors.New("binary reported a version its install directory does not claim")
	// ErrNoCustody reports that the installation root, or a directory on the way to
	// it, can be modified by a principal other than this process's identity, the root
	// user, or an identity declared in [Config.TrustedUIDs] or [Config.TrustedGIDs].
	// No group is trusted unless declared, the root group included, so nothing
	// installed there can be trusted to stay what was installed. The
	// wrapped text names the offending path and what is wrong with it: an owner, a
	// mode, or an access-control list whose entries the mode does not show. Fix the
	// volume, or set [Config.InstallWithoutCustody] to proceed anyway.
	//
	// Its absence is not a proof of safety: the check reads Unix ownership, the mode and
	// the ACL-dialect attributes, so a filesystem that does not make the mode its
	// access decision at all — a cifs mount with noperm, a FUSE filesystem without
	// default_permissions — returns a clean verdict from inside the process no matter
	// who can write. If that is your volume, you know something this library cannot
	// measure, and [Config.InstallWithoutCustody] is where you say so.
	ErrNoCustody = errors.New("the installation root is not under this process's exclusive control")
)
