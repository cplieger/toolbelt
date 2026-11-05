//go:build linux

// Package pinstall installs, activates and maintains a digest-pinned upstream
// release under <Root>/<Name>-versions/<version>/, populated only from a
// digest-verified archive, published by one same-filesystem rename and marked
// by a ".complete" sentinel written last, so an interrupted install is never a
// selection candidate.
//
// Custody is verified before any byte is fetched and never repaired: Root and
// every directory above it must be writable only by this process's identity
// or root (see [ErrNoCustody], [Config.TrustedUIDs] and
// [Config.InstallWithoutCustody]). Names taken from a profile, an archive or
// an on-disk tree are acted on through an [os.Root]; paths the package
// generates itself are acted on directly. Build a [Release] once and a
// [Config] per deployment, then call [New]. Nothing exits the process, reads
// the environment or works at import time. Linux only.
package pin
