//go:build linux

// Package pin installs, activates and maintains one digest-pinned upstream
// release under <Root>/<Name>-versions/<version>/: populated only from a
// verified archive, published by one same-filesystem rename and marked by a
// ".complete" sentinel written last, so an interrupted install is never a
// selection candidate. Custody of the tree is judged before any byte is
// fetched and never repaired. Linux only.
package pin
