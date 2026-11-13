//go:build linux

package pin

import "errors"

// ErrNoVersion reports that no complete version is installed and none could
// be installed, so there is nothing to activate.
var ErrNoVersion = errors.New("no complete version is installed")
