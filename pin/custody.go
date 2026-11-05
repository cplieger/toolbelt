//go:build linux

package pin

import (
	"fmt"
	"os"
	"path/filepath"
)

// checkCustody judges the versions directory, or its nearest existing
// ancestor before the first install, and records the verdict.
func (m *Manager) checkCustody() {
	dir := nearestExisting(m.versionsDir)
	err := m.trust.Verify(dir, dir == m.versionsDir)
	if err != nil {
		err = fmt.Errorf("the installation root is %w", err)
		m.log.Warn("this process does not exclusively control the installation tree, so a completion sentinel there is not evidence; only versions installed by this process will be activated",
			"package", m.cfg.Name, "root", m.versionsDir, "error", err)
	}
	m.setCustody(err)
}

// requireCustody judges the versions directory itself, which install has
// just created, and refuses the install when another principal can write it.
func (m *Manager) requireCustody() error {
	err := m.trust.Verify(m.versionsDir, true)
	if err != nil {
		err = fmt.Errorf("the installation root is %w", err)
	}
	m.setCustody(err)
	return err
}

// nearestExisting returns dir or its closest ancestor that exists.
func nearestExisting(dir string) string {
	for {
		if _, err := os.Lstat(dir); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return dir
		}
		dir = parent
	}
}

// setCustody records the verdict under the state lock.
func (m *Manager) setCustody(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.custodyErr = err
}

// custodyVerdict returns the last recorded verdict.
func (m *Manager) custodyVerdict() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.custodyErr
}
