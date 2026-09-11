package toolbelt

import "path/filepath"

// The managed layout under a tools dir, defined once: the installer creates
// these, New pins the stored mode of bin/, the probe resolves through bin/, and
// VerifyRootIntegrity audits the whole set — a second spelling drifts.

// binDir is the single directory published on PATH.
func binDir(toolsDir string) string { return filepath.Join(toolsDir, "bin") }

// optDir holds one versioned tree per tool.
func optDir(toolsDir string) string { return filepath.Join(toolsDir, "opt") }

// npmDir is the npm prefix; npmBinDir is the bin dir npm writes under it.
func npmDir(toolsDir string) string    { return filepath.Join(toolsDir, "npm") }
func npmBinDir(toolsDir string) string { return filepath.Join(npmDir(toolsDir), "bin") }

// pythonDir is uv's tool root; pythonBinDir is the launcher dir under it.
func pythonDir(toolsDir string) string    { return filepath.Join(toolsDir, "python") }
func pythonBinDir(toolsDir string) string { return filepath.Join(pythonDir(toolsDir), "bin") }

// managedDirs is every directory the engine owns, in audit order.
func managedDirs(toolsDir string) []string {
	return []string{
		binDir(toolsDir),
		optDir(toolsDir),
		npmDir(toolsDir),
		npmBinDir(toolsDir),
		pythonDir(toolsDir),
		pythonBinDir(toolsDir),
	}
}
