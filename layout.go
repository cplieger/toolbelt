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

func npmLibDir(toolsDir string) string { return filepath.Join(npmDir(toolsDir), "lib") }

// npmModulesDir is where npm's global install under the prefix puts each
// package (https://docs.npmjs.com/cli/v11/configuring-npm/folders).
func npmModulesDir(toolsDir string) string {
	return filepath.Join(npmLibDir(toolsDir), "node_modules")
}

// pythonDir is uv's tool root; pythonBinDir is the launcher dir under it.
func pythonDir(toolsDir string) string    { return filepath.Join(toolsDir, "python") }
func pythonBinDir(toolsDir string) string { return filepath.Join(pythonDir(toolsDir), "bin") }

// pythonToolDir holds one uv venv per pip: tool (UV_TOOL_DIR).
func pythonToolDir(toolsDir string) string { return filepath.Join(pythonDir(toolsDir), "tools") }

// pythonInterpreterDir holds the uv-managed CPython builds every pip: venv
// links to (UV_PYTHON_INSTALL_DIR).
func pythonInterpreterDir(toolsDir string) string {
	return filepath.Join(pythonDir(toolsDir), "interpreters")
}

// managedDirs is every directory the engine owns, in audit order.
func managedDirs(toolsDir string) []string {
	return []string{
		binDir(toolsDir),
		optDir(toolsDir),
		npmDir(toolsDir),
		npmBinDir(toolsDir),
		npmLibDir(toolsDir),
		npmModulesDir(toolsDir),
		pythonDir(toolsDir),
		pythonBinDir(toolsDir),
		pythonToolDir(toolsDir),
		pythonInterpreterDir(toolsDir),
	}
}

// writtenTree is what one install wrote under the managed root dir: the
// entry sub, or every entry beneath dir when sub is ".".
type writtenTree struct{ dir, sub string }

// writtenTrees is every tree an install from source kind can write files
// into that the engine later runs. apt: is dpkg's.
func writtenTrees(toolsDir, kind, name string) []writtenTree {
	bin := writtenTree{binDir(toolsDir), "."}
	opt := writtenTree{optDir(toolsDir), name}
	switch kind {
	case SourceAqua, SourceRelease:
		return []writtenTree{opt}
	case SourceManual:
		return []writtenTree{opt, bin}
	case SourceGo, SourceCargo:
		return []writtenTree{bin}
	case SourceNpm:
		return []writtenTree{{npmModulesDir(toolsDir), "."}, {npmBinDir(toolsDir), "."}}
	case SourcePip:
		return []writtenTree{
			{pythonToolDir(toolsDir), "."},
			{pythonInterpreterDir(toolsDir), "."},
			{pythonBinDir(toolsDir), "."},
		}
	}
	return nil
}
