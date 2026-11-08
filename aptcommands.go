package toolbelt

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// dpkgInfoDir holds dpkg's per-package file lists; a variable so tests point it at a fixture tree.
var dpkgInfoDir = "/var/lib/dpkg/info"

// dpkgListCap bounds one file-list read: the largest Debian packages list a few thousand paths.
const dpkgListCap = 1 << 20

// commandDirs are the PATH directories whose direct entries count as a package's commands.
var commandDirs = []string{"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/"}

// aptCommands returns the commands dpkg records pkg as placing directly in a PATH directory:
// basenames, sorted and deduped. A missing or unreadable list yields none. Read as files, not
// through dpkg-query, for the latency reason given at aptExtendedStatesPath.
func aptCommands(pkg string) []string {
	if pkg == "" || strings.ContainsAny(pkg, "/*?[\\") {
		return nil
	}
	paths := []string{filepath.Join(dpkgInfoDir, pkg+".list")}
	if _, err := os.Stat(paths[0]); err != nil {
		// A Multi-Arch: same package records its list under <pkg>:<arch>.list.
		paths, _ = filepath.Glob(filepath.Join(dpkgInfoDir, pkg+":*.list"))
	}
	var entries []string
	for _, p := range paths {
		entries = append(entries, readDpkgList(p)...)
	}
	return commandsFromList(entries)
}

func readDpkgList(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, dpkgListCap))
	if err != nil {
		return nil
	}
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			out = append(out, line)
		}
	}
	return out
}

// commandsFromList keeps the entries directly under a commandDirs directory. An entry another
// entry sits under is a directory, never a command; the list itself does not mark which is which.
func commandsFromList(entries []string) []string {
	var dirs map[string]bool
	for _, e := range entries {
		if parent := filepath.Dir(e); parent != "/" {
			if dirs == nil {
				dirs = map[string]bool{}
			}
			dirs[parent] = true
		}
	}
	var out []string
	for _, e := range entries {
		if dirs[e] {
			continue
		}
		for _, d := range commandDirs {
			if name, ok := strings.CutPrefix(e, d); ok && name != "" && !strings.Contains(name, "/") {
				out = append(out, name)
				break
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// commands is the cached aptCommands answer for pkg, dropped with the rest of the cache by
// Invalidate after an apt job.
func (d *aptDiscovery) commands(pkg string) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if cmds, ok := d.cmds[pkg]; ok {
		return cmds
	}
	cmds := aptCommands(pkg)
	if d.cmds == nil {
		d.cmds = map[string][]string{}
	}
	d.cmds[pkg] = cmds
	return cmds
}
