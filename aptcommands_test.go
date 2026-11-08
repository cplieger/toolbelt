package toolbelt

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func writeDpkgList(t *testing.T, dir, file string, paths ...string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, file), []byte(strings.Join(paths, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestAptCommands(t *testing.T) {
	dir := t.TempDir()
	old := dpkgInfoDir
	dpkgInfoDir = dir
	t.Cleanup(func() { dpkgInfoDir = old })

	writeDpkgList(t, dir, "ffmpeg.list",
		"/.", "/usr", "/usr/bin", "/usr/bin/ffprobe", "/usr/bin/ffmpeg", "/usr/share", "/usr/share/doc/x")
	writeDpkgList(t, dir, "libfoo1.list", "/.", "/usr", "/usr/lib", "/usr/lib/x86_64-linux-gnu/libfoo.so.1")
	writeDpkgList(t, dir, "tool-ma:amd64.list", "/.", "/usr/sbin", "/usr/sbin/toold", "/bin/toolctl")
	writeDpkgList(t, dir, "nested.list", "/usr/bin/sub", "/usr/bin/sub/inner", "/usr/libexec/helper")

	cases := []struct {
		name string
		pkg  string
		want []string
	}{
		{"commands under a PATH dir only", "ffmpeg", []string{"ffmpeg", "ffprobe"}},
		{"library yields none", "libfoo1", nil},
		{"multi-arch list found by arch suffix", "tool-ma", []string{"toolctl", "toold"}},
		{"missing list yields none", "absent", nil},
		{"a directory under a PATH dir is no command", "nested", nil},
		{"a glob in the name is refused", "ff*", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := aptCommands(tc.pkg); !slices.Equal(got, tc.want) {
				t.Errorf("aptCommands(%q) = %v, want %v", tc.pkg, got, tc.want)
			}
		})
	}
}

func TestAptDiscovery_CommandsCacheDroppedByInvalidate(t *testing.T) {
	dir := t.TempDir()
	old := dpkgInfoDir
	dpkgInfoDir = dir
	t.Cleanup(func() { dpkgInfoDir = old })

	d := &aptDiscovery{}
	if got := d.commands("pkg"); got != nil {
		t.Fatalf("before install = %v, want none", got)
	}
	writeDpkgList(t, dir, "pkg.list", "/usr/bin/pkg")
	if got := d.commands("pkg"); got != nil {
		t.Errorf("cached answer = %v, want the cached none until Invalidate", got)
	}
	d.Invalidate()
	if got := d.commands("pkg"); !slices.Equal(got, []string{"pkg"}) {
		t.Errorf("after Invalidate = %v, want [pkg]", got)
	}
}

func TestInventory_EngineRowCommandsAreBinsAndPMBins(t *testing.T) {
	e := newTestEngine(t, nil)
	addManual(t, e, "zeta", nil)
	if err := os.WriteFile(filepath.Join(e.toolsDir, "bin", "alpha"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := e.store.setToolStatus("zeta", func(s *ToolStatus) { s.PMBins = []string{"alpha"} }); err != nil {
		t.Fatal(err)
	}
	st := e.store.State().Tools["zeta"]
	want := slices.Sorted(slices.Values(slices.Concat(st.Bins, st.PMBins)))

	inv, err := e.Inventory()
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Tools) != 1 || !inv.Tools[0].Installed {
		t.Fatalf("inventory = %+v, want one installed row", inv.Tools)
	}
	if got := inv.Tools[0].Commands; !slices.Equal(got, want) || len(got) != 2 {
		t.Errorf("Commands = %v, want Bins plus PMBins %v", got, want)
	}
}
