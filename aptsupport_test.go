package toolbelt

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// readOnlyDirs answers like access(2) on a read-only mount for the named
// directories, and writable for every other one.
func readOnlyDirs(dirs ...string) func(string) error {
	return func(dir string) error {
		if slices.Contains(dirs, dir) {
			return &fs.PathError{Op: "access", Path: dir, Err: syscall.EROFS}
		}
		return nil
	}
}

func writableDirs(string) error { return nil }

// aptHostCases are the three hosts the capability check tells apart. The
// reasons are the messages the user sees on an apt: row and in a search.
var aptHostCases = []struct {
	writable func(string) error
	name     string
	reason   string
	euid     int
}{
	{name: "root on a writable root filesystem", euid: 0, writable: writableDirs},
	{
		name: "root on a read-only root filesystem", euid: 0,
		writable: readOnlyDirs("/var/lib/dpkg", "/var/lib/apt/lists", "/var/cache/apt"),
		reason:   "apt packages need a writable root filesystem",
	},
	{name: "not root", euid: 1000, writable: writableDirs, reason: "apt packages need the container to run as root"},
}

func TestAptUnavailableReason_NamesWhyAptCannotWork(t *testing.T) {
	cases := append(slices.Clip(aptHostCases), struct {
		writable func(string) error
		name     string
		reason   string
		euid     int
	}{
		// The tmpfs layout the read-only test tried: the index and the
		// archives are writable, dpkg's database is still the image's.
		name: "root with only the dpkg database read-only", euid: 0,
		writable: readOnlyDirs("/var/lib/dpkg"),
		reason:   "apt packages need a writable root filesystem",
	})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubApt(t)
			fakeAptHost(t, tc.euid, tc.writable)

			if got := AptUnavailableReason(); got != tc.reason {
				t.Errorf("AptUnavailableReason() = %q, want %q", got, tc.reason)
			}
			if got := AptAvailable(); got != (tc.reason == "") {
				t.Errorf("AptAvailable() = %v beside the reason %q", got, tc.reason)
			}
		})
	}
}

func TestAptUnavailableReason_ProbesEachStateDirOnce(t *testing.T) {
	stubApt(t)
	probed := map[string]int{}
	fakeAptHost(t, 0, func(dir string) error {
		probed[dir]++
		return nil
	})

	for range 3 {
		AptUnavailableReason()
		AptAvailable()
	}
	for _, dir := range []string{"/var/lib/dpkg", "/var/lib/apt/lists", "/var/cache/apt"} {
		if probed[dir] != 1 {
			t.Errorf("%s probed %d times across six reads, want once", dir, probed[dir])
		}
	}
}

// TestAptUnavailable_RowsFailAtOnceWithTheReason: where apt cannot work, an
// apt: row fails without running apt-get and names why, while a catalog-kind
// row in the same job still installs.
func TestAptUnavailable_RowsFailAtOnceWithTheReason(t *testing.T) {
	for _, tc := range aptHostCases {
		t.Run(tc.name, func(t *testing.T) {
			s := stubApt(t)
			fakeAptHost(t, tc.euid, tc.writable)
			e := newTestEngine(t, nil)
			setAptRow(t, e, false, false)
			if err := e.store.MutateManifest(func(m *Manifest) error {
				m.Tools["tool"] = Tool{Source: SourceManual, Version: "1", Install: binStub("tool")}
				return nil
			}); err != nil {
				t.Fatalf("Setup: %v", err)
			}

			jv, _, err := e.Reconcile(ReconcileMissing)
			if err != nil {
				t.Fatalf("Reconcile = %v", err)
			}
			final := waitJob(t, e, jv.ID)

			if !inventoryRow(t, e, "tool").Installed {
				t.Errorf("the manual row is not installed; job %s (%s)", final.State, final.Error)
			}
			jq := inventoryRow(t, e, "jq")
			if tc.reason == "" {
				if final.State != JobDone || !jq.Installed {
					t.Errorf("job = %s (%s), jq installed = %v; want done and installed", final.State, final.Error, jq.Installed)
				}
				if !s.ran(t, "apt-get") {
					t.Error("apt-get never ran on a host where apt works")
				}
				return
			}
			if final.State != JobFailed {
				t.Errorf("job = %s, want %s", final.State, JobFailed)
			}
			if !strings.Contains(final.Error, tc.reason) || !strings.Contains(jq.LastError, tc.reason) {
				t.Errorf("job error = %q, jq last_error = %q, want both to carry %q", final.Error, jq.LastError, tc.reason)
			}
			if s.ran(t, "apt-get") {
				t.Errorf("apt calls = %q, want no apt-get where apt cannot work", s.lines(t))
			}
		})
	}
}

// TestAptUnavailable_SearchListsPackagesAsUnavailable: a search where apt
// cannot work states the reason, never runs apt-get update, reads the package
// list already on disk at most once, and lists its matches apart from the
// installable ones, as the catalog lists a tool it cannot install.
func TestAptUnavailable_SearchListsPackagesAsUnavailable(t *testing.T) {
	const dumpavail = "Package: jq\\nVersion: 1.7.1-1\\nDescription: lightweight and flexible command-line JSON processor\\n\\n"
	for _, tc := range aptHostCases[1:] {
		for _, onDisk := range []bool{true, false} {
			name := tc.name + ", no package list on disk"
			if onDisk {
				name = tc.name + ", a package list on disk"
			}
			t.Run(name, func(t *testing.T) {
				s := stubApt(t)
				list := ""
				if onDisk {
					list = "printf '" + dumpavail + "'"
				}
				script := "#!/bin/sh\necho \"apt-cache $*\" >> " + s.log + "\n" +
					"case \"$1\" in dumpavail) " + list + ";; *) exit 1;; esac\n"
				if err := os.WriteFile(filepath.Join(s.dir, "apt-cache"), []byte(script), 0o755); err != nil {
					t.Fatalf("Setup: %v", err)
				}
				fakeAptHost(t, tc.euid, tc.writable)
				e := newAptEngine(t)

				var sc SearchCounts
				for range 4 {
					sc = e.SearchWithCounts("jq")
					e.aptIdx.refreshing.Wait()
				}
				sc = e.SearchWithCounts("jq")

				if sc.AptState != AptStateUnavailable || sc.AptAvailable {
					t.Errorf("apt state = %q (available %v), want %q", sc.AptState, sc.AptAvailable, AptStateUnavailable)
				}
				if sc.AptReason != tc.reason {
					t.Errorf("AptReason = %q, want %q", sc.AptReason, tc.reason)
				}
				if len(sc.Apt) != 0 || sc.AptMatched != 0 {
					t.Errorf("installable apt hits = %v (matched %d), want none", sc.Apt, sc.AptMatched)
				}
				wantListed := 0
				if onDisk {
					wantListed = 1
				}
				if len(sc.AptUnavailable) != wantListed || wantListed == 1 && sc.AptUnavailable[0].Name != "jq" {
					t.Errorf("unavailable apt hits = %v, want %d naming jq", sc.AptUnavailable, wantListed)
				}
				if sc.AptUnavailableMatched != wantListed {
					t.Errorf("AptUnavailableMatched = %d, want %d", sc.AptUnavailableMatched, wantListed)
				}
				if s.ran(t, "apt-get") {
					t.Errorf("apt calls = %q, want no apt-get where apt cannot work", s.lines(t))
				}
				reads := 0
				for _, l := range s.lines(t) {
					if l == "apt-cache dumpavail" {
						reads++
					}
				}
				if reads > 1 {
					t.Errorf("the package list was read %d times over five searches, want at most once", reads)
				}
			})
		}
	}
}

// TestAccessWritable_AsksTheNearestExistingDirectory: apt creates a missing
// state directory itself, so an absent one is as writable as its parent.
func TestAccessWritable_AsksTheNearestExistingDirectory(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "var", "cache", "apt")

	if err := accessWritable(missing); err != nil {
		t.Errorf("accessWritable(%s) = %v, want nil under a writable parent", missing, err)
	}
}
