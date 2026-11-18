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

type aptHostCase struct {
	writable func(string) error
	name     string
	reason   string
	euid     int
}

// aptHostCases are the three hosts the capability check tells apart. The
// reasons are the messages the user sees on an apt: row and in a search.
var aptHostCases = []aptHostCase{
	{name: "root on a writable root filesystem", euid: 0, writable: writableDirs},
	{
		name: "root on a read-only root filesystem", euid: 0,
		writable: readOnlyDirs("/usr", "/var/lib/dpkg", "/var/lib/apt", "/var/lib/apt/lists", "/var/cache/apt"),
		reason:   "apt packages need a writable root filesystem",
	},
	{name: "not root", euid: 1000, writable: writableDirs, reason: "apt packages need the container to run as root"},
}

func TestAptUnavailableReason_NamesWhyAptCannotWork(t *testing.T) {
	// A read-only root with writable mounts over some of apt's directories
	// still fails on the first one left read-only: dpkg writes the package's
	// files under /usr and its database, apt its auto-install marks.
	const writableRoot = "apt packages need a writable root filesystem"
	cases := append(slices.Clip(aptHostCases),
		aptHostCase{name: "root with only the dpkg database read-only", writable: readOnlyDirs("/var/lib/dpkg"), reason: writableRoot},
		aptHostCase{name: "root with only /usr read-only", writable: readOnlyDirs("/usr"), reason: writableRoot},
		aptHostCase{name: "root with only /var/lib/apt read-only", writable: readOnlyDirs("/var/lib/apt"), reason: writableRoot},
	)
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
	for _, dir := range []string{"/usr", "/var/lib/dpkg", "/var/lib/apt", "/var/lib/apt/lists", "/var/cache/apt"} {
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

// TestInstall_ResolveFailureIsRecordedOnTheRow: a row that fails before its
// install starts (no version to resolve, no install knowledge) carries the
// cause in the inventory's last_error, through an install job and a
// reconcile alike, as a row failing during its install does.
func TestInstall_ResolveFailureIsRecordedOnTheRow(t *testing.T) {
	const notRoot = "apt packages need the container to run as root"
	install := func(e *Engine) (*Job, error) { return e.Install("jq") }
	reconcile := func(e *Engine) (*Job, error) {
		j, _, err := e.Reconcile(ReconcileMissing)
		return j, err
	}
	for _, tc := range []struct {
		run  func(*Engine) (*Job, error)
		name string
		want string
		row  Tool
	}{
		{name: "an unversioned apt row on a non-root host, installed", row: Tool{Source: "apt:jq"}, want: notRoot, run: install},
		{name: "an unversioned apt row on a non-root host, reconciled", row: Tool{Source: "apt:jq"}, want: notRoot, run: reconcile},
		{name: "a row with no install knowledge, installed", want: "no install knowledge exists", run: install},
		{name: "a row with no install knowledge, reconciled", want: "no install knowledge exists", run: reconcile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := stubApt(t)
			fakeAptHost(t, 1000, writableDirs)
			e := newTestEngine(t, nil)
			if err := e.store.MutateManifest(func(m *Manifest) error {
				m.Tools["jq"] = tc.row
				return nil
			}); err != nil {
				t.Fatalf("Setup: %v", err)
			}

			jv, err := tc.run(e)
			if err != nil {
				t.Fatalf("enqueue = %v", err)
			}
			final := waitJob(t, e, jv.ID)

			if final.State != JobFailed || !strings.Contains(final.Error, tc.want) {
				t.Errorf("job = %s (%q), want failed with %q", final.State, final.Error, tc.want)
			}
			if got := inventoryRow(t, e, "jq").LastError; !strings.Contains(got, tc.want) {
				t.Errorf("jq last_error = %q, want it to carry %q", got, tc.want)
			}
			if s.ran(t, "apt-get") {
				t.Errorf("apt calls = %q, want none", s.lines(t))
			}
		})
	}
}

// TestAptUnavailable_SearchListsPackagesAsUnavailable: every search where apt
// cannot work, the first included, states the reason, never runs apt-get
// update, reads the package list already on disk at most once, and lists its
// matches apart from the installable ones, as the catalog lists a tool it
// cannot install.
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

				replies := make([]SearchCounts, 0, 5)
				for range 5 {
					replies = append(replies, e.SearchWithCounts("jq"))
				}

				wantListed := 0
				if onDisk {
					wantListed = 1
				}
				for i, sc := range replies {
					if sc.AptState != AptStateUnavailable || sc.AptAvailable {
						t.Errorf("search %d: apt state = %q (available %v), want %q", i+1, sc.AptState, sc.AptAvailable, AptStateUnavailable)
					}
					if sc.AptReason != tc.reason {
						t.Errorf("search %d: AptReason = %q, want %q", i+1, sc.AptReason, tc.reason)
					}
					if len(sc.Apt) != 0 || sc.AptMatched != 0 {
						t.Errorf("search %d: installable apt hits = %v (matched %d), want none", i+1, sc.Apt, sc.AptMatched)
					}
					if len(sc.AptUnavailable) != wantListed || wantListed == 1 && sc.AptUnavailable[0].Name != "jq" {
						t.Errorf("search %d: unavailable apt hits = %v, want %d naming jq", i+1, sc.AptUnavailable, wantListed)
					}
					if sc.AptUnavailableMatched != wantListed {
						t.Errorf("search %d: AptUnavailableMatched = %d, want %d", i+1, sc.AptUnavailableMatched, wantListed)
					}
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

// TestInventory_ListsImagePackagesWhereAptCannotInstall: listing the
// packages the image holds only reads dpkg's database, so a host where apt
// cannot install still shows them.
func TestInventory_ListsImagePackagesWhereAptCannotInstall(t *testing.T) {
	for _, tc := range aptHostCases {
		t.Run(tc.name, func(t *testing.T) {
			s := stubApt(t)
			script := "#!/bin/sh\nprintf 'imagetool\\t2.0-1\\tinstalled\\toptional\\tno\\n'\n"
			if err := os.WriteFile(filepath.Join(s.dir, "dpkg-query"), []byte(script), 0o755); err != nil {
				t.Fatalf("Setup: %v", err)
			}
			fakeAptHost(t, tc.euid, tc.writable)
			e := newAptEngine(t)

			inv, err := e.Inventory()
			if err != nil {
				t.Fatalf("Inventory = %v", err)
			}
			if want := []AptPackage{{Name: "imagetool", Version: "2.0-1"}}; !slices.Equal(inv.AptPackages, want) {
				t.Errorf("AptPackages = %v, want %v", inv.AptPackages, want)
			}
		})
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
