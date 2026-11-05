package pin_test

import (
	"fmt"
	"strings"
	"time"

	"github.com/cplieger/pinstall/v3"
)

// widgetRelease is the profile a consumer of a fictional "widget" release writes
// once. Everything in it is true of the package regardless of where it is deployed.
func widgetRelease() pinstall.Release {
	return pinstall.Release{
		Name:        "widget",
		Binary:      "widget-cli", // the package and its binary have different names
		URLTemplate: "https://widgets.example/dl/{arch}/widget_{version}.zip",
		ArchTokens:  map[string]string{"amd64": "linux-64", "arm64": "linux-arm"},
		Installer: &pinstall.ArchiveInstaller{
			Path:    "widget/install.sh",
			Args:    []string{"--no-confirm"},
			Timeout: 2 * time.Minute,
		},
		ArtifactDir: ".local/bin",
		ProbeArgs:   []string{"--version"},
		Mandatory: []pinstall.Assertion{
			// At least one is required: it is the guarantee a deployment cannot
			// drop. Here, the package must not update itself, because that would
			// replace the artifact whose digest was verified.
			{Name: "autoupdate", Args: []string{"config", "set", "autoupdate", "off"}},
		},
	}
}

// ExampleNew builds a manager for one deployment of the widget release. The pin and
// the digests come from wherever the consumer keeps them; nothing is downloaded until
// Ensure runs.
func ExampleNew() {
	mgr, err := pinstall.New(&pinstall.Config{
		Release: widgetRelease(),
		Version: "1.4.2",
		Digests: map[string]string{
			"amd64": strings.Repeat("a", 64),
			"arm64": strings.Repeat("b", 64),
		},
		Root:    "/var/lib/example/tools",
		GOARCH:  "amd64",
		LinkDir: "bin",
		Require: []string{"widget-helper"},
		Assert: []pinstall.Assertion{
			{Name: "telemetry", Args: []string{"config", "set", "telemetry", "off"}},
		},
		Retain: 2,
	})
	if err != nil {
		fmt.Println("config error:", err)
		return
	}

	// Before the first Ensure nothing is active, and the reason says why.
	ready, why := mgr.Ready()
	fmt.Println("ready:", ready, "reason:", why)
	fmt.Printf("path: %q\n", mgr.Path())

	// Output:
	// ready: false reason: installing
	// path: ""
}

// ExampleNew_missingMandatory shows the one construction error a profile author is
// most likely to hit: a release with no mandatory assertion is refused, so a
// guarantee cannot be lost by omitting it.
func ExampleNew_missingMandatory() {
	release := widgetRelease()
	release.Mandatory = nil

	_, err := pinstall.New(&pinstall.Config{
		Release: release,
		Version: "1.4.2",
		Digests: map[string]string{"amd64": strings.Repeat("a", 64)},
		Root:    "/var/lib/example/tools",
		GOARCH:  "amd64",
	})
	fmt.Println(strings.SplitN(err.Error(), ". ", 2)[0])

	// Output:
	// pinstall: Release.Mandatory is empty
}

// ExampleLastFieldOfFirstLine shows the default version parser, which covers the two
// common probe shapes and returns "" when there is nothing to take.
func ExampleLastFieldOfFirstLine() {
	fmt.Printf("%q\n", pinstall.LastFieldOfFirstLine("widget 1.4.2\n"))
	fmt.Printf("%q\n", pinstall.LastFieldOfFirstLine("1.4.2\n"))
	fmt.Printf("%q\n", pinstall.LastFieldOfFirstLine("widget 1.4.2\nbuilt 2026-01-01\n"))
	fmt.Printf("%q\n", pinstall.LastFieldOfFirstLine("\n"))

	// Output:
	// "1.4.2"
	// "1.4.2"
	// "1.4.2"
	// ""
}
