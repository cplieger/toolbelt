//go:build linux

package pin_test

import (
	"fmt"
	"strings"

	"github.com/cplieger/toolbelt/v3/pin"
)

// widgetConfig is one deployment of a fictional "widget" release: the
// profile, then the pin, the root and the assertions.
func widgetConfig() *pin.Config {
	return &pin.Config{
		Name:        "widget",
		URLTemplate: "https://widgets.example/dl/{arch}/widget_{version}.tar.gz",
		ArchTokens:  map[string]string{"amd64": "linux-64", "arm64": "linux-arm"},
		ArtifactDir: "widget/bin",
		ProbeArgs:   []string{"--version"},
		Version:     "1.4.2",
		Digests: map[string]string{
			"amd64": strings.Repeat("a", 64),
			"arm64": strings.Repeat("b", 64),
		},
		Root:    "/var/lib/example/tools",
		LinkDir: "bin",
		Require: []string{"widget-helper"},
		Assertions: []pin.Assertion{
			// The widget must not update itself: that would replace the
			// artifact whose digest was verified.
			{Name: "autoupdate", Args: []string{"config", "set", "autoupdate", "off"}, Required: true},
			{Name: "telemetry", Args: []string{"config", "set", "telemetry", "off"}},
		},
	}
}

// ExampleNew builds a manager; nothing is downloaded until Ensure runs.
func ExampleNew() {
	mgr, err := pin.New(widgetConfig())
	if err != nil {
		fmt.Println("config error:", err)
		return
	}

	// Before the first Ensure nothing is active, and the reason says why.
	ready, why := mgr.Ready()
	fmt.Println("ready:", ready, "reason:", why)
	fmt.Printf("path: %q version: %q\n", mgr.Path(), mgr.Version())

	// Output:
	// ready: false reason: installing
	// path: "" version: ""
}

// ExampleNew_noRequiredAssertion shows the construction error a profile author
// is most likely to hit: a config with no Required assertion is refused.
func ExampleNew_noRequiredAssertion() {
	cfg := widgetConfig()
	cfg.Assertions = cfg.Assertions[1:]

	_, err := pin.New(cfg)
	fmt.Println(strings.SplitN(err.Error(), ". ", 2)[0])

	// Output:
	// pin: Assertions has no Required entry
}
