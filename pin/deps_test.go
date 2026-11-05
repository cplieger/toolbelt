//go:build linux

package pin

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestPinLinksNoEngineDependency pins N1: a program that imports only pin
// links none of the engine's third-party requires.
func TestPinLinksNoEngineDependency(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command on PATH")
	}
	cmd := exec.CommandContext(t.Context(), gobin, "list", "-deps", ".")
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=mod")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	for dep := range strings.SplitSeq(string(out), "\n") {
		for _, forbidden := range []string{"github.com/expr-lang/", "github.com/BurntSushi/", "go.yaml.in/", "golang.org/x/mod"} {
			if strings.HasPrefix(dep, forbidden) {
				t.Errorf("pin links %s, an engine dependency", dep)
			}
		}
	}
}
