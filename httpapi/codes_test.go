package httpapi

import (
	"maps"
	"testing"

	"github.com/cplieger/go/httpserver/v2"
	"github.com/cplieger/go/httpserver/v2/httpservertest"
)

// The source writes exactly the codes CodeSpecs and httpserver's own CodeSpecs
// list, and CodeSpecs claims none of httpserver's, so a catalog's AddOwned
// takes both without a clash.
func TestCodeSpecs_matchSource(t *testing.T) {
	own := CodeSpecs()
	all := httpserver.CodeSpecs()
	for code := range own {
		if _, clash := all[code]; clash {
			t.Errorf("CodeSpecs lists %q, which httpserver owns", code)
		}
	}
	maps.Copy(all, own)
	written := maps.Clone(all)
	for code := range httpserver.CodeSpecs() {
		if code != "bad_request" && code != "not_found" {
			delete(written, code)
		}
	}
	httpservertest.CheckCodeSpecs(t, ".", written)
}

// Every code the route table names answers the status its spec holds, so a
// host binding Routes itself documents the same status Handler writes.
func TestRoutesCodes_matchSpecs(t *testing.T) {
	all := httpserver.CodeSpecs()
	maps.Copy(all, CodeSpecs())
	for _, rt := range Routes() {
		for _, c := range rt.Codes {
			spec, ok := all[httpserver.ErrorCode(c.Code)]
			if !ok || spec.Status != c.Status || spec.Remediation == "" {
				t.Errorf("%s %s: code %q status %d has no matching spec with a remediation (%+v)", rt.Method, rt.Suffix, c.Code, c.Status, spec)
			}
		}
	}
}
