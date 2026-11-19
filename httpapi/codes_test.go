package httpapi

import (
	"encoding/json"
	"maps"
	"net/http"
	"testing"

	"github.com/cplieger/go/httpserver/v2"
	"github.com/cplieger/go/httpserver/v2/httpservertest"
	"github.com/cplieger/toolbelt/v3"
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

// Without WithErrors a refusal of this package's own code carries its
// remediation; with it, every plain refusal goes through the given writer, and
// the two refusals with extra fields keep their remediation either way.
func TestRefusalsCarryRemediation(t *testing.T) {
	const doc = `{"entries":{"gh":{"name":"gh","source":"manual","version":"1","install":"true","essential":true}}}`
	e, h := newHandlerWithCatalog(t, doc)
	if _, err := e.Add(t.Context(), &toolbelt.AddRequest{Name: "gh", Disabled: true}); err != nil {
		t.Fatalf("Setup: add gh: %v", err)
	}
	rec, _ := serve(t, h, http.MethodDelete, "/api/tools/gh", "")
	var body httpserver.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Code != "essential" || body.Remediation != codeSpecs["essential"].Remediation {
		t.Errorf("default writer answered %s, want essential with its remediation", rec.Body.String())
	}

	var got []httpserver.ErrorCode
	custom := Handler(e, "/api/tools", WithErrors(func(w http.ResponseWriter, r *http.Request, status int, code httpserver.ErrorCode, msg string) {
		got = append(got, code)
		httpserver.WriteError(w, r, status, code, msg)
	}))
	serve(t, custom, http.MethodDelete, "/api/tools/gh", "")
	if len(got) != 1 || got[0] != "essential" {
		t.Errorf("WithErrors writer saw %v, want [essential]", got)
	}

	env := newErrorResponse(nil, "has_dependents", "tool has dependents: x")
	if env.Remediation != codeSpecs["has_dependents"].Remediation || env.RequestID == "" {
		t.Errorf("has_dependents envelope = %+v, want its remediation and a request id", env)
	}
}
