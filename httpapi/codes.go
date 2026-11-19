package httpapi

import (
	"maps"
	"net/http"

	"github.com/cplieger/go/httpserver/v2"
	"github.com/cplieger/toolbelt/v3"
)

// codeSpecs holds exactly the codes this package answers besides httpserver's
// own bad_request and not_found; httpservertest.CheckCodeSpecs holds it to the
// source. Every refusal here changes nothing, so each is safe to resend.
var codeSpecs = map[httpserver.ErrorCode]httpserver.CodeSpec{
	"inventory_failed":                  {Status: http.StatusInternalServerError, Remediation: "Retry the request; if it fails again, the server log names the inventory error.", NoEffect: true},
	"has_dependents":                    {Status: http.StatusConflict, Remediation: "Remove or disable the tools listed in dependents first, or resend with force=1 to remove them too.", NoEffect: true},
	toolbelt.ErrorCodeGitHubRateLimited: {Status: http.StatusServiceUnavailable, Remediation: "Retry after rate_limit.reset_at, or give the server a GitHub token to raise the limit.", NoEffect: true},
	"essential":                         {Status: http.StatusConflict, Remediation: "Keep the tool: the product that serves this API needs it.", NoEffect: true},
	"disabled":                          {Status: http.StatusConflict, Remediation: "Enable the tool's entry, then install it.", NoEffect: true},
	"not_configured":                    {Status: http.StatusConflict, Remediation: "This server has no catalog refresh configured, so the request cannot run here.", NoEffect: true},
	"queue_full":                        {Status: http.StatusServiceUnavailable, Remediation: "Retry once a queued job finishes.", NoEffect: true},
	"shutting_down":                     {Status: http.StatusServiceUnavailable, Remediation: "Retry after the server restarts.", NoEffect: true},
}

// CodeSpecs returns every code this package answers that httpserver's own
// CodeSpecs does not list, with its status and default remediation, for an
// application's error catalog. The map is the caller's own copy.
func CodeSpecs() map[httpserver.ErrorCode]httpserver.CodeSpec {
	return maps.Clone(codeSpecs)
}

// codeOf is the route table's entry for c, its status read from the one spec
// that owns c: this package's, else httpserver's.
func codeOf(c httpserver.ErrorCode) Code {
	spec, ok := codeSpecs[c]
	if !ok {
		spec = httpserver.CodeSpecs()[c]
	}
	return Code{Code: string(c), Status: spec.Status}
}
