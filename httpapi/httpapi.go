// Package httpapi is the HTTP projection of a toolbelt Engine: a REST
// surface over the Engine's Go API, one route per method, JSON in and
// out. It is a pure function of the Engine — no auth, no SSE, and one
// piece of middleware only, the cache policy below; consumers wrap the
// returned handler in their own stack (an origin/CSP chain, a
// loopback-peer gate, logging) and stream job progress themselves via
// the Engine's Config callbacks or by polling the jobs route.
//
// Mutations return 202 with the enqueued job (null when the operation
// needed none, e.g. adding a disabled template). Refusals map to
// conflict responses: has_dependents and disabled are 409 with the
// standard webhttp error envelope, has_dependents additionally naming
// the blocking tools.
//
// # Cache policy
//
// The handler owns its cache policy: every response it produces
// carries Cache-Control: no-store, so a consumer no longer needs to
// wrap it in a no-store middleware of its own. This is a mutable JSON
// control plane — it lists jobs and accepts installs — so a stored
// response is always wrong, on a success body, a decode rejection, an
// engine error, and the mux's own 404/405/redirect alike.
//
// A Cache-Control header already set on the response when the handler
// runs is left exactly as it is, on the same rule webhttp.JSONHeaders
// applies to X-Content-Type-Options: a wrapping stack that states the
// policy stays that header's single writer. The package cannot tell a
// stricter value from a weaker one without parsing directives, so it
// treats any present value as deliberate — which makes an outer
// Cache-Control both the way to say "no-store, no-cache,
// must-revalidate" and the documented escape hatch for a consumer that
// genuinely wants this route cached.
package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/cplieger/toolbelt/v2"
	"github.com/cplieger/webhttp"
)

// maxBodyBytes caps request bodies: tool definitions are small.
const maxBodyBytes = 64 << 10

const (
	// cacheControlHeader is the response header this package owns.
	cacheControlHeader = "Cache-Control"
	// noStorePolicy is the policy it states: nothing this control plane
	// answers may be stored by a cache, shared or private.
	noStorePolicy = "no-store"
)

// JobResponse is the 202 body of every mutating route.
type JobResponse struct {
	Job *toolbelt.Job `json:"job"`
}

// SearchHit is one catalog search result. A projection of
// toolbelt.CatalogEntry without the embedded install definition (an
// implementation detail no client needs).
type SearchHit struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Source      string `json:"source"`
	// Version is the catalog's default pinned version, set only for
	// entries without an upstream version source (manual installs).
	Version  string `json:"version,omitempty"`
	Featured bool   `json:"featured,omitempty"`
	Lsp      bool   `json:"lsp,omitempty"`
}

// SearchResponse is the search route's body.
type SearchResponse struct {
	Results []SearchHit `json:"results"`
}

// JobsResponse is the jobs route's body: the active job (with output
// tail) and recent history.
type JobsResponse struct {
	Active *toolbelt.Job   `json:"active,omitempty"`
	Recent []*toolbelt.Job `json:"recent"`
}

// dependentsResponse is the 409 envelope for refused remove/disable:
// the standard error envelope plus the blocking tool names.
type dependentsResponse struct {
	Error      string   `json:"error"`
	Code       string   `json:"code"`
	Dependents []string `json:"dependents"`
}

// RemoveResponse rides a 409-free DELETE alongside the job (dependents
// is populated on forced cascades so the client can report what else
// was removed).
type RemoveResponse struct {
	Job        *toolbelt.Job `json:"job"`
	Dependents []string      `json:"dependents,omitempty"`
}

// routeHandler is the shape of every entry in the route table: the
// engine the projection reads, plus the standard http pair.
type routeHandler func(e *toolbelt.Engine, w http.ResponseWriter, r *http.Request)

// route is one route of the projection. Field order is
// fieldalignment's, not the reading order; the table below uses keyed
// literals so it reads method, path, handler regardless.
type route struct {
	// h serves the route.
	h routeHandler
	// method is the HTTP method the ServeMux pattern is anchored to.
	method string
	// suffix is appended to the mount prefix to form the pattern's path
	// ("" is the prefix itself); wildcards use ServeMux "{name}" syntax.
	suffix string
}

// routes is the projection's complete route table and the single source
// of truth for it: Handler registers exactly these, and the package's
// tests enumerate the same slice, so a route added here inherits the
// cache-policy coverage without the tests being touched.
var routes = []route{
	{method: http.MethodGet, suffix: "", h: getInventory},
	{method: http.MethodGet, suffix: "/search", h: getSearch},
	{method: http.MethodGet, suffix: "/jobs", h: func(e *toolbelt.Engine, w http.ResponseWriter, _ *http.Request) { getJobs(e, w) }},
	{method: http.MethodGet, suffix: "/catalog", h: func(e *toolbelt.Engine, w http.ResponseWriter, _ *http.Request) { getCatalog(e, w) }},
	{method: http.MethodPost, suffix: "/catalog/refresh", h: postCatalogRefresh},
	{method: http.MethodPost, suffix: "", h: postAdd},
	{method: http.MethodPost, suffix: "/update", h: postUpdate},
	{method: http.MethodPatch, suffix: "/{name}", h: patchTool},
	{method: http.MethodPost, suffix: "/{name}/install", h: postInstall},
	{method: http.MethodDelete, suffix: "/{name}", h: deleteTool},
	{method: http.MethodPost, suffix: "/jobs/{id}/cancel", h: postCancel},
}

// Handler builds the projection's routes under prefix (e.g.
// "/api/tools") and returns the handler. Mount it at both the exact
// prefix and the subtree:
//
//	h := httpapi.Handler(engine, "/api/tools")
//	mux.Handle("/api/tools", h)
//	mux.Handle("/api/tools/", h)
//
// Every response the returned handler produces carries Cache-Control:
// no-store unless the header is already set — see the package doc's
// cache-policy section.
func Handler(e *toolbelt.Engine, prefix string) http.Handler {
	prefix = strings.TrimSuffix(prefix, "/")
	mux := http.NewServeMux()
	for _, rt := range routes {
		mux.HandleFunc(rt.method+" "+prefix+rt.suffix, func(w http.ResponseWriter, r *http.Request) {
			rt.h(e, w, r)
		})
	}
	return withNoStore(mux)
}

// withNoStore states the package's cache policy on the response header
// map before h runs, which is the only site that cannot be missed: it
// is upstream of every route in the table, of every error writer those
// routes reach, and of the responses the mux itself generates (404 for
// an unrouted path, 405 for a method the path doesn't serve, a
// path-cleaning redirect). Setting it here also settles the ordering
// requirement structurally — the header is in the map before any
// handler can call WriteHeader, after which it would be ignored.
//
// A value already present is left alone; see the package doc for why
// that, and not an overwrite, is the right precedence.
func withNoStore(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if w.Header().Get(cacheControlHeader) == "" {
			w.Header().Set(cacheControlHeader, noStorePolicy)
		}
		h.ServeHTTP(w, r)
	})
}

func getInventory(e *toolbelt.Engine, w http.ResponseWriter, r *http.Request) {
	inv, err := e.Inventory()
	if err != nil {
		webhttp.WriteError(w, r, http.StatusInternalServerError, "inventory_failed", err.Error())
		return
	}
	webhttp.WriteJSON(w, inv)
}

func getSearch(e *toolbelt.Engine, w http.ResponseWriter, r *http.Request) {
	hits := e.Search(r.URL.Query().Get("q"))
	res := SearchResponse{Results: make([]SearchHit, 0, len(hits))}
	for i := range hits {
		res.Results = append(res.Results, SearchHit{
			Name:        hits[i].Name,
			Description: hits[i].Description,
			Source:      hits[i].Source,
			Version:     hits[i].Version,
			Featured:    hits[i].Featured,
			Lsp:         hits[i].Lsp,
		})
	}
	webhttp.WriteJSON(w, res)
}

func getJobs(e *toolbelt.Engine, w http.ResponseWriter) {
	active, recent := e.Jobs()
	if recent == nil {
		recent = []*toolbelt.Job{}
	}
	webhttp.WriteJSON(w, JobsResponse{Active: active, Recent: recent})
}

func getCatalog(e *toolbelt.Engine, w http.ResponseWriter) {
	webhttp.WriteJSON(w, e.CatalogInfo())
}

func postCatalogRefresh(e *toolbelt.Engine, w http.ResponseWriter, r *http.Request) {
	job, err := e.RefreshCatalog()
	if err != nil {
		writeEngineError(w, r, err)
		return
	}
	webhttp.WriteJSONStatus(w, http.StatusAccepted, JobResponse{Job: job})
}

func postAdd(e *toolbelt.Engine, w http.ResponseWriter, r *http.Request) {
	var req toolbelt.AddRequest
	if err := webhttp.DecodeJSONInto(w, r, &req, maxBodyBytes); err != nil {
		webhttp.WriteError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	job, err := e.Add(r.Context(), &req)
	if err != nil {
		writeEngineError(w, r, err)
		return
	}
	webhttp.WriteJSONStatus(w, http.StatusAccepted, JobResponse{Job: job})
}

func postUpdate(e *toolbelt.Engine, w http.ResponseWriter, r *http.Request) {
	var req struct {
		Names []string `json:"names,omitempty"`
	}
	if r.ContentLength != 0 {
		if err := webhttp.DecodeJSONInto(w, r, &req, maxBodyBytes); err != nil {
			webhttp.WriteError(w, r, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
	}
	job, err := e.Update(req.Names...)
	if err != nil {
		writeEngineError(w, r, err)
		return
	}
	webhttp.WriteJSONStatus(w, http.StatusAccepted, JobResponse{Job: job})
}

func patchTool(e *toolbelt.Engine, w http.ResponseWriter, r *http.Request) {
	var req toolbelt.PatchRequest
	if err := webhttp.DecodeJSONInto(w, r, &req, maxBodyBytes); err != nil {
		webhttp.WriteError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	job, err := e.Patch(r.PathValue("name"), req)
	if err != nil {
		writeEngineError(w, r, err)
		return
	}
	webhttp.WriteJSONStatus(w, http.StatusAccepted, JobResponse{Job: job})
}

func postInstall(e *toolbelt.Engine, w http.ResponseWriter, r *http.Request) {
	job, err := e.Install(r.PathValue("name"))
	if err != nil {
		writeEngineError(w, r, err)
		return
	}
	webhttp.WriteJSONStatus(w, http.StatusAccepted, JobResponse{Job: job})
}

func deleteTool(e *toolbelt.Engine, w http.ResponseWriter, r *http.Request) {
	force := r.URL.Query().Get("force") == "1" || r.URL.Query().Get("force") == "true"
	job, dependents, err := e.Remove(r.PathValue("name"), force)
	if err != nil {
		writeEngineError(w, r, err)
		return
	}
	webhttp.WriteJSONStatus(w, http.StatusAccepted, RemoveResponse{Job: job, Dependents: dependents})
}

func postCancel(e *toolbelt.Engine, w http.ResponseWriter, r *http.Request) {
	if !e.CancelJob(r.PathValue("id")) {
		webhttp.WriteError(w, r, http.StatusNotFound, "not_found", "no such job")
		return
	}
	webhttp.Ok(w)
}

// writeEngineError maps engine sentinels onto wire responses.
func writeEngineError(w http.ResponseWriter, r *http.Request, err error) {
	var dep *toolbelt.DependentsError
	switch {
	case errors.As(err, &dep):
		webhttp.WriteJSONStatus(w, http.StatusConflict, dependentsResponse{
			Error:      dep.Error(),
			Code:       "has_dependents",
			Dependents: dep.Dependents,
		})
	case errors.Is(err, toolbelt.ErrNotFound):
		webhttp.WriteError(w, r, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, toolbelt.ErrDisabled):
		webhttp.WriteError(w, r, http.StatusConflict, "disabled", err.Error())
	case errors.Is(err, toolbelt.ErrRefreshNotConfigured):
		webhttp.WriteError(w, r, http.StatusConflict, "not_configured", err.Error())
	default:
		webhttp.WriteError(w, r, http.StatusBadRequest, "bad_request", err.Error())
	}
}
