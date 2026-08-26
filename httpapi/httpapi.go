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
// # Search
//
// GET /search?q=<query> returns installable catalog entries followed by
// matching Debian packages. Adding &unavailable=1 appends the catalog
// entries no install source exists for, each carrying the registry
// backend that defeated the compiler. That block is opt-in rather than
// default, because a UI offering things to install has no use for a row
// it cannot act on, while an agent calling this API is better served by
// "this tool is known and here is why it cannot be installed" than by an
// empty result.
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

	"github.com/cplieger/toolbelt/v3"
	"github.com/cplieger/webhttp/v2"
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
	// Unavailable marks a hit the catalog knows about and cannot
	// install, with Reason naming the registry backend that defeated the
	// compiler. Such a hit is informational: a client must not offer an
	// install for it, and the engine refuses one anyway.
	//
	// Both fields are omitempty, so an installable hit serialises exactly
	// as it did before this pair existed.
	Unavailable bool   `json:"unavailable,omitempty"`
	Reason      string `json:"reason,omitempty"`
	// Apt marks a Debian package rather than a catalog entry. Version
	// then carries the distro's candidate, which routinely differs from
	// the catalog's version for the same tool, and the row's install lands
	// in the container layer rather than on the persistent volume.
	Apt bool `json:"apt,omitempty"`
}

// SearchResponse is the search route's body. Results arrive in blocks,
// in this order: installable catalog entries, Debian packages, then,
// only when the caller asked for them, the catalog entries no install
// source exists for. Each block is capped independently by the engine, so
// a client renders them as sections without re-sorting and one corpus
// cannot crowd out another.
//
// The third block is OPT-IN via `?unavailable=1`. Absent by default
// because a dialog offering things to install has no use for a row it
// cannot act on, while an agent reading this API does: it would rather be
// told a tool is known and why it cannot be installed than get an empty
// result and conclude the tool does not exist.
//
// AptAvailable distinguishes "no Debian package matched" from "the
// package list could not be consulted", which look identical in an empty
// result and mean opposite things.
type SearchResponse struct {
	Results      []SearchHit `json:"results"`
	AptAvailable bool        `json:"apt_available"`
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

// searchUnavailableParam is the query parameter that opts a caller INTO
// the uninstallable block. Absent means hidden, which is the default
// every consumer gets by doing nothing.
//
// Hidden by default because the two consumers want opposite things and
// only one of them is a person: vibekit's Add dialog offers what can be
// installed, and a row it cannot act on is noise there. The headless
// consumer's caller is an agent reading the loopback API, which benefits
// from being told a tool is known and why it cannot be installed instead
// of getting an empty result. A per-request parameter serves both without
// a deployment flag or a per-app build.
const searchUnavailableParam = "unavailable"

func getSearch(e *toolbelt.Engine, w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	installable := e.Search(q)
	aptHits, aptOK := e.SearchApt(q)

	var unavailable []toolbelt.CatalogEntry
	if searchWantsUnavailable(r) {
		unavailable = e.SearchUnavailable(q)
	}

	res := SearchResponse{
		Results:      make([]SearchHit, 0, len(installable)+len(aptHits)+len(unavailable)),
		AptAvailable: aptOK,
	}
	for i := range installable {
		res.Results = append(res.Results, searchHit(&installable[i], false))
	}
	for i := range aptHits {
		res.Results = append(res.Results, SearchHit{
			Name:        aptHits[i].Name,
			Description: aptHits[i].Description,
			Source:      toolbelt.SourceApt + ":" + aptHits[i].Name,
			Version:     aptHits[i].Candidate,
			Apt:         true,
		})
	}
	for i := range unavailable {
		res.Results = append(res.Results, searchHit(&unavailable[i], true))
	}
	webhttp.WriteJSON(w, res)
}

// searchWantsUnavailable reads the opt-in parameter. Any of the usual
// affirmative spellings counts, and a bare `?unavailable` counts too,
// because a caller writing that plainly means yes and answering it with
// silence would be the unhelpful reading.
func searchWantsUnavailable(r *http.Request) bool {
	qs := r.URL.Query()
	if !qs.Has(searchUnavailableParam) {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(qs.Get(searchUnavailableParam))) {
	case "", "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// searchHit projects a catalog entry, dropping the embedded install
// definition no client needs.
func searchHit(e *toolbelt.CatalogEntry, unavailable bool) SearchHit {
	return SearchHit{
		Name:        e.Name,
		Description: e.Description,
		Source:      e.Source,
		Version:     e.Version,
		Featured:    e.Featured,
		Lsp:         e.Lsp,
		Unavailable: unavailable,
		Reason:      e.Reason,
	}
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
	// The route's ?force=1 is the caller's cascade intent; the two engine
	// methods are what that intent selects.
	force := r.URL.Query().Get("force") == "1" || r.URL.Query().Get("force") == "true"
	remove := e.Remove
	if force {
		remove = e.RemoveWithDependents
	}
	job, dependents, err := remove(r.PathValue("name"))
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
