// Package httpapi is the HTTP projection of a toolbelt Engine: a REST
// surface over the Engine's Go API, one route per method, JSON in and
// out. No auth, no SSE; consumers wrap the handler in their own stack
// and stream job progress via the Engine's Config callbacks or by
// polling the jobs route.
//
// Mutations return 202 with the enqueued job (null when none was
// needed). has_dependents and disabled refusals are 409.
//
// GET /search?q=<query> returns installable hits, and, with
// &unavailable=1, the catalog entries no install source exists for
// (opt-in: a UI offering installs has no use for a row it cannot act
// on). See [SearchResponse].
//
// Every response carries Cache-Control: no-store, since this is a
// mutable JSON control plane where a stored response is always wrong.
// A value already set when the handler runs is left as-is, treated as
// deliberate — the escape hatch for a consumer that wants a route
// cached.
package httpapi

import (
	"errors"
	"net/http"
	"slices"
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
	Version string `json:"version,omitempty"`
	// Reason names the registry backend that defeated the compiler, and
	// is set only alongside Unavailable.
	Reason string `json:"reason,omitempty"`
	// Match names which field the query hit — see [toolbelt.MatchKind].
	// Empty for the featured set and for an unavailable hit. On the wire
	// because a client cannot derive it: aliases are not projected here,
	// so a hit on `rg` would look like a description match otherwise.
	Match    string `json:"match,omitempty"`
	Featured bool   `json:"featured,omitempty"`
	Lsp      bool   `json:"lsp,omitempty"`
	// Unavailable marks a hit the catalog knows about and cannot
	// install, with Reason naming the registry backend that defeated the
	// compiler. Such a hit is informational: a client must not offer an
	// install for it, and the engine refuses one anyway.
	//
	// Both fields are omitempty, so an installable hit serialises exactly
	// as it did before this pair existed.
	Unavailable bool `json:"unavailable,omitempty"`
	// Apt marks a Debian package rather than a catalog entry. Version
	// then carries the distro's candidate, which routinely differs from
	// the catalog's version for the same tool, and the row's install lands
	// in the container layer rather than on the persistent volume.
	Apt bool `json:"apt,omitempty"`
}

// SearchResponse is the search route's body: installable hits merged
// into one relevance order via [toolbelt.Match] (catalog and Debian, not
// concatenated — a bare concatenation put every catalog hit ahead of
// every Debian one regardless of score), then the opt-in unavailable
// block, kept separate and unranked since ranking a dead end above a
// live option would be wrong.
//
// AptAvailable distinguishes "no Debian package matched" from "the
// package list could not be consulted" — identical in an empty result,
// opposite in meaning.
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
// "/api/tools"). Mount it at both the exact prefix and the subtree:
//
//	h := httpapi.Handler(engine, "/api/tools")
//	mux.Handle("/api/tools", h)
//	mux.Handle("/api/tools/", h)
//
// Every response carries Cache-Control: no-store unless already set.
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

// withNoStore states the package's cache policy before h runs: upstream
// of every route, every error writer, and the mux's own 404/405/redirect
// responses, and before any handler can call WriteHeader (after which a
// header set here would be ignored). A value already present is left
// alone; see the package doc for why.
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

// searchUnavailableParam opts a caller INTO the uninstallable block;
// absent means hidden. Hidden by default because a UI offering installs
// has no use for a row it cannot act on, while an agent reading this
// API benefits from knowing why a tool cannot be installed rather than
// getting an empty result. A per-request parameter serves both without
// a deployment flag.
const searchUnavailableParam = "unavailable"

func getSearch(e *toolbelt.Engine, w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	installable := e.Search(q)
	aptHits, aptOK := e.SearchApt(q)

	var unavailable []toolbelt.CatalogEntry
	if searchWantsUnavailable(r) {
		unavailable = e.SearchUnavailable(q)
	}

	merged := mergeSearchHits(installable, aptHits, q)
	res := SearchResponse{
		Results:      make([]SearchHit, 0, len(merged)+len(unavailable)),
		AptAvailable: aptOK,
	}
	res.Results = append(res.Results, merged...)
	for i := range unavailable {
		res.Results = append(res.Results, searchHit(&unavailable[i], true))
	}
	webhttp.WriteJSON(w, res)
}

// mergeSearchHits projects both installable corpora into ONE
// relevance-ordered list, stamping each hit's match kind on the way.
//
// A pure function of its inputs: apt needs root, so a test driving the
// route can only exercise this merge on a privileged host — this way
// the ordering gets a test that runs on every CI runner.
//
// Sort is skipped for an empty query (the featured set): every hit
// scores 0 then, so sorting would discard Featured's by-name order for
// the length tie-break instead.
func mergeSearchHits(catalog []toolbelt.CatalogEntry, apt []toolbelt.AptHit, query string) []SearchHit {
	// The score is an implementation detail of the ranking and never
	// reaches the wire, unlike the match kind, which is a contract.
	type ranked struct {
		hit  SearchHit
		rank toolbelt.Rank
	}
	scored := make([]ranked, 0, len(catalog)+len(apt))
	add := func(hit SearchHit, aliases []string) {
		kind, score := toolbelt.Match(hit.Name, aliases, hit.Description, query)
		hit.Match = string(kind)
		scored = append(scored, ranked{hit: hit, rank: toolbelt.Rank{Name: hit.Name, Score: score}})
	}
	for i := range catalog {
		add(searchHit(&catalog[i], false), catalog[i].Aliases)
	}
	for i := range apt {
		add(SearchHit{
			Name:        apt[i].Name,
			Description: apt[i].Description,
			Source:      toolbelt.SourceApt + ":" + apt[i].Name,
			Version:     apt[i].Candidate,
			Apt:         true,
		}, nil)
	}
	if strings.TrimSpace(query) != "" {
		slices.SortStableFunc(scored, func(a, b ranked) int {
			return toolbelt.CompareRank(a.rank, b.rank)
		})
	}
	hits := make([]SearchHit, 0, len(scored))
	for i := range scored {
		hits = append(hits, scored[i].hit)
	}
	return hits
}

// searchWantsUnavailable reads the opt-in parameter. A bare
// `?unavailable` counts too: a caller writing that plainly means yes.
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
