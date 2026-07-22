// Package httpapi is the HTTP projection of a toolbelt Engine: a REST
// surface over the Engine's Go API, one route per method, JSON in and
// out. It is a pure function of the Engine — no auth, no SSE, no
// middleware; consumers wrap the returned handler in their own stack
// (an origin/CSP chain, a loopback-peer gate, logging) and stream job
// progress themselves via the Engine's Config callbacks or by polling
// the jobs route.
//
// Mutations return 202 with the enqueued job (null when the operation
// needed none, e.g. adding a disabled template). Refusals map to
// conflict responses: has_dependents and disabled are 409 with the
// standard webhttp error envelope, has_dependents additionally naming
// the blocking tools.
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

// Handler builds the projection's routes under prefix (e.g.
// "/api/tools") and returns the handler. Mount it at both the exact
// prefix and the subtree:
//
//	h := httpapi.Handler(engine, "/api/tools")
//	mux.Handle("/api/tools", h)
//	mux.Handle("/api/tools/", h)
func Handler(e *toolbelt.Engine, prefix string) http.Handler {
	prefix = strings.TrimSuffix(prefix, "/")
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+prefix, func(w http.ResponseWriter, r *http.Request) { getInventory(e, w, r) })
	mux.HandleFunc("GET "+prefix+"/search", func(w http.ResponseWriter, r *http.Request) { getSearch(e, w, r) })
	mux.HandleFunc("GET "+prefix+"/jobs", func(w http.ResponseWriter, _ *http.Request) { getJobs(e, w) })
	mux.HandleFunc("GET "+prefix+"/catalog", func(w http.ResponseWriter, _ *http.Request) { getCatalog(e, w) })
	mux.HandleFunc("POST "+prefix+"/catalog/refresh", func(w http.ResponseWriter, r *http.Request) { postCatalogRefresh(e, w, r) })
	mux.HandleFunc("POST "+prefix, func(w http.ResponseWriter, r *http.Request) { postAdd(e, w, r) })
	mux.HandleFunc("POST "+prefix+"/update", func(w http.ResponseWriter, r *http.Request) { postUpdate(e, w, r) })
	mux.HandleFunc("PATCH "+prefix+"/{name}", func(w http.ResponseWriter, r *http.Request) { patchTool(e, w, r) })
	mux.HandleFunc("POST "+prefix+"/{name}/install", func(w http.ResponseWriter, r *http.Request) { postInstall(e, w, r) })
	mux.HandleFunc("DELETE "+prefix+"/{name}", func(w http.ResponseWriter, r *http.Request) { deleteTool(e, w, r) })
	mux.HandleFunc("POST "+prefix+"/jobs/{id}/cancel", func(w http.ResponseWriter, r *http.Request) { postCancel(e, w, r) })
	return mux
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
