package httpapi

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/toolbelt/v3"
)

// newServer builds an engine on temp dirs and serves the projection at
// /api/tools.
func newServer(t *testing.T) (*toolbelt.Engine, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	e, err := toolbelt.New(&toolbelt.Config{
		ConfigDir: dir,
		ToolsDir:  dir + "/tools",
		Logger:    slog.Default(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	h := Handler(e, "/api/tools")
	mux := http.NewServeMux()
	mux.Handle("/api/tools", h)
	mux.Handle("/api/tools/", h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return e, srv
}

// call issues a JSON request and decodes the response body into out
// (when non-nil), returning the status code.
func call(t *testing.T, srv *httptest.Server, method, path, body string, out any) int {
	t.Helper()
	var rdr *strings.Reader
	if body == "" {
		rdr = strings.NewReader("")
	} else {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, srv.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if out != nil {
		if err := json.NewDecoder(res.Body).Decode(out); err != nil {
			t.Fatalf("%s %s: decode: %v", method, path, err)
		}
	}
	return res.StatusCode
}

// waitDone polls the jobs endpoint until the named job finishes.
func waitDone(t *testing.T, srv *httptest.Server, jobID string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		var jr JobsResponse
		call(t, srv, http.MethodGet, "/api/tools/jobs", "", &jr)
		for _, r := range jr.Recent {
			if r.ID == jobID {
				if r.State != toolbelt.JobDone {
					t.Fatalf("job %s = %+v", jobID, r)
				}
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("job %s never finished", jobID)
}

// addBody is an add request whose install command writes a RUNNABLE stub
// into $BIN. The engine's install probe executes what it finds there, so
// a fixture that only creates a file reads as not installed.
func addBody(name string) string {
	install := fmt.Sprintf(`printf "#!/bin/sh\necho %s $VERSION\n" > "$BIN/%s" && chmod 755 "$BIN/%s"`,
		name, name, name)
	cmd, err := json.Marshal(install)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf(`{"name":%q,"source":"manual","version":"1","install":%s}`, name, cmd)
}

func TestRoutes_EndToEnd(t *testing.T) {
	_, srv := newServer(t)

	// Empty inventory.
	var inv toolbelt.Inventory
	if code := call(t, srv, http.MethodGet, "/api/tools", "", &inv); code != http.StatusOK {
		t.Fatalf("GET inventory = %d", code)
	}
	if len(inv.Tools) != 0 {
		t.Fatalf("fresh inventory = %+v", inv.Tools)
	}

	// Add a manual tool: 202 + job.
	var jr JobResponse
	if code := call(t, srv, http.MethodPost, "/api/tools", addBody("t1"), &jr); code != http.StatusAccepted {
		t.Fatalf("POST add = %d", code)
	}
	if jr.Job == nil {
		t.Fatal("add returned no job")
	}
	waitDone(t, srv, jr.Job.ID)

	// Row shows installed.
	call(t, srv, http.MethodGet, "/api/tools", "", &inv)
	if len(inv.Tools) != 1 || !inv.Tools[0].Installed {
		t.Fatalf("inventory after install = %+v", inv.Tools)
	}

	// Disable via PATCH: 202 + disable job; row flips.
	if code := call(t, srv, http.MethodPatch, "/api/tools/t1", `{"disabled":true}`, &jr); code != http.StatusAccepted {
		t.Fatalf("PATCH disable = %d", code)
	}
	waitDone(t, srv, jr.Job.ID)
	call(t, srv, http.MethodGet, "/api/tools", "", &inv)
	if inv.Tools[0].Installed || !inv.Tools[0].Disabled {
		t.Fatalf("row after disable = %+v", inv.Tools[0])
	}

	// Install on a disabled template: 409 code=disabled.
	var errBody struct {
		Code string `json:"code"`
	}
	if code := call(t, srv, http.MethodPost, "/api/tools/t1/install", "", &errBody); code != http.StatusConflict || errBody.Code != "disabled" {
		t.Fatalf("install disabled = %d code=%q", code, errBody.Code)
	}

	// Enable via PATCH installs again.
	if code := call(t, srv, http.MethodPatch, "/api/tools/t1", `{"disabled":false}`, &jr); code != http.StatusAccepted {
		t.Fatalf("PATCH enable = %d", code)
	}
	waitDone(t, srv, jr.Job.ID)

	// Unknown tool: 404.
	if code := call(t, srv, http.MethodPatch, "/api/tools/nope", `{"pin":true}`, &errBody); code != http.StatusNotFound {
		t.Fatalf("PATCH unknown = %d", code)
	}

	// Cancel unknown job: 404.
	if code := call(t, srv, http.MethodPost, "/api/tools/jobs/tj-nope/cancel", "", &errBody); code != http.StatusNotFound {
		t.Fatalf("cancel unknown = %d", code)
	}
}

// slowAddBody is addBody with the install stalled, so the job stays
// running long enough for the cancel route to catch it.
func slowAddBody(name string) string {
	install := fmt.Sprintf(`sleep 3 && printf "#!/bin/sh\necho %s $VERSION\n" > "$BIN/%s" && chmod 755 "$BIN/%s"`,
		name, name, name)
	cmd, err := json.Marshal(install)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf(`{"name":%q,"source":"manual","version":"1","install":%s}`, name, cmd)
}

// rawJobs is the jobs route decoded without the library's types: the
// point is what an operator (or an older consumer) literally receives.
func rawJobs(t *testing.T, srv *httptest.Server) []map[string]any {
	t.Helper()
	var body struct {
		Active map[string]any   `json:"active"`
		Recent []map[string]any `json:"recent"`
	}
	call(t, srv, http.MethodGet, "/api/tools/jobs", "", &body)
	if body.Active != nil {
		return append([]map[string]any{body.Active}, body.Recent...)
	}
	return body.Recent
}

// waitRawJob polls the jobs route until the id shows up in a terminal
// state and returns its raw payload.
func waitRawJob(t *testing.T, srv *httptest.Server, jobID string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		for _, j := range rawJobs(t, srv) {
			if j["id"] != jobID {
				continue
			}
			switch j["state"] {
			case toolbelt.JobDone, toolbelt.JobFailed, toolbelt.JobCancelled:
				return j
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("job %s never finished", jobID)
	return nil
}

// TestCancelRoute_ReportsCallerCause: a cancellation through the route is
// an operator action, and the JSON must say so. The addition is additive
// — a job nobody cancelled carries no cancel_cause key at all, so an
// older consumer's payload is unchanged.
func TestCancelRoute_ReportsCallerCause(t *testing.T) {
	_, srv := newServer(t)

	var done JobResponse
	call(t, srv, http.MethodPost, "/api/tools", addBody("finished"), &done)
	waitDone(t, srv, done.Job.ID)

	var slow JobResponse
	if code := call(t, srv, http.MethodPost, "/api/tools", slowAddBody("stalled"), &slow); code != http.StatusAccepted {
		t.Fatalf("POST add slow = %d", code)
	}
	if code := call(t, srv, http.MethodPost, "/api/tools/jobs/"+slow.Job.ID+"/cancel", "", nil); code != http.StatusOK {
		t.Fatalf("POST cancel = %d", code)
	}

	cases := map[string]struct {
		jobID string
		// wantState is the state field the payload must still carry;
		// wantCause is the cancel_cause value ("" = key must be absent).
		wantState string
		wantCause string
	}{
		"cancelled job names the caller": {
			jobID: slow.Job.ID, wantState: toolbelt.JobCancelled, wantCause: string(toolbelt.CancelCaller),
		},
		"finished job carries no cause key": {
			jobID: done.Job.ID, wantState: toolbelt.JobDone, wantCause: "",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			raw := waitRawJob(t, srv, tc.jobID)
			if raw["state"] != tc.wantState {
				t.Fatalf("state = %v, want %s (payload %v)", raw["state"], tc.wantState, raw)
			}
			got, present := raw["cancel_cause"]
			if tc.wantCause == "" {
				if present {
					t.Errorf("cancel_cause = %v, want the key absent", got)
				}
				return
			}
			if got != tc.wantCause {
				t.Errorf("cancel_cause = %v (present=%v), want %q", got, present, tc.wantCause)
			}
		})
	}
}

func TestRoutes_DependentsConflict(t *testing.T) {
	_, srv := newServer(t)
	var jr JobResponse
	call(t, srv, http.MethodPost, "/api/tools", addBody("base"), &jr)
	waitDone(t, srv, jr.Job.ID)
	body := `{"name":"dep","source":"manual","version":"1","requires":["base"],` +
		strings.TrimPrefix(addBody("dep"), `{"name":"dep","source":"manual","version":"1",`)
	call(t, srv, http.MethodPost, "/api/tools", body, &jr)
	waitDone(t, srv, jr.Job.ID)

	// DELETE without force: 409 has_dependents naming dep.
	var conflict struct {
		Code       string   `json:"code"`
		Dependents []string `json:"dependents"`
	}
	if code := call(t, srv, http.MethodDelete, "/api/tools/base", "", &conflict); code != http.StatusConflict {
		t.Fatalf("DELETE with dependents = %d", code)
	}
	if conflict.Code != "has_dependents" || len(conflict.Dependents) != 1 || conflict.Dependents[0] != "dep" {
		t.Fatalf("conflict body = %+v", conflict)
	}

	// Forced: 202, cascade recorded.
	var rm RemoveResponse
	if code := call(t, srv, http.MethodDelete, "/api/tools/base?force=1", "", &rm); code != http.StatusAccepted {
		t.Fatalf("forced DELETE = %d", code)
	}
	if rm.Job == nil || len(rm.Dependents) != 1 {
		t.Fatalf("remove response = %+v", rm)
	}
}

func TestRoutes_SearchAndBadBody(t *testing.T) {
	_, srv := newServer(t)
	var sr SearchResponse
	if code := call(t, srv, http.MethodGet, "/api/tools/search?q=anything", "", &sr); code != http.StatusOK {
		t.Fatalf("GET search = %d", code)
	}
	if sr.Results == nil {
		t.Fatal("search results should be an empty array, not null")
	}
	var errBody struct {
		Code string `json:"code"`
	}
	if code := call(t, srv, http.MethodPost, "/api/tools", `{"name": bogus`, &errBody); code != http.StatusBadRequest {
		t.Fatalf("bad body = %d", code)
	}
}

// newRefreshServer is newServer with catalog refresh configured (an
// unreachable URL: route-level tests need the enqueue, not the fetch).
func newRefreshServer(t *testing.T) (*toolbelt.Engine, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	e, err := toolbelt.New(&toolbelt.Config{
		ConfigDir: dir,
		ToolsDir:  dir + "/tools",
		Logger:    slog.Default(),
		Refresh:   &toolbelt.CatalogRefresh{URL: "https://catalog.invalid/tool-catalog.json"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	h := Handler(e, "/api/tools")
	mux := http.NewServeMux()
	mux.Handle("/api/tools", h)
	mux.Handle("/api/tools/", h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return e, srv
}

func TestCatalogInfoRoute(t *testing.T) {
	_, srv := newServer(t)
	var info toolbelt.CatalogInfo
	if code := call(t, srv, http.MethodGet, "/api/tools/catalog", "", &info); code != http.StatusOK {
		t.Fatalf("GET catalog = %d", code)
	}
	if info.Source != toolbelt.CatalogSourceNone || info.Scheduled || info.Entries != 0 {
		t.Errorf("info = %+v", info)
	}
}

func TestCatalogRefreshRoute(t *testing.T) {
	t.Run("unconfigured refuses with not_configured", func(t *testing.T) {
		_, srv := newServer(t)
		var errBody struct {
			Code string `json:"code"`
		}
		code := call(t, srv, http.MethodPost, "/api/tools/catalog/refresh", "", &errBody)
		if code != http.StatusConflict || errBody.Code != "not_configured" {
			t.Errorf("POST refresh = %d code=%q, want 409 not_configured", code, errBody.Code)
		}
	})

	t.Run("configured returns 202 with the job", func(t *testing.T) {
		_, srv := newRefreshServer(t)
		var jr JobResponse
		code := call(t, srv, http.MethodPost, "/api/tools/catalog/refresh", "", &jr)
		if code != http.StatusAccepted || jr.Job == nil {
			t.Fatalf("POST refresh = %d job=%v, want 202 with job", code, jr.Job)
		}
		if jr.Job.Kind != toolbelt.JobKindCatalogRefresh {
			t.Errorf("job kind = %q", jr.Job.Kind)
		}
	})
}

// --- cache policy ---------------------------------------------------
//
// The projection owns Cache-Control: no-store on every response it
// produces. The tests below enumerate the route table rather than a
// hand-picked list, so a route added to `routes` is covered without
// them being touched.

// newHandler builds an engine on temp dirs and returns the projection
// mounted at /api/tools, served in-process: these tests assert on
// response headers, which needs no listener.
func newHandler(t *testing.T) (*toolbelt.Engine, http.Handler) {
	t.Helper()
	dir := t.TempDir()
	e, err := toolbelt.New(&toolbelt.Config{
		ConfigDir: dir,
		ToolsDir:  dir + "/tools",
		Logger:    slog.Default(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e, Handler(e, "/api/tools")
}

// statusSnapshotRecorder records the response header map at the instant
// the response is committed. A Cache-Control set after WriteHeader is
// silently dropped on the wire, so "present in the map when the status
// is written" — not "present on the recorder afterwards" — is the
// property that matters, and only a writer that observes the commit can
// tell the two apart. Write is intercepted too, so a handler that
// commits implicitly by writing a body is snapshotted as well.
type statusSnapshotRecorder struct {
	*httptest.ResponseRecorder
	atCommit http.Header
}

func (w *statusSnapshotRecorder) snap() {
	if w.atCommit == nil {
		w.atCommit = w.Header().Clone()
	}
}

func (w *statusSnapshotRecorder) WriteHeader(code int) {
	w.snap()
	w.ResponseRecorder.WriteHeader(code)
}

func (w *statusSnapshotRecorder) Write(b []byte) (int, error) {
	w.snap()
	return w.ResponseRecorder.Write(b)
}

// serve issues method+path against h and returns the recorder together
// with the header map as it stood when the response was committed.
func serve(t *testing.T, h http.Handler, method, path, body string) (*httptest.ResponseRecorder, http.Header) {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := &statusSnapshotRecorder{ResponseRecorder: httptest.NewRecorder()}
	h.ServeHTTP(rec, req)
	if rec.atCommit == nil {
		t.Fatalf("%s %s: handler committed no response at all", method, path)
	}
	return rec.ResponseRecorder, rec.atCommit
}

// assertCachePolicy checks the response carried exactly one
// Cache-Control value, equal to want, both at the moment of commit and
// on the committed response the client receives.
func assertCachePolicy(t *testing.T, rec *httptest.ResponseRecorder, atCommit http.Header, want string) {
	t.Helper()
	if got := atCommit.Values(cacheControlHeader); len(got) != 1 || got[0] != want {
		t.Errorf("Cache-Control when the status was written = %v, want exactly [%q]", got, want)
	}
	if got := rec.Result().Header.Values(cacheControlHeader); len(got) != 1 || got[0] != want {
		t.Errorf("Cache-Control on the committed response = %v, want exactly [%q]", got, want)
	}
}

// wildcardValues fills the route table's ServeMux wildcards for the
// enumeration test. Values that resolve to nothing are deliberate: an
// unrouted name is an error path, and error paths carry the policy too.
var wildcardValues = map[string]string{
	"{name}": "no-such-tool",
	"{id}":   "tj-no-such-job",
}

// routePath turns a route table suffix into a concrete request path
// under prefix. A wildcard with no test value fails loudly instead of
// requesting a literal "{x}" path, so a route added with a new wildcard
// name is caught here rather than passing vacuously.
func routePath(t *testing.T, prefix, suffix string) string {
	t.Helper()
	for seg := range strings.SplitSeq(suffix, "/") {
		if !strings.HasPrefix(seg, "{") {
			continue
		}
		v, ok := wildcardValues[seg]
		if !ok {
			t.Fatalf("route suffix %q uses wildcard %s with no test value: add one to wildcardValues", suffix, seg)
		}
		suffix = strings.Replace(suffix, seg, v, 1)
	}
	return prefix + suffix
}

// TestCachePolicy_EveryRouteInTheTable walks the same slice Handler
// registers from, so a route added to the projection is asserted here
// automatically: it must commit a response, and that response must
// carry the no-store policy before its status goes out.
func TestCachePolicy_EveryRouteInTheTable(t *testing.T) {
	_, h := newHandler(t)
	if len(routes) == 0 {
		t.Fatal("route table is empty: the enumeration below would assert nothing")
	}
	for _, rt := range routes {
		suffix := rt.suffix
		if suffix == "" {
			suffix = " (the mount prefix)"
		}
		t.Run(rt.method+suffix, func(t *testing.T) {
			rec, atCommit := serve(t, h, rt.method, routePath(t, "/api/tools", rt.suffix), "")
			assertCachePolicy(t, rec, atCommit, noStorePolicy)
		})
	}
}

// seedTool records an enabled manual entry whose install writes a
// RUNNABLE stub, the same fixture shape addBody uses over HTTP.
func seedTool(t *testing.T, e *toolbelt.Engine, name string, requires ...string) {
	t.Helper()
	install := fmt.Sprintf(`printf "#!/bin/sh\necho %s $VERSION\n" > "$BIN/%s" && chmod 755 "$BIN/%s"`,
		name, name, name)
	if _, err := e.Add(t.Context(), &toolbelt.AddRequest{
		Name: name, Source: "manual", Version: "1", Install: install, Requires: requires,
	}); err != nil {
		t.Fatalf("seed %s: %v", name, err)
	}
}

// TestCachePolicy_EveryWriterClass covers each distinct response writer
// the package reaches — success bodies, the 202 job envelope, the
// decode rejection, every writeEngineError branch, and the responses
// the mux generates for a method or path it does not serve. Fixtures
// are disabled templates: the dependents and disabled refusals read the
// manifest, so no install has to run.
func TestCachePolicy_EveryWriterClass(t *testing.T) {
	e, h := newHandler(t)
	// A disabled template for the install refusal, plus an enabled pair
	// for the dependents refusal — only ENABLED dependents block a
	// remove, so the blocker cannot be a template.
	if _, err := e.Add(t.Context(), &toolbelt.AddRequest{
		Name: "tmpl", Source: "manual", Version: "1", Disabled: true,
	}); err != nil {
		t.Fatalf("seed template: %v", err)
	}
	seedTool(t, e, "base")
	seedTool(t, e, "dep", "base")

	cases := map[string]struct {
		method, path, body string
		wantStatus         int
	}{
		"200 inventory":            {http.MethodGet, "/api/tools", "", http.StatusOK},
		"200 search":               {http.MethodGet, "/api/tools/search?q=x", "", http.StatusOK},
		"200 jobs":                 {http.MethodGet, "/api/tools/jobs", "", http.StatusOK},
		"200 catalog":              {http.MethodGet, "/api/tools/catalog", "", http.StatusOK},
		"202 template add":         {http.MethodPost, "/api/tools", `{"name":"tmpl2","source":"manual","version":"1","disabled":true}`, http.StatusAccepted},
		"202 patch":                {http.MethodPatch, "/api/tools/base", `{"pin":true}`, http.StatusAccepted},
		"202 update":               {http.MethodPost, "/api/tools/update", "", http.StatusAccepted},
		"400 decode failure":       {http.MethodPost, "/api/tools", `{"name": bogus`, http.StatusBadRequest},
		"404 unknown tool":         {http.MethodPatch, "/api/tools/nope", `{"pin":true}`, http.StatusNotFound},
		"404 unknown job":          {http.MethodPost, "/api/tools/jobs/tj-nope/cancel", "", http.StatusNotFound},
		"409 install a template":   {http.MethodPost, "/api/tools/tmpl/install", "", http.StatusConflict},
		"409 has dependents":       {http.MethodDelete, "/api/tools/base", "", http.StatusConflict},
		"409 refresh unconfigured": {http.MethodPost, "/api/tools/catalog/refresh", "", http.StatusConflict},

		"mux: method the path does not serve": {http.MethodPut, "/api/tools", "", http.StatusMethodNotAllowed},
		"mux: no route at all":                {http.MethodGet, "/api/tools/jobs/a/b/c", "", http.StatusNotFound},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rec, atCommit := serve(t, h, tc.method, tc.path, tc.body)
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body %s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			assertCachePolicy(t, rec, atCommit, noStorePolicy)
		})
	}
}

// TestCachePolicy_SuccessfulCancel covers webhttp.Ok, the one writer
// class the table above cannot reach without a job actually queued.
func TestCachePolicy_SuccessfulCancel(t *testing.T) {
	e, h := newHandler(t)
	job, err := e.Add(t.Context(), &toolbelt.AddRequest{
		Name: "stalled", Source: "manual", Version: "1",
		Install: `sleep 3 && printf "#!/bin/sh\nexit 0\n" > "$BIN/stalled" && chmod 755 "$BIN/stalled"`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if job == nil {
		t.Fatal("add enqueued no job to cancel")
	}
	rec, atCommit := serve(t, h, http.MethodPost, "/api/tools/jobs/"+job.ID+"/cancel", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("cancel = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	assertCachePolicy(t, rec, atCommit, noStorePolicy)
}

// TestCachePolicy_WrapperValueWins pins the documented precedence: a
// Cache-Control an outer middleware already stated is left exactly as
// it is — stricter or weaker — and never joined by a second value. The
// package cannot rank directives without parsing them, so it treats any
// stated policy as deliberate.
func TestCachePolicy_WrapperValueWins(t *testing.T) {
	_, h := newHandler(t)
	cases := map[string]string{
		"a stricter wrapper policy survives intact":   "no-store, no-cache, must-revalidate, private",
		"a weaker one is the documented escape hatch": "public, max-age=300",
		"an identical value is not duplicated":        noStorePolicy,
	}
	for name, outer := range cases {
		t.Run(name, func(t *testing.T) {
			wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(cacheControlHeader, outer)
				h.ServeHTTP(w, r)
			})
			rec, atCommit := serve(t, wrapped, http.MethodGet, "/api/tools", "")
			assertCachePolicy(t, rec, atCommit, outer)
		})
	}
}
