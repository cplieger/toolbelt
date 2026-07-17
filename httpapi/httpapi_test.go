package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/toolbelt/v2"
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
	req, err := http.NewRequestWithContext(context.Background(), method, srv.URL+path, rdr)
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

func addBody(name string) string {
	return fmt.Sprintf(`{"name":%q,"source":"manual","version":"1","install":"printf x > \"$BIN/%s\" && chmod 755 \"$BIN/%s\""}`,
		name, name, name)
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

func TestRoutes_DependentsConflict(t *testing.T) {
	_, srv := newServer(t)
	var jr JobResponse
	call(t, srv, http.MethodPost, "/api/tools", addBody("base"), &jr)
	waitDone(t, srv, jr.Job.ID)
	body := `{"name":"dep","source":"manual","version":"1","requires":["base"],"install":"printf x > \"$BIN/dep\" && chmod 755 \"$BIN/dep\""}`
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
