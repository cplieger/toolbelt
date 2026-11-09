package httpapi

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/cplieger/toolbelt/v3"
)

// writtenCodes parses httpapi.go for every code it writes: the code argument of
// httpserver.WriteError and the Code field of a typed error body.
func writtenCodes(t *testing.T) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "httpapi.go", nil, 0)
	if err != nil {
		t.Fatalf("parse httpapi.go: %v", err)
	}
	consts := map[string]string{"toolbelt.ErrorCodeGitHubRateLimited": toolbelt.ErrorCodeGitHubRateLimited}
	resolve := func(e ast.Expr) string {
		switch v := e.(type) {
		case *ast.BasicLit:
			s, err := strconv.Unquote(v.Value)
			if err != nil {
				t.Fatalf("code literal %s: %v", v.Value, err)
			}
			return s
		case *ast.SelectorExpr:
			if x, ok := v.X.(*ast.Ident); ok {
				if s, ok := consts[x.Name+"."+v.Sel.Name]; ok {
					return s
				}
			}
		}
		t.Fatalf("a code expression %T this test cannot resolve", e)
		return ""
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.CallExpr:
			if sel, ok := v.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "WriteError" && len(v.Args) == 5 {
				out = append(out, resolve(v.Args[3]))
			}
		case *ast.KeyValueExpr:
			if k, ok := v.Key.(*ast.Ident); ok && k.Name == "Code" {
				if _, isCode := v.Value.(*ast.BasicLit); isCode || isSelector(v.Value) {
					out = append(out, resolve(v.Value))
				}
			}
		}
		return true
	})
	slices.Sort(out)
	return slices.Compact(out)
}

func isSelector(e ast.Expr) bool { _, ok := e.(*ast.SelectorExpr); return ok }

func TestRoutes_CodesAreTheCodesWritten(t *testing.T) {
	written := writtenCodes(t)
	status := map[string]int{}
	for _, rt := range Routes() {
		for _, c := range rt.Codes {
			if s, ok := status[c.Code]; ok && s != c.Status {
				t.Errorf("code %s listed at %d and %d", c.Code, s, c.Status)
			}
			status[c.Code] = c.Status
			if c.Status < 400 || c.Status > 599 {
				t.Errorf("%s %s: code %s has status %d", rt.Method, rt.Suffix, c.Code, c.Status)
			}
		}
	}
	listed := make([]string, 0, len(status))
	for c := range status {
		listed = append(listed, c)
	}
	slices.Sort(listed)
	if !slices.Equal(listed, written) {
		t.Errorf("Routes lists codes %v, the package writes %v", listed, written)
	}
}

func TestRoutes_DescribeTheTable(t *testing.T) {
	rs := Routes()
	if len(rs) != len(routes) || len(rs) == 0 {
		t.Fatalf("Routes() has %d routes, the table %d", len(rs), len(routes))
	}
	for i, rt := range rs {
		id := rt.Method + " " + rt.Suffix
		if rt.Method != routes[i].method || rt.Suffix != routes[i].suffix {
			t.Errorf("route %d is %s, the table's %s %s", i, id, routes[i].method, routes[i].suffix)
		}
		if rt.Response == nil || rt.Response.Kind() != reflect.Struct || rt.Response.Name() == "" {
			t.Errorf("%s: response %v is not a named struct", id, rt.Response)
		}
		for _, typ := range []reflect.Type{rt.Request, rt.Query, rt.Params} {
			if typ != nil && (typ.Kind() != reflect.Struct || typ.Name() == "") {
				t.Errorf("%s: type %v is not a named struct", id, typ)
			}
		}
		var wild []string
		for seg := range strings.SplitSeq(rt.Suffix, "/") {
			if name, ok := strings.CutPrefix(seg, "{"); ok {
				wild = append(wild, strings.TrimSuffix(name, "}"))
			}
		}
		var tags []string
		if rt.Params != nil {
			for f := range rt.Params.Fields() {
				tags = append(tags, f.Tag.Get("json"))
			}
		}
		if !slices.Equal(tags, wild) {
			t.Errorf("%s: Params keys %v, wildcards %v", id, tags, wild)
		}
		want := http.StatusAccepted
		if rt.Method == http.MethodGet || strings.HasSuffix(rt.Suffix, "/cancel") {
			want = http.StatusOK
		}
		if rt.Status != want {
			t.Errorf("%s: status %d, want %d", id, rt.Status, want)
		}
	}
}

// TestRoutes_HandlerServesItsRoute binds each route on a host mux as a host would, and checks the
// answers it gives match what the route declares.
func TestRoutes_HandlerServesItsRoute(t *testing.T) {
	e, _ := newHandler(t)
	mux := http.NewServeMux()
	byKey := map[string]Route{}
	for _, rt := range Routes() {
		mux.Handle(rt.Method+" /api/tools"+rt.Suffix, rt.Handler(e))
		byKey[rt.Method+" "+rt.Suffix] = rt
	}
	cases := []struct {
		method, suffix, path string
		want                 int
	}{
		{http.MethodGet, "", "/api/tools", http.StatusOK},
		{http.MethodGet, "/jobs", "/api/tools/jobs", http.StatusOK},
		{http.MethodPost, "/jobs/{id}/cancel", "/api/tools/jobs/nope/cancel", http.StatusNotFound},
		{http.MethodPost, "/catalog/refresh", "/api/tools/catalog/refresh", http.StatusConflict},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, http.NoBody))
		if rec.Code != tc.want {
			t.Errorf("%s %s = %d, want %d", tc.method, tc.path, rec.Code, tc.want)
		}
		if got := rec.Header().Get(cacheControlHeader); got != noStorePolicy {
			t.Errorf("%s %s: Cache-Control %q, want the package's policy", tc.method, tc.path, got)
		}
		if rec.Code < 400 {
			continue
		}
		var body struct {
			Code string `json:"code"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s %s: %v", tc.method, tc.path, err)
		}
		rt := byKey[tc.method+" "+tc.suffix]
		if !slices.Contains(rt.Codes, Code{Code: body.Code, Status: rec.Code}) {
			t.Errorf("%s %s answered %d %q, which its Codes %v lack", tc.method, tc.path, rec.Code, body.Code, rt.Codes)
		}
	}
}
