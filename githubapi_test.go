package toolbelt

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/httpx/v5"
)

func githubTestClient(srv *httptest.Server, token func(context.Context) (string, error)) *http.Client {
	return &http.Client{Transport: githubAPITransport{next: srv.Client().Transport, token: token, limits: &rateLimitGate{}}}
}

func staticToken(tok string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) { return tok, nil }
}

type authLog struct {
	got map[string]string
	mu  sync.Mutex
}

func (a *authLog) record(r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.got[r.Host+r.URL.Path] = r.Header.Get("Authorization")
}

func (a *authLog) header(hostPath string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	h, ok := a.got[hostPath]
	return h, ok
}

func (a *authLog) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.got)
}

// githubFixture serves a release, its asset listing, and an API path that
// redirects to a download host, recording each request's Authorization.
func githubFixture(t *testing.T) (*httptest.Server, *authLog) {
	t.Helper()
	auth := &authLog{got: map[string]string{}}
	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth.record(r)
		switch r.URL.Path {
		case "/repos/o/r/releases/latest":
			fmt.Fprint(w, `{"tag_name":"v1.0.0"}`)
		case "/repos/o/r/releases/tags/v1.0.0":
			fmt.Fprint(w, `{"assets":[{"name":"r-linux-amd64"}]}`)
		case "/repos/o/r/moved":
			http.Redirect(w, r, "https://objects.githubusercontent.com/asset.json", http.StatusFound)
		default:
			fmt.Fprint(w, `{}`)
		}
	}))
	return srv, auth
}

// fakeGHOnPath puts a gh on PATH that prints a token and records that it ran.
// It returns the record's path, which exists only if something spawned gh.
func fakeGHOnPath(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	ran := filepath.Join(t.TempDir(), "gh-ran")
	script := "#!/bin/sh\necho ran > " + ran + "\necho tok-from-gh\n"
	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return ran
}

// engineAgainst builds an Engine through New and reroutes its client's
// network leg to srv, keeping the production GitHub transport in front.
func engineAgainst(t *testing.T, srv *httptest.Server, cfg *Config) *Engine {
	t.Helper()
	dir := t.TempDir()
	cfg.ConfigDir, cfg.ToolsDir = dir, filepath.Join(dir, "tools")
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(e.Close)
	gh, ok := e.client.Transport.(githubAPITransport)
	if !ok {
		t.Fatalf("engine transport is %T, want githubAPITransport", e.client.Transport)
	}
	gh.next = srv.Client().Transport
	e.client.Transport = gh
	return e
}

func TestGitHubAPITransport_TokenReachesOnlyTheAPI(t *testing.T) {
	cases := []struct {
		name  string
		token string
		want  string
	}{
		{name: "a supplied token is attached", token: "tok-abc", want: "Bearer tok-abc"},
		{name: "an empty token means no header at all", token: "", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, auth := githubFixture(t)
			var calls atomic.Int32
			source := func(context.Context) (string, error) {
				calls.Add(1)
				return tc.token, nil
			}
			client := githubTestClient(srv, source)
			v := newTestVersionResolver(client)
			in := &installer{client: client, output: func(string) {}}
			rr := releaseRef{Host: releaseHostGitHub, Owner: "o", Repo: "r"}

			if _, err := v.Latest(t.Context(), "release:github/o/r", nil); err != nil {
				t.Fatalf("Latest(release:github/o/r) = %v", err)
			}
			if _, err := in.listReleaseAssets(t.Context(), rr, "v1.0.0"); err != nil {
				t.Fatalf("listReleaseAssets(o/r v1.0.0) = %v", err)
			}
			var doc struct{}
			if err := fetchJSON(t.Context(), client, releaseDownloadURL(rr, "v1.0.0", "r.json"), 1<<10, &doc); err != nil {
				t.Fatalf("fetchJSON(download URL) = %v", err)
			}
			if err := fetchJSON(t.Context(), client, "https://api.github.com/repos/o/r/moved", 1<<10, &doc); err != nil {
				t.Fatalf("fetchJSON(redirecting API URL) = %v", err)
			}

			for _, hostPath := range []string{
				"api.github.com/repos/o/r/releases/latest",
				"api.github.com/repos/o/r/releases/tags/v1.0.0",
				"api.github.com/repos/o/r/moved",
			} {
				if got, ok := auth.header(hostPath); !ok || got != tc.want {
					t.Errorf("%s: Authorization = %q (seen %v), want %q", hostPath, got, ok, tc.want)
				}
			}
			for _, hostPath := range []string{
				"github.com/o/r/releases/download/v1.0.0/r.json",
				"objects.githubusercontent.com/asset.json",
			} {
				if got, ok := auth.header(hostPath); !ok || got != "" {
					t.Errorf("%s: Authorization = %q (seen %v), want none: the token must not leave the API host", hostPath, got, ok)
				}
			}
			if got := calls.Load(); got != 3 {
				t.Errorf("token source called %d times, want 3: once per api.github.com request and never for another host", got)
			}
		})
	}
}

func TestGitHubAPITransport_SourceErrorFailsTheRequest(t *testing.T) {
	srv, auth := githubFixture(t)
	errSource := errors.New("credential revoked")
	client := githubTestClient(srv, func(context.Context) (string, error) { return "", errSource })

	_, err := newTestVersionResolver(client).Latest(t.Context(), "release:github/o/r", nil)
	if !errors.Is(err, errSource) {
		t.Fatalf("Latest(release:github/o/r) = %v, want an error wrapping the source's", err)
	}
	if n := auth.count(); n != 0 {
		t.Errorf("server saw %d requests, want 0: a failed source must not fall back to an anonymous request", n)
	}
}

type tokenSourceError struct{ reason string }

func (e *tokenSourceError) Error() string { return "token source: " + e.reason }

func TestAdd_GitHubTokenErrorReachesTheCaller(t *testing.T) {
	srv, auth := githubFixture(t)
	errSource := &tokenSourceError{reason: "credential revoked"}
	e := engineAgainst(t, srv, &Config{
		GitHubToken: func(context.Context) (string, error) { return "", errSource },
	})

	_, err := e.Add(t.Context(), &AddRequest{Name: "r", Source: "release:github/o/r"})
	if !errors.Is(err, errSource) {
		t.Errorf("Add(r, release:github/o/r) = %v, want errors.Is to reach the token source's error", err)
	}
	var got *tokenSourceError
	if !errors.As(err, &got) || got != errSource {
		t.Errorf("errors.As(Add error, *tokenSourceError) = %v (got %p), want the source's %p", errors.As(err, &got), got, errSource)
	}
	if n := auth.count(); n != 0 {
		t.Errorf("server saw %d requests, want 0: a failed source must not fall back to an anonymous request", n)
	}
}

func TestNew_SuppliedGitHubTokenIsUsedAndNoGHRuns(t *testing.T) {
	ran := fakeGHOnPath(t)
	srv, auth := githubFixture(t)
	e := engineAgainst(t, srv, &Config{GitHubToken: staticToken("tok-app")})

	if _, err := e.versions.Latest(t.Context(), "release:github/o/r", nil); err != nil {
		t.Fatalf("Latest(release:github/o/r) = %v", err)
	}
	if got, _ := auth.header("api.github.com/repos/o/r/releases/latest"); got != "Bearer tok-app" {
		t.Errorf("Authorization = %q, want %q from Config.GitHubToken", got, "Bearer tok-app")
	}
	if _, err := os.Stat(ran); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a gh process ran (stat %s: %v); with a token source supplied the engine must not spawn gh", ran, err)
	}
}

func TestNew_NoGitHubTokenIsAnonymousAndNoGHRuns(t *testing.T) {
	ran := fakeGHOnPath(t)
	srv, auth := githubFixture(t)
	e := engineAgainst(t, srv, &Config{})

	if _, err := e.versions.Latest(t.Context(), "release:github/o/r", nil); err != nil {
		t.Fatalf("Latest(release:github/o/r) = %v", err)
	}
	if got, ok := auth.header("api.github.com/repos/o/r/releases/latest"); !ok || got != "" {
		t.Errorf("Authorization = %q (seen %v), want none: no source means anonymous", got, ok)
	}
	if _, err := os.Stat(ran); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a gh process ran (stat %s: %v); the engine must never spawn gh for a credential", ran, err)
	}
}

func TestGitHubAPITransport_ExhaustedQuotaIsANamedError(t *testing.T) {
	reset := time.Date(2026, 10, 4, 14, 5, 0, 0, time.UTC)
	cases := []struct {
		name     string
		token    string
		status   int
		resetHdr string
		want     []string
		notWant  []string
	}{
		{
			name: "403 anonymous", status: http.StatusForbidden, resetHdr: strconv.FormatInt(reset.Unix(), 10),
			want:    []string{"rate limit", "unauthenticated", "resets at 14:05 UTC", "GitHub token"},
			notWant: []string{"api.github.com", "https://", "gh auth login", "GH_TOKEN"},
		},
		{
			name: "429 anonymous", status: http.StatusTooManyRequests, resetHdr: strconv.FormatInt(reset.Unix(), 10),
			want: []string{"rate limit", "resets at 14:05 UTC"},
		},
		{
			name: "403 with a token", token: "tok", status: http.StatusForbidden, resetHdr: strconv.FormatInt(reset.Unix(), 10),
			want:    []string{"rate limit reached for this token", "resets at 14:05 UTC"},
			notWant: []string{"unauthenticated"},
		},
		{
			name: "no reset header", status: http.StatusForbidden,
			want:    []string{"rate limit"},
			notWant: []string{"resets at"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var requests int
			srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests++
				w.Header().Set("X-RateLimit-Remaining", "0")
				if tc.resetHdr != "" {
					w.Header().Set("X-RateLimit-Reset", tc.resetHdr)
				}
				w.WriteHeader(tc.status)
			}))
			v := newTestVersionResolver(githubTestClient(srv, staticToken(tc.token)))

			_, err := v.Latest(t.Context(), "aqua:owner/repo", nil)
			if _, ok := errors.AsType[*GitHubRateLimitError](err); !ok {
				t.Fatalf("Latest(aqua:owner/repo) = %v (%T), want a *GitHubRateLimitError", err, err)
			}
			if requests != 1 {
				t.Errorf("Latest(aqua:owner/repo) made %d requests, want 1: an exhausted quota is not retried", requests)
			}
			msg := err.Error()
			for _, s := range tc.want {
				if !strings.Contains(msg, s) {
					t.Errorf("error %q does not contain %q", msg, s)
				}
			}
			for _, s := range tc.notWant {
				if strings.Contains(msg, s) {
					t.Errorf("error %q contains %q", msg, s)
				}
			}
		})
	}
}

func TestGitHubAPITransport_ReleaseListingReportsTheRateLimit(t *testing.T) {
	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.WriteHeader(http.StatusForbidden)
	}))
	in := &installer{client: githubTestClient(srv, nil), output: func(string) {}}

	_, err := in.listReleaseAssets(t.Context(), releaseRef{Host: releaseHostGitHub, Owner: "o", Repo: "r"}, "v1")
	if _, ok := errors.AsType[*GitHubRateLimitError](err); !ok {
		t.Fatalf("listReleaseAssets(o/r v1) = %v (%T), want a *GitHubRateLimitError", err, err)
	}
}

func TestGitHubAPITransport_OtherForbiddenPassesThrough(t *testing.T) {
	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "42")
		w.WriteHeader(http.StatusForbidden)
	}))
	v := newTestVersionResolver(githubTestClient(srv, nil))

	_, err := v.Latest(t.Context(), "aqua:owner/repo", nil)
	se, ok := errors.AsType[*httpx.StatusError](err)
	if !ok || se.Code != http.StatusForbidden {
		t.Fatalf("Latest(aqua:owner/repo) = %v (%T), want an *httpx.StatusError with code 403", err, err)
	}
	if _, ok := errors.AsType[*GitHubRateLimitError](err); ok {
		t.Errorf("Latest(aqua:owner/repo) = %v, classified as a rate limit with quota remaining", err)
	}
}

// rateLimitedServer answers every request with h's headers, status and body,
// counting requests.
func rateLimitedServer(t *testing.T, status int, hdr map[string]string, body string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32
	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		for k, v := range hdr {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	return srv, &requests
}

// The cases follow GitHub's "Exceeding the rate limit" rules:
// https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api
func TestGitHubAPITransport_RateLimitRefusalIsTyped(t *testing.T) {
	reset := time.Date(2026, 10, 5, 9, 30, 0, 0, time.UTC)
	resetHdr := strconv.FormatInt(reset.Unix(), 10)
	soon := time.Now().Add(time.Hour).Truncate(time.Second).UTC()
	soonHdr := strconv.FormatInt(soon.Unix(), 10)
	const secondaryBody = `{"message":"You have exceeded a secondary rate limit. Please wait a few minutes before you try again."}`
	const abuseBody = `{"message":"You have triggered an abuse detection mechanism. Please wait a few minutes before you try again."}`
	cases := []struct {
		hdr        map[string]string
		name       string
		token      string
		body       string
		status     int
		wantLimit  int
		wantAfter  time.Duration // Reset relative to the request, when wantReset is zero
		wantReset  time.Time
		wantAuth   bool
		wantSecond bool
	}{
		{
			name: "primary anonymous", status: http.StatusForbidden,
			hdr:       map[string]string{"X-RateLimit-Limit": "60", "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": resetHdr},
			body:      `{"message":"API rate limit exceeded for 203.0.113.7."}`,
			wantLimit: 60, wantReset: reset,
		},
		{
			name: "primary authenticated", token: "tok", status: http.StatusTooManyRequests,
			hdr:       map[string]string{"X-RateLimit-Limit": "5000", "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": resetHdr},
			body:      `{"message":"API rate limit exceeded for user ID 1."}`,
			wantLimit: 5000, wantReset: reset, wantAuth: true,
		},
		{
			name: "secondary with Retry-After", token: "tok", status: http.StatusForbidden,
			hdr: map[string]string{"Retry-After": "120", "X-RateLimit-Limit": "5000", "X-RateLimit-Remaining": "4999"},
			// GitHub's older wording: only Retry-After marks it a rate limit.
			body:      abuseBody,
			wantLimit: 5000, wantAfter: 120 * time.Second, wantAuth: true, wantSecond: true,
		},
		{
			name: "secondary message only", status: http.StatusTooManyRequests,
			hdr:  map[string]string{"X-RateLimit-Limit": "60", "X-RateLimit-Remaining": "59"},
			body: secondaryBody, wantLimit: 60, wantAfter: time.Minute, wantSecond: true,
		},
		// GitHub documents that a secondary refusal can also carry remaining 0.
		{
			name: "secondary message over a spent quota", token: "tok", status: http.StatusForbidden,
			hdr:       map[string]string{"X-RateLimit-Limit": "5000", "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": soonHdr},
			body:      secondaryBody,
			wantLimit: 5000, wantReset: soon, wantAuth: true, wantSecond: true,
		},
		{
			name: "secondary Retry-After before the quota reset", status: http.StatusTooManyRequests,
			hdr: map[string]string{
				"X-RateLimit-Limit": "60", "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": soonHdr, "Retry-After": "120",
			},
			body:      secondaryBody,
			wantLimit: 60, wantReset: soon, wantSecond: true,
		},
		{
			name: "secondary Retry-After after the quota reset", status: http.StatusForbidden,
			hdr: map[string]string{
				"X-RateLimit-Limit": "60", "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": soonHdr, "Retry-After": "7200",
			},
			body:      abuseBody,
			wantLimit: 60, wantAfter: 2 * time.Hour, wantSecond: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, requests := rateLimitedServer(t, tc.status, tc.hdr, tc.body)
			v := newTestVersionResolver(githubTestClient(srv, staticToken(tc.token)))

			before := time.Now()
			_, err := v.Latest(t.Context(), "aqua:owner/repo", nil)
			after := time.Now()
			rl, ok := errors.AsType[*GitHubRateLimitError](err)
			if !ok {
				t.Fatalf("Latest(aqua:owner/repo) = %v (%T), want a *GitHubRateLimitError", err, err)
			}
			if !errors.Is(err, ErrGitHubRateLimited) {
				t.Errorf("errors.Is(%v, ErrGitHubRateLimited) = false, want true", err)
			}
			if rl.Authenticated != tc.wantAuth || rl.Secondary != tc.wantSecond || rl.Limit != tc.wantLimit {
				t.Errorf("rate limit = {Authenticated:%v Secondary:%v Limit:%d}, want {%v %v %d}",
					rl.Authenticated, rl.Secondary, rl.Limit, tc.wantAuth, tc.wantSecond, tc.wantLimit)
			}
			switch {
			case !tc.wantReset.IsZero() && !rl.Reset.Equal(tc.wantReset):
				t.Errorf("Reset = %v, want %v from X-RateLimit-Reset", rl.Reset, tc.wantReset)
			case tc.wantReset.IsZero() && (rl.Reset.Before(before.Add(tc.wantAfter).Truncate(time.Second)) || rl.Reset.After(after.Add(tc.wantAfter))):
				t.Errorf("Reset = %v, want %v after the request (between %v and %v)", rl.Reset, tc.wantAfter, before, after)
			}
			if n := requests.Load(); n != 1 {
				t.Errorf("server saw %d requests, want 1: a rate limit is not retried", n)
			}
		})
	}
}

func TestGitHubAPITransport_PlainForbiddenIsNotARateLimit(t *testing.T) {
	srv, _ := rateLimitedServer(t, http.StatusForbidden,
		map[string]string{"X-RateLimit-Limit": "60", "X-RateLimit-Remaining": "42"},
		`{"message":"Resource not accessible by integration"}`)
	v := newTestVersionResolver(githubTestClient(srv, nil))

	_, err := v.Latest(t.Context(), "aqua:owner/repo", nil)
	if se, ok := errors.AsType[*httpx.StatusError](err); !ok || se.Code != http.StatusForbidden {
		t.Errorf("Latest(aqua:owner/repo) = %v (%T), want an *httpx.StatusError with code 403", err, err)
	}
	if errors.Is(err, ErrGitHubRateLimited) {
		t.Errorf("Latest(aqua:owner/repo) = %v, classified as a rate limit with quota remaining and no secondary message", err)
	}
}

func TestGitHubAPITransport_PlainForbiddenKeepsItsBody(t *testing.T) {
	const body = `{"message":"Resource not accessible by integration"}`
	srv, _ := rateLimitedServer(t, http.StatusForbidden, map[string]string{"X-RateLimit-Remaining": "42"}, body)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.github.com/repos/o/r", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := githubTestClient(srv, nil).Do(req)
	if err != nil {
		t.Fatalf("Do(api.github.com/repos/o/r) = %v, want the 403 response", err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil || string(got) != body {
		t.Errorf("403 body = %q (%v), want %q unchanged", got, err, body)
	}
}

// primaryLimitServer refuses every request the way GitHub refuses an
// anonymous caller whose hourly quota is spent.
func primaryLimitServer(t *testing.T, reset time.Time) *httptest.Server {
	t.Helper()
	srv, _ := rateLimitedServer(t, http.StatusForbidden, map[string]string{
		"X-RateLimit-Limit": "60", "X-RateLimit-Remaining": "0",
		"X-RateLimit-Reset": strconv.FormatInt(reset.Unix(), 10),
	}, `{"message":"API rate limit exceeded"}`)
	return srv
}

// assertRateLimitedJob checks a failed job exposes the rate limit to a Go
// consumer (Err) and on the wire (error_code, rate_limit).
func assertRateLimitedJob(t *testing.T, what string, jv *Job, reset time.Time) {
	t.Helper()
	if jv.State != JobFailed {
		t.Fatalf("%s job state = %q (error %q), want %q", what, jv.State, jv.Error, JobFailed)
	}
	rl, ok := errors.AsType[*GitHubRateLimitError](jv.Err())
	if !ok || rl.Authenticated || !rl.Reset.Equal(reset) {
		t.Errorf("%s: errors.As(Job.Err() = %v, *GitHubRateLimitError) = %+v, %v; want anonymous, reset %v", what, jv.Err(), rl, ok, reset)
	}
	raw, err := json.Marshal(jv)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		RateLimit *GitHubRateLimit `json:"rate_limit"`
		ErrorCode string           `json:"error_code"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	want := GitHubRateLimit{ResetAt: reset.UnixMilli(), Limit: 60}
	if wire.ErrorCode != ErrorCodeGitHubRateLimited || wire.RateLimit == nil || *wire.RateLimit != want {
		t.Errorf("%s job JSON = %s, want error_code %q and rate_limit %+v", what, raw, ErrorCodeGitHubRateLimited, want)
	}
}

func TestInstallJob_RateLimitReachesTheFailedJob(t *testing.T) {
	reset := time.Date(2026, 10, 5, 9, 30, 0, 0, time.UTC)
	e := engineAgainst(t, primaryLimitServer(t, reset), &Config{})

	jv, err := e.Add(t.Context(), &AddRequest{Name: "r", Source: "release:github/o/r", Version: "v1.0.0"})
	if err != nil {
		t.Fatalf("Add(r, release:github/o/r@v1.0.0) = %v", err)
	}
	final, err := e.Wait(t.Context(), jv.ID)
	if err != nil {
		t.Fatalf("Wait(%s) = %v", jv.ID, err)
	}
	assertRateLimitedJob(t, "install", final, reset)
}

func TestAdd_RateLimitReachesTheCaller(t *testing.T) {
	e := engineAgainst(t, primaryLimitServer(t, time.Now().Add(time.Hour)), &Config{})

	_, err := e.Add(t.Context(), &AddRequest{Name: "r", Source: "release:github/o/r"})
	if _, ok := errors.AsType[*GitHubRateLimitError](err); !ok {
		t.Errorf("Add(r, release:github/o/r) = %v (%T), want a *GitHubRateLimitError", err, err)
	}
}

// seededEngine is an engine whose manifest holds the named release tools,
// enabled at v1.0.0 and not installed.
func seededEngine(t *testing.T, srv *httptest.Server, names ...string) *Engine {
	t.Helper()
	seed := &Manifest{Tools: map[string]Tool{}}
	for _, n := range names {
		seed.Tools[n] = Tool{Source: "release:github/o/" + n, Version: "v1.0.0"}
	}
	return engineAgainst(t, srv, &Config{Seed: seed})
}

func TestReconcileJob_RateLimitSurvivesSeveralFailures(t *testing.T) {
	reset := time.Date(2026, 10, 5, 9, 30, 0, 0, time.UTC)
	e := seededEngine(t, primaryLimitServer(t, reset), "a", "b")

	jv, _, err := e.Reconcile(ReconcileMissing)
	if err != nil || jv == nil {
		t.Fatalf("Reconcile(missing) = %v, %v; want a job", jv, err)
	}
	final, err := e.Wait(t.Context(), jv.ID)
	if err != nil {
		t.Fatalf("Wait(%s) = %v", jv.ID, err)
	}
	assertRateLimitedJob(t, "reconcile of two tools", final, reset)
}

func TestUpdateJob_RateLimitedVersionCheckFailsTheJob(t *testing.T) {
	reset := time.Date(2026, 10, 5, 9, 30, 0, 0, time.UTC)
	e := seededEngine(t, primaryLimitServer(t, reset), "r")

	jv, err := e.Update("r")
	if err != nil {
		t.Fatalf("Update(r) = %v", err)
	}
	final, err := e.Wait(t.Context(), jv.ID)
	if err != nil {
		t.Fatalf("Wait(%s) = %v", jv.ID, err)
	}
	assertRateLimitedJob(t, "update", final, reset)
}

func TestEnsureInstalled_RateLimitReachesTheCaller(t *testing.T) {
	e := seededEngine(t, primaryLimitServer(t, time.Now().Add(time.Hour)), "r")

	err := e.EnsureInstalled(t.Context(), "r")
	if _, ok := errors.AsType[*GitHubRateLimitError](err); !ok {
		t.Errorf("EnsureInstalled(r) = %v (%T), want a *GitHubRateLimitError", err, err)
	}
}

// spentQuotaServer refuses every request for a spent anonymous quota that
// resets an hour from now, counting requests; it returns the reset too.
func spentQuotaServer(t *testing.T) (*httptest.Server, *atomic.Int32, time.Time) {
	t.Helper()
	reset := time.Now().Add(time.Hour).Truncate(time.Second).UTC()
	srv, requests := rateLimitedServer(t, http.StatusForbidden, map[string]string{
		"X-RateLimit-Limit": "60", "X-RateLimit-Remaining": "0",
		"X-RateLimit-Reset": strconv.FormatInt(reset.Unix(), 10),
	}, `{"message":"API rate limit exceeded"}`)
	return srv, requests, reset
}

func TestReconcileJob_RateLimitStopsFurtherGitHubRequests(t *testing.T) {
	srv, requests, reset := spentQuotaServer(t)
	e := seededEngine(t, srv, "a", "b", "c")

	jv, _, err := e.Reconcile(ReconcileMissing)
	if err != nil || jv == nil {
		t.Fatalf("Reconcile(missing) = %v, %v; want a job", jv, err)
	}
	final, err := e.Wait(t.Context(), jv.ID)
	if err != nil {
		t.Fatalf("Wait(%s) = %v", jv.ID, err)
	}
	assertRateLimitedJob(t, "reconcile of three tools", final, reset)
	if n := requests.Load(); n != 1 {
		t.Errorf("reconcile of three GitHub release tools sent %d requests after the first was rate limited, want 1 in all", n)
	}
}

func TestUpdateJob_RateLimitStopsFurtherGitHubRequests(t *testing.T) {
	srv, requests, reset := spentQuotaServer(t)
	e := seededEngine(t, srv, "a", "b", "c")

	jv, err := e.Update()
	if err != nil {
		t.Fatalf("Update() = %v", err)
	}
	final, err := e.Wait(t.Context(), jv.ID)
	if err != nil {
		t.Fatalf("Wait(%s) = %v", jv.ID, err)
	}
	assertRateLimitedJob(t, "update of three tools", final, reset)
	if n := requests.Load(); n != 1 {
		t.Errorf("update of three GitHub release tools sent %d requests after the first was rate limited, want 1 in all", n)
	}
}

func TestGitHubAPITransport_RateLimitIsHeldPerCredential(t *testing.T) {
	reset := time.Now().Add(time.Hour)
	var requests atomic.Int32
	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(reset.Unix(), 10))
			w.WriteHeader(http.StatusForbidden)
			return
		}
		fmt.Fprint(w, `{"tag_name":"v1.0.0"}`)
	}))
	var tok atomic.Value
	tok.Store("")
	v := newTestVersionResolver(githubTestClient(srv, func(context.Context) (string, error) {
		return tok.Load().(string), nil
	}))

	if _, err := v.Latest(t.Context(), "aqua:o/one", nil); !errors.Is(err, ErrGitHubRateLimited) {
		t.Fatalf("anonymous Latest(aqua:o/one) = %v, want ErrGitHubRateLimited from the server", err)
	}
	if _, err := v.Latest(t.Context(), "aqua:o/two", nil); !errors.Is(err, ErrGitHubRateLimited) {
		t.Errorf("anonymous Latest(aqua:o/two) after a refusal = %v, want ErrGitHubRateLimited", err)
	}
	if n := requests.Load(); n != 1 {
		t.Errorf("server saw %d anonymous requests, want 1: the second must be refused without sending", n)
	}
	tok.Store("tok")
	if got, err := v.Latest(t.Context(), "aqua:o/three", nil); err != nil || got != "v1.0.0" {
		t.Errorf("Latest(aqua:o/three) with a token = %q, %v; want v1.0.0: another credential's refusal does not hold this one", got, err)
	}
}

func TestRateLimitGate_HoldsUntilTheReset(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		reset time.Time
		until time.Time
		name  string
	}{
		{name: "reset ahead", reset: now.Add(10 * time.Minute), until: now.Add(10 * time.Minute)},
		{name: "reset already past", reset: now.Add(-time.Hour), until: now.Add(time.Minute)},
		{name: "no reset", until: now.Add(time.Minute)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := &rateLimitGate{}
			key := sha256.Sum256([]byte("tok"))
			g.record(key, &GitHubRateLimitError{Reset: tc.reset, Limit: 5000, Authenticated: true}, now)

			before := tc.until.Add(-time.Second)
			if rl := g.refusal(key, before); rl == nil || rl.Limit != 5000 || !rl.Authenticated || !rl.Reset.Equal(tc.reset) {
				t.Errorf("refusal(%v) = %+v, want the recorded refusal, held until %v", before, rl, tc.until)
			}
			if rl := g.refusal(key, tc.until); rl != nil {
				t.Errorf("refusal(%v) = %+v, want nil: the hold lapses at %v", tc.until, rl, tc.until)
			}
			if rl := g.refusal(sha256.Sum256(nil), before); rl != nil {
				t.Errorf("refusal(anonymous, %v) = %+v, want nil: only the refused credential is held", before, rl)
			}
		})
	}
}
